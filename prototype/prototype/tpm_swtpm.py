"""
prototype/tpm_swtpm.py
=======================

Real swtpm-backed implementation of the AIK.  Uses tpm2-tools via
subprocess (rather than tpm2-pytss) because the tpm2-tools CLI has a
stable, well-documented interface across Ubuntu 24.04 / 22.04 versions,
whereas the tpm2-pytss Python API has changed between recent releases.

Design in three parts:

    1. TpmSwtpmContext  -- spawns and manages a swtpm daemon,
                           creates a primary key and a restricted
                           signing AK, and exposes a small "quote
                           this qualifyingData" method.  Cleans up
                           on __exit__.

    2. SwtpmAikKey      -- object attached to an aggregator; delegates
                           sign(payload) to context.quote(payload).
                           The signature that comes back is the raw TPM
                           RSA-SSA signature over the TPM2_ATTEST
                           structure; the verifier reconstructs the
                           attestation structure and checks it.

    3. verify_tpm_quote_signature -- helper on the verifier side that
                           parses the TPM2_ATTEST structure, extracts
                           the extraData (== qualifyingData), and
                           checks the RSA-SSA/SHA-256 signature against
                           the AK public key.

Notes on scheme choice:
    The backend uses  rsa2048:rsassa-sha256 (RSA-PKCS1-v1.5-like) rather than
    RSA-PSS because rsapss on restricted signing keys is fragile in
    the tpm2-tools 5.6 shipped with Ubuntu 24.04 (Esys returns 0x2D2
    "unsupported or incompatible scheme").  This is a *scheme* change,
    not a *primitive* change: the Tamarin abstract algebra models
    every AIK signature as sign(payload, aik) with a free-term
    signing constructor, so the choice of RSASSA vs. RSAPSS is
    invisible at the proof level.  The paper's threat model does not
    depend on message-recovery or PSS-specific properties.
"""
from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


# ============================================================================
#  Helper: run a tpm2-tools command with a hard timeout
# ============================================================================


def _run_tpm2(argv: list[str], tcti: str, timeout: float = 10.0,
              cwd: Optional[str] = None) -> bytes:
    env = os.environ.copy()
    env["TPM2TOOLS_TCTI"] = tcti
    proc = subprocess.run(
        argv, env=env, cwd=cwd,
        capture_output=True, timeout=timeout, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"tpm2 command failed ({proc.returncode}): {' '.join(argv)}\n"
            f"stderr:\n{proc.stderr.decode(errors='replace')}"
        )
    return proc.stdout


# ============================================================================
#  swtpm daemon lifecycle
# ============================================================================


@dataclass
class TpmSwtpmContext:
    """A per-process swtpm instance, plus a loaded restricted AK.

    Typical usage:

        with TpmSwtpmContext() as ctx:
            aik = SwtpmAikKey.from_context(ctx)
            sig = aik.sign(some_payload)          # <-- real TPM2_Quote

    The context object holds the AK's context file, the AK's public
    modulus (extracted once at setup), and a lock to serialise Quote
    calls (TPMs are single-threaded).
    """

    tpm_dir: Path = field(default_factory=lambda: Path(
        os.environ.get("SWTPM_STATE_DIR",
                       tempfile.mkdtemp(prefix="bce27-swtpm-"))))
    pid: Optional[int] = None
    _tcti: str = ""
    _ak_ctx_path: Optional[Path] = None
    _ak_pub_pem: Optional[bytes] = None
    _closed: bool = False

    # --------------------------------------------------------------
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()

    # --------------------------------------------------------------
    def start(self):
        """Start a swtpm or attach to a pre-existing one.

        If the environment variable SWTPM_SOCKET is set (pointing at
        an already-running swtpm's server socket), that socket is used
        directly and no new daemon is spawned.  This is the
        recommended path on constrained containers where in-process
        forking of long-lived children is fragile.  Otherwise a dedicated
        swtpm is spawned under `self.tpm_dir` (setsid + background).
        """
        sock_env = os.environ.get("SWTPM_SOCKET")
        if sock_env:
            sock = Path(sock_env)
            if not sock.exists():
                raise RuntimeError(
                    f"SWTPM_SOCKET is set to {sock} but no socket exists there"
                )
            self.tpm_dir = sock.parent
            self._tcti = f"swtpm:path={sock}"
            self._provision_ak()
            return

        self.tpm_dir.mkdir(parents=True, exist_ok=True)
        for name in ("swtpm.pid",):
            p = self.tpm_dir / name
            if p.exists():
                p.unlink()
        sock = self.tpm_dir / "swtpm-sock"
        ctrl = self.tpm_dir / "swtpm-sock.ctrl"
        for s in (sock, ctrl):
            if s.exists():
                s.unlink()

        cmd = [
            "swtpm", "socket",
            "--tpmstate", f"dir={self.tpm_dir}",
            "--ctrl", f"type=unixio,path={ctrl}",
            "--server", f"type=unixio,path={sock}",
            "--tpm2",
            "--flags", "not-need-init,startup-clear",
            "--pid", f"file={self.tpm_dir / 'swtpm.pid'}",
        ]
        self._popen = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        for _ in range(30):
            if sock.exists():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"swtpm did not create its socket at {sock}")
        pid_file = self.tpm_dir / "swtpm.pid"
        if pid_file.exists():
            self.pid = int(pid_file.read_text().strip())

        self._tcti = f"swtpm:path={sock}"
        atexit.register(self._silent_stop)
        self._provision_ak()

    # --------------------------------------------------------------
    def _provision_ak(self):
        """Create a primary key, then a restricted RSA-SSA/SHA-256 AK.

        Flushes any transient objects left by a previous session first;
        this makes provisioning idempotent even when the TPM was already
        used earlier in the same swtpm lifetime.
        """
        d = self.tpm_dir

        primary_ctx = d / "primary.ctx"
        ak_pub = d / "ak.pub"
        ak_priv = d / "ak.priv"
        ak_pem = d / "ak.pem"

        # 0) flush any transient objects left by a previous run
        _run_tpm2(["tpm2_flushcontext", "-t"], self._tcti)
        _run_tpm2(["tpm2_flushcontext", "-l"], self._tcti)
        _run_tpm2(["tpm2_flushcontext", "-s"], self._tcti)

        # 1) default primary in the owner hierarchy
        _run_tpm2(
            ["tpm2_createprimary", "-C", "o", "-c", str(primary_ctx)],
            self._tcti,
        )

        # 2) restricted RSA-SSA signing AK under it
        _run_tpm2(
            ["tpm2_create",
             "-C", str(primary_ctx),
             "-G", "rsa2048:rsassa-sha256:null",
             "-u", str(ak_pub),
             "-r", str(ak_priv),
             "-c", str(d / "ak.ctx"),
             "-a",
             "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|"
             "sign|restricted"],
            self._tcti,
        )

        # 3) flush transient objects and reload the AK.
        #    Necessary because primary + newly-created AK together
        #    exhaust the 3-object transient slot in most TPM 2.0
        #    implementations.  After the flush+load below, only the
        #    AK is loaded.
        _run_tpm2(["tpm2_flushcontext", "-t"], self._tcti)
        ak_reload = d / "ak_reload.ctx"
        _run_tpm2(
            ["tpm2_load",
             "-C", str(primary_ctx),
             "-u", str(ak_pub), "-r", str(ak_priv),
             "-c", str(ak_reload)],
            self._tcti,
        )
        _run_tpm2(["tpm2_flushcontext", "-t"], self._tcti)

        # 4) Export the AK public key as PEM for the verifier.
        _run_tpm2(
            ["tpm2_readpublic",
             "-c", str(ak_reload),
             "-f", "pem",
             "-o", str(ak_pem)],
            self._tcti,
        )

        self._ak_ctx_path = ak_reload
        self._ak_pub_pem = ak_pem.read_bytes()

    # --------------------------------------------------------------
    def ak_public_pem(self) -> bytes:
        assert self._ak_pub_pem is not None, "context not started"
        return self._ak_pub_pem

    # --------------------------------------------------------------
    def quote(self, qualifying_data: bytes) -> tuple[bytes, bytes, bytes]:
        """Run TPM2_Quote with the given qualifyingData.

        Returns (attest_blob, signature, pcr_bundle):
            attest_blob  : the raw TPM2_ATTEST structure (~145 B)
            signature    : the AK's RSA-SSA/SHA-256 signature over the
                           SHA-256 hash of the attest_blob (~256 B)
            pcr_bundle   : the concatenated PCR values quoted (~668 B)

        qualifying_data must be <= 64 bytes (TPM2B_DATA limit).
        """
        assert self._ak_ctx_path is not None
        assert len(qualifying_data) <= 64, "TPM2B_DATA is capped at 64 B"
        d = self.tpm_dir

        # Use a per-call subdir to keep concurrent tests independent
        with tempfile.TemporaryDirectory(prefix="quote-", dir=str(d)) as td:
            msg = Path(td) / "quote.msg"
            sig = Path(td) / "quote.sig"
            pcrs = Path(td) / "quote.pcrs"
            _run_tpm2(
                ["tpm2_quote",
                 "-c", str(self._ak_ctx_path),
                 "-l", "sha256:0,1,2,3",
                 "-q", qualifying_data.hex(),
                 "-m", str(msg),
                 "-s", str(sig),
                 "-o", str(pcrs),
                 "-g", "sha256"],
                self._tcti,
            )
            # tpm2_quote's -c argument transiently loads the AK on
            # every invocation but does not always unload it, so
            # object contexts accumulate over hundreds of calls and
            # eventually trigger TPM_RC_OBJECT_MEMORY (0x902).
            # Flush transient handles after every Quote to keep the
            # per-call cost stable.
            _run_tpm2(["tpm2_flushcontext", "-t"], self._tcti)
            return msg.read_bytes(), sig.read_bytes(), pcrs.read_bytes()

    # --------------------------------------------------------------
    @property
    def tcti(self) -> str:
        return self._tcti

    # --------------------------------------------------------------
    def stop(self):
        self._silent_stop()

    def _silent_stop(self):
        if self._closed:
            return
        self._closed = True
        try:
            if self.pid:
                try:
                    os.kill(self.pid, 15)
                except ProcessLookupError:
                    pass
        except Exception:
            pass


# ============================================================================
#  SwtpmAikKey  -- object with a sign() method matching the mock AikKey
# ============================================================================


@dataclass
class SwtpmAikKey:
    """An AIK realised by a running TpmSwtpmContext.

    The paper's Tamarin algebra treats the AIK signature as an opaque
    sign(payload, sk) blob; for the swtpm backend this is materialised
    as (attest_blob, sig) so the verifier can also parse the TPM's own
    freshness / PCR fields.  The wire format hides this dichotomy so
    higher-level code (aggregator.py, verifier.py) is agnostic.
    """

    ctx: TpmSwtpmContext
    pk_bytes: bytes = field(init=False)
    _pub_pem: bytes = field(init=False)

    def __post_init__(self):
        self._pub_pem = self.ctx.ak_public_pem()
        # Serialize to DER-SPKI so it matches the mock AikKey.pk_bytes
        pub = serialization.load_pem_public_key(self._pub_pem)
        self.pk_bytes = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # --------------------------------------------------------------
    def sign(self, payload: bytes) -> bytes:
        """The 'signature' in swtpm mode is the concatenation
             len(attest) || attest || sig
        so a single 'bytes' object round-trips both parts.
        See verify_aik_swtpm() below for the parser.
        """
        qualifying = hashes.Hash(hashes.SHA256())
        qualifying.update(payload)
        qd = qualifying.finalize()

        attest, sig, _pcrs = self.ctx.quote(qd)
        packed = len(attest).to_bytes(2, "big") + attest + sig
        return packed


# ============================================================================
#  Verifier helper: parse and check an swtpm signature
# ============================================================================


def verify_aik_swtpm(pk_bytes: bytes, payload: bytes, sig_blob: bytes) -> bool:
    """Verify an AIK signature emitted by SwtpmAikKey.sign().

    Steps (each of which is a distinct check):
        1. Parse the (attest || sig) packing.
        2. Load the TPM2_ATTEST structure and extract extraData.
        3. Check extraData == SHA-256(payload).
        4. Verify the RSA-SSA/SHA-256 signature over SHA-256(attest_blob)
           against pk_bytes.

    Step 3 is the D2 anchor -- it is what binds the AIK signature to
    the extended application payload.
    Step 4 is the standard TPM attestation-signature check.
    """
    try:
        if len(sig_blob) < 2:
            return False
        n = int.from_bytes(sig_blob[:2], "big")
        if len(sig_blob) < 2 + n:
            return False
        attest = sig_blob[2:2 + n]
        sig    = sig_blob[2 + n:]

        # Parse TPM2_ATTEST: the extraData field is a TPM2B_DATA
        # located after the fixed prefix.  Layout (v1.38 §10.12.8):
        #   UINT32  magic          (0xff544347 = "\xffTCG")
        #   UINT16  type
        #   TPM2B_NAME qualifiedSigner
        #   TPM2B_DATA extraData    <-- the field needed here
        #   TPMS_CLOCK_INFO clockInfo
        #   UINT64  firmwareVersion
        #   TPMU_ATTEST attested
        if attest[:4] != b"\xffTCG":
            return False
        off = 4 + 2                          # magic + type
        # qualifiedSigner is a length-prefixed name
        qs_len = int.from_bytes(attest[off:off+2], "big")
        off += 2 + qs_len
        # extraData
        ed_len = int.from_bytes(attest[off:off+2], "big")
        off += 2
        extra_data = attest[off:off+ed_len]

        expected = hashes.Hash(hashes.SHA256())
        expected.update(payload)
        if extra_data != expected.finalize():
            return False

        # Step 4: verify the RSA-SSA/SHA-256 signature over attest.
        # `tpm2_quote -s` writes a TPMT_SIGNATURE wire structure whose
        # first 6 bytes are a header:
        #     UINT16  sigAlg     (0x0014 = TPM_ALG_RSASSA)
        #     UINT16  hashAlg    (0x000b = TPM_ALG_SHA256)
        #     UINT16  sig_size   (0x0100 = 256 for RSA-2048)
        # The raw RSA signature follows.  Strip the header before
        # passing to cryptography's verify().
        raw_sig = sig[6:] if len(sig) > 6 else sig
        pk = serialization.load_der_public_key(pk_bytes)
        assert isinstance(pk, RSAPublicKey)
        pk.verify(
            raw_sig,
            attest,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

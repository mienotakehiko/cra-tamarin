"""
prototype/crypto.py
====================

Thin cryptographic abstraction used by every actor in the prototype.

Two modes are supported:

    * "mock"  : all TPM/DICE/TEE keys are pure-Python
                RSA-PSS / Ed25519 / X25519 keys.
                Works everywhere, including CI, without a TPM daemon.
    * "swtpm" : the AIK (aggregator TPM key) lives inside a running
                swtpm 0.7+ instance and is used via tpm2-pytss.
                Leaf DICE keys and TEE keys stay pure-Python (matching
                the paper's abstraction: only the TPM is a real HSM,
                DICE/TEE are stand-ins).

Which mode is active is controlled by the environment variable
    PROTO_TPM_MODE=mock|swtpm      (default: mock)

The Tamarin model treats the TPM Quote and the DICE signature as the
generic  sign(payload, sk)  constructor; we mirror that here.  Every
sign/verify function returns the same shape of (payload_bytes,
signature_bytes) regardless of mode, so the aggregator and verifier
code is identical between the two modes.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)


# ============================================================================
#  Mode selection
# ============================================================================
MODE = os.environ.get("PROTO_TPM_MODE", "mock").lower()
if MODE not in ("mock", "swtpm"):
    raise RuntimeError(f"PROTO_TPM_MODE must be mock or swtpm, got {MODE!r}")


# ============================================================================
#  Key containers
# ============================================================================


@dataclass
class DiceKey:
    """A leaf's DICE attestation key (Ed25519, in-memory)."""

    sk: ed25519.Ed25519PrivateKey
    pk: ed25519.Ed25519PublicKey

    @classmethod
    def generate(cls) -> "DiceKey":
        sk = ed25519.Ed25519PrivateKey.generate()
        return cls(sk=sk, pk=sk.public_key())

    def sign(self, payload: bytes) -> bytes:
        return self.sk.sign(payload)

    def public_bytes(self) -> bytes:
        return self.pk.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )


@dataclass
class TeeKey:
    """A TEE signing key (Ed25519, in-memory).

    In a real deployment this key lives inside ARM TrustZone or Intel TDX;
    here we treat it as an in-memory stand-in.  The paper's threat model
    explicitly abstracts the TEE as an isolated signer, so a software
    stand-in is faithful to the model.
    """

    sk: ed25519.Ed25519PrivateKey
    pk: ed25519.Ed25519PublicKey

    @classmethod
    def generate(cls) -> "TeeKey":
        sk = ed25519.Ed25519PrivateKey.generate()
        return cls(sk=sk, pk=sk.public_key())

    def sign(self, payload: bytes) -> bytes:
        return self.sk.sign(payload)


_SWTPM_CTX_SINGLETON = None   # populated by first swtpm-mode AikKey.generate()


@dataclass
class AikKey:
    """A TPM AIK (Attestation Identity Key).

    In mock mode the key is a plain RSA-2048 with PSS/SHA-256.
    In swtpm mode the private key lives inside a running swtpm and 'sign'
    invokes TPM2_Quote via tpm2-tools (see prototype/tpm_swtpm.py).

    Both modes expose the same interface:
        aik.sign(payload) -> bytes
        aik.pk_bytes      -- DER-SPKI of the public key
    The bytes returned by sign() differ in interpretation between the
    two modes (mock: raw RSA-PSS signature; swtpm: length-prefixed
    attest || rsa_sig), so the mode also selects the verifier's parser.
    """

    sk: Optional[RSAPrivateKey]        # mock mode only
    pk_bytes: bytes                    # DER-encoded SPKI (both modes)
    _swtpm_aik: object = None          # swtpm mode only, SwtpmAikKey

    @classmethod
    def generate(cls) -> "AikKey":
        if MODE == "mock":
            sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pk_bytes = sk.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return cls(sk=sk, pk_bytes=pk_bytes)
        else:
            # Lazy import so mock mode never pulls in swtpm dependencies.
            from prototype.tpm_swtpm import TpmSwtpmContext, SwtpmAikKey
            global _SWTPM_CTX_SINGLETON
            if _SWTPM_CTX_SINGLETON is None:
                _SWTPM_CTX_SINGLETON = TpmSwtpmContext()
                _SWTPM_CTX_SINGLETON.start()
            aik = SwtpmAikKey(_SWTPM_CTX_SINGLETON)
            return cls(sk=None, pk_bytes=aik.pk_bytes, _swtpm_aik=aik)

    def sign(self, payload: bytes) -> bytes:
        if MODE == "mock":
            assert self.sk is not None
            return self.sk.sign(
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:
            return self._swtpm_aik.sign(payload)


# ============================================================================
#  Verification helpers
# ============================================================================


def verify_dice(pk: ed25519.Ed25519PublicKey, payload: bytes, sig: bytes) -> bool:
    try:
        pk.verify(sig, payload)
        return True
    except Exception:
        return False


def verify_tee(pk: ed25519.Ed25519PublicKey, payload: bytes, sig: bytes) -> bool:
    return verify_dice(pk, payload, sig)


def verify_aik(pk_bytes: bytes, payload: bytes, sig: bytes) -> bool:
    """Verify an AIK signature.

    Mode-dispatched:
        mock  -> raw RSA-PSS/SHA-256 signature over `payload`.
        swtpm -> parse (attest || rsa_sig), check that
                 extraData == SHA-256(payload), then verify the
                 RSA-SSA/SHA-256 signature over the attest blob.

    Both branches return True/False without ever raising, because the
    caller uses the boolean directly in an equality restriction.
    """
    if MODE == "mock":
        try:
            pk = serialization.load_der_public_key(pk_bytes)
            assert isinstance(pk, RSAPublicKey)
            pk.verify(
                sig,
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False
    else:
        from prototype.tpm_swtpm import verify_aik_swtpm
        return verify_aik_swtpm(pk_bytes, payload, sig)


# ============================================================================
#  Cleanup helper (called from experiment scripts to shut swtpm down)
# ============================================================================


def cleanup_swtpm():
    """Terminate the singleton swtpm context if one was started."""
    global _SWTPM_CTX_SINGLETON
    if _SWTPM_CTX_SINGLETON is not None:
        try:
            _SWTPM_CTX_SINGLETON.stop()
        except Exception:
            pass
        _SWTPM_CTX_SINGLETON = None


# ============================================================================
#  Domain-separated hashes and helpers
# ============================================================================


def h(data: bytes) -> bytes:
    """SHA-256 wrapper used both by the aggregator and the verifier."""
    return hashlib.sha256(data).digest()


def now_ns() -> int:
    """Nanosecond wall-clock, for latency measurement."""
    return time.perf_counter_ns()

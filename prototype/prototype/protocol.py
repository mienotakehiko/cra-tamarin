"""
prototype/protocol.py
=====================

Wire formats and payload encoders for the Baseline and Hardened
hierarchical CRA protocols, in one-to-one correspondence with the
Tamarin rules of  baseline.spthy  and  fixed.spthy.

Every function that produces bytes is deterministic and stable, so
signatures over these bytes can be independently reproduced from the
recorded transcripts.  All framings use length-prefixed concatenation
via `_pack`, which is trivial to parse but obviously not
production-grade (no ASN.1, no CBOR); the paper's claim is about
the abstract protocol, not the wire format.

The two versions share every field except:
    * baseline AGG_EV payload  =  ('AGG_EV', A, V, epoch, n)
    * fixed    AGG_EV payload  =  ('AGG_EV', A, V, epoch, n,
                                    h(<m1, ev1, m2, ev2>),
                                    h(<L1, L2>))
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from prototype.crypto import h


# ============================================================================
#  Low-level packer  (length-prefixed concatenation)
# ============================================================================


def _pack(*parts: bytes) -> bytes:
    """Concatenate `parts` with 4-byte big-endian length prefixes.

    Deterministic; injective; safe to hash.  Any change in any field
    changes the output byte string.
    """
    out = bytearray()
    for p in parts:
        assert isinstance(p, (bytes, bytearray)), f"non-bytes part: {type(p)}"
        out += len(p).to_bytes(4, "big")
        out += p
    return bytes(out)


def _s(s: str) -> bytes:
    return s.encode("utf-8")


# ============================================================================
#  Leaf evidence  (identical between baseline and fixed)
# ============================================================================


def leaf_ev_payload(
    L: str, A: str, V: str, epoch: bytes, n: bytes, m: bytes
) -> bytes:
    """The bytes signed by a leaf's DICE key when producing evidence.

    Matches Tamarin's:
        sign(<'LEAF_EV', L, A, V, epoch, n, m>, cdi)
    """
    return _pack(_s("LEAF_EV"), _s(L), _s(A), _s(V), epoch, n, m)


# ============================================================================
#  Aggregator report  --  BASELINE version
# ============================================================================


def baseline_quote_payload(
    A: str, V: str, epoch: bytes, n: bytes
) -> bytes:
    """AIK-signed payload in the baseline protocol.

    Matches Tamarin's:
        sign(<'AGG_EV', A, V, epoch, n>, aik)
    Deliberately does NOT commit to any evidence set or roster.
    """
    return _pack(_s("AGG_EV"), _s(A), _s(V), epoch, n)


@dataclass
class BaselineReport:
    """The bytes the baseline aggregator sends to the verifier."""

    A: str
    V: str
    epoch: bytes
    evset: List[Tuple[str, bytes, bytes]]   # list of (leaf_id, m, dice_sig)
    aik_sig: bytes                          # over baseline_quote_payload

    def wire_bytes(self) -> bytes:
        entries = b""
        for (L, m, sig) in self.evset:
            entries += _pack(_s(L), m, sig)
        return _pack(
            _s("AGG_REPORT_BASE"),
            _s(self.A), _s(self.V), self.epoch,
            entries, self.aik_sig,
        )


# ============================================================================
#  Aggregator report  --  HARDENED version  (matches fixed.spthy)
# ============================================================================


def hardened_quote_payload(
    A: str, V: str, epoch: bytes, n: bytes,
    m1: bytes, ev1: bytes, m2: bytes, ev2: bytes,
    L1: str, L2: str,
) -> bytes:
    """AIK-signed payload in the hardened protocol.

    Matches Tamarin's:
        payload = <'AGG_EV', A, V, epoch, n,
                   h(<m1, ev1, m2, ev2>),
                   h(<L1, L2>)>
    """
    return _pack(
        _s("AGG_EV"), _s(A), _s(V), epoch, n,
        h(_pack(m1, ev1, m2, ev2)),
        h(_pack(_s(L1), _s(L2))),
    )


# ------------------------------------------------------------------
#  TPM 2.0 qualifyingData construction  (paper Section 8, question Q2)
# ------------------------------------------------------------------
#  The extended payload is larger than TPM2B_DATA's 64-byte limit,
#  so it is hashed once more with SHA-256 (32 bytes), and that digest
#  is passed to TPM2_Quote as qualifyingData.  The verifier receives
#  the plaintext extended payload alongside the aggregate and re-hashes
#  to match.
def qualifying_data_for(payload: bytes) -> bytes:
    return h(payload)


@dataclass
class HardenedReport:
    """The bytes the hardened aggregator sends to the verifier.

    Includes the plaintext components the verifier needs to
    reconstruct the extended payload before checking the AIK
    signature.
    """

    A: str
    V: str
    epoch: bytes
    L1: str
    L2: str
    m1: bytes
    ev1: bytes    # DICE signature of L1
    m2: bytes
    ev2: bytes    # DICE signature of L2
    aik_sig: bytes

    def wire_bytes(self) -> bytes:
        return _pack(
            _s("AGG_REPORT_FIXED"),
            _s(self.A), _s(self.V), self.epoch,
            _s(self.L1), _s(self.L2),
            self.m1, self.ev1, self.m2, self.ev2,
            self.aik_sig,
        )


# ============================================================================
#  Verifier challenge (identical between baseline and fixed)
# ============================================================================


@dataclass
class Challenge:
    V: str
    A: str
    nonce: bytes
    epoch: bytes

    def wire_bytes(self) -> bytes:
        return _pack(_s("CHAL"), _s(self.V), _s(self.A), self.nonce, self.epoch)

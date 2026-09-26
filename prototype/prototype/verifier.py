"""
prototype/verifier.py
=====================

Verifier.  Two flavours matching the two Tamarin theories:

    * BaselineVerifier  ~  baseline.spthy
    * HardenedVerifier  ~  fixed.spthy   (D3, D4 apply)

The key methodological point (paper Section 8, question Q3):
HardenedVerifier.accept() is a SINGLE Python function that verifies
the AIK signature AND both DICE signatures before returning an
AcceptedReport.  A failure in any of those checks returns None without
side effects.  This is the implementation counterpart of the Tamarin
atomicity property.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from prototype.crypto import verify_aik, verify_dice, h
from prototype.protocol import (
    BaselineReport, HardenedReport, Challenge,
    baseline_quote_payload, hardened_quote_payload,
    leaf_ev_payload, _pack, _s,
)


@dataclass
class AcceptedReport:
    V: str
    A: str
    epoch: bytes
    entries: List[Tuple[str, bytes]]   # list of (leaf_id, measurement)


# ============================================================================
#  Baseline verifier
# ============================================================================


@dataclass
class BaselineVerifier:
    V: str
    aik_pk_of: Dict[str, bytes]                       # A -> DER-SPKI
    leaf_pk_of: Dict[str, Ed25519PublicKey]           # L -> pk
    roster_of: Dict[str, List[str]]                   # A -> [L1, L2, ...]

    def start_session(self, A: str) -> Challenge:
        return Challenge(
            V=self.V, A=A, nonce=os.urandom(16), epoch=os.urandom(16)
        )

    def accept(
        self, chal: Challenge, report: BaselineReport
    ) -> Optional[AcceptedReport]:
        """Baseline accept: verify AIK sig, then per-leaf sigs.  Not atomic.

        This mirrors baseline.spthy's rule split
        (Verifier_AcceptAggregate + Verifier_ParseEntry).  The
        parse-entry step iterates over whatever evset the aggregator
        forwarded; if the adversary omitted a roster member, no
        AcceptEntry is produced for that member, so the silent-omission
        attack succeeds.
        """
        # (1) AIK signature over the fixed baseline payload
        payload = baseline_quote_payload(chal.A, chal.V, chal.epoch, chal.nonce)
        if not verify_aik(self.aik_pk_of[chal.A], payload, report.aik_sig):
            return None

        # (2) per-entry parse: verify each DICE signature
        entries: List[Tuple[str, bytes]] = []
        for (L, m, sig) in report.evset:
            if L not in self.leaf_pk_of:
                continue
            leaf_payload = leaf_ev_payload(L, chal.A, chal.V, chal.epoch, chal.nonce, m)
            if verify_dice(self.leaf_pk_of[L], leaf_payload, sig):
                entries.append((L, m))
        return AcceptedReport(
            V=chal.V, A=chal.A, epoch=chal.epoch, entries=entries
        )


# ============================================================================
#  Hardened verifier: atomic accept (D3, D4)
# ============================================================================


@dataclass
class HardenedVerifier:
    V: str
    aik_pk_of: Dict[str, bytes]
    leaf_pk_of: Dict[str, Ed25519PublicKey]
    roster_of: Dict[str, List[str]]

    def start_session(self, A: str) -> Challenge:
        return Challenge(
            V=self.V, A=A, nonce=os.urandom(16), epoch=os.urandom(16)
        )

    def accept(
        self, chal: Challenge, report: HardenedReport
    ) -> Optional[AcceptedReport]:
        """Hardened accept: verify AIK sig AND both DICE sigs atomically.

        No AcceptEntry is emitted until every signature has verified.
        This is the D4 atomicity property; the paper's Q3 experiment
        stresses it with adversarial reports.
        """
        A = chal.A
        L1, L2 = self.roster_of[A]

        # Consistency check: report's roster must match verifier's
        if (report.L1, report.L2) != (L1, L2):
            return None

        # Reconstruct the exact payload the aggregator's TPM signed
        payload = hardened_quote_payload(
            A, chal.V, chal.epoch, chal.nonce,
            report.m1, report.ev1, report.m2, report.ev2,
            L1, L2,
        )

        # (1) verify AIK signature
        if not verify_aik(self.aik_pk_of[A], payload, report.aik_sig):
            return None

        # (2) verify DICE signature of L1
        p1 = leaf_ev_payload(L1, A, chal.V, chal.epoch, chal.nonce, report.m1)
        if not verify_dice(self.leaf_pk_of[L1], p1, report.ev1):
            return None

        # (3) verify DICE signature of L2
        p2 = leaf_ev_payload(L2, A, chal.V, chal.epoch, chal.nonce, report.m2)
        if not verify_dice(self.leaf_pk_of[L2], p2, report.ev2):
            return None

        # Only now is the AcceptedReport built.  This is the atomic
        # counterpart of the Tamarin rule emitting Accept and both
        # AcceptEntry actions in the same rule body.
        return AcceptedReport(
            V=chal.V, A=A, epoch=chal.epoch,
            entries=[(L1, report.m1), (L2, report.m2)],
        )

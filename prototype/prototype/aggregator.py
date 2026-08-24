"""
prototype/aggregator.py
=======================

Composite Attester.  Owns one AIK (TPM) and one TSK (TEE).  Collects
leaf evidence and produces an aggregate report, in one of two modes:

    * BaselineAggregator : follows baseline.spthy
    * HardenedAggregator : follows fixed.spthy   (D1--D4 applied)

The signed-DH TEE--TPM handshake is intentionally kept minimal here
because none of the three focus questions (Q1/Q2/Q3) exercises it
directly -- E4 measures its latency in isolation.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Tuple

from prototype.crypto import AikKey, TeeKey
from prototype.protocol import (
    BaselineReport,
    HardenedReport,
    baseline_quote_payload,
    hardened_quote_payload,
)


# ============================================================================
#  Baseline aggregator
# ============================================================================


@dataclass
class BaselineAggregator:
    A: str
    aik: AikKey
    tee: TeeKey
    roster: List[str] = field(default_factory=list)   # ["L1", "L2"] etc.

    @classmethod
    def register(cls, A: str, roster: List[str]) -> "BaselineAggregator":
        return cls(A=A, aik=AikKey.generate(), tee=TeeKey.generate(), roster=list(roster))

    # ------------------------------------------------------------------
    def make_report(
        self,
        V: str,
        epoch: bytes,
        n: bytes,
        evset: List[Tuple[str, bytes, bytes]],
    ) -> BaselineReport:
        """Produce a baseline aggregate report over `evset`.

        `evset` is a list of (leaf_id, measurement, dice_signature).
        The aggregator's AIK signs *only* the fixed baseline payload;
        the evset is not bound.  This is the vulnerability exploited
        in experiment E1.
        """
        payload = baseline_quote_payload(self.A, V, epoch, n)
        aik_sig = self.aik.sign(payload)
        return BaselineReport(
            A=self.A, V=V, epoch=epoch, evset=evset, aik_sig=aik_sig
        )


# ============================================================================
#  Hardened aggregator
# ============================================================================


@dataclass
class HardenedAggregator:
    A: str
    aik: AikKey
    tee: TeeKey
    roster: List[str] = field(default_factory=list)

    @classmethod
    def register(cls, A: str, roster: List[str]) -> "HardenedAggregator":
        assert len(roster) == 2, "fixed.spthy models a two-leaf roster; extend for k>2"
        return cls(A=A, aik=AikKey.generate(), tee=TeeKey.generate(), roster=list(roster))

    # ------------------------------------------------------------------
    def make_report(
        self,
        V: str,
        epoch: bytes,
        n: bytes,
        ev_by_leaf: dict[str, Tuple[bytes, bytes]],
    ) -> HardenedReport:
        """Produce a hardened aggregate report.

        The aggregator MUST have both roster members' (m, dice_sig).
        Missing any of them raises KeyError, which is the intended
        behaviour: a compromised aggregator that drops a leaf CANNOT
        produce a valid Quote in the hardened design.
        """
        L1, L2 = self.roster
        m1, ev1 = ev_by_leaf[L1]
        m2, ev2 = ev_by_leaf[L2]
        payload = hardened_quote_payload(
            self.A, V, epoch, n, m1, ev1, m2, ev2, L1, L2
        )
        aik_sig = self.aik.sign(payload)
        return HardenedReport(
            A=self.A, V=V, epoch=epoch,
            L1=L1, L2=L2,
            m1=m1, ev1=ev1, m2=m2, ev2=ev2,
            aik_sig=aik_sig,
        )

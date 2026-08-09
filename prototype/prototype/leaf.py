"""
prototype/leaf.py
=================

Leaf attester.  One instance per registered DICE-based device.

Corresponds to the Tamarin  Leaf_Attest  rule in both baseline.spthy
and fixed.spthy.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from prototype.crypto import DiceKey
from prototype.protocol import leaf_ev_payload


@dataclass
class Leaf:
    L: str                       # leaf identifier, e.g. "L1"
    A: str                       # aggregator identifier this leaf reports to
    key: DiceKey                 # DICE attestation key

    @classmethod
    def register(cls, L: str, A: str) -> "Leaf":
        return cls(L=L, A=A, key=DiceKey.generate())

    def attest(
        self, V: str, epoch: bytes, n: bytes, measurement: bytes = None
    ) -> tuple[bytes, bytes]:
        """Return (measurement, dice_signature).

        The measurement is a fresh 32-byte random value in the
        prototype; a real leaf would populate this from its
        DICE-derived layered measurement of its firmware / OS / apps.
        """
        if measurement is None:
            measurement = os.urandom(32)
        payload = leaf_ev_payload(
            self.L, self.A, V, epoch, n, measurement
        )
        sig = self.key.sign(payload)
        return measurement, sig

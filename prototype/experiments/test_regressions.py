"""
pytest regression suite.  Each test is a smoke run of one experiment
with a small N; the full-scale experiments are the scripts themselves.

    cd prototype && PYTHONPATH=. pytest experiments/test_regressions.py -v
"""
from __future__ import annotations
import os
from copy import deepcopy

import pytest

from prototype.leaf import Leaf
from prototype.aggregator import BaselineAggregator, HardenedAggregator
from prototype.verifier import BaselineVerifier, HardenedVerifier
from prototype.protocol import (
    baseline_quote_payload, hardened_quote_payload, qualifying_data_for,
)


N_SMOKE = 50


@pytest.fixture
def setup2():
    """A verifier + aggregator + 2 registered leaves, for both flavours."""
    V = "V"
    L1 = Leaf.register("L1", "A")
    L2 = Leaf.register("L2", "A")

    base_A = BaselineAggregator.register("A", ["L1", "L2"])
    hard_A = HardenedAggregator.register("A", ["L1", "L2"])
    base_A.leaves = [L1, L2]

    base_V = BaselineVerifier(
        V=V, aik_pk_of={"A": base_A.aik.pk_bytes},
        leaf_pk_of={"L1": L1.key.pk, "L2": L2.key.pk},
        roster_of={"A": ["L1", "L2"]},
    )
    hard_V = HardenedVerifier(
        V=V, aik_pk_of={"A": hard_A.aik.pk_bytes},
        leaf_pk_of={"L1": L1.key.pk, "L2": L2.key.pk},
        roster_of={"A": ["L1", "L2"]},
    )
    return dict(V=V, L1=L1, L2=L2, base_A=base_A, hard_A=hard_A,
                base_V=base_V, hard_V=hard_V)


# E1 (Q1): the silent-omission attack succeeds on the baseline.


def test_e1_baseline_silent_omission(setup2):
    s = setup2
    for _ in range(N_SMOKE):
        chal = s["base_V"].start_session("A")
        m1, e1 = s["L1"].attest(s["V"], chal.epoch, chal.nonce)
        _ = s["L2"].attest(s["V"], chal.epoch, chal.nonce)     # dropped
        report = s["base_A"].make_report(
            s["V"], chal.epoch, chal.nonce, [("L1", m1, e1)]   # <-- L2 omitted
        )
        accepted = s["base_V"].accept(chal, report)
        assert accepted is not None, "baseline verifier must (wrongly) Accept"
        leaves_present = {L for (L, _) in accepted.entries}
        assert "L2" not in leaves_present, "L2 must be missing (attack success)"


# E2 (Q2): the hardened Quote fits TPM qualifyingData (<= 64 B).


def test_e2_qualifying_data_size(setup2):
    s = setup2
    for _ in range(N_SMOKE):
        epoch, nonce = os.urandom(16), os.urandom(16)
        m1, e1 = s["L1"].attest(s["V"], epoch, nonce)
        m2, e2 = s["L2"].attest(s["V"], epoch, nonce)
        payload = hardened_quote_payload(
            "A", s["V"], epoch, nonce, m1, e1, m2, e2, "L1", "L2"
        )
        q = qualifying_data_for(payload)
        assert len(q) == 32, "qualifyingData must be a 32-byte SHA-256 digest"
        assert len(q) <= 64, "qualifyingData must fit TPM2B_DATA"


# E3 (Q3): the hardened accept stays atomic under adversarial reports.


def test_e3_atomic_all_good(setup2):
    s = setup2
    for _ in range(N_SMOKE):
        chal = s["hard_V"].start_session("A")
        m1, e1 = s["L1"].attest(s["V"], chal.epoch, chal.nonce)
        m2, e2 = s["L2"].attest(s["V"], chal.epoch, chal.nonce)
        rep = s["hard_A"].make_report(
            s["V"], chal.epoch, chal.nonce,
            {"L1": (m1, e1), "L2": (m2, e2)},
        )
        acc = s["hard_V"].accept(chal, rep)
        assert acc is not None and len(acc.entries) == 2


def test_e3_atomic_bad_aik(setup2):
    s = setup2
    for _ in range(N_SMOKE):
        chal = s["hard_V"].start_session("A")
        m1, e1 = s["L1"].attest(s["V"], chal.epoch, chal.nonce)
        m2, e2 = s["L2"].attest(s["V"], chal.epoch, chal.nonce)
        rep = s["hard_A"].make_report(
            s["V"], chal.epoch, chal.nonce,
            {"L1": (m1, e1), "L2": (m2, e2)},
        )
        rep2 = deepcopy(rep); rep2.aik_sig = os.urandom(256)
        assert s["hard_V"].accept(chal, rep2) is None


def test_e3_atomic_bad_leaf_sigs(setup2):
    s = setup2
    for _ in range(N_SMOKE):
        chal = s["hard_V"].start_session("A")
        m1, e1 = s["L1"].attest(s["V"], chal.epoch, chal.nonce)
        m2, e2 = s["L2"].attest(s["V"], chal.epoch, chal.nonce)
        rep = s["hard_A"].make_report(
            s["V"], chal.epoch, chal.nonce,
            {"L1": (m1, e1), "L2": (m2, e2)},
        )
        rep2 = deepcopy(rep); rep2.ev1 = os.urandom(64)
        assert s["hard_V"].accept(chal, rep2) is None
        rep3 = deepcopy(rep); rep3.ev2 = os.urandom(64)
        assert s["hard_V"].accept(chal, rep3) is None

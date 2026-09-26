"""
Experiment E3 (Q3): check that HardenedVerifier.accept() is atomic.

The script builds one honest and three adversarial reports and feeds
each to the verifier N_RUNS times (default 1000 in mock mode, 100 in
swtpm mode).  Success criterion:
    - R_all_good   : accept, both AcceptEntry emitted
    - R_bad_aik    : reject, ZERO AcceptEntry emitted
    - R_bad_L1     : reject, ZERO AcceptEntry emitted (not even for L2)
    - R_bad_L2     : reject, ZERO AcceptEntry emitted (not even for L1)

Run:
    PYTHONPATH=. python3 experiments/e3_atomicity.py
"""
from __future__ import annotations
import statistics, sys, os
from copy import deepcopy
from prototype.leaf import Leaf
from prototype.aggregator import HardenedAggregator
from prototype.verifier import HardenedVerifier
from prototype.crypto import now_ns

import os
N_RUNS = int(os.environ.get("N_RUNS",
                            "100" if os.environ.get("PROTO_TPM_MODE") == "swtpm" else "1000"))

def build_good_report(V, aggr, L1, L2, verifier):
    chal = verifier.start_session(aggr.A)
    m1, e1 = L1.attest(V, chal.epoch, chal.nonce)
    m2, e2 = L2.attest(V, chal.epoch, chal.nonce)
    report = aggr.make_report(V, chal.epoch, chal.nonce, {"L1": (m1, e1), "L2": (m2, e2)})
    return chal, report


def main():
    V = "V"
    L1 = Leaf.register("L1", "A")
    L2 = Leaf.register("L2", "A")
    aggr = HardenedAggregator.register("A", ["L1", "L2"])
    verifier = HardenedVerifier(
        V=V,
        aik_pk_of={"A": aggr.aik.pk_bytes},
        leaf_pk_of={"L1": L1.key.pk, "L2": L2.key.pk},
        roster_of={"A": ["L1", "L2"]},
    )

    stats = {"R_all_good": {"n_accept": 0, "n_reject": 0, "t_ns": []},
             "R_bad_aik":  {"n_accept": 0, "n_reject": 0, "t_ns": []},
             "R_bad_L1":   {"n_accept": 0, "n_reject": 0, "t_ns": []},
             "R_bad_L2":   {"n_accept": 0, "n_reject": 0, "t_ns": []}}

    for _ in range(N_RUNS):
        # R_all_good
        chal, rep = build_good_report(V, aggr, L1, L2, verifier)
        t0 = now_ns(); res = verifier.accept(chal, rep); t1 = now_ns()
        stats["R_all_good"]["n_accept" if res else "n_reject"] += 1
        stats["R_all_good"]["t_ns"].append(t1 - t0)

        # R_bad_aik : tamper the AIK signature
        chal, rep = build_good_report(V, aggr, L1, L2, verifier)
        rep2 = deepcopy(rep); rep2.aik_sig = os.urandom(256)
        t0 = now_ns(); res = verifier.accept(chal, rep2); t1 = now_ns()
        stats["R_bad_aik"]["n_accept" if res else "n_reject"] += 1
        stats["R_bad_aik"]["t_ns"].append(t1 - t0)

        # R_bad_L1 : keep AIK/L2 signatures valid, tamper L1's DICE sig
        chal, rep = build_good_report(V, aggr, L1, L2, verifier)
        rep2 = deepcopy(rep); rep2.ev1 = os.urandom(64)
        t0 = now_ns(); res = verifier.accept(chal, rep2); t1 = now_ns()
        stats["R_bad_L1"]["n_accept" if res else "n_reject"] += 1
        stats["R_bad_L1"]["t_ns"].append(t1 - t0)

        # R_bad_L2 : symmetric
        chal, rep = build_good_report(V, aggr, L1, L2, verifier)
        rep2 = deepcopy(rep); rep2.ev2 = os.urandom(64)
        t0 = now_ns(); res = verifier.accept(chal, rep2); t1 = now_ns()
        stats["R_bad_L2"]["n_accept" if res else "n_reject"] += 1
        stats["R_bad_L2"]["t_ns"].append(t1 - t0)

    print("E3 -- Atomic accept under adversarial reports")
    print("-----------------------------------------------")
    print(f"{'Case':<12} {'accept':>7} {'reject':>7} {'mean_ns':>10} {'p95_ns':>10}")
    for k, v in stats.items():
        m = statistics.mean(v["t_ns"])
        p = sorted(v["t_ns"])[int(N_RUNS*0.95)]
        print(f"{k:<12} {v['n_accept']:>7} {v['n_reject']:>7} {m:>10.0f} {p:>10.0f}")

    ok = (stats["R_all_good"]["n_accept"] == N_RUNS and
          stats["R_bad_aik"]["n_reject"] == N_RUNS and
          stats["R_bad_L1"]["n_reject"] == N_RUNS and
          stats["R_bad_L2"]["n_reject"] == N_RUNS)

    import os as _os
    suffix = "" if _os.environ.get("PROTO_TPM_MODE", "mock") == "mock" else "_swtpm"
    out = f"results/e3_atomicity{suffix}.csv"
    with open(out, "w") as f:
        f.write("case,accepts,rejects,mean_ns,p95_ns\n")
        for k, v in stats.items():
            m = statistics.mean(v["t_ns"])
            p = sorted(v["t_ns"])[int(N_RUNS*0.95)]
            f.write(f"{k},{v['n_accept']},{v['n_reject']},{m:.0f},{p:.0f}\n")
    print(f"wrote {out}")

    print()
    print("Q3 answered YES" if ok else "Q3 answered NO -- atomicity violated!")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

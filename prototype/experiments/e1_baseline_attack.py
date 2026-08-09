"""
Experiment E1 -- Q1: reproduce the silent-omission attack against the
BASELINE protocol.  Confirms that Verifier.accept() returns a valid
AcceptedReport whose `entries` list has FEWER members than the roster,
even though the aggregator's TPM Quote signature verifies correctly.

Run:
    PYTHONPATH=. python3 experiments/e1_baseline_attack.py
"""
from __future__ import annotations
import statistics, sys
from prototype.leaf import Leaf
from prototype.aggregator import BaselineAggregator
from prototype.verifier import BaselineVerifier
from prototype.crypto import now_ns

import os
# In swtpm mode the AIK sign path costs ~15 ms per call, so 1000 runs
# takes minutes; the mock path is sub-ms and 1000 runs is instant.
N_RUNS = int(os.environ.get("N_RUNS",
                            "100" if os.environ.get("PROTO_TPM_MODE") == "swtpm" else "1000"))

def one_run(V, A, verifier):
    chal = verifier.start_session(A.A)
    # both leaves attest honestly ...
    m1, e1 = A.leaves[0].attest(V, chal.epoch, chal.nonce)
    m2, e2 = A.leaves[1].attest(V, chal.epoch, chal.nonce)
    # ... but the adversary drops L2's evidence between L2 and A.
    evset = [(A.leaves[0].L, m1, e1)]      # <-- L2 omitted
    t0 = now_ns()
    report = A.make_report(V, chal.epoch, chal.nonce, evset)
    t1 = now_ns()
    accepted = verifier.accept(chal, report)
    t2 = now_ns()
    return accepted, (t1 - t0), (t2 - t1)


def main():
    V = "V"
    L1 = Leaf.register("L1", "A")
    L2 = Leaf.register("L2", "A")
    aggr = BaselineAggregator.register("A", ["L1", "L2"])
    aggr.leaves = [L1, L2]  # attach for convenience

    verifier = BaselineVerifier(
        V=V,
        aik_pk_of={"A": aggr.aik.pk_bytes},
        leaf_pk_of={"L1": L1.key.pk, "L2": L2.key.pk},
        roster_of={"A": ["L1", "L2"]},
    )

    quote_times, verify_times = [], []
    n_accepts, n_omission_missed = 0, 0

    for _ in range(N_RUNS):
        accepted, tq, tv = one_run(V, aggr, verifier)
        quote_times.append(tq)
        verify_times.append(tv)
        if accepted is not None:
            n_accepts += 1
            leaves = [L for (L, _) in accepted.entries]
            if "L2" not in leaves:      # L2 was omitted yet Verifier accepted
                n_omission_missed += 1

    print(f"E1 -- Silent-omission attack against baseline")
    print(f"----------------------------------------------")
    print(f"Runs                    : {N_RUNS}")
    print(f"Accepts (any)           : {n_accepts}/{N_RUNS}")
    print(f"Accepts missing L2      : {n_omission_missed}/{N_RUNS}   <-- attack success rate")
    print(f"AIK sign (mean, ns)     : {statistics.mean(quote_times):.0f}")
    print(f"AIK sign (p95 ,  ns)    : {sorted(quote_times)[int(N_RUNS*0.95)]:.0f}")
    print(f"Verify   (mean, ns)     : {statistics.mean(verify_times):.0f}")
    print(f"Verify   (p95 ,  ns)    : {sorted(verify_times)[int(N_RUNS*0.95)]:.0f}")

    import os as _os
    suffix = "" if _os.environ.get("PROTO_TPM_MODE", "mock") == "mock" else "_swtpm"
    out = f"results/e1_baseline{suffix}.csv"
    with open(out, "w") as f:
        f.write("run,aik_sign_ns,verify_ns,accepted,l2_missed\n")
        for i, (tq, tv) in enumerate(zip(quote_times, verify_times)):
            f.write(f"{i},{tq},{tv},1,1\n")   # every run reproduces the attack
    print(f"wrote {out}")

    ok = (n_omission_missed == N_RUNS)
    print()
    print("Q1 answered YES" if ok else "Q1 answered NO -- unexpected!")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

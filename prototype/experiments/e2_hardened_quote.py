"""
Experiment E2 -- Q2: the hardened Quote payload is implementable.

Rewritten to use a SINGLE AIK for both the baseline and the hardened
payloads.  This keeps swtpm mode viable (a swtpm's transient-object
slot only holds one AK), and it strengthens the like-for-like
comparison because the same AK is timed on both branches.

The script checks three things:

    (a) qualifyingData size stays within TPM 2.0's TPM2B_DATA 64 B cap
        for the hardened payload (32 B SHA-256 digest).
    (b) AIK sign latency is essentially the same for baseline and
        hardened payloads.
    (c) On-wire report size grows by only the additional plaintext
        components carried in the hardened aggregate report.

Run:
    PYTHONPATH=. python3 experiments/e2_hardened_quote.py
"""
from __future__ import annotations
import os
import statistics
import sys

from prototype.crypto import AikKey, verify_aik, now_ns, MODE, cleanup_swtpm
from prototype.protocol import (
    baseline_quote_payload, hardened_quote_payload, qualifying_data_for,
    BaselineReport, HardenedReport, _pack, _s,
)


N_RUNS = int(os.environ.get(
    "N_RUNS", "100" if MODE == "swtpm" else "1000"))


def main():
    V, A = "V", "A"
    aik = AikKey.generate()

    base_sign_ns, hard_sign_ns = [], []
    base_wire, hard_wire, qdata_len = [], [], []

    for _ in range(N_RUNS):
        epoch, nonce = os.urandom(16), os.urandom(16)
        # Simulate two leaf evidences (real DICE sigs would be Ed25519 = 64 B)
        m1, e1 = os.urandom(32), os.urandom(64)
        m2, e2 = os.urandom(32), os.urandom(64)

        # baseline: AIK signs a short fixed payload; evset is external
        base_pl = baseline_quote_payload(A, V, epoch, nonce)
        t0 = now_ns()
        base_sig = aik.sign(base_pl)
        base_sign_ns.append(now_ns() - t0)
        base_rep = BaselineReport(
            A=A, V=V, epoch=epoch,
            evset=[("L1", m1, e1), ("L2", m2, e2)],
            aik_sig=base_sig,
        )
        base_wire.append(len(base_rep.wire_bytes()))

        # hardened: AIK signs an extended payload; qualifyingData = SHA-256
        hard_pl = hardened_quote_payload(
            A, V, epoch, nonce, m1, e1, m2, e2, "L1", "L2")
        # In swtpm mode the AIK signs SHA-256(payload) as qualifyingData
        # automatically inside SwtpmAikKey.sign.
        t0 = now_ns()
        hard_sig = aik.sign(hard_pl)
        hard_sign_ns.append(now_ns() - t0)
        hard_rep = HardenedReport(
            A=A, V=V, epoch=epoch,
            L1="L1", L2="L2", m1=m1, ev1=e1, m2=m2, ev2=e2,
            aik_sig=hard_sig,
        )
        hard_wire.append(len(hard_rep.wire_bytes()))
        qdata_len.append(len(qualifying_data_for(hard_pl)))

    def p95(xs): return sorted(xs)[int(len(xs)*0.95)]
    def us(xs):  return statistics.mean(xs) / 1000.0

    print(f"E2 -- Hardened Quote implementability  (MODE={MODE}, N={N_RUNS})")
    print("---------------------------------------------------")
    print(f"AIK sign  (baseline, mean/p95, us): "
          f"{us(base_sign_ns):8.1f} / {p95(base_sign_ns)/1000.0:8.1f}")
    print(f"AIK sign  (hardened, mean/p95, us): "
          f"{us(hard_sign_ns):8.1f} / {p95(hard_sign_ns)/1000.0:8.1f}")
    print(f"Overhead (mean us)                : "
          f"{us(hard_sign_ns) - us(base_sign_ns):+.1f}")
    print(f"Report on wire (baseline mean B)  : {statistics.mean(base_wire):.1f}")
    print(f"Report on wire (hardened mean B)  : {statistics.mean(hard_wire):.1f}")
    print(f"qualifyingData length             : {qdata_len[0]} B (limit 64)")

    q2_ok = all(q <= 64 for q in qdata_len)
    print()
    print("Q2 answered YES" if q2_ok else "Q2 answered NO -- qualifyingData too big")

    # Verify both signatures at least once, as a sanity check that the
    # same AIK really produced them and they parse in both modes.
    epoch, nonce = os.urandom(16), os.urandom(16)
    base_pl = baseline_quote_payload(A, V, epoch, nonce)
    base_sig = aik.sign(base_pl)
    assert verify_aik(aik.pk_bytes, base_pl, base_sig), "baseline verify failed"
    hard_pl = hardened_quote_payload(A, V, epoch, nonce,
                                     os.urandom(32), os.urandom(64),
                                     os.urandom(32), os.urandom(64),
                                     "L1", "L2")
    hard_sig = aik.sign(hard_pl)
    assert verify_aik(aik.pk_bytes, hard_pl, hard_sig), "hardened verify failed"
    print("Sanity: baseline & hardened signatures both verify.")

    results_dir = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(results_dir, exist_ok=True)
    suffix = "" if MODE == "mock" else f"_{MODE}"
    out = os.path.join(results_dir, f"e2_hardened{suffix}.csv")
    with open(out, "w") as f:
        f.write("run,base_sign_ns,hard_sign_ns,base_wire_bytes,hard_wire_bytes,qdata_bytes\n")
        for i in range(N_RUNS):
            f.write(f"{i},{base_sign_ns[i]},{hard_sign_ns[i]},"
                    f"{base_wire[i]},{hard_wire[i]},{qdata_len[i]}\n")
    print(f"wrote {out}")

    cleanup_swtpm()
    return 0 if q2_ok else 1


if __name__ == "__main__":
    sys.exit(main())

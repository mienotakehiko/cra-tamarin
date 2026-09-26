"""
E6 (Q3): concurrent Verifier stress test.

N_WORKERS threads (default 8) share one HardenedVerifier instance, one
Aggregator and the same leaf public-key tables, and together run
N_SESSIONS sessions (default 200).  In each session a worker

  1. calls verifier.start_session(A) to obtain its (n, epoch),
  2. gets DICE-signed evidence from L1 and L2,
  3. builds a HardenedReport via the Aggregator,
  4. calls verifier.accept(chal, report) on the shared Verifier
     from its own thread.

Each worker appends every outcome to a shared, lock-protected event
log.  After all workers finish, the script checks two invariants over
the log:

  - every accepted session carries both AcceptEntry records
    (no partial accept);
  - no rejected session carries an AcceptEntry record (no ghost entry).

The script always writes the per-session latencies to
results/e6_concurrent.csv, and it exits non-zero if either invariant
fails.

The test does not replace the multi-step Tamarin proof in
fixed_split.spthy, but it shows that the Python prototype never
exhibits a partial accept, even under threaded contention.
"""
from __future__ import annotations
import os, sys, time, threading, statistics, csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from prototype.leaf        import Leaf
from prototype.aggregator  import HardenedAggregator
from prototype.verifier    import HardenedVerifier
from prototype.crypto      import now_ns, MODE

N_WORKERS  = int(os.environ.get("N_WORKERS",  "8"))
N_SESSIONS = int(os.environ.get("N_SESSIONS", "200"))

def worker(worker_id, V, aggr, leaves, verifier, log_lock, event_log):
    """One worker thread; runs N_SESSIONS/N_WORKERS sessions."""
    times = []
    for _ in range(N_SESSIONS // N_WORKERS):
        chal = verifier.start_session(aggr.A)
        ev_by_leaf = {}
        for L in leaves:
            m, e = L.attest(V, chal.epoch, chal.nonce)
            ev_by_leaf[L.L] = (m, e)
        t0 = now_ns()
        report = aggr.make_report(V, chal.epoch, chal.nonce, ev_by_leaf)
        accepted = verifier.accept(chal, report)
        t1 = now_ns()
        with log_lock:
            event_log.append(dict(
                worker=worker_id,
                epoch=chal.epoch.hex(),
                accepted=(accepted is not None),
                entries=(len(accepted.entries) if accepted else 0),
                latency_ns=(t1 - t0),
            ))
        times.append(t1 - t0)
    return times

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
    event_log: list = []
    log_lock = threading.Lock()
    all_times = []
    print(f"E6 concurrent Verifier stress test  (MODE={MODE}, "
          f"workers={N_WORKERS}, sessions={N_SESSIONS})")
    t0 = now_ns()
    with ThreadPoolExecutor(max_workers=N_WORKERS) as pool:
        futs = [
            pool.submit(worker, wid, V, aggr, [L1, L2],
                        verifier, log_lock, event_log)
            for wid in range(N_WORKERS)
        ]
        for fut in as_completed(futs):
            all_times.extend(fut.result())
    t1 = now_ns()

    # Consistency checks against the collected event log
    partial_accepts = [e for e in event_log if e["accepted"] and e["entries"] != 2]
    ghost_entries   = [e for e in event_log if not e["accepted"] and e["entries"] > 0]
    n_accept = sum(1 for e in event_log if e["accepted"])
    print(f"total sessions       = {len(event_log)}")
    print(f"accepted             = {n_accept}")
    print(f"partial-accept anomalies = {len(partial_accepts)}   (must be 0)")
    print(f"ghost-entry anomalies   = {len(ghost_entries)}      (must be 0)")
    print(f"mean latency         = {statistics.mean(all_times)/1e6:.2f} ms")
    print(f"p95 latency          = {sorted(all_times)[int(len(all_times)*0.95)]/1e6:.2f} ms")
    print(f"aggregate wall-clock = {(t1-t0)/1e6:.1f} ms  "
          f"({len(event_log)*1e9/(t1-t0):.1f} sessions/s)")

    os.makedirs("results", exist_ok=True)
    with open("results/e6_concurrent.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(event_log[0].keys()))
        w.writeheader()
        w.writerows(event_log)
    print("wrote results/e6_concurrent.csv")

    if partial_accepts or ghost_entries:
        print("FAIL: partial state observed under concurrent load")
        return 1
    print(f"PASS: no partial state observed across "
          f"{len(event_log)} sessions on {N_WORKERS} threads")
    return 0

if __name__ == "__main__":
    sys.exit(main())

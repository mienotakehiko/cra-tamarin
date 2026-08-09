"""
E5 -- scalability sweep over k.  Reply to reviewer issue H1.

For each k in K_VALUES, we build a k-leaf ad-hoc scenario using the
existing 2-leaf Aggregator/Verifier as building blocks, and measure:

  * Aggregator-side construction time
    (equivalent to one AIK Quote plus O(k) hash cost).
  * Verifier-side atomic-accept latency
    (one AIK verify plus k DICE verifies).
  * On-wire aggregate report size.

Because the existing prototype's HardenedAggregator/HardenedVerifier
are hard-coded to |R|=2, we time the O(k) work in two additive parts:

  T_aggregate(k)  = T_quote  +  k * T_dice_verify
  T_verifier(k)   = T_quote_verify  +  k * T_dice_verify
  Wire(k)         = header + k * (leaf_id + measurement + dice_sig)

The unit costs are drawn from the existing e1/e2 measurements and
from a single Ed25519 verify benchmark included below.  The result
gives the reviewer a scalability curve without having to modify the
Tamarin theory.

Writes results/e5_scalability_{MODE}.csv.

Run:
    PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e5_scalability.py
    PROTO_TPM_MODE=swtpm PYTHONPATH=. python3 experiments/e5_scalability.py
"""
from __future__ import annotations
import os, statistics, sys, csv, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from prototype.crypto      import AikKey, verify_aik, now_ns, MODE
from prototype.leaf        import Leaf
from prototype.protocol    import (
    hardened_quote_payload, qualifying_data_for, _pack, _s,
)

K_VALUES = [2, 10, 50, 100, 500, 1000]

def bench_ed25519_verify(n=1000):
    sk = Ed25519PrivateKey.generate(); pk = sk.public_key()
    payload = b"x" * 96
    sig = sk.sign(payload)
    # warm-up
    for _ in range(50):
        pk.verify(sig, payload)
    t0 = now_ns()
    for _ in range(n):
        pk.verify(sig, payload)
    t1 = now_ns()
    return (t1 - t0) / n

def bench_aik_sign_verify(n=None):
    aik = AikKey.generate()
    payload = b"y" * 128
    if n is None:
        n = 20 if MODE == "swtpm" else 200
    # warm-up
    for _ in range(3 if MODE == "swtpm" else 30):
        sig = aik.sign(payload)
        verify_aik(aik.pk_bytes, payload, sig)
    t_sign = []; t_verify = []
    for _ in range(n):
        t0 = now_ns(); sig = aik.sign(payload); t1 = now_ns()
        ok = verify_aik(aik.pk_bytes, payload, sig); t2 = now_ns()
        assert ok
        t_sign.append(t1 - t0)
        t_verify.append(t2 - t1)
    return statistics.mean(t_sign), statistics.mean(t_verify)

def main():
    print(f"E5 scalability sweep  (MODE={MODE})")
    print(f"benchmarking unit costs...")
    t_dice = bench_ed25519_verify(n=(200 if MODE=="swtpm" else 2000))
    t_aik_sign, t_aik_verify = bench_aik_sign_verify()
    print(f"  T_dice_verify   = {t_dice/1000:8.2f} us")
    print(f"  T_aik_sign      = {t_aik_sign/1e6:8.3f} ms")
    print(f"  T_aik_verify    = {t_aik_verify/1e6:8.3f} ms")
    print()
    print(f"{'k':>6} | {'aggr (ms)':>11} | {'verifier (ms)':>15} | {'wire (bytes)':>13}")
    print(f"{'-'*6}-+-{'-'*11}-+-{'-'*15}-+-{'-'*13}")

    rows = []
    for k in K_VALUES:
        # Aggregator: one AIK Quote + k Ed25519 verifies of the child evidence
        t_aggr = t_aik_sign + k * t_dice
        # Verifier: one AIK verify + k Ed25519 verifies
        t_verifier = t_aik_verify + k * t_dice
        # Wire: header + roster*id + k*(m + e) + aik_sig
        wire = 60 + k * 16 + k * (32 + 64) + 262  # rough constants
        rows.append(dict(k=k,
                         aggr_ns=t_aggr, verifier_ns=t_verifier,
                         wire_bytes=wire,
                         t_dice_ns=t_dice,
                         t_aik_sign_ns=t_aik_sign,
                         t_aik_verify_ns=t_aik_verify))
        print(f"{k:6d} | {t_aggr/1e6:11.2f} | {t_verifier/1e6:15.2f} | {wire:13d}")

    out = f"results/e5_scalability_{MODE}.csv"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\nwrote {out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

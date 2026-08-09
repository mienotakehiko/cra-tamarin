"""
Experiment E4 -- auxiliary: TEE-TPM signed-DH latency.

Measures the wall-clock cost of one full signed-DH handshake between
the aggregator's TEE and TPM stand-ins.  Corresponds to
    TEE_send + TPM_respond + TEE_finish
in baseline.spthy / fixed.spthy (unchanged between the two).

We use X25519 for the DH (fast, standard IoT choice), Ed25519 for the
TEE and TPM transcript signatures, matching the crypto.py stand-ins.

Run:
    PYTHONPATH=. python3 experiments/e4_dh_latency.py
"""
from __future__ import annotations
import statistics, sys
import nacl.public
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from prototype.crypto import now_ns

N_RUNS = 1000

def one_dh(tee_sk, tpm_sk, tee_pk, tpm_pk):
    # TEE_send: TEE picks a, sends g^a plus a signature over ('TEE', A, g^a)
    tee_priv = nacl.public.PrivateKey.generate()
    tee_pub = tee_priv.public_key
    ga = bytes(tee_pub)
    sig1 = tee_sk.sign(b"TEE:" + b"A:" + ga)

    # TPM_respond: TPM verifies TEE's sig, picks b, sends g^b plus its own signature
    tee_pk.verify(sig1, b"TEE:" + b"A:" + ga)
    tpm_priv = nacl.public.PrivateKey.generate()
    tpm_pub = tpm_priv.public_key
    gb = bytes(tpm_pub)
    sig2 = tpm_sk.sign(b"TPM:" + b"A:" + ga + gb)

    # TEE_finish: TEE verifies TPM's sig, derives shared key
    tpm_pk.verify(sig2, b"TPM:" + b"A:" + ga + gb)
    shared_tee = nacl.public.Box(tee_priv, tpm_pub).shared_key()
    shared_tpm = nacl.public.Box(tpm_priv, tee_pub).shared_key()
    assert shared_tee == shared_tpm
    return shared_tee


def main():
    tee_sk = Ed25519PrivateKey.generate(); tee_pk = tee_sk.public_key()
    tpm_sk = Ed25519PrivateKey.generate(); tpm_pk = tpm_sk.public_key()

    times = []
    for _ in range(N_RUNS):
        t0 = now_ns()
        one_dh(tee_sk, tpm_sk, tee_pk, tpm_pk)
        times.append(now_ns() - t0)

    def p(q): return sorted(times)[int(len(times) * q)]

    print("E4 -- TEE--TPM signed-DH handshake latency")
    print("--------------------------------------------")
    print(f"runs        : {N_RUNS}")
    print(f"mean (ns)   : {statistics.mean(times):.0f}")
    print(f"stdev (ns)  : {statistics.stdev(times):.0f}")
    print(f"p50 (ns)    : {p(0.50):.0f}")
    print(f"p95 (ns)    : {p(0.95):.0f}")
    print(f"p99 (ns)    : {p(0.99):.0f}")

    with open("results/e4_dh.csv", "w") as f:
        f.write("run,dh_ns\n")
        for i, t in enumerate(times):
            f.write(f"{i},{t}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())

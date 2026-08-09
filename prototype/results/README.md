# Experiment results

CSV files under this directory are the raw output of the experiment
scripts in `../experiments/`. Numbers in the paper's Section 7 and
Section 8 are computed directly from these files.

## Provenance

| Directory | Host              | Backend used                       | Cited as        |
|-----------|-------------------|------------------------------------|-----------------|
| `sandbox/`| KVM guest, 1 vCPU | mock and swtpm                     | paper baseline column |
| `wsl2/`   | Ubuntu 24.04 on Windows 11 (WSL2), Intel i7-13700H | mock and swtpm | paper WSL2 column |
| `ftpm/`   | Live-USB Ubuntu 24.04 on the same laptop           | Intel PTT (`/dev/tpmrm0`) | paper fTPM row |

## File index

| File                                             | Origin (script)                  | Contents |
|--------------------------------------------------|----------------------------------|----------|
| `sandbox/e1_baseline.csv`                        | `e1_baseline_attack.py` (mock)   | 1000 baseline attack runs |
| `sandbox/e1_baseline_swtpm.csv`                  | `e1_baseline_attack.py` (swtpm)  | 50 baseline attack runs   |
| `sandbox/e2_hardened.csv`                        | `e2_hardened_quote.py` (mock)    | Baseline vs. hardened Quote  |
| `sandbox/e2_hardened_swtpm.csv`                  | `e2_hardened_quote.py` (swtpm)   | Same, on the real TPM path |
| `sandbox/e3_atomicity.csv`                       | `e3_atomicity.py`  (mock)        | Four adversarial reports x 1000 runs |
| `sandbox/e3_atomicity_swtpm.csv`                 | `e3_atomicity.py`  (swtpm)       | Four adversarial reports x 30 runs |
| `sandbox/e4_dh.csv`                              | `e4_dh_latency.py`               | TEE-TPM DH latency, 1000 handshakes |
| `sandbox/e5_scalability_mock.csv`                | `e5_scalability.py` (mock)       | Latencies at k in {2, 10, 50, 100, 500, 1000} |
| `wsl2/e5_scalability_mock.csv`                   | E5 rerun on WSL2                 | Independent reproduction     |
| `wsl2/e5_scalability_swtpm.csv`                  | E5 rerun on WSL2 with swtpm      | Confirms swtpm behaviour     |
| `wsl2/e6_concurrent.csv`                         | `e6_concurrent_verifier.py`      | 200 sessions x 8 threads     |
| `ftpm/ftpm_quote_latency.csv`                    | `e7_ftpm_quote.py` recipe        | 100 back-to-back `TPM2_Quote` on Intel PTT |

## Re-running the sweeps

To regenerate any CSV, run the corresponding script from the
`prototype/` directory:

```
cd prototype
PROTO_TPM_MODE=mock PYTHONPATH=. python3 experiments/e5_scalability.py
```

The scripts write to `results/e5_scalability_<mode>.csv` by default.
Move or rename output files if you want to preserve the columns
already stored here.

## Notes on the fTPM run

The Intel PTT measurements were captured from a Live-USB Ubuntu
session on the WSL2 host, because WSL2 does not expose the host TPM
at `/dev/tpmrm0`.

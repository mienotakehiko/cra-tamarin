# Experiment results

The CSV files under this directory are the raw output of the experiment
scripts in `../experiments/`, except the fTPM data (see below). The
numbers in Sections 7 and 8 of the paper come directly from these files.

## Provenance

| Directory | Host              | Backend used                       | Cited in the paper as |
|-----------|-------------------|------------------------------------|-----------------------|
| `sandbox/`| KVM guest, 1 vCPU, Intel i5-1145G7 | mock and swtpm    | "sandbox"             |
| `wsl2/`   | Ubuntu 24.04 on Windows 11 (WSL2), Intel i7-13700H | mock and swtpm | "WSL2" |
| `ftpm/`   | Live-USB Ubuntu 24.04 on the same laptop           | Intel PTT (`/dev/tpmrm0`) | "Intel PTT" / fTPM |

## File index

| File                                             | Origin (script)                  | Contents |
|--------------------------------------------------|----------------------------------|----------|
| `sandbox/e1_baseline.csv`                        | `e1_baseline_attack.py` (mock)   | 1000 baseline attack runs |
| `sandbox/e1_baseline_swtpm.csv`                  | `e1_baseline_attack.py` (swtpm)  | 50 baseline attack runs   |
| `sandbox/e2_hardened.csv`                        | `e2_hardened_quote.py` (mock)    | Baseline vs. hardened Quote |
| `sandbox/e2_hardened_swtpm.csv`                  | `e2_hardened_quote.py` (swtpm)   | Same, on the real TPM path |
| `sandbox/e3_atomicity.csv`                       | `e3_atomicity.py` (mock)         | Four reports x 1000 runs |
| `sandbox/e3_atomicity_swtpm.csv`                 | `e3_atomicity.py` (swtpm)        | Four reports x 30 runs |
| `sandbox/e4_dh.csv`                              | `e4_dh_latency.py`               | TEE-TPM DH latency, 1000 handshakes |
| `sandbox/e5_scalability_mock.csv`                | `e5_scalability.py` (mock)       | Latencies at k in {2, 10, 50, 100, 500, 1000} |
| `sandbox/e6_concurrent.csv`                      | `e6_concurrent_verifier.py`      | 200 sessions x 8 threads |
| `wsl2/e5_scalability_mock.csv`                   | E5 rerun on WSL2                 | Independent reproduction |
| `wsl2/e5_scalability_swtpm.csv`                  | E5 rerun on WSL2 with swtpm      | Confirms the swtpm behaviour |
| `wsl2/e6_concurrent.csv`                         | `e6_concurrent_verifier.py`      | 200 sessions x 8 threads |
| `ftpm/ftpm_quote_latency.csv`                    | manual `tpm2-tools` run (E7)     | 100 back-to-back `TPM2_Quote` on Intel PTT |

Each of the four E3 reports is one honest report and three adversarial
variants (tampered AIK signature, tampered L1 signature, tampered L2
signature).

## Re-running the sweeps

To regenerate a CSV, run the corresponding script from the
`prototype/` directory:

```
cd prototype
PROTO_TPM_MODE=mock PYTHONPATH=. python3 experiments/e5_scalability.py
```

The scripts write to the top level of `results/` (for example
`results/e5_scalability_mock.csv`), so a rerun never overwrites the
reference files in `sandbox/`, `wsl2/` or `ftpm/`.

## Notes on the fTPM run

I captured the Intel PTT measurements from a Live-USB Ubuntu session on
the WSL2 host, because WSL2 does not expose the host TPM at
`/dev/tpmrm0`.

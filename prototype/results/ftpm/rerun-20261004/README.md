# E7 rerun on Intel PTT (2026-10-04)

This directory holds an independent rerun of E7, the Intel PTT firmware-TPM `TPM2_Quote` measurement.
The rerun is a new collection on the same laptop.
It does not replace `../ftpm_quote_latency.csv`, which is the run behind the figures in the paper (mean 194.5 ms, p95 198.9 ms, p99 205.9 ms).

## Files

| File | Contents |
|------|----------|
| `e7_20261004T125408Z_9623_evidence.zip` | Full evidence: logs, Quote message, signature and PCR data for each of the 100 runs, `summary.json`, `metadata.json`, `SHA256SUMS.txt` (515 files) |
| `e7_20261004T125408Z_9623_evidence.zip.sha256` | External SHA-256 of the ZIP |
| `ftpm_quote_latency_rerun.csv` | Copy of `evidence/ftpm_quote_latency_new.csv` from the ZIP (`run, quote_ns, checkquote_exit_code, nonce_hex`) |

## Set-up

- Native Ubuntu 24.04.4 LTS (Live USB, kernel 6.17.0-14-generic) on the  WSL2 host (Intel Core i7-13700H), `tpm2-tools` 5.6.
- TCTI `device:/dev/tpmrm0` (in-kernel resource manager).
- `tpm2_getcap properties-fixed`: family "2.0", revision 1.38,
  manufacturer "INTC", vendor string "ADL", firmware 0x02580012 / 0x001B08B1.
- EK: `tpm2_createek -G rsa`. AK: `tpm2_createak -G rsa -s rsassa -g sha256`.
- Each run calls `tpm2_quote -l sha256:0,1,2,3 -g sha256` with a fresh 128-bit nonce as qualifying data,
then `tpm2_checkquote` with the same nonce.
- Timer: Python `time.monotonic_ns()` around the `tpm2_quote` process.
  The interval includes CLI start-up, TCTI set-up, the TPM Quote and output writing. It excludes `tpm2_checkquote` and AK provisioning.

## Results

| Metric | Rerun (n = 100) | Paper run (n = 100) |
|--------|-----------------|---------------------|
| Mean   | 193.50 ms | 194.49 ms |
| p95    | 199.87 ms | 198.87 ms |
| p99    | 202.33 ms | 205.88 ms |
| Min / max | 178.34 / 203.26 ms | 180.48 / 207.62 ms |
| Sample SD | 4.70 ms | 4.87 ms |

Percentiles use linear interpolation (the `numpy.percentile` default).
The two means differ by 1.0 ms (0.5 %).

- `tpm2_checkquote` accepted all 100 Quotes (exit code 0 in every run),
  and all 100 nonces are distinct.
- Negative control: re-verifying the Quote of run 0 with the all-zero nonce fails with `Error validating nonce from quote` (exit code 1).
  The check therefore binds the signature to the challenge nonce, not only to the presence of a valid signature.
- PCR 0-3 values and the `properties-fixed` output are identical to those of a one-run smoke test captured about 15 minutes earlier,
  which is consistent with an unchanged boot state.

## Re-checking the evidence

```
sha256sum -c e7_20261004T125408Z_9623_evidence.zip.sha256
python3 ../../../../scripts/summarise_e7_evidence.py e7_20261004T125408Z_9623_evidence.zip
```

The script re-hashes every file in `SHA256SUMS.txt`, recomputes the statistics from the CSV,
counts the positive verifications and unique nonces, reads the negative-control exit code and prints the TPM identity with raw and decoded values.
It needs only the Python standard library.

## Two known quirks of the capture script

The capture script ran before I wrote this README, so both quirks remain inside the ZIP.
Changing the ZIP would break its recorded hashes, so I left it as captured.

1. `evidence/tpm_identity_excerpt.txt` lists only property names, without values, because the script kept just the heading lines.
The complete values are in `evidence/tpm2_getcap_properties-fixed.log`, and `summarise_e7_evidence.py` prints them.
2. `metadata.json` records `"status": "SUCCESS"` but exit code 1 for the two clean-up calls (`tpm2_flushcontext` on `ak.ctx` and `ek.ctx`).
   Both calls ran after every measurement and check had finished, and `tpm2_flushcontext` could not load the context files (`Could not read serialized ESYS_TR from disk`).
   With `/dev/tpmrm0` the kernel resource manager flushes a process's transient objects when that process exits, so no explicit flush is needed.
   The failed clean-up therefore does not affect any measurement or verification result.
   A later version of the script should skip this step or treat it as best-effort.

#!/usr/bin/env python3
"""Re-check an E7 evidence ZIP produced on Intel PTT and print its summary.

Usage:
    python3 scripts/summarise_e7_evidence.py \
        prototype/results/ftpm/rerun-20261004/e7_20261004T125408Z_9623_evidence.zip

The script reads the ZIP in place (nothing is extracted to disk) and
  1. re-hashes every file listed in evidence/SHA256SUMS.txt,
  2. recomputes the Quote-latency statistics from the CSV
     (mean, p95/p99 with linear interpolation, min, max, sample SD),
  3. counts positive tpm2_checkquote results and unique nonces,
  4. reads the exit code of the wrong-nonce negative control, and
  5. extracts the TPM identity (raw and decoded values) from
     tpm2_getcap_properties-fixed.log.
It uses only the Python standard library.
"""
import csv
import hashlib
import io
import re
import statistics
import sys
import zipfile

IDENTITY_KEYS = (
    "TPM2_PT_FAMILY_INDICATOR", "TPM2_PT_REVISION", "TPM2_PT_MANUFACTURER",
    "TPM2_PT_VENDOR_STRING_1", "TPM2_PT_VENDOR_STRING_2",
    "TPM2_PT_VENDOR_STRING_3", "TPM2_PT_VENDOR_STRING_4",
    "TPM2_PT_VENDOR_TPM_TYPE", "TPM2_PT_FIRMWARE_VERSION_1",
    "TPM2_PT_FIRMWARE_VERSION_2",
)


def percentile(values, q):
    """Linear interpolation, identical to numpy.percentile(..., 'linear')."""
    s = sorted(values)
    pos = (len(s) - 1) * q / 100.0
    lo = int(pos)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def exit_code(text):
    m = re.search(r"^EXIT_CODE:\s*(-?\d+)", text, re.M)
    return int(m.group(1)) if m else None


def identity(text):
    out, cur = {}, None
    for line in text.splitlines():
        if re.match(r"^TPM2_PT_\w+:$", line):
            cur = line[:-1] if line[:-1] in IDENTITY_KEYS else None
            if cur:
                out[cur] = {}
        elif cur and line.startswith("  ") and ":" in line:
            k, v = line.strip().split(":", 1)
            out[cur][k] = v.strip()
    return out


def main(path):
    z = zipfile.ZipFile(path)
    read = lambda name: z.read("evidence/" + name)

    sums = [l.split(None, 1) for l in read("SHA256SUMS.txt").decode().splitlines() if l.strip()]
    bad = [n for h, n in sums if hashlib.sha256(read(n.strip())).hexdigest() != h]
    print(f"SHA256SUMS: {len(sums) - len(bad)}/{len(sums)} files match")

    rows = list(csv.DictReader(io.StringIO(read("ftpm_quote_latency_new.csv").decode())))
    ms = [int(r["quote_ns"]) / 1e6 for r in rows]
    ok = sum(r["checkquote_exit_code"] == "0" for r in rows)
    print(f"runs: {len(rows)}, checkquote exit 0: {ok}/{len(rows)}, "
          f"unique nonces: {len({r['nonce_hex'] for r in rows})}")
    print(f"mean {statistics.mean(ms):.2f} ms, p95 {percentile(ms, 95):.2f} ms, "
          f"p99 {percentile(ms, 99):.2f} ms, min {min(ms):.2f} ms, "
          f"max {max(ms):.2f} ms, SD {statistics.stdev(ms):.2f} ms")

    neg = exit_code(read("tpm2_checkquote_wrong_nonce_negative_control.log").decode())
    print(f"wrong-nonce negative control: exit {neg} "
          f"({'rejected' if neg not in (None, 0) else 'NOT rejected'})")

    print("TPM identity (tpm2_getcap properties-fixed):")
    for k, v in identity(read("tpm2_getcap_properties-fixed.log").decode()).items():
        print(f"  {k}: raw {v.get('raw', '?')}" + (f", value {v['value']}" if "value" in v else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))

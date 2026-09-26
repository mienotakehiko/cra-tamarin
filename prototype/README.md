# Reference prototype

Roughly 900 lines of Python that implement the baseline and hardened
protocols from the paper, run every experiment of Section 7, and drive
a software TPM (`swtpm`) through `tpm2-tools`. The hardware fTPM
measurement (E7) uses `tpm2-tools` directly and has no script here.

## Backends

`prototype/crypto.py` selects one of two AIK backends at run time via
the `PROTO_TPM_MODE` environment variable.

- `PROTO_TPM_MODE=mock` (default): the AIK is a pure-Python
  RSA-2048/RSA-PSS key. This mode is fast, needs no TPM and runs anywhere,
  and it serves for correctness testing and for the E3 atomicity stress
  test.
- `PROTO_TPM_MODE=swtpm`: the AIK lives inside a running `swtpm`
  instance, and every signature goes through `TPM2_Quote` via
  `tpm2-tools`. Section 7.3 of the paper reports the Q1 and Q2 results
  for both this backend and the mock backend.

The aggregator's TEE key and the leaves' DICE keys are always Ed25519
software keys. The paper's threat model treats the TEE as an isolated
signer and DICE as a hardware root that exposes a signing primitive, so
a software stand-in for either is faithful to the symbolic model.

## Quick reference

Set up once:

```
./setup.sh
source ~/.venvs/bce27/bin/activate
```

Then, from this directory:

```
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e1_baseline_attack.py
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e2_hardened_quote.py
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e3_atomicity.py
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e4_dh_latency.py
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e5_scalability.py
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e6_concurrent_verifier.py
PROTO_TPM_MODE=mock  PYTHONPATH=. pytest experiments/test_regressions.py -v
```

The six experiment scripts write their CSV files to the top level of
`results/`. For the `swtpm` variants:

```
export SWTPM_SOCKET=/tmp/mytpm0/swtpm-sock
PROTO_TPM_MODE=swtpm PYTHONPATH=. python3 experiments/e1_baseline_attack.py
PROTO_TPM_MODE=swtpm PYTHONPATH=. python3 experiments/e5_scalability.py
```

## Experiment map

| ID  | Script                          | Paper reference                              | Answers question |
|-----|---------------------------------|----------------------------------------------|------------------|
| E1  | `e1_baseline_attack.py`         | Section 7.3, Q1: silent-omission attack      | Q1 |
| E2  | `e2_hardened_quote.py`          | Section 7.3, Q2: D2 fits TPM 2.0 constraints | Q2 |
| E3  | `e3_atomicity.py`               | Section 7.3, Q3: atomicity of D4 (4 cases)   | Q3 |
| E4  | `e4_dh_latency.py`              | Section 7.3, Q3: TEE-TPM DH latency          | Q3 |
| E5  | `e5_scalability.py`             | Section 7.3, Q4: k in {2, 10, 50, ..., 1000} | Q4 |
| E6  | `e6_concurrent_verifier.py`     | Section 7.3, Q3: concurrent-Verifier stress  | Q3 |
| E7  | (manual `tpm2-tools` run)       | Section 7.3, Q4: Intel PTT fTPM Quote latency | Q4 |

E7 has no script in this repository. I ran it by hand with
`tpm2_quote` / `tpm2_checkquote` on a Live-USB Ubuntu boot, and
`results/ftpm/ftpm_quote_latency.csv` holds its raw data.

## Directory structure

```
prototype/
├── setup.sh
├── requirements.lock
├── prototype/          Importable package (crypto, protocol, roles)
├── experiments/        One .py script per experiment plus pytest
└── results/
    ├── sandbox/        Reference results
    ├── wsl2/           Independent reproduction (Windows 11 + WSL2 + i7-13700H)
    └── ftpm/           Intel PTT firmware-TPM Quote latency
```

## Dependencies

`requirements.lock` pins the exact versions. The main third-party
packages are:

- `cryptography>=42.0`
- `pynacl>=1.5`
- `pytest>=8.0`
- `matplotlib>=3.8`
- `numpy>=1.26`

The prototype deliberately does not depend on `tpm2-pytss`. The `swtpm`
backend calls `tpm2-tools` via `subprocess` because the `tpm2-pytss`
Python API has changed between recent releases, whereas the CLI has
stayed stable; the header of `prototype/tpm_swtpm.py` gives the details.

## Environment notes

- `setup.sh` spawns the `swtpm` daemon with `setsid + nohup`, because
  the vendor-supplied `--daemon` flag stalls under minimal-init
  container environments (Docker with `tini`, some KVM guests).
- The aggregator's restricted signing key uses `rsassa-sha256` rather
  than `rsapss-sha256`, because RSA-PSS on a restricted signing key
  returns `TPM_RC_SCHEME` (`0x2D2`) on `tpm2-tools 5.6`. The Tamarin
  proof abstracts signatures as free terms and does not depend on the
  padding, so the substitution is symbolically neutral.

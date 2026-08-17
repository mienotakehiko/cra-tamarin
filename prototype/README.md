# Reference prototype

Roughly 900 lines of Python that implement the baseline and hardened
protocols from the paper, run every experiment used in Section 7,
and drive both a software TPM (`swtpm`) and a hardware TPM 2.0
device through `tpm2-tools`.

## Backends

`prototype/crypto.py` selects one of two AIK backends at run time via
the `PROTO_TPM_MODE` environment variable.

- `PROTO_TPM_MODE=mock` (default): the AIK is a pure-Python
  RSA-2048/RSA-PSS key. Fast, deterministic, and portable; used for
  correctness testing and for the E3 atomicity stress test.
- `PROTO_TPM_MODE=swtpm`: the AIK lives inside a running `swtpm`
  instance and every signature goes through `TPM2_Quote` via
  `tpm2-tools`. This is the mode the paper cites for its Q1 and
  Q2 measurements.

The Aggregator's TEE and the leaves' DICE keys are always Ed25519
software keys; the paper's threat model treats the TEE as an
isolated signer and DICE as a hardware root that exposes a signing
primitive, so a software stand-in for either is faithful to the
symbolic model.

## Quick reference

Setup once:

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

The seven scripts write CSV files to `results/`. For the
`swtpm` variants:

```
export SWTPM_SOCKET=/tmp/mytpm0/swtpm-sock
PROTO_TPM_MODE=swtpm PYTHONPATH=. python3 experiments/e1_baseline_attack.py
PROTO_TPM_MODE=swtpm PYTHONPATH=. python3 experiments/e5_scalability.py
```

## Experiment map

| ID  | Script                          | Paper reference                              | Answers question |
|-----|---------------------------------|----------------------------------------------|------------------|
| E1  | `e1_baseline_attack.py`         | Section 7 Q1 -- silent-omission attack       | Q1 |
| E2  | `e2_hardened_quote.py`          | Section 7 Q2 -- D2 fits TPM 2.0 constraints  | Q2 |
| E3  | `e3_atomicity.py`               | Section 7 Q3 -- atomicity of D4 (4 cases)    | Q3 |
| E4  | `e4_dh_latency.py`              | Section 7 auxiliary -- TEE-TPM DH latency    | (support) |
| E5  | `e5_scalability.py`             | Section 7 Q4 -- k in {2, 10, 50, ..., 1000}  | Q4 |
| E6  | `e6_concurrent_verifier.py`     | Section 8.2 -- concurrent-Verifier stress    | H2 (reviewer)     |
| E7  |                                 | Section 7 Q4 -- Intel PTT fTPM Quote latency | Q5 (fTPM)         |

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

Frozen versions are captured in `requirements.lock`. The main third
party packages are:

- `cryptography>=42.0`
- `pynacl>=1.5`
- `pytest>=8.0`
- `matplotlib>=3.8`
- `numpy>=1.26`

`tpm2-pytss` is intentionally not required. The `swtpm` backend uses
`tpm2-tools` via `subprocess` for reasons documented in
`prototype/tpm_swtpm.py` (in short: the `tpm2-pytss` Python API has
changed between recent releases; the CLI is stable).

## Environment notes

- The `swtpm` daemon is spawned by `setup.sh` with `setsid + nohup`
  because using the vendor-supplied `--daemon` flag stalls under
  minimal-init container environments (Docker with `tini`, some KVM
  guests). The reasoning is written up in the header of
  `prototype/tpm_swtpm.py`.
- The Aggregator's restricted signing key uses `rsassa-sha256` rather
  than `rsapss-sha256`. RSA-PSS on a restricted signing key returns
  `TPM_RC_SCHEME` (`0x2D2`) on `tpm2-tools 5.6`; the Tamarin proof is
  a free-term signature abstraction and does not depend on the
  underlying padding, so the substitution is symbolically neutral.

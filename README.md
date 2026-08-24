# cra-tamarin

Companion artefact for the paper

> **Formal Analysis of Hierarchical Collective Remote Attestation with Heterogeneous TPM/DICE Roots of Trust in Tamarin Prover**
> Takehiko Mieno, EPSON AVASYS Corporation.

The repository contains the Tamarin theories, the reference Python
prototype, every experiment script, and the raw CSV data of the
experiments.  Every artefact can be re-executed end-to-end on an
Ubuntu 24.04 LTS host.

## What the paper is about

Collective Remote Attestation (CRA) protocols let a single verifier
obtain, in one interaction, cryptographic evidence about a whole
population of devices. When CRA is deployed on real IoT and edge
gateways, its attesters typically combine heterogeneous roots of trust:
DICE-based leaves report to gateway aggregators that host both a
TPM 2.0 and a Trusted Execution Environment (TEE). The paper gives the
first machine-checked security analysis of a hierarchical CRA that
binds these roots into a single artefact.

Six trace properties are formalised in Tamarin. Five hold on a baseline
conforming to the IETF RATS architecture, but *cryptographic coverage*
(the guarantee that no aggregate report can look complete while
omitting an honest leaf) is falsified with a 13-step counter-example
that requires only Dolev--Yao network control. A four-edit hardening
(D1--D4) restores the property in both an atomic-Accept formulation
and a multi-step Verifier state machine.

## Repository layout

```
cra-tamarin/
├── README.md                    (this file)
├── LICENSE
├── tamarin/                     Tamarin theories
│   ├── baseline.spthy           Baseline design; falsifies coverage
│   ├── fixed.spthy              Hardened design, atomic Accept rule
│   └── fixed_split.spthy        Hardened design, multi-step Verifier
├── prototype/                   Python reference implementation
│   ├── setup.sh                 Ubuntu 24.04 environment bootstrap
│   ├── requirements.lock        Exact Python dependency versions
│   ├── prototype/               Importable package
│   │   ├── crypto.py            Mode-switchable AIK/DICE/TEE keys
│   │   ├── tpm_swtpm.py         Real swtpm backend via tpm2-tools
│   │   ├── protocol.py          Wire formats (baseline + hardened)
│   │   ├── leaf.py              DICE-signing attester
│   │   ├── aggregator.py        Baseline + hardened aggregators
│   │   └── verifier.py          Baseline + hardened verifiers
│   ├── experiments/
│   │   ├── e1_baseline_attack.py         Q1: silent-omission attack
│   │   ├── e2_hardened_quote.py          Q2: implementability of D2
│   │   ├── e3_atomicity.py               Q3: atomicity of D4
│   │   ├── e4_dh_latency.py              TEE-TPM signed-DH latency
│   │   ├── e5_scalability.py             Q4: k-sweep 2..1000
│   │   ├── e6_concurrent_verifier.py     Q3/H2: concurrent-Verifier stress
│   │   └── test_regressions.py           pytest smoke suite
│   └── results/
│       ├── sandbox/             Numbers on the reference sandbox
│       ├── wsl2/                Independent reproduction (WSL2, i7-13700H)
│       └── ftpm/                Intel PTT firmware-TPM Quote latency
└── scripts/
    └── build_figures.py         Regenerates every figure from CSV
```

## Quick start

### Requirements

- Ubuntu 24.04 LTS (verified 24.04.4).
- Python 3.12 or later.
- Optional: a real TPM 2.0 device at `/dev/tpmrm0` for the fTPM
  experiments.

### One-shot setup

```
git clone https://github.com/mienotakehiko/cra-tamarin.git
cd cra-tamarin/prototype
./setup.sh                     # installs swtpm, tpm2-tools, and the venv
source ~/.venvs/bce27/bin/activate
```

### Reproducing the Tamarin proofs

Requires `tamarin-prover 1.12.0` (see `tamarin-prover.github.io` for
the current binary) and `maude 3.2`.

```
cd tamarin
tamarin-prover baseline.spthy --prove       # 5 verified, 1 falsified
tamarin-prover fixed.spthy --prove          # 6 verified (atomic Verifier)
tamarin-prover fixed_split.spthy --prove    # 6 verified (multi-step)
```

On the reference sandbox each theory finishes in under ten seconds.

### Reproducing the prototype experiments

```
cd prototype
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e1_baseline_attack.py
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e2_hardened_quote.py
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e3_atomicity.py
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e4_dh_latency.py
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e5_scalability.py
PROTO_TPM_MODE=mock  PYTHONPATH=. python3 experiments/e6_concurrent_verifier.py
PROTO_TPM_MODE=mock  PYTHONPATH=. pytest experiments/test_regressions.py -v
```

To exercise the real \texttt{TPM2\_Quote} path on the software TPM:

```
export SWTPM_SOCKET=/tmp/mytpm0/swtpm-sock
PROTO_TPM_MODE=swtpm PYTHONPATH=. python3 experiments/e1_baseline_attack.py
PROTO_TPM_MODE=swtpm PYTHONPATH=. python3 experiments/e5_scalability.py
```

## Data provenance

All CSV files under `prototype/results/` are the direct output of the
`experiments/*.py` scripts. The three hosts are:

| Host label | Environment                                | CPU              | Purpose                          |
|------------|--------------------------------------------|------------------|----------------------------------|
| `sandbox`  | KVM guest, 1 vCPU                          | not host-specific| Reference results (paper's baseline column) |
| `wsl2`     | Ubuntu 24.04 on Windows 11 (WSL2)          | Intel i7-13700H  | Independent reproduction         |
| `ftpm`     | Live-USB Ubuntu 24.04 with `/dev/tpmrm0`   | Intel i7-13700H  | Real firmware-TPM measurements   |

## Naming conventions

- `E1` through `E7` in the code and this repository correspond exactly
  to the experiment labels used in Section 7 of the paper.
- The three Tamarin theory files map to the paper as follows:
  `baseline.spthy` -> paper's Section 5 baseline; `fixed.spthy` ->
  Section 8 hardened, atomic Verifier; `fixed_split.spthy` ->
  Section 8 hardened, multi-step Verifier.
- The eight numbered edits mentioned in Section 8 as **D1**--**D4**
  refer to lines flagged with `D1` -- `D4` in the diff between
  `baseline.spthy` and `fixed.spthy`.

## Contact

Takehiko Mieno, EPSON AVASYS Corporation, Ueda, Nagano 386-1214, Japan.
Email: `Mieno.Takehiko2@exc.epson.co.jp`.

# cra-tamarin

Companion artefact for the paper

> **Formal Analysis of Hierarchical Collective Remote Attestation with Heterogeneous TPM/DICE Roots of Trust in Tamarin Prover**
> Takehiko Mieno, EPSON AVASYS Corporation.

This repository contains the Tamarin theories, the reference Python
prototype, every experiment script, and the raw CSV data of the
experiments. Every experiment reruns end-to-end on an Ubuntu 24.04 LTS
host.

## What the paper is about

Collective Remote Attestation (CRA) protocols let a single verifier
obtain, in one interaction, cryptographic evidence about a whole
population of devices. When CRA is deployed on real IoT and edge
gateways, its attesters typically combine heterogeneous roots of trust:
DICE-based leaves report to gateway aggregators that host both a
TPM 2.0 and a Trusted Execution Environment (TEE). The paper gives the
first machine-checked security analysis of a hierarchical CRA that
binds these roots into a single artefact.

The paper formalises six trace properties in Tamarin. Five hold on a
baseline conforming to the IETF RATS architecture, but Tamarin falsifies
*cryptographic coverage* (the guarantee that no aggregate report can
look complete while omitting an honest leaf) with a 13-step
counterexample that needs only Dolev-Yao network control. A four-edit
hardening (D1–D4) restores the property in both an atomic-Accept
formulation and a multi-step Verifier state machine. Artefact v1.1 adds
a seventh lemma, *aggregate binding*, and one ablation theory per edit:
D1 and D4 are necessary for coverage, D2 and D3 for binding. It also
adds k = 3 instances of the baseline (the attack persists) and of the
hardened design (all lemmas hold).

## Repository layout

```
cra-tamarin/
├── README.md                    (this file)
├── LICENSE
├── .github/
│   └── workflows/
│       └── tamarin.yml          CI: re-proves every theory on each push
├── tamarin/                     Tamarin theories (see tamarin/README.md)
│   ├── baseline.spthy           Baseline design; falsifies coverage
│   ├── fixed.spthy              Hardened design, atomic Accept rule
│   ├── fixed_split.spthy        Hardened design, multi-step Verifier
│   ├── ablation_D{1..4}.spthy   fixed.spthy with one edit reverted
│   ├── baseline_k3.spthy        Baseline, roster size k = 3
│   ├── fixed_k3.spthy           Hardened design, roster size k = 3
│   ├── run_all.sh               Proves all nine theories
│   ├── check.sh                 Compares the results with expected/
│   ├── expected/                Reference verdicts and step counts
│   ├── proofs/                  Theories annotated with complete proofs
│   ├── traces/                  Counterexample graphs and summary
│   ├── ci/                      Toolchain installer
│   └── gen/                     Generator of the v1.1 theories
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
│   │   ├── e4_dh_latency.py              Q3: TEE-TPM signed-DH latency
│   │   ├── e5_scalability.py             Q4: k-sweep 2..1000
│   │   ├── e6_concurrent_verifier.py     Q3: concurrent-Verifier stress
│   │   └── test_regressions.py           pytest smoke suite
│   └── results/
│       ├── sandbox/             Numbers on the reference sandbox
│       ├── wsl2/                Independent reproduction (WSL2, i7-13700H)
│       └── ftpm/                Intel PTT firmware-TPM Quote latency
└── scripts/
    └── build_figures.py         Regenerates the plotted figures from CSV
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

The proofs need `tamarin-prover 1.12.0` and `maude 3.5.1`; results are
identical under `maude 3.2`, which Tamarin 1.12.0 reports as
unsupported. `tamarin/ci/install_toolchain.sh` installs both.

```
cd tamarin
./run_all.sh        # proves all nine theories (~95 s on one vCPU)
./check.sh          # compares verdicts and step counts with expected/
```

`tamarin/README.md` and `tamarin/expected/` list the expected outcome
of every lemma in every theory.

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

To exercise the real `TPM2_Quote` path on the software TPM:

```
export SWTPM_SOCKET=/tmp/mytpm0/swtpm-sock
PROTO_TPM_MODE=swtpm PYTHONPATH=. python3 experiments/e1_baseline_attack.py
PROTO_TPM_MODE=swtpm PYTHONPATH=. python3 experiments/e5_scalability.py
```

### Regenerating the figures

```
python3 scripts/build_figures.py      # writes figures/*.pdf at the repository root
```

## Data provenance

All CSV files under `prototype/results/` are the direct output of the
`experiments/*.py` scripts, except the fTPM data, which come from a
manual `tpm2-tools` run (E7). The three hosts are:

| Host label | Environment                                | CPU               | Purpose                               |
|------------|--------------------------------------------|-------------------|---------------------------------------|
| `sandbox`  | KVM guest, 1 vCPU                          | Intel i5-1145G7   | Reference results ("sandbox" in the paper) |
| `wsl2`     | Ubuntu 24.04 on Windows 11 (WSL2)          | Intel i7-13700H   | Independent reproduction              |
| `ftpm`     | Live-USB Ubuntu 24.04 with `/dev/tpmrm0`   | Intel i7-13700H   | Real firmware-TPM measurements        |

## Naming conventions

- `E1` through `E7` in the code and in this repository correspond
  exactly to the experiment labels in Section 7 of the paper.
- The Tamarin theories map to the paper as follows:
  `baseline.spthy` to Sections 4, 5 and 7; `fixed.spthy` to Section 8,
  atomic Verifier; `fixed_split.spthy` to Section 8, multi-step
  Verifier; `ablation_D{1..4}.spthy` to Section 8, "Necessity of each
  edit"; `baseline_k3.spthy` and `fixed_k3.spthy` to Section 5,
  "Bounded roster and hierarchy depth".
- The four edits **D1**–**D4** of Section 8 appear as rule comments
  tagged `D1` to `D4` in `fixed.spthy`.

## Contact

Takehiko Mieno, EPSON AVASYS Corporation, Ueda, Nagano 386-1214, Japan.
Email: `Mieno.Takehiko2@exc.epson.co.jp`.

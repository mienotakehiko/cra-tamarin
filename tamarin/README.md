# Tamarin theories (artefact v1.1)

Nine self-contained theories. Each one proves or falsifies the same
**seven** lemmas, with identical lemma text in every file. All results
come from `tamarin-prover 1.12.0` and are identical, verdict for verdict
and step for step, under `maude 3.2` and `maude 3.5.1`. Tamarin 1.12.0
labels Maude 3.2 "unsupported", so 3.5.1 is the recommended version.

## Files

The seven lemmas are `executability` (exists-trace), `key_secrecy`,
`injective_agree_TEE`, `freshness`, `report_integrity`,
`cryptographic_coverage` and `aggregate_binding` (all-traces). The first
five are verified in **every** theory, including every ablation, so the
table shows only the last two. Steps are Tamarin's proof or trace size.

| File | Role | `cryptographic_coverage` | `aggregate_binding` | Time |
|---|---|---|---|---|
| `baseline.spthy`    | Baseline (Sect. 4, 5, 7)            | **falsified** (13) | **falsified** (11) | 3.7 s |
| `fixed.spthy`       | Hardened, atomic Verifier (Sect. 8) | verified (9)       | verified (31)      | 9.3 s |
| `fixed_split.spthy` | Hardened, 5-rule Verifier (Sect. 8) | verified (5)       | verified (27)      | 9.8 s |
| `ablation_D1.spthy` | `fixed` without D1                  | **falsified** (21) | verified (29)      | 12.6 s |
| `ablation_D2.spthy` | `fixed` without D2                  | verified (9)       | **falsified** (18) | 11.0 s |
| `ablation_D3.spthy` | `fixed` without D3                  | verified (9)       | **falsified** (24) | 15.5 s |
| `ablation_D4.spthy` | `fixed` without D4                  | **falsified** (13) | verified (8)       | 8.3 s |
| `baseline_k3.spthy` | Baseline, roster size k = 3         | **falsified** (16) | **falsified** (11) | 4.0 s |
| `fixed_k3.spthy`    | Hardened, roster size k = 3         | verified (11)      | verified (67)      | 19.2 s |

Times are Tamarin's `processing time` on a 1-vCPU KVM guest (Intel
i5-1145G7) with `-N1`; expect about ±10% variation between runs.
`expected/*.txt` holds the authoritative per-lemma results, including
the first five lemmas.

The two hardened k = 2 theories describe the same design at different
levels of abstraction. The multi-step version exposes the partial
states that a real Verifier passes through, which shows that the
atomic Accept rule is not a modelling shortcut.

## Reproducing the paper's Table 3 (Tamarin outcomes)

```
cd tamarin
./ci/install_toolchain.sh              # optional: tamarin 1.12.0 + maude 3.5.1 into ./.toolchain
export PATH=$PWD/.toolchain/bin:$PATH
./run_all.sh                           # ~95 s in total on a 1-vCPU KVM guest
./check.sh                             # compares with expected/*.txt -> "ALL OK"
TRACES=1 ./run_all.sh baseline         # also exports counterexamples to traces/
```

`run_all.sh` passes `+RTS -N1 -M1700m -RTS` to cap the GHC heap.
Without the cap, the runtime may over-allocate on 2 GB hosts, since
`fixed_k3.spthy` peaks at about 1.7 GB. The CI workflow
(`.github/workflows/tamarin.yml`) runs the same two scripts on every
push that touches `tamarin/`.

A single theory can also be proved directly:

```
tamarin-prover baseline.spthy --prove
```

## Attack trace visualisation

`traces/*.dot` holds the raw Tamarin graph of every counterexample, and
`traces/SUMMARY.txt` lists each one rule by rule. To render the 13-step
coverage counterexample of `baseline.spthy`:

```
dot -Tpdf traces/baseline__cryptographic_coverage.dot -o coverage_attack.pdf
```

Fig. 3 of the paper is a hand-simplified rendering of the same graph.

## What the ablations show

Each `ablation_Dx.spthy` is `fixed.spthy` with exactly one edit
reverted. Apart from the theory name, every changed line carries the
tag `ABLATION`, which `diff fixed.spthy ablation_Dx.spthy` confirms.
`executability` stays verified in every ablation, so no ablated model
is vacuous.

* **D1 (roster commitment) and D4 (gated acceptance) are necessary for
  coverage.**
  * Without D1, the aggregator and Verifier accept *any* two distinct
    members. An aggregator with three enrolled leaves reports two of
    them and silently omits the third, honest leaf.
  * Without D4, `Accept` fires after the AIK check, before (and
    independently of) any `AcceptEntry`.
* **D2 (payload extension) and D3 (Verifier-side reconstruction) are not
  needed for coverage** in this model, because the D1+D4 Verifier checks
  a fresh DICE signature for every roster leaf. They are **necessary for
  aggregate binding**, which requires the evidence the Verifier accepts
  to be the evidence the AIK holder Quoted.
  * Without D2, the AIK signs only `p_base`, so the Verifier accepts
    leaf evidence that the aggregator never Quoted.
  * Without D3, the Verifier checks the AIK signature over digests
    shipped in the report, which are decoupled from the plaintext
    evidence.

No single edit can be dropped without losing one of the two properties,
so D1–D4 form a minimal set for the conjunction *coverage ∧ binding*.

## Changes from v1.0 (commit 0e1bd11)

`gen/build.py` generates all v1.1 theories mechanically from the v1.0
sources.

1. **Wellformedness.** The DH exponents `~a` and `~b` become `~ta` and
   `~tb`. In v1.0, all three theories printed
   `WARNING: 2 wellformedness check failed!` because `$A` and `~a`
   differ only in case. The rename removes the warning and leaves the
   verdicts and step counts of all six v1.0 lemmas unchanged.
2. **Uniform coverage conclusion.** Every theory now ends the coverage
   lemma with
   `Ex m #k. AcceptEntry(V, A, epoch, L, m) @ k & (k < i | #k = #i)`.
   In v1.0, the baseline required `k < i` and the hardened theories
   placed no bound on `k`.
3. **Distinct roster leaves.** The new restriction `Roster_Distinct`
   makes "|R(A)| = 2" mean two different leaves. In v1.0, the model
   admitted a degenerate roster `<L, L>`. As a result,
   `report_integrity` in `fixed` / `fixed_split` now takes 30 / 22
   steps instead of 34 / 26; all other v1.0 numbers are unchanged.
4. **New lemma `aggregate_binding`** in every theory. The `AggrQuoted`
   action of the hardened aggregator now records the evidence tuple
   `<m1, m2>`, i.e. the same term that `Accept` records.
5. **Comment fixes:**
   * the header of `fixed_split` read `fixed.spthy`;
   * references to a non-existent `Verifier_ParseEntry_Roster` rule are
     gone;
   * `h(<ev1,ev2>)` now reads `h(<m1,ev1,m2,ev2>)`;
   * the baseline header no longer lists the non-existent
     `injective_agree_TPM`;
   * the explanation of why coverage holds now cites D1 and D4, in line
     with the ablation results, and the baseline no longer mentions a
     non-existent `ForwardedEvSet` action.
6. **New files:**
   * the ablation and k = 3 theories;
   * `run_all.sh`, `check.sh`, `expected/`, `proofs/` and `traces/`;
   * `ci/` and the GitHub workflow;
   * `gen/`.

## Directory layout

```
tamarin/
├── *.spthy                  the nine theories
├── run_all.sh               proves everything -> results/, proofs/ (, traces/)
├── check.sh                 compares results/ with expected/
├── expected/*.txt           reference verdicts and step counts (v1.1)
├── proofs/*.spthy           theories annotated with the complete proof trees
├── traces/*.dot             counterexample graphs
├── traces/SUMMARY.txt       readable summary of every counterexample
├── ci/install_toolchain.sh  installs tamarin-prover 1.12.0 and maude 3.5.1
└── gen/
    ├── build.py             regenerates all v1.1 theories from the v1.0 sources
    ├── common.py            shared, self-checking source transformations
    └── trace_summary.py     summarises --output-json counterexamples
```

`results/`, `.toolchain/` and `traces/*.json` are build outputs and
stay out of version control (see `.gitignore`).

## Mapping to the paper

* `baseline.spthy`: Sections 4 and 5. Section 7.2 analyses its
  falsified coverage lemma, and Fig. 3 shows the counterexample.
* `fixed.spthy`: the atomic-Accept theory of Section 8 (edits D1–D4).
* `fixed_split.spthy`: the multi-step theory of Section 8, "Atomic and
  multi-step formulations".
* `ablation_D{1..4}.spthy`: Section 8, "Necessity of each edit".
* `baseline_k3.spthy` and `fixed_k3.spthy`: Section 5, "Bounded roster
  and hierarchy depth".
* Table 3 reproduces `expected/baseline.txt` and `expected/fixed.txt`.

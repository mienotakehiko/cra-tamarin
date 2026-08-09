# Tamarin theories

Three self-contained theories.  All three parse under
`tamarin-prover 1.12.0` with `maude 3.2` and complete their proofs
under 10 seconds on a laptop-class host.

## Files

| File               | Design      | Verifier structure  | Coverage lemma  |
|--------------------|-------------|---------------------|-----------------|
| `baseline.spthy`   | Baseline    | Two rules (Accept then per-leaf ParseEntry) | **FALSIFIED** (13-step attack trace) |
| `fixed.spthy`      | Hardened    | Single atomic Accept rule (D4)              | verified (9 steps) |
| `fixed_split.spthy`| Hardened    | Five-rule state machine with linear facts   | verified (5 steps) |

The two hardened theories describe the same design at different
levels of abstraction; the multi-step version exhibits the partial
states that a real Verifier passes through, and is the reply to the
review objection that atomic-rule closure is a "modelling shortcut".

## Reproducing the paper's Table 2 (Tamarin outcomes)

```
tamarin-prover baseline.spthy      --prove
tamarin-prover fixed.spthy         --prove
tamarin-prover fixed_split.spthy   --prove
```

Expected summary lines (abridged):

```
baseline.spthy       processing time: 3.14 s
  executability                     verified (11 steps)
  key_secrecy                       verified (9 steps)
  injective_agree_TEE               verified (14 steps)
  freshness                         verified (3 steps)
  report_integrity                  verified (8 steps)
  cryptographic_coverage            falsified - found trace (13 steps)

fixed.spthy          processing time: 8.85 s
  executability                     verified (18 steps)
  key_secrecy                       verified (9 steps)
  injective_agree_TEE               verified (14 steps)
  freshness                         verified (3 steps)
  report_integrity                  verified (34 steps)
  cryptographic_coverage            verified (9 steps)

fixed_split.spthy    processing time: 6.83 s
  executability                     verified (14 steps)
  key_secrecy                       verified (9 steps)
  injective_agree_TEE               verified (14 steps)
  freshness                         verified (3 steps)
  report_integrity                  verified (26 steps)
  cryptographic_coverage            verified (5 steps)
```

## Attack trace visualisation

To render the 13-step counter-example of `baseline.spthy` as a
graph:

```
tamarin-prover baseline.spthy --prove=cryptographic_coverage \
    --output-dot=coverage_attack.dot
dot -Tpdf coverage_attack.dot -o coverage_attack.pdf
```

The paper's Fig. 3 is a hand-simplified rendering of the same
graph; the raw `.dot` file lives under `paper/figures/`.

## Mapping to the paper

- `baseline.spthy` is discussed in Section 4 and Section 5, and its
  falsified lemma is the subject of Section 7.2.
- `fixed.spthy` is the atomic-Accept theory of Section 8 (edits
  D1--D4).
- `fixed_split.spthy` is the multi-step theory of Section 8.2
  ("Atomic and multi-step formulations").

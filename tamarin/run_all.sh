#!/usr/bin/env bash
#  run_all.sh: re-prove every theory of the cra-tamarin artefact (v1.1)
#
#  Usage:   ./run_all.sh [theory ...]        (default: all nine theories)
#  Env:     TAMARIN (default: tamarin-prover)
#           RTS     (default: "-N1 -M1700m")  GHC runtime flags; the heap cap
#                   keeps fixed_k3.spthy inside 2 GB hosts
#           TRACES=1  also export counterexamples as JSON/DOT into traces/
#  Output:  results/<theory>.log   full Tamarin output
#           results/<theory>.txt   normalised summary (compared by check.sh)
#           proofs/<theory>.spthy  theory annotated with the complete proofs
set -euo pipefail
cd "$(dirname "$0")"
export LANG=C.UTF-8 LC_ALL=C.UTF-8          # avoids 'commitBuffer: invalid argument'
TAMARIN=${TAMARIN:-tamarin-prover}
RTS=${RTS:--N1 -M1700m}
THEORIES=("$@")
[ ${#THEORIES[@]} -eq 0 ] && THEORIES=(baseline fixed fixed_split \
    ablation_D1 ablation_D2 ablation_D3 ablation_D4 baseline_k3 fixed_k3)
mkdir -p results proofs
"$TAMARIN" --version 2>&1 | grep -m1 'tamarin-prover' || true
maude --version 2>/dev/null | sed 's/^/maude /' || true
for t in "${THEORIES[@]}"; do
  t=${t%.spthy}
  start=$(date +%s)
  # shellcheck disable=SC2086
  "$TAMARIN" "$t.spthy" --prove --output="proofs/$t.spthy" +RTS $RTS -RTS \
      > "results/$t.log" 2>&1
  secs=$(( $(date +%s) - start ))
  if grep -q 'wellformedness check failed' "results/$t.log"; then
      echo "ERROR: $t.spthy has wellformedness warnings" >&2; exit 2; fi
  sed -n '/summary of summaries/,$p' "results/$t.log" \
    | grep -E '^  [A-Za-z_]+ \((exists-trace|all-traces)\):' \
    | sed -E 's/^  //; s/ - found trace//' > "results/$t.txt"
  printf '%-18s %4ss  %s\n' "$t" "$secs" "$(tr '\n' ';' < "results/$t.txt" \
    | sed -E 's/ \((exists-trace|all-traces)\)//g')"
  if [ "${TRACES:-0}" = 1 ]; then
    mkdir -p traces
    for l in $(grep -E 'falsified' "results/$t.txt" | cut -d' ' -f1); do
      # shellcheck disable=SC2086
      "$TAMARIN" "$t.spthy" --prove="$l" --output-json="traces/${t}__$l.json" \
          --output-dot="traces/${t}__$l.dot" +RTS $RTS -RTS > /dev/null 2>&1
    done
  fi
done

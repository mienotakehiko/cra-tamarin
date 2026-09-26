#!/usr/bin/env bash
# check.sh: compare results/*.txt (from run_all.sh) with expected/*.txt.
# Verdicts (verified / falsified) must match exactly.  Step counts are
# compared too; set STRICT_STEPS=0 to report step drift as a warning only
# (step counts depend on the Tamarin heuristic, not on the verdict).
set -uo pipefail
cd "$(dirname "$0")"
STRICT_STEPS=${STRICT_STEPS:-1}
fail=0; warn=0
for e in expected/*.txt; do
  t=$(basename "$e")
  r="results/$t"
  if [ ! -f "$r" ]; then echo "MISSING  $t"; fail=1; continue; fi
  verd() { sed -E 's/ \(([0-9]+) steps\)$//' "$1"; }
  if ! diff -q <(verd "$e") <(verd "$r") > /dev/null; then
      echo "VERDICT  $t"; diff <(verd "$e") <(verd "$r"); fail=1; continue; fi
  if ! diff -q "$e" "$r" > /dev/null; then
      echo "STEPS    $t"; diff "$e" "$r"
      if [ "$STRICT_STEPS" = 1 ]; then fail=1; else warn=1; fi
      continue; fi
  echo "OK       $t"
done
[ $fail -eq 0 ] && { [ $warn -eq 0 ] && echo "ALL OK" || echo "OK (step drift only)"; }
exit $fail

#!/bin/bash
# Every suite, one after another, then the scorecard over all of them.
#
#   bench/all.sh
#
# One at a time on purpose: each saturates the machine, and two at once would
# measure the contention rather than the servers. Takes a couple of hours.
#
# Knobs: ROUNDS, DURATION, SOAK_MINUTES, SUITES (a subset), OUT.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HERE/results/all-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
read -ra SUITES <<< "${SUITES:-http rate h3 l4 hostile ws soak}"

for s in "${SUITES[@]}"; do
    echo "=== $s ==="
    started=$SECONDS
    # The long-held and long-running suites get fewer rounds; the rest are
    # short enough that three is affordable.
    case $s in
        ws) knobs=(ROUNDS="${ROUNDS_WS:-2}" LEVELS="${LEVELS:-1000 10000 50000}") ;;
        hostile) knobs=(ROUNDS="${ROUNDS_HOSTILE:-2}") ;;
        soak) knobs=(SOAK_MINUTES="${SOAK_MINUTES:-5}") ;;
        *) knobs=(ROUNDS="${ROUNDS:-3}" DURATION="${DURATION:-8}") ;;
    esac
    if env "${knobs[@]}" OUT="$OUT/$s" "$HERE/run.sh" "$s" > "$OUT/$s.log" 2>&1; then
        echo "  ok in $(( (SECONDS - started) / 60 )) min"
    else
        echo "  FAILED after $(( (SECONDS - started) / 60 )) min, see $OUT/$s.log"
        tail -n 15 "$OUT/$s.log"
    fi
done

echo "=== scorecard ==="
dirs=()
for s in "${SUITES[@]}"; do [ -f "$OUT/$s/results.jsonl" ] && dirs+=("$OUT/$s"); done
if [ ${#dirs[@]} -gt 0 ]; then
    python3 "$HERE/scorecard.py" "${dirs[@]}" || true
    mv -f scorecard.md "$OUT/scorecard.md" 2>/dev/null || true
    python3 "$HERE/history.py" add "${dirs[@]}" || true
fi
echo "results: $OUT"

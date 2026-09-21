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

# A whole chain of these has been killed partway through for low memory more than
# once, which looks like a suite failing rather than the machine giving up. Say so
# instead. The check is before each suite, and a suite can still be killed during
# one: the container's page cache grows with the fixtures, and the HTTP suite
# writes a 100 MB file and ten thousand small ones. On a 16 GB machine, run the
# suites one invocation at a time rather than chaining all seven.
free_pct() {
    if [ "$(uname -s)" == Darwin ]; then
        memory_pressure 2>/dev/null | awk '/free percentage/ {gsub("%", "", $NF); print $NF; exit}'
    else
        awk '/MemAvailable/ {a=$2} /MemTotal/ {t=$2} END {if (t) printf "%d", 100 * a / t}' /proc/meminfo
    fi
}

for s in "${SUITES[@]}"; do
    pct=$(free_pct)
    if [ -n "$pct" ] && [ "$pct" -lt "${MIN_FREE_PCT:-20}" ]; then
        echo "=== $s: skipped, only $pct% of memory free (MIN_FREE_PCT=${MIN_FREE_PCT:-20}) ==="
        continue
    fi
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

#!/bin/bash
# Runs one suite repeatedly over the values of one knob, then reports how each
# figure moves across them.
#   bench/sweep.sh WORKERS 1 2 4
#   bench/sweep.sh CONNS 16 256 4096 20000
#   bench/sweep.sh ACCESS_LOG off on
#   SUITE=ws bench/sweep.sh WORKERS 1 2 4
# Results land in bench/results/sweep-<knob>-<timestamp>/<value>/. Other knobs
# (WORKLOADS, ROUNDS, DURATION, QUIC_ZIG) pass through to the suite.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
[ $# -ge 2 ] || { echo "usage: sweep.sh <KNOB> <value> [value ...]"; exit 1; }
KNOB=$1; shift
SUITE=${SUITE:-http}
OUT="${OUT:-$HERE/results/sweep-$(echo "$KNOB" | tr 'A-Z' 'a-z')-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
echo "knob: $KNOB" > "$OUT/sweep.txt"
echo "values: $*" >> "$OUT/sweep.txt"
echo "suite: $SUITE" >> "$OUT/sweep.txt"
for v in "$@"; do
    echo "=== $KNOB=$v ==="
    # One at a time: each of these saturates the machine on its own.
    env "$KNOB=$v" OUT="$OUT/$v" "$HERE/run.sh" "$SUITE"
done
python3 "$HERE/report_sweep.py" "$OUT" && echo && cat "$OUT/table.md"

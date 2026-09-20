#!/bin/bash
# Runs one cell of one suite twice over, once sampled and once traced, and says
# where that server spent itself.
#
#   bench/profile.sh <suite> <row> <server>
#   bench/profile.sh http fileset routez
#   bench/profile.sh h3 h3-conns64 routez
#
# A row the scorecard calls a loss becomes a list of the functions it spent
# itself in.
#
# The sample comes from perf. Syscall counts are a second, separate pass under
# strace and are off by default: counting a threaded server's syscalls pushes
# every one of them through ptrace, and routez makes enough that the run stops
# progressing rather than merely slowing down. `--strace <list>` turns it on with
# a narrow set, which does work: `--strace sendmsg,sendto` is how the HTTP/3 send
# path was counted.
#
# Output lands in bench/results/profile-<suite>-<row>-<server>-<timestamp>/:
#   <server>.hot      the functions, by share of samples
#   <server>.folded   collapsed stacks, what a flamegraph tool reads
#   <server>.syscalls calls and calls per request, with --strace
#   <server>.perf     the raw sample, for `perf report -i`
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
TRACE=
if [ "${1:-}" == --strace ]; then TRACE=${2:?--strace needs a syscall list}; shift 2; fi
[ $# -eq 3 ] || { sed -n '2,20p' "$0"; exit 1; }
SUITE=$1 ROW=$2 SERVER=$3
OUT="${OUT:-$HERE/results/profile-$SUITE-$ROW-$SERVER-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"

# Each suite names its row selection differently.
case $SUITE in
    http) SEL=WORKLOADS ;;
    h3|l4|hostile) SEL=ROWS ;;
    ws|soak) SEL= ;;
    *) echo "unknown suite '$SUITE'"; exit 1 ;;
esac

run() { # mode seconds
    echo "=== $1 pass ==="
    env PROFILE="$1" PROFILE_SERVER="$SERVER" PROFILE_TRACE="${PROFILE_TRACE:-%net,%desc}" \
        ${SEL:+"$SEL=$ROW"} SERVERS="$SERVER" \
        ROUNDS=1 DURATION="$2" OUT="$OUT/$1" \
        "$HERE/run.sh" "$SUITE" > "$OUT/$1.log" 2>&1 ||
        { echo "the $1 pass failed:"; tail -n 20 "$OUT/$1.log"; exit 1; }
}

run perf "${DURATION:-10}"
# Shorter: a trace costs orders of magnitude, and the counts are ratios, so a few
# seconds of them is as good as a minute.
[ -n "$TRACE" ] && PROFILE_TRACE="$TRACE" run strace "${STRACE_DURATION:-3}"
for f in "$OUT"/perf/"$SERVER".hot "$OUT"/perf/"$SERVER".folded "$OUT"/perf/"$SERVER".perf; do
    [ -e "$f" ] && mv "$f" "$OUT/"
done

# Requests served during the traced pass, so the syscall counts can be per request.
if [ -n "$TRACE" ]; then
REQS=$(python3 - "$OUT/strace" <<'PY'
import json, sys
from pathlib import Path
total = 0
for f in (Path(sys.argv[1]) / "results.jsonl").open() if (Path(sys.argv[1]) / "results.jsonl").exists() else []:
    r = json.loads(f)
    m = r.get("metrics", {})
    d = r.get("detail", {})
    rate = m.get("rps", d.get("rps")) or m.get("pps") or m.get("handshakes_per_s") or 0
    total += rate
print(int(total))
PY
) || REQS=0
DUR=${STRACE_DURATION:-3}
{
    echo "syscalls made by $SERVER on $SUITE/$ROW, and per request"
    echo "(about $((REQS * DUR)) requests during the traced run; strace slows the server,"
    echo " so read the ratios and not the absolute rate)"
    echo
    awk -v n="$((REQS * DUR))" 'NR > 2 && $NF !~ /^(total|-+)$/ {
        printf "  %-20s calls=%-10d %8.2f per request\n", $NF, $4, (n ? $4 / n : 0) }' \
        "$OUT/strace/$SERVER.strace" 2>/dev/null | sort -t= -k2 -rn | head -20
} > "$OUT/$SERVER.syscalls"
fi

echo
echo "results: $OUT"
echo
[ -s "$OUT/$SERVER.hot" ] && { echo "--- where the time went ---"; grep -vE '^#|^$' "$OUT/$SERVER.hot" | head -15; }
echo
[ -n "$TRACE" ] && cat "$OUT/$SERVER.syscalls"
exit 0

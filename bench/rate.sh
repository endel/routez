#!/bin/bash
# Latency at a rate the servers are held to, rather than at whatever rate each
# one happens to reach. wrk is closed-loop: it offers as much as a server will
# take, so its percentiles are the reciprocal of throughput and two servers are
# never compared at the same load. oha holds a fixed request rate, so they are.
#
#   bench/run.sh rate
#
# Each row is measured twice. First a short wrk pass finds every server's peak;
# then oha offers FRACTION of the slowest server's peak to all of them and the
# percentiles are read at that one rate. A server that cannot hold the offered
# rate is flagged, because its latency then means nothing.
#
# Knobs: WORKERS, CONNS, DURATION, ROUNDS, WORKLOADS, FRACTION (0.5), OUT.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORKERS=${WORKERS:-3}
CONNS=${CONNS:-64}
DURATION=${DURATION:-10}
ROUNDS=${ROUNDS:-3}
FRACTION=${FRACTION:-0.5}

OUT_PREFIX=rate- . "$HERE/lib.sh"
CERTS="$SRC_QZ/interop/certs"
WWW="$RUN/www"

# Only the rows oha can drive: a plain GET, no scripted request shape.
declare -A W_SCHEME W_PATH W_SERVERS W_UP W_LABEL
ORDER=()
while read -r name scheme path lua servers check up conns profile label; do
    case ${name:-} in ""|\#*) continue ;; esac
    [ "$lua" == - ] && [ "$profile" == main ] && [ "$check" == pong -o "$check" == "file:10k.bin" ] || continue
    ORDER+=("$name")
    W_SCHEME[$name]=$scheme W_PATH[$name]=$path W_SERVERS[$name]=$servers W_UP[$name]=$up
    W_LABEL[$name]=$label
done < "$HERE/workloads.txt"
read -ra WORKLOADS <<< "${WORKLOADS:-${ORDER[*]}}"
for w in "${WORKLOADS[@]}"; do
    [ -n "${W_SCHEME[$w]:-}" ] || { echo "'$w' is not a fixed-rate row; have: ${ORDER[*]}"; exit 1; }
done

read -ra SERVERS <<< "${SERVERS:-nginx haproxy routez}"
declare -A PLAIN=([nginx]=19080 [routez]=19081 [haproxy]=19082)
declare -A TLS=([nginx]=19443 [routez]=19444 [haproxy]=19445)
declare -A SPID=()
serves() { [ "${W_SERVERS[$1]}" == all ] || [ "$2" != haproxy ]; }
active() { local s; for s in "${SERVERS[@]}"; do serves "$1" "$s" && echo "$s"; done; }
target() {
    local port=${PLAIN[$2]}
    [ "${W_SCHEME[$1]}" == https ] && port=${TLS[$2]}
    echo "${W_SCHEME[$1]}://127.0.0.1:$port${W_PATH[$1]}"
}

NCPU=$(nproc)
UPSTREAM_WORKERS=2
if [ "$NCPU" -ge $((2 * WORKERS + UPSTREAM_WORKERS)) ]; then
    SERVER_CPUS=0-$((WORKERS - 1))
    LOAD_CPUS=$WORKERS-$((NCPU - UPSTREAM_WORKERS - 1))
    UP_CPUS=$((NCPU - UPSTREAM_WORKERS))-$((NCPU - 1))
    PINNING="server on cpus $SERVER_CPUS, client on $LOAD_CPUS, upstream on $UP_CPUS"
else
    SERVER_CPUS=0-$((NCPU - 1)) LOAD_CPUS=$SERVER_CPUS UP_CPUS=$SERVER_CPUS
    PINNING="none ($NCPU cpus, pinning needs $((2 * WORKERS + UPSTREAM_WORKERS)))"
    echo "warning: not pinning, $PINNING"
fi

mkdir -p "$WWW" "$OUT/raw"
[ -s "$WWW/10k.bin" ] || head -c 10240 /dev/urandom > "$WWW/10k.bin"
cat "$CERTS/server.crt" "$CERTS/server.key" > "$RUN/server.pem"
mkdir -p "$RUN/main"
for f in nginx.conf haproxy.cfg routez.zon; do
    sed "s|UPSTREAM_WORKERS|$UPSTREAM_WORKERS|g; s|WORKERS|$WORKERS|g; s|WWW|$WWW|g; s|CERTS|$CERTS|g; \
         s|ACCESS_LOG|off|g; s|ROUTEZ_LOG|false|g; s|HAPROXY_LOG|no log|g; s|RUN|$RUN|g" \
        "$HERE/conf/$f" | sed -e "/# ROUTING/d" -e "\|// ROUTING|d" > "$RUN/main/$f"
done
sed "s|UPSTREAM_WORKERS|$UPSTREAM_WORKERS|g; s|WWW|$WWW|g; s|CERTS|$CERTS|g; s|RUN|$RUN|g" \
    "$HERE/conf/upstream.conf" > "$RUN/upstream.conf"

start upstream "$UP_CPUS" nginx -c "$RUN/upstream.conf"
wait_port 19090
up_servers() {
    start nginx "$SERVER_CPUS" nginx -c "$RUN/main/nginx.conf"; SPID[nginx]=$!
    start haproxy "$SERVER_CPUS" haproxy -f "$RUN/main/haproxy.cfg"; SPID[haproxy]=$!
    start routez "$SERVER_CPUS" "$ROOT/zig-out/bin/routez" "$RUN/main/routez.zon"; SPID[routez]=$!
    local p
    for p in "${PLAIN[@]}" "${TLS[@]}"; do wait_port "$p"; done
    until pgrep -P "${SPID[nginx]}" >/dev/null; do sleep 0.05; done
}
down_servers() {
    local s
    profile_report
    for s in "${SERVERS[@]}"; do kill "${SPID[$s]:-}" 2>/dev/null; done
    for s in "${SERVERS[@]}"; do wait "${SPID[$s]:-}" 2>/dev/null; done
    SPID=()
}

up_servers
fail=0
for s in "${SERVERS[@]}"; do
    for w in "${WORKLOADS[@]}"; do
        serves "$w" "$s" || continue
        code=$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' "$(target "$w" "$s")")
        [ "$code" == 200 ] || { echo "sanity: $s $w: status $code"; fail=1; }
    done
done
[ "$fail" == 0 ] || { tail -n 20 "$RUN"/*.log; exit 1; }

{ env_header; cat <<EOF
oha: $(oha --version | awk '{print $2}')
wrk: $(wrk -v 2>&1 | awk 'NR == 1 {print $2}')
workers: $WORKERS
conns: $CONNS
duration: $DURATION
rounds: $ROUNDS
fraction: $FRACTION
pinning: $PINNING
server_cpus: $SERVER_CPUS
wrk_cpus: $LOAD_CPUS
upstream_cpus: $UP_CPUS
EOF
} > "$OUT/env.txt"

# Pass one: what each server can do, so the offered rate is a share of the
# slowest rather than a number picked out of the air.
for w in "${WORKLOADS[@]}"; do
    mapfile -t act < <(active "$w")
    peak=
    for s in "${act[@]}"; do
        taskset -c "$LOAD_CPUS" wrk -t4 -c "$CONNS" -d 4s --timeout 10s \
            -s "$HERE/report.lua" "$(target "$w" "$s")" > "$RUN/peak.txt" 2>&1
        r=$(awk '/^Requests\/sec/ {printf "%d", $2}' "$RUN/peak.txt")
        echo "$w $s peak: $r req/s"
        [ -z "$peak" ] || [ "$r" -lt "$peak" ] && peak=$r
    done
    echo "$peak" > "$OUT/raw/$w.peak"
done

# Pass two: hold every server to the same rate and read the percentiles.
for w in "${WORKLOADS[@]}"; do
    mapfile -t act < <(active "$w")
    rate=$(python3 -c "print(max(100, int($(cat "$OUT/raw/$w.peak") * $FRACTION)))")
    echo "$w: offering $rate req/s to each server"
    for n in $(seq 1 "$ROUNDS"); do
        for i in $(seq 0 $((${#act[@]} - 1))); do
            s=${act[$(((i + n - 1) % ${#act[@]}))]}
            f="$OUT/raw/$w.$s.$n"
            sleep 1
            grep '^cpu[0-9]' /proc/stat > "$f.stat0"
            taskset -c "$LOAD_CPUS" oha --no-tui --insecure --output-format json \
                -q "$rate" -z "${DURATION}s" -c "$CONNS" --latency-correction \
                "$(target "$w" "$s")" > "$f.json" 2>"$f.err"
            grep '^cpu[0-9]' /proc/stat > "$f.stat1"
            echo "$w $s #$n: $(python3 -c "
import json
d = json.load(open('$f.json'))
print(f\"{d['summary']['requestsPerSec']:.0f} req/s, p99 {d['latencyPercentiles']['p99'] * 1000:.2f} ms\")
" 2>/dev/null || echo "no result")"
        done
    done
done
down_servers

python3 "$HERE/report_rate.py" "$OUT" && echo && cat "$OUT/table.md"

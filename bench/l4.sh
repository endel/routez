#!/bin/bash
# Layer-4 forwarding: routez's tcp_proxy and udp_proxy against nginx stream and
# HAProxy's mode tcp, with the unproxied path as the baseline every row is read
# against. Runs inside `bench/run.sh l4`'s container; on a Linux host it needs
# root and what bench/Dockerfile installs.
# Knobs: WORKERS, CONNS, DURATION (seconds), ROUNDS, FLOWS, PPS, ROWS, OUT.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORKERS=${WORKERS:-3}
CONNS=${CONNS:-256}
DURATION=${DURATION:-10}
ROUNDS=${ROUNDS:-3}
FLOWS=${FLOWS:-10000}
PPS=${PPS:-50000}

OUT_PREFIX=l4- . "$HERE/lib.sh"
CERTS="$SRC_QZ/interop/certs" # the shared backend config has a TLS listener
WWW="$RUN/www"
build_tool udpload

# name          kind path      lua     servers label
ROWS_ALL="
tcp-small       tcp  /ping     -       all   TCP: a small response, keep-alive
tcp-conn        tcp  /ping     close   all   TCP: a new connection per request
tcp-bulk        tcp  /1m.bin   -       all   TCP: 1 MB responses
udp-rtt         udp  -         -       noudp UDP: round trip at a fixed rate
udp-flood       udp  -         -       noudp UDP: loss at a high rate
udp-flows       udp  -         -       noudp UDP: memory per client flow
"
declare -A R_KIND R_PATH R_LUA R_SERVERS R_LABEL
ORDER=()
while read -r name kind path lua servers label; do
    [ -n "${name:-}" ] || continue
    ORDER+=("$name")
    R_KIND[$name]=$kind R_PATH[$name]=$path R_LUA[$name]=$lua R_SERVERS[$name]=$servers
    R_LABEL[$name]=$label
done <<< "$ROWS_ALL"
read -ra ROWS <<< "${ROWS:-${ORDER[*]}}"
for r in "${ROWS[@]}"; do
    [ -n "${R_KIND[$r]:-}" ] || { echo "unknown row '$r'; have: ${ORDER[*]}"; exit 1; }
done

# `direct` is the baseline: the same traffic with no proxy in the path.
SERVERS=(direct nginx haproxy routez)
declare -A TCP=([direct]=19090 [nginx]=19280 [routez]=19281 [haproxy]=19282)
declare -A UDP=([direct]=19201 [nginx]=19290 [routez]=19291)
declare -A SPID=()
# HAProxy has no generic UDP proxy.
serves() { [ "${R_SERVERS[$1]}" == all ] || [ "$2" != haproxy ]; }
active() { local s; for s in "${SERVERS[@]}"; do serves "$1" "$s" && echo "$s"; done; }

NCPU=$(nproc)
BACK_WORKERS=2
if [ "$NCPU" -ge $((2 * WORKERS + BACK_WORKERS)) ]; then
    SERVER_CPUS=0-$((WORKERS - 1))
    LOAD_CPUS=$WORKERS-$((NCPU - BACK_WORKERS - 1)) LOAD_THREADS=$((NCPU - BACK_WORKERS - WORKERS))
    BACK_CPUS=$((NCPU - BACK_WORKERS))-$((NCPU - 1))
    PINNING="proxy on cpus $SERVER_CPUS, load on $LOAD_CPUS, backend on $BACK_CPUS"
else
    SERVER_CPUS=0-$((NCPU - 1)) LOAD_CPUS=$SERVER_CPUS BACK_CPUS=$SERVER_CPUS LOAD_THREADS=$WORKERS
    PINNING="none ($NCPU cpus, pinning needs $((2 * WORKERS + BACK_WORKERS)))"
    echo "warning: not pinning, $PINNING"
fi

mkdir -p "$WWW" "$OUT/raw"
[ -s "$WWW/1m.bin" ] || head -c $((1024 * 1024)) /dev/urandom > "$WWW/1m.bin"
for f in nginx-l4.conf haproxy-l4.cfg routez-l4.zon upstream.conf; do
    sed "s|UPSTREAM_WORKERS|$BACK_WORKERS|g; s|WORKERS|$WORKERS|g; s|WWW|$WWW|g; s|CERTS|$CERTS|g; \
         s|ACCESS_LOG|off|g; s|RUN|$RUN|g" "$HERE/conf/$f" > "$RUN/$f"
done
for r in "${ROWS[@]}"; do
    [ "${R_LUA[$r]}" == - ] && continue
    cat "$HERE/report.lua" "$HERE/lua/${R_LUA[$r]}.lua" > "$RUN/wrk-$r.lua"
done

# The backends: an HTTP server for the TCP rows, a UDP echo for the UDP ones.
start backend "$BACK_CPUS" nginx -c "$RUN/upstream.conf"
start udpecho "$BACK_CPUS" "$RUN/udpload" server 19201
wait_port 19090
wait_udp 19201

up_proxies() {
    start nginx "$SERVER_CPUS" nginx -c "$RUN/nginx-l4.conf"; SPID[nginx]=$!
    start haproxy "$SERVER_CPUS" haproxy -f "$RUN/haproxy-l4.cfg"; SPID[haproxy]=$!
    start routez "$SERVER_CPUS" "$ROOT/zig-out/bin/routez" "$RUN/routez-l4.zon"; SPID[routez]=$!
    SPID[direct]=
    wait_port "${TCP[nginx]}"; wait_port "${TCP[routez]}"; wait_port "${TCP[haproxy]}"
    wait_udp "${UDP[nginx]}"; wait_udp "${UDP[routez]}"
    until pgrep -P "${SPID[nginx]}" >/dev/null; do sleep 0.05; done
}
down_proxies() {
    local s
    profile_report
    for s in nginx haproxy routez; do kill "${SPID[$s]}" 2>/dev/null; done
    for s in nginx haproxy routez; do wait "${SPID[$s]}" 2>/dev/null; done
    PIDS=("${PIDS[0]}" "${PIDS[1]}")
    SPID=()
}

# Sanity: every path carries the bytes through unchanged, TCP and UDP.
up_proxies
fail=0
bad() { echo "sanity: $*"; fail=1; }
for s in "${SERVERS[@]}"; do
    for r in "${ROWS[@]}"; do
        serves "$r" "$s" || continue
        case ${R_KIND[$r]} in
            tcp)
                code=$(curl -s --max-time 10 -o "$RUN/body" -w '%{http_code}' \
                    "http://127.0.0.1:${TCP[$s]}${R_PATH[$r]}")
                [ "$code" == 200 ] || { bad "$s $r: status $code"; continue; }
                case ${R_PATH[$r]} in
                    *.bin) cmp -s "$RUN/body" "$WWW/$(basename "${R_PATH[$r]}")" || bad "$s $r: wrong body" ;;
                    *) [ "$(cat "$RUN/body")" == pong ] || bad "$s $r: body '$(head -c 40 "$RUN/body")'" ;;
                esac ;;
            udp)
                j=$("$RUN/udpload" client "127.0.0.1:${UDP[$s]}" --flows 2 --pps 100 --seconds 1)
                sent=$(echo "$j" | sed 's/.*"sent":\([0-9]*\).*/\1/')
                got=$(echo "$j" | sed 's/.*"received":\([0-9]*\).*/\1/')
                [ "$got" -gt 0 ] && [ "$got" == "$sent" ] || bad "$s $r: $got of $sent datagrams echoed" ;;
        esac
    done
done
down_proxies
[ "$fail" == 0 ] || { tail -n 20 "$RUN"/*.log; exit 1; }

{ env_header; cat <<EOF
wrk: $(wrk -v 2>&1 | awk 'NR == 1 {print $2}')
workers: $WORKERS
conns: $CONNS
duration: $DURATION
rounds: $ROUNDS
flows: $FLOWS
pps: $PPS
rmem_max: $(cat /proc/sys/net/core/rmem_max)
pinning: $PINNING
server_cpus: $SERVER_CPUS
wrk_cpus: $LOAD_CPUS
upstream_cpus: $BACK_CPUS
EOF
} > "$OUT/env.txt"

run_row() { # row server seconds output-prefix
    local r=$1 s=$2 secs=$3 f=$4 script=$HERE/report.lua threads=$LOAD_THREADS
    case ${R_KIND[$r]} in
        tcp)
            [ "${R_LUA[$r]}" == - ] || script=$RUN/wrk-$r.lua
            [ "$threads" -gt "$CONNS" ] && threads=$CONNS
            taskset -c "$LOAD_CPUS" wrk -t "$threads" -c "$CONNS" -d "${secs}s" --timeout 10s \
                --latency -s "$script" "http://127.0.0.1:${TCP[$s]}${R_PATH[$r]}" > "$f.txt" 2>&1 ;;
        udp)
            local flows=64 pps=$PPS
            case $r in
                udp-rtt) flows=64 pps=20000 ;;
                udp-flood) flows=256 pps=$PPS ;;
                udp-flows) flows=$FLOWS pps=$FLOWS ;; # one datagram per flow per second
            esac
            taskset -c "$LOAD_CPUS" "$RUN/udpload" client "127.0.0.1:${UDP[$s]}" \
                --flows "$flows" --pps "$pps" --seconds "$secs" > "$f.txt" 2>&1 ;;
    esac
}

for r in "${ROWS[@]}"; do
    mapfile -t act < <(active "$r")
    up_proxies
    for s in "${act[@]}"; do tree_rss "${SPID[$s]:-}" > "$OUT/raw/$r.$s.base"; done
    for s in "${act[@]}"; do run_row "$r" "$s" 2 /dev/null; done
    for n in $(seq 1 "$ROUNDS"); do
        for i in $(seq 0 $((${#act[@]} - 1))); do
            s=${act[$(((i + n - 1) % ${#act[@]}))]}
            f="$OUT/raw/$r.$s.$n"
            sleep 1
            grep '^cpu[0-9]' /proc/stat > "$f.stat0"
            run_row "$r" "$s" "$DURATION" "$f"
            grep '^cpu[0-9]' /proc/stat > "$f.stat1"
            tree_rss "${SPID[$s]:-}" > "$f.rss"
            echo "$r $s #$n: $(tail -n 1 "$f.txt" | head -c 120)"
        done
    done
    down_proxies
done

python3 "$HERE/report_l4.py" "$OUT" && echo && cat "$OUT/table.md"

#!/bin/bash
# HTTP/3 against nginx, HAProxy and routez with h2load, and the same rows over
# HTTP/1.1 from the same client so each server's h3-to-h1 ratio comes from one
# place. Runs inside `bench/run.sh h3`'s container; on a Linux host it needs
# root and what bench/Dockerfile installs.
# Knobs: WORKERS, CONNS (QUIC connections), DURATION (seconds), ROUNDS, ROWS, OUT.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORKERS=${WORKERS:-3}
CONNS=${CONNS:-64}
DURATION=${DURATION:-10}
ROUNDS=${ROUNDS:-3}

OUT_PREFIX=h3- . "$HERE/lib.sh"
CERTS="$SRC_QZ/interop/certs"
WWW="$RUN/www"
export XDG_CACHE_HOME=/cache # so the HTTP/3 curl is fetched once, not per run

# The four h3-conns rows hold the requests in flight at 64 and move them from
# streams onto connections, which is the axis that separates per-request cost
# from per-connection cost. Read a single-stream row with care: at one stream per
# connection h2load's own QUIC client costs milliseconds per request, and every
# server measures ~2 ms there, so those rows are partly the client's.
# name           alpn path      streams conns servers label
ROWS_ALL="
h3-conns4        h3   /ping      16     4     all   64 in flight over 4 connections
h3-conns16       h3   /ping      4      16    all   64 in flight over 16 connections
h3-conns64       h3   /ping      1      64    all   64 in flight over 64 connections
h3-return-m10    h3   /ping      10     -     all   Fixed response, 10 streams per connection
h3-static        h3   /10k.bin   10     -     nohap 10 KB static file
h3-static-1m     h3   /1m.bin    10     32    nohap 1 MB static file
h3-proxy         h3   /up/       10     -     all   Reverse proxy to a keep-alive upstream
h1-return        h1   /ping      1      -     all   HTTP/1.1 over TLS: fixed response
h1-static        h1   /10k.bin   1      -     nohap HTTP/1.1 over TLS: 10 KB static file
h1-proxy         h1   /up/       1      -     all   HTTP/1.1 over TLS: reverse proxy
"
declare -A R_ALPN R_PATH R_STREAMS R_CONNS R_SERVERS R_LABEL
ORDER=()
while read -r name alpn path streams conns servers label; do
    [ -n "${name:-}" ] || continue
    ORDER+=("$name")
    R_ALPN[$name]=$alpn R_PATH[$name]=$path R_STREAMS[$name]=$streams R_CONNS[$name]=$conns
    R_SERVERS[$name]=$servers R_LABEL[$name]=$label
done <<< "$ROWS_ALL"
read -ra ROWS <<< "${ROWS:-${ORDER[*]}}"
for r in "${ROWS[@]}"; do
    [ -n "${R_ALPN[$r]:-}" ] || { echo "unknown row '$r'; have: ${ORDER[*]}"; exit 1; }
done

read -ra SERVERS <<< "${SERVERS:-nginx haproxy routez}"
declare -A QUIC=([nginx]=19543 [routez]=19544 [haproxy]=19545)
declare -A TLS=([nginx]=19443 [routez]=19444 [haproxy]=19445)
declare -A SPID=()
serves() { [ "${R_SERVERS[$1]}" == all ] || [ "$2" != haproxy ]; }
active() { local s; for s in "${SERVERS[@]}"; do serves "$1" "$s" && echo "$s"; done; }
target() { # row server -> URL
    local port=${TLS[$2]}
    [ "${R_ALPN[$1]}" == h3 ] && port=${QUIC[$2]}
    echo "https://127.0.0.1:$port${R_PATH[$1]}"
}
conns_of() { local c=${R_CONNS[$1]}; [ "$c" == - ] && c=$CONNS; echo "$c"; }

NCPU=$(nproc)
UPSTREAM_WORKERS=2
if [ "$NCPU" -ge $((2 * WORKERS + UPSTREAM_WORKERS)) ]; then
    SERVER_CPUS=0-$((WORKERS - 1))
    LOAD_CPUS=$WORKERS-$((NCPU - UPSTREAM_WORKERS - 1)) LOAD_THREADS=$((NCPU - UPSTREAM_WORKERS - WORKERS))
    UP_CPUS=$((NCPU - UPSTREAM_WORKERS))-$((NCPU - 1))
    WIDE_CPUS=$WORKERS-$((NCPU - 1)) WIDE_THREADS=$((NCPU - WORKERS))
    PINNING="server on cpus $SERVER_CPUS, h2load on $LOAD_CPUS ($WIDE_CPUS without an upstream), upstream on $UP_CPUS"
else
    SERVER_CPUS=0-$((NCPU - 1)) LOAD_CPUS=$SERVER_CPUS UP_CPUS=$SERVER_CPUS LOAD_THREADS=$WORKERS
    WIDE_CPUS=$LOAD_CPUS WIDE_THREADS=$LOAD_THREADS
    PINNING="none ($NCPU cpus, pinning needs $((2 * WORKERS + UPSTREAM_WORKERS)))"
    echo "warning: not pinning, $PINNING"
fi

mkdir -p "$WWW" "$OUT/raw"
for f in 10k.bin:10240 1m.bin:$((1024 * 1024)); do
    [ -s "$WWW/${f%%:*}" ] || head -c "${f##*:}" /dev/urandom > "$WWW/${f%%:*}"
done
cat "$CERTS/server.crt" "$CERTS/server.key" > "$RUN/server.pem"
for f in nginx-h3.conf haproxy-h3.cfg routez-h3.zon upstream.conf; do
    sed "s|UPSTREAM_WORKERS|$UPSTREAM_WORKERS|g; s|WORKERS|$WORKERS|g; s|WWW|$WWW|g; s|CERTS|$CERTS|g; \
         s|ACCESS_LOG|off|g; s|ROUTEZ_LOG|false|g; s|HAPROXY_LOG|no log|g; s|RUN|$RUN|g" \
        "$HERE/conf/$f" > "$RUN/$f"
done

start upstream "$UP_CPUS" nginx -c "$RUN/upstream.conf"
wait_port 19090
up_servers() {
    start nginx "$SERVER_CPUS" nginx -c "$RUN/nginx-h3.conf"; SPID[nginx]=$!
    start haproxy "$SERVER_CPUS" haproxy -f "$RUN/haproxy-h3.cfg"; SPID[haproxy]=$!
    start routez "$SERVER_CPUS" "$ROOT/zig-out/bin/routez" "$RUN/routez-h3.zon"; SPID[routez]=$!
    local p
    for p in "${TLS[@]}"; do wait_port "$p"; done
    for p in "${QUIC[@]}"; do wait_udp "$p"; done
    until pgrep -P "${SPID[nginx]}" >/dev/null; do sleep 0.05; done
}
down_servers() {
    local s
    profile_report
    for s in "${SERVERS[@]}"; do kill "${SPID[$s]}" 2>/dev/null; done
    for s in "${SERVERS[@]}"; do wait "${SPID[$s]}" 2>/dev/null; done
    PIDS=("${PIDS[0]}")
    SPID=()
}

# Sanity: HTTP/3 really is HTTP/3, and every body is byte-exact. h2load alone
# would prove neither, so the gate uses a curl built with HTTP/3.
CURL=$("$ROOT/tests/e2e/curl-h3.sh") || { echo "no curl with HTTP/3"; exit 1; }
"$CURL" --version | grep -q HTTP3 || { echo "curl at $CURL has no HTTP/3"; exit 1; }
up_servers
fail=0
bad() { echo "sanity: $*"; fail=1; }
for s in "${SERVERS[@]}"; do
    for r in "${ROWS[@]}"; do
        serves "$r" "$s" || continue
        url=$(target "$r" "$s")
        ver=--http3-only
        [ "${R_ALPN[$r]}" == h1 ] && ver=--http1.1
        code=$("$CURL" -sk $ver --max-time 20 -o "$RUN/body" -w '%{http_code}' "$url")
        [ "$code" == 200 ] || { bad "$s $r: status $code"; continue; }
        case ${R_PATH[$r]} in
            *.bin) cmp -s "$RUN/body" "$WWW/$(basename "${R_PATH[$r]}")" || bad "$s $r: wrong body" ;;
            *) [ "$(cat "$RUN/body")" == pong ] || bad "$s $r: body '$(head -c 60 "$RUN/body")'" ;;
        esac
        # The protocol actually used, not the one asked for.
        want=3; [ "${R_ALPN[$r]}" == h1 ] && want=1.1
        got=$("$CURL" -sk $ver --max-time 20 -o /dev/null -w '%{http_version}' "$url")
        [ "$got" == "$want" ] || bad "$s $r: HTTP version $got, want $want"
    done
done
down_servers
[ "$fail" == 0 ] || { tail -n 20 "$RUN"/*.log; exit 1; }

{ env_header; cat <<EOF
h2load: $(h2load --version | awk '{print $2}')
curl: $("$CURL" --version | awk 'NR == 1 {print $2}')
openssl: $(openssl version | awk '{print $2}')
workers: $WORKERS
conns: $CONNS
duration: $DURATION
rounds: $ROUNDS
pinning: $PINNING
server_cpus: $SERVER_CPUS
wrk_cpus: $LOAD_CPUS
wide_wrk_cpus: $WIDE_CPUS
upstream_cpus: $UP_CPUS
EOF
} > "$OUT/env.txt"

udp_errors() { awk '/^Udp:/ {getline; print $4 + $6}' /proc/net/snmp; } # InErrors + RcvbufErrors

run_load() { # row server seconds output
    local r=$1 cpus=$LOAD_CPUS threads=$LOAD_THREADS c alpn=--h1
    [ "${R_ALPN[$r]}" == h3 ] && alpn=--h3
    case $r in *proxy*) ;; *) cpus=$WIDE_CPUS threads=$WIDE_THREADS ;; esac
    c=$(conns_of "$r")
    [ "$threads" -gt "$c" ] && threads=$c
    taskset -c "$cpus" h2load "$alpn" -c "$c" -t "$threads" -m "${R_STREAMS[$r]}" \
        -D "$3" "$(target "$r" "$2")" > "$4" 2>&1
}

for r in "${ROWS[@]}"; do
    mapfile -t act < <(active "$r")
    up_servers
    for s in "${act[@]}"; do tree_rss "${SPID[$s]}" > "$OUT/raw/$r.$s.base"; done
    for s in "${act[@]}"; do run_load "$r" "$s" 2 /dev/null; done
    for n in $(seq 1 "$ROUNDS"); do
        for i in $(seq 0 $((${#act[@]} - 1))); do
            s=${act[$(((i + n - 1) % ${#act[@]}))]}
            f="$OUT/raw/$r.$s.$n"
            sleep 1
            grep '^cpu[0-9]' /proc/stat > "$f.stat0"
            udp_errors > "$f.udp0"
            run_load "$r" "$s" "$DURATION" "$f.txt"
            grep '^cpu[0-9]' /proc/stat > "$f.stat1"
            udp_errors > "$f.udp1"
            tree_rss "${SPID[$s]}" > "$f.rss"
            echo "$r $s #$n: $(awk '/req\/s/ {print $4, $5; exit}' "$f.txt")"
        done
    done
    down_servers
done

python3 "$HERE/report_h3.py" "$OUT" && echo && cat "$OUT/table.md"

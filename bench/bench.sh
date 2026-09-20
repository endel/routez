#!/bin/bash
# Throughput of nginx, HAProxy and routez on the same workloads, measured one
# server at a time with wrk. Runs inside bench/run.sh's container; directly on
# a Linux host it needs root and what bench/Dockerfile installs.
# Knobs: WORKERS, CONNS, DURATION (seconds), ROUNDS, WORKLOADS (subset of rows), OUT.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORKERS=${WORKERS:-3}
CONNS=${CONNS:-256}
DURATION=${DURATION:-10}
ROUNDS=${ROUNDS:-3}

. "$HERE/lib.sh"
CERTS="$SRC_QZ/interop/certs"
WWW="$RUN/www"

# Server, wrk and upstream each get their own cores when there are enough;
# otherwise everything shares all of them. wrk spends about what the server
# does per request, so it gets every core the other two don't.
NCPU=$(nproc)
UPSTREAM_WORKERS=2
if [ "$NCPU" -ge $((2 * WORKERS + UPSTREAM_WORKERS)) ]; then
    SERVER_CPUS=0-$((WORKERS - 1)) WRK_CPUS=$WORKERS-$((NCPU - UPSTREAM_WORKERS - 1))
    UP_CPUS=$((NCPU - UPSTREAM_WORKERS))-$((NCPU - 1)) WRK_THREADS=$((NCPU - UPSTREAM_WORKERS - WORKERS))
    # The upstream idles in the handshake row, so wrk takes its cores too.
    HS_WRK_CPUS=$WORKERS-$((NCPU - 1)) HS_THREADS=$((NCPU - WORKERS))
    PINNING="server on cpus $SERVER_CPUS, wrk on $WRK_CPUS ($HS_WRK_CPUS for handshakes), upstream on $UP_CPUS"
else
    SERVER_CPUS=0-$((NCPU - 1)) WRK_CPUS=0-$((NCPU - 1)) UP_CPUS=0-$((NCPU - 1)) WRK_THREADS=$WORKERS
    HS_WRK_CPUS=$WRK_CPUS HS_THREADS=$WORKERS
    PINNING="none ($NCPU cpus, pinning needs $((2 * WORKERS + UPSTREAM_WORKERS)))"
    echo "warning: not pinning, $PINNING"
fi

mkdir -p "$WWW" "$OUT/raw"
head -c 10240 /dev/urandom > "$WWW/10k.bin"
cat "$CERTS/server.crt" "$CERTS/server.key" > "$RUN/server.pem"
for f in nginx.conf haproxy.cfg routez.zon upstream.conf; do
    sed "s|UPSTREAM_WORKERS|$UPSTREAM_WORKERS|g; s|WORKERS|$WORKERS|g; s|WWW|$WWW|g; s|CERTS|$CERTS|g; s|RUN|$RUN|g" \
        "$HERE/conf/$f" > "$RUN/$f"
done

start upstream "$UP_CPUS" nginx -c "$RUN/upstream.conf"
start nginx "$SERVER_CPUS" nginx -c "$RUN/nginx.conf"
start haproxy "$SERVER_CPUS" haproxy -f "$RUN/haproxy.cfg"
start routez "$SERVER_CPUS" "$ROOT/zig-out/bin/routez" "$RUN/routez.zon"

SERVERS=(nginx haproxy routez)
declare -A PLAIN=([nginx]=19080 [routez]=19081 [haproxy]=19082)
declare -A TLS=([nginx]=19443 [routez]=19444 [haproxy]=19445)
read -ra WORKLOADS <<< "${WORKLOADS:-return static proxy tls-return tls-static tls-handshake}"

for p in 19090 "${PLAIN[@]}" "${TLS[@]}"; do wait_port "$p"; done

target() { # workload server -> URL
    local scheme=http port=${PLAIN[$2]} path
    case $1 in tls-*) scheme=https port=${TLS[$2]} ;; esac
    case $1 in *static) path=/10k.bin ;; proxy) path=/up/ ;; *) path=/ping ;; esac
    echo "$scheme://127.0.0.1:$port$path"
}
serves() { ! [[ $2 == haproxy && $1 == *static ]]; } # HAProxy isn't a file server

# Every cell must answer correctly and every TLS port must negotiate the same
# parameters, or the numbers compare different things.
fail=0
bad() { echo "sanity: $*"; fail=1; }
for s in "${SERVERS[@]}"; do
    for w in "${WORKLOADS[@]}"; do
        serves "$w" "$s" || continue
        code=$(curl -sk --max-time 5 -o "$RUN/body" -w '%{http_code}' "$(target "$w" "$s")")
        [ "$code" == 200 ] || { bad "$s $w: status $code"; continue; }
        case $w in
            *static) cmp -s "$RUN/body" "$WWW/10k.bin" || bad "$s $w: wrong body" ;;
            *) [ "$(cat "$RUN/body")" == pong ] || bad "$s $w: body '$(head -c 60 "$RUN/body")'" ;;
        esac
    done
    tls=$(echo | openssl s_client -brief -connect "127.0.0.1:${TLS[$s]}" 2>&1 |
        awk -F': ' '/^Protocol version/ {p=$2} /^Ciphersuite/ {c=$2} /Temp Key|Negotiated TLS1.3 group/ {split($2, k, ","); g=k[1]} END {print p, c, g}')
    [ "$tls" == "TLSv1.3 TLS_AES_128_GCM_SHA256 X25519" ] || bad "$s negotiates '$tls'"
    printf 'GET /ping HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n' |
        openssl s_client -connect "127.0.0.1:${TLS[$s]}" -sess_out "$RUN/sess" -ign_eof >/dev/null 2>&1
    echo | openssl s_client -connect "127.0.0.1:${TLS[$s]}" -sess_in "$RUN/sess" 2>/dev/null | grep -q '^Reused' ||
        bad "$s doesn't resume TLS sessions"
done
[ "$fail" == 0 ] || { tail -n 20 "$RUN"/*.log; exit 1; }

{ env_header; cat <<EOF
wrk: $(wrk -v 2>&1 | awk 'NR == 1 {print $2}')
openssl: $(openssl version | awk '{print $2}')
workers: $WORKERS
conns: $CONNS
duration: $DURATION
rounds: $ROUNDS
pinning: $PINNING
server_cpus: $SERVER_CPUS
wrk_cpus: $WRK_CPUS
wrk_threads: $WRK_THREADS
handshake_wrk_cpus: $HS_WRK_CPUS
upstream_cpus: $UP_CPUS
EOF
} > "$OUT/env.txt"

run_wrk() { # workload server seconds output
    local cpus=$WRK_CPUS threads=$WRK_THREADS extra=()
    [ "$1" == tls-handshake ] && cpus=$HS_WRK_CPUS threads=$HS_THREADS extra=(-H "Connection: close")
    OPENSSL_CONF="$HERE/conf/wrk-openssl.cnf" taskset -c "$cpus" wrk -t "$threads" -c "$CONNS" -d "${3}s" --latency -s "$HERE/report.lua" \
        "${extra[@]}" "$(target "$1" "$2")" > "$4" 2>&1
}

for w in "${WORKLOADS[@]}"; do
    active=()
    for s in "${SERVERS[@]}"; do serves "$w" "$s" && active+=("$s"); done
    for s in "${active[@]}"; do run_wrk "$w" "$s" 2 /dev/null; done
    for r in $(seq 1 "$ROUNDS"); do
        # Rotate who goes first so drift doesn't favour one server.
        for i in $(seq 0 $((${#active[@]} - 1))); do
            s=${active[$(((i + r - 1) % ${#active[@]}))]}
            f="$OUT/raw/$w.$s.$r"
            sleep 1
            grep '^cpu[0-9]' /proc/stat > "$f.stat0"
            run_wrk "$w" "$s" "$DURATION" "$f.txt"
            grep '^cpu[0-9]' /proc/stat > "$f.stat1"
            echo "$w $s #$r: $(awk '/^Requests\/sec/ {print $2}' "$f.txt") req/s"
        done
    done
done

python3 "$HERE/report.py" "$OUT" && echo && cat "$OUT/table.md"

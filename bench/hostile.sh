#!/bin/bash
# What nginx, HAProxy and routez do under load that isn't well behaved: parked
# and stalled connections, connection storms, full TLS handshakes, a reload
# mid-flight and an upstream that dies. Each row is read against the same
# server's own quiet baseline, so the figure is what the abuse costs it.
# Runs inside `bench/run.sh hostile`'s container; on a Linux host it needs root
# and what bench/Dockerfile installs.
# Knobs: WORKERS, CONNS, DURATION (seconds), ROUNDS, LEVELS (held connections), ROWS, OUT.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORKERS=${WORKERS:-3}
CONNS=${CONNS:-256}
DURATION=${DURATION:-10}
ROUNDS=${ROUNDS:-3}
HOLD_COUNT=${LEVELS:-20000}
HANDSHAKES=${HANDSHAKES:-20000}

OUT_PREFIX=hostile- . "$HERE/lib.sh"
CERTS="$SRC_QZ/interop/certs"
WWW="$RUN/www"
build_tool holdconn

# name             kind       servers label
ROWS_ALL="
idle               hold       all   Parked keep-alive connections
slowhead           hold       all   Request heads that never end
slowread           hold       nohap Clients reading a 1 MB body a trickle at a time
storm              storm      all   A new connection per request
handshake-ecdsa    handshake  all   Full TLS handshakes, ECDSA P-256
handshake-rsa      handshake  all   Full TLS handshakes, RSA 2048
reload             reload     all   A reload every 2 s under load
failover           failover   all   An upstream killed mid-run
"
declare -A R_KIND R_SERVERS R_LABEL
ORDER=()
while read -r name kind servers label; do
    [ -n "${name:-}" ] || continue
    ORDER+=("$name") R_KIND[$name]=$kind R_SERVERS[$name]=$servers R_LABEL[$name]=$label
done <<< "$ROWS_ALL"
read -ra ROWS <<< "${ROWS:-${ORDER[*]}}"
for r in "${ROWS[@]}"; do
    [ -n "${R_KIND[$r]:-}" ] || { echo "unknown row '$r'; have: ${ORDER[*]}"; exit 1; }
done

read -ra SERVERS <<< "${SERVERS:-nginx haproxy routez}"
declare -A PLAIN=([nginx]=19080 [routez]=19081 [haproxy]=19082)
declare -A TLS=([nginx]=19443 [routez]=19444 [haproxy]=19445)
declare -A RSA=([nginx]=19484 [routez]=19485 [haproxy]=19486)
declare -A SPID=()
# HAProxy is not a file server, so a row that asks for a file would measure its
# error page rather than the abuse.
serves() { [ "${R_SERVERS[$1]}" == all ] || [ "$2" != haproxy ]; }
active() { local s; for s in "${SERVERS[@]}"; do serves "$1" "$s" && echo "$s"; done; }

NCPU=$(nproc)
BACK_WORKERS=2
if [ "$NCPU" -ge $((2 * WORKERS + BACK_WORKERS)) ]; then
    SERVER_CPUS=0-$((WORKERS - 1))
    LOAD_CPUS=$WORKERS-$((NCPU - BACK_WORKERS - 1)) LOAD_THREADS=$((NCPU - BACK_WORKERS - WORKERS))
    BACK_CPUS=$((NCPU - BACK_WORKERS))-$((NCPU - 1))
    PINNING="server on cpus $SERVER_CPUS, load on $LOAD_CPUS, upstream on $BACK_CPUS"
else
    SERVER_CPUS=0-$((NCPU - 1)) LOAD_CPUS=$SERVER_CPUS BACK_CPUS=$SERVER_CPUS LOAD_THREADS=$WORKERS
    PINNING="none ($NCPU cpus, pinning needs $((2 * WORKERS + BACK_WORKERS)))"
    echo "warning: not pinning, $PINNING"
fi

mkdir -p "$WWW" "$OUT/raw"
[ -s "$WWW/1m.bin" ] || head -c $((1024 * 1024)) /dev/urandom > "$WWW/1m.bin"
cat "$CERTS/server.crt" "$CERTS/server.key" > "$RUN/server.pem"
# An RSA certificate beside the ECDSA one: signing cost is the point of the row.
openssl req -x509 -newkey rsa:2048 -keyout "$RUN/rsa.key" -out "$RUN/rsa.crt" -days 30 -nodes \
    -subj /CN=rsa.bench 2>/dev/null || { echo "could not make an RSA certificate"; exit 1; }
cat "$RUN/rsa.crt" "$RUN/rsa.key" > "$RUN/rsa.pem"
for f in nginx-hostile.conf haproxy-hostile.cfg routez-hostile.zon upstream.conf; do
    sed "s|UPSTREAM_WORKERS|$BACK_WORKERS|g; s|WORKERS|$WORKERS|g; s|WWW|$WWW|g; s|CERTS|$CERTS|g; \
         s|ACCESS_LOG|off|g; s|ROUTEZ_LOG|false|g; s|HAPROXY_LOG|no log|g; s|RUN|$RUN|g" \
        "$HERE/conf/$f" > "$RUN/$f"
done

# Two backends: the shared one, and a second the failover row may kill.
cat > "$RUN/up2.conf" <<EOF
worker_processes 1;
daemon off;
pid $RUN/up2.pid;
error_log stderr error;
events { worker_connections 4096; }
http {
    access_log off;
    default_type text/plain;
    server { listen 127.0.0.1:19102; location / { return 200 "pong"; } }
}
EOF
start upstream "$BACK_CPUS" nginx -c "$RUN/upstream.conf"
wait_port 19090
UP2_PID=
up2_start() {
    [ -n "$UP2_PID" ] && kill -0 "$UP2_PID" 2>/dev/null && return
    start up2 "$BACK_CPUS" nginx -c "$RUN/up2.conf"
    UP2_PID=$!
    wait_port 19102
}
up2_start

up_servers() {
    start nginx "$SERVER_CPUS" nginx -c "$RUN/nginx-hostile.conf"; SPID[nginx]=$!
    start haproxy "$SERVER_CPUS" haproxy -W -f "$RUN/haproxy-hostile.cfg"; SPID[haproxy]=$!
    start routez "$SERVER_CPUS" "$ROOT/zig-out/bin/routez" "$RUN/routez-hostile.zon"; SPID[routez]=$!
    local p
    for p in "${PLAIN[@]}" "${TLS[@]}" "${RSA[@]}"; do wait_port "$p"; done
    until pgrep -P "${SPID[nginx]}" >/dev/null; do sleep 0.05; done
}
down_servers() {
    local s
    profile_report
    for s in "${SERVERS[@]}"; do kill "${SPID[$s]}" 2>/dev/null; done
    for s in "${SERVERS[@]}"; do wait "${SPID[$s]}" 2>/dev/null; done
    SPID=()
}

# Sanity: every port answers, and the handshake client really does not resume,
# or the handshake rows would compare a full handshake against a resumed one.
up_servers
fail=0
bad() { echo "sanity: $*"; fail=1; }
for s in "${SERVERS[@]}"; do
    for u in "http://127.0.0.1:${PLAIN[$s]}/ping" "https://127.0.0.1:${TLS[$s]}/ping" \
        "https://127.0.0.1:${RSA[$s]}/ping"; do
        body=$(curl -sk --max-time 10 "$u")
        [ "$body" == pong ] || bad "$s $u: body '$(echo "$body" | head -c 40)'"
    done
    out=$(h2load --h1 -c 4 -n 4 -m 1 "https://127.0.0.1:${TLS[$s]}/ping" 2>&1)
    echo "$out" | grep -q "Resumption: no" || bad "$s: the handshake client resumed sessions"
    echo "$out" | grep -q "4 succeeded" || bad "$s: h2load got $(echo "$out" | grep -o '[0-9]* succeeded')"
done
down_servers
[ "$fail" == 0 ] || { tail -n 20 "$RUN"/*.log; exit 1; }

{ env_header; cat <<EOF
wrk: $(wrk -v 2>&1 | awk 'NR == 1 {print $2}')
h2load: $(h2load --version | awk '{print $2}')
workers: $WORKERS
conns: $CONNS
duration: $DURATION
rounds: $ROUNDS
held: $HOLD_COUNT
handshakes: $HANDSHAKES
pinning: $PINNING
server_cpus: $SERVER_CPUS
wrk_cpus: $LOAD_CPUS
upstream_cpus: $BACK_CPUS
EOF
} > "$OUT/env.txt"

wrk_ping() { # server seconds output [extra wrk args...]
    local s=$1 secs=$2 f=$3; shift 3
    local threads=$LOAD_THREADS
    [ "$threads" -gt "$CONNS" ] && threads=$CONNS
    taskset -c "$LOAD_CPUS" wrk -t "$threads" -c "$CONNS" -d "${secs}s" --timeout 10s --latency \
        -s "$HERE/report.lua" "$@" "http://127.0.0.1:${PLAIN[$s]}/ping" > "$f" 2>&1
}

run_row() { # row server seconds prefix
    local r=$1 s=$2 secs=$3 f=$4 pid
    case ${R_KIND[$r]} in
        hold)
            # Hold the connections, sample the server's memory while they are
            # held, and measure what a well-behaved client still gets.
            local mode=idle req=/ping
            [ "$r" == slowhead ] && mode=partial
            # A body the server has to hold while the client barely reads it.
            [ "$r" == slowread ] && mode=slow req=/1m.bin
            tree_rss "${SPID[$s]}" > "$f.rss0"
            taskset -c "$LOAD_CPUS" "$RUN/holdconn" "127.0.0.1:${PLAIN[$s]}" \
                --count "$HOLD_COUNT" --mode "$mode" --request "$req" \
                --seconds $((secs + 6)) > "$f.hold" 2>&1 &
            pid=$!
            sleep 5 # let them all be open before anything is measured
            tree_rss "${SPID[$s]}" > "$f.rss1"
            open_fds "${SPID[$s]}" > "$f.fds"
            wrk_ping "$s" "$secs" "$f.txt"
            wait $pid 2>/dev/null ;;
        storm)
            wrk_ping "$s" "$secs" "$f.txt" -H 'Connection: close' ;;
        handshake)
            local port=${TLS[$s]}
            [ "$r" == handshake-rsa ] && port=${RSA[$s]}
            # One request per connection and no session offered, so every
            # connection pays for a full handshake. h2load ends when they are done.
            taskset -c "$LOAD_CPUS" h2load --h1 -c "$HANDSHAKES" -n "$HANDSHAKES" -m 1 \
                -t "$LOAD_THREADS" "https://127.0.0.1:$port/ping" > "$f.txt" 2>&1 ;;
        reload)
            wrk_ping "$s" "$secs" "$f.txt" &
            pid=$!
            local n=0
            while kill -0 $pid 2>/dev/null && [ $n -lt $((secs / 2)) ]; do
                sleep 2
                case $s in
                    nginx) nginx -c "$RUN/nginx-hostile.conf" -s reload 2>/dev/null ;;
                    haproxy) kill -USR2 "${SPID[haproxy]}" 2>/dev/null ;;
                    routez) kill -HUP "${SPID[routez]}" 2>/dev/null ;;
                esac
                n=$((n + 1))
            done
            wait $pid 2>/dev/null
            echo "$n" > "$f.reloads" ;;
        failover)
            # One of the two upstreams dies halfway; the row is what leaks out to
            # clients before the server notices and stops using it.
            local threads=$LOAD_THREADS
            [ "$threads" -gt "$CONNS" ] && threads=$CONNS
            taskset -c "$LOAD_CPUS" wrk -t "$threads" -c "$CONNS" -d "${secs}s" --timeout 10s \
                --latency -s "$HERE/report.lua" "http://127.0.0.1:${PLAIN[$s]}/up/" > "$f.txt" 2>&1 &
            pid=$!
            sleep $((secs / 2))
            kill "$UP2_PID" 2>/dev/null
            wait "$UP2_PID" 2>/dev/null
            UP2_PID=
            wait $pid 2>/dev/null
            up2_start ;;
    esac
}

for r in "${ROWS[@]}"; do
    mapfile -t act < <(active "$r")
    up_servers
    for s in "${act[@]}"; do
        # The quiet baseline this row is read against.
        f="$OUT/raw/$r.$s.base"
        tree_rss "${SPID[$s]}" > "$f.rss"
        wrk_ping "$s" 3 "$f.txt"
    done
    for n in $(seq 1 "$ROUNDS"); do
        for i in $(seq 0 $((${#act[@]} - 1))); do
            s=${act[$(((i + n - 1) % ${#act[@]}))]}
            f="$OUT/raw/$r.$s.$n"
            sleep 1
            grep '^cpu[0-9]' /proc/stat > "$f.stat0"
            run_row "$r" "$s" "$DURATION" "$f"
            grep '^cpu[0-9]' /proc/stat > "$f.stat1"
            tree_rss "${SPID[$s]}" > "$f.rss"
            echo "$r $s #$n: $(awk '/^Requests\/sec/ {print $2" req/s"}' "$f.txt" 2>/dev/null |
                head -1)$(awk '/finished in/ {print $4" req/s"}' "$f.txt" 2>/dev/null | head -1)"
        done
    done
    down_servers
done

python3 "$HERE/report_hostile.py" "$OUT" && echo && cat "$OUT/table.md"

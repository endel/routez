#!/bin/bash
# Concurrent WebSocket connections through nginx, HAProxy and routez, each a
# single process with one worker, to a Node.js `ws` echo app; plus the app
# alone as a baseline. Runs inside `bench/run.sh ws`'s container; directly on
# a Linux host it needs root and what bench/Dockerfile installs.
# Knobs: LEVELS (connection counts), RATE (echoes/s over all connections), HOLD and
# DURATION (seconds), ROUNDS, CLIENTS (load generator processes), SERVERS, OUT.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
read -ra LEVELS <<< "${LEVELS:-1000 10000 50000}"
read -ra SERVERS <<< "${SERVERS:-direct nginx haproxy routez}"
export RATE=${RATE:-10000} HOLD=${HOLD:-5} DURATION=${DURATION:-10}
ROUNDS=${ROUNDS:-3}

OUT_PREFIX=ws- . "$HERE/lib.sh"

# The server and the app get a core each; the load generator gets the rest.
NCPU=$(nproc)
if [ "$NCPU" -ge 4 ]; then
    SERVER_CPUS=0 APP_CPUS=1 CLIENT_CPUS=2-$((NCPU - 1)) CLIENTS=${CLIENTS:-$((NCPU - 2))}
    PINNING="server on cpu $SERVER_CPUS, app on $APP_CPUS, client on $CLIENT_CPUS"
else
    SERVER_CPUS=0-$((NCPU - 1)) APP_CPUS=$SERVER_CPUS CLIENT_CPUS=$SERVER_CPUS CLIENTS=${CLIENTS:-2}
    PINNING="none ($NCPU cpus, pinning needs 4)"
    echo "warning: not pinning, $PINNING"
fi
export CLIENTS

mkdir -p "$OUT/raw"
for f in nginx-ws.conf haproxy-ws.cfg routez-ws.zon; do sed "s|RUN|$RUN|g" "$HERE/conf/$f" > "$RUN/$f"; done

# Four ports: each proxy→app address pair has only ~64k source ports. The
# confs list the same four, and run.sh keeps them out of the ephemeral range.
APP_PORTS=(19191 19192 19193 19194)
declare -A PORT=([nginx]=19180 [routez]=19181 [haproxy]=19182)
url() { # server -> the client's comma-separated target URLs
    if [ "$1" == direct ]; then
        local p u=()
        for p in "${APP_PORTS[@]}"; do u+=("ws://127.0.0.1:$p/ws"); done
        (IFS=,; echo "${u[*]}")
    else
        echo "ws://127.0.0.1:${PORT[$1]}/ws"
    fi
}

up() { # server: start the app and the server, set APP_PID and SERVER_PID
    start app "$APP_CPUS" node "$HERE/ws/app.cjs" "${APP_PORTS[@]}"; APP_PID=$!
    SERVER_PID=
    case $1 in
        nginx) start nginx "$SERVER_CPUS" nginx -c "$RUN/nginx-ws.conf" ;;
        haproxy) start haproxy "$SERVER_CPUS" haproxy -f "$RUN/haproxy-ws.cfg" ;;
        routez) start routez "$SERVER_CPUS" "$ROOT/zig-out/bin/routez" "$RUN/routez-ws.zon" ;;
    esac
    [ "$1" != direct ] && SERVER_PID=$!
    for p in "${APP_PORTS[@]}"; do wait_port "$p"; done
    [ "$1" != direct ] && wait_port "${PORT[$1]}"
    # The master listens before its worker exists; the baseline RSS needs both.
    if [ "$1" == nginx ]; then
        until pgrep -P "$SERVER_PID" >/dev/null; do sleep 0.05; done
    fi
}
down() { kill $SERVER_PID "$APP_PID" 2>/dev/null; wait $SERVER_PID "$APP_PID" 2>/dev/null; PIDS=(); }

# Sanity: every path upgrades and echoes.
fail=0
for s in "${SERVERS[@]}"; do
    up "$s"
    for u in $(url "$s" | tr , ' '); do
        node "$HERE/ws/client.cjs" --check "$u" || fail=1
    done
    down
done
[ "$fail" == 0 ] || { tail -n 20 "$RUN"/*.log; exit 1; }

# Run by the client at each phase boundary. "base" and "held": resident
# memory of the server's process tree and the app, and connections the app
# holds (N whether or not a proxy sits in front). "load0" and "load1": per-cpu
# time only, so sampling adds nothing to the measured window.
export HOOK_APP_PORTS="( sport >= :${APP_PORTS[0]} and sport <= :${APP_PORTS[-1]} )"
cat > "$RUN/hook.sh" <<'EOF'
#!/bin/bash
case $1 in load0|load1) grep '^cpu[0-9]' /proc/stat > "$HOOK_OUT.stat${1#load}"; exit ;; esac
rss() { # pid -> kB of it and its children
    local t=0 p
    [ -n "$1" ] || { echo 0; return; }
    for p in $1 $(pgrep -P "$1"); do t=$((t + $(awk '/^VmRSS/ {print $2}' "/proc/$p/status" 2>/dev/null || echo 0))); done
    echo $t
}
est=$(ss -Htn state established "$HOOK_APP_PORTS" | wc -l)
echo "$1 $(rss "$HOOK_SERVER_PID") $(rss "$HOOK_APP_PID") $est" >> "$HOOK_OUT.rss"
EOF
chmod +x "$RUN/hook.sh"

{ env_header; cat <<EOF
node: $(node -v)
ws: $(node -p 'require("ws/package.json").version')
rate: $RATE
duration: $DURATION
rounds: $ROUNDS
clients: $CLIENTS
pinning: $PINNING
server_cpus: $SERVER_CPUS
app_cpus: $APP_CPUS
client_cpus: $CLIENT_CPUS
EOF
} > "$OUT/env.txt"

for n in "${LEVELS[@]}"; do
    for r in $(seq 1 "$ROUNDS"); do
        # Rotate who goes first so drift doesn't favour one server.
        for i in $(seq 0 $((${#SERVERS[@]} - 1))); do
            s=${SERVERS[$(((i + r - 1) % ${#SERVERS[@]}))]}
            f="$OUT/raw/$n.$s.$r"
            rm -f "$f".*
            up "$s"
            export HOOK="$RUN/hook.sh" HOOK_OUT="$f" HOOK_SERVER_PID="$SERVER_PID" HOOK_APP_PID="$APP_PID"
            "$HOOK" base
            timeout $((HOLD + DURATION + 600)) taskset -c "$CLIENT_CPUS" \
                node "$HERE/ws/client.cjs" "$(url "$s")" "$n" > "$f.json" 2> "$f.err"
            down
            echo "$n $s #$r: $(tail -n 1 "$f.json")"
        done
    done
done

python3 "$HERE/report_ws.py" "$OUT" && echo && cat "$OUT/table.md"

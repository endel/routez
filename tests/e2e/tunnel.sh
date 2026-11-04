#!/bin/bash
# End-to-end checks for `routez tunnel`: an edge, agents, and the local
# servers they share. Needs python3, bun, and a curl with HTTP/3 for the h3
# checks (tests/e2e/curl-h3.sh finds one). WORKERS sets the edge's workers.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; if [ -n "${KEEP:-}" ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi; }
trap cleanup EXIT

[ -n "${SKIP_BUILD:-}" ] || (cd "$ROOT" && zig build) || exit 1
BIN="$ROOT/zig-out/bin/routez"
CERTS="$ROOT/../quic-zig/interop/certs"
WORKERS=${WORKERS:-2}
CURL_BIN=${CURL_BIN:-$("$HERE/curl-h3.sh")}
CURL="$CURL_BIN -s --max-time 10"
SUITE=tunnel
pass=0; fail=0
check() { if [ "$2" == "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL [$SUITE] $1: got '$2' want '$3'"; fi; }
json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)" 2>/dev/null; }
sha() { shasum | cut -c1-40; }
nap() { perl -e "select(undef,undef,undef,$1)"; }
wait_port() {
    for _ in $(seq 1 100); do
        python3 -c "import socket; socket.create_connection(('127.0.0.1', $1), 0.2).close()" 2>/dev/null && return 0
        nap 0.1
    done
    echo "port $1 never came up"; exit 1
}
# Wait (up to $2 tenths of a second) for a file to have something in it.
wait_file() { for _ in $(seq 1 "$2"); do [ -s "$1" ] && return 0; nap 0.1; done; return 1; }
# Wait until a GET through the tunnel answers $2.
wait_status() { for _ in $(seq 1 "${3:-50}"); do [ "$(get_status "$1")" == "$2" ] && return 0; nap 0.1; done; return 1; }
get_status() { $CURL -o /dev/null -w '%{http_code}' --resolve "$1.play.test:28080:127.0.0.1" "http://$1.play.test:28080/"; }
rss() { ps -o rss= -p "$1" | tr -d ' '; }

cp "$HERE/htpasswd" "$WORK/htpasswd"
cat > "$WORK/edge.zon" <<EOF
.{
    .workers = $WORKERS,
    .access_log = false,
    .servers = .{
        .{
            .server_names = .{"localhost"},
            .listen = .{.{ .address = "127.0.0.1", .port = 28443, .tls = true, .quic = true }},
            .tls = .{ .cert = "$CERTS/server.crt", .key = "$CERTS/server.key" },
            .locations = .{
                .{ .prefix = "/.tunnel", .tunnel_accept = .{ .domain = "play.test:28443" } },
                .{ .prefix = "/.tunnel-auth", .tunnel_accept = .{ .domain = "play.test:28443" }, .auth_basic = .{ .user_file = "$WORK/htpasswd" } },
                .{ .prefix = "/metrics", .metrics = true },
            },
        },
        .{
            .server_names = .{"*.play.test"},
            .listen = .{
                .{ .address = "127.0.0.1", .port = 28080 },
                .{ .address = "127.0.0.1", .port = 28443, .tls = true, .quic = true },
            },
            .tls = .{ .cert = "$CERTS/server.crt", .key = "$CERTS/server.key" },
            .locations = .{.{ .prefix = "/", .tunnel_pass = true }},
        },
    },
}
EOF
"$BIN" -t "$WORK/edge.zon" 2>/dev/null || { "$BIN" -t "$WORK/edge.zon"; exit 1; }

python3 "$HERE/upstream.py" 29001 2> "$WORK/upstream.log" & PIDS+=($!)
bun "$HERE/ws_upstream.ts" 29003 & PIDS+=($!)
wait_port 29001; wait_port 29003
start_edge() { "$BIN" "$WORK/edge.zon" 2>> "$WORK/edge.log" & EDGE=$!; PIDS+=($EDGE); wait_port 28080; }
start_edge

# agent NAME LOCAL [options]: a tunnel in the background; its pid in AGENT.
agent() {
    local name=$1 local=$2; shift 2
    : > "$WORK/$name.out"
    "$BIN" tunnel -n "$name" --ca "$CERTS/ca.crt" "$@" "https://localhost:28443/.tunnel${PATH_SUFFIX:-}" "$local" \
        > "$WORK/$name.out" 2>> "$WORK/$name.log" & AGENT=$!; PIDS+=($AGENT)
}
agent game 29001; GAME=$AGENT
agent ws 29003
agent down 29099  # nothing listens there
for n in game ws down; do wait_file "$WORK/$n.out" 100 || echo "agent $n never opened: $(tail -3 "$WORK/$n.log")"; done
check agent-url "$(cat "$WORK/game.out")" "https://game.play.test:28443 -> 127.0.0.1:29001"

G=http://game.play.test:28080
RG="--resolve game.play.test:28080:127.0.0.1 --resolve game.play.test:28443:127.0.0.1"
r=$($CURL $RG -H 'X-Forwarded-For: 203.0.113.7' "$G/hello?x=1")
check http-get "$(json '["path"]' <<< "$r") $(json '["headers"]["X-Real-IP"]' <<< "$r") $(json '["headers"]["X-Forwarded-For"]' <<< "$r")" \
    "/hello?x=1 127.0.0.1 203.0.113.7, 127.0.0.1"
check forwarded-host "$(json '["headers"]["X-Forwarded-Host"]' <<< "$r")" "game.play.test:28080"
check https-get "$($CURL $RG -k https://game.play.test:28443/tls | json '["headers"]["X-Forwarded-Proto"]')" https
BYTES3M=$(python3 -c 'import sys; sys.stdout.buffer.write(bytes(i % 251 for i in range(3000000)))' | sha)
if $CURL_BIN --version | grep -q HTTP3; then
    check h3-get "$($CURL $RG -k --http3-only https://game.play.test:28443/h3 | json '["path"]')" "/h3"
    check h3-download "$($CURL $RG -k --http3-only https://game.play.test:28443/bytes/3000000 | sha)" "$BYTES3M"
    head -c 3000000 /dev/urandom > "$WORK/up3.bin"
    check h3-upload "$($CURL $RG -k --http3-only --data-binary @"$WORK/up3.bin" https://game.play.test:28443/up | json '["received"]')" 3000000
else
    echo "skip [tunnel] h3: no curl with HTTP/3"
fi
check unknown-tunnel "$(get_status nope)" 404
check no-label "$($CURL -o /dev/null -w '%{http_code}' http://127.0.0.1:28080/)" 404
# One client connection, so one worker's pool: the same local connection.
check keepalive "$($CURL $RG "$G/k1" "$G/k2" "$G/k3" | python3 -c 'import sys,json; print(len({json.loads(l)["peer_port"] for l in sys.stdin.read().replace("}{", "}\n{").splitlines()}))')" 1
check download "$($CURL $RG "$G/bytes/3000000" | sha)" "$BYTES3M"
head -c 5000000 /dev/urandom > "$WORK/up.bin"
check upload "$($CURL $RG --data-binary @"$WORK/up.bin" "$G/up" | json '["received"]')" 5000000
check upload-chunked "$($CURL $RG -H 'Transfer-Encoding: chunked' --data-binary @"$WORK/up.bin" "$G/up" | json '["received"]')" 5000000
check chunked "$($CURL $RG "$G/chunked" | wc -c | tr -d ' ')" 5000
check sse "$($CURL $RG -N "$G/sse" | python3 "$HERE/sse_client.py")" streamed
check websocket "$(python3 "$HERE/tunnel_ws.py" ws.play.test:28080 28080)" ws-ok
r=$($CURL -w '\n%{http_code}' --resolve down.play.test:28080:127.0.0.1 http://down.play.test:28080/)
check local-down "$(tail -1 <<< "$r") $(grep -c 'nothing answered at 127.0.0.1:29099' <<< "$r")" "502 1"
check load "$(python3 "$HERE/tunnel_load.py" game.play.test:28080 28080 64 20)" ok
metric() { $CURL -k https://localhost:28443/metrics | python3 "$HERE/check_metrics.py" "$@"; }
check metrics "$(metric routez_tunnels_open) $([ "$(metric routez_tunnel_streams_total)" -gt 0 ] && echo streams)" "3 streams"
# Only Linux spreads one port's connections over the workers.
if [ "$(uname -s)" == Linux ] && [ "$WORKERS" -gt 1 ]; then
    check cross-worker "$([ "$(metric routez_tunnel_streams_cross_worker_total)" -gt 0 ] && echo crossed)" crossed
fi

# A slow client: the edge and the agent hold the local server back rather
# than buffer the body. Holding costs the stream's receive window (6 MiB)
# and the socket buffers; buffering it all would cost 24 MB.
EDGE_BASE=$(rss $EDGE); AGENT_BASE=$(rss $GAME); edge_peak=$EDGE_BASE; agent_peak=$AGENT_BASE
$CURL_BIN -s --max-time 30 --limit-rate 4M $RG "$G/bytes/24000000" -o "$WORK/slow.bin" & SLOW=$!
while kill -0 $SLOW 2>/dev/null; do
    e=$(rss $EDGE); a=$(rss $GAME)
    [ "$e" -gt "$edge_peak" ] && edge_peak=$e; [ "$a" -gt "$agent_peak" ] && agent_peak=$a
    nap 0.1
done
check slow-client-body "$(wc -c < "$WORK/slow.bin" | tr -d ' ')" 24000000
check slow-client-edge "$([ $((edge_peak - EDGE_BASE)) -lt 16384 ] && echo bounded || echo "grew $((edge_peak - EDGE_BASE)) KB")" bounded
check slow-client-agent "$([ $((agent_peak - AGENT_BASE)) -lt 16384 ] && echo bounded || echo "grew $((agent_peak - AGENT_BASE)) KB")" bounded

# Players' WebTransport sessions: the agent opens each again on its local
# WebTransport server, and streams (either side's, either kind) and
# datagrams go both ways.
(cd "$ROOT" && zig build wt-test-client wt-slow-server) || exit 1
WTC="$ROOT/zig-out/bin/wt-test-client"
"$ROOT/zig-out/bin/wt-slow-server" 29004 "$CERTS/server.crt" "$CERTS/server.key" >/dev/null 2>&1 & PIDS+=($!)
agent wt 29001 --wt 29004; WTA=$AGENT
agent wtdown 29001 --wt 29098  # no WebTransport server there
for n in wt wtdown; do wait_file "$WORK/$n.out" 100 || echo "agent $n never opened: $(tail -3 "$WORK/$n.log")"; done
# wt NAME TENTHS ARGS...: start the test client on NAME's tunnel; its pid in WTP.
wt_start() { local name=$1; shift; WTARGS="$name $*"; WT_HOST=$name.play.test "$WTC" 28443 "$CERTS/ca.crt" "$@" > "$WORK/wtc.log" 2>&1 & WTP=$!; }
# ...and its verdict, waiting up to TENTHS. Each client's last lines go to
# wtc-all.log too, as the next client overwrites wtc.log.
wt_verdict() {
    for _ in $(seq 1 "$1"); do kill -0 $WTP 2>/dev/null || break; nap 0.1; done
    kill $WTP 2>/dev/null; wait $WTP 2>/dev/null
    { echo "=== $(date +%T) $WTARGS"; tail -100 "$WORK/wtc.log"; } >> "$WORK/wtc-all.log"
    grep -o 'wt-ok\|wt-fail.*\|wt-rejected [0-9]*' "$WORK/wtc.log" | head -1
}
wt() { local name=$1 t=$2; shift 2; wt_start "$name" "$@"; wt_verdict "$t"; }
check wt-game "$(wt wt 100 0 /push game)" wt-ok
grep -q wt-ok "$WORK/wtc.log" || cat "$WORK/wtc.log"
# A player's connection lands on any worker: until one has crossed, more.
if [ "$(uname -s)" == Linux ] && [ "$WORKERS" -gt 1 ]; then
    games=""
    for _ in $(seq 1 12); do
        [ "$(metric routez_tunnel_player_sessions_cross_worker_total)" -gt 0 ] && break
        games="$games$(wt wt 100 0 /push game) "
    done
    check wt-cross-worker "$([ "$(metric routez_tunnel_player_sessions_cross_worker_total)" -gt 0 ] && echo crossed) $(tr ' ' '\n' <<< "$games" | grep -v '^wt-ok$' | grep -c .)" "crossed 0"
fi
check wt-forwarded "$(wt wt 100 0 /h headers) $(grep '^echo-' "$WORK/wtc.log" | sort | paste -sd '|' -)" \
    "wt-ok echo-x-forwarded-for: 203.0.113.7, 127.0.0.1|echo-x-forwarded-host: wt.play.test|echo-x-forwarded-proto: https|echo-x-real-ip: 127.0.0.1"
check wt-unknown-tunnel "$(wt nope 50 0 /push game)" "wt-rejected 404"
check wt-local-down "$(wt wtdown 150 0 /push game)" "wt-rejected 502"
# 24 MiB into a server reading ~8 MB/s: the edge and the agent hold the
# player back. Holding costs the paused streams' receive windows (6 MiB
# each) and the socket buffers; buffering it all would cost 24 MB on each.
EDGE_BASE=$(rss $EDGE); AGENT_BASE=$(rss $WTA); edge_peak=$EDGE_BASE; agent_peak=$AGENT_BASE
wt_start wt 24 /flood
for _ in $(seq 1 600); do
    kill -0 $WTP 2>/dev/null || break
    e=$(rss $EDGE); a=$(rss $WTA)
    [ "$e" -gt "$edge_peak" ] && edge_peak=$e; [ "$a" -gt "$agent_peak" ] && agent_peak=$a
    nap 0.1
done
check wt-flood "$(wt_verdict 1)" wt-ok; echo "wt-flood growth: edge $((edge_peak - EDGE_BASE)) KB, agent $((agent_peak - AGENT_BASE)) KB"
check wt-flood-edge "$([ $((edge_peak - EDGE_BASE)) -lt 32768 ] && echo bounded || echo "grew $((edge_peak - EDGE_BASE)) KB")" bounded
check wt-flood-agent "$([ $((agent_peak - AGENT_BASE)) -lt 32768 ] && echo bounded || echo "grew $((agent_peak - AGENT_BASE)) KB")" bounded
wait_metric() { for _ in $(seq 1 50); do [ "$(metric "$1")" == "$2" ] && break; nap 0.1; done; metric "$1"; }
check wt-sessions-closed "$(wait_metric routez_tunnel_player_sessions 0)" 0
# Streams the local server opens as it accepts can reach the player's worker
# before its accept does; right after a flood they mostly do.
check wt-game-after-flood "$(wt wt 100 0 /push game)" wt-ok
# The agent goes mid-session: the player's session ends at once, not at an
# idle timeout.
wt_start wt 48 /flood
for _ in $(seq 1 50); do [ "$(metric routez_tunnel_player_sessions)" == 1 ] && break; nap 0.1; done
nap 0.5; kill -INT $WTA
check wt-agent-gone "$(wt_verdict 50 | cut -c1-7) $(wait_metric routez_tunnel_player_sessions 0)" "wt-fail 0"

# A second agent asking for a held name hears 409 and keeps trying.
agent game 29001; DUP=$AGENT
for _ in $(seq 1 50); do grep -q 409 "$WORK/game.log" && break; nap 0.1; done
check name-taken "$(grep -q 'refused the tunnel: 409' "$WORK/game.log" && echo 409) $(kill -0 $DUP 2>/dev/null && echo retrying)" "409 retrying"
kill $DUP; wait $DUP 2>/dev/null

PATH_SUFFIX=-auth agent authd 29001
for _ in $(seq 1 50); do kill -0 $AGENT 2>/dev/null || break; nap 0.1; done
wait $AGENT; code=$?
check auth-required "$code $(grep -c 'refused the tunnel: 401' "$WORK/authd.log")" "1 1"
PATH_SUFFIX=-auth agent authd 29001 -u alice:secret
wait_file "$WORK/authd.out" 100
check auth-ok "$(get_status authd)" 200

# Ctrl-C closes the session: the name is free at once, not at the idle timeout.
kill -INT $GAME
for _ in $(seq 1 50); do kill -0 $GAME 2>/dev/null || break; nap 0.1; done
check agent-exits "$(kill -0 $GAME 2>/dev/null && echo running || echo exited)" exited
check closed-tunnel "$(get_status game)" 404
agent game 29001; GAME=$AGENT
wait_file "$WORK/game.out" 100
check reopened "$(get_status game)" 200

# An agent without -n: the edge's pick holds across the reload and the restart.
"$BIN" tunnel --ca "$CERTS/ca.crt" https://localhost:28443/.tunnel 29001 > "$WORK/anon.out" 2>> "$WORK/anon.log" & PIDS+=($!)
wait_file "$WORK/anon.out" 100
ANON=$(sed -n 's#^https://\([a-z0-9]*\)\..*#\1#p' "$WORK/anon.out")
check unnamed "$(get_status "$ANON")" 200

# A reload: the edge tells agents it is draining, and each one's next
# session takes its name over before the old one goes. Requests keep landing.
: > "$WORK/reload.txt"
( for _ in $(seq 1 80); do echo "$(get_status game)" >> "$WORK/reload.txt"; nap 0.1; done ) & LOOP=$!
nap 0.5; kill -HUP $EDGE
wait $LOOP
check reload "$(sort "$WORK/reload.txt" | uniq -c | awk '{printf "%s:%s ", $2, $1}')" "200:80 "
check reload-took-over "$(grep -c 'draining this session' "$WORK/game.log")" 1

# The edge restarts: agents come back by themselves.
kill $EDGE; wait $EDGE 2>/dev/null
start_edge
for n in game authd $ANON; do wait_status $n 200 300; done
wait_status ws 400 300  # its server answers a plain GET so
check unnamed-kept-name "$(grep -c . "$WORK/anon.out") $(grep -c 'draining this session' "$WORK/anon.log")" "1 2"
# On the new generation by the restart, so told to drain a second time.
check moved-before-restart "$(grep -c 'draining this session' "$WORK/game.log")" 2
check edge-restart "$(get_status game) $(get_status authd) $(python3 "$HERE/tunnel_ws.py" ws.play.test:28080 28080)" "200 200 ws-ok"

if grep -qiE "panic|segmentation|reached unreachable" "$WORK"/*.log; then
    fail=$((fail+1)); echo "FAIL [tunnel] crash:"; grep -iE -B2 -A8 "panic|segmentation|unreachable" "$WORK"/*.log | head -40
fi
echo "tunnel: passed=$pass failed=$fail"
if [ $fail -ne 0 ]; then echo "--- edge log (tail)"; tail -30 "$WORK/edge.log"; echo "--- game agent log (tail)"; tail -20 "$WORK/game.log"; fi
[ $fail -eq 0 ]

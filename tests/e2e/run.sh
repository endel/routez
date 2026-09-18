#!/bin/bash
# End-to-end checks against a real server and toy upstreams.
# Needs: python3, bun (WebSocket upstream), node >= 22 (WebSocket client), curl.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

(cd "$ROOT" && zig build) || exit 1
mkdir -p "$WORK/www/sub"
echo '<h1>hello</h1>' > "$WORK/www/index.html"
echo 'sub file' > "$WORK/www/sub/a.txt"
head -c 3000000 /dev/urandom > "$WORK/www/big.bin"
mkdir -p "$WORK/gz"
for i in $(seq 1 2000); do echo "line $i: the quick brown fox jumps over the lazy dog"; done > "$WORK/gz/text.txt"
mkdir -p "$WORK/spa/assets" "$WORK/spa/docs"
echo '<h1>spa</h1>' > "$WORK/spa/index.html"
echo 'console.log(1)' > "$WORK/spa/assets/app.js"
echo 'docs' > "$WORK/spa/docs/index.html"
CERTS="$ROOT/../quic-zig/interop/certs"
sed "s|WWW|$WORK/www|; s|CERTS|$CERTS|g" "$HERE/routez.zon" > "$WORK/routez.zon"

python3 "$HERE/upstream.py" 19001 & PIDS+=($!)
python3 "$HERE/upstream.py" 19002 & PIDS+=($!)
python3 "$HERE/slow_upstream.py" "$WORK/www" & PIDS+=($!)
# The HTTPS upstream needs a Python whose ssl has TLS 1.3 (not Xcode's LibreSSL one).
for PY_TLS in python3 /opt/homebrew/bin/python3 ""; do
    [ -n "$PY_TLS" ] && "$PY_TLS" -c 'import ssl, sys; sys.exit(not ssl.HAS_TLSv1_3)' 2>/dev/null && break
done
[ -n "$PY_TLS" ] || { echo "no python3 with TLS 1.3 for the HTTPS upstream"; exit 1; }
"$PY_TLS" "$HERE/upstream.py" 19005 "$CERTS/server.crt" "$CERTS/server.key" & PIDS+=($!)
bun "$HERE/ws_upstream.ts" & PIDS+=($!)
QZ="$ROOT/../quic-zig"
(cd "$ROOT" && zig build wt-slow-server) || exit 1
"$ROOT/zig-out/bin/wt-slow-server" 4451 "$CERTS/server.crt" "$CERTS/server.key" >/dev/null 2>&1 & PIDS+=($!)
"$ROOT/zig-out/bin/wt-slow-server" 4452 "$CERTS/server.crt" "$CERTS/server.key" 64 >/dev/null 2>&1 & PIDS+=($!)
(cd "$QZ" && exec ./zig-out/bin/wt-echo-server --cert interop/certs/server.crt --key interop/certs/server.key --port 4450 >/dev/null 2>&1) & PIDS+=($!)

# Wait until a TCP port accepts connections (slow CI machines start slowly).
wait_port() {
    for _ in $(seq 1 100); do
        python3 -c "import socket; socket.create_connection(('127.0.0.1', $1), 0.2).close()" 2>/dev/null && return 0
        perl -e 'select(undef,undef,undef,0.1)'
    done
    echo "port $1 never came up"; exit 1
}
for p in 19001 19002 19003 19004 19005; do wait_port $p; done
"$ROOT/zig-out/bin/routez" "$WORK/routez.zon" 2> "$WORK/server.log" & SERVER=$!; PIDS+=($SERVER)
wait_port 18080
# Health checks start optimistic; wait out one probe round so a slow
# upstream start can't flip them mid-suite.
for _ in $(seq 1 50); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/api/ready)" == 200 ] && break
    perl -e 'select(undef,undef,undef,0.1)'
done

# Homebrew curl: TLS 1.3 and HTTP/3 support.
CURL_BIN=$(command -v /opt/homebrew/opt/curl/bin/curl || command -v curl)
pass=0; fail=0
check() { if [ "$2" == "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL [$SUITE] $1: got '$2' want '$3'"; fi; }
json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)" 2>/dev/null; }
sha() { shasum | cut -c1-40; }

suite() {
B=$1
CURL="$CURL_BIN -s --max-time 10 --cacert $CERTS/ca.crt"

check index "$($CURL "$B/")" "<h1>hello</h1>"
check fixed "$($CURL "$B/ping")" "pong"
check 404 "$($CURL -o /dev/null -w '%{http_code}' "$B/nope")" 404
check dir-redirect "$($CURL -o /dev/null -w '%{http_code} %{redirect_url}' "$B/sub")" "301 $B/sub/"
check traversal "$($CURL -o /dev/null -w '%{http_code}' --path-as-is "$B/../etc/passwd")" 400
check big-file "$($CURL "$B/big.bin" | sha)" "$(sha < "$WORK/www/big.bin")"
check range "$($CURL -H 'Range: bytes=10-19' "$B/big.bin" | sha)" "$(dd if="$WORK/www/big.bin" bs=1 skip=10 count=10 2>/dev/null | sha)"
ET=$($CURL -D - -o /dev/null "$B/" | grep -i etag | cut -d' ' -f2 | tr -d '\r')
check not-modified "$($CURL -o /dev/null -w '%{http_code}' -H "If-None-Match: $ET" "$B/")" 304
check head "$($CURL -I "$B/big.bin" | grep -i content-length | tr -d '\r' | tr A-Z a-z)" "content-length: 3000000"
check redirect-vars "$($CURL -o /dev/null -w '%{http_code} %{redirect_url}' "$B/old/a%20b?c=1")" "301 https://127.0.0.1/old/a%20b?c=1"
check header-vars "$($CURL -D - -o /dev/null "$B/old/a%20b?c=1" | grep -i '^x-vars' | tr -d '\r')" "x-vars: ${B%%:*} /old/a%20b ?c=1 127.0.0.1"
check proxy-header-vars "$($CURL "$B/api2/h?q=1" | json '["headers"]["x-orig"]')" "/api2/h?q=1"
check try-files-file "$($CURL "$B/spa/assets/app.js")" "console.log(1)"
check try-files-dir "$($CURL "$B/spa/docs")" "docs"
check try-files-fallback "$($CURL -w '%{http_code}' "$B/spa/deep/link" | tr -d '\n')" "<h1>spa</h1>200"
check try-files-traversal "$($CURL -o /dev/null -w '%{http_code}' --path-as-is "$B/spa/../../etc/passwd") $($CURL -o /dev/null -w '%{http_code}' --path-as-is "$B/spa/%2e%2e/%2e%2e/etc/passwd")" "400 400"
check try-files-status "$($CURL -o /dev/null -w '%{http_code}' "$B/sub/missing") $($CURL "$B/sub/a.txt")" "404 sub file"
check proxy-path "$($CURL "$B/api/hello?x=1" | json '["path"]')" "/hello?x=1"
check proxy-xff "$($CURL "$B/api/h" | json '["headers"]["X-Forwarded-For"]')" "127.0.0.1"
check round-robin "$(for i in 1 2 3 4; do $CURL "$B/api/p" | json '["port"]'; done | sort -u | wc -l | tr -d ' ')" 2
check chunked-upstream "$($CURL "$B/api/chunked" | wc -c | tr -d ' ')" 5000
check post-sized "$($CURL -X POST --data-binary @"$WORK/www/big.bin" "$B/api/up" | json '["received"]')" 3000000
check post-chunked "$($CURL -X POST -H 'Transfer-Encoding: chunked' --data-binary @"$WORK/www/big.bin" "$B/api/up" | json '["received"]')" 3000000
[ "$SUITE" != h3 ] && check keepalive "$($CURL -v "$B/ping" "$B/ping" "$B/api/x" 2>&1 | grep -c 'Re-using\|Reusing')" 2
[ "$SUITE" == http ] && check pipelining "$(python3 "$HERE/pipe.py" 'GET /ping HTTP/1.1\r\nHost: a\r\n\r\nGET /sub/a.txt HTTP/1.1\r\nHost: a\r\n\r\nGET /api/q HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n' | grep -o 'HTTP/1.1 200' | wc -l | tr -d ' ')" 3
[ "$SUITE" != h3 ] && check websocket "$(NODE_EXTRA_CA_CERTS=$CERTS/ca.crt node "$HERE/ws_client.mjs" ${B/http/ws}/ws/echo)" "ws-ok"
check gateway-timeout "$($CURL -o /dev/null -w '%{http_code}' "$B/slow/x")" 504
check slow-client "$($CURL --limit-rate 4M "$B/slow/big" | sha)" "$(sha < "$WORK/www/big.bin")"
# Default read timeout: the 1 s one on /slow/ is for the 504 check, and a
# slow reader may still be draining its socket buffer that long.
check slow-upstream-upload "$($CURL -X POST --data-binary @"$WORK/www/big.bin" "$B/slowup/up")" 3000000
[ "$SUITE" == http ] && check smuggling "$(python3 "$HERE/pipe.py" 'POST /api/x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' | grep -o 'HTTP/1.1 [0-9]*')" "HTTP/1.1 400"

}

SUITE=http suite http://127.0.0.1:18080
SUITE=https suite https://127.0.0.1:18443
if $CURL_BIN --version | grep -q HTTP3; then
    CURL_TCP=$CURL_BIN; CURL_BIN="$CURL_BIN --http3-only"
    SUITE=h3 suite https://127.0.0.1:18443
    CURL_BIN=$CURL_TCP
else
    echo "skipping HTTP/3 suite: $CURL_BIN has no HTTP/3 support"
fi
SUITE=h3 check alt-svc "$($CURL_BIN -s -D - -o /dev/null --cacert $CERTS/ca.crt https://127.0.0.1:18443/ping | grep -i alt-svc | tr -d '\r')" 'Alt-Svc: h3=":18443"; ma=86400'
OPENSSL=$(command -v "$(brew --prefix openssl@3 2>/dev/null)/bin/openssl" || command -v openssl)
echo | $OPENSSL s_client -connect 127.0.0.1:18443 -tls1_3 -CAfile $CERTS/ca.crt -sess_out "$WORK/sess" -ign_eof >/dev/null 2>&1 <<< $'GET /ping HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n'
SUITE=https check tls-resumption "$(echo | $OPENSSL s_client -connect 127.0.0.1:18443 -tls1_3 -CAfile $CERTS/ca.crt -sess_in "$WORK/sess" 2>/dev/null | grep -c '^Reused')" 1
SUITE=https check tls-alpn "$($CURL_BIN -s -o /dev/null -w '%{http_version}' --cacert $CERTS/ca.crt https://127.0.0.1:18443/ping)" "1.1"
SUITE=https check plain-http-on-tls-port "$($CURL_BIN -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18443/ping)" "000"
SUITE=features check gzip-encoding "$($CURL_BIN -s -H 'Accept-Encoding: gzip' -D - -o /dev/null http://127.0.0.1:18080/gz/text.txt | grep -i '^content-encoding' | tr -d '\r' | tr A-Z a-z)" "content-encoding: gzip"
SUITE=features check gzip-content "$($CURL_BIN -s --compressed http://127.0.0.1:18080/gz/text.txt | sha)" "$(sha < "$WORK/gz/text.txt")"
SUITE=features check gzip-smaller "$([ "$($CURL_BIN -s -H 'Accept-Encoding: gzip' http://127.0.0.1:18080/gz/text.txt | wc -c)" -lt 20000 ] && echo yes)" yes
SUITE=features check gzip-not-asked "$($CURL_BIN -s -D - -o /dev/null http://127.0.0.1:18080/gz/text.txt | grep -ci '^content-encoding')" 0
SUITE=features check add-headers "$($CURL_BIN -s -D - -o /dev/null http://127.0.0.1:18080/gz/text.txt | grep -i '^x-served-by' | tr -d '\r')" "x-served-by: routez"
SUITE=features check set-header-host "$($CURL_BIN -s http://127.0.0.1:18080/api2/h | json '["headers"]["Host"]')" "upstream.local"
SUITE=features check set-header-add "$($CURL_BIN -s http://127.0.0.1:18080/api2/h | json '["headers"]["x-custom"]')" "v1"
SUITE=features check set-header-remove "$($CURL_BIN -s http://127.0.0.1:18080/api2/h | json '.get("headers").get("User-Agent")')" "None"
SUITE=features check rate-limit "$(for i in 1 2 3 4 5 6; do $CURL_BIN -s -o /dev/null -w '%{http_code} ' http://127.0.0.1:18080/limited; done)" "200 200 200 429 429 429 "

# HTTPS upstreams. The health checks (TLS too) have had two rounds by now,
# enough to take the upstream down if they failed.
SUITE=tls-upstream
B=http://127.0.0.1:18080
check verified "$($CURL_BIN -s "$B/tls/hello?x=1" | json '["path"]')" "/hello?x=1"
check post "$($CURL_BIN -s -X POST --data-binary @"$WORK/www/big.bin" $B/tls/up | json '["received"]')" 3000000
check download "$($CURL_BIN -s --limit-rate 4M $B/tls/bytes/3000000 | sha)" "$(python3 -c 'import sys; sys.stdout.buffer.write(bytes(i % 251 for i in range(3000000)))' | sha)"
check keepalive "$(for i in 1 2 3; do $CURL_BIN -s $B/tls/k | json '["peer_port"]'; done | sort -u | wc -l | tr -d ' ')" 1
check unverified "$($CURL_BIN -s -o /dev/null -w '%{http_code}' $B/tls-insecure/x)" 200
check wrong-ca "$($CURL_BIN -s -o /dev/null -w '%{http_code}' $B/tls-wrong-ca/x)" 502
check wrong-name "$($CURL_BIN -s -o /dev/null -w '%{http_code}' $B/tls-wrong-name/x)" 502
check health "$(grep -c '19005 is unhealthy' "$WORK/server.log")" 0

# Reload: edit the config, SIGHUP, keep serving throughout.
(for i in $(seq 1 100); do $CURL_BIN -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/ping; done > "$WORK/reload_codes.txt") & LOOP=$!
python3 -c "import sys; p=sys.argv[1]; s=open(p).read().replace('pong\\\\n', 'pong2\\\\n'); open(p,'w').write(s)" "$WORK/routez.zon"
kill -HUP $SERVER
for _ in $(seq 1 50); do [ "$($CURL_BIN -s http://127.0.0.1:18080/ping)" == pong2 ] && break; perl -e 'select(undef,undef,undef,0.1)'; done
wait $LOOP
# The old generation keeps its QUIC socket until it has drained; wait it out
# so the QUIC checks below don't land on it.
for _ in $(seq 1 100); do grep -q "worker 0 stopped" "$WORK/server.log" && break; perl -e 'select(undef,undef,undef,0.1)'; done
SUITE=reload check reload-applied "$($CURL_BIN -s http://127.0.0.1:18080/ping)" "pong2"
SUITE=reload check reload-no-errors "$(sort -u "$WORK/reload_codes.txt" | tr '\n' ' ')" "200 "

SUITE=limits check per-ip-limit "$(python3 "$HERE/conn_limit.py" 25)" 5
SUITE=limits check stub-status "$($CURL_BIN -s http://127.0.0.1:18080/status | grep -c '^Active connections: ')" 1

# QUIC connection migration across workers: four workers share UDP 18444;
# a NAT relay moves the client to a new source port mid-connection, which
# the kernel usually hashes to another worker. Steering by connection ID
# keeps every connection alive. (macOS hands all of a port's UDP to one
# socket, so only Linux really exercises the steering.)
(cd "$ROOT" && zig build h3-test-client) || exit 1
cat > "$WORK/mig.zon" <<EOF2
.{ .access_log = false, .workers = 4, .servers = .{.{
    .listen = .{.{ .address = "127.0.0.1", .port = 18444, .quic = true, .tcp = false }},
    .tls = .{ .cert = "$CERTS/server.crt", .key = "$CERTS/server.key" },
    .locations = .{ .{ .prefix = "/", .@"return" = .{ .body = "ok" } }, .{ .prefix = "/status", .stub_status = true } },
}} }
EOF2
"$ROOT/zig-out/bin/routez" "$WORK/mig.zon" 2> "$WORK/mig.log" & MIG=$!; PIDS+=($MIG)
perl -e 'select(undef,undef,undef,0.5)'
migrated=0
for i in $(seq 1 8); do
    python3 "$HERE/nat_relay.py" 18500 18444 12 > /dev/null & NAT=$!
    perl -e 'select(undef,undef,undef,0.3)'
    "$ROOT/zig-out/bin/h3-test-client" 18500 "$CERTS/ca.crt" 40 > "$WORK/mig_client.log" 2>&1 && migrated=$((migrated+1))
    kill $NAT; wait $NAT 2>/dev/null
done
SUITE=migration check survives-rebinding "$migrated" 8
kill $MIG; wait $MIG 2>/dev/null
echo "migration: $(grep -o 'quic steered: [0-9]*' "$WORK/mig.log")"

# limits.quic_idle_timeout_ms: an idle connection is dropped after ~1.5 s.
cat > "$WORK/idle.zon" <<EOF2
.{ .access_log = false, .limits = .{ .quic_idle_timeout_ms = 1500 }, .servers = .{.{
    .listen = .{.{ .address = "127.0.0.1", .port = 18446, .quic = true }},
    .tls = .{ .cert = "$CERTS/server.crt", .key = "$CERTS/server.key" },
    .locations = .{ .{ .prefix = "/status", .stub_status = true }, .{ .prefix = "/", .@"return" = .{ .body = "ok" } } },
}} }
EOF2
"$ROOT/zig-out/bin/routez" "$WORK/idle.zon" 2> "$WORK/idle.log" & IDLE=$!; PIDS+=($IDLE)
perl -e 'select(undef,undef,undef,0.5)'
quic_conns() { $CURL_BIN -s http://127.0.0.1:18446/status | grep -o 'quic (this worker): [0-9]*' | grep -o '[0-9]*$'; }
"$ROOT/zig-out/bin/h3-test-client" 18446 "$CERTS/ca.crt" 1 idle > "$WORK/idle_client.log" 2>&1 & IC=$!
for _ in $(seq 1 50); do grep -q h3-idle "$WORK/idle_client.log" && break; perl -e 'select(undef,undef,undef,0.05)'; done
# The timeout is at least 3 PTOs (RFC 9000 §10.1), which a slow runner's RTT
# estimates can stretch past 1.5 s; the default would hold it 30 s.
now_ms() { perl -MTime::HiRes=time -e 'printf "%d", time*1000'; }
t0=$(now_ms); open_conns=$(quic_conns)
while [ "$(quic_conns)" != 0 ] && [ $(($(now_ms) - t0)) -lt 15000 ]; do perl -e 'select(undef,undef,undef,0.1)'; done
waited=$(($(now_ms) - t0))
kill $IC 2>/dev/null; wait $IC 2>/dev/null
SUITE=quic-idle check server-drops-idle "$open_conns $([ $waited -ge 700 ] && [ $waited -lt 12000 ] && echo in-time || echo "after ${waited}ms")" "1 in-time"
kill $IDLE; wait $IDLE 2>/dev/null

# WebTransport through the relay: a stream and a datagram, echoed.
(cd "$ROOT" && zig build wt-test-client) || exit 1
"$ROOT/zig-out/bin/wt-test-client" 18443 "$CERTS/ca.crt" > "$WORK/wt.log" 2>&1 & WT=$!
for i in $(seq 1 50); do kill -0 $WT 2>/dev/null || break; perl -e 'select(undef,undef,undef,0.1)'; done
kill $WT 2>/dev/null; wait $WT 2>/dev/null
SUITE=wt check webtransport-relay "$(grep -o 'wt-ok\|wt-fail.*' "$WORK/wt.log")" "wt-ok"

# 24 MiB into an upstream that reads ~8 MB/s: the relay must hold the client
# back rather than buffer it, so routez's memory grows by far less than 24 MiB.
rss() { ps -o rss= -p $SERVER | tr -d ' '; }
base=$(rss); peak=$base
"$ROOT/zig-out/bin/wt-test-client" 18443 "$CERTS/ca.crt" 24 /wt-slow > "$WORK/wtflood.log" 2>&1 & WT=$!
for _ in $(seq 1 600); do kill -0 $WT 2>/dev/null || break; r=$(rss); [ "$r" -gt "$peak" ] && peak=$r; perl -e 'select(undef,undef,undef,0.1)'; done
kill $WT 2>/dev/null; wait $WT 2>/dev/null
SUITE=wt check webtransport-flood "$(grep -o 'wt-ok\|wt-fail.*' "$WORK/wtflood.log")" "wt-ok"
grep -q wt-ok "$WORK/wtflood.log" || tail -5 "$WORK/wtflood.log"
SUITE=wt check webtransport-backpressure "$([ $((peak - base)) -lt 16384 ] && echo bounded || echo "grew $((peak - base)) KB")" bounded

# An upstream granting 64 KiB of session credit (WT_MAX_DATA): a write past
# it is refused, not buffered, so the relay must hold it rather than drop it.
"$ROOT/zig-out/bin/wt-test-client" 18443 "$CERTS/ca.crt" 4 /wt-credit > "$WORK/wtcredit.log" 2>&1 & WT=$!
for _ in $(seq 1 300); do kill -0 $WT 2>/dev/null || break; perl -e 'select(undef,undef,undef,0.1)'; done
kill $WT 2>/dev/null; wait $WT 2>/dev/null
SUITE=wt check webtransport-session-credit "$(grep -o 'wt-ok\|wt-fail.*' "$WORK/wtcredit.log")" "wt-ok"

B=http://127.0.0.1:18080
CURL="$CURL_BIN -s --max-time 10"
SUITE=failover
kill "${PIDS[1]}"; wait "${PIDS[1]}" 2>/dev/null; sleep 0.2  # take down 19002
check failover "$(for i in 1 2 3 4 5 6; do $CURL -o /dev/null -w '%{http_code}' "$B/api/f"; done)" "200200200200200200"

if grep -qiE "panic|segmentation" "$WORK/server.log"; then fail=$((fail+1)); echo "FAIL server crashed:"; cat "$WORK/server.log"; fi
# A connection that never sends a request mustn't hold the stop for the
# whole drain window.
python3 -c "import socket, time; s = socket.create_connection(('127.0.0.1', 18080)); time.sleep(30)" & SILENT=$!; PIDS+=($SILENT)
perl -e 'select(undef,undef,undef,0.3)'
kill -TERM $SERVER
for _ in $(seq 1 30); do kill -0 $SERVER 2>/dev/null || break; perl -e 'select(undef,undef,undef,0.1)'; done
if kill -0 $SERVER 2>/dev/null; then fail=$((fail+1)); echo "FAIL graceful stop within 3 s"; else pass=$((pass+1)); fi
echo "passed=$pass failed=$fail"
if [ $fail -ne 0 ]; then echo "--- routez log (tail)"; tail -50 "$WORK/server.log"; fi
[ $fail -eq 0 ]

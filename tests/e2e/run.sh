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

# A curl with TLS 1.3 and HTTP/3; CI must not skip the HTTP/3 checks.
CURL_BIN=${CURL_BIN:-$("$HERE/curl-h3.sh")}
if ! $CURL_BIN --version | grep -q HTTP3 && [ -n "${CI:-}" ]; then echo "no curl with HTTP/3 on CI"; exit 1; fi
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
# The held connections' closes race the next accept, which the per-IP
# limit refuses until they are processed.
for _ in $(seq 1 20); do $CURL_BIN -s http://127.0.0.1:18080/status | grep -q '^Active connections: ' && break; perl -e 'select(undef,undef,undef,0.05)'; done
SUITE=limits check stub-status "$($CURL_BIN -s http://127.0.0.1:18080/status | grep -c '^Active connections: ')" 1

# Limits hold across workers: four of them, each taking its share of the
# connections (on Linux; macOS gives one worker a port's TCP), and HTTP/3.
cat > "$WORK/shared.zon" <<EOF2
.{ .access_log = false, .workers = 4, .limits = .{ .max_connections_per_ip = 8 }, .servers = .{.{
    .listen = .{.{ .address = "127.0.0.1", .port = 18470, .tls = true, .quic = true }, .{ .address = "127.0.0.1", .port = 18471 }},
    .tls = .{ .cert = "$CERTS/server.crt", .key = "$CERTS/server.key" },
    .locations = .{
        .{ .prefix = "/", .@"return" = .{ .body = "ok" } },
        .{ .prefix = "/burst", .@"return" = .{ .body = "ok" }, .limit_req = .{ .rate = 1, .burst = 9 } },
        .{ .prefix = "/za", .@"return" = .{ .body = "ok" }, .limit_req = .{ .zone = "z", .rate = 1, .burst = 5 } },
        .{ .prefix = "/zb", .@"return" = .{ .body = "ok" }, .limit_req = .{ .zone = "z", .rate = 1, .burst = 5 } },
        .{ .prefix = "/metrics", .metrics = true },
    },
}} }
EOF2
"$ROOT/zig-out/bin/routez" "$WORK/shared.zon" 2> "$WORK/shared.log" & SHARED=$!; PIDS+=($SHARED)
wait_port 18471
SCURL="$CURL_BIN -s --max-time 10 --cacert $CERTS/ca.crt"
# 40 requests, each on a new connection, well inside a second: rate + burst
# is 10 (11 if a second ticks by), where per-worker buckets would allow 40.
codes=$(for i in $(seq 1 40); do echo "url = \"http://127.0.0.1:18471/burst\""; done | $SCURL -K - -Z --parallel-max 8 -H 'Connection: close' -o /dev/null -w '%{http_code}\n')
ok=$(grep -c 200 <<< "$codes")
SUITE=shared-limits check limit-req-across-workers "$([ "$ok" -ge 10 ] && [ "$ok" -le 11 ] && echo ok || echo "$ok allowed")" ok
# One zone behind two locations, and both protocols when curl has HTTP/3:
# 6 in all, then 429.
status_of() { for u in "$@"; do $SCURL ${H3:-} -o /dev/null -w '%{http_code} ' "$u"; done; }
if $CURL_BIN --version | grep -q HTTP3; then
    zone="$(status_of http://127.0.0.1:18471/za http://127.0.0.1:18471/zb https://127.0.0.1:18470/za)"
    zone+="$(H3=--http3-only status_of https://127.0.0.1:18470/zb https://127.0.0.1:18470/za https://127.0.0.1:18470/zb https://127.0.0.1:18470/za)"
else
    zone="$(status_of http://127.0.0.1:18471/za http://127.0.0.1:18471/zb http://127.0.0.1:18471/za http://127.0.0.1:18471/zb http://127.0.0.1:18471/za http://127.0.0.1:18471/zb http://127.0.0.1:18471/za)"
fi
SUITE=shared-limits check zone "$zone" "200 200 200 200 200 200 429 "
SUITE=shared-limits check per-ip-across-workers "$(python3 "$HERE/conn_limit.py" 20 18471)" 12
# A reload keeps the buckets (about a second has refilled one request, where
# a fresh bucket would allow 6), and releases what the old workers counted.
kill -HUP $SHARED
for _ in $(seq 1 100); do [ "$(grep -c 'worker [0-3] stopped' "$WORK/shared.log")" -ge 4 ] && break; perl -e 'select(undef,undef,undef,0.1)'; done
after=$(for i in $(seq 1 10); do echo 'url = "http://127.0.0.1:18471/za"'; done | $SCURL -K - -o /dev/null -w '%{http_code}\n' | grep -c 200)
SUITE=shared-limits check bucket-survives-reload "$([ "$after" -le 4 ] && echo kept || echo "$after allowed")" kept
SUITE=shared-limits check per-ip-after-reload "$(python3 "$HERE/conn_limit.py" 12 18471)" 4
for _ in $(seq 1 20); do $SCURL -o /dev/null http://127.0.0.1:18471/ && break; perl -e 'select(undef,undef,undef,0.05)'; done
SUITE=shared-limits check metrics "$($SCURL http://127.0.0.1:18471/metrics | python3 "$HERE/check_metrics.py" routez_http_requests_limited_total routez_limit_table_capacity)" "$((40 - ok + 1 + 10 - after)) 100032"
kill $SHARED; wait $SHARED 2>/dev/null

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

# An RSA certificate next to an EC one on the same listener, chosen by SNI;
# its key in PKCS#1 ("BEGIN RSA PRIVATE KEY").
$OPENSSL req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/rsa8.key" -out "$WORK/rsa.crt" -days 2 \
    -subj /CN=rsa.test -addext subjectAltName=DNS:rsa.test 2>/dev/null
$OPENSSL rsa -in "$WORK/rsa8.key" -traditional -out "$WORK/rsa.key" 2>/dev/null
cat > "$WORK/rsa.zon" <<EOF2
.{ .access_log = false, .servers = .{
    .{
        .server_names = .{"localhost"},
        .listen = .{.{ .address = "127.0.0.1", .port = 18447, .tls = true, .quic = true }},
        .tls = .{ .cert = "$CERTS/server.crt", .key = "$CERTS/server.key" },
        .locations = .{.{ .prefix = "/", .@"return" = .{ .body = "ec" } }},
    },
    .{
        .server_names = .{"rsa.test"},
        .listen = .{.{ .address = "127.0.0.1", .port = 18447, .tls = true, .quic = true }},
        .tls = .{ .cert = "$WORK/rsa.crt", .key = "$WORK/rsa.key" },
        .locations = .{.{ .prefix = "/", .@"return" = .{ .body = "rsa" } }},
    },
} }
EOF2
"$ROOT/zig-out/bin/routez" "$WORK/rsa.zon" 2> "$WORK/rsa.log" & RSA=$!; PIDS+=($RSA)
wait_port 18447
RSA_CURL="$CURL_BIN -s --max-time 10 --cacert $WORK/rsa.crt --resolve rsa.test:18447:127.0.0.1"
# OpenSSL 3.0 prints "RSA-PSS", later versions "rsa_pss_rsae_sha256"; both give the digest.
sig_type() {
    local out t
    out=$(echo | $OPENSSL s_client -connect 127.0.0.1:18447 -tls1_3 -servername "$1" ${2:+-sigalgs $2} 2>/dev/null)
    t=$(grep -o 'Peer signature type: [A-Za-z0-9_-]*' <<< "$out" | cut -d' ' -f4 | tr A-Z a-z)
    case $t in *pss*) t=pss ;; *ecdsa*) t=ecdsa ;; esac
    echo "$t-$(grep -o 'Peer signing digest: [A-Za-z0-9]*' <<< "$out" | cut -d' ' -f4)"
}
SUITE=rsa check https "$($RSA_CURL https://rsa.test:18447/)" "rsa"
if $CURL_BIN --version | grep -q HTTP3; then
    SUITE=rsa check h3 "$($RSA_CURL --http3-only https://rsa.test:18447/)" "rsa"
fi
SUITE=rsa check pss-schemes "$(sig_type rsa.test) $(sig_type rsa.test rsa_pss_rsae_sha512)" "pss-SHA256 pss-SHA512"
SUITE=rsa check ec-alongside "$(sig_type localhost)" "ecdsa-SHA256"
kill $RSA; wait $RSA 2>/dev/null

# Operations: JSON access log to a file, reopened on SIGUSR1; error log at
# warn; Prometheus metrics; a key that isn't the certificate's.
OPS="$WORK/ops"; mkdir -p "$OPS"
cat > "$OPS/routez.zon" <<EOF2
.{ .access_log_path = "$OPS/access.log", .access_log_format = "json", .error_log = "$OPS/error.log", .log_level = .warn,
   .servers = .{.{
    .listen = .{.{ .address = "127.0.0.1", .port = 18460 }},
    .locations = .{
        .{ .prefix = "/", .@"return" = .{ .body = "ok" } },
        .{ .prefix = "/api/", .proxy_pass = "ops_backend", .strip_prefix = true },
        .{ .prefix = "/metrics", .metrics = true },
    },
  }},
  .upstreams = .{.{ .name = "ops_backend", .servers = .{"127.0.0.1:19001"}, .health = .{ .path = "/healthz", .interval_ms = 200 } }},
}
EOF2
"$ROOT/zig-out/bin/routez" "$OPS/routez.zon" 2> "$OPS/stderr.log" & OPSD=$!; PIDS+=($OPSD)
wait_port 18460
OCURL="$CURL_BIN -s --max-time 10"
for i in 1 2 3; do $OCURL -o /dev/null "http://127.0.0.1:18460/api/x?i=$i"; done
$OCURL -o /dev/null -A 'agent "quoted" \ back' "http://127.0.0.1:18460/nope%22"
jsonl() { python3 -c "import json,sys; ls=[json.loads(l) for l in open(sys.argv[1])]; print($2)" "$1" 2>&1; }
SUITE=ops check access-log-json "$(jsonl "$OPS/access.log" 'len(ls), ls[0]["status"], ls[0]["upstream_addr"], ls[3]["user_agent"], ls[3]["uri"]')" \
    "4 200 127.0.0.1:19001 agent \"quoted\" \\ back /nope%22"
mv "$OPS/access.log" "$OPS/access.log.1"
kill -USR1 $OPSD
for _ in $(seq 1 50); do [ -e "$OPS/access.log" ] && break; perl -e 'select(undef,undef,undef,0.05)'; done
$OCURL -o /dev/null "http://127.0.0.1:18460/after-rotate"
SUITE=ops check reopen-on-usr1 "$(jsonl "$OPS/access.log.1" 'len(ls)') $(jsonl "$OPS/access.log" 'len(ls), ls[0]["uri"]')" "4 1 /after-rotate"
# A broken reload is an error, logged; the info lines around it are not.
cp "$OPS/routez.zon" "$OPS/good.zon"; echo broken >> "$OPS/routez.zon"
kill -HUP $OPSD
for _ in $(seq 1 50); do grep -q "reload failed" "$OPS/error.log" 2>/dev/null && break; perl -e 'select(undef,undef,undef,0.05)'; done
SUITE=ops check error-log-level "$(grep -c 'reload failed' "$OPS/error.log") $(grep -c '\[info\]' "$OPS/error.log")" "1 0"
METRICS=$($OCURL -D "$OPS/metrics.head" http://127.0.0.1:18460/metrics)
SUITE=ops check metrics-content-type "$(grep -i '^content-type' "$OPS/metrics.head" | tr -d '\r')" "content-type: text/plain; version=0.0.4; charset=utf-8"
# Five 2xx before the scrape; its connection and wait_port's are accepted too.
SUITE=ops check metrics "$(python3 "$HERE/check_metrics.py" \
    'routez_http_responses_total{protocol="http1",code="2xx"}' 'routez_http_responses_total{protocol="http1",code="4xx"}' \
    'routez_upstream_requests_total{upstream="ops_backend",server="127.0.0.1:19001"}' \
    'routez_upstream_healthy{upstream="ops_backend",server="127.0.0.1:19001"}' 'routez_reload_failures_total' \
    'routez_connections_accepted_total{protocol="tcp"}' <<< "$METRICS")" "5 0 3 1 1 7"
if command -v promtool >/dev/null; then
    SUITE=ops check promtool "$(promtool check metrics <<< "$METRICS" 2>&1 | grep -vc '^$')" 0
fi
kill $OPSD; wait $OPSD 2>/dev/null
$OPENSSL ecparam -genkey -name prime256v1 -noout -out "$OPS/other.key" 2>/dev/null
sed "s|\.servers = \.{\.{|.servers = .{.{ .tls = .{ .cert = \"$CERTS/server.crt\", .key = \"$OPS/other.key\" },|; s|18460 }|18461, .tls = true }|" "$OPS/good.zon" > "$OPS/mismatch.zon"
"$ROOT/zig-out/bin/routez" -t "$OPS/mismatch.zon" 2> "$OPS/mismatch.log"
SUITE=ops check key-mismatch "$? $(grep -c 'is not the key of the first certificate' "$OPS/mismatch.log")" "1 1"

# Dropping root after binding ports below 1024. Needs root: the Linux
# container, or passwordless sudo on CI.
if [ "$(id -u)" = 0 ]; then SUDO=""; PRIV_OK=1
elif [ -n "${CI:-}" ] && sudo -n true 2>/dev/null; then SUDO="sudo -n"; PRIV_OK=1
else PRIV_OK=; echo "skipping privilege checks: not root"; fi
if [ -n "$PRIV_OK" ]; then
SUITE=privileges
# Under /tmp so that nobody can reach the config and certificates on reload.
PRIV=$(mktemp -d /tmp/routez-priv.XXXXXX); chmod 755 "$PRIV"; mkdir -m 777 "$PRIV/logs"
cp "$CERTS/server.crt" "$CERTS/server.key" "$PRIV/"; chmod 644 "$PRIV"/server.*
priv_conf() {
cat > "$PRIV/routez.zon" <<EOF2
.{ .user = "nobody", .workers = 2, .access_log_path = "$PRIV/logs/access.log", .error_log = "$PRIV/logs/error.log",
   .servers = .{.{
    .listen = .{ .{ .address = "127.0.0.1", .port = 880, .tls = true, .quic = true }, .{ .address = "127.0.0.1", .port = 881 } $2 },
    .tls = .{ .cert = "$PRIV/server.crt", .key = "$PRIV/server.key" },
    .locations = .{.{ .prefix = "/", .@"return" = .{ .body = "$1" } }},
}} }
EOF2
}
priv_conf priv ""
$SUDO "$ROOT/zig-out/bin/routez" "$PRIV/routez.zon" 2> "$PRIV/stderr.log" & SPID=$!; PIDS+=($SPID)
wait_port 881
PPID_=$SPID; [ -n "$SUDO" ] && PPID_=$(pgrep -P $SPID | head -1)
psig() { $SUDO kill -"$1" $PPID_; }
wait_log() { for _ in $(seq 1 100); do grep -q "$1" "$PRIV/logs/error.log" && return; perl -e 'select(undef,undef,undef,0.1)'; done; }
PCURL="$CURL_BIN -s --max-time 10 --cacert $CERTS/ca.crt"
NOBODY="$(id -u nobody) $(id -g nobody)"
if [ -d /proc ]; then
    ids=$(for f in /proc/$PPID_/task/*/status; do echo "$(awk '/^Uid:/{print $2,$3,$4,$5}' $f) $(awk '/^Gid:/{print $2,$3,$4,$5}' $f)"; done | sort -u)
    nu=${NOBODY% *}; ng=${NOBODY#* }
    check all-threads-dropped "$ids" "$nu $nu $nu $nu $ng $ng $ng $ng"
else
    # macOS's ps prints nobody's ids as -2.
    check dropped "$(ps -o uid= -o rgid= -p $PPID_ | awk '{u=$1; g=$2; if (u < 0) u += 4294967296; if (g < 0) g += 4294967296; print u, g}')" "$NOBODY"
fi
check serves "$($PCURL http://127.0.0.1:881/) $($PCURL https://127.0.0.1:880/)" "priv priv"
"$ROOT/zig-out/bin/h3-test-client" 880 "$CERTS/ca.crt" 3 > "$PRIV/h3.log" 2>&1
check serves-h3 "$(grep -o 'h3-ok' "$PRIV/h3.log")" "h3-ok"
# A reload as nobody takes the privileged sockets over, QUIC's included.
priv_conf priv2 ""
psig HUP
wait_log "worker 0 stopped"; wait_log "worker 1 stopped"
check reload "$($PCURL http://127.0.0.1:881/) $($PCURL https://127.0.0.1:880/)" "priv2 priv2"
"$ROOT/zig-out/bin/h3-test-client" 880 "$CERTS/ca.crt" 3 > "$PRIV/h3.log" 2>&1
check reload-h3 "$(grep -o 'h3-ok' "$PRIV/h3.log")" "h3-ok"
# A new privileged port can't be bound any more: the reload is refused.
# (macOS has no privileged ports, nor has Docker by default.)
if [ "$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 0)" -gt 882 ]; then
    priv_conf priv3 ', .{ .address = "127.0.0.1", .port = 882 }'
    psig HUP
    wait_log "reload failed"
    check new-port-refused "$(grep -c 'ports below 1024 need root' "$PRIV/logs/error.log") $($PCURL http://127.0.0.1:881/)" "1 priv2"
else
    echo "skipping new-port-refused: port 882 is not privileged here"
fi
mv "$PRIV/logs/access.log" "$PRIV/logs/access.log.1"
psig USR1
for _ in $(seq 1 50); do [ -e "$PRIV/logs/access.log" ] && break; perl -e 'select(undef,undef,undef,0.05)'; done
$PCURL -o /dev/null http://127.0.0.1:881/rotated
check reopen-as-nobody "$(grep -c rotated "$PRIV/logs/access.log")" 1
psig TERM
for _ in $(seq 1 50); do kill -0 $SPID 2>/dev/null || break; perl -e 'select(undef,undef,undef,0.1)'; done
if grep -qiE "panic|segmentation" "$PRIV/logs/error.log" "$PRIV/stderr.log"; then fail=$((fail+1)); echo "FAIL privileged server crashed:"; cat "$PRIV/logs/error.log"; fi
$SUDO rm -rf "$PRIV"
fi

# WebTransport through the relay: a stream and a datagram, echoed.
(cd "$ROOT" && zig build wt-test-client) || exit 1
"$ROOT/zig-out/bin/wt-test-client" 18443 "$CERTS/ca.crt" > "$WORK/wt.log" 2>&1 & WT=$!
for i in $(seq 1 50); do kill -0 $WT 2>/dev/null || break; perl -e 'select(undef,undef,undef,0.1)'; done
kill $WT 2>/dev/null; wait $WT 2>/dev/null
SUITE=wt check webtransport-relay "$(grep -o 'wt-ok\|wt-fail.*' "$WORK/wt.log")" "wt-ok"

# 48 MiB into an upstream that reads ~8 MB/s: the relay must hold the client
# back rather than buffer it. Holding it still costs the paused stream's
# receive window (6 MiB) plus the upstream stream's in-flight data, ~20 MiB
# at peak; buffering it all costs 60+.
rss() { ps -o rss= -p $SERVER | tr -d ' '; }
base=$(rss); peak=$base
"$ROOT/zig-out/bin/wt-test-client" 18443 "$CERTS/ca.crt" 48 /wt-slow > "$WORK/wtflood.log" 2>&1 & WT=$!
# 6 s at the upstream's pace, but a Debug build on Linux is CPU-bound at ~30 s.
for _ in $(seq 1 1200); do kill -0 $WT 2>/dev/null || break; r=$(rss); [ "$r" -gt "$peak" ] && peak=$r; perl -e 'select(undef,undef,undef,0.1)'; done
kill $WT 2>/dev/null; wait $WT 2>/dev/null
SUITE=wt check webtransport-flood "$(grep -o 'wt-ok\|wt-fail.*' "$WORK/wtflood.log")" "wt-ok"
grep -q wt-ok "$WORK/wtflood.log" || tail -5 "$WORK/wtflood.log"
SUITE=wt check webtransport-backpressure "$([ $((peak - base)) -lt 32768 ] && echo bounded || echo "grew $((peak - base)) KB")" bounded

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
# libxev's kqueue backend logs this when a completion is queued twice.
if grep -q "invalid state" "$WORK/server.log"; then fail=$((fail+1)); echo "FAIL event loop: $(grep -c 'invalid state' "$WORK/server.log") invalid-state errors"; fi
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

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
CERTS="$ROOT/../quic-zig/interop/certs"
sed "s|WWW|$WORK/www|; s|CERTS|$CERTS|g" "$HERE/routez.zon" > "$WORK/routez.zon"

python3 "$HERE/upstream.py" 19001 & PIDS+=($!)
python3 "$HERE/upstream.py" 19002 & PIDS+=($!)
python3 "$HERE/slow_upstream.py" "$WORK/www" & PIDS+=($!)
bun "$HERE/ws_upstream.ts" & PIDS+=($!)
QZ="$ROOT/../quic-zig"
(cd "$QZ" && exec ./zig-out/bin/wt-echo-server --cert interop/certs/server.crt --key interop/certs/server.key --port 4450 >/dev/null 2>&1) & PIDS+=($!)
sleep 0.7
"$ROOT/zig-out/bin/routez" "$WORK/routez.zon" 2> "$WORK/server.log" & SERVER=$!; PIDS+=($SERVER)
sleep 0.7

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
check slow-upstream-upload "$($CURL -X POST --data-binary @"$WORK/www/big.bin" "$B/slow/up")" 3000000
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
SUITE=limits check per-ip-limit "$(python3 "$HERE/conn_limit.py" 25)" 5
SUITE=limits check stub-status "$($CURL_BIN -s http://127.0.0.1:18080/status | grep -c '^Active connections: ')" 1

# WebTransport through the relay: a stream and a datagram, echoed.
(cd "$ROOT" && zig build wt-test-client) || exit 1
"$ROOT/zig-out/bin/wt-test-client" 18443 "$CERTS/ca.crt" > "$WORK/wt.log" 2>&1 & WT=$!
for i in $(seq 1 50); do kill -0 $WT 2>/dev/null || break; perl -e 'select(undef,undef,undef,0.1)'; done
kill $WT 2>/dev/null; wait $WT 2>/dev/null
SUITE=wt check webtransport-relay "$(grep -o 'wt-ok\|wt-fail.*' "$WORK/wt.log")" "wt-ok"

B=http://127.0.0.1:18080
CURL="$CURL_BIN -s --max-time 10"
SUITE=failover
kill "${PIDS[1]}"; wait "${PIDS[1]}" 2>/dev/null; sleep 0.2  # take down 19002
check failover "$(for i in 1 2 3 4 5 6; do $CURL -o /dev/null -w '%{http_code}' "$B/api/f"; done)" "200200200200200200"

if grep -qiE "panic|segmentation" "$WORK/server.log"; then fail=$((fail+1)); echo "FAIL server crashed:"; cat "$WORK/server.log"; fi
kill -TERM $SERVER; sleep 1.5
if kill -0 $SERVER 2>/dev/null; then fail=$((fail+1)); echo "FAIL graceful stop"; else pass=$((pass+1)); fi
echo "passed=$pass failed=$fail"
[ $fail -eq 0 ]

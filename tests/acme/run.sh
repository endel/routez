#!/bin/bash
# ACME end to end against Pebble, Let's Encrypt's test CA, in Docker: issue a
# certificate over real HTTP-01 validation, serve it, restart on the stored
# one, renew one near expiry with connections in flight.
# Skips when docker isn't usable. Needs python3, curl and openssl.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMAGE=${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}
HTTP_PORT=18580
HTTPS_PORT=18543
ACME_PORT=${PEBBLE_PORT:-14000}
MGMT_PORT=${PEBBLE_MGMT_PORT:-15000}
NAMES=(routez.test www.routez.test)

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "skipping ACME test: docker is not available"; exit 0
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1 && ! docker pull -q "$IMAGE" >/dev/null; then
    echo "skipping ACME test: can't pull $IMAGE"; exit 0
fi

WORK="$(mktemp -d)"
CONTAINER="routez-pebble-$$"
SERVER=""
cleanup() {
    [ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null && wait "$SERVER" 2>/dev/null
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

(cd "$ROOT" && zig build && zig build acme-test-tool) || exit 1
TOOL="$ROOT/zig-out/bin/acme-test-tool"

# Pebble validates HTTP-01 on httpPort; point it at routez's plain listener.
python3 - "$WORK/pebble.json" "$HTTP_PORT" "$ACME_PORT" "$MGMT_PORT" <<'EOF'
import json, sys
out, http, acme, mgmt = sys.argv[1:]
json.dump({"pebble": {
    "listenAddress": f"0.0.0.0:{acme}", "managementListenAddress": f"0.0.0.0:{mgmt}",
    "certificate": "/test/certs/localhost/cert.pem", "privateKey": "/test/certs/localhost/key.pem",
    "httpPort": int(http), "tlsPort": 5001, "ocspResponderURL": "", "externalAccountBindingRequired": False,
    "retryAfter": {"authz": 1, "order": 1}, "keyAlgorithm": "ecdsa",
}}, open(out, "w"))
EOF

# Linux: share the host's network, so Pebble reaches routez on 127.0.0.1.
# Docker Desktop: publish Pebble's ports and resolve the names to the host.
if [ "$(uname)" == Linux ]; then
    NET=(--network host); HOST_IP=127.0.0.1
else
    NET=(-p "127.0.0.1:$ACME_PORT:$ACME_PORT" -p "127.0.0.1:$MGMT_PORT:$MGMT_PORT"); HOST_IP=host-gateway
fi
ADD_HOSTS=(); for n in "${NAMES[@]}"; do ADD_HOSTS+=(--add-host "$n:$HOST_IP"); done
# A high nonce rejection rate exercises the badNonce retry.
docker run -d --name "$CONTAINER" "${NET[@]}" "${ADD_HOSTS[@]}" \
    -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=30 \
    -v "$WORK/pebble.json:/pebble.json:ro" "$IMAGE" -config /pebble.json >/dev/null || exit 1
docker cp -q "$CONTAINER:/test/certs/pebble.minica.pem" "$WORK/pebble-ca.pem" 2>/dev/null ||
    docker cp "$CONTAINER:/test/certs/pebble.minica.pem" "$WORK/pebble-ca.pem" >/dev/null || exit 1

CURL_BIN=$(command -v /opt/homebrew/opt/curl/bin/curl || command -v curl)
for _ in $(seq 1 100); do
    $CURL_BIN -s -o /dev/null --cacert "$WORK/pebble-ca.pem" "https://localhost:$ACME_PORT/dir" && break
    perl -e 'select(undef,undef,undef,0.1)'
done
# Pebble's issuing root is generated at startup.
$CURL_BIN -s --cacert "$WORK/pebble-ca.pem" "https://localhost:$MGMT_PORT/roots/0" > "$WORK/root.pem"
grep -q "BEGIN CERTIFICATE" "$WORK/root.pem" || { echo "no Pebble root"; docker logs "$CONTAINER"; exit 1; }

# $1: the ACME directory.
write_config() {
    cat > "$WORK/routez.zon" <<EOF
.{
    .servers = .{.{
        .listen = .{
            .{ .address = "127.0.0.1", .port = $HTTP_PORT },
            .{ .address = "127.0.0.1", .port = $HTTPS_PORT, .tls = true, .quic = true },
        },
        .server_names = .{ "${NAMES[0]}", "${NAMES[1]}" },
        .tls = .{ .acme = .{
            .email = "test@routez.test",
            .directory = "$1",
            .ca_file = "$WORK/pebble-ca.pem",
            .storage = "$WORK/acme",
        } },
        .locations = .{.{ .prefix = "/ping", .@"return" = .{ .body = "pong\n" } }},
    }},
}
EOF
}

start_server() {
    "$ROOT/zig-out/bin/routez" "$WORK/routez.zon" 2>> "$WORK/server.log" & SERVER=$!
    for _ in $(seq 1 100); do
        python3 -c "import socket; socket.create_connection(('127.0.0.1', $HTTP_PORT), 0.2).close()" 2>/dev/null && return 0
        perl -e 'select(undef,undef,undef,0.1)'
    done
    echo "routez never came up"; cat "$WORK/server.log"; exit 1
}

pass=0; fail=0
check() { if [ "$2" == "$3" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL [$PHASE] $1: got '$2' want '$3'"; fi; }

# Wait for the Nth occurrence of a log line.
wait_log() {
    for _ in $(seq 1 ${3:-600}); do
        [ "$(grep -c "$1" "$WORK/server.log")" -ge "$2" ] && return 0
        perl -e 'select(undef,undef,undef,0.1)'
    done
    return 1
}

HTTPS="$CURL_BIN -s --max-time 5 --cacert $WORK/root.pem --resolve ${NAMES[0]}:$HTTPS_PORT:127.0.0.1 --resolve ${NAMES[1]}:$HTTPS_PORT:127.0.0.1"
BUNDLE="$WORK/acme/localhost_$ACME_PORT/${NAMES[0]}.pem"
# Fingerprint of the certificate on the TLS port; perl's alarm bounds a stalled handshake.
served_cert() { perl -e 'alarm 5; exec @ARGV' openssl s_client -connect 127.0.0.1:$HTTPS_PORT -servername ${NAMES[0]} </dev/null 2>/dev/null | openssl x509 -noout -fingerprint 2>/dev/null; }
mode() { python3 -c "import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))" "$1"; }

# Our CSR encoding, checked by openssl rather than by our own parser.
PHASE=csr
"$TOOL" csr "$WORK/req.pem" "${NAMES[@]}"
check csr-signature "$(openssl req -in "$WORK/req.pem" -noout -verify 2>&1 | grep -c 'verify OK')" 1
check csr-sans "$(openssl req -in "$WORK/req.pem" -noout -text | grep -o 'DNS:[a-z.]*' | sort | tr '\n' ' ')" "DNS:${NAMES[0]} DNS:${NAMES[1]} "

PHASE=placeholder
# A CA that can't be reached: TLS serves a self-signed stand-in meanwhile.
write_config "https://localhost:1/dir"
start_server
wait_log "certificate for ${NAMES[0]}: " 1 50 || echo "no ACME failure logged"
check placeholder-served "$($HTTPS -k https://${NAMES[0]}:$HTTPS_PORT/ping)" pong
check placeholder-untrusted "$($HTTPS -o /dev/null -w '%{http_code}' https://${NAMES[0]}:$HTTPS_PORT/ping)" 000

PHASE=issue
write_config "https://localhost:$ACME_PORT/dir"
kill -HUP $SERVER
wait_log "reloading for a new certificate" 1 || echo "no certificate was issued"
wait_log "reloaded: " 2 50
check issued "$(grep -c "certificate for ${NAMES[0]} stored" "$WORK/server.log")" 1
check https "$($HTTPS https://${NAMES[0]}:$HTTPS_PORT/ping)" pong
check https-second-name "$($HTTPS https://${NAMES[1]}:$HTTPS_PORT/ping)" pong
if $CURL_BIN --version | grep -q HTTP3; then
    check h3 "$($HTTPS --http3-only https://${NAMES[0]}:$HTTPS_PORT/ping)" pong
fi
check bundle-mode "$(mode "$BUNDLE")" 0o600
check account-key-mode "$(mode "$WORK/acme/localhost_$ACME_PORT/account.key")" 0o600
check storage-mode "$(mode "$WORK/acme/localhost_$ACME_PORT")" 0o700
check key-matches-cert "$(openssl x509 -in "$BUNDLE" -noout -pubkey | openssl sha256)" "$(openssl ec -in "$BUNDLE" -pubout 2>/dev/null | openssl sha256)"
check sans "$(openssl x509 -in "$BUNDLE" -noout -text | grep -o 'DNS:[a-z.]*' | sort | tr '\n' ' ')" "DNS:${NAMES[0]} DNS:${NAMES[1]} "
check challenge-gone "$($CURL_BIN -s --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:$HTTP_PORT/.well-known/acme-challenge/x)" 404
FIRST=$(served_cert)
check cert-fetched "$(echo "$FIRST" | grep -c 'Fingerprint=')" 1
ORDERS=$(grep -c "requesting a certificate" "$WORK/server.log")

PHASE=restart
kill -TERM $SERVER; wait $SERVER; SERVER=""
start_server
check stored-cert-served "$($HTTPS https://${NAMES[0]}:$HTTPS_PORT/ping)" pong
check same-cert "$(served_cert)" "$FIRST"
check no-new-order "$(grep -c "requesting a certificate" "$WORK/server.log")" "$ORDERS"

PHASE=renew
# Swap in a stored certificate with 10 of its 90 days left; SIGHUP serves it
# and the ACME thread replaces it, with requests in flight throughout.
"$TOOL" cert "$BUNDLE" 80 10 "${NAMES[@]}"
(for i in $(seq 1 200); do $HTTPS -k -o /dev/null -w '%{http_code}\n' https://${NAMES[0]}:$HTTPS_PORT/ping; perl -e 'select(undef,undef,undef,0.02)'; done > "$WORK/codes.txt") & LOOP=$!
kill -HUP $SERVER
wait_log "reloading for a new certificate" 2 || echo "no renewal"
wait $LOOP
check renewed "$(grep -c "certificate for ${NAMES[0]} stored" "$WORK/server.log")" 2
for _ in $(seq 1 50); do $HTTPS -o /dev/null https://${NAMES[0]}:$HTTPS_PORT/ping && break; perl -e 'select(undef,undef,undef,0.1)'; done
check renewed-cert-served "$($HTTPS https://${NAMES[0]}:$HTTPS_PORT/ping)" pong
check renewed-is-new "$([ "$(served_cert)" != "$FIRST" ] && echo yes)" yes
check no-errors-during-swap "$(sort -u "$WORK/codes.txt" | tr '\n' ' ')" "200 "

if grep -qiE "panic|segmentation" "$WORK/server.log"; then fail=$((fail+1)); echo "FAIL server crashed"; fi
kill -TERM $SERVER; wait $SERVER; SERVER=""
echo "passed=$pass failed=$fail"
if [ $fail -ne 0 ]; then echo "--- routez log (tail)"; tail -40 "$WORK/server.log"; echo "--- pebble log (tail)"; docker logs "$CONTAINER" 2>&1 | tail -20; fi
[ $fail -eq 0 ]

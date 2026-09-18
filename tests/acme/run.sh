#!/bin/bash
# ACME end to end against Pebble, Let's Encrypt's test CA, in Docker: issue a
# certificate over real HTTP-01 validation, serve it, restart on the stored
# one, renew one near expiry with connections in flight, and the failure
# cases around them (a silent CA, a name added, a failed reload, storage that
# can't be written).
# Skips when docker isn't usable. Needs python3, curl and openssl.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMAGE=${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}
HTTP_PORT=18580
HTTPS_PORT=18543
ACME_PORT=${PEBBLE_PORT:-14000}
MGMT_PORT=${PEBBLE_MGMT_PORT:-15000}
SILENT_PORT=18590 # accepts connections and never answers
DELAY_PORT=18591  # Pebble, with every connection held 2 s first
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
PROXIES=()
cleanup() {
    [ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null && wait "$SERVER" 2>/dev/null
    for p in "${PROXIES[@]}"; do kill "$p" 2>/dev/null; done
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    chmod -R u+rwx "$WORK" 2>/dev/null
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

# $1: ACME directory, $2: order_timeout_s, rest: server names. A second
# server, with a static certificate, shares the TLS port.
write_config() {
    local dir=$1 timeout=$2; shift 2
    local names=""; for n in "$@"; do names="$names \"$n\","; done
    cat > "$WORK/routez.zon" <<EOF
.{
    .servers = .{
        .{
            .listen = .{
                .{ .address = "127.0.0.1", .port = $HTTP_PORT },
                .{ .address = "127.0.0.1", .port = $HTTPS_PORT, .tls = true, .quic = true },
            },
            .server_names = .{ $names },
            .tls = .{ .acme = .{
                .email = "test@routez.test",
                .directory = "$dir",
                .ca_file = "$WORK/pebble-ca.pem",
                .storage = "$WORK/acme",
                .order_timeout_s = $timeout,
            } },
            .locations = .{.{ .prefix = "/ping", .@"return" = .{ .body = "pong\n" } }},
        },
        .{
            .listen = .{.{ .address = "127.0.0.1", .port = $HTTPS_PORT, .tls = true }},
            .server_names = .{"static.test"},
            .tls = .{ .cert = "$WORK/static.pem", .key = "$WORK/static.pem" },
            .locations = .{.{ .prefix = "/", .@"return" = .{ .body = "static\n" } }},
        },
    },
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

# Wait for the Nth occurrence of a log line; $3 is the limit in tenths of a second.
wait_log() {
    for _ in $(seq 1 ${3:-600}); do
        [ "$(grep -c "$1" "$WORK/server.log")" -ge "$2" ] && return 0
        perl -e 'select(undef,undef,undef,0.1)'
    done
    return 1
}
count_log() { grep -c "$1" "$WORK/server.log"; }
issued_by_pebble() { docker logs "$CONTAINER" 2>&1 | grep -c "Issued certificate"; }

HTTPS="$CURL_BIN -s --max-time 5 --cacert $WORK/root.pem --resolve ${NAMES[0]}:$HTTPS_PORT:127.0.0.1 --resolve ${NAMES[1]}:$HTTPS_PORT:127.0.0.1"
BUNDLE="$WORK/acme/localhost_$ACME_PORT/${NAMES[0]}.pem"
DIRECT="https://localhost:$ACME_PORT/dir"
# Fingerprint of the certificate on the TLS port; perl's alarm bounds a stalled handshake.
served_cert() { perl -e 'alarm 5; exec @ARGV' openssl s_client -connect 127.0.0.1:$HTTPS_PORT -servername ${NAMES[0]} </dev/null 2>/dev/null | openssl x509 -noout -fingerprint 2>/dev/null; }
mode() { python3 -c "import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))" "$1"; }

python3 "$HERE/slow_proxy.py" $SILENT_PORT 0 0 & PROXIES+=($!)
python3 "$HERE/slow_proxy.py" $DELAY_PORT $ACME_PORT 2 & PROXIES+=($!)
"$TOOL" cert "$WORK/static.pem" 1 30 static.test

# Our CSR encoding, checked by openssl rather than by our own parser.
PHASE=csr
"$TOOL" csr "$WORK/req.pem" "${NAMES[@]}"
check csr-signature "$(openssl req -in "$WORK/req.pem" -noout -verify 2>&1 | grep -c 'verify OK')" 1
check csr-sans "$(openssl req -in "$WORK/req.pem" -noout -text | grep -o 'DNS:[a-z.]*' | sort | tr '\n' ' ')" "DNS:${NAMES[0]} DNS:${NAMES[1]} "

PHASE=placeholder
# A CA that accepts connections and never answers: the attempt is abandoned
# after order_timeout_s, and TLS serves a self-signed stand-in meanwhile.
write_config "https://localhost:$SILENT_PORT/dir" 2 "${NAMES[@]}"
start_server
check placeholder-served "$($HTTPS -k https://${NAMES[0]}:$HTTPS_PORT/ping)" pong
check placeholder-untrusted "$($HTTPS -o /dev/null -w '%{http_code}' https://${NAMES[0]}:$HTTPS_PORT/ping)" 000
wait_log "attempt abandoned" 1 80
check silent-ca-abandoned "$(count_log "attempt abandoned")" 1
check port-80-warning "$([ "$(count_log "no plain-HTTP listener on port 80")" -ge 1 ] && echo yes)" yes

PHASE=issue
write_config "$DIRECT" 60 "${NAMES[@]}"
kill -HUP $SERVER
wait_log "reloading for a new certificate" 1 || echo "no certificate was issued"
wait_log "reloaded: " 2 50
check issued "$(count_log "certificate for ${NAMES[0]} stored")" 1
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
ORDERS=$(count_log "requesting a certificate")

PHASE=restart
# Names reordered: still the same stored certificate.
kill -TERM $SERVER; wait $SERVER; SERVER=""
write_config "$DIRECT" 60 "${NAMES[1]}" "${NAMES[0]}"
start_server
check stored-cert-served "$($HTTPS https://${NAMES[0]}:$HTTPS_PORT/ping)" pong
check same-cert "$(served_cert)" "$FIRST"
check no-new-order "$(count_log "requesting a certificate")" "$ORDERS"

PHASE=add-name
# A name the CA can't validate: the stored certificate keeps serving the
# names it covers instead of the placeholder taking over.
write_config "$DIRECT" 60 "${NAMES[@]}" pending.routez.test
FAILURES=$(count_log "certificate for ${NAMES[0]}: .*retrying")
kill -HUP $SERVER
wait_log "certificate for ${NAMES[0]}: .*retrying" $((FAILURES + 1))
check partial-cert-logged "$(count_log "covers 2 of 3 names")" 1
check old-cert-still-served "$($HTTPS https://${NAMES[0]}:$HTTPS_PORT/ping)" pong
check same-cert "$(served_cert)" "$FIRST"
RELOADS=$(count_log "reloaded: ")
write_config "$DIRECT" 60 "${NAMES[@]}"
kill -HUP $SERVER
wait_log "reloaded: " $((RELOADS + 1)) 50

PHASE=renew
# Swap in a stored certificate with 10 of its 90 days left; SIGHUP serves it
# and the ACME thread replaces it, with requests in flight throughout.
"$TOOL" cert "$BUNDLE" 80 10 "${NAMES[@]}"
RENEWALS=$(count_log "reloading for a new certificate")
(for i in $(seq 1 200); do $HTTPS -k -o /dev/null -w '%{http_code}\n' https://${NAMES[0]}:$HTTPS_PORT/ping; perl -e 'select(undef,undef,undef,0.02)'; done > "$WORK/codes.txt") & LOOP=$!
kill -HUP $SERVER
wait_log "reloading for a new certificate" $((RENEWALS + 1)) || echo "no renewal"
wait $LOOP
check renewed "$(count_log "certificate for ${NAMES[0]} stored")" 2
for _ in $(seq 1 50); do $HTTPS -o /dev/null https://${NAMES[0]}:$HTTPS_PORT/ping && break; perl -e 'select(undef,undef,undef,0.1)'; done
check renewed-cert-served "$($HTTPS https://${NAMES[0]}:$HTTPS_PORT/ping)" pong
check renewed-is-new "$([ "$(served_cert)" != "$FIRST" ] && echo yes)" yes
check no-errors-during-swap "$(sort -u "$WORK/codes.txt" | tr '\n' ' ')" "200 "

PHASE=reload-retry
# The reload for a new certificate fails (another server's certificate file
# is missing just then) and is asked for again until it works. The delaying
# proxy in front of the CA leaves time to pull the file after the SIGHUP.
write_config "https://localhost:$DELAY_PORT/dir" 60 "${NAMES[@]}"
RELOADS=$(count_log "reloaded: ")
kill -HUP $SERVER
wait_log "reloaded: " $((RELOADS + 1)) 50
mv "$WORK/static.pem" "$WORK/static.pem.away"
wait_log "reload failed" 1 300
check reload-failed "$(count_log "reload failed")" 1
mv "$WORK/static.pem.away" "$WORK/static.pem"
wait_log "asking for the reload again" 1 200
wait_log "reloaded: " $((RELOADS + 2)) 50
check retried-reload-serves-cert "$($HTTPS https://${NAMES[0]}:$HTTPS_PORT/ping)" pong
check static-still-served "$($CURL_BIN -sk --max-time 5 --resolve static.test:$HTTPS_PORT:127.0.0.1 https://static.test:$HTTPS_PORT/)" static

PHASE=read-only-storage
# Storage that can't be written: no order is placed, since the certificate
# couldn't be kept. Root ignores permission bits, so this needs another user.
if [ "$(id -u)" != 0 ]; then
    DELAYED="$WORK/acme/localhost_$DELAY_PORT"
    "$TOOL" cert "$DELAYED/${NAMES[0]}.pem" 80 10 "${NAMES[@]}"
    ISSUED=$(issued_by_pebble)
    chmod 500 "$DELAYED"
    kill -HUP $SERVER
    wait_log "AccessDenied\|PermissionDenied" 1 100
    check storage-error-logged "$([ "$(count_log "AccessDenied\|PermissionDenied")" -ge 1 ] && echo yes)" yes
    check no-order-without-storage "$(issued_by_pebble)" "$ISSUED"
    chmod 700 "$DELAYED"
fi

if grep -qiE "panic|segmentation" "$WORK/server.log"; then fail=$((fail+1)); echo "FAIL server crashed"; fi
kill -TERM $SERVER; wait $SERVER; SERVER=""
echo "passed=$pass failed=$fail"
if [ $fail -ne 0 ]; then echo "--- routez log (tail)"; tail -60 "$WORK/server.log"; echo "--- pebble log (tail)"; docker logs "$CONTAINER" 2>&1 | tail -20; fi
[ $fail -eq 0 ]

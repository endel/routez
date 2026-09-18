#!/bin/bash
# Benchmarks routez against nginx and HAProxy inside a Linux container (see
# bench.sh for what's measured). Results land in bench/results/<timestamp>/.
# Knobs: WORKERS, CONNS, DURATION (seconds), ROUNDS, WORKLOADS, OUT,
# QUIC_ZIG, HAPROXY_BRANCH.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
QZ="$(cd "${QUIC_ZIG:-$ROOT/../quic-zig}" && pwd)"
OUT="${OUT:-$HERE/results/$(date -u +%Y%m%dT%H%M%SZ)}"
IMAGE=routez-bench

mkdir -p "$OUT"
docker build -q -t "$IMAGE" --build-arg "HAPROXY_BRANCH=${HAPROXY_BRANCH:-3.2}" - < "$HERE/Dockerfile" >/dev/null
# tw_reuse and the wide port range keep the handshake row from running out of ports.
docker run --rm \
    --ulimit nofile=65536:65536 \
    --sysctl net.ipv4.tcp_tw_reuse=1 \
    --sysctl net.ipv4.ip_local_port_range="1024 65535" \
    --sysctl net.core.somaxconn=4096 \
    -e WORKERS -e CONNS -e DURATION -e ROUNDS -e WORKLOADS \
    -v "$ROOT:/src/routez:ro" -v "$QZ:/src/quic-zig:ro" \
    -v zigcache:/cache -v "$OUT:/out" \
    "$IMAGE" /src/routez/bench/bench.sh
echo "results: $OUT"

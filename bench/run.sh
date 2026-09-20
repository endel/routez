#!/bin/bash
# Benchmarks routez against nginx and HAProxy inside a Linux container.
#   bench/run.sh      HTTP throughput with wrk (bench.sh)
#   bench/run.sh ws   concurrent WebSocket connections (ws.sh)
# Results land in bench/results/[ws-]<timestamp>/. Knobs: see each script; also
# OUT, QUIC_ZIG, HAPROXY_BRANCH.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
QZ="$(cd "${QUIC_ZIG:-$ROOT/../quic-zig}" && pwd)"
SCRIPT=bench.sh PREFIX=
[ "${1:-}" == ws ] && SCRIPT=ws.sh PREFIX=ws-
OUT="${OUT:-$HERE/results/$PREFIX$(date -u +%Y%m%dT%H%M%SZ)}"
IMAGE=routez-bench

mkdir -p "$OUT"
# The container can't read a worktree's .git, so name the versions here.
rev() { git -C "$1" describe --always --dirty 2>/dev/null || echo unknown; }
export ROUTEZ_REV="$(rev "$ROOT")" QUIC_ZIG_REV="$(rev "$QZ")"
docker build -q -t "$IMAGE" --build-arg "HAPROXY_BRANCH=${HAPROXY_BRANCH:-3.2}" - < "$HERE/Dockerfile" >/dev/null
# tw_reuse and the wide port range keep the handshake row from running out of
# ports, minus the bench's own so no outgoing socket takes one. The WebSocket
# run holds hundreds of thousands of descriptors.
docker run --rm \
    --ulimit nofile=1048576:1048576 \
    --sysctl net.ipv4.tcp_tw_reuse=1 \
    --sysctl net.ipv4.ip_local_port_range="1024 65535" \
    --sysctl net.ipv4.ip_local_reserved_ports=19080-19194 \
    --sysctl net.core.somaxconn=4096 \
    --sysctl net.ipv4.tcp_max_syn_backlog=65535 \
    -e WORKERS -e CONNS -e DURATION -e ROUNDS -e WORKLOADS -e ROUTEZ_REV -e QUIC_ZIG_REV \
    -e LEVELS -e RATE -e HOLD -e CLIENTS -e SERVERS \
    -v "$ROOT:/src/routez:ro" -v "$QZ:/src/quic-zig:ro" \
    -v zigcache:/cache -v "$OUT:/out" \
    "$IMAGE" "/src/routez/bench/$SCRIPT"
echo "results: $OUT"

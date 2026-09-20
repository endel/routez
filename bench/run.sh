#!/bin/bash
# Benchmarks routez against nginx and HAProxy inside a Linux container.
#   bench/run.sh [http]   HTTP rows with wrk (bench.sh)
#   bench/run.sh ws       concurrent WebSocket connections (ws.sh)
#   bench/run.sh h3       HTTP/3 with h2load (h3.sh)
#   bench/run.sh l4       layer-4 TCP and UDP proxying (l4.sh)
#   bench/run.sh hostile  connection storms, slow clients, limits, reload (hostile.sh)
#   bench/run.sh soak     a long mixed run, watching memory and descriptors (soak.sh)
# Results land in bench/results/[<suite>-]<timestamp>/. Knobs: see each script;
# also OUT, QUIC_ZIG, HAPROXY_BRANCH.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
QZ="$(cd "${QUIC_ZIG:-$ROOT/../quic-zig}" && pwd)"
SUITE=${1:-http}
case $SUITE in
    http) SCRIPT=bench.sh PREFIX= ;;
    ws|h3|l4|hostile|soak) SCRIPT=$SUITE.sh PREFIX=$SUITE- ;;
    *) echo "unknown suite '$SUITE'; one of: http ws h3 l4 hostile soak"; exit 1 ;;
esac
[ -f "$HERE/$SCRIPT" ] || { echo "$SCRIPT doesn't exist yet"; exit 1; }
OUT="${OUT:-$HERE/results/$PREFIX$(date -u +%Y%m%dT%H%M%SZ)}"
IMAGE=routez-bench

mkdir -p "$OUT"
# The container can't read a worktree's .git, so name the versions here.
rev() { git -C "$1" describe --always --dirty 2>/dev/null || echo unknown; }
export ROUTEZ_REV="$(rev "$ROOT")" QUIC_ZIG_REV="$(rev "$QZ")"
docker build -q -t "$IMAGE" --build-arg "HAPROXY_BRANCH=${HAPROXY_BRANCH:-3.2}" - < "$HERE/Dockerfile" >/dev/null
# tw_reuse and the wide port range keep the handshake row from running out of
# ports, minus the bench's own so no outgoing socket takes one. The WebSocket
# run holds hundreds of thousands of descriptors. net.core.rmem_max isn't
# namespaced, so the container can't raise it: the UDP rows size their own
# socket buffers and record what the kernel allowed.
# perf needs to read the kernel's counters, which the default profile forbids.
PRIV=()
[ "${PROFILE:-}" == perf ] && PRIV=(--privileged)
docker run --rm \
    ${PRIV[@]+"${PRIV[@]}"} \
    --ulimit nofile=1048576:1048576 \
    --sysctl net.ipv4.tcp_tw_reuse=1 \
    --sysctl net.ipv4.ip_local_port_range="1024 65535" \
    --sysctl net.ipv4.ip_local_reserved_ports=19080-19599 \
    --sysctl net.core.somaxconn=4096 \
    --sysctl net.ipv4.tcp_max_syn_backlog=65535 \
    -e WORKERS -e CONNS -e DURATION -e ROUNDS -e WORKLOADS -e ROUTEZ_REV -e QUIC_ZIG_REV \
    -e LEVELS -e RATE -e HOLD -e CLIENTS -e SERVERS \
    -e SWEEP -e SWEEP_VALUES -e STREAMS -e PPS -e FLOWS -e SOAK_MINUTES -e ROWS \
    -e HANDSHAKES -e ACCESS_LOG -e PHASE -e SAMPLE \
    -e PROFILE -e PROFILE_SERVER -e PROFILE_HZ \
    -v "$ROOT:/src/routez:ro" -v "$QZ:/src/quic-zig:ro" \
    -v zigcache:/cache -v "$OUT:/out" \
    "$IMAGE" "/src/routez/bench/$SCRIPT"
echo "results: $OUT"

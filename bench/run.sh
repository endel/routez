#!/bin/bash
# Benchmarks routez against nginx and HAProxy inside a Linux container.
#   bench/run.sh [http]   HTTP rows with wrk (bench.sh)
#   bench/run.sh ws       concurrent WebSocket connections (ws.sh)
#   bench/run.sh h3       HTTP/3 with h2load (h3.sh)
#   bench/run.sh l4       layer-4 TCP and UDP proxying (l4.sh)
#   bench/run.sh hostile  connection storms, slow clients, limits, reload (hostile.sh)
#   bench/run.sh rate     latency at a rate every server is held to (rate.sh)
#   bench/run.sh soak     a long mixed run, watching memory and descriptors (soak.sh)
# Results land in bench/results/[<suite>-]<timestamp>/. Knobs: see each script;
# also OUT, QUIC_ZIG, HAPROXY_BRANCH.
#
# ROUTEZ_B and/or QUIC_ZIG_B (h3 only) build a second routez from those trees
# and run it as server `routez-b` beside the first, round for round: an A/B of
# two builds that one machine's drift can't tell apart run to run. ZIG_B_DIR, a
# Linux Zig directory on the host, builds the B side with that Zig instead.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
QZ="$(cd "${QUIC_ZIG:-$ROOT/../quic-zig}" && pwd)"
SUITE=${1:-http}
case $SUITE in
    http) SCRIPT=bench.sh PREFIX= ;;
    ws|h3|l4|hostile|soak|rate) SCRIPT=$SUITE.sh PREFIX=$SUITE- ;;
    *) echo "unknown suite '$SUITE'; one of: http rate ws h3 l4 hostile soak"; exit 1 ;;
esac
[ -f "$HERE/$SCRIPT" ] || { echo "$SCRIPT doesn't exist yet"; exit 1; }
AB=
if [ -n "${ROUTEZ_B:-}${QUIC_ZIG_B:-}" ]; then
    [ "$SUITE" == h3 ] || { echo "ROUTEZ_B/QUIC_ZIG_B: only the h3 suite runs two builds"; exit 1; }
    AB=1
    RZB="$(cd "${ROUTEZ_B:-$ROOT}" && pwd)" QZB="$(cd "${QUIC_ZIG_B:-$QZ}" && pwd)"
fi
OUT="${OUT:-$HERE/results/$PREFIX$(date -u +%Y%m%dT%H%M%SZ)}"
IMAGE=routez-bench

mkdir -p "$OUT"
# The container can't read a worktree's .git, so name the versions here.
rev() { git -C "$1" describe --always --dirty 2>/dev/null || echo unknown; }
# Preset, they name trees with no history, such as a snapshot.
export ROUTEZ_REV="${ROUTEZ_REV:-$(rev "$ROOT")}" QUIC_ZIG_REV="${QUIC_ZIG_REV:-$(rev "$QZ")}"
B_MOUNTS=()
if [ -n "$AB" ]; then
    export AB ROUTEZ_B_REV="${ROUTEZ_B_REV:-$(rev "$RZB")}" QUIC_ZIG_B_REV="${QUIC_ZIG_B_REV:-$(rev "$QZB")}"
    B_MOUNTS=(-v "$RZB:/src/routez-b:ro" -v "$QZB:/src/quic-zig-b:ro")
    [ -z "${ZIG_B_DIR:-}" ] || B_MOUNTS+=(-v "$(cd "$ZIG_B_DIR" && pwd):/opt/zig-b:ro")
fi
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
    -e AB -e ROUTEZ_B_REV -e QUIC_ZIG_B_REV \
    -e LEVELS -e RATE -e HOLD -e CLIENTS -e SERVERS \
    -e SWEEP -e SWEEP_VALUES -e STREAMS -e PPS -e FLOWS -e SOAK_MINUTES -e ROWS \
    -e HANDSHAKES -e ACCESS_LOG -e PHASE -e SAMPLE -e QLOG \
    -e PROFILE -e PROFILE_SERVER -e PROFILE_HZ -e PROFILE_TRACE -e FRACTION \
    -v "$ROOT:/src/routez:ro" -v "$QZ:/src/quic-zig:ro" ${B_MOUNTS[@]+"${B_MOUNTS[@]}"} \
    -v zigcache:/cache -v "$OUT:/out" \
    "$IMAGE" "/src/routez/bench/$SCRIPT"
echo "results: $OUT"

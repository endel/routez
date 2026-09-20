# Sourced by every suite: builds routez and sets SRC, SRC_QZ, ROOT, OUT, RUN
# and ZIG_CPU, plus the process helpers and the env.txt header the reports
# read. Expects HERE; OUT_PREFIX names local result directories.

if [ -d /src/routez ]; then
    # Sources are mounted read-only, so build a copy. Only quic-zig's package
    # paths: its tree also holds gigabytes of interop artifacts.
    SRC=/src/routez SRC_QZ=/src/quic-zig OUT=${OUT:-/out}
    mkdir -p /work/quic-zig
    rsync -a --delete --exclude .git --exclude .zig-cache --exclude zig-out "$SRC/" /work/routez/ || exit 1
    rsync -a --delete "$SRC_QZ"/{build.zig,build.zig.zon,src} /work/quic-zig/ || exit 1
    ROOT=/work/routez
    export ZIG_GLOBAL_CACHE_DIR=/cache/global ZIG_LOCAL_CACHE_DIR=/cache/local
else
    ROOT="$(cd "$HERE/.." && pwd)" SRC_QZ="$(cd "$HERE/../../quic-zig" && pwd)"
    SRC=$ROOT OUT=${OUT:-$HERE/results/${OUT_PREFIX:-}$(date -u +%Y%m%dT%H%M%SZ)}
    # run.sh sets these on the container; on a bare host do it here. The load
    # needs the descriptors, the ports and the socket buffers, or the rig
    # becomes the limit. Not fatal: a tuned host may already have them.
    if [ "$(id -u)" == 0 ]; then
        ulimit -n 1048576 2>/dev/null
        for kv in net.ipv4.tcp_tw_reuse=1 "net.ipv4.ip_local_port_range=1024 65535" \
            net.ipv4.ip_local_reserved_ports=19080-19294 net.core.somaxconn=4096 \
            net.ipv4.tcp_max_syn_backlog=65535 net.core.rmem_max=16777216 \
            net.core.wmem_max=16777216; do # rmem/wmem only work on a bare host
            sysctl -qw "$kv" 2>/dev/null || echo "warning: could not set $kv"
        done
    else
        echo "warning: not root, leaving sysctls and ulimits alone"
    fi
fi
RUN="$(mktemp -d)"
chmod 755 "$RUN" # nginx's workers drop to an unprivileged user
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$RUN"; }
trap cleanup EXIT

# Zig 0.16 detects some arm64 cores as `generic` without AES (Apple silicon
# under Docker Desktop reports CPU part 0x000), leaving AES-GCM in software
# while OpenSSL finds the instructions at runtime.
ZIG_CPU=native
[ "$(uname -m)" == aarch64 ] && grep -qw aes /proc/cpuinfo && grep -qw sha2 /proc/cpuinfo && ZIG_CPU=native+aes+sha2
echo "building routez (ReleaseFast, -Dcpu=$ZIG_CPU)"
(cd "$ROOT" && zig build -Doptimize=ReleaseFast -Dcpu="$ZIG_CPU") || exit 1

build_tool() { # name: build bench/tools/<name>.zig next to the routez binary
    [ -x "$RUN/$1" ] && return 0
    zig build-exe -OReleaseFast -mcpu="$ZIG_CPU" -femit-bin="$RUN/$1" "$HERE/tools/$1.zig" || exit 1
}

start() { local name=$1 cpus=$2; shift 2; taskset -c "$cpus" "$@" > "$RUN/$name.log" 2>&1 & PIDS+=($!); }

wait_port() {
    for _ in $(seq 1 100); do
        (: < "/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
        sleep 0.1
    done
    echo "port $1 never came up"; tail -n 20 "$RUN"/*.log; exit 1
}

wait_udp() { # a UDP listener has no handshake to wait on; look for the socket
    for _ in $(seq 1 100); do
        ss -Haun "sport = :$1" | grep -q . && return 0
        sleep 0.1
    done
    echo "udp port $1 never came up"; tail -n 20 "$RUN"/*.log; exit 1
}

tree_rss() { # pid -> kB resident in it and its children (nginx is master+workers)
    local t=0 p
    [ -n "${1:-}" ] || { echo 0; return; }
    for p in $1 $(pgrep -P "$1" 2>/dev/null); do
        t=$((t + $(awk '/^VmRSS/ {print $2}' "/proc/$p/status" 2>/dev/null || echo 0)))
    done
    echo "$t"
}

open_fds() { # pid -> descriptors it and its children hold
    local t=0 p
    [ -n "${1:-}" ] || { echo 0; return; }
    for p in $1 $(pgrep -P "$1" 2>/dev/null); do
        t=$((t + $(ls "/proc/$p/fd" 2>/dev/null | wc -l)))
    done
    echo "$t"
}

git_rev() { git -c safe.directory='*' -C "$1" describe --always --dirty 2>/dev/null || echo unknown; }
env_header() {
    cat <<HDR
date: $(date -u +%Y-%m-%dT%H:%MZ)
routez: ${ROUTEZ_REV:-$(git_rev "$SRC")}
quic-zig: ${QUIC_ZIG_REV:-$(git_rev "$SRC_QZ")}
nginx: $(nginx -v 2>&1 | sed 's|.*/||')
haproxy: $(haproxy -v | awk 'NR == 1 {sub(/-.*/, "", $3); print $3}')
zig_cpu: $ZIG_CPU
kernel: $(uname -r)
cpus: $(nproc)
nofile: $(ulimit -n)
somaxconn: $(cat /proc/sys/net/core/somaxconn)
HDR
}

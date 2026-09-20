#!/bin/bash
# A long mixed run, watching memory and descriptors rather than speed: what
# grows and never comes back. Runs inside `bench/run.sh soak`'s container; on a
# Linux host it needs root and what bench/Dockerfile installs.
# Knobs: WORKERS, CONNS, SOAK_MINUTES (per server), SERVERS, OUT.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORKERS=${WORKERS:-3}
CONNS=${CONNS:-256}
MINUTES=${SOAK_MINUTES:-15}
PHASE=${PHASE:-30} # seconds per phase of the cycle
SAMPLE=${SAMPLE:-10}

OUT_PREFIX=soak- . "$HERE/lib.sh"
CERTS="$SRC_QZ/interop/certs"
WWW="$RUN/www"

read -ra SERVERS <<< "${SERVERS:-nginx haproxy routez}"
declare -A PLAIN=([nginx]=19080 [routez]=19081 [haproxy]=19082)
declare -A TLS=([nginx]=19443 [routez]=19444 [haproxy]=19445)
declare -A SPID=()

NCPU=$(nproc)
UPSTREAM_WORKERS=2
if [ "$NCPU" -ge $((2 * WORKERS + UPSTREAM_WORKERS)) ]; then
    SERVER_CPUS=0-$((WORKERS - 1))
    LOAD_CPUS=$WORKERS-$((NCPU - UPSTREAM_WORKERS - 1)) LOAD_THREADS=$((NCPU - UPSTREAM_WORKERS - WORKERS))
    UP_CPUS=$((NCPU - UPSTREAM_WORKERS))-$((NCPU - 1))
    PINNING="server on cpus $SERVER_CPUS, wrk on $LOAD_CPUS, upstream on $UP_CPUS"
else
    SERVER_CPUS=0-$((NCPU - 1)) LOAD_CPUS=$SERVER_CPUS UP_CPUS=$SERVER_CPUS LOAD_THREADS=$WORKERS
    PINNING="none ($NCPU cpus, pinning needs $((2 * WORKERS + UPSTREAM_WORKERS)))"
    echo "warning: not pinning, $PINNING"
fi

mkdir -p "$WWW" "$OUT/raw"
[ -s "$WWW/10k.bin" ] || head -c 10240 /dev/urandom > "$WWW/10k.bin"
[ -s "$WWW/1m.bin" ] || head -c $((1024 * 1024)) /dev/urandom > "$WWW/1m.bin"
mkdir -p "$WWW/z"
[ -s "$WWW/z/text.html" ] || python3 -c "
import sys
w = 'the quick brown fox jumps over the lazy dog while routez nginx and haproxy compare notes'.split()
out = ['<!doctype html><html><body>']
n = i = 0
while n < 100 * 1024:
    p = ' '.join(w[(i + k) % len(w)] for k in range(60)); out.append(f'<p>{p}</p>'); n += len(p) + 7; i += 7
out.append('</body></html>')
open('$WWW/z/text.html', 'w').write('\n'.join(out))
"
cat "$CERTS/server.crt" "$CERTS/server.key" > "$RUN/server.pem"
mkdir -p "$RUN/main"
for f in nginx.conf haproxy.cfg routez.zon; do
    sed "s|UPSTREAM_WORKERS|$UPSTREAM_WORKERS|g; s|WORKERS|$WORKERS|g; s|WWW|$WWW|g; s|CERTS|$CERTS|g; \
         s|ACCESS_LOG|off|g; s|ROUTEZ_LOG|false|g; s|HAPROXY_LOG|no log|g; s|RUN|$RUN|g" \
        "$HERE/conf/$f" | sed -e "/# ROUTING/d" -e "\|// ROUTING|d" > "$RUN/main/$f"
done
sed "s|UPSTREAM_WORKERS|$UPSTREAM_WORKERS|g; s|WWW|$WWW|g; s|CERTS|$CERTS|g; s|RUN|$RUN|g" \
    "$HERE/conf/upstream.conf" > "$RUN/upstream.conf"

start upstream "$UP_CPUS" nginx -c "$RUN/upstream.conf"
wait_port 19090

{ env_header; cat <<EOF
wrk: $(wrk -v 2>&1 | awk 'NR == 1 {print $2}')
workers: $WORKERS
conns: $CONNS
minutes: $MINUTES
phase: $PHASE
sample: $SAMPLE
rounds: 1
duration: $((MINUTES * 60))
pinning: $PINNING
server_cpus: $SERVER_CPUS
wrk_cpus: $LOAD_CPUS
upstream_cpus: $UP_CPUS
EOF
} > "$OUT/env.txt"

# The cycle: a cheap answer, a static file, a proxied response, compression, and
# a stretch of connection churn, so no single path is the only one exercised.
phase_args() { # phase index -> scheme path [extra wrk args...]
    case $(($1 % 5)) in
        0) echo "http /ping" ;;
        1) echo "http /10k.bin" ;;
        2) echo "http /up/" ;;
        3) echo "http /z/text.html -HAccept-Encoding:gzip" ;;
        4) echo "http /ping -HConnection:close" ;;
    esac
}

for s in "${SERVERS[@]}"; do
    case $s in
        nginx) start nginx "$SERVER_CPUS" nginx -c "$RUN/main/nginx.conf" ;;
        haproxy) start haproxy "$SERVER_CPUS" haproxy -f "$RUN/main/haproxy.cfg" ;;
        routez) start routez "$SERVER_CPUS" "$ROOT/zig-out/bin/routez" "$RUN/main/routez.zon" ;;
    esac
    SPID[$s]=$!
    wait_port "${PLAIN[$s]}"
    [ "$s" == nginx ] && until pgrep -P "${SPID[$s]}" >/dev/null; do sleep 0.05; done

    samples="$OUT/raw/$s.samples"
    : > "$samples"
    end=$((SECONDS + MINUTES * 60))
    phase=0
    threads=$LOAD_THREADS
    [ "$threads" -gt "$CONNS" ] && threads=$CONNS
    while [ $SECONDS -lt $end ]; do
        read -ra pa <<< "$(phase_args $phase)"
        url="${pa[0]}://127.0.0.1:${PLAIN[$s]}${pa[1]}"
        taskset -c "$LOAD_CPUS" wrk -t "$threads" -c "$CONNS" -d "${PHASE}s" --timeout 10s --latency \
            -s "$HERE/report.lua" "${pa[@]:2}" "$url" > "$OUT/raw/$s.phase$phase.txt" 2>&1 &
        wrk_pid=$!
        # Sample while the phase runs: elapsed, RSS of the tree, open descriptors.
        while kill -0 $wrk_pid 2>/dev/null; do
            sleep "$SAMPLE"
            printf '%d\t%d\t%d\n' "$SECONDS" "$(tree_rss "${SPID[$s]}")" "$(open_fds "${SPID[$s]}")" \
                >> "$samples"
        done
        wait $wrk_pid 2>/dev/null
        phase=$((phase + 1))
    done
    echo "$s: $(wc -l < "$samples") samples over $MINUTES min"
    kill "${SPID[$s]}" 2>/dev/null
    wait "${SPID[$s]}" 2>/dev/null
    PIDS=("${PIDS[0]}")
done

python3 "$HERE/report_soak.py" "$OUT" && echo && cat "$OUT/table.md"

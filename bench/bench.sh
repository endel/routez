#!/bin/bash
# Throughput, latency, CPU and memory of nginx, HAProxy and routez on the rows
# of workloads.txt, measured one server at a time with wrk. Runs inside
# bench/run.sh's container; directly on a Linux host it needs root and what
# bench/Dockerfile installs.
# Knobs: WORKERS, CONNS, DURATION (seconds), ROUNDS, WORKLOADS (subset of rows),
# ACCESS_LOG (off/on — on for all three servers, to price the log), OUT.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORKERS=${WORKERS:-3}
CONNS=${CONNS:-256}
DURATION=${DURATION:-10}
ROUNDS=${ROUNDS:-3}
ACCESS_LOG=${ACCESS_LOG:-off}
case $ACCESS_LOG in off|on) ;; *) echo "ACCESS_LOG is off or on"; exit 1 ;; esac

. "$HERE/lib.sh"
CERTS="$SRC_QZ/interop/certs"
WWW="$RUN/www"

# ---------------------------------------------------------------- the registry
declare -A W_SCHEME W_PATH W_LUA W_SERVERS W_CHECK W_UP W_CONNS W_PROFILE W_LABEL
ORDER=()
while read -r name scheme path lua servers check up conns profile label; do
    case ${name:-} in ""|\#*) continue ;; esac
    ORDER+=("$name")
    W_SCHEME[$name]=$scheme W_PATH[$name]=$path W_LUA[$name]=$lua W_SERVERS[$name]=$servers
    W_CHECK[$name]=$check W_UP[$name]=$up W_CONNS[$name]=$conns W_PROFILE[$name]=$profile
    W_LABEL[$name]=$label
done < "$HERE/workloads.txt"

read -ra WORKLOADS <<< "${WORKLOADS:-${ORDER[*]}}"
for w in "${WORKLOADS[@]}"; do
    [ -n "${W_SCHEME[$w]:-}" ] || { echo "unknown workload '$w'; have: ${ORDER[*]}"; exit 1; }
done

read -ra SERVERS <<< "${SERVERS:-nginx haproxy routez}"
declare -A PLAIN=([nginx]=19080 [routez]=19081 [haproxy]=19082)
declare -A TLS=([nginx]=19443 [routez]=19444 [haproxy]=19445)
declare -A SPID=()

serves() { # workload server
    [ "${W_SERVERS[$1]}" == all ] || [ "$2" != haproxy ]
}
active() { # workload -> the servers that run it
    local s; for s in "${SERVERS[@]}"; do serves "$1" "$s" && echo "$s"; done
}
target() { # workload server -> URL
    local port=${PLAIN[$2]}
    [ "${W_SCHEME[$1]}" == https ] && port=${TLS[$2]}
    echo "${W_SCHEME[$1]}://127.0.0.1:$port${W_PATH[$1]}"
}
conns_of() { local c=${W_CONNS[$1]}; [ "$c" == - ] && c=$CONNS; echo "$c"; }

# ------------------------------------------------------------------- CPU groups
# Server, wrk and the upstream each get their own cores when there are enough.
# wrk spends about what the server does per request, so it gets the rest — and
# on a row with no upstream, the upstream's cores too.
NCPU=$(nproc)
UPSTREAM_WORKERS=2
if [ "$NCPU" -ge $((2 * WORKERS + UPSTREAM_WORKERS)) ]; then
    SERVER_CPUS=0-$((WORKERS - 1))
    WRK_CPUS=$WORKERS-$((NCPU - UPSTREAM_WORKERS - 1)) WRK_THREADS=$((NCPU - UPSTREAM_WORKERS - WORKERS))
    UP_CPUS=$((NCPU - UPSTREAM_WORKERS))-$((NCPU - 1))
    WIDE_CPUS=$WORKERS-$((NCPU - 1)) WIDE_THREADS=$((NCPU - WORKERS))
    PINNING="server on cpus $SERVER_CPUS, wrk on $WRK_CPUS ($WIDE_CPUS without an upstream), upstream on $UP_CPUS"
else
    SERVER_CPUS=0-$((NCPU - 1)) WRK_CPUS=$SERVER_CPUS UP_CPUS=$SERVER_CPUS WRK_THREADS=$WORKERS
    WIDE_CPUS=$WRK_CPUS WIDE_THREADS=$WRK_THREADS
    PINNING="none ($NCPU cpus, pinning needs $((2 * WORKERS + UPSTREAM_WORKERS)))"
    echo "warning: not pinning, $PINNING"
fi

# --------------------------------------------------------------------- fixtures
mkdir -p "$WWW" "$OUT/raw"
bin() { # basename: random bytes of the size its name gives
    local f=$WWW/$1 n
    [ -s "$f" ] && return
    case $1 in
        1k.bin) n=1024 ;; 10k.bin) n=10240 ;; 100k.bin) n=102400 ;;
        1m.bin) n=$((1024 * 1024)) ;; 100m.bin) n=$((100 * 1024 * 1024)) ;;
        *) echo "no size for fixture $1"; exit 1 ;;
    esac
    head -c "$n" /dev/urandom > "$f"
}
text() { # path under WWW: 100 KB of compressible text; pre.html gets a .gz sibling
    local f=$WWW/$1
    [ -s "$f" ] && return
    mkdir -p "$(dirname "$f")"
    python3 - "$f" <<'PY'
import sys
words = ("the quick brown fox jumps over the lazy dog while routez nginx and haproxy "
         "compare notes about sendfile keepalive and the page cache ").split()
out = ["<!doctype html><html><body>"]
n = 0
i = 0
while n < 100 * 1024:
    para = " ".join(words[(i + k) % len(words)] for k in range(60))
    out.append(f"<p>{para}</p>")
    n += len(para) + 7
    i += 7
out.append("</body></html>")
open(sys.argv[1], "w").write("\n".join(out))
PY
    case $1 in *pre.html) gzip -9nk -f "$f" ;; esac
    return 0
}
fileset() { # 10k files of 4 KB: more than the open-file cache holds
    [ -d "$WWW/set" ] && return
    mkdir -p "$WWW/set"
    python3 - "$WWW/set" <<'PY'
import os, sys
blob = os.urandom(4096)
d = sys.argv[1]
for i in range(10000):
    with open(f"{d}/{i:04d}.bin", "wb") as f:
        f.write(blob)
PY
}
for w in "${WORKLOADS[@]}"; do
    case ${W_CHECK[$w]} in
        post:*) head -c "$((1024 * 1024))" /dev/zero | tr '\0' x > "$RUN/post.body" ;;
        file:*) bin "${W_CHECK[$w]#*:}" ;;
        gz:*) text "${W_CHECK[$w]#*:}" ;;
        set) fileset ;;
        ims) bin "$(basename "${W_PATH[$w]}")" ;;
    esac
done

# ---------------------------------------------------------------------- configs
cat "$CERTS/server.crt" "$CERTS/server.key" > "$RUN/server.pem"
if [ "$ACCESS_LOG" == on ]; then
    NGINX_LOG=$RUN/access-nginx.log ROUTEZ_LOG=true HAPROXY_LOG='option httplog'
else
    NGINX_LOG=off ROUTEZ_LOG=false HAPROXY_LOG='no log'
fi
fill() { # template -> rendered config
    sed "s|UPSTREAM_WORKERS|$UPSTREAM_WORKERS|g; s|WORKERS|$WORKERS|g; s|WWW|$WWW|g; s|CERTS|$CERTS|g; \
         s|ACCESS_LOG|$NGINX_LOG|g; s|ROUTEZ_LOG|$ROUTEZ_LOG|g; s|HAPROXY_LOG|$HAPROXY_LOG|g; s|RUN|$RUN|g" \
        "$1"
}
fill "$HERE/conf/upstream.conf" > "$RUN/upstream.conf"

# A row whose settings would change every other row's result gets its own
# config, and its own server processes: the routing row's regex locations are
# tried for most paths, so in the main config every row would pay for them.
render_profile() { # profile
    local d=$RUN/$1 f
    mkdir -p "$d"
    for f in nginx.conf haproxy.cfg routez.zon; do fill "$HERE/conf/$f" > "$d/$f"; done
    if [ "$1" == routing ]; then
        python3 "$HERE/tools/genrouting.py" nginx > "$d/gen.nginx"
        python3 "$HERE/tools/genrouting.py" haproxy > "$d/gen.haproxy"
        python3 "$HERE/tools/genrouting.py" routez > "$d/gen.routez"
        sed -i -e "/# ROUTING/r $d/gen.nginx" -e "/# ROUTING/d" "$d/nginx.conf"
        sed -i -e "/# ROUTING/r $d/gen.haproxy" -e "/# ROUTING/d" "$d/haproxy.cfg"
        sed -i -e "\|// ROUTING|r $d/gen.routez" -e "\|// ROUTING|d" "$d/routez.zon"
    else
        sed -i -e "/# ROUTING/d" "$d/nginx.conf" -e "/# ROUTING/d" "$d/haproxy.cfg"
        sed -i -e "\|// ROUTING|d" "$d/routez.zon"
    fi
}
PROFILES=()
for w in "${WORKLOADS[@]}"; do
    case " ${PROFILES[*]:-} " in *" ${W_PROFILE[$w]} "*) ;; *) PROFILES+=("${W_PROFILE[$w]}") ;; esac
done
for prof in "${PROFILES[@]}"; do render_profile "$prof"; done
# The 304 rows need the file's own Last-Modified, so both the gate and wrk send
# a date the servers agree is not older than the file.
IMS_DATE=
for w in "${WORKLOADS[@]}"; do
    [ "${W_CHECK[$w]}" == ims ] || continue
    IMS_DATE=$(date -u -d "@$(stat -c %Y "$WWW${W_PATH[$w]}")" '+%a, %d %b %Y %H:%M:%S GMT')
done
for w in "${WORKLOADS[@]}"; do
    [ "${W_LUA[$w]}" == - ] && continue
    cat "$HERE/report.lua" "$HERE/lua/${W_LUA[$w]}.lua" > "$RUN/wrk-$w.lua"
    [ -n "$IMS_DATE" ] && sed -i "s|IMS_DATE|$IMS_DATE|" "$RUN/wrk-$w.lua"
done

start upstream "$UP_CPUS" nginx -c "$RUN/upstream.conf"
wait_port 19090

up_servers() { # profile
    local d=$RUN/$1
    start nginx "$SERVER_CPUS" nginx -c "$d/nginx.conf"; SPID[nginx]=$!
    start haproxy "$SERVER_CPUS" haproxy -f "$d/haproxy.cfg"; SPID[haproxy]=$!
    start routez "$SERVER_CPUS" "$ROOT/zig-out/bin/routez" "$d/routez.zon"; SPID[routez]=$!
    local p
    for p in "${PLAIN[@]}" "${TLS[@]}"; do wait_port "$p"; done
    # nginx's master listens before its worker exists; the RSS baseline needs both.
    until pgrep -P "${SPID[nginx]}" >/dev/null; do sleep 0.05; done
}
down_servers() {
    local s
    profile_report
    for s in "${SERVERS[@]}"; do kill "${SPID[$s]}" 2>/dev/null; done
    for s in "${SERVERS[@]}"; do wait "${SPID[$s]}" 2>/dev/null; done
    PIDS=(${PIDS[0]}) # the upstream stays up
    SPID=()
}

# ------------------------------------------------------------------ sanity gate
# Every cell must answer correctly and every TLS port must negotiate the same
# parameters, or the numbers compare different things. The check also fixes the
# request shape each row's lua has to match.
fail=0 CODE= DL=
bad() { echo "sanity: $*"; fail=1; }
# Sets CODE and DL (bytes of body): with -I curl writes the headers into the
# body file, so its own download count is what says a response had no body.
fetch() { # url [curl args...]
    local url=$1 out; shift
    rm -f "$RUN/hdr" "$RUN/body"
    out=$(curl -sk --max-time 30 -D "$RUN/hdr" -o "$RUN/body" -w '%{http_code} %{size_download}' "$@" "$url")
    CODE=${out% *} DL=${out#* }
}
hdr() { awk -v n="$(echo "$1" | tr 'A-Z' 'a-z')" 'BEGIN{IGNORECASE=1} tolower($1) == n":" {sub(/\r$/,"",$2); print $2}' "$RUN/hdr"; }
check_cell() { # workload server
    local w=$1 s=$2 url want f
    url=$(target "$w" "$s")
    case ${W_CHECK[$w]} in
        pong)
            fetch "$url"
            [ "$CODE" == 200 ] || { bad "$s $w: status $CODE"; return; }
            [ "$(cat "$RUN/body")" == pong ] || bad "$s $w: body '$(head -c 60 "$RUN/body")'" ;;
        file:*)
            f=$WWW/${W_CHECK[$w]#*:}
            fetch "$url"
            [ "$CODE" == 200 ] || { bad "$s $w: status $CODE"; return; }
            cmp -s "$RUN/body" "$f" || bad "$s $w: wrong body" ;;
        set)
            fetch "${url}0042.bin"
            [ "$CODE" == 200 ] || { bad "$s $w: status $CODE"; return; }
            cmp -s "$RUN/body" "$WWW/set/0042.bin" || bad "$s $w: wrong body" ;;
        ims)
            fetch "$url" -H "If-Modified-Since: $IMS_DATE"
            [ "$CODE" == 304 ] || bad "$s $w: status $CODE, want 304"
            [ "$DL" == 0 ] || bad "$s $w: 304 with $DL bytes of body" ;;
        404)
            fetch "$url"
            [ "$CODE" == 404 ] || bad "$s $w: status $CODE, want 404" ;;
        pipe:*)
            python3 "$HERE/tools/pipecheck.py" "$url" "${W_CHECK[$w]#*:}" pong || bad "$s $w: pipelining" ;;
        post:*)
            fetch "$url" --data-binary "@$RUN/post.body" -H 'Content-Type: application/octet-stream'
            [ "$CODE" == 200 ] || { bad "$s $w: status $CODE"; return; }
            [ "$(cat "$RUN/body")" == pong ] || bad "$s $w: body '$(head -c 60 "$RUN/body")'" ;;
        gz:*)
            f=$WWW/${W_CHECK[$w]#*:}
            fetch "$url" -H 'Accept-Encoding: gzip'
            [ "$CODE" == 200 ] || { bad "$s $w: status $CODE"; return; }
            [ "$(hdr content-encoding)" == gzip ] || bad "$s $w: content-encoding '$(hdr content-encoding)', want gzip"
            gzip -dc < "$RUN/body" | cmp -s - "$f" || bad "$s $w: body doesn't decompress to the file"
            # The row compares encoders, so say how well each one did: a server
            # sending twice the bytes is not doing the same work as its neighbour.
            echo "sanity: $s $w: $DL bytes from $(wc -c < "$f") compressed" ;;
        *) bad "$w: unknown check '${W_CHECK[$w]}'" ;;
    esac
}
check_tls() { # server: same parameters everywhere, or the rows compare different work
    local s=$1 tls
    tls=$(echo | openssl s_client -brief -connect "127.0.0.1:${TLS[$s]}" 2>&1 |
        awk -F': ' '/^Protocol version/ {p=$2} /^Ciphersuite/ {c=$2} /Temp Key|Negotiated TLS1.3 group/ {split($2, k, ","); g=k[1]} END {print p, c, g}')
    [ "$tls" == "TLSv1.3 TLS_AES_128_GCM_SHA256 X25519" ] || bad "$s negotiates '$tls'"
    printf 'GET /ping HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n' |
        openssl s_client -connect "127.0.0.1:${TLS[$s]}" -sess_out "$RUN/sess" -ign_eof >/dev/null 2>&1
    echo | openssl s_client -connect "127.0.0.1:${TLS[$s]}" -sess_in "$RUN/sess" 2>/dev/null | grep -q '^Reused' ||
        bad "$s doesn't resume TLS sessions"
}
for prof in "${PROFILES[@]}"; do
    up_servers "$prof"
    https=no
    for w in "${WORKLOADS[@]}"; do
        [ "${W_PROFILE[$w]}" == "$prof" ] && [ "${W_SCHEME[$w]}" == https ] && https=yes
    done
    for s in "${SERVERS[@]}"; do
        for w in "${WORKLOADS[@]}"; do
            [ "${W_PROFILE[$w]}" == "$prof" ] && serves "$w" "$s" && check_cell "$w" "$s"
        done
        [ "$https" == yes ] && check_tls "$s"
    done
    down_servers
done
[ "$fail" == 0 ] || { tail -n 20 "$RUN"/*.log; exit 1; }

{ env_header; cat <<EOF
wrk: $(wrk -v 2>&1 | awk 'NR == 1 {print $2}')
openssl: $(openssl version | awk '{print $2}')
workers: $WORKERS
conns: $CONNS
duration: $DURATION
rounds: $ROUNDS
access_log: $ACCESS_LOG
pinning: $PINNING
server_cpus: $SERVER_CPUS
wrk_cpus: $WRK_CPUS
wrk_threads: $WRK_THREADS
wide_wrk_cpus: $WIDE_CPUS
wide_wrk_threads: $WIDE_THREADS
upstream_cpus: $UP_CPUS
EOF
} > "$OUT/env.txt"

# ------------------------------------------------------------------ measurement
run_wrk() { # workload server seconds output
    local w=$1 cpus=$WRK_CPUS threads=$WRK_THREADS c script=$HERE/report.lua
    [ "${W_UP[$w]}" == no ] && cpus=$WIDE_CPUS threads=$WIDE_THREADS
    [ "${W_LUA[$w]}" == - ] || script=$RUN/wrk-$w.lua
    c=$(conns_of "$w")
    [ "$threads" -gt "$c" ] && threads=$c # wrk needs a connection per thread
    OPENSSL_CONF="$HERE/conf/wrk-openssl.cnf" taskset -c "$cpus" \
        wrk -t "$threads" -c "$c" -d "${3}s" --timeout 10s --latency -s "$script" \
            "$(target "$w" "$2")" > "$4" 2>&1
}

for w in "${WORKLOADS[@]}"; do
    mapfile -t act < <(active "$w")
    # Restart the servers per row, so its memory is its own and no earlier row's
    # open-file cache or connection pool is still warm.
    up_servers "${W_PROFILE[$w]}"
    for s in "${act[@]}"; do tree_rss "${SPID[$s]}" > "$OUT/raw/$w.$s.base"; done
    for s in "${act[@]}"; do run_wrk "$w" "$s" 2 /dev/null; done
    for r in $(seq 1 "$ROUNDS"); do
        # Rotate who goes first so drift doesn't favour one server.
        for i in $(seq 0 $((${#act[@]} - 1))); do
            s=${act[$(((i + r - 1) % ${#act[@]}))]}
            f="$OUT/raw/$w.$s.$r"
            sleep 1
            grep '^cpu[0-9]' /proc/stat > "$f.stat0"
            run_wrk "$w" "$s" "$DURATION" "$f.txt"
            grep '^cpu[0-9]' /proc/stat > "$f.stat1"
            tree_rss "${SPID[$s]}" > "$f.rss"
            echo "$w $s #$r: $(awk '/^Requests\/sec/ {print $2}' "$f.txt") req/s"
        done
    done
    down_servers
done

python3 "$HERE/report.py" "$OUT" && echo && cat "$OUT/table.md"

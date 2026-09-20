# nginx (nginx.org stable), HAProxy (LTS PPA), wrk and oha, h2load with HTTP/3,
# Zig, Node.js with `ws`, and strace/perf/eu-stack for bench/profile.sh, all for
# bench/run.sh.
FROM ubuntu:26.04
ARG ZIG_VERSION=0.16.0
ARG HAPROXY_BRANCH=3.2
ARG WRK_VERSION=4.2.0
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg xz-utils unzip software-properties-common \
        build-essential libssl-dev openssl python3 rsync git util-linux \
        iproute2 procps strace linux-perf elfutils nodejs npm \
    && . /etc/os-release \
    && curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/nginx.gpg] https://nginx.org/packages/ubuntu $VERSION_CODENAME nginx" \
        > /etc/apt/sources.list.d/nginx.list \
    && add-apt-repository -y "ppa:vbernat/haproxy-$HAPROXY_BRANCH" \
    && apt-get update && apt-get install -y --no-install-recommends nginx "haproxy=$HAPROXY_BRANCH.*" \
    && rm -rf /var/lib/apt/lists/*
# wrk times requests on the wall clock. Docker Desktop's VM steps it to
# follow the host, and a step back counts every request in flight as a
# timeout, so time them on the monotonic clock.
RUN curl -fsSL "https://github.com/wg/wrk/archive/refs/tags/$WRK_VERSION.tar.gz" | tar -xz -C /tmp \
    && cd "/tmp/wrk-$WRK_VERSION" \
    && sed -i '1i #include <time.h>' src/wrk.c \
    && sed -i 's/struct timeval t;/struct timespec t;/; s/gettimeofday(&t, NULL);/clock_gettime(CLOCK_MONOTONIC, \&t);/; s/+ t\.tv_usec;/+ t.tv_nsec \/ 1000;/' src/wrk.c \
    && grep -q 'clock_gettime(CLOCK_MONOTONIC' src/wrk.c && grep -q 'tv_nsec / 1000' src/wrk.c \
    && make -j"$(nproc)" WITH_OPENSSL=/usr VER="$WRK_VERSION" \
    && cp wrk /usr/local/bin/ && cd / && rm -rf "/tmp/wrk-$WRK_VERSION"
RUN curl -fsSL "https://ziglang.org/download/$ZIG_VERSION/zig-$(uname -m)-linux-$ZIG_VERSION.tar.xz" | tar -xJ -C /opt \
    && ln -s "/opt/zig-$(uname -m)-linux-$ZIG_VERSION/zig" /usr/local/bin/zig
# h2load is the HTTP/3 load generator: a client from neither project under test.
# OpenSSL 3.5 in this image has the QUIC API, so ngtcp2 needs no forked TLS.
ARG NGHTTP3_VERSION=v1.18.0
ARG NGTCP2_VERSION=v1.25.0
ARG NGHTTP2_VERSION=v1.70.0
RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake libtool pkg-config cmake g++ libev-dev libc-ares-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux \
    && git clone --depth 1 -b "$NGHTTP3_VERSION" --recursive https://github.com/ngtcp2/nghttp3 /tmp/nghttp3 \
    && cd /tmp/nghttp3 && autoreconf -i && ./configure --prefix=/usr/local --enable-lib-only \
    && make -j"$(nproc)" && make install \
    && git clone --depth 1 -b "$NGTCP2_VERSION" --recursive https://github.com/ngtcp2/ngtcp2 /tmp/ngtcp2 \
    && cd /tmp/ngtcp2 && autoreconf -i && ./configure --prefix=/usr/local --enable-lib-only --with-ossl \
    && make -j"$(nproc)" && make install \
    && git clone --depth 1 -b "$NGHTTP2_VERSION" --recursive https://github.com/nghttp2/nghttp2 /tmp/nghttp2 \
    && cd /tmp/nghttp2 && autoreconf -i \
    && ./configure --prefix=/usr/local --enable-app --enable-http3 --disable-python-bindings \
        --without-jemalloc PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    && make -j"$(nproc)" -C third-party && make -j"$(nproc)" -C lib \
    && make -j"$(nproc)" -C src h2load \
    && ./libtool --mode=install install -c src/h2load /usr/local/bin/h2load \
    && ldconfig \
    && cd / && rm -rf /tmp/nghttp3 /tmp/ngtcp2 /tmp/nghttp2 \
    && h2load --version \
    && h2load --help 2>&1 | grep -qi 'h3'  # built without HTTP/3 it wouldn't mention it
# oha holds a fixed request rate, which wrk cannot: its closed loop reports the
# latency the server allows rather than the latency at a given load.
ARG OHA_VERSION=v1.16.0
RUN case "$(uname -m)" in aarch64|arm64) A=arm64 ;; x86_64) A=amd64 ;; *) echo "no oha build for $(uname -m)"; exit 1 ;; esac \
    && curl -fsSL -o /usr/local/bin/oha \
        "https://github.com/hatoo/oha/releases/download/$OHA_VERSION/oha-linux-$A" \
    && chmod +x /usr/local/bin/oha \
    && oha --version

ARG WS_VERSION=8
RUN mkdir /opt/ws && cd /opt/ws && npm install --no-audit --no-fund "ws@$WS_VERSION"
ENV NODE_PATH=/opt/ws/node_modules

# nginx (nginx.org stable), HAProxy (LTS PPA), wrk and Zig, for bench/run.sh.
FROM ubuntu:26.04
ARG ZIG_VERSION=0.16.0
ARG HAPROXY_BRANCH=3.2
ARG WRK_VERSION=4.2.0
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg xz-utils unzip software-properties-common \
        build-essential libssl-dev openssl python3 rsync git util-linux \
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

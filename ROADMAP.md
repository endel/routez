# Roadmap

In priority order. Effort: S (days), M (a week or two), L (several weeks).

## Next: expected by most sites

1. **HTTP/2** (L). Most TLS traffic and all gRPC use it; clients fall back to
   HTTP/1.1 today, or to HTTP/3 via `Alt-Svc`.
2. **Matching and rewriting** (M). Exact and regex locations, rewrite rules,
   IP allow/deny.
3. **Access control** (M). Basic auth; client certificates for internal
   services.
4. **Compression** (S–M). Serve precompressed `.gz`/`.br` files; Brotli on
   the fly.
5. **Limits shared across workers** (M). `limit_req` and per-IP limits are
   multiplied by the worker count today.
6. **Static file I/O off the worker thread** (M). A slow disk stalls the
   worker today.

## Later: differentiators and larger projects

7. **Response caching** like nginx's `proxy_cache` (L).
8. **WebSockets over HTTP/3 and HTTP/2** (RFC 9220, RFC 8441) (M, after
   HTTP/2). Moves up if real-time and game traffic is the main audience.
9. **ACME DNS-01** for wildcard certificates, and OCSP stapling (M).
10. **Layer-4 TCP proxy** beside the UDP one (S).
11. **Zero-downtime QUIC reloads** (L). New connections that land on the old
    generation's sockets are refused for up to 10 s; needs socket handover or
    eBPF steering.
12. **quic-zig idle timeout covering PTO backoff.** A patch exists, parked:
    under realistic loss nothing fails, only outages of 12 s or more do, and
    it would let dead peers hold a slot for up to 180 s.

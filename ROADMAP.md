# Roadmap

In priority order. Effort: S (days), M (a week or two), L (several weeks).

## Next

1. **Limits shared across workers** (M). `limit_req` and per-IP limits are
   multiplied by the worker count today.
2. **Access control** (M). IP allow/deny, basic auth, client certificates
   for internal services.
3. **Matching and rewriting** (M). Exact and regex locations (a linear-time
   engine, so patterns can't be used for ReDoS), rewrite rules.
4. **Compression** (S–M). Serve precompressed `.gz`/`.br` files; Brotli on
   the fly.
5. **Static file I/O off the worker thread** (M). A slow disk stalls the
   worker today.

## Later: larger projects, or waiting on a need

6. **Zero-downtime QUIC reloads** (L). New connections that land on the old
   generation's sockets are refused for up to 10 s; needs socket handover or
   eBPF steering.
7. **Response caching** like nginx's `proxy_cache` (L).
8. **WebSockets over HTTP/3** (RFC 9220) (M). Browsers don't use it yet;
   worth doing once they do, for real-time traffic.
9. **HTTP/2** (L), with WebSockets over it (RFC 8441). Needed for gRPC and
   for clients on networks that block UDP, who fall back to HTTP/1.1 today;
   browsers otherwise reach HTTP/3 via `Alt-Svc`. A third protocol stack
   with a long DoS history (Rapid Reset, CONTINUATION floods, HPACK bombs),
   so only when one of those needs arrives.
10. **ACME DNS-01** for wildcard certificates, and OCSP stapling (M).
11. **Layer-4 TCP proxy** beside the UDP one (S).
12. **quic-zig idle timeout covering PTO backoff.** A patch exists, parked:
    under realistic loss nothing fails, only outages of 12 s or more do, and
    it would let dead peers hold a slot for up to 180 s.

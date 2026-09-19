# Roadmap

In priority order. Effort: S (days), M (a week or two), L (several weeks).

## Next

1. **Matching and rewriting** (M). Exact and regex locations (a linear-time
   engine, so patterns can't be used for ReDoS), rewrite rules.
2. **Compression** (S–M). Serve precompressed `.gz`/`.br` files; Brotli on
   the fly.
3. **Static file I/O off the worker thread** (M). A slow disk stalls the
   worker today.
4. **Trusted proxies** (S). `real_ip_from`: take the client address from
   `X-Forwarded-For` or the PROXY protocol when the peer is a listed proxy,
   so IP rules, limits and logs see the real client behind a load balancer.
5. **Client certificates to upstreams** (S). quic-zig's `tls_client` can
   present one; routez needs the config and key loading.

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

# Roadmap

In priority order. Effort: S (days), M (a week or two), L (several weeks).

## Next

1. **`sendfile` for plain HTTP/1.1** (S). Static bodies are copied through
   userspace; TLS and HTTP/3 need that, plain HTTP doesn't.

## Later: larger projects, or waiting on a need

2. **Zero-downtime QUIC reloads** (L). New connections that land on the old
   generation's sockets are refused for up to 10 s; needs socket handover or
   eBPF steering.
3. **Response caching** like nginx's `proxy_cache` (L).
4. **WebSockets over HTTP/3** (RFC 9220) (M). Browsers don't use it yet;
   worth doing once they do, for real-time traffic.
5. **HTTP/2** (L), with WebSockets over it (RFC 8441). Needed for gRPC and
   for clients on networks that block UDP, who fall back to HTTP/1.1 today;
   browsers otherwise reach HTTP/3 via `Alt-Svc`. A third protocol stack
   with a long DoS history (Rapid Reset, CONTINUATION floods, HPACK bombs),
   so only when one of those needs arrives.
6. **ACME DNS-01** for wildcard certificates, and OCSP stapling (M).
7. **Layer-4 TCP proxy** beside the UDP one (S).
8. **quic-zig idle timeout covering PTO backoff.** A patch exists, parked:
   under realistic loss nothing fails, only outages of 12 s or more do, and
   it would let dead peers hold a slot for up to 180 s.
9. **Brotli and zstd on the fly** (L). Needs an encoder: Zig's standard
   library has neither, a minimal one would compress worse than gzip, and C
   libraries are out. Precompress at build time instead.

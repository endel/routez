# Roadmap

In priority order. Effort: S (days), M (a week or two), L (several weeks).

## Now: blockers for a real deployment

1. **Known bugs.**
   - quic-zig never checks received packets for a stateless reset, so a
     client keeps retransmitting after the server has dropped it.
   - quic-zig: QPACK encoder instructions split across reads are fatal.
   - quic-zig: a bidi stream is freed on FIN while a gap is still open.
   - A request during a SIGHUP reload occasionally gets no response (seen on
     Linux CI).
2. **Redirects with variables** (S). `return` can't build a `Location` from
   the request, so there's no plain HTTP to HTTPS redirect. Needs `$host`
   and `$request_uri`.
3. **`try_files` fallback** (S). Single-page apps need a missing path to
   serve `index.html`.
4. **RSA certificates** (M). Only EC P-256 and Ed25519 keys load; ACME is
   unaffected.
5. **TLS to HTTP/1.1 upstreams** (M). `proxy_pass` can't reach an HTTPS
   backend; needs a TCP TLS client.
6. **Operations basics** (M). Drop root after binding, reopen logs for
   rotation, configurable access log format and error log level, Prometheus
   metrics.

## Next: expected by most sites

7. **HTTP/2** (L). Most TLS traffic and all gRPC use it; clients fall back to
   HTTP/1.1 today, or to HTTP/3 via `Alt-Svc`.
8. **Matching and rewriting** (M). Exact and regex locations, rewrite rules,
   IP allow/deny.
9. **Access control** (M). Basic auth; client certificates for internal
   services.
10. **Compression** (S–M). Serve precompressed `.gz`/`.br` files; Brotli on
    the fly.
11. **Limits shared across workers** (M). `limit_req` and per-IP limits are
    multiplied by the worker count today.
12. **Static file I/O off the worker thread** (M). A slow disk stalls the
    worker today.

## Later: differentiators and larger projects

13. **Response caching** like nginx's `proxy_cache` (L).
14. **WebSockets over HTTP/3 and HTTP/2** (RFC 9220, RFC 8441) (M, after
    HTTP/2). Moves up if real-time and game traffic is the main audience.
15. **ACME DNS-01** for wildcard certificates, and OCSP stapling (M).
16. **Layer-4 TCP proxy** beside the UDP one (S).
17. **Zero-downtime QUIC reloads** (L). New connections that land on the old
    generation's sockets are refused for up to 10 s; needs socket handover or
    eBPF steering.
18. **quic-zig idle timeout covering PTO backoff.** A patch exists, parked:
    under realistic loss nothing fails, only outages of 12 s or more do, and
    it would let dead peers hold a slot for up to 180 s.

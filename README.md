# routez

An nginx-style edge server in Zig 0.16, on [libxev](https://github.com/mitchellh/libxev)
and [quic-zig](../quic-zig). No C dependencies beyond libc.

- HTTP/1.1 server: keep-alive, pipelining, chunked bodies, strict parsing
  (request smuggling defenses), header/body limits, timeouts, per-IP
  connection limits.
- HTTP/3 over QUIC (quic-zig), on the same event loop as everything else,
  with `Alt-Svc` advertised on the TCP side.
- WebTransport relay: sessions are terminated and re-opened on an HTTP/3
  upstream, with streams and datagrams paired one to one.
- TLS 1.3 on TCP (quic-zig's sans-IO `tls_server`): SNI certificate
  selection, ALPN, session resumption.
- Static files: ranges, ETag / Last-Modified conditional requests, index
  files, directory redirects, path normalization.
- Reverse proxy to HTTP/1.1 upstreams: streaming in both directions with
  backpressure, keep-alive connection pools, retries of replayable requests,
  connect/read timeouts, WebSocket (Upgrade) tunnels, X-Forwarded-* headers.
- Load balancing: round robin, least connections, IP hash; passive failure
  tracking and active HTTP health checks.
- Layer-4 UDP proxy for QUIC traffic, with QUIC-LB connection-ID routing.
- Worker threads with SO_REUSEPORT. Graceful shutdown on SIGINT/SIGTERM:
  keep-alive connections close when idle, HTTP/3 connections get GOAWAY and
  finish their requests, with a 10 s limit.
- `stub_status`-style counters and an access log.

## Build and run

```sh
zig build -Doptimize=ReleaseFast
./zig-out/bin/routez routez.zon         # -t checks the config and exits
```

`build.zig.zon` depends on `../quic-zig` by path.

## Configuration

A ZON file; see `src/config.zig` for every field and default.

```zig
.{
    .workers = 4,
    .servers = .{.{
        .listen = .{
            .{ .port = 80 },
            .{ .port = 443, .tls = true, .quic = true },
        },
        .server_names = .{ "example.com", "*.example.com" },
        .tls = .{ .cert = "fullchain.pem", .key = "privkey.pem" },
        .locations = .{
            .{ .prefix = "/", .root = "/var/www" },
            .{ .prefix = "/api/", .proxy_pass = "backend", .strip_prefix = true },
            .{ .prefix = "/health", .@"return" = .{ .body = "ok\n" } },
            .{ .prefix = "/status", .stub_status = true },
            .{ .prefix = "/wt/", .webtransport_pass = "10.0.0.5:4433" },
        },
    }},
    .upstreams = .{.{
        .name = "backend",
        .servers = .{ "10.0.0.1:8080", "10.0.0.2:8080" },
        .balance = .least_conn,
        .health = .{ .path = "/healthz", .interval_ms = 5000 },
    }},
    .udp_proxies = .{.{
        .port = 4433,
        .proxy_pass = "game",
        .quic_lb = .{ .server_id_len = 2, .server_ids = .{ "0001", "0002" } },
    }},
}
```

- A location has exactly one of `root`, `proxy_pass`, `return`,
  `stub_status` or `webtransport_pass`; the longest matching prefix wins.
- `webtransport_pass` applies to WebTransport CONNECTs over HTTP/3. QUIC
  upstream certificates are not verified unless the upstream sets
  `tls_verify` or `tls_ca`.
- `root` follows nginx semantics: the full request path is appended.
- Servers sharing a listen address are virtual hosts, chosen by `Host`
  (exact name, then one-label wildcard, then the first server).
- TLS keys must be EC P-256 or Ed25519. TLS 1.2 is not supported.

## Tests

```sh
zig build test          # unit tests
tests/e2e/run.sh        # end-to-end over HTTP/1.1, TLS, HTTP/3 and WebTransport
```

The end-to-end script needs python3, bun, node >= 22, a curl built with
HTTP/3 (Homebrew's), and a built `../quic-zig` (its WebTransport echo server
is the relay's upstream).

## Limitations

- The WebTransport relay has no backpressure between its two sides.
- With several workers, a QUIC client that changes address can land on a
  worker that doesn't hold its connection and gets reset; steering by
  connection ID (QUIC-LB or eBPF) isn't wired up.
- Static files are read on the worker thread; fine for page-cached files,
  slow disks stall that worker.
- Upstream pools and health state are per worker, so health checks run once
  per worker per interval.
- macOS does not spread TCP connections across SO_REUSEPORT listeners, so
  extra workers only help on Linux.

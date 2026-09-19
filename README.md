![routez](./routez.svg)

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
- Automatic certificates from Let's Encrypt or any ACME CA (RFC 8555,
  HTTP-01), renewed and swapped in without dropping connections.
- Static files: ranges, ETag / Last-Modified conditional requests, index
  files, directory redirects, path normalization, `try_files` fallbacks for
  single-page apps.
- Reverse proxy to HTTP/1.1 upstreams, plain or over TLS 1.3 (quic-zig's
  sans-IO `tls_client`, with optional certificate verification): streaming
  in both directions with backpressure, keep-alive connection pools, retries
  of replayable requests, connect/read timeouts, WebSocket (Upgrade)
  tunnels, X-Forwarded-* headers.
- Load balancing: round robin, least connections, IP hash; passive failure
  tracking and active HTTP health checks.
- Layer-4 UDP proxy for QUIC traffic, with QUIC-LB connection-ID routing.
- Worker threads with SO_REUSEPORT. Graceful shutdown on SIGINT/SIGTERM:
  keep-alive connections close when idle, HTTP/3 connections get GOAWAY and
  finish their requests, with a 10 s limit.
- Reload on SIGHUP: new workers start on the new config beside the old ones,
  taking over their TCP listening sockets, and the old ones drain. A config
  that fails to load is rejected and the running one kept.
- Per location: gzip for text-like responses, `add_headers`,
  `proxy_set_headers` (set, replace, remove, override Host) and `limit_req`
  (per-client token bucket).
- Redirects and header values built from the request with nginx-style
  variables (`$host`, `$request_uri`, ...).
- Operations: drops root after binding (`user`, `group`), access and error
  log files reopened on SIGUSR1 for rotation, access log formats (nginx's
  `combined`, JSON lines, or a template of variables), a runtime log level,
  Prometheus metrics and `stub_status`-style counters.
- Certificates are checked against their keys at load (`-t` too).

## Build and run

```sh
zig build -Doptimize=ReleaseFast
./zig-out/bin/routez routez.zon         # -t checks the config and exits
```

`build.zig.zon` depends on `../quic-zig` by path.

On arm64, check that the build has AES: Zig 0.16 reads some CPUs as
`generic` without it (Apple silicon inside a Linux VM, for one), and TLS then
encrypts in software, about 10× slower serving a 10 KB file. Build with
`-Dcpu=native+aes+sha2` there.

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
            .{ .prefix = "/api/", .proxy_pass = "backend", .strip_prefix = true,
               .proxy_set_headers = .{.{ .name = "x-env", .value = "prod" }},
               .limit_req = .{ .rate = 50, .burst = 100 } },
            .{ .prefix = "/assets/", .root = "/var/www", .gzip = true,
               .add_headers = .{.{ .name = "cache-control", .value = "max-age=3600" }} },
            .{ .prefix = "/health", .@"return" = .{ .body = "ok\n" } },
            .{ .prefix = "/status", .stub_status = true },
            .{ .prefix = "/metrics", .metrics = true },
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
  `stub_status`, `metrics` or `webtransport_pass`; the longest matching
  prefix wins.
- `webtransport_pass` applies to WebTransport CONNECTs over HTTP/3. QUIC
  upstream certificates are not verified unless the upstream sets
  `tls_verify` or `tls_ca`.
- An upstream with `.tls = true` is reached over HTTPS (TLS 1.3 only). As
  with nginx's `proxy_ssl_verify off`, its certificate is not checked unless
  the upstream sets `tls_verify = true` (system CA store) or
  `tls_ca = "ca.pem"`. Verification checks the chain, the host name and the
  handshake signature; `tls_server_name` overrides the name used for SNI and
  the check, which is otherwise each server's host. A server given as an IP
  address is matched against the certificate's IP addresses and gets no
  SNI. A failed handshake counts as a failed connect: the request moves to
  the next server, or gets a 502. Health checks use TLS too.

  ```zig
  .{ .name = "api", .servers = .{"10.0.0.7:443"}, .tls = true,
     .tls_verify = true, .tls_server_name = "api.internal.example" },
  ```
- `root` follows nginx semantics: the full request path is appended.
- `try_files = .{ "$uri", "$uri/", "/index.html" }` on a `root` location
  serves the first entry that is a file: `$uri` is the request path, an
  entry ending in `/` means that directory's `index`. The last entry is the
  fallback, served for any path, or a status such as `"=404"`. Unlike
  nginx, the fallback is a file under the same `root`, not a new request
  routed through the locations.
- Servers sharing a listen address are virtual hosts, chosen by `Host`
  (exact name, then one-label wildcard, then the first server).
- TLS keys may be EC P-256, Ed25519 or RSA (2048 to 4096 bits). TLS 1.2 is
  not supported. A key that doesn't belong to the first certificate of its
  `cert` file fails the load.

### Operations

```zig
.{
    .user = "www-data",              // after binding; group defaults to its own
    .error_log = "/var/log/routez/error.log",
    .log_level = .warn,              // .err, .warn, .info (default), .debug
    .access_log_path = "/var/log/routez/access.log",
    .access_log_format = "json",     // "main" (default), "combined", "json" or a template
    // .access_log_format = "$remote_addr [$time_iso8601] \"$request\" $status $request_time",
    .servers = ...,
}
```

- Started as root with `user` set, routez binds its listeners, opens its log
  files, hands ACME storage to that user, then gives up root in every thread
  before serving. If that fails it exits rather than serve as root. After
  that a reload takes the listening sockets (TCP, QUIC and UDP) over from
  the running workers, so it keeps ports below 1024, but it can't bind a new
  one: such a reload is refused, naming the port, and the old configuration
  keeps running. The config file, certificates and document roots must be
  readable by `user`, since reloads read them as that user.
- Without `access_log_path` and `error_log`, both go to stderr. SIGUSR1
  reopens both by path, after logrotate has moved them; lines being written
  meanwhile go to one file or the other, none is lost. The new files are
  created by `user`, so the log directory must be writable by it, or the
  rotation must create them (logrotate's `create`); a file that can't be
  reopened keeps being written where it was.
- Access log templates take the variables above and `$status`,
  `$body_bytes_sent`, `$request_time`, `$request`, `$request_method`,
  `$protocol`, `$upstream_addr`, `$request_completion`, `$time_iso8601`,
  `$time_local`, `$msec` and any request header as `$http_<name>`
  (`$http_user_agent`); see `src/access_log.zig`. Values are escaped as
  nginx does (`\xHH`), or for JSON with `.access_log_escape = .json`; the
  `json` preset always is. Times are in UTC. `main`, the default, is
  `client "GET /path HTTP/1.1" status bytes time host= upstream=`.
- `.metrics = true` on a location serves the Prometheus text format:
  connections accepted and open (TCP and QUIC), requests by protocol,
  responses by protocol and status class, body bytes in and out, per
  upstream server requests, failures and health-check state, reloads,
  QUIC datagrams steered between workers, workers, start time and version.
  Counters are process-wide and survive reloads. Restrict it like any
  location, for instance on a listener bound to a private address.

### Redirects and variables

`return` takes a `location` for redirects, and it, `add_headers` and
`proxy_set_headers` values may use variables, written `$name` or `${name}`:

```zig
// Plain HTTP to HTTPS.
.{ .listen = .{.{ .port = 80 }}, .locations = .{
    .{ .prefix = "/", .@"return" = .{ .status = 301, .location = "https://$host$request_uri" } },
} },
```

| variable | value |
|---|---|
| `$scheme` | `http` or `https` |
| `$host` | `Host` / `:authority` lowercased, without the port; the first `server_names` entry if absent |
| `$request_uri` | path and query as the client sent them |
| `$uri` | normalized path (dot segments resolved), percent-encoded |
| `$args`, `$is_args` | query string without the `?`; `?` if there is one |
| `$remote_addr` | client IP |

An unknown variable, or a `$` not starting one, fails the config check. A
value that would expand to something invalid in a header gets a 400.

### Automatic certificates (ACME)

Instead of `cert` and `key`, a server can ask an ACME CA for its certificate:

```zig
.{
    .listen = .{ .{ .port = 80 }, .{ .port = 443, .tls = true, .quic = true } },
    .server_names = .{ "example.com", "www.example.com" },
    .tls = .{ .acme = .{
        .email = "ops@example.com",
        // Default: Let's Encrypt production. Try staging first:
        // .directory = "https://acme-staging-v02.api.letsencrypt.org/directory",
        .storage = "/var/lib/routez/acme",
    } },
    .locations = .{ .{ .prefix = "/", .root = "/var/www" } },
}
```

| field | default | |
|---|---|---|
| `email` | none | contact for the CA's expiry and policy notices |
| `directory` | Let's Encrypt production | the CA's directory URL (https) |
| `storage` | `/var/lib/routez/acme` | account key and certificates |
| `ca_file` | system roots | PEM bundle to trust for the directory's HTTPS (test CAs such as Pebble) |
| `renew_days` | 30 | renew when fewer days than this remain (or half the lifetime, if that is shorter) |
| `check_interval_s` | 43200 | how often stored certificates are checked |
| `order_timeout_s` | 300 | longest one attempt may take, network waits included |

- The certificate covers every name in `server_names`. Configuring `acme`
  means agreeing to the CA's terms of service.
- Validation is HTTP-01: while an order is pending, every plain-HTTP listener
  answers `/.well-known/acme-challenge/<token>` ahead of its locations. The
  CA connects to port 80 of each name, so one must reach a plain listener
  (routez warns when none listens on 80).
- One thread per process talks to the CA, off the worker event loops.
- At startup the stored certificate is used as long as it hasn't expired.
  When the names changed, the stored one covering the most of them keeps
  serving until the new one arrives. With nothing usable stored, the TLS
  listeners come up at once with a self-signed placeholder (clients see a
  certificate error, not a refused connection) while one is obtained.
- A new certificate is written to storage, then the running configuration is
  reloaded as for SIGHUP: new workers load it, old ones drain. That reload
  reuses the configuration text already running, so edits to the file
  still wait for a SIGHUP. A reload that fails is asked for again every 10 s.
- Failures are logged and retried after 1 minute, doubling to 32 minutes, or
  later if the CA says so (Retry-After, rate limits). An attempt that hits
  `order_timeout_s` is abandoned. A certificate issued but not yet stored,
  or an order already finalized, is picked up on the retry rather than
  ordered again, and no order is placed while storage can't be written.
- Storage layout, directories 0700 and files 0600, replaced atomically:
  `<storage>/<ca-host>/account.key` and `<storage>/<ca-host>/<name>.pem`
  (the chain, then its key), where `<name>` is the alphabetically first
  server name. Keeping them per CA host means staging
  certificates are never served once `directory` points at production.

## Tests

```sh
zig build test          # unit tests
tests/e2e/run.sh        # end-to-end over HTTP/1.1, TLS, HTTP/3 and WebTransport
tests/acme/run.sh       # ACME against Pebble in Docker (skipped without Docker)
```

The end-to-end script needs python3, bun, node >= 22, curl, and a built
`../quic-zig` (its WebTransport echo server is the relay's upstream). The
HTTP/3 checks need a curl built with HTTP/3: Homebrew's on macOS; on Linux,
without one, the script fetches a pinned static build (stunnel/static-curl,
checksummed) into `~/.cache/routez-e2e`. Set `CURL_BIN` to use another. The ACME script needs Docker, python3, curl and
openssl; it runs Pebble, Let's Encrypt's test CA, with real HTTP-01
validation against routez.

## Performance

```sh
bench/run.sh    # routez, nginx and HAProxy in a Linux container (needs Docker)
```

It builds routez, starts all three beside a shared upstream, and runs wrk
against one server at a time. The table and every run land in
`bench/results/<timestamp>/`. Knobs: `WORKERS` (3), `CONNS` (256),
`DURATION` (10 s), `ROUNDS` (3), `WORKLOADS` (a subset of rows).

Docker Desktop on an Apple M-series Mac (10 cores), 18 Sep 2026: nginx 1.30.5
and HAProxy 3.2.23 on OpenSSL 3.5, 3 workers each, with the server, wrk and
upstream on separate cores. Median of 3 × 10 s runs, keep-alive, in
requests per second. Relative numbers only; a VM is not a benchmark machine.

| Workload | nginx | HAProxy | routez |
|---|---|---|---|
| Fixed response (`return`) | 597k | 402k | 495k |
| 10 KB static file | 251k | — | 240k |
| Reverse proxy to a keep-alive upstream | 218k | 180k | 225k |
| TLS: fixed response | 368k | 275k | 385k |
| TLS: 10 KB static file | 131k | — | 163k |
| TLS: new connection per request | 12k | 10k | 16k |

- HAProxy isn't a file server. nginx has `sendfile` on; routez reads files on
  the worker thread.
- TLS is 1.3 with AES-128-GCM and X25519 everywhere, routez's own choice;
  nginx and HAProxy are pinned to it.
- The last row measures resumed handshakes: wrk reuses the session on each
  new connection. wrk is also at its limit there, so read it as an ordering.

## Limitations

- ACME: HTTP-01 only, so no wildcard names (they need DNS-01) and port 80
  must be reachable from the internet. No certificate revocation, ARI or
  external account binding. Every change of certificate reloads all workers.
- Let's Encrypt rate-limits issuance (for example 5 certificates per exact
  set of names per week, and failed validations per hour); test against
  the staging directory before production.

- During a reload, new QUIC connections that the kernel hands to the old
  generation's sockets are refused until it finishes draining (up to 10 s);
  browsers fall back to TCP meanwhile.
- A reload that lowers `workers` closes the extra TCP listening sockets,
  resetting any connection queued on them at that moment.
- QUIC connections close after `limits.quic_idle_timeout_ms` of silence
  (30 s by default). Each end uses the smaller of the two advertised values,
  so raising it only helps clients that advertise more; a client that
  vanishes holds its connection slot until the timeout.
- With several workers, a stateless reset from a client that changed address
  can reach a worker that doesn't own its connection and is dropped: its
  connection ID is random by design, so QUIC-LB can't steer it. The
  connection then closes at the idle timeout instead of at once.
- `limit_req` and per-IP limits count per worker, so the effective limit is
  multiplied by the number of workers.
- Static files are read on the worker thread; fine for page-cached files,
  slow disks stall that worker.
- Upstream pools and health state are per worker, so health checks run once
  per worker per interval; the `routez_upstream_healthy` metric is the
  verdict of whichever worker probed last.
- After dropping root, a reload can't add a listener on a port below 1024
  or change `user`, and SIGUSR1 can't reopen a log file where `user` can't
  write: nothing keeps root to do those, unlike nginx's master process.
- TLS to upstreams: TLS 1.3 only, no session resumption (pooled keep-alive
  connections avoid most handshakes), no client certificates and no
  revocation checks. A literal `proxy_pass` target is always plain HTTP;
  declare an upstream to use TLS.
- macOS does not spread TCP connections across SO_REUSEPORT listeners, so
  extra workers only help on Linux.

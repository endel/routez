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
  single-page apps. Opened and read on I/O threads, so a slow disk stalls
  only the requests reading from it; what the page cache holds is served
  straight from the worker, with an open-file cache and, over plain HTTP,
  `sendfile`.
- Reverse proxy to HTTP/1.1 upstreams, plain or over TLS 1.3 (quic-zig's
  sans-IO `tls_client`, with optional certificate verification and client
  certificates): streaming
  in both directions with backpressure, keep-alive connection pools, retries
  of replayable requests, connect/read timeouts, WebSocket (Upgrade)
  tunnels, X-Forwarded-* headers.
- Load balancing: round robin, least connections, IP hash; passive failure
  tracking and active HTTP health checks.
- Layer-4 UDP proxy for QUIC traffic, with QUIC-LB connection-ID routing.
- Worker threads with SO_REUSEPORT. Graceful shutdown on SIGINT/SIGTERM:
  keep-alive connections close once idle, after the client has been sent
  every byte of its last response (queued output and `sendfile` ranges
  included); HTTP/3 connections get GOAWAY and finish their requests. All
  within a 10 s limit, after which what is left is closed.
- Reload on SIGHUP: new workers start on the new config beside the old ones,
  taking over their TCP listening sockets, and the old ones drain. A config
  that fails to load is rejected and the running one kept.
- Locations matched as nginx does: exact paths, longest prefix (optionally
  ending the search, like `^~`) and regular expressions, case-sensitive or
  not, on a linear-time engine, so no pattern can be turned into a ReDoS.
  Regex groups feed `proxy_pass` URIs, redirects and header values.
- `rewrite` rules at server and location level with nginx's flags (`last`,
  `break`, `redirect`, `permanent`) and query-string handling.
- Compression: precompressed `.br`, `.zst` and `.gz` files served in place
  of the original (nginx `gzip_static`), chosen by the client's
  `Accept-Encoding` q-values, and on-the-fly gzip for text-like responses.
- Per location: `add_headers`, `proxy_set_headers` (set, replace, remove,
  override Host) and `limit_req` (per-client token bucket, optionally a
  named zone shared by locations).
- Redirects and header values built from the request with nginx-style
  variables (`$host`, `$request_uri`, ...).
- Access control: IP allow/deny rules, Basic auth against htpasswd files
  (bcrypt checked off the event loop), and client certificates (mutual TLS)
  over TLS and HTTP/3, with the client's identity in variables.
- Trusted proxies: behind a load balancer, the client's address comes from
  `X-Forwarded-For` (nginx's `real_ip_from`) or the PROXY protocol (v1 and
  v2), for IP rules, limits, variables and logs alike.
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
  `stub_status`, `metrics` or `webtransport_pass`, and matches by `prefix`,
  `exact` or `regex` (see [Locations](#locations)).
- `proxy_pass` may name a URI after the upstream, as in nginx:
  `.{ .prefix = "/api/", .proxy_pass = "backend/v2/" }` sends `/api/x` as
  `/v2/x`; `strip_prefix = true` is the same as `"backend/"`. A URI with
  variables replaces the whole path and query:
  `.{ .regex = "^/u/(\\d+)$", .proxy_pass = "backend/users?id=$1" }`.
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
  `tls_client_cert` and `tls_client_key` give a certificate to present when
  the upstream asks for one (mutual TLS), in health checks too, and to
  WebTransport (QUIC) upstreams; the key may be EC P-256, Ed25519 or RSA.
  Both are read at start and on every reload, and `-t` checks that the key
  belongs to the certificate.

  ```zig
  .{ .name = "api", .servers = .{"10.0.0.7:443"}, .tls = true,
     .tls_verify = true, .tls_server_name = "api.internal.example",
     .tls_client_cert = "/etc/routez/api-client.pem", .tls_client_key = "/etc/routez/api-client.key" },
  ```
- `root` follows nginx semantics: the full request path is appended.
- `try_files = .{ "$uri", "$uri/", "/index.html" }` on a `root` location
  serves the first entry that is a file: `$uri` is the request path, an
  entry ending in `/` means that directory's `index`. The last entry is the
  fallback, served for any path, or a status such as `"=404"`. Unlike
  nginx, the fallback is a file under the same `root`, not a new request
  routed through the locations.
- Static files are opened, stat-ed and read on `file_io_threads` threads (4
  by default, shared by all workers; a change takes a restart), with at
  most one 32 KiB read out per response, paced by the client. Where the
  kernel can tell the data is cached, the worker skips the round trip:
  lookups on Linux (`openat2` with `RESOLVE_CACHED`), reads everywhere
  (`RWF_NOWAIT`, or `mincore` on filesystems without it, such as overlayfs).
  When 1024 new lookups are already waiting for a thread, further requests
  get 503.
- Each worker keeps what its lookups found, like nginx's `open_file_cache`
  with `open_file_cache_errors on`: open descriptors with their size, mtime
  and inode, and paths that don't exist or are directories. `try_files`
  entries and precompressed variants are cached the same way. On by
  default:

  ```zig
  .open_file_cache = .{ .max = 1000, .valid_ms = 1000, .inactive_ms = 60_000 },
  ```

  An entry is used for `valid_ms`; after that the path is opened and
  stat-ed again, and a file replaced (renamed over), created or deleted
  shows. `max` counts entries per worker (0 turns the cache off) and is
  lowered at start, with a log line, so that all workers' cached
  descriptors stay within a quarter of `RLIMIT_NOFILE`. Entries unused for
  `inactive_ms` are closed. A reload starts with empty caches. Within
  `valid_ms`, a file edited in place is served with its old length and
  ETag: truncated, its response is cut short (the connection closes); grown,
  the extra bytes are left out.
- Over plain HTTP/1.1, a static body over 32 KiB that isn't compressed on
  the fly goes out with `sendfile`, range by range as the socket takes it,
  for the parts the page cache holds; the rest is read on an I/O thread as
  over TLS and HTTP/3 (sendfile reads the file on the calling thread, so a
  cold page would stall the worker). Where the filesystem can't sendfile,
  the socket falls back to reading the cached range itself.
- Servers sharing a listen address are virtual hosts, chosen by `Host`
  (exact name, then one-label wildcard, then the first server).
- TLS keys may be EC P-256, Ed25519 or RSA (2048 to 4096 bits). TLS 1.2 is
  not supported. A key that doesn't belong to the first certificate of its
  `cert` file fails the load.

### Locations

```zig
.locations = .{
    .{ .prefix = "/", .root = "/var/www" },
    .{ .exact = "/health", .@"return" = .{ .body = "ok\n" } },            // nginx `=`
    .{ .prefix = "/static/", .no_regex = true, .root = "/var/www" },     // nginx `^~`
    .{ .regex = "\\.(png|jpe?g|gif)$", .case_insensitive = true,         // nginx `~*`
       .root = "/var/www", .add_headers = .{.{ .name = "cache-control", .value = "max-age=86400" }} },
    .{ .regex = "^/users/(\\d+)/avatar$", .proxy_pass = "backend/avatars/$1" },  // nginx `~`
},
```

A location matches the path after percent-decoding and resolving dot
segments, in nginx's order:

1. An `exact` location equal to the path wins.
2. Otherwise the longest matching `prefix` is remembered; if it has
   `no_regex`, it wins.
3. Otherwise the `regex` locations are tried in config order, and the
   first that finds a match wins.
4. Otherwise the remembered prefix wins, or the request gets a 404.

A regex matches anywhere in the path unless anchored with `^`/`$`. Its
groups are `$1`..`$9` (`$0` the whole match) in `return.location`,
`add_headers`, `proxy_set_headers` and `proxy_pass` URIs, percent-encoded
like `$uri`. Case-insensitive matching folds ASCII letters only.

Regular expressions are a PCRE subset, matched without backtracking in time
proportional to pattern size × path length: literals, `.`, classes
(`[a-z_]`, `[^/]`, `\d \w \s \D \W \S`), anchors `^ $`, word boundaries
`\b \B`, groups `( )` and `(?: )`, `|`, greedy and lazy `* + ? {n} {n,}
{n,m}`, and the escapes `\t \n \r \f \v \xHH` and `\.`-style punctuation.
Backreferences, lookahead and lookbehind, named groups, inline flags such as
`(?i)`, atomic groups and possessive quantifiers fail the config check with
the reason and offset. A pattern is at most 1024 bytes and compiles to at
most 1000 instructions (so `x{1,1000}` fits only for a small `x`); only the
first nine groups are captured.

### Rewrites

```zig
.{
    .listen = .{.{ .port = 80 }},
    // Before a location is chosen.
    .rewrite = .{.{ .regex = "^/blog/(\\d+)/(.*)$", .replacement = "/posts/$2?year=$1", .flag = .last }},
    .locations = .{
        .{ .prefix = "/posts/", .proxy_pass = "backend" },
        .{ .prefix = "/old/", .@"return" = .{ .status = 404 }, .rewrite = .{
            .{ .regex = "^/old/docs/(.*)$", .replacement = "https://docs.example.com/$1", .flag = .permanent },
            .{ .regex = "^/old/(.*)$", .replacement = "/$1", .flag = .last },
        } },
    },
}
```

Each rule whose `regex` finds a match in the path replaces the URI with
`replacement`, in which the rule's groups are `$1`..`$9` and other
variables work too. The flag says what happens next, as in nginx:

- none: go on with the next rule; if the URI changed, the locations are
  matched again after the last one.
- `.last`: stop, and match the locations again with the new URI.
- `.@"break"`: stop, and carry on in the current location with the new URI.
- `.redirect` / `.permanent`: answer 302 / 301 with the new URI as
  `Location`. A replacement starting with `http://`, `https://` or
  `$scheme` redirects (302) whatever the flag.

Server rules run once, before a location is chosen (`last` and `break`
both just end them); a location's run when it is chosen, before access
checks, limits and its handler. The query string is appended to the new
URI, after a `&` if the replacement has a query of its own; a replacement
ending in `?` drops it. `$request_uri` stays what the client sent, while
`$uri`, `$args` and the path a proxied request or file lookup uses are the
rewritten ones. A proxied request sends the rewritten path in full,
ignoring the `proxy_pass` URI unless that has variables, as nginx does. A
request whose URI changes more than 10 times gets a 500. Rewrites don't
apply to WebTransport CONNECTs.

### Compression

```zig
.{ .prefix = "/assets/", .root = "/var/www", .precompressed = .{ .br, .zstd, .gzip }, .gzip = true },
```

`precompressed` serves `app.js.br`, `app.js.zst` or `app.js.gz` for a
request for `app.js`, when that file exists as a regular file beside it and
the client's `Accept-Encoding` takes the coding. Among the codings it
takes, the highest q-value wins and equal ones go by the list's order. A
coding below an explicit `identity` q-value is passed over, `*` stands for
codings the header doesn't name, and an entry with a malformed q-value is
ignored. With no acceptable variant the original is served, even to a
client that sent `identity;q=0`.

The variant is its own representation: `Content-Encoding` names the
coding, `Content-Type` comes from the original's name, and `Content-Length`,
`Last-Modified` and the ETag come from the compressed file, whose ETag also
ends in the coding (`"…-br"`) so it never matches the original's. `Range`
requests count bytes of the compressed file, as in nginx; `If-None-Match`,
`If-Modified-Since`, `If-Range` and HEAD work on it as on any file.
Precompress at build time, for example `brotli -k -q 11 app.js`,
`zstd -k -19 app.js`, `gzip -k -9 app.js`, and keep each variant in step
with its original: routez doesn't compare them.

A variant counts as the file, so it's served even when the original is
missing; a client that doesn't take it gets a 404. With `try_files`, an
entry matches if its file exists or has a variant the client takes, so for
such a client a lone `.gz` stops the fallback.

`gzip = true` compresses text-like responses (`text/*`, JSON, JavaScript,
XML, SVG, wasm) not known to be under 1 KiB, for clients that take gzip, up
to 64 at once per worker; beyond that, responses go uncompressed. It leaves
alone responses that already have a `Content-Encoding` (such as a
precompressed file or an upstream's), 206 partial responses, and responses
marked `Cache-Control: no-transform`. The compressed response gets a weak
ETag and no `Content-Length`; a HEAD request gets the same headers.

Every response that could be encoded differently for another client,
compressed or not, carries `Vary: Accept-Encoding` (a static file's 304s
too), so caches keep the variants apart. In a `precompressed` location
that is any response for a path with a variant beside it, taken or not and
whatever the type, including the 404 for a path whose only file is a
variant the client doesn't take.

### Client limits

```zig
.{
    .limits = .{ .max_connections_per_ip = 100 },
    .servers = .{.{ .listen = ..., .locations = .{
        .{ .prefix = "/login", .proxy_pass = "backend", .limit_req = .{ .rate = 2, .burst = 5 } },
        .{ .prefix = "/api/", .proxy_pass = "backend", .limit_req = .{ .zone = "api", .rate = 50, .burst = 100 } },
        .{ .prefix = "/v2/", .proxy_pass = "backend", .limit_req = .{ .zone = "api", .rate = 50 } },
    } }},
}
```

- `limit_req` allows each client address `rate` requests per second, and
  `burst` more at once; the rest get 429 with `Retry-After: 1`. It applies
  to HTTP/1.1, HTTPS and HTTP/3 alike. Locations naming the same `zone`
  share each client's bucket (they must agree on `rate`; each has its own
  `burst`); a location without one has its own.
- `limits.max_connections_per_ip` caps the TCP connections (HTTP and TLS)
  one address holds; more are closed at accept. A `real_ip_from` proxy
  isn't counted, and on a `proxy_protocol` listener the client its header
  names is (see [Trusted proxies](#trusted-proxies)).
- Both count across all workers, and across a reload: buckets carry over
  (a zone by name, an unnamed one by server name, listen address and
  prefix), and connections accepted by the old workers count until they
  close.
- The counts live in a table of `limits.max_tracked_clients` entries
  (100 000 by default, about 32 bytes each): one per address holding
  connections, one per address and zone being limited. Entries are dropped
  once a bucket has refilled or the last connection closes. When the table
  is full of live entries, new clients go unlimited, with a warning at most
  once a minute and the `routez_limit_table_untracked_total` counter,
  rather than being refused: refusing would let anyone with enough
  addresses lock out every new client, and those addresses already let
  them sidestep per-address limits.
- `limits.max_connections` (10 000) counts **per worker**, so a four-worker
  server holds up to 40 000 TCP connections; connections over the cap are
  closed right after accept, counted by
  `routez_connections_refused_max_connections_total`, and logged once per
  worker. Long-lived connections (WebSocket tunnels, SSE) make it the limit
  that bites first: raise it for them. It is lowered at startup to fit
  `RLIMIT_NOFILE`, which every worker's clients and their upstream
  connections share, with a warning saying so.

### Access control

```zig
.{ .servers = .{.{
    .listen = .{ .{ .port = 443, .tls = true, .quic = true } },
    .tls = .{ .cert = "fullchain.pem", .key = "privkey.pem",
              .client_ca = "clients-ca.pem", .client_verify = .optional },
    // Every location without rules of its own.
    .access = .{ .{ .allow = "10.0.0.0/8" }, .{ .allow = "2001:db8::/32" }, .{ .deny = "all" } },
    .locations = .{
        .{ .prefix = "/", .root = "/var/www" },
        .{ .prefix = "/public/", .root = "/var/www", .access = .{.{ .allow = "all" }} },
        .{ .prefix = "/admin/", .proxy_pass = "backend",
           .auth_basic = .{ .realm = "Admin", .user_file = "/etc/routez/htpasswd" },
           .proxy_set_headers = .{.{ .name = "x-user", .value = "$remote_user" }} },
        .{ .prefix = "/internal/", .proxy_pass = "backend", .require_client_cert = true,
           .proxy_set_headers = .{
               .{ .name = "x-client-dn", .value = "$ssl_client_s_dn" },
               .{ .name = "x-client-verify", .value = "$ssl_client_verify" },
           } },
    },
}} }
```

Checks run in this order, after `limit_req`: IP rules (403), client
certificate (421, 403), Basic auth (401). They apply to HTTP/1.1, HTTPS,
HTTP/3 and WebTransport CONNECTs alike.

- **IP rules**: `.allow`/`.deny` with `all`, an address or a CIDR network,
  IPv4 or IPv6; the first rule matching the client decides, and a client
  none matches is allowed (as in nginx). A location's `access` replaces its
  server's. IPv4 rules also match IPv4-mapped IPv6 peers. The client is the
  TCP or QUIC peer, or the one a trusted proxy names (see
  [Trusted proxies](#trusted-proxies)).
- **Basic auth**: `auth_basic` answers 401 with
  `WWW-Authenticate: Basic realm="..."` until the credentials match the
  htpasswd file. Entries may be bcrypt (`htpasswd -B`; cost 4 to 16) or
  `{SHA}` (`htpasswd -s`; unsalted SHA-1, accepted with a warning). apr1
  MD5, crypt(3) and plain-text entries are refused at load with the line
  named, as is a missing file; `-t` checks the files, and a reload rereads
  them. The `Authorization` header is passed upstream, as nginx does;
  remove it with `.proxy_set_headers = .{.{ .name = "authorization", .value = "" }}`.
  `$remote_user` holds the user, for headers and the access log (`combined`
  logs it).
  bcrypt costs tens to hundreds of milliseconds, so checks run on a few
  verifier threads, never on a worker. A correct password is cached for
  five minutes (an HMAC of the stored hash, user and password; changing the
  password invalidates it), so a browser sending it with every request
  costs one check. Each client may start 5 uncached checks per second
  (burst 10, across workers) before getting 429, and at most 128 wait for a
  thread before requests get 503. An unknown user is checked against
  another entry's hash, so it takes as long as a wrong password.
- **Client certificates**: `tls.client_ca` makes the server ask TLS and
  QUIC clients reaching it by SNI for a certificate, verified against that
  CA bundle (chain, validity, and the clientAuth usage when present). With
  `client_verify = .required` (the default) a client without a valid one
  fails the handshake (`certificate_required`, `unknown_ca`, ...); with
  `.optional` it gets in, `require_client_cert = true` on a location answers
  403, and the variables say `NONE`. A certificate that fails to verify
  fails the handshake either way. Several servers can share a port, each
  with its own CA or none; a request whose `Host` names a server with a
  `client_ca` other than the one its handshake ran under (SNI one name,
  Host another) gets 421. Session tickets are neither issued nor accepted
  for such a server, so a resumed session can never skip the certificate.
  `client_verify` means nothing on a plain-HTTP listener: don't serve the
  same locations there, or mark them `require_client_cert`.

### Trusted proxies

Behind a load balancer every client is the balancer, unless routez is told
which proxies to believe:

```zig
.{
    .real_ip_from = .{ "10.0.0.0/8", "2001:db8::/32" },
    .real_ip_header = "x-forwarded-for", // the default; null for the PROXY protocol alone
    .real_ip_recursive = true,           // for a chain of proxies
    .servers = .{.{
        .listen = .{
            .{ .port = 80 },
            // Behind an L4 balancer: HAProxy's send-proxy, AWS NLB, ...
            .{ .port = 443, .tls = true, .proxy_protocol = true },
        },
        ...
    }},
}
```

- **Header**: a request from a `real_ip_from` peer takes its client from
  `real_ip_header`, a comma-separated list of addresses (ports allowed,
  several header lines read as one list). Without `real_ip_recursive` the
  rightmost address is the client; with it, the rightmost that isn't itself
  in `real_ip_from` (the leftmost if they all are), so
  `X-Forwarded-For: client, proxy1` from `proxy2` names `client` when
  `proxy1` is trusted. From any other peer the header means nothing. An
  address in the walk that doesn't parse leaves the peer as the client, as
  in nginx.
- **PROXY protocol**: on a TCP listener with `proxy_protocol = true`, every
  connection opens with a v1 or v2 header, ahead of TLS, and the client it
  names is the connection's for its lifetime. Only `real_ip_from` peers may
  connect; others are closed at accept. So is a connection whose header is
  malformed (a v1 line over 107 bytes, a v2 header over 4 KiB, anything the
  spec doesn't allow) or hasn't arrived within `limits.header_timeout_ms`;
  `routez_connections_refused_proxy_protocol_total` counts them. `LOCAL`
  connections (the balancer's health checks), `UNKNOWN` and UNIX-socket
  sources keep the peer's address; TLVs are skipped. If the client the
  header names is itself in `real_ip_from`, its `X-Forwarded-For` counts.
- **Where it applies**: IP rules, `limit_req`, `auth_basic`'s per-client
  rate limit, `ip_hash`, `$remote_addr`, access logs and the `X-Real-IP`
  sent upstream all see the real client, over HTTP/1.1, HTTPS, HTTP/3 and
  WebTransport CONNECTs. `$realip_remote_addr` is the TCP or QUIC peer.
  `X-Forwarded-For` upstream gets the address the request came from
  appended (the peer, or the PROXY protocol's client), so the list stays
  one entry per hop.
- `max_connections_per_ip` is decided at accept, before any header: a
  `real_ip_from` peer isn't counted, and on a `proxy_protocol` listener the
  client the header names is counted instead. Clients a proxy names in a
  header are bound by `limit_req` and `max_connections` only.
- These settings are global, not per server: the PROXY header is read
  before SNI or `Host` has chosen a server.

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
  (`$http_user_agent`); see `src/access_log.zig`. Over HTTP/1.1, as in
  nginx, a request is logged once its response has been handed to the
  kernel, and `$body_bytes_sent` counts only what was: a client that drops
  the connection before then is logged with the bytes it got and no
  `$request_completion`. Values are escaped as
  nginx does (`\xHH`), or for JSON with `.access_log_escape = .json`; the
  `json` preset always is. Times are in UTC. `main`, the default, is
  `client "GET /path HTTP/1.1" status bytes time host= upstream=`.
- `.metrics = true` on a location serves the Prometheus text format:
  connections accepted and open (TCP and QUIC), requests by protocol,
  responses by protocol and status class, body bytes in and out, per
  upstream server requests, failures and health-check state, reloads,
  QUIC datagrams steered between workers, workers, start time and version,
  connections and requests refused by the client limits and the occupancy
  of their table, and connections refused on PROXY protocol listeners.
  Counters are process-wide and survive reloads. Restrict it like any
  location, for instance on a listener bound to a private address.

### Redirects and variables

`return` takes a `location` for redirects, and it, `add_headers` and
`proxy_set_headers` values and `proxy_pass` URIs may use variables, written
`$name` or `${name}`:

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
| `$uri` | normalized path (dot segments resolved), percent-encoded; after a rewrite, the new one |
| `$args`, `$is_args` | query string without the `?`; `?` if there is one |
| `$remote_addr` | client IP: the one a trusted proxy names, else the TCP or QUIC peer |
| `$realip_remote_addr` | the TCP or QUIC peer, whoever it names |
| `$remote_user` | the user `auth_basic` let in |
| `$ssl_client_verify` | `SUCCESS` for a verified client certificate, else `NONE` |
| `$ssl_client_s_dn`, `$ssl_client_i_dn` | its subject and issuer, RFC 4514 (`CN=alice,O=Example`) |
| `$ssl_client_serial` | its serial number, hex |
| `$ssl_client_fingerprint` | SHA-1 of the certificate, hex |
| `$1`..`$9`, `$0` | groups of the last regex that matched (a rewrite's or the location's), and its whole match, percent-encoded |

Pass certificate details upstream with `proxy_set_headers`: it replaces
any header the client sent under the same name (and an empty value removes
it), so a client can't forge them.

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
zig build regex-diff && tests/regex/differential.py   # regex engine against Python's re
```

The regex differential test compares every group's span on a few thousand
random patterns and inputs; where Python's `re` differs from PCRE (around
repeated groups that can match empty) it asks PCRE2's `pcre2test`, if
installed. `zig build fuzz` runs the fuzz targets, regex compilation and
matching among them.

The end-to-end script needs python3, bun, node >= 22, curl, and a built
`../quic-zig` (its WebTransport echo server is the relay's upstream). The
HTTP/3 checks need a curl built with HTTP/3: Homebrew's on macOS; on Linux,
without one, the script fetches a pinned static build (stunnel/static-curl,
checksummed) into `~/.cache/routez-e2e`. Set `CURL_BIN` to use another.
It builds routez with `-Dfault-injection`, a test-only option under which
files named `*slow-read*` read as if from a stalled disk, and requests naming
`small-sndbuf` get a 16 KiB socket send buffer. The ACME script needs
Docker, python3, curl and openssl; it runs Pebble, Let's Encrypt's test CA, with real HTTP-01
validation against routez.

## Performance

```sh
bench/run.sh    # routez, nginx and HAProxy in a Linux container (needs Docker)
```

It builds routez, starts all three beside a shared upstream, and runs wrk
against one server at a time. The table and every run land in
`bench/results/<timestamp>/`. Knobs: `WORKERS` (3), `CONNS` (256),
`DURATION` (10 s), `ROUNDS` (3), `WORKLOADS` (a subset of rows).

Docker Desktop on an Apple M-series Mac (10 cores), 19 Sep 2026: routez
58ed54b, nginx 1.30.5 and HAProxy 3.2.23 on OpenSSL 3.5, 3 workers each, with
the server, wrk and upstream on separate cores. Median of 3 × 10 s runs,
keep-alive, in requests per second. Relative numbers only; a VM is not a
benchmark machine.

| Workload | nginx | HAProxy | routez |
|---|---|---|---|
| Fixed response (`return`) | 579k | 400k | 684k |
| 10 KB static file | 236k | — | 334k |
| Reverse proxy to a keep-alive upstream | 207k | 167k | 239k |
| TLS: fixed response | 347k | 255k | 507k |
| TLS: 10 KB static file | 125k | — | 189k |
| TLS: new connection per request | 11k | 8.3k | 14k |

- HAProxy isn't a file server.
- TLS is 1.3 with AES-128-GCM and X25519 everywhere, routez's own choice;
  nginx and HAProxy are pinned to it.
- The last row measures resumed handshakes: wrk reuses the session on each
  new connection. wrk is also at its limit there, so read it as an ordering.

### WebSocket connections

```sh
bench/run.sh ws   # concurrent WebSocket tunnels, one worker per server
```

Each server runs as a single process with one worker and proxies WebSocket
over HTTP/1.1 to a Node.js app built on `ws` (an echo server). The Node app
with no proxy in front is the baseline. The client opens the connections,
holds them idle, then sends a fixed total of echoes spread over all of them.
Results land in `bench/results/ws-<timestamp>/`. Knobs: `LEVELS`
(1000 10000 50000), `RATE` (10000 echoes/s in total), `HOLD` (5 s),
`DURATION` (10 s), `ROUNDS` (3), `CLIENTS`, `SERVERS`.

Same machine, 20 Sep 2026: Node.js 22.22 and `ws` 8.21; the server, the app
and the client are pinned to separate cores. One round per level.

**Memory per open connection** (lower is better). This is the server's RSS
growth over its idle baseline, divided by the number of connections. It
barely moves between rounds.

| Open connections | nginx | HAProxy | routez |
|---|---|---|---|
| 1,000 | 16.8 KB | 11.3 KB | 6.4 KB |
| 10,000 | 18.0 KB | 5.3 KB | 5.3 KB |
| 50,000 | 17.8 KB | 4.8 KB | 5.3 KB |

**Echo latency, p99** (lower is better). 10,000 messages per second in
total, spread over all open connections. "No proxy" is the client talking
to the app directly.

| Open connections | No proxy | nginx | HAProxy | routez |
|---|---|---|---|---|
| 1,000 | 5 ms | 5 ms | 7 ms | 5 ms |
| 10,000 | 10 ms | 17 ms | 26 ms | 12 ms |
| 50,000 | 89 ms | 53 ms | 75 ms | 68 ms |

- The p99 is noisy from round to round, above all at 50k connections. The
  p50 stayed under 1.6 ms everywhere.
- On Linux, sockets share one read buffer per worker instead of holding
  16 KiB each; without that, routez held 21 KB per connection here.
- The 1,000-connection row includes each server's fixed startup cost, which
  is why it is higher for everyone.
- One Node process can't absorb much more. At 1 message per second per
  connection it saturates near 25k connections, so the load is a fixed
  total rather than a rate per connection.

## Limitations

- ACME: HTTP-01 only, so no wildcard names (they need DNS-01) and port 80
  must be reachable from the internet. No certificate revocation, ARI or
  external account binding. Every change of certificate reloads all workers.
- Let's Encrypt rate-limits issuance (for example 5 certificates per exact
  set of names per week, and failed validations per hour); test against
  the staging directory before production.

- HTTP/3 requests are logged when their response is produced, not when
  the client has acknowledged it: a stream reset or lost connection after
  that isn't reflected in `$body_bytes_sent` or `$request_completion`.
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
- `max_connections_per_ip` counts TCP connections only. A QUIC connection's
  address isn't validated when it is accepted (a spoofed Initial would
  count against someone else's) and changes when the client migrates;
  `max_connections` and `limit_req` bound QUIC clients instead.
- A disk that stalls for good ties up an I/O thread per request reading
  from it; once all are taken, other static requests wait too (proxied
  ones don't). On macOS a lookup the open-file cache can't answer (a path's
  first request, or its first after `valid_ms`) takes a round trip to an
  I/O thread: nothing there can tell that an open won't wait.
- `sendfile` is used for plain HTTP/1.1 only: TLS and HTTP/3 encrypt in
  userspace, and bodies compressed on the fly are made there.
- Compression on the fly is gzip only: Zig's standard library has no
  Brotli or zstd encoder, and a small one written here would compress worse
  than gzip. Precompress with `brotli` or `zstd` at build time and serve the
  files with `precompressed` instead.
- Upstream pools and health state are per worker, so health checks run once
  per worker per interval; the `routez_upstream_healthy` metric is the
  verdict of whichever worker probed last.
- After dropping root, a reload can't add a listener on a port below 1024
  or change `user`, and SIGUSR1 can't reopen a log file where `user` can't
  write: nothing keeps root to do those, unlike nginx's master process.
- TLS to upstreams: TLS 1.3 only, no session resumption (pooled keep-alive
  connections avoid most handshakes) and no revocation checks.
- Client certificates: no revocation checks (CRL, OCSP) and no
  post-handshake authentication, so a location can't ask for a certificate
  the handshake didn't; a server's `client_ca` applies to its whole name.
  Connections to a `client_ca` server are never resumed from a ticket.
- The PROXY protocol is read on TCP listeners only: not by QUIC on the same
  port or by the UDP proxy, and routez doesn't send it to upstreams.
- A literal `proxy_pass` target is always plain HTTP; declare an upstream
  to use TLS.
- Regular expressions lack backreferences, lookaround, named groups,
  inline flags, Unicode classes and POSIX classes (`[[:alpha:]]`); they
  match bytes, and case-insensitive matching is ASCII only.
- macOS does not spread TCP connections across SO_REUSEPORT listeners, so
  extra workers only help on Linux.

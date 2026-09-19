//! Server configuration, loaded from a ZON file.
//!
//! ```zig
//! .{
//!     .workers = 1,
//!     .servers = .{.{
//!         .listen = .{.{ .port = 8443, .tls = true, .quic = true }},
//!         .server_names = .{"example.com"},
//!         .tls = .{ .cert = "fullchain.pem", .key = "key.pem" },
//!         .locations = .{
//!             .{ .prefix = "/static/", .root = "/var/www" },
//!             .{ .prefix = "/", .proxy_pass = "backend" },
//!         },
//!     }},
//!     .upstreams = .{.{ .name = "backend", .servers = .{"127.0.0.1:8080"} }},
//! }
//! ```
const std = @import("std");
const vars = @import("http/vars.zig");
const access_log = @import("access_log.zig");
const access = @import("access.zig");
const regex = @import("regex.zig");
const encoding = @import("encoding.zig");

pub const Config = struct {
    /// Worker threads, each with its own event loop and SO_REUSEPORT sockets.
    workers: u16 = 1,
    /// Threads that open, stat and read static files for all workers, so a
    /// slow disk stalls only the requests reading from it. Read at start;
    /// a reload doesn't change it.
    file_io_threads: u16 = 4,
    servers: []const Server = &.{},
    upstreams: []const Upstream = &.{},
    /// Layer-4 UDP forwarding, for QUIC traffic we don't terminate.
    udp_proxies: []const UdpProxy = &.{},
    limits: Limits = .{},
    /// Write one line per completed request.
    access_log: bool = true,
    /// File the access log goes to, opened for appending; stderr when null.
    /// Reopened on SIGUSR1, for log rotation.
    access_log_path: ?[]const u8 = null,
    /// `"main"` (the default line), `"combined"` (nginx's), `"json"` (one
    /// object per line), or a template of `$variables`; see `access_log.zig`.
    access_log_format: []const u8 = "main",
    /// How a template escapes variable values: `.default` writes `"`, `\`
    /// and control bytes as `\xHH`, `.json` escapes for a JSON string.
    access_log_escape: LogEscape = .default,
    /// File for everything else the server logs (stderr is redirected to
    /// it); stderr when null. Reopened on SIGUSR1.
    error_log: ?[]const u8 = null,
    /// Least severe messages logged: `.err`, `.warn`, `.info` or `.debug`.
    log_level: std.log.Level = .info,
    /// Run as this user (a name or a numeric id) once listeners are bound,
    /// so the server can start as root to bind ports below 1024. Log files
    /// are opened and ACME storage handed over before the switch.
    user: ?[]const u8 = null,
    /// Group to run as (a name or a numeric id); `user`'s primary group
    /// when null. Needs `user`.
    group: ?[]const u8 = null,
    /// Proxies trusted to name the client (load balancers, CDNs): addresses
    /// or CIDR networks, IPv4 or IPv6. A request from one of them takes its
    /// client from `real_ip_header`, and only they may connect to a
    /// `proxy_protocol` listener. Global because the PROXY protocol is read
    /// before a server is chosen.
    real_ip_from: []const []const u8 = &.{},
    /// Header a `real_ip_from` peer names the client in: a comma-separated
    /// list of addresses, ports allowed. The rightmost address is the
    /// client. Null ignores headers, for the PROXY protocol alone.
    real_ip_header: ?[]const u8 = "x-forwarded-for",
    /// Take the rightmost address in `real_ip_header` that isn't itself in
    /// `real_ip_from` (the leftmost when all are), for a chain of proxies.
    real_ip_recursive: bool = false,
};

pub const LogEscape = enum { default, json };

pub const Limits = struct {
    /// Largest request or response head (request line + headers) accepted.
    max_header_bytes: u32 = 16 * 1024,
    max_headers: u16 = 100,
    /// Request bodies above this are refused with 413. 0 disables the check.
    max_body_bytes: u64 = 64 * 1024 * 1024,
    /// Idle time allowed between requests on a keep-alive connection.
    keepalive_timeout_ms: u32 = 75_000,
    /// Time allowed to receive a complete request head.
    header_timeout_ms: u32 = 30_000,
    /// Time a connection may go without any socket progress mid-request.
    io_timeout_ms: u32 = 60_000,
    /// Silence after which a QUIC connection closes (RFC 9000 §10.1); the
    /// shorter of this and the client's value applies. Raise it for clients
    /// that ride out long outages; a vanished peer then holds its slot longer.
    quic_idle_timeout_ms: u32 = 30_000,
    max_connections: u32 = 10_000,
    /// TCP connections one client address may hold, across all workers.
    /// 0 disables it.
    max_connections_per_ip: u32 = 0,
    /// Entries in the table behind `max_connections_per_ip` and `limit_req`:
    /// one per client address for its connection count, and one per client
    /// address and zone for each request limit it is under. ~32 bytes each.
    /// When full, new clients go unlimited (and a warning is logged). Sized
    /// at start; a change takes effect at the next restart.
    max_tracked_clients: u32 = 100_000,
};

pub const Listen = struct {
    address: []const u8 = "0.0.0.0",
    port: u16,
    /// TLS 1.3 on the TCP listener. Requires `Server.tls`.
    tls: bool = false,
    /// Also serve HTTP/3 on the same UDP port. Requires `Server.tls`.
    quic: bool = false,
    /// Plain TCP listener disabled; only meaningful together with `quic`.
    tcp: bool = true,
    /// Connections start with a PROXY protocol header (v1 or v2, before
    /// TLS) naming the client. Only `real_ip_from` peers may connect; others
    /// are closed at once, as is one whose header is malformed or doesn't
    /// arrive within `limits.header_timeout_ms`. TCP only: QUIC on the same
    /// port doesn't use it.
    proxy_protocol: bool = false,
};

/// Either `cert` and `key`, or `acme`.
pub const Tls = struct {
    /// PEM certificate chain (leaf first).
    cert: ?[]const u8 = null,
    /// PEM private key: EC P-256, Ed25519, or RSA of 2048 to 4096 bits
    /// (PKCS#1 or PKCS#8). RSA signs with RSA-PSS.
    key: ?[]const u8 = null,
    /// Obtain and renew the certificate for `server_names` automatically.
    acme: ?Acme = null,
    /// PEM bundle of the CAs client certificates must chain to. Set, TLS and
    /// QUIC clients reaching this server by SNI are asked for a certificate
    /// (mutual TLS); see `client_verify`.
    client_ca: ?[]const u8 = null,
    /// `.required`: a client without a valid certificate fails the handshake.
    /// `.optional`: it gets in without one, and locations can insist with
    /// `require_client_cert`. A certificate that fails to verify fails the
    /// handshake either way.
    client_verify: ClientVerify = .required,
};

pub const ClientVerify = enum { required, optional };

/// One IP rule: `.{ .allow = "10.0.0.0/8" }`, `.{ .deny = "all" }`. The
/// value is `all`, an address, or a CIDR network, IPv4 or IPv6.
pub const AccessRule = union(enum) {
    allow: []const u8,
    deny: []const u8,

    pub fn action(self: AccessRule) access.Action {
        return switch (self) {
            .allow => .allow,
            .deny => .deny,
        };
    }

    pub fn text(self: AccessRule) []const u8 {
        return switch (self) {
            inline else => |t| t,
        };
    }
};

/// HTTP Basic authentication against an htpasswd file.
pub const AuthBasic = struct {
    /// Shown by the browser's login prompt.
    realm: []const u8 = "Restricted",
    /// htpasswd file with bcrypt (`htpasswd -B`) or `{SHA}` entries. Read
    /// at start and on every reload.
    user_file: []const u8,
};

/// Automatic certificates from an ACME CA (RFC 8555), validated with HTTP-01
/// on the plain-HTTP listeners.
pub const Acme = struct {
    /// Contact address given to the CA for expiry and policy notices.
    email: ?[]const u8 = null,
    /// Directory URL. Let's Encrypt staging is
    /// `https://acme-staging-v02.api.letsencrypt.org/directory`.
    directory: []const u8 = "https://acme-v02.api.letsencrypt.org/directory",
    /// Account key and certificates, kept per CA. Created with mode 0700.
    storage: []const u8 = "/var/lib/routez/acme",
    /// PEM bundle trusted for the directory's HTTPS instead of the system
    /// store; for test CAs such as Pebble.
    ca_file: ?[]const u8 = null,
    /// Renew when the certificate has fewer days than this left (or less
    /// than half its lifetime, for certificates shorter than twice this).
    renew_days: u16 = 30,
    /// How often stored certificates are checked for renewal.
    check_interval_s: u32 = 12 * 3600,
    /// Longest one attempt at a certificate may take, network waits
    /// included, before it is abandoned and retried later.
    order_timeout_s: u32 = 300,
};

pub const Server = struct {
    listen: []const Listen,
    /// Host names this server answers for; `*.example.com` matches one label.
    /// The first server on a listener is the default for unmatched hosts.
    server_names: []const []const u8 = &.{},
    tls: ?Tls = null,
    /// IP rules for every location that has none of its own; see
    /// `Location.access`.
    access: []const AccessRule = &.{},
    /// Applied to every request before a location is chosen. `last` and
    /// `break` both end the server's rules here.
    rewrite: []const Rewrite = &.{},
    locations: []const Location,
};

/// nginx's `rewrite`: when `regex` finds a match in the path, the request
/// URI becomes `replacement`. Rules run in order.
pub const Rewrite = struct {
    regex: []const u8,
    /// The new URI, with variables and the groups `$1`..`$9` (percent-encoded
    /// like `$uri`). Starting with `http://`, `https://` or `$scheme`, it
    /// is a redirect. The request's query string is appended unless the
    /// replacement ends with `?` (which is dropped); after a replacement
    /// that has a query of its own, it follows with `&`.
    replacement: []const u8,
    flag: Flag = .none,
    /// ASCII letters match either case.
    case_insensitive: bool = false,

    pub const Flag = enum {
        /// On to the next rule; if the URI changed, locations are matched
        /// again after the last one.
        none,
        /// Stop, and match the locations again with the new URI.
        last,
        /// Stop, and carry on in this location with the new URI.
        @"break",
        /// Answer 302 with the new URI.
        redirect,
        /// Answer 301 with the new URI.
        permanent,
    };

    /// The replacement is sent back to the client rather than served.
    pub fn redirects(self: *const Rewrite) bool {
        return self.flag == .redirect or self.flag == .permanent or isAbsolute(self.replacement);
    }

    fn isAbsolute(r: []const u8) bool {
        return std.mem.startsWith(u8, r, "http://") or std.mem.startsWith(u8, r, "https://") or
            std.mem.startsWith(u8, r, "$scheme") or std.mem.startsWith(u8, r, "${scheme}");
    }
};

/// A location matches the request path (decoded, dot segments resolved)
/// by exactly one of `prefix`, `exact` or `regex`, chosen as nginx does:
/// an `exact` match wins; else the longest `prefix` is remembered and wins
/// at once if it has `no_regex`; else the first `regex`, in config order,
/// that matches; else the remembered prefix.
pub const Location = struct {
    /// Matches paths starting with this.
    prefix: ?[]const u8 = null,
    /// With `prefix`: when this is the longest matching prefix, regexes
    /// aren't tried (nginx `^~`).
    no_regex: bool = false,
    /// Matches this path only (nginx `=`).
    exact: ?[]const u8 = null,
    /// Matches paths this regular expression finds a match in (nginx `~`);
    /// its groups are `$1`..`$9` for the location's variables. Syntax in
    /// `regex.zig`.
    regex: ?[]const u8 = null,
    /// With `regex`: ASCII letters match either case (nginx `~*`).
    case_insensitive: bool = false,

    /// Serve files from this directory.
    root: ?[]const u8 = null,
    /// File served for a request that names a directory.
    index: []const u8 = "index.html",
    /// Paths tried in order under `root`, nginx-style; the first regular
    /// file found is served. `$uri` stands for the request path, and an
    /// entry ending in `/` tries that directory's `index`. The last entry
    /// is the fallback: a file served whatever the path, or `=404` (any
    /// status). `.{ "$uri", "$uri/", "/index.html" }` serves a single-page app.
    try_files: []const []const u8 = &.{},

    /// Name of an upstream, or a literal `host:port`, optionally followed by
    /// a URI (`"backend/v2/"`), as in nginx: the part of the path the
    /// `prefix` or `exact` matched is replaced by it. A URI with variables
    /// (`"backend/img/$1"`, for a `regex` location) is the whole path and
    /// query sent upstream.
    proxy_pass: ?[]const u8 = null,
    /// Remove `prefix` (or `exact`) from the path before proxying (keeps a
    /// leading '/').
    strip_prefix: bool = false,

    /// Relay WebTransport sessions to this upstream (HTTP/3 only).
    webtransport_pass: ?[]const u8 = null,

    /// Answer with a fixed status and body, or redirect.
    @"return": ?Return = null,
    /// Rules applied once the location is chosen, before its handler; see
    /// `Rewrite`.
    rewrite: []const Rewrite = &.{},

    /// Request headers set on proxied requests, replacing any the client
    /// sent under the same name. An empty value removes the header; `host`
    /// overrides the Host sent upstream. Values may use variables (see
    /// `http/vars.zig`).
    proxy_set_headers: []const HeaderKV = &.{},
    /// Headers added to every response from this location. Values may use
    /// variables.
    add_headers: []const HeaderKV = &.{},
    /// Compress text-like responses with gzip for clients that accept it.
    /// Such responses carry `Vary: Accept-Encoding`, compressed or not.
    gzip: bool = false,
    /// With `root`: serve `file.br`, `file.zst` or `file.gz` in place of
    /// `file` when it exists and the client accepts that coding (nginx
    /// `gzip_static`/`brotli_static`). The client's q-values pick among
    /// them; equal ones go by this list's order. `.{ .br, .zstd, .gzip }`
    /// offers all three.
    precompressed: []const encoding.Coding = &.{},
    /// Per-client request rate limit, shared by all workers.
    limit_req: ?LimitReq = null,
    /// IP allow/deny rules, nginx-style: the first rule matching the client
    /// decides, and a client no rule matches is allowed; denied ones get 403.
    /// Replaces the server's `access` when not empty. The client is the TCP
    /// or QUIC peer, or the one a `real_ip_from` proxy names.
    access: []const AccessRule = &.{},
    /// Ask for a user and password (401 until they match).
    auth_basic: ?AuthBasic = null,
    /// 403 unless the client presented a certificate that verified against
    /// the server's `tls.client_ca`; for `client_verify = .optional`.
    require_client_cert: bool = false,

    /// Serve connection and request counters as plain text.
    stub_status: bool = false,
    /// Serve counters in the Prometheus text format.
    metrics: bool = false,

    pub const Match = enum { prefix, exact, regex };

    pub fn match(self: *const Location) Match {
        if (self.exact != null) return .exact;
        if (self.regex != null) return .regex;
        return .prefix;
    }

    /// The prefix, path or pattern, for messages.
    pub fn pattern(self: *const Location) []const u8 {
        return self.prefix orelse self.exact orelse self.regex orelse "";
    }

    pub const LimitReq = struct {
        /// Sustained requests per second.
        rate: u32,
        /// Extra requests allowed in a burst above the rate.
        burst: u32 = 0,
        /// Locations naming the same zone share each client's bucket; they
        /// must agree on `rate`, and each applies its own `burst`. Without
        /// one, the location has a bucket of its own.
        zone: ?[]const u8 = null,
    };

    pub const Return = struct {
        status: u16 = 200,
        body: []const u8 = "",
        content_type: []const u8 = "text/plain; charset=utf-8",
        /// `Location` header, with variables: `"https://$host$request_uri"`.
        location: ?[]const u8 = null,
    };
};

pub const HeaderKV = struct { name: []const u8, value: []const u8 };

pub const ProxyPass = struct { target: []const u8, uri: ?[]const u8 };

/// `proxy_pass` split into its upstream (or `host:port`) and URI.
pub fn splitProxyPass(text: []const u8) ProxyPass {
    const from: usize = if (std.mem.startsWith(u8, text, "http://")) "http://".len else 0;
    const slash = std.mem.indexOfScalarPos(u8, text, from, '/') orelse return .{ .target = text, .uri = null };
    return .{ .target = text[0..slash], .uri = text[slash..] };
}

pub const Upstream = struct {
    name: []const u8,
    /// `host:port` entries.
    servers: []const []const u8,
    balance: Balance = .round_robin,
    /// Idle keep-alive connections kept per server, per worker.
    keepalive: u16 = 32,
    /// Consecutive failures that mark a server down.
    max_fails: u16 = 3,
    /// How long a server stays down before being tried again.
    fail_timeout_ms: u32 = 10_000,
    connect_timeout_ms: u32 = 5_000,
    /// Time allowed between upstream reads while waiting for a response.
    read_timeout_ms: u32 = 60_000,
    /// Upstream speaks HTTP/3 (QUIC) instead of HTTP/1.1. Used for WebTransport relays.
    h3: bool = false,
    /// Upstream speaks HTTPS: HTTP/1.1 over TLS 1.3.
    tls: bool = false,
    /// For TLS and QUIC upstreams: verify the certificate against the system
    /// store (or `tls_ca`). Off by default, like nginx's `proxy_ssl_verify`,
    /// for self-signed internal backends.
    tls_verify: bool = false,
    /// PEM CA bundle for verifying TLS and QUIC upstreams; implies `tls_verify`.
    tls_ca: ?[]const u8 = null,
    /// Name sent as SNI and matched against the certificate, for TLS and
    /// QUIC upstreams. Defaults to each server's host; an IP address is
    /// matched against the certificate's IP addresses and not sent as SNI.
    tls_server_name: ?[]const u8 = null,
    /// PEM certificate chain (leaf first) presented to TLS and QUIC
    /// upstreams that ask for a client certificate, health checks included.
    /// Needs `tls_client_key`. Read at start and on every reload.
    tls_client_cert: ?[]const u8 = null,
    /// Its private key: EC P-256, Ed25519, or RSA of 2048 to 4096 bits.
    tls_client_key: ?[]const u8 = null,
    health: ?Health = null,

    pub const Balance = enum { round_robin, least_conn, ip_hash };

    pub const Health = struct {
        path: []const u8 = "/",
        interval_ms: u32 = 5_000,
        timeout_ms: u32 = 2_000,
        /// Successes needed to bring a down server back.
        rise: u16 = 2,
        /// Failures needed to take a server down.
        fall: u16 = 3,
        /// Status codes 200..=399 pass unless this narrows it.
        expect_status: ?u16 = null,
    };
};

/// Forward UDP datagrams (typically QUIC) to an upstream group without
/// decrypting them. Each client address gets its own upstream socket, so
/// replies need no parsing.
pub const UdpProxy = struct {
    address: []const u8 = "0.0.0.0",
    port: u16,
    /// Upstream name or literal `host:port`.
    proxy_pass: []const u8,
    /// Drop a client flow after this long without traffic either way.
    idle_timeout_ms: u32 = 60_000,
    max_flows: u32 = 100_000,
    /// Route by the server ID backends encode in their connection IDs
    /// (draft-ietf-quic-load-balancers), so a client that changes address
    /// keeps reaching the same backend.
    quic_lb: ?QuicLb = null,

    pub const QuicLb = struct {
        config_id: u3 = 0,
        server_id_len: u4,
        nonce_len: u5 = 6,
        /// 32 hex characters; absent means plaintext server IDs.
        key: ?[]const u8 = null,
        /// Hex server ID of each upstream server, in the upstream's order.
        server_ids: []const []const u8,
    };
};

pub const LoadError = error{ InvalidConfig, OutOfMemory } || std.Io.Dir.ReadFileAllocError;

/// Parse and validate `path`. Everything is allocated in `arena` and lives as
/// long as the process.
pub fn load(io: std.Io, arena: std.mem.Allocator, path: []const u8) LoadError!Config {
    return parse(arena, try readSource(io, arena, path), path);
}

pub fn readSource(io: std.Io, arena: std.mem.Allocator, path: []const u8) std.Io.Dir.ReadFileAllocError![:0]u8 {
    return std.Io.Dir.cwd().readFileAllocOptions(io, path, arena, .limited(1024 * 1024), .of(u8), 0);
}

pub fn parse(arena: std.mem.Allocator, source: [:0]const u8, name: []const u8) error{ InvalidConfig, OutOfMemory }!Config {
    // std.zon generates code per field; Location has more than its default allows.
    @setEvalBranchQuota(4000);
    // All in `arena`; freeing on error would also touch strings still in `source`.
    var diag: std.zon.parse.Diagnostics = .{};
    const cfg = std.zon.parse.fromSliceAlloc(Config, arena, source, &diag, .{ .free_on_error = false }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            std.log.err("{s}: {f}", .{ name, diag });
            return error.InvalidConfig;
        },
    };
    try validate(arena, &cfg);
    return cfg;
}

fn fail(comptime fmt: []const u8, args: anytype) error{InvalidConfig} {
    // Tests fail on any error-level log.
    if (!@import("builtin").is_test) std.log.err("config: " ++ fmt, args);
    return error.InvalidConfig;
}

/// `alloc` holds regexes compiled to check them, freed before returning.
pub fn validate(alloc: std.mem.Allocator, cfg: *const Config) error{ InvalidConfig, OutOfMemory }!void {
    if (cfg.workers == 0) return fail("workers must be at least 1", .{});
    if (cfg.file_io_threads == 0 or cfg.file_io_threads > 256) return fail("file_io_threads must be 1 to 256", .{});
    // 0 would disable the idle timeout: dead peers would never be dropped.
    if (cfg.limits.quic_idle_timeout_ms == 0) return fail("limits.quic_idle_timeout_ms must be at least 1", .{});
    if (cfg.servers.len == 0 and cfg.udp_proxies.len == 0) return fail("nothing to serve: no servers or udp_proxies", .{});
    if (cfg.group != null and cfg.user == null) return fail("group needs user", .{});
    if (cfg.user) |u| if (u.len == 0) return fail("user is empty", .{});
    if (cfg.access_log_path) |p| if (p.len == 0) return fail("access_log_path is empty", .{});
    if (cfg.error_log) |p| if (p.len == 0) return fail("error_log is empty", .{});
    access_log.validate(cfg.access_log_format) catch |err| return fail("access_log_format: {s}", .{switch (err) {
        error.UnknownVariable => "unknown variable",
        error.BadVariable => "bad variable syntax",
        error.NoVariable => "not a preset (main, combined, json) and has no $variable",
    }});
    for (cfg.udp_proxies) |u| {
        try checkTarget(cfg, u.proxy_pass);
        if (u.quic_lb) |lb| {
            const n = if (findUpstream(cfg, u.proxy_pass)) |up| up.servers.len else 1;
            if (lb.server_ids.len != n) return fail("udp_proxy :{d}: quic_lb needs one server_id per upstream server", .{u.port});
            for (lb.server_ids) |sid| {
                if (sid.len != @as(usize, lb.server_id_len) * 2) return fail("udp_proxy :{d}: server_id '{s}' must be {d} hex bytes", .{ u.port, sid, lb.server_id_len });
                var buf: [15]u8 = undefined;
                _ = std.fmt.hexToBytes(buf[0..lb.server_id_len], sid) catch return fail("udp_proxy :{d}: bad hex '{s}'", .{ u.port, sid });
            }
            if (lb.key) |k| {
                var buf: [16]u8 = undefined;
                if (k.len != 32) return fail("udp_proxy :{d}: quic_lb key must be 32 hex chars", .{u.port});
                _ = std.fmt.hexToBytes(&buf, k) catch return fail("udp_proxy :{d}: bad quic_lb key", .{u.port});
            }
        }
    }

    for (cfg.upstreams, 0..) |up, i| {
        if (up.servers.len == 0) return fail("upstream '{s}' has no servers", .{up.name});
        if (up.tls and up.h3) return fail("upstream '{s}': tls and h3 are exclusive (h3 is always encrypted)", .{up.name});
        if (up.tls_server_name) |n| if (n.len == 0 or n.len > 255) return fail("upstream '{s}': bad tls_server_name", .{up.name});
        if ((up.tls_client_cert == null) != (up.tls_client_key == null)) return fail("upstream '{s}': tls_client_cert and tls_client_key go together", .{up.name});
        if (up.tls_client_cert != null and !up.tls and !up.h3) return fail("upstream '{s}': a client certificate needs tls or h3", .{up.name});
        for (up.servers) |s| _ = parseHostPort(s) catch return fail("upstream '{s}': bad server '{s}'", .{ up.name, s });
        for (cfg.upstreams[0..i]) |prev| {
            if (std.mem.eql(u8, prev.name, up.name)) return fail("duplicate upstream '{s}'", .{up.name});
        }
    }

    try checkRealIp(cfg);
    for (cfg.servers) |*srv| {
        if (srv.listen.len == 0) return fail("server without listen", .{});
        for (srv.listen) |l| {
            if ((l.tls or l.quic) and srv.tls == null) return fail("listen :{d} needs server tls", .{l.port});
            if (!l.tcp and !l.quic) return fail("listen :{d} has neither tcp nor quic", .{l.port});
            if (!l.tcp and l.tls) return fail("listen :{d}: tls without tcp", .{l.port});
            if (!l.tcp and l.proxy_protocol) return fail("listen :{d}: proxy_protocol without tcp", .{l.port});
        }
        if (srv.tls) |t| try checkTls(cfg, srv, t);
        try checkAccess(srv.access, "server");
        for (srv.rewrite) |rw| try checkRewrite(alloc, "server", rw);
        for (srv.locations) |*loc| {
            try checkMatch(alloc, loc);
            for (loc.rewrite) |rw| try checkRewrite(alloc, loc.pattern(), rw);
            var actions: u8 = 0;
            if (loc.root != null) actions += 1;
            if (loc.proxy_pass != null) actions += 1;
            if (loc.webtransport_pass != null) actions += 1;
            if (loc.@"return" != null) actions += 1;
            if (loc.stub_status) actions += 1;
            if (loc.metrics) actions += 1;
            if (actions != 1) return fail("location '{s}' needs exactly one of root, proxy_pass, webtransport_pass, return, stub_status, metrics", .{loc.pattern()});
            if (loc.proxy_pass) |p| try checkProxyPass(cfg, loc, p);
            for (loc.proxy_set_headers) |h| try checkHeader(h);
            for (loc.add_headers) |h| try checkHeader(h);
            if (loc.try_files.len > 0) try checkTryFiles(loc.*);
            if (loc.precompressed.len > 0 and loc.root == null) return fail("location '{s}': precompressed needs root", .{loc.pattern()});
            if (loc.@"return") |r| {
                if (r.status < 100 or r.status > 599) return fail("location '{s}': return status {d} is out of range", .{ loc.pattern(), r.status });
                if (r.location) |l| try checkHeader(.{ .name = "location", .value = l });
            }
            if (loc.limit_req) |l| try checkLimitReq(cfg, loc.pattern(), l);
            try checkAccess(loc.access, loc.pattern());
            if (loc.auth_basic) |ab| try checkAuthBasic(loc.pattern(), ab);
            if (loc.require_client_cert and (srv.tls == null or srv.tls.?.client_ca == null))
                return fail("location '{s}': require_client_cert needs the server's tls.client_ca", .{loc.pattern()});
            if (loc.webtransport_pass) |p| try checkTarget(cfg, p);
        }
    }
}

fn checkRealIp(cfg: *const Config) error{InvalidConfig}!void {
    for (cfg.real_ip_from) |text| {
        _ = access.parse(.allow, text) catch return fail("real_ip_from '{s}' is not an address or a network", .{text});
        if (access.hostBitsSet(.allow, text) and !@import("builtin").is_test)
            std.log.scoped(.config).warn("real_ip_from '{s}' has bits set past its prefix; they are ignored", .{text});
    }
    if (cfg.real_ip_header) |h| if (!@import("http/common.zig").isToken(h)) return fail("real_ip_header '{s}' is not a header name", .{h});
    for (cfg.servers) |srv| for (srv.listen) |l| {
        if (!l.proxy_protocol) continue;
        if (cfg.real_ip_from.len == 0) return fail("listen :{d}: proxy_protocol needs real_ip_from, the proxies allowed to send it", .{l.port});
    };
    // One TCP socket serves every server naming the address and port.
    for (cfg.servers, 0..) |srv, i| for (srv.listen) |l| {
        if (!l.tcp) continue;
        for (cfg.servers[0 .. i + 1]) |other| for (other.listen) |ol| {
            if (!ol.tcp or ol.port != l.port or !std.mem.eql(u8, ol.address, l.address)) continue;
            if (ol.proxy_protocol != l.proxy_protocol) return fail("listen {s}:{d}: servers disagree on proxy_protocol", .{ l.address, l.port });
        };
    };
}

fn checkMatch(alloc: std.mem.Allocator, loc: *const Location) error{ InvalidConfig, OutOfMemory }!void {
    const given = @as(u8, @intFromBool(loc.prefix != null)) + @intFromBool(loc.exact != null) + @intFromBool(loc.regex != null);
    if (given != 1) return fail("location '{s}' needs exactly one of prefix, exact, regex", .{loc.pattern()});
    if (loc.no_regex and loc.prefix == null) return fail("location '{s}': no_regex applies to prefix locations", .{loc.pattern()});
    if (loc.case_insensitive and loc.regex == null) return fail("location '{s}': case_insensitive applies to regex locations", .{loc.pattern()});
    if (loc.strip_prefix and loc.regex != null) return fail("location '{s}': strip_prefix needs a prefix or exact location", .{loc.pattern()});
    if (loc.regex) |pattern| return checkRegex(alloc, "location", pattern, loc.case_insensitive);
    const path = loc.pattern();
    if (path.len == 0 or path[0] != '/') return fail("location '{s}' must start with '/'", .{path});
}

pub fn checkRegex(alloc: std.mem.Allocator, what: []const u8, pattern: []const u8, case_insensitive: bool) error{ InvalidConfig, OutOfMemory }!void {
    var d: regex.Diagnostic = .{};
    const re = regex.Regex.compile(alloc, pattern, .{ .case_insensitive = case_insensitive }, &d) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidPattern => return fail("{s} regex '{s}': {s} (at offset {d})", .{ what, pattern, d.message, d.offset }),
    };
    re.deinit(alloc);
}

fn checkRewrite(alloc: std.mem.Allocator, where: []const u8, rw: Rewrite) error{ InvalidConfig, OutOfMemory }!void {
    try checkRegex(alloc, "rewrite", rw.regex, rw.case_insensitive);
    const r = rw.replacement;
    if (r.len == 0 or (r[0] != '/' and r[0] != '$' and !Rewrite.isAbsolute(r)))
        return fail("{s}: rewrite replacement '{s}' must start with '/', http://, https:// or a variable", .{ where, r });
    try checkUri(r, "rewrite replacement");
}

fn checkProxyPass(cfg: *const Config, loc: *const Location, text: []const u8) error{InvalidConfig}!void {
    const pp = splitProxyPass(text);
    try checkTarget(cfg, pp.target);
    const uri = pp.uri orelse return;
    try checkUri(uri, "proxy_pass");
    if (loc.strip_prefix) return fail("location '{s}': strip_prefix and a proxy_pass URI both rewrite the path; use one", .{loc.pattern()});
    // What a regex matched has no fixed part to replace.
    if (loc.regex != null and !vars.has(uri)) return fail("location '{s}': a proxy_pass URI in a regex location needs variables, such as $1", .{loc.pattern()});
}

/// A path template: no spaces or control characters, known variables.
fn checkUri(uri: []const u8, what: []const u8) error{InvalidConfig}!void {
    for (uri) |c| if (c <= 0x20 or c == 0x7f) return fail("{s} '{s}': spaces and control characters must be percent-encoded", .{ what, uri });
    vars.validate(uri) catch |err| return fail("{s} '{s}': {s}", .{ what, uri, switch (err) {
        error.UnknownVariable => "unknown variable",
        error.BadVariable => "bad variable syntax",
    } });
}

fn checkAccess(rules: []const AccessRule, where: []const u8) error{InvalidConfig}!void {
    for (rules) |r| {
        _ = access.parse(r.action(), r.text()) catch return fail("{s}: access rule '{s}' is not all, an address or a network", .{ where, r.text() });
        if (access.hostBitsSet(r.action(), r.text()) and !@import("builtin").is_test)
            std.log.scoped(.config).warn("{s}: access rule '{s}' has bits set past its prefix; they are ignored", .{ where, r.text() });
    }
}

fn checkAuthBasic(prefix: []const u8, ab: AuthBasic) error{InvalidConfig}!void {
    if (ab.user_file.len == 0) return fail("location '{s}': auth_basic.user_file is empty", .{prefix});
    // It goes out inside a quoted string in WWW-Authenticate.
    if (ab.realm.len == 0 or ab.realm.len > 256) return fail("location '{s}': auth_basic.realm must be 1 to 256 bytes", .{prefix});
    for (ab.realm) |c| if (c < 0x20 or c == 0x7f or c == '"' or c == '\\')
        return fail("location '{s}': auth_basic.realm may not hold quotes, backslashes or control characters", .{prefix});
}

fn checkLimitReq(cfg: *const Config, prefix: []const u8, l: Location.LimitReq) error{InvalidConfig}!void {
    if (l.rate == 0) return fail("location '{s}': limit_req.rate must be > 0", .{prefix});
    const zone = l.zone orelse return;
    if (zone.len == 0) return fail("location '{s}': limit_req.zone is empty", .{prefix});
    for (cfg.servers) |srv| for (srv.locations) |other| {
        const o = other.limit_req orelse continue;
        const oz = o.zone orelse continue;
        if (std.mem.eql(u8, oz, zone) and o.rate != l.rate) return fail("limit_req zone '{s}': rates differ ({d} and {d})", .{ zone, o.rate, l.rate });
    };
}

fn checkTryFiles(loc: Location) error{InvalidConfig}!void {
    if (loc.root == null) return fail("location '{s}': try_files needs root", .{loc.pattern()});
    for (loc.try_files, 0..) |entry, i| {
        if (tryFilesStatus(entry)) |status| {
            if (i != loc.try_files.len - 1) return fail("location '{s}': try_files '{s}' must come last", .{ loc.pattern(), entry });
            if (status < 100 or status > 599) return fail("location '{s}': try_files '{s}' is not a status", .{ loc.pattern(), entry });
            continue;
        }
        const rest = if (std.mem.startsWith(u8, entry, "$uri")) entry["$uri".len..] else if (std.mem.startsWith(u8, entry, "/")) entry else return fail("location '{s}': try_files '{s}' must start with '/' or $uri", .{ loc.pattern(), entry });
        // Appended to an already-normalized path, so these are all it takes
        // to keep the result under root.
        if (std.mem.indexOf(u8, rest, "..") != null or std.mem.indexOfAny(u8, rest, "$\x00") != null)
            return fail("location '{s}': try_files '{s}' may only use $uri, at the start, and no '..'", .{ loc.pattern(), entry });
    }
}

/// The status of a `=404`-style try_files entry.
pub fn tryFilesStatus(entry: []const u8) ?u16 {
    if (entry.len < 2 or entry[0] != '=') return null;
    return std.fmt.parseInt(u16, entry[1..], 10) catch null;
}

fn checkTls(cfg: *const Config, srv: *const Server, t: Tls) error{InvalidConfig}!void {
    if (t.client_ca) |p| if (p.len == 0) return fail("server tls.client_ca is empty", .{});
    const acme = t.acme orelse {
        if (t.cert == null or t.key == null) return fail("server tls needs cert and key, or acme", .{});
        return;
    };
    if (t.cert != null or t.key != null) return fail("server tls: acme replaces cert and key; give one or the other", .{});
    if (srv.server_names.len == 0) return fail("acme needs server_names", .{});
    for (srv.server_names) |n| {
        if (std.mem.indexOfScalar(u8, n, '*') != null) return fail("acme: '{s}': wildcard names need DNS-01, which isn't supported", .{n});
        if (!isDnsName(n)) return fail("acme: '{s}' is not a DNS name", .{n});
    }
    if (!std.mem.startsWith(u8, acme.directory, "https://")) return fail("acme directory must be an https:// URL", .{});
    if (acme.storage.len == 0) return fail("acme storage must be set", .{});
    if (acme.renew_days == 0) return fail("acme renew_days must be > 0", .{});
    if (acme.check_interval_s == 0) return fail("acme check_interval_s must be > 0", .{});
    if (acme.order_timeout_s == 0) return fail("acme order_timeout_s must be > 0", .{});
    // HTTP-01 is answered on plain-HTTP listeners; the CA connects to port 80.
    var has_plain = false;
    var has_port_80 = false;
    for (cfg.servers) |other| for (other.listen) |l| if (l.tcp and !l.tls) {
        has_plain = true;
        if (l.port == 80) has_port_80 = true;
    };
    if (!has_plain) return fail("acme needs a plain-HTTP listener for HTTP-01 challenges", .{});
    // Behind a port-forward or a test CA another port can work, so only warn.
    if (!has_port_80 and !@import("builtin").is_test) {
        std.log.scoped(.config).warn("acme for '{s}': no plain-HTTP listener on port 80, where CAs validate HTTP-01", .{srv.server_names[0]});
    }
    // Certificates are stored under one name; a second server using the same
    // one must ask for the same set.
    const key = acmeStorageName(srv.server_names);
    for (cfg.servers) |*other| {
        if (other == srv) break;
        const oa = (other.tls orelse continue).acme orelse continue;
        if (!std.mem.eql(u8, acmeStorageName(other.server_names), key)) continue;
        if (!std.mem.eql(u8, oa.directory, acme.directory) or !std.mem.eql(u8, oa.storage, acme.storage)) continue;
        if (!sameNames(other.server_names, srv.server_names)) return fail("acme: two servers with '{s}' need the same server_names", .{key});
    }
}

/// The name an ACME certificate is stored under: the alphabetically first,
/// so the order of `server_names` doesn't matter.
pub fn acmeStorageName(names: []const []const u8) []const u8 {
    var first = names[0];
    for (names[1..]) |n| if (std.mem.lessThan(u8, n, first)) {
        first = n;
    };
    return first;
}

/// The same set of names, in any order.
pub fn sameNames(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a) |x| {
        for (b) |y| {
            if (std.mem.eql(u8, x, y)) break;
        } else return false;
    }
    return true;
}

/// Letters, digits and hyphens in dot-separated labels, and not an IP address.
fn isDnsName(n: []const u8) bool {
    if (n.len == 0 or n.len > 253) return false;
    if (std.Io.net.IpAddress.parse(n, 0)) |_| return false else |_| {}
    var it = std.mem.splitScalar(u8, n, '.');
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
    }
    return true;
}

fn checkHeader(h: HeaderKV) error{InvalidConfig}!void {
    const common = @import("http/common.zig");
    if (!common.isToken(h.name)) return fail("bad header name '{s}'", .{h.name});
    if (!common.isFieldValue(h.value)) return fail("bad value for header '{s}'", .{h.name});
    vars.validate(h.value) catch |err| return fail("header '{s}': {s} in '{s}'", .{ h.name, switch (err) {
        error.UnknownVariable => "unknown variable",
        error.BadVariable => "bad variable syntax",
    }, h.value });
}

fn checkTarget(cfg: *const Config, target: []const u8) error{InvalidConfig}!void {
    if (findUpstream(cfg, target) != null) return;
    _ = parseHostPort(target) catch return fail("'{s}' is neither an upstream nor host:port", .{target});
}

pub fn findUpstream(cfg: *const Config, name: []const u8) ?*const Upstream {
    for (cfg.upstreams) |*up| {
        if (std.mem.eql(u8, up.name, name)) return up;
    }
    return null;
}

pub const HostPort = struct { host: []const u8, port: u16 };

/// `host:port` or `[v6]:port`. Accepts an `http://` prefix for familiarity.
pub fn parseHostPort(text_in: []const u8) error{InvalidAddress}!HostPort {
    var text = text_in;
    if (std.mem.startsWith(u8, text, "http://")) text = text["http://".len..];
    text = std.mem.trimEnd(u8, text, "/");
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidAddress;
    var host = text[0..colon];
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
    if (host.len == 0) return error.InvalidAddress;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.InvalidAddress;
    if (port == 0) return error.InvalidAddress;
    return .{ .host = host, .port = port };
}

test "parse sample config" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const cfg = try parse(arena_state.allocator(),
        \\.{
        \\    .servers = .{.{
        \\        .listen = .{.{ .port = 8080 }},
        \\        .locations = .{
        \\            .{ .prefix = "/", .root = "static" },
        \\            .{ .prefix = "/api/", .proxy_pass = "backend", .strip_prefix = true },
        \\            .{ .prefix = "/ping", .@"return" = .{ .body = "pong" } },
        \\        },
        \\    }},
        \\    .upstreams = .{.{ .name = "backend", .servers = .{ "127.0.0.1:9000", "[::1]:9001" } }},
        \\}
    , "test");
    try std.testing.expectEqual(@as(usize, 3), cfg.servers[0].locations.len);
    try std.testing.expect(findUpstream(&cfg, "backend") != null);
}

test "reject location with two actions" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(error.InvalidConfig, parse(arena_state.allocator(),
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .proxy_pass = "a:1" }} }} }
    , "test"));
}

test "quic idle timeout" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try parse(a,
        \\.{ .limits = .{ .quic_idle_timeout_ms = 120000 }, .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
    , "test");
    try std.testing.expectEqual(@as(u32, 120_000), cfg.limits.quic_idle_timeout_ms);
    try std.testing.expectError(error.InvalidConfig, parse(a,
        \\.{ .limits = .{ .quic_idle_timeout_ms = 0 }, .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
    , "test"));
}

test "limit_req zones" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    _ = try parse(a,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{
        \\    .{ .prefix = "/a", .root = "x", .limit_req = .{ .zone = "api", .rate = 5, .burst = 10 } },
        \\    .{ .prefix = "/b", .root = "x", .limit_req = .{ .zone = "api", .rate = 5 } },
        \\    .{ .prefix = "/c", .root = "x", .limit_req = .{ .rate = 1 } },
        \\} }} }
    , "test");
    try std.testing.expectError(error.InvalidConfig, parse(a,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{
        \\    .{ .prefix = "/a", .root = "x", .limit_req = .{ .zone = "api", .rate = 5 } },
        \\    .{ .prefix = "/b", .root = "x", .limit_req = .{ .zone = "api", .rate = 6 } },
        \\} }} }
    , "test"));
    try std.testing.expectError(error.InvalidConfig, parse(a,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .limit_req = .{ .zone = "", .rate = 5 } }} }} }
    , "test"));
}

test "tls upstreams" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try parse(a,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .proxy_pass = "b" }} }},
        \\   .upstreams = .{.{ .name = "b", .servers = .{"10.0.0.1:443"}, .tls = true, .tls_server_name = "api.internal" }} }
    , "test");
    try std.testing.expect(cfg.upstreams[0].tls);
    try std.testing.expectEqualStrings("api.internal", cfg.upstreams[0].tls_server_name.?);
    try std.testing.expectError(error.InvalidConfig, parse(a,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .proxy_pass = "b" }} }},
        \\   .upstreams = .{.{ .name = "b", .servers = .{"10.0.0.1:443"}, .tls = true, .h3 = true }} }
    , "test"));
}

test "host:port parsing" {
    const hp = try parseHostPort("[::1]:9001");
    try std.testing.expectEqualStrings("::1", hp.host);
    try std.testing.expectEqual(@as(u16, 9001), hp.port);
    try std.testing.expectError(error.InvalidAddress, parseHostPort("nohost"));
}

test "acme tls: exactly one form, no wildcards, needs plain http" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const ok = try parse(a,
        \\.{ .servers = .{.{
        \\    .listen = .{ .{ .port = 80 }, .{ .port = 443, .tls = true } },
        \\    .server_names = .{ "example.com", "www.example.com" },
        \\    .tls = .{ .acme = .{ .email = "ops@example.com", .storage = "/tmp/acme" } },
        \\    .locations = .{.{ .prefix = "/", .root = "x" }},
        \\}} }
    , "test");
    try std.testing.expectEqual(@as(u16, 30), ok.servers[0].tls.?.acme.?.renew_days);

    const bad = [_][:0]const u8{
        // wildcard
        \\.{ .servers = .{.{ .listen = .{ .{ .port = 80 }, .{ .port = 443, .tls = true } }, .server_names = .{"*.example.com"},
        \\    .tls = .{ .acme = .{} }, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
        // no plain listener
        \\.{ .servers = .{.{ .listen = .{.{ .port = 443, .tls = true }}, .server_names = .{"example.com"},
        \\    .tls = .{ .acme = .{} }, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
        // acme and cert together
        \\.{ .servers = .{.{ .listen = .{ .{ .port = 80 }, .{ .port = 443, .tls = true } }, .server_names = .{"example.com"},
        \\    .tls = .{ .cert = "c", .key = "k", .acme = .{} }, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
        // no names
        \\.{ .servers = .{.{ .listen = .{ .{ .port = 80 }, .{ .port = 443, .tls = true } },
        \\    .tls = .{ .acme = .{} }, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
        // IP address
        \\.{ .servers = .{.{ .listen = .{ .{ .port = 80 }, .{ .port = 443, .tls = true } }, .server_names = .{"192.0.2.1"},
        \\    .tls = .{ .acme = .{} }, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
        // cert without key
        \\.{ .servers = .{.{ .listen = .{.{ .port = 443, .tls = true }}, .tls = .{ .cert = "c" }, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
    };
    for (bad) |src| try std.testing.expectError(error.InvalidConfig, parse(a, src, "test"));
}

test "variables in return and headers" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try parse(a,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{
        \\    .{ .prefix = "/", .@"return" = .{ .status = 301, .location = "https://$host$request_uri" },
        \\       .add_headers = .{.{ .name = "x-uri", .value = "${uri}" }} },
        \\} }} }
    , "test");
    try std.testing.expectEqualStrings("https://$host$request_uri", cfg.servers[0].locations[0].@"return".?.location.?);
    const bad = [_][:0]const u8{
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .@"return" = .{ .status = 301, .location = "https://$hostname/" } }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .add_headers = .{.{ .name = "x", .value = "$" }} }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .proxy_pass = "a:1", .proxy_set_headers = .{.{ .name = "x", .value = "$nope" }} }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .@"return" = .{ .status = 3010 } }} }} }
        ,
    };
    for (bad) |src| try std.testing.expectError(error.InvalidConfig, parse(a, src, "test"));
}

test "precompressed" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try parse(a,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{
        \\    .{ .prefix = "/", .root = "x", .precompressed = .{ .br, .zstd, .gzip } },
        \\} }} }
    , "test");
    try std.testing.expectEqualSlices(encoding.Coding, &.{ .br, .zstd, .gzip }, cfg.servers[0].locations[0].precompressed);
    const bad = [_][:0]const u8{
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .proxy_pass = "a:1", .precompressed = .{.gzip} }} }} }
        ,
    };
    for (bad) |src| try std.testing.expectError(error.InvalidConfig, parse(a, src, "test"));
}

test "try_files" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    _ = try parse(a,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{
        \\    .{ .prefix = "/", .root = "x", .try_files = .{ "$uri", "$uri/", "$uri.html", "/index.html" } },
        \\    .{ .prefix = "/a/", .root = "x", .try_files = .{ "$uri", "=404" } },
        \\} }} }
    , "test");
    const bad = [_][:0]const u8{
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .proxy_pass = "a:1", .try_files = .{"$uri"} }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .try_files = .{ "=404", "$uri" } }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .try_files = .{ "$uri", "/../etc/passwd" } }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .try_files = .{ "$uri..", "/i.html" } }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .try_files = .{ "index.html" } }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .try_files = .{ "/$host/x" } }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .try_files = .{ "$uri", "=40x" } }} }} }
        ,
    };
    for (bad) |src| try std.testing.expectError(error.InvalidConfig, parse(a, src, "test"));
}

test "access rules, auth_basic and client certificates" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try parse(a,
        \\.{ .servers = .{.{
        \\    .listen = .{.{ .port = 443, .tls = true }},
        \\    .tls = .{ .cert = "c", .key = "k", .client_ca = "ca.pem", .client_verify = .optional },
        \\    .access = .{ .{ .allow = "10.0.0.0/8" }, .{ .allow = "2001:db8::/32" }, .{ .deny = "all" } },
        \\    .locations = .{
        \\        .{ .prefix = "/", .root = "x" },
        \\        .{ .prefix = "/admin/", .root = "x", .require_client_cert = true,
        \\           .auth_basic = .{ .realm = "Admins", .user_file = "/etc/routez/htpasswd" },
        \\           .access = .{.{ .allow = "all" }} },
        \\    },
        \\}} }
    , "test");
    const srv = cfg.servers[0];
    try std.testing.expectEqual(@as(usize, 3), srv.access.len);
    try std.testing.expectEqualStrings("all", srv.access[2].deny);
    try std.testing.expectEqual(ClientVerify.optional, srv.tls.?.client_verify);
    try std.testing.expectEqualStrings("Admins", srv.locations[1].auth_basic.?.realm);

    const bad = [_][:0]const u8{
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .access = .{.{ .allow = "10.0.0.0/33" }}, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .access = .{.{ .deny = "everyone" }} }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .auth_basic = .{ .user_file = "" } }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .auth_basic = .{ .realm = "a\"b", .user_file = "f" } }} }} }
        ,
        // require_client_cert without a client CA
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .require_client_cert = true }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 443, .tls = true }}, .tls = .{ .cert = "c", .key = "k", .client_ca = "" }, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
    };
    for (bad) |src| try std.testing.expectError(error.InvalidConfig, parse(a, src, "test"));
}

test "location match types and proxy_pass URIs" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try parse(a,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{
        \\    .{ .prefix = "/", .root = "x" },
        \\    .{ .exact = "/health", .@"return" = .{ .body = "ok" } },
        \\    .{ .prefix = "/static/", .no_regex = true, .root = "x" },
        \\    .{ .regex = "\\.(png|jpe?g)$", .case_insensitive = true, .root = "x" },
        \\    .{ .regex = "^/u/(\\d+)$", .proxy_pass = "127.0.0.1:9/users/$1?full=1" },
        \\    .{ .prefix = "/api/", .proxy_pass = "http://127.0.0.1:9/v2/" },
        \\} }} }
    , "test");
    const locs = cfg.servers[0].locations;
    try std.testing.expectEqual(Location.Match.exact, locs[1].match());
    try std.testing.expectEqual(Location.Match.regex, locs[3].match());
    try std.testing.expectEqualStrings("/static/", locs[2].pattern());

    const bad = [_][:0]const u8{
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .exact = "/", .root = "x" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .root = "x" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .exact = "health", .root = "x" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .regex = "^/(a)\\1", .root = "x" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .regex = "^/(?=a)", .root = "x" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .regex = "/", .no_regex = true, .root = "x" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .case_insensitive = true, .root = "x" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .regex = "/", .strip_prefix = true, .proxy_pass = "a:1" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .regex = "^/x", .proxy_pass = "a:1/y" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .proxy_pass = "a:1/a b" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .proxy_pass = "a:1/$nope" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .strip_prefix = true, .proxy_pass = "a:1/y/" }} }} }
        ,
    };
    for (bad) |src| try std.testing.expectError(error.InvalidConfig, parse(a, src, "test"));

    try std.testing.expectEqualDeep(ProxyPass{ .target = "backend", .uri = null }, splitProxyPass("backend"));
    try std.testing.expectEqualDeep(ProxyPass{ .target = "http://h:1", .uri = "/" }, splitProxyPass("http://h:1/"));
    try std.testing.expectEqualDeep(ProxyPass{ .target = "[::1]:80", .uri = "/x/$1" }, splitProxyPass("[::1]:80/x/$1"));
}

test "rewrite rules" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try parse(a,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }},
        \\    .rewrite = .{.{ .regex = "^/old/(.*)$", .replacement = "/new/$1", .flag = .last }},
        \\    .locations = .{.{ .prefix = "/", .root = "x", .rewrite = .{
        \\        .{ .regex = "^/a$", .replacement = "/b?x=1", .flag = .@"break" },
        \\        .{ .regex = "^/c$", .replacement = "https://$host/c?", .case_insensitive = true },
        \\        .{ .regex = "^/d$", .replacement = "/e", .flag = .permanent },
        \\        .{ .regex = "^/f$", .replacement = "$scheme://h/f" },
        \\    } }},
        \\}} }
    , "test");
    const rw = cfg.servers[0].locations[0].rewrite;
    try std.testing.expectEqual(Rewrite.Flag.last, cfg.servers[0].rewrite[0].flag);
    try std.testing.expect(!rw[0].redirects());
    try std.testing.expect(rw[1].redirects() and rw[2].redirects() and rw[3].redirects());

    const bad = [_][:0]const u8{
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .rewrite = .{.{ .regex = "^/(a)\\1", .replacement = "/b" }}, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .rewrite = .{.{ .regex = "a", .replacement = "b" }} }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .rewrite = .{.{ .regex = "a", .replacement = "/$bad" }} }} }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x", .rewrite = .{.{ .regex = "a", .replacement = "/a b" }} }} }} }
        ,
    };
    for (bad) |src| try std.testing.expectError(error.InvalidConfig, parse(a, src, "test"));
}

test "trusted proxies and the PROXY protocol" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try parse(a,
        \\.{ .real_ip_from = .{ "10.0.0.0/8", "2001:db8::/32", "192.0.2.1" }, .real_ip_recursive = true,
        \\   .servers = .{.{ .listen = .{ .{ .port = 1, .proxy_protocol = true }, .{ .port = 2 } }, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
    , "test");
    try std.testing.expectEqualStrings("x-forwarded-for", cfg.real_ip_header.?);
    try std.testing.expect(cfg.servers[0].listen[0].proxy_protocol);
    _ = try parse(a,
        \\.{ .real_ip_from = .{"10.0.0.1"}, .real_ip_header = null, .servers = .{.{ .listen = .{.{ .port = 1, .proxy_protocol = true }}, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
    , "test");

    const bad = [_][:0]const u8{
        // proxy_protocol without anyone trusted to send it
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1, .proxy_protocol = true }}, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
        \\.{ .real_ip_from = .{"10.0.0.0/33"}, .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
        \\.{ .real_ip_from = .{"10.0.0.1"}, .real_ip_header = "x forwarded", .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
        \\.{ .real_ip_from = .{"10.0.0.1"}, .servers = .{.{ .listen = .{.{ .port = 1, .quic = true, .tcp = false, .proxy_protocol = true }}, .tls = .{ .cert = "c", .key = "k" }, .locations = .{.{ .prefix = "/", .root = "x" }} }} }
        ,
        // two servers on one port, one with the PROXY protocol
        \\.{ .real_ip_from = .{"10.0.0.1"}, .servers = .{
        \\    .{ .listen = .{.{ .port = 1, .proxy_protocol = true }}, .locations = .{.{ .prefix = "/", .root = "x" }} },
        \\    .{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .root = "x" }} },
        \\} }
        ,
    };
    for (bad) |src| try std.testing.expectError(error.InvalidConfig, parse(a, src, "test"));
}

test "upstream client certificates" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    _ = try parse(a,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .proxy_pass = "b" }} }},
        \\   .upstreams = .{
        \\       .{ .name = "b", .servers = .{"10.0.0.1:443"}, .tls = true, .tls_client_cert = "c.pem", .tls_client_key = "c.key" },
        \\       .{ .name = "q", .servers = .{"10.0.0.1:443"}, .h3 = true, .tls_client_cert = "c.pem", .tls_client_key = "c.key" },
        \\   } }
    , "test");
    const bad = [_][:0]const u8{
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .proxy_pass = "b" }} }},
        \\   .upstreams = .{.{ .name = "b", .servers = .{"10.0.0.1:443"}, .tls = true, .tls_client_cert = "c.pem" }} }
        ,
        \\.{ .servers = .{.{ .listen = .{.{ .port = 1 }}, .locations = .{.{ .prefix = "/", .proxy_pass = "b" }} }},
        \\   .upstreams = .{.{ .name = "b", .servers = .{"10.0.0.1:80"}, .tls_client_cert = "c.pem", .tls_client_key = "c.key" }} }
        ,
    };
    for (bad) |src| try std.testing.expectError(error.InvalidConfig, parse(a, src, "test"));
}

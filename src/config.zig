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

pub const Config = struct {
    /// Worker threads, each with its own event loop and SO_REUSEPORT sockets.
    workers: u16 = 1,
    servers: []const Server = &.{},
    upstreams: []const Upstream = &.{},
    /// Layer-4 UDP forwarding, for QUIC traffic we don't terminate.
    udp_proxies: []const UdpProxy = &.{},
    limits: Limits = .{},
    /// Write one line per completed request to stderr.
    access_log: bool = true,
};

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
    /// TCP connections one client address may hold per worker. 0 disables it.
    max_connections_per_ip: u32 = 0,
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
};

/// Either `cert` and `key`, or `acme`.
pub const Tls = struct {
    /// PEM certificate chain (leaf first).
    cert: ?[]const u8 = null,
    /// PEM private key: EC P-256 or Ed25519.
    key: ?[]const u8 = null,
    /// Obtain and renew the certificate for `server_names` automatically.
    acme: ?Acme = null,
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
    locations: []const Location,
};

pub const Location = struct {
    /// Longest matching prefix wins.
    prefix: []const u8,

    /// Serve files from this directory.
    root: ?[]const u8 = null,
    /// File served for a request that names a directory.
    index: []const u8 = "index.html",

    /// Name of an upstream, or a literal `host:port`.
    proxy_pass: ?[]const u8 = null,
    /// Remove `prefix` from the path before proxying (keeps a leading '/').
    strip_prefix: bool = false,

    /// Relay WebTransport sessions to this upstream (HTTP/3 only).
    webtransport_pass: ?[]const u8 = null,

    /// Answer with a fixed status and body.
    @"return": ?Return = null,

    /// Request headers set on proxied requests, replacing any the client
    /// sent under the same name. An empty value removes the header; `host`
    /// overrides the Host sent upstream.
    proxy_set_headers: []const HeaderKV = &.{},
    /// Headers added to every response from this location.
    add_headers: []const HeaderKV = &.{},
    /// Compress text-like responses with gzip for clients that accept it.
    gzip: bool = false,
    /// Per-client request rate limit, counted per worker.
    limit_req: ?LimitReq = null,

    /// Serve connection and request counters as plain text.
    stub_status: bool = false,

    pub const LimitReq = struct {
        /// Sustained requests per second.
        rate: u32,
        /// Extra requests allowed in a burst above the rate.
        burst: u32 = 0,
    };

    pub const Return = struct {
        status: u16 = 200,
        body: []const u8 = "",
        content_type: []const u8 = "text/plain; charset=utf-8",
    };
};

pub const HeaderKV = struct { name: []const u8, value: []const u8 };

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
    /// For QUIC upstreams: verify the upstream certificate against the system
    /// store (or `tls_ca`). Off by default, for self-signed internal backends.
    tls_verify: bool = false,
    /// PEM CA bundle for verifying QUIC upstreams; implies `tls_verify`.
    tls_ca: ?[]const u8 = null,
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
    var diag: std.zon.parse.Diagnostics = .{};
    const cfg = std.zon.parse.fromSliceAlloc(Config, arena, source, &diag, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            std.log.err("{s}: {f}", .{ name, diag });
            return error.InvalidConfig;
        },
    };
    try validate(&cfg);
    return cfg;
}

fn fail(comptime fmt: []const u8, args: anytype) error{InvalidConfig} {
    // Tests fail on any error-level log.
    if (!@import("builtin").is_test) std.log.err("config: " ++ fmt, args);
    return error.InvalidConfig;
}

pub fn validate(cfg: *const Config) error{InvalidConfig}!void {
    if (cfg.workers == 0) return fail("workers must be at least 1", .{});
    // 0 would disable the idle timeout: dead peers would never be dropped.
    if (cfg.limits.quic_idle_timeout_ms == 0) return fail("limits.quic_idle_timeout_ms must be at least 1", .{});
    if (cfg.servers.len == 0 and cfg.udp_proxies.len == 0) return fail("nothing to serve: no servers or udp_proxies", .{});
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
        for (up.servers) |s| _ = parseHostPort(s) catch return fail("upstream '{s}': bad server '{s}'", .{ up.name, s });
        for (cfg.upstreams[0..i]) |prev| {
            if (std.mem.eql(u8, prev.name, up.name)) return fail("duplicate upstream '{s}'", .{up.name});
        }
    }

    for (cfg.servers) |*srv| {
        if (srv.listen.len == 0) return fail("server without listen", .{});
        for (srv.listen) |l| {
            if ((l.tls or l.quic) and srv.tls == null) return fail("listen :{d} needs server tls", .{l.port});
            if (!l.tcp and !l.quic) return fail("listen :{d} has neither tcp nor quic", .{l.port});
            if (!l.tcp and l.tls) return fail("listen :{d}: tls without tcp", .{l.port});
        }
        if (srv.tls) |t| try checkTls(cfg, srv, t);
        for (srv.locations) |loc| {
            var actions: u8 = 0;
            if (loc.root != null) actions += 1;
            if (loc.proxy_pass != null) actions += 1;
            if (loc.webtransport_pass != null) actions += 1;
            if (loc.@"return" != null) actions += 1;
            if (loc.stub_status) actions += 1;
            if (actions != 1) return fail("location '{s}' needs exactly one of root, proxy_pass, webtransport_pass, return, stub_status", .{loc.prefix});
            if (loc.prefix.len == 0 or loc.prefix[0] != '/') return fail("location prefix '{s}' must start with '/'", .{loc.prefix});
            if (loc.proxy_pass) |p| try checkTarget(cfg, p);
            for (loc.proxy_set_headers) |h| try checkHeader(h);
            for (loc.add_headers) |h| try checkHeader(h);
            if (loc.limit_req) |l| if (l.rate == 0) return fail("location '{s}': limit_req.rate must be > 0", .{loc.prefix});
            if (loc.webtransport_pass) |p| try checkTarget(cfg, p);
        }
    }
}

fn checkTls(cfg: *const Config, srv: *const Server, t: Tls) error{InvalidConfig}!void {
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

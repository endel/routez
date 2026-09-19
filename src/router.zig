//! Request routing: virtual host by Host/:authority, then the location for
//! the normalized path, in nginx's order (see `config.Location`).
const std = @import("std");
const config = @import("config.zig");
const regex = @import("regex.zig");

pub const Target = struct {
    /// Percent-decoded path with dot segments resolved and slashes merged.
    path: []const u8,
    query: ?[]const u8,
};

pub const TargetError = error{BadTarget};

/// Normalize an origin-form (or absolute-form) request target into `buf`.
/// Rejects paths that climb above the root and encoded NULs.
pub fn normalizeTarget(target_in: []const u8, buf: []u8) TargetError!Target {
    var target = target_in;
    // absolute-form: keep only the path
    if (std.ascii.startsWithIgnoreCase(target, "http://") or std.ascii.startsWithIgnoreCase(target, "https://")) {
        const after_scheme = std.mem.indexOf(u8, target, "://").? + 3;
        const slash = std.mem.indexOfScalarPos(u8, target, after_scheme, '/') orelse return .{ .path = "/", .query = null };
        target = target[slash..];
    }
    if (std.mem.eql(u8, target, "*")) return .{ .path = "/", .query = null };
    if (target.len == 0 or target[0] != '/') return error.BadTarget;
    // HTTP/1.1's request line already excludes these; HTTP/3's :path doesn't.
    for (target) |c| if (c <= 0x20 or c == 0x7f) return error.BadTarget;

    const qpos = std.mem.indexOfScalar(u8, target, '?');
    const raw_path = target[0 .. qpos orelse target.len];
    const query = if (qpos) |q| target[q + 1 ..] else null;
    // One spare byte: every kept segment is followed by a '/'.
    if (raw_path.len >= buf.len) return error.BadTarget;

    var n: usize = 0;
    var i: usize = 0;
    while (i < raw_path.len) : (i += 1) {
        var c = raw_path[i];
        if (c == '%') {
            if (i + 2 >= raw_path.len) return error.BadTarget;
            const hi = std.fmt.charToDigit(raw_path[i + 1], 16) catch return error.BadTarget;
            const lo = std.fmt.charToDigit(raw_path[i + 2], 16) catch return error.BadTarget;
            c = hi * 16 + lo;
            if (c == 0) return error.BadTarget;
            i += 2;
        }
        buf[n] = c;
        n += 1;
    }

    // Resolve segments in place: the write cursor never passes the read cursor.
    var out: usize = 1;
    var depth: usize = 0;
    var trailing_slash = false;
    var r: usize = 1;
    while (r <= n) {
        const seg_end = std.mem.indexOfScalarPos(u8, buf[0..n], r, '/') orelse n;
        const seg_len = seg_end - r;
        const is_dot = seg_len == 1 and buf[r] == '.';
        const is_dotdot = seg_len == 2 and buf[r] == '.' and buf[r + 1] == '.';
        trailing_slash = false;
        if (seg_len == 0 or is_dot) {
            trailing_slash = true;
        } else if (is_dotdot) {
            if (depth == 0) return error.BadTarget;
            depth -= 1;
            // Drop the last kept segment: back up past its '/' to the previous one.
            out -= 1;
            while (out > 0 and buf[out - 1] != '/') out -= 1;
            trailing_slash = true;
        } else {
            std.mem.copyForwards(u8, buf[out .. out + seg_len], buf[r..seg_end]);
            out += seg_len;
            buf[out] = '/';
            out += 1;
            depth += 1;
        }
        r = seg_end + 1;
    }
    buf[0] = '/';
    // Every kept segment appended a '/'; keep it only where the request had one.
    if (out > 1 and !trailing_slash) out -= 1;
    return .{ .path = buf[0..out], .query = query };
}

/// Percent-encode a decoded path for sending upstream.
pub fn encodePath(path: []const u8, out: *std.ArrayList(u8), alloc: std.mem.Allocator) !void {
    for (path) |c| {
        const safe = std.ascii.isAlphanumeric(c) or switch (c) {
            '/', '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@' => true,
            else => false,
        };
        if (safe) {
            try out.append(alloc, c);
        } else {
            try out.print(alloc, "%{X:0>2}", .{c});
        }
    }
}

/// Servers sharing one listener, in config order.
pub const VirtualHosts = struct {
    servers: []const *const config.Server,

    /// Exact name, then one-label wildcard, then the first server.
    pub fn select(self: *const VirtualHosts, authority: ?[]const u8) *const config.Server {
        const host = hostOnly(authority orelse return self.servers[0]);
        for (self.servers) |srv| {
            for (srv.server_names) |name| {
                if (std.ascii.eqlIgnoreCase(name, host)) return srv;
            }
        }
        for (self.servers) |srv| {
            for (srv.server_names) |name| {
                if (wildcardMatch(name, host)) return srv;
            }
        }
        return self.servers[0];
    }
};

/// Strip port and trailing dot from a Host value.
pub fn hostOnly(authority: []const u8) []const u8 {
    var h = authority;
    if (h.len > 0 and h[0] == '[') {
        if (std.mem.indexOfScalar(u8, h, ']')) |end| return h[1..end];
        return h;
    }
    if (std.mem.lastIndexOfScalar(u8, h, ':')) |c| h = h[0..c];
    return std.mem.trimEnd(u8, h, ".");
}

fn wildcardMatch(pattern: []const u8, host: []const u8) bool {
    if (!std.mem.startsWith(u8, pattern, "*.")) return false;
    const suffix = pattern[1..]; // ".example.com"
    if (host.len <= suffix.len) return false;
    if (!std.ascii.endsWithIgnoreCase(host, suffix)) return false;
    const label = host[0 .. host.len - suffix.len];
    return std.mem.indexOfScalar(u8, label, '.') == null;
}

/// The compiled regexes of one config generation, built at load and read
/// by every worker.
pub const Routes = struct {
    /// By the address of the `config.Location` (or rewrite rule) they belong to.
    regexes: std.AutoHashMapUnmanaged(usize, regex.Regex) = .empty,
    /// `regex.Scratch` capacity the largest program needs.
    max_states: usize = 0,

    pub fn build(arena: std.mem.Allocator, cfg: *const config.Config) !Routes {
        var r: Routes = .{};
        for (cfg.servers) |*srv| for (srv.locations) |*loc| {
            if (loc.regex) |pattern| try r.add(arena, loc, pattern, loc.case_insensitive);
        };
        return r;
    }

    fn add(self: *Routes, arena: std.mem.Allocator, owner: *const anyopaque, pattern: []const u8, ci: bool) !void {
        // Checked when the config was parsed.
        const re = regex.Regex.compile(arena, pattern, .{ .case_insensitive = ci }, null) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidPattern => return error.InvalidConfig,
        };
        try self.regexes.put(arena, @intFromPtr(owner), re);
        self.max_states = @max(self.max_states, re.states());
    }

    pub fn get(self: *const Routes, owner: *const anyopaque) *const regex.Regex {
        return self.regexes.getPtr(@intFromPtr(owner)).?;
    }
};

/// What regex matching needs: the generation's regexes and a worker's
/// scratch space. Prefix and exact matches use neither.
pub const Matcher = struct {
    routes: *const Routes,
    scratch: *regex.Scratch,

    /// Match `path` against `re`, into `caps` (whose input is then `path`).
    pub fn find(self: Matcher, owner: *const anyopaque, path: []const u8, caps: *regex.Captures) bool {
        return self.routes.get(owner).match(path, self.scratch, caps);
    }
};

/// The location for `path`, in nginx's order: an exact match; else the
/// longest prefix, if it has `no_regex`; else the first regex that matches,
/// its groups left in `caps`; else the longest prefix.
pub fn matchLocation(server: *const config.Server, path: []const u8, m: Matcher, caps: *regex.Captures) ?*const config.Location {
    var best: ?*const config.Location = null;
    var best_len: usize = 0;
    var has_regex = false;
    for (server.locations) |*loc| {
        if (loc.exact) |e| {
            if (std.mem.eql(u8, path, e)) return loc;
        } else if (loc.prefix) |p| {
            if (std.mem.startsWith(u8, path, p) and (best == null or p.len > best_len)) {
                best = loc;
                best_len = p.len;
            }
        } else has_regex = true;
    }
    if (best) |b| if (b.no_regex) return b;
    if (has_regex) for (server.locations) |*loc| {
        if (loc.regex == null) continue;
        if (m.find(loc, path, caps)) return loc;
    };
    return best;
}

const testing = std.testing;

fn expectNorm(input: []const u8, want: []const u8) !void {
    var buf: [256]u8 = undefined;
    const t = try normalizeTarget(input, &buf);
    try testing.expectEqualStrings(want, t.path);
}

test "normalize" {
    try expectNorm("/", "/");
    try expectNorm("/a/b", "/a/b");
    try expectNorm("/a/b/", "/a/b/");
    try expectNorm("//a///b", "/a/b");
    try expectNorm("/a/./b/../c", "/a/c");
    try expectNorm("/a/b/..", "/a/");
    try expectNorm("/%61%2Fb", "/a/b");
    try expectNorm("/a%20b?x=1", "/a b");
    try expectNorm("http://host:8080/x/y?q", "/x/y");
    var buf: [256]u8 = undefined;
    try testing.expectError(error.BadTarget, normalizeTarget("/../etc/passwd", &buf));
    try testing.expectError(error.BadTarget, normalizeTarget("/a/%2e%2e/%2e%2e/x", &buf));
    try testing.expectError(error.BadTarget, normalizeTarget("/a%00", &buf));
    try testing.expectError(error.BadTarget, normalizeTarget("/a\x00b", &buf));
    try testing.expectError(error.BadTarget, normalizeTarget("/a b", &buf));
    try testing.expectError(error.BadTarget, normalizeTarget("/a%zz", &buf));
    try testing.expectError(error.BadTarget, normalizeTarget("relative", &buf));
    const t = try normalizeTarget("/p?a=1&b=2", &buf);
    try testing.expectEqualStrings("a=1&b=2", t.query.?);
}

test "virtual hosts" {
    const a: config.Server = .{ .listen = &.{}, .server_names = &.{"a.com"}, .locations = &.{} };
    const b: config.Server = .{ .listen = &.{}, .server_names = &.{"*.b.com"}, .locations = &.{} };
    const vh: VirtualHosts = .{ .servers = &.{ &a, &b } };
    try testing.expectEqual(&b, vh.select("x.b.com:443"));
    try testing.expectEqual(&a, vh.select("A.COM"));
    try testing.expectEqual(&a, vh.select("y.x.b.com"));
    try testing.expectEqual(&a, vh.select(null));
}

/// The pattern of the location `path` matches, or "none".
fn expectLocation(srv: *const config.Server, path: []const u8, want: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg: config.Config = .{ .servers = srv[0..1] };
    const routes = try Routes.build(a, &cfg);
    var scratch = try regex.Scratch.init(a, routes.max_states);
    var caps: regex.Captures = .{};
    const loc = matchLocation(srv, path, .{ .routes = &routes, .scratch = &scratch }, &caps);
    try testing.expectEqualStrings(want, if (loc) |l| l.pattern() else "none");
}

test "longest prefix" {
    const srv: config.Server = .{ .listen = &.{}, .locations = &.{
        .{ .prefix = "/", .root = "x" },
        .{ .prefix = "/api/", .proxy_pass = "a:1" },
        .{ .prefix = "/api/v2/", .proxy_pass = "b:1" },
    } };
    try expectLocation(&srv, "/api/v2/x", "/api/v2/");
    try expectLocation(&srv, "/api/x", "/api/");
    try expectLocation(&srv, "/apix", "/");
}

test "nginx precedence: exact, ^~ prefix, regex in order, longest prefix" {
    const srv: config.Server = .{ .listen = &.{}, .locations = &.{
        .{ .prefix = "/", .root = "x" },
        .{ .prefix = "/static/", .no_regex = true, .root = "x" },
        .{ .prefix = "/images/", .root = "x" },
        .{ .prefix = "/docs/", .root = "x" },
        .{ .regex = "\\.(png|jpg)$", .case_insensitive = true, .root = "x" },
        .{ .regex = "^/images/.*\\.png$", .root = "x" },
        .{ .exact = "/", .root = "x" },
        .{ .exact = "/images/logo.png", .root = "x" },
        .{ .regex = "^/docs", .root = "x" },
    } };
    try expectLocation(&srv, "/", "/");
    try expectLocation(&srv, "/x", "/");
    try expectLocation(&srv, "/images/logo.png", "/images/logo.png");
    // The first regex in config order, not the longest or most specific.
    try expectLocation(&srv, "/images/a.png", "\\.(png|jpg)$");
    try expectLocation(&srv, "/images/a.PNG", "\\.(png|jpg)$");
    try expectLocation(&srv, "/images/a.gif", "/images/");
    try expectLocation(&srv, "/static/a.png", "/static/");
    try expectLocation(&srv, "/docs/a", "^/docs");
    const none: config.Server = .{ .listen = &.{}, .locations = &.{.{ .exact = "/a", .root = "x" }} };
    try expectLocation(&none, "/a/", "none");
}

test "encode path" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try encodePath("/a b/%/é", &out, testing.allocator);
    try testing.expectEqualStrings("/a%20b/%25/%C3%A9", out.items);
}

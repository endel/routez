//! nginx-style `$name` / `${name}` variables in config strings: `return`'s
//! `location`, the values of `add_headers` and `proxy_set_headers`, and
//! `proxy_pass` URIs. `$1`..`$9` are the groups of the last regex that
//! matched (a regex location's), `$0` the whole match; percent-encoded like
//! `$uri`, and empty when unset.
const std = @import("std");
const common = @import("common.zig");
const router = @import("../router.zig");
const regex = @import("../regex.zig");

pub const Var = enum {
    /// `http` or `https`.
    scheme,
    /// Host from Host / :authority, lowercased, without the port; the
    /// server's first name when the request has none.
    host,
    /// The request target as received: path and query, still encoded.
    request_uri,
    /// Normalized path, percent-encoded again.
    uri,
    /// Query string without the `?`.
    args,
    /// `?` when there is a query string, else empty.
    is_args,
    /// Client IP address.
    remote_addr,
    /// The user `auth_basic` let in; empty otherwise.
    remote_user,
    /// `SUCCESS` when the client presented a certificate that verified
    /// against the server's `tls.client_ca`, else `NONE`.
    ssl_client_verify,
    /// The client certificate's subject, RFC 4514 (`CN=alice,O=Example`).
    ssl_client_s_dn,
    /// The client certificate's issuer, RFC 4514.
    ssl_client_i_dn,
    /// The client certificate's serial number, uppercase hex.
    ssl_client_serial,
    /// SHA-1 of the client certificate (DER), lowercase hex.
    ssl_client_fingerprint,

    /// Empty for this request means unset: logged as `-`.
    pub fn optional(v: Var) bool {
        return switch (v) {
            .remote_user, .ssl_client_s_dn, .ssl_client_i_dn, .ssl_client_serial, .ssl_client_fingerprint => true,
            else => false,
        };
    }
};

/// The verified client certificate, as the `ssl_client_*` variables show it.
pub const ClientCert = struct {
    s_dn: []const u8 = "",
    i_dn: []const u8 = "",
    serial: []const u8 = "",
    fingerprint: []const u8 = "",
};

/// What the variables read from one request.
pub const Request = struct {
    scheme: []const u8,
    authority: []const u8,
    default_host: []const u8,
    target: []const u8,
    path: []const u8,
    query: ?[]const u8,
    remote_addr: []const u8,
    remote_user: []const u8 = "",
    client_cert: ?*const ClientCert = null,
    captures: ?*const regex.Captures = null,
};

pub const TemplateError = error{ UnknownVariable, BadVariable };

pub fn has(template: []const u8) bool {
    return std.mem.indexOfScalar(u8, template, '$') != null;
}

/// One piece of a template: literal text, a variable or a regex group.
const Part = union(enum) { text: []const u8, variable: Var, capture: u8 };

/// A template split into literal text and variable names, whatever the
/// names; other templates (the access log's) accept more of them.
pub const Scanner = struct {
    s: []const u8,
    i: usize = 0,

    pub const Token = union(enum) { text: []const u8, name: []const u8 };

    pub fn next(self: *Scanner) TemplateError!?Token {
        const s = self.s;
        if (self.i >= s.len) return null;
        if (s[self.i] != '$') {
            const end = std.mem.indexOfScalarPos(u8, s, self.i, '$') orelse s.len;
            defer self.i = end;
            return .{ .text = s[self.i..end] };
        }
        var start = self.i + 1;
        var end: usize = undefined;
        if (start < s.len and s[start] == '{') {
            start += 1;
            const close = std.mem.indexOfScalarPos(u8, s, start, '}') orelse return error.BadVariable;
            end = close;
            self.i = close + 1;
        } else if (start < s.len and std.ascii.isDigit(s[start])) {
            // `$1abc` is group 1, then text.
            end = start + 1;
            self.i = end;
        } else {
            end = start;
            while (end < s.len and isNameChar(s[end])) end += 1;
            self.i = end;
        }
        if (end == start) return error.BadVariable;
        return .{ .name = s[start..end] };
    }

    fn isNameChar(c: u8) bool {
        return std.ascii.isAlphanumeric(c) or c == '_';
    }
};

const Iterator = struct {
    scanner: Scanner,

    fn next(self: *Iterator) TemplateError!?Part {
        return switch (try self.scanner.next() orelse return null) {
            .text => |t| .{ .text = t },
            .name => |n| if (n.len == 1 and std.ascii.isDigit(n[0]))
                .{ .capture = n[0] - '0' }
            else
                .{ .variable = std.meta.stringToEnum(Var, n) orelse return error.UnknownVariable },
        };
    }
};

/// Check at config load that every variable in `template` exists.
pub fn validate(template: []const u8) TemplateError!void {
    var it: Iterator = .{ .scanner = .{ .s = template } };
    while (try it.next()) |_| {}
}

/// Expand a validated template. The result is checked to be a valid field
/// value, so a request can never smuggle CR or LF into a header through it.
pub fn expand(alloc: std.mem.Allocator, template: []const u8, req: Request) error{ OutOfMemory, InvalidValue }![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it: Iterator = .{ .scanner = .{ .s = template } };
    while (it.next() catch return error.InvalidValue) |part| switch (part) {
        .text => |t| try out.appendSlice(alloc, t),
        .variable => |v| try append(alloc, &out, v, req),
        .capture => |g| if (req.captures) |c| if (c.get(g)) |text| try router.encodePath(text, &out, alloc),
    };
    if (!common.isFieldValue(out.items)) return error.InvalidValue;
    return out.items;
}

pub fn append(alloc: std.mem.Allocator, out: *std.ArrayList(u8), v: Var, req: Request) !void {
    switch (v) {
        .scheme => try out.appendSlice(alloc, req.scheme),
        .host => {
            const h = hostOf(req.authority);
            const start = out.items.len;
            try out.appendSlice(alloc, if (h.len == 0) req.default_host else h);
            for (out.items[start..]) |*c| c.* = std.ascii.toLower(c.*);
        },
        .request_uri => try out.appendSlice(alloc, originForm(req.target)),
        .uri => try router.encodePath(req.path, out, alloc),
        .args => try out.appendSlice(alloc, req.query orelse ""),
        .is_args => if (req.query != null) try out.append(alloc, '?'),
        .remote_addr => try out.appendSlice(alloc, req.remote_addr),
        .remote_user => try out.appendSlice(alloc, req.remote_user),
        .ssl_client_verify => try out.appendSlice(alloc, if (req.client_cert != null) "SUCCESS" else "NONE"),
        .ssl_client_s_dn => if (req.client_cert) |c| try out.appendSlice(alloc, c.s_dn),
        .ssl_client_i_dn => if (req.client_cert) |c| try out.appendSlice(alloc, c.i_dn),
        .ssl_client_serial => if (req.client_cert) |c| try out.appendSlice(alloc, c.serial),
        .ssl_client_fingerprint => if (req.client_cert) |c| try out.appendSlice(alloc, c.fingerprint),
    }
}

/// The authority without its port; an IPv6 literal keeps its brackets.
fn hostOf(authority: []const u8) []const u8 {
    if (authority.len > 0 and authority[0] == '[') {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return authority;
        return authority[0 .. end + 1];
    }
    const h = if (std.mem.lastIndexOfScalar(u8, authority, ':')) |c| authority[0..c] else authority;
    return std.mem.trimEnd(u8, h, ".");
}

/// Path and query of an origin- or absolute-form target.
fn originForm(target: []const u8) []const u8 {
    if (target.len > 0 and target[0] == '/') return target;
    const after = (std.mem.indexOf(u8, target, "://") orelse return "/") + 3;
    const slash = std.mem.indexOfScalarPos(u8, target, after, '/') orelse return "/";
    return target[slash..];
}

const testing = std.testing;

test "validate" {
    try validate("https://$host$request_uri");
    try validate("${scheme}://x${uri}$is_args$args");
    try validate("no variables");
    try testing.expectError(error.UnknownVariable, validate("$hots"));
    try testing.expectError(error.BadVariable, validate("cost: $ 5"));
    try testing.expectError(error.BadVariable, validate("${host"));
    try testing.expectError(error.BadVariable, validate("trailing $"));
    try validate("/img/$1/${2}x$0");
}

test "regex groups" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const re = try regex.Regex.compile(a, "^/u/([^/]+)/(.*)$", .{}, null);
    var s = try regex.Scratch.init(a, re.states());
    var caps: regex.Captures = .{};
    try testing.expect(re.match("/u/al ice/p?q", &s, &caps));
    const req: Request = .{ .scheme = "http", .authority = "h", .default_host = "", .target = "/", .path = "/", .query = null, .remote_addr = "::1", .captures = &caps };
    try testing.expectEqualStrings("/al%20ice/p%3Fq/[]x", try expand(a, "/$1/${2}/[$3]x", req));
    try testing.expectEqualStrings("/u/al%20ice/p%3Fq1", try expand(a, "$01", req));
}

test "expand" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const req: Request = .{
        .scheme = "http",
        .authority = "Example.COM:8080",
        .default_host = "fallback",
        .target = "/a%20b/c?x=1&y",
        .path = "/a b/c",
        .query = "x=1&y",
        .remote_addr = "192.0.2.7",
    };
    try testing.expectEqualStrings("https://example.com/a%20b/c?x=1&y", try expand(a, "https://$host$request_uri", req));
    try testing.expectEqualStrings("http /a%20b/c?x=1&y 192.0.2.7", try expand(a, "$scheme ${uri}$is_args$args $remote_addr", req));

    var r2 = req;
    r2.authority = "[::1]:443";
    r2.query = null;
    r2.target = "http://h/p";
    try testing.expectEqualStrings("[::1] /p []", try expand(a, "$host $request_uri [$is_args$args]", r2));
    r2.authority = "";
    try testing.expectEqualStrings("fallback", try expand(a, "$host", r2));
}

test "expand refuses control characters" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const req: Request = .{
        .scheme = "https",
        .authority = "evil\r\nset-cookie: x",
        .default_host = "",
        .target = "/",
        .path = "/\r\n",
        .query = null,
        .remote_addr = "::1",
    };
    try testing.expectError(error.InvalidValue, expand(a, "https://$host/", req));
    // A decoded CR LF in the path is percent-encoded again.
    try testing.expectEqualStrings("/%0D%0A", try expand(a, "$uri", req));
}

test "client certificate and user variables" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var req: Request = .{
        .scheme = "https",
        .authority = "x",
        .default_host = "",
        .target = "/",
        .path = "/",
        .query = null,
        .remote_addr = "::1",
    };
    try testing.expectEqualStrings("NONE [] []", try expand(a, "$ssl_client_verify [$ssl_client_s_dn] [$remote_user]", req));
    const cert: ClientCert = .{ .s_dn = "CN=alice,O=Example", .i_dn = "CN=CA", .serial = "1001", .fingerprint = "ab" };
    req.client_cert = &cert;
    req.remote_user = "alice";
    try testing.expectEqualStrings("SUCCESS CN=alice,O=Example CN=CA 1001 ab alice", try expand(a, "$ssl_client_verify $ssl_client_s_dn $ssl_client_i_dn $ssl_client_serial $ssl_client_fingerprint $remote_user", req));
}

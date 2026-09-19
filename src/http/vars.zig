//! nginx-style `$name` / `${name}` variables in config strings: `return`'s
//! `location` and the values of `add_headers` and `proxy_set_headers`.
const std = @import("std");
const common = @import("common.zig");
const router = @import("../router.zig");

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
};

pub const TemplateError = error{ UnknownVariable, BadVariable };

pub fn has(template: []const u8) bool {
    return std.mem.indexOfScalar(u8, template, '$') != null;
}

/// One piece of a template: literal text or a variable.
const Part = union(enum) { text: []const u8, variable: Var };

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
            .name => |n| .{ .variable = std.meta.stringToEnum(Var, n) orelse return error.UnknownVariable },
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

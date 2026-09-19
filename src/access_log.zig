//! Access log formats: the built-in `main` line, nginx's `combined`, a
//! `json` object per line, or a template of `$variables`.
//!
//! A template may use the request variables of `http/vars.zig` and:
//!
//!   $status               response status (499: the client went away first)
//!   $body_bytes_sent      response body bytes sent, after compression
//!   $request_time         seconds from request head to the end, ms resolution
//!   $request              "$request_method $request_uri $protocol", as received
//!   $request_method       GET, POST, ...
//!   $protocol             HTTP/1.0, HTTP/1.1 or HTTP/3
//!   $upstream_addr        the upstream server that answered
//!   $request_completion   OK when the response was sent in full, else empty
//!   $time_iso8601         2026-09-18T20:00:32+00:00 (UTC)
//!   $time_local           18/Sep/2026:20:00:32 +0000 (UTC)
//!   $msec                 Unix time in seconds, ms resolution
//!   $http_<name>          a request header, `_` standing for `-`
//!
//! A variable without a value logs as `-`, or as an empty string under JSON
//! escaping.
const std = @import("std");
const config = @import("config.zig");
const vars = @import("http/vars.zig");
const common = @import("http/common.zig");

pub const LogVar = enum {
    status,
    body_bytes_sent,
    request_time,
    request,
    request_method,
    protocol,
    upstream_addr,
    request_completion,
    time_iso8601,
    time_local,
    msec,
};

const Part = union(enum) {
    text: []const u8,
    request: vars.Var,
    log: LogVar,
    /// Lowercase header name.
    header: []const u8,
};

pub const Template = struct {
    parts: []const Part,
    escape: config.LogEscape,
};

pub const Format = union(enum) {
    main,
    template: Template,
};

const combined = "$remote_addr - - [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

const json =
    \\{"time":"$time_iso8601","remote_addr":"$remote_addr","method":"$request_method","uri":"$request_uri","protocol":"$protocol","status":$status,"body_bytes_sent":$body_bytes_sent,"request_time":$request_time,"host":"$host","referer":"$http_referer","user_agent":"$http_user_agent","upstream_addr":"$upstream_addr","request_completion":"$request_completion"}
;

pub const Error = vars.TemplateError || error{NoVariable};

/// Check a configured format at load.
pub fn validate(text: []const u8) Error!void {
    if (preset(text) != null) return;
    if (!vars.has(text)) return error.NoVariable;
    var sc: vars.Scanner = .{ .s = text };
    while (try sc.next()) |tok| switch (tok) {
        .text => {},
        .name => |n| _ = classify(n, null) catch |err| switch (err) {
            error.OutOfMemory => unreachable, // no allocation without an arena
            else => |e| return e,
        },
    };
}

const Preset = struct { text: []const u8, escape: ?config.LogEscape };

fn preset(text: []const u8) ?Preset {
    if (std.mem.eql(u8, text, "main")) return .{ .text = "", .escape = null };
    if (std.mem.eql(u8, text, "combined")) return .{ .text = combined, .escape = .default };
    if (std.mem.eql(u8, text, "json")) return .{ .text = json, .escape = .json };
    return null;
}

/// Compile a validated format.
pub fn compile(arena: std.mem.Allocator, text: []const u8, escape: config.LogEscape) (Error || error{OutOfMemory})!Format {
    var source = text;
    var esc = escape;
    if (preset(text)) |p| {
        if (p.escape == null) return .main;
        source = p.text;
        esc = p.escape.?;
    }
    var parts: std.ArrayList(Part) = .empty;
    var sc: vars.Scanner = .{ .s = source };
    while (try sc.next()) |tok| try parts.append(arena, switch (tok) {
        .text => |t| .{ .text = t },
        .name => |n| try classify(n, arena),
    });
    return .{ .template = .{ .parts = parts.items, .escape = esc } };
}

/// With `arena` null, only checks that the name exists.
fn classify(name: []const u8, arena: ?std.mem.Allocator) (Error || error{OutOfMemory})!Part {
    if (std.meta.stringToEnum(vars.Var, name)) |v| return .{ .request = v };
    if (std.meta.stringToEnum(LogVar, name)) |v| return .{ .log = v };
    if (std.mem.startsWith(u8, name, "http_") and name.len > "http_".len) {
        const a = arena orelse return .{ .header = "" };
        const h = try a.dupe(u8, name["http_".len..]);
        for (h) |*c| c.* = if (c.* == '_') '-' else std.ascii.toLower(c.*);
        return .{ .header = h };
    }
    return error.UnknownVariable;
}

/// What a line reads from one finished request.
pub const Entry = struct {
    req: vars.Request,
    method: []const u8,
    protocol: []const u8,
    /// Request headers, Host excluded.
    headers: []const common.Header,
    status: u16,
    body_bytes: u64,
    elapsed_ms: i64,
    upstream_addr: ?[]const u8,
    completed: bool,
    /// Wall clock at the end of the request, ms since the Unix epoch.
    now_ms: i64,

    fn header(self: *const Entry, name: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, name, "host")) return if (self.req.authority.len > 0) self.req.authority else null;
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }
};

/// One log line, newline included.
pub fn render(t: Template, alloc: std.mem.Allocator, e: *const Entry) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var scratch: std.ArrayList(u8) = .empty;
    for (t.parts) |part| {
        scratch.clearRetainingCapacity();
        const value: ?[]const u8 = switch (part) {
            .text => |text| {
                try out.appendSlice(alloc, text);
                continue;
            },
            .request => |v| blk: {
                vars.append(alloc, &scratch, v, e.req) catch return error.OutOfMemory;
                break :blk scratch.items;
            },
            .header => |name| e.header(name),
            .log => |v| try logValue(alloc, &scratch, v, e),
        };
        const bytes = value orelse {
            if (t.escape == .default) try out.append(alloc, '-');
            continue;
        };
        switch (t.escape) {
            .default => try escapeDefault(alloc, &out, bytes),
            .json => try escapeJson(alloc, &out, bytes),
        }
    }
    try out.append(alloc, '\n');
    return out.items;
}

fn logValue(alloc: std.mem.Allocator, buf: *std.ArrayList(u8), v: LogVar, e: *const Entry) !?[]const u8 {
    const w = struct {
        fn print(a: std.mem.Allocator, b: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) ![]const u8 {
            try b.print(a, fmt, args);
            return b.items;
        }
    }.print;
    return switch (v) {
        .status => try w(alloc, buf, "{d}", .{e.status}),
        .body_bytes_sent => try w(alloc, buf, "{d}", .{e.body_bytes}),
        .request_time => try w(alloc, buf, "{d}.{d:0>3}", .{ @divTrunc(e.elapsed_ms, 1000), @as(u64, @intCast(@mod(e.elapsed_ms, 1000))) }),
        .request => try w(alloc, buf, "{s} {s} {s}", .{ e.method, e.req.target, e.protocol }),
        .request_method => e.method,
        .protocol => e.protocol,
        .upstream_addr => e.upstream_addr,
        .request_completion => if (e.completed) "OK" else "",
        .time_iso8601, .time_local => blk: {
            const t = civil(@divFloor(e.now_ms, 1000));
            break :blk if (v == .time_iso8601)
                try w(alloc, buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}+00:00", .{ t.year, t.month, t.day, t.hour, t.minute, t.second })
            else
                try w(alloc, buf, "{d:0>2}/{s}/{d:0>4}:{d:0>2}:{d:0>2}:{d:0>2} +0000", .{ t.day, month_names[t.month - 1], t.year, t.hour, t.minute, t.second });
        },
        .msec => try w(alloc, buf, "{d}.{d:0>3}", .{ @divFloor(e.now_ms, 1000), @as(u64, @intCast(@mod(e.now_ms, 1000))) }),
    };
}

const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

pub const Civil = struct { year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8 };

pub fn civil(unix_s: i64) Civil {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(unix_s, 0)) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return .{
        .year = yd.year,
        .month = md.month.numeric(),
        .day = md.day_index + 1,
        .hour = ds.getHoursIntoDay(),
        .minute = ds.getMinutesIntoHour(),
        .second = ds.getSecondsIntoMinute(),
    };
}

/// nginx's default: `"`, `\` and bytes outside printable ASCII as `\xHH`.
fn escapeDefault(alloc: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |c| {
        if (c == '"' or c == '\\' or c < 0x20 or c >= 0x7f) {
            try out.print(alloc, "\\x{X:0>2}", .{c});
        } else {
            try out.append(alloc, c);
        }
    }
}

/// The inside of a JSON string. Bytes that aren't UTF-8 are written as the
/// code points of the same value, so the line always parses.
fn escapeJson(alloc: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
    const utf8 = std.unicode.utf8ValidateSlice(s);
    for (s) |c| switch (c) {
        '"' => try out.appendSlice(alloc, "\\\""),
        '\\' => try out.appendSlice(alloc, "\\\\"),
        '\n' => try out.appendSlice(alloc, "\\n"),
        '\r' => try out.appendSlice(alloc, "\\r"),
        '\t' => try out.appendSlice(alloc, "\\t"),
        0...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => try out.print(alloc, "\\u{x:0>4}", .{c}),
        else => if (c >= 0x80 and !utf8) try out.print(alloc, "\\u{x:0>4}", .{c}) else try out.append(alloc, c),
    };
}

const testing = std.testing;

fn testEntry() Entry {
    return .{
        .req = .{
            .scheme = "https",
            .authority = "Example.com:8443",
            .default_host = "fallback",
            .target = "/a%20b?x=\"1\"",
            .path = "/a b",
            .query = "x=\"1\"",
            .remote_addr = "192.0.2.7",
        },
        .method = "GET",
        .protocol = "HTTP/1.1",
        .headers = &.{ .{ .name = "User-Agent", .value = "curl/8 \"quoted\"\x01" }, .{ .name = "X-Id", .value = "caf\xc3\xa9" } },
        .status = 200,
        .body_bytes = 1234,
        .elapsed_ms = 1042,
        .upstream_addr = null,
        .completed = true,
        .now_ms = 1789761632_123,
    };
}

test "validate" {
    try validate("main");
    try validate("json");
    try validate("combined");
    try validate("$remote_addr $status ${request_time}s $http_x_forwarded_for");
    try testing.expectError(error.UnknownVariable, validate("$remote_adr"));
    try testing.expectError(error.UnknownVariable, validate("$http_"));
    try testing.expectError(error.BadVariable, validate("${status"));
    try testing.expectError(error.NoVariable, validate("jsonx"));
}

test "combined and a custom template" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const e = testEntry();
    try testing.expectEqual(Format.main, try compile(a, "main", .default));

    const c = (try compile(a, "combined", .json)).template;
    try testing.expectEqualStrings(
        "192.0.2.7 - - [18/Sep/2026:20:00:32 +0000] \"GET /a%20b?x=\\x221\\x22 HTTP/1.1\" 200 1234 \"-\" \"curl/8 \\x22quoted\\x22\\x01\"\n",
        try render(c, a, &e),
    );

    const t = (try compile(a, "$host|$request_time|$msec|$time_iso8601|$upstream_addr|$request_completion|$http_x_id", .default)).template;
    try testing.expectEqualStrings("example.com|1.042|1789761632.123|2026-09-18T20:00:32+00:00|-|OK|caf\\xC3\\xA9\n", try render(t, a, &e));
}

test "json lines parse, whatever the request holds" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var e = testEntry();
    e.upstream_addr = "10.0.0.1:80";
    e.headers = &.{.{ .name = "user-agent", .value = "a\"b\\c\n\xff\x7f" }};
    const t = (try compile(a, "json", .default)).template;
    const line = try render(t, a, &e);
    const parsed = try std.json.parseFromSlice(std.json.Value, a, line, .{});
    const o = parsed.value.object;
    try testing.expectEqual(@as(i64, 200), o.get("status").?.integer);
    try testing.expectEqual(@as(i64, 1234), o.get("body_bytes_sent").?.integer);
    try testing.expectEqual(@as(f64, 1.042), o.get("request_time").?.float);
    try testing.expectEqualStrings("/a%20b?x=\"1\"", o.get("uri").?.string);
    try testing.expectEqualStrings("10.0.0.1:80", o.get("upstream_addr").?.string);
    try testing.expectEqualStrings("", o.get("referer").?.string);
    try testing.expectEqualStrings("a\"b\\c\n\u{ff}\x7f", o.get("user_agent").?.string);
}

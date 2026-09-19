//! The client behind a trusted proxy, as nginx's realip module finds it.
//!
//! A request from an address in `real_ip_from` may name its client in a
//! header (`X-Forwarded-For` by default): the rightmost address in it, or
//! with `real_ip_recursive` the rightmost one that isn't itself trusted.
//! From anyone else the header means nothing. The PROXY protocol, the other
//! way a proxy passes the client on, is per connection; see
//! `net/proxy_protocol.zig`.
const std = @import("std");
const access = @import("access.zig");

pub const Trust = struct {
    from: []const access.Rule = &.{},
    /// Null when only the PROXY protocol is used.
    header: ?[]const u8 = null,
    recursive: bool = false,

    pub fn trusted(self: *const Trust, ip: [16]u8) bool {
        for (self.from) |r| if (r.matches(ip)) return true;
        return false;
    }
};

/// The client a request from `peer` names in `trust.header`, walking every
/// such header from the last; null when the peer isn't trusted, there is
/// no header, or an address in the walk doesn't parse (the peer stands, as
/// in nginx). `headers` holds anything with `name` and `value`.
pub fn fromHeaders(trust: *const Trust, peer: [16]u8, headers: anytype) ?[16]u8 {
    const name = trust.header orelse return null;
    if (trust.from.len == 0 or !trust.trusted(peer)) return null;
    var found: ?[16]u8 = null;
    var i = headers.len;
    while (i > 0) {
        i -= 1;
        if (!std.ascii.eqlIgnoreCase(headers[i].name, name)) continue;
        var rest: []const u8 = headers[i].value;
        while (lastEntry(&rest)) |entry| {
            const ip = parseEntry(entry) orelse return null;
            found = ip;
            if (!trust.recursive or !trust.trusted(ip)) return ip;
        }
    }
    return found;
}

/// Pop the last non-empty comma-separated entry, trimmed.
fn lastEntry(rest: *[]const u8) ?[]const u8 {
    while (rest.len > 0) {
        const comma = std.mem.lastIndexOfScalar(u8, rest.*, ',');
        const entry = std.mem.trim(u8, rest.*[if (comma) |c| c + 1 else 0..], " \t");
        rest.* = rest.*[0 .. comma orelse 0];
        if (entry.len > 0) return entry;
    }
    return null;
}

/// An IPv4 or IPv6 address, optionally with a port (`192.0.2.1:80`,
/// `[2001:db8::1]:80`); IPv4 in mapped form.
pub fn parseEntry(text: []const u8) ?[16]u8 {
    var host = text;
    if (host.len > 0 and host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return null;
        if (close + 1 < host.len and (host[close + 1] != ':' or !isPort(host[close + 2 ..]))) return null;
        host = host[1..close];
        return parse6(host);
    }
    const colons = std.mem.count(u8, host, ":");
    if (colons == 1) {
        const c = std.mem.indexOfScalar(u8, host, ':').?;
        if (!isPort(host[c + 1 ..])) return null;
        host = host[0..c];
    } else if (colons > 1) {
        return parse6(host);
    }
    const a = std.Io.net.Ip4Address.parse(host, 0) catch return null;
    return .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3] };
}

fn parse6(text: []const u8) ?[16]u8 {
    if (std.mem.indexOfScalar(u8, text, '%') != null) return null;
    const a = std.Io.net.Ip6Address.parse(text, 0) catch return null;
    return a.bytes;
}

fn isPort(text: []const u8) bool {
    if (text.len == 0 or text.len > 5) return false;
    for (text) |c| if (!std.ascii.isDigit(c)) return false;
    _ = std.fmt.parseInt(u16, text, 10) catch return false;
    return true;
}

const testing = std.testing;

const H = struct { name: []const u8, value: []const u8 };

fn v4(a: u8, b: u8, c: u8, d: u8) [16]u8 {
    return .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d };
}

fn trustOf(recursive: bool, rules: []const access.Rule) Trust {
    return .{ .from = rules, .header = "x-forwarded-for", .recursive = recursive };
}

test "only a trusted peer's header counts" {
    const rules = [_]access.Rule{ try access.parse(.allow, "10.0.0.0/8"), try access.parse(.allow, "2001:db8::/32") };
    const t = trustOf(false, &rules);
    const hs = [_]H{.{ .name = "X-Forwarded-For", .value = "203.0.113.9" }};
    try testing.expectEqual(v4(203, 0, 113, 9), fromHeaders(&t, v4(10, 1, 2, 3), &hs).?);
    try testing.expectEqual(@as(?[16]u8, null), fromHeaders(&t, v4(192, 0, 2, 1), &hs));
    const six = (try std.Io.net.Ip6Address.parse("2001:db8::7", 0)).bytes;
    try testing.expectEqual(v4(203, 0, 113, 9), fromHeaders(&t, six, &hs).?);
    try testing.expectEqual(@as(?[16]u8, null), fromHeaders(&t, v4(10, 1, 2, 3), &[_]H{.{ .name = "x-real-ip", .value = "1.2.3.4" }}));
    const no_header: Trust = .{ .from = &rules };
    try testing.expectEqual(@as(?[16]u8, null), fromHeaders(&no_header, v4(10, 1, 2, 3), &hs));
}

test "rightmost, or recursive past trusted proxies" {
    const rules = [_]access.Rule{try access.parse(.allow, "10.0.0.0/8")};
    const peer = v4(10, 0, 0, 1);
    const chain = [_]H{
        .{ .name = "x-forwarded-for", .value = "198.51.100.1, 203.0.113.9" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = "x-forwarded-for", .value = " 10.9.9.9 ,,10.0.0.2:8080 " },
    };
    try testing.expectEqual(v4(10, 0, 0, 2), fromHeaders(&trustOf(false, &rules), peer, &chain).?);
    try testing.expectEqual(v4(203, 0, 113, 9), fromHeaders(&trustOf(true, &rules), peer, &chain).?);
    // Every hop trusted: the leftmost.
    const all = [_]H{.{ .name = "x-forwarded-for", .value = "10.0.0.5, 10.0.0.6" }};
    try testing.expectEqual(v4(10, 0, 0, 5), fromHeaders(&trustOf(true, &rules), peer, &all).?);
    // Garbage in the walk: the peer stands.
    const junk = [_]H{.{ .name = "x-forwarded-for", .value = "evil, 10.0.0.6" }};
    try testing.expectEqual(@as(?[16]u8, null), fromHeaders(&trustOf(true, &rules), peer, &junk));
    try testing.expectEqual(v4(10, 0, 0, 6), fromHeaders(&trustOf(false, &rules), peer, &junk).?);
    const empty = [_]H{.{ .name = "x-forwarded-for", .value = " , " }};
    try testing.expectEqual(@as(?[16]u8, null), fromHeaders(&trustOf(true, &rules), peer, &empty));
}

test "entries" {
    const ok = [_][]const u8{ "192.0.2.1", "192.0.2.1:80", "2001:db8::1", "[2001:db8::1]", "[2001:db8::1]:443", "::ffff:192.0.2.1" };
    for (ok) |e| if (parseEntry(e) == null) {
        std.debug.print("rejected '{s}'\n", .{e});
        return error.TestUnexpectedResult;
    };
    try testing.expectEqual(v4(192, 0, 2, 1), parseEntry("::ffff:192.0.2.1").?);
    const bad = [_][]const u8{ "", "unknown", "192.0.2.1:", "192.0.2.1:99999", "192.0.2.1:8x", "[2001:db8::1", "[2001:db8::1]80", "fe80::1%en0", "[::1]:", "192.0.2", "_hidden" };
    for (bad) |e| if (parseEntry(e) != null) {
        std.debug.print("accepted '{s}'\n", .{e});
        return error.TestUnexpectedResult;
    };
}

//! IP allow/deny rules, nginx-style: checked in order, the first rule whose
//! network holds the client decides, and a client no rule matches is
//! allowed. Addresses are compared as IPv6, IPv4 in its mapped form, so
//! `10.0.0.0/8` also matches a dual-stack socket's `::ffff:10.1.2.3`.
//!
//! The client is the TCP or QUIC peer, or the one a `real_ip_from` proxy
//! names (`realip.zig`).
const std = @import("std");

pub const Action = enum { allow, deny };

/// A compiled rule: the network as 16 bytes and a prefix length over them.
pub const Rule = struct {
    action: Action,
    net: [16]u8,
    /// Leading bits of `net` that must match; 0 matches everything.
    bits: u8,

    pub fn matches(self: Rule, ip: [16]u8) bool {
        const full: usize = self.bits / 8;
        if (!std.mem.eql(u8, ip[0..full], self.net[0..full])) return false;
        const rest: u3 = @intCast(self.bits % 8);
        if (rest == 0) return true;
        const m: u8 = @as(u8, 0xff) << @intCast(8 - @as(u4, rest));
        return ip[full] & m == self.net[full];
    }
};

pub const ParseError = error{InvalidAddress};

/// `"all"`, an address (`192.0.2.1`, `2001:db8::1`), or a network in CIDR
/// form (`10.0.0.0/8`, `2001:db8::/32`). Host bits past the prefix are
/// ignored, as nginx does; `hostBitsSet` reports them.
pub fn parse(action: Action, text: []const u8) ParseError!Rule {
    if (std.mem.eql(u8, text, "all")) return .{ .action = action, .net = @splat(0), .bits = 0 };
    const slash = std.mem.indexOfScalar(u8, text, '/');
    const addr_text = text[0 .. slash orelse text.len];
    var net: [16]u8 = @splat(0);
    var is_v4 = false;
    if (std.Io.net.Ip4Address.parse(addr_text, 0)) |a| {
        net[10] = 0xff;
        net[11] = 0xff;
        net[12..16].* = a.bytes;
        is_v4 = true;
    } else |_| {
        // No zone: it would mean nothing against a peer address.
        if (std.mem.indexOfScalar(u8, addr_text, '%') != null) return error.InvalidAddress;
        const a = std.Io.net.Ip6Address.parse(addr_text, 0) catch return error.InvalidAddress;
        net = a.bytes;
    }
    const max: u8 = if (is_v4) 32 else 128;
    var bits: u8 = max;
    if (slash) |s| {
        const len_text = text[s + 1 ..];
        if (len_text.len == 0 or len_text.len > 3) return error.InvalidAddress;
        for (len_text) |c| if (!std.ascii.isDigit(c)) return error.InvalidAddress;
        bits = std.fmt.parseInt(u8, len_text, 10) catch return error.InvalidAddress;
        if (bits > max) return error.InvalidAddress;
    }
    if (is_v4) bits += 96;
    var rule: Rule = .{ .action = action, .net = net, .bits = bits };
    mask(&rule.net, bits);
    return rule;
}

/// Whether `text` names a network with bits set past its prefix
/// (`10.1.0.0/8`), which `parse` drops.
pub fn hostBitsSet(action: Action, text: []const u8) bool {
    const rule = parse(action, text) catch return false;
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return false;
    const full = parse(action, text[0..slash]) catch return false;
    return !std.mem.eql(u8, &rule.net, &full.net);
}

fn mask(net: *[16]u8, bits: u8) void {
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const lo: usize = i * 8;
        if (bits >= lo + 8) continue;
        if (bits <= lo) {
            net[i] = 0;
        } else {
            net[i] &= @as(u8, 0xff) << @intCast(8 - (bits - lo));
        }
    }
}

/// The action of the first rule matching `ip`; allow when none does.
pub fn check(rules: []const Rule, ip: [16]u8) Action {
    for (rules) |r| if (r.matches(ip)) return r.action;
    return .allow;
}

const testing = std.testing;

fn v4(a: u8, b: u8, c: u8, d: u8) [16]u8 {
    return .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d };
}

fn v6(text: []const u8) [16]u8 {
    return (std.Io.net.Ip6Address.parse(text, 0) catch unreachable).bytes;
}

test "first match wins, no match allows" {
    const rules = [_]Rule{
        try parse(.deny, "10.1.2.3"),
        try parse(.allow, "10.0.0.0/8"),
        try parse(.allow, "2001:db8::/32"),
        try parse(.deny, "all"),
    };
    try testing.expectEqual(Action.deny, check(&rules, v4(10, 1, 2, 3)));
    try testing.expectEqual(Action.allow, check(&rules, v4(10, 200, 0, 1)));
    try testing.expectEqual(Action.deny, check(&rules, v4(11, 0, 0, 1)));
    try testing.expectEqual(Action.allow, check(&rules, v6("2001:db8:ffff::1")));
    try testing.expectEqual(Action.deny, check(&rules, v6("2001:db9::1")));
    try testing.expectEqual(Action.allow, check(rules[0..0], v4(1, 2, 3, 4)));
}

test "IPv4 rules match v4-mapped IPv6 peers, and IPv6 ones don't match IPv4" {
    const r = try parse(.allow, "192.0.2.0/24");
    try testing.expect(r.matches(v6("::ffff:192.0.2.77")));
    try testing.expect(!r.matches(v4(192, 0, 3, 1)));
    const six = try parse(.allow, "::/1");
    try testing.expect(six.matches(v4(1, 2, 3, 4))); // ::ffff:0:0/96 is inside ::/1
    try testing.expect(!(try parse(.allow, "2000::/3")).matches(v4(1, 2, 3, 4)));
    const mapped = try parse(.deny, "::ffff:10.0.0.0/104");
    try testing.expect(mapped.matches(v4(10, 9, 8, 7)));
}

test "prefix lengths at every boundary" {
    try testing.expect((try parse(.allow, "0.0.0.0/0")).matches(v4(255, 1, 2, 3)));
    try testing.expect(!(try parse(.allow, "0.0.0.0/0")).matches(v6("2001:db8::1")));
    try testing.expect((try parse(.allow, "10.0.0.0/7")).matches(v4(11, 255, 0, 0)));
    try testing.expect(!(try parse(.allow, "10.0.0.0/7")).matches(v4(12, 0, 0, 0)));
    try testing.expect((try parse(.allow, "10.0.0.128/25")).matches(v4(10, 0, 0, 200)));
    try testing.expect(!(try parse(.allow, "10.0.0.128/25")).matches(v4(10, 0, 0, 127)));
    try testing.expect((try parse(.allow, "2001:db8::1/128")).matches(v6("2001:db8::1")));
    try testing.expect(!(try parse(.allow, "2001:db8::1/128")).matches(v6("2001:db8::2")));
    try testing.expect((try parse(.allow, "::/0")).matches(v6("ffff::")));
}

test "host bits are dropped and reported" {
    const r = try parse(.allow, "10.1.0.0/8");
    try testing.expectEqualSlices(u8, &v4(10, 0, 0, 0), &r.net);
    try testing.expect(hostBitsSet(.allow, "10.1.0.0/8"));
    try testing.expect(!hostBitsSet(.allow, "10.0.0.0/8"));
    try testing.expect(!hostBitsSet(.allow, "10.1.2.3"));
}

test "malformed rules" {
    const bad = [_][]const u8{
        "",               "10.0.0.0/",   "10.0.0.0/33", "10.0.0.0/-1",  "10.0.0.0/+8", "10.0.0/8",
        "2001:db8::/129", "fe80::1%en0", "::1/08x",     "10.0.0.0/8/8", "all/0",       "256.0.0.1",
        "localhost",      "10.0.0.0 ",   " 10.0.0.0",
    };
    for (bad) |text| {
        if (parse(.allow, text)) |_| {
            std.debug.print("accepted '{s}'\n", .{text});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

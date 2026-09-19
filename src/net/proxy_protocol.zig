//! PROXY protocol headers (v1 text, v2 binary), which a load balancer sends
//! ahead of a TCP connection's own bytes to pass on the client's address.
//! Spec: https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt
//!
//! Parsing is strict: anything the spec doesn't allow fails, and so does a
//! v2 header longer than `v2_max` (the spec's own ceiling is 64 KiB, far
//! beyond what load balancers send).
const std = @import("std");

/// Longest v1 line, CRLF included (the spec's bound).
pub const v1_max = 107;
/// Longest v2 header we accept: 16 fixed bytes, addresses and TLVs.
pub const v2_max = 4096;

pub const v2_signature = "\r\n\r\n\x00\r\nQUIT\n";

pub const Address = struct {
    /// IPv4 in mapped form.
    ip: [16]u8,
    port: u16,
};

pub const Header = struct {
    /// Bytes the header takes; the connection's own data follows.
    len: usize,
    /// The client; null for a LOCAL or UNKNOWN connection (the load
    /// balancer's own, such as a health check) or a UNIX socket: the TCP
    /// peer's address stands.
    source: ?Address,
};

pub const Error = error{Invalid};

/// The header at the start of `buf`; null while it could still complete.
pub fn parse(buf: []const u8) Error!?Header {
    if (buf.len == 0) return null;
    return switch (buf[0]) {
        'P' => parseV1(buf),
        '\r' => parseV2(buf),
        else => error.Invalid,
    };
}

fn parseV1(buf: []const u8) Error!?Header {
    const prefix = "PROXY ";
    const n = @min(buf.len, prefix.len);
    if (!std.mem.eql(u8, buf[0..n], prefix[0..n])) return error.Invalid;
    const window = buf[0..@min(buf.len, v1_max)];
    const lf = std.mem.indexOfScalar(u8, window, '\n') orelse {
        if (buf.len >= v1_max) return error.Invalid;
        // No control byte but a CR that the LF may yet follow.
        for (window, 0..) |c, i| if (c < 0x20 and !(c == '\r' and i == window.len - 1)) return error.Invalid;
        return null;
    };
    if (lf < prefix.len + 1 or buf[lf - 1] != '\r') return error.Invalid;
    const line = buf[prefix.len .. lf - 1];
    for (line) |c| if (c < 0x20 or c > 0x7e) return error.Invalid;
    const len = lf + 1;

    var it = std.mem.splitScalar(u8, line, ' ');
    const proto = it.next().?;
    // The rest of an UNKNOWN line is to be ignored.
    if (std.mem.eql(u8, proto, "UNKNOWN")) return .{ .len = len, .source = null };
    const v6 = if (std.mem.eql(u8, proto, "TCP4")) false else if (std.mem.eql(u8, proto, "TCP6")) true else return error.Invalid;
    const src = it.next() orelse return error.Invalid;
    const dst = it.next() orelse return error.Invalid;
    const sport = it.next() orelse return error.Invalid;
    const dport = it.next() orelse return error.Invalid;
    if (it.next() != null) return error.Invalid;
    const ip = try parseIp(src, v6);
    _ = try parseIp(dst, v6);
    const port = try parsePort(sport);
    _ = try parsePort(dport);
    return .{ .len = len, .source = .{ .ip = ip, .port = port } };
}

fn parseIp(text: []const u8, v6: bool) Error![16]u8 {
    if (!v6) {
        const a = std.Io.net.Ip4Address.parse(text, 0) catch return error.Invalid;
        return mapped(a.bytes);
    }
    if (std.mem.indexOfScalar(u8, text, '%') != null) return error.Invalid;
    const a = std.Io.net.Ip6Address.parse(text, 0) catch return error.Invalid;
    return a.bytes;
}

/// 0 to 65535 in decimal, without leading zeros.
fn parsePort(text: []const u8) Error!u16 {
    if (text.len == 0 or text.len > 5) return error.Invalid;
    if (text.len > 1 and text[0] == '0') return error.Invalid;
    for (text) |c| if (!std.ascii.isDigit(c)) return error.Invalid;
    return std.fmt.parseInt(u16, text, 10) catch error.Invalid;
}

fn mapped(a: [4]u8) [16]u8 {
    return .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a[0], a[1], a[2], a[3] };
}

fn parseV2(buf: []const u8) Error!?Header {
    const n = @min(buf.len, v2_signature.len);
    if (!std.mem.eql(u8, buf[0..n], v2_signature[0..n])) return error.Invalid;
    if (buf.len < 16) return null;
    const ver_cmd = buf[12];
    if (ver_cmd >> 4 != 2) return error.Invalid;
    const cmd = ver_cmd & 0x0f;
    if (cmd > 1) return error.Invalid;
    const fam = buf[13];
    const payload_len = std.mem.readInt(u16, buf[14..16], .big);
    const len = 16 + @as(usize, payload_len);
    if (len > v2_max) return error.Invalid;
    if (buf.len < len) return null;
    const payload = buf[16..len];

    // LOCAL: the balancer's own connection; the address block means nothing.
    if (cmd == 0) return .{ .len = len, .source = null };
    const addr_len: usize, const source: ?Address = switch (fam) {
        // UNSPEC: the receiver uses the connection's own addresses.
        0x00 => .{ 0, null },
        0x11 => blk: {
            if (payload.len < 12) return error.Invalid;
            break :blk .{ 12, .{ .ip = mapped(payload[0..4].*), .port = std.mem.readInt(u16, payload[8..10], .big) } };
        },
        0x21 => blk: {
            if (payload.len < 36) return error.Invalid;
            break :blk .{ 36, .{ .ip = payload[0..16].*, .port = std.mem.readInt(u16, payload[32..34], .big) } };
        },
        // UNIX stream sockets: nothing an IP rule could match.
        0x31 => blk: {
            if (payload.len < 216) return error.Invalid;
            break :blk .{ 216, null };
        },
        // Datagrams (0x12, 0x22, 0x32) don't come over a TCP listener.
        else => return error.Invalid,
    };
    try checkTlvs(payload[addr_len..]);
    return .{ .len = len, .source = source };
}

/// Type, 16-bit length, value, back to back to the end: nothing left over.
fn checkTlvs(tlvs: []const u8) Error!void {
    var rest = tlvs;
    while (rest.len > 0) {
        if (rest.len < 3) return error.Invalid;
        const l = std.mem.readInt(u16, rest[1..3], .big);
        if (rest.len - 3 < l) return error.Invalid;
        rest = rest[3 + l ..];
    }
}

const testing = std.testing;

fn v4(a: u8, b: u8, c: u8, d: u8) [16]u8 {
    return mapped(.{ a, b, c, d });
}

test "v1 TCP4, TCP6 and UNKNOWN" {
    const tcp4 = "PROXY TCP4 198.51.100.4 192.0.2.1 56324 443\r\nGET /";
    const h = (try parse(tcp4)).?;
    try testing.expectEqual(@as(usize, 45), h.len);
    try testing.expectEqualSlices(u8, &v4(198, 51, 100, 4), &h.source.?.ip);
    try testing.expectEqual(@as(u16, 56324), h.source.?.port);

    const tcp6 = "PROXY TCP6 2001:db8::5 2001:db8::1 65535 0\r\n";
    const h6 = (try parse(tcp6)).?;
    try testing.expectEqual(tcp6.len, h6.len);
    try testing.expectEqualSlices(u8, &(try std.Io.net.Ip6Address.parse("2001:db8::5", 0)).bytes, &h6.source.?.ip);

    const unknown = "PROXY UNKNOWN ffff::1 whatever\r\n";
    try testing.expectEqual(@as(?Address, null), (try parse(unknown)).?.source);
    try testing.expectEqual(@as(usize, 15), (try parse("PROXY UNKNOWN\r\n")).?.len);
}

test "v1 incomplete, then complete" {
    const full = "PROXY TCP4 10.0.0.1 10.0.0.2 1 2\r\n";
    for (0..full.len) |i| try testing.expectEqual(@as(?Header, null), try parse(full[0..i]));
    try testing.expectEqual(full.len, (try parse(full)).?.len);
}

test "v1 malformed" {
    const bad = [_][]const u8{
        "GET / HTTP/1.1\r\n",
        "PROXX",
        "PROXY TCP4 10.0.0.1 10.0.0.2 1 2\n",
        "PROXY TCP4 10.0.0.1 10.0.0.2 1\r\n",
        "PROXY TCP4 10.0.0.1 10.0.0.2 1 2 3\r\n",
        "PROXY TCP4  10.0.0.1 10.0.0.2 1 2\r\n",
        "PROXY TCP4 10.0.0.1 10.0.0.2 1 2 \r\n",
        "PROXY TCP4 2001:db8::1 10.0.0.2 1 2\r\n",
        "PROXY TCP6 10.0.0.1 2001:db8::1 1 2\r\n",
        "PROXY TCP6 fe80::1%en0 fe80::2 1 2\r\n",
        "PROXY TCP4 10.0.0.1 10.0.0.2 65536 2\r\n",
        "PROXY TCP4 10.0.0.1 10.0.0.2 01 2\r\n",
        "PROXY TCP4 10.0.0.1 10.0.0.2 -1 2\r\n",
        "PROXY TCP4 10.0.0.256 10.0.0.2 1 2\r\n",
        "PROXY UDP4 10.0.0.1 10.0.0.2 1 2\r\n",
        "PROXY \r\n",
        "PROXY TCP4 10.0.0.1\x00 10.0.0.2 1 2\r\n",
        "PROXY TCP4 10.0.0.1\r10.0.0.2",
    };
    for (bad) |b| {
        if (parse(b)) |r| {
            std.debug.print("accepted {any}: {any}\n", .{ b, r });
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    // No line end within 107 bytes.
    const long = "PROXY UNKNOWN " ++ "x" ** 93;
    try testing.expectEqual(@as(?Header, null), try parse(long[0 .. v1_max - 1]));
    try testing.expectError(error.Invalid, parse(long));
    try testing.expectEqual(@as(usize, v1_max), (try parse(long[0 .. v1_max - 2] ++ "\r\n")).?.len);
}

fn v2(comptime cmd: u8, comptime fam: u8, comptime payload: []const u8) []const u8 {
    const len = std.mem.toBytes(std.mem.nativeToBig(u16, payload.len));
    return v2_signature ++ [_]u8{ 0x20 | cmd, fam } ++ len ++ payload;
}

test "v2 addresses, LOCAL and TLVs" {
    const inet = [_]u8{ 203, 0, 113, 7, 192, 0, 2, 1, 0x1f, 0x90, 0x01, 0xbb };
    const h = (try parse(comptime v2(1, 0x11, &inet) ++ "GET")).?;
    try testing.expectEqual(@as(usize, 28), h.len);
    try testing.expectEqualSlices(u8, &v4(203, 0, 113, 7), &h.source.?.ip);
    try testing.expectEqual(@as(u16, 8080), h.source.?.port);

    const six = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{9}; // 2001:db8::9
    const inet6 = six ++ ([_]u8{0} ** 16) ++ [_]u8{ 0x00, 0x50, 0x01, 0xbb };
    const h6 = (try parse(comptime v2(1, 0x21, &inet6))).?;
    try testing.expectEqualSlices(u8, &six, &h6.source.?.ip);
    try testing.expectEqual(@as(u16, 80), h6.source.?.port);

    // A NOOP TLV and an AWS one after the addresses.
    const tlvs = inet ++ [_]u8{ 0x04, 0x00, 0x02, 0, 0, 0xea, 0x00, 0x03, 1, 2, 3 };
    try testing.expectEqual(@as(usize, 16 + tlvs.len), (try parse(comptime v2(1, 0x11, &tlvs))).?.len);

    const local = (try parse(comptime v2(0, 0x00, ""))).?;
    try testing.expectEqual(@as(?Address, null), local.source);
    // LOCAL ignores whatever address block comes with it.
    try testing.expectEqual(@as(?Address, null), (try parse(comptime v2(0, 0x11, &inet))).?.source);
    try testing.expectEqual(@as(?Address, null), (try parse(comptime v2(1, 0x00, ""))).?.source);
    try testing.expectEqual(@as(?Address, null), (try parse(comptime v2(1, 0x31, &([_]u8{0} ** 216)))).?.source);
}

test "v2 incomplete, then complete" {
    const inet = [_]u8{ 10, 0, 0, 1, 10, 0, 0, 2, 0, 1, 0, 2 };
    const full = comptime v2(1, 0x11, &inet);
    for (0..full.len) |i| try testing.expectEqual(@as(?Header, null), try parse(full[0..i]));
    try testing.expectEqual(full.len, (try parse(full)).?.len);
}

test "v2 malformed" {
    const inet = [_]u8{ 10, 0, 0, 1, 10, 0, 0, 2, 0, 1, 0, 2 };
    const bad = [_][]const u8{
        "\r\n\r\n\x00\r\nQUIX",
        comptime v2(2, 0x11, &inet), // command 2
        comptime v2(1, 0x12, &inet), // UDP
        comptime v2(1, 0x41, &inet), // family 4
        comptime v2(1, 0x11, inet[0..11]), // short address block
        comptime v2(1, 0x21, &inet),
        comptime v2(1, 0x31, &inet),
        comptime v2(1, 0x11, &(inet ++ [_]u8{ 0x04, 0x00 })), // truncated TLV
        comptime v2(1, 0x11, &(inet ++ [_]u8{ 0x04, 0x00, 0x05, 1 })), // TLV past the end
        "\r\n\r\n\x00\r\nQUIT\n\x11\x11\x00\x0c" ++ inet, // version 1
    };
    for (bad) |b| {
        if (parse(b)) |r| {
            std.debug.print("accepted {any}: {any}\n", .{ b, r });
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    // Longer than v2_max: refused from its fixed part alone.
    try testing.expectError(error.Invalid, parse(v2_signature ++ "\x21\x11\x10\x00"));
    try testing.expectEqual(@as(?Header, null), try parse(v2_signature ++ "\x21\x11\x0f\xf0"));
}

//! JA4 fingerprints in the 16 bytes a client table key has, so one is
//! banned, listed, saved and shared like a network. The ten characters of
//! the `a` part fit 32 bits as a mixed-radix number; the two hashes take
//! the other 12 bytes.
const std = @import("std");
const quic = @import("quic");
const client_limits = @import("client_limits.zig");
const stats = @import("stats.zig");

pub const Ja4 = quic.ja4.Ja4;
pub const Key = [16]u8;

/// The handshakes' `fingerprint_filter`, for TLS and QUIC listeners: a
/// fingerprint banned in the client table gets no key exchange.
pub const filter: quic.ja4.Filter = .{ .func = admit };

/// The client table, once a config needs one; process-wide, like it.
var table: std.atomic.Value(?*client_limits.Table) = .init(null);
var table_io: std.Io = undefined;

/// Let `filter` read bans from `t`.
pub fn watch(io: std.Io, t: *client_limits.Table) void {
    if (table.load(.acquire) != null) return;
    table_io = io;
    table.store(t, .release);
}

fn admit(_: ?*anyopaque, fp: *const Ja4) bool {
    const t = table.load(.acquire) orelse return true;
    if (!t.anyFingerprintBans()) return true;
    const key = pack(fp.*) orelse return true;
    if (!t.fingerprintBanned(table_io, key, quic.sys.nanoTimestamp())) return true;
    stats.inc(&stats.refused_fingerprint);
    return false;
}

const protos = "tq";
/// The codes JA4 gives versions, then the one for any other.
const versions = blk: {
    var codes: [quic.ja4.versions.len + 1]*const [2]u8 = undefined;
    for (quic.ja4.versions, 0..) |v, i| codes[i] = v[1];
    codes[codes.len - 1] = "00";
    break :blk codes;
};
const alnum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

comptime {
    // Every `a` part has to fit the key's first 32 bits.
    std.debug.assert(protos.len * versions.len * 2 * 100 * 100 * alnum.len * alnum.len <= 1 << 32);
}

/// The key of a connection's fingerprint, if it has one.
pub fn keyOf(fp: ?Ja4) ?Key {
    return pack(fp orelse return null);
}

/// Null for an `a` part JA4 never produces.
pub fn pack(fp: Ja4) ?Key {
    const a = &fp.a;
    var n: u64 = std.mem.indexOfScalar(u8, protos, a[0]) orelse return null;
    n = n * versions.len + (versionIndex(a[1..3]) orelse return null);
    n = n * 2 + @as(u64, switch (a[3]) {
        'd' => 0,
        'i' => 1,
        else => return null,
    });
    n = n * 100 + (std.fmt.parseUnsigned(u8, a[4..6], 10) catch return null);
    n = n * 100 + (std.fmt.parseUnsigned(u8, a[6..8], 10) catch return null);
    n = n * alnum.len + (std.mem.indexOfScalar(u8, alnum, a[8]) orelse return null);
    n = n * alnum.len + (std.mem.indexOfScalar(u8, alnum, a[9]) orelse return null);
    var key: Key = undefined;
    std.mem.writeInt(u32, key[0..4], @intCast(n), .big);
    key[4..10].* = fp.b;
    key[10..16].* = fp.c;
    return key;
}

pub fn unpack(key: Key) Ja4 {
    var n: u64 = std.mem.readInt(u32, key[0..4], .big);
    var fp: Ja4 = .{ .a = undefined, .b = key[4..10].*, .c = key[10..16].* };
    fp.a[9] = alnum[@intCast(n % alnum.len)];
    n /= alnum.len;
    fp.a[8] = alnum[@intCast(n % alnum.len)];
    n /= alnum.len;
    for ([_]usize{ 6, 4 }) |at| {
        const v: u8 = @intCast(n % 100);
        fp.a[at..][0..2].* = .{ '0' + v / 10, '0' + v % 10 };
        n /= 100;
    }
    fp.a[3] = if (n % 2 == 0) 'd' else 'i';
    n /= 2;
    fp.a[1..3].* = versions[@intCast(n % versions.len)].*;
    n /= versions.len;
    // A key from a peer or a file may hold any 32 bits.
    fp.a[0] = if (n < protos.len) protos[@intCast(n)] else '?';
    return fp;
}

/// A fingerprint as an operator writes it; null when `text` isn't one.
pub fn parse(text: []const u8) ?Key {
    return pack(Ja4.parse(text) orelse return null);
}

pub fn format(key: Key, buf: *[Ja4.text_len]u8) []const u8 {
    buf.* = unpack(key).text();
    return buf;
}

fn versionIndex(v: *const [2]u8) ?u64 {
    for (versions, 0..) |known, i| if (std.mem.eql(u8, known, v)) return i;
    return null;
}

const testing = std.testing;

test "packed and back" {
    for ([_][]const u8{
        "t13d1516h2_8daaf6152771_e5627efa2ab1",
        "q13d0312h3_55b375c5d22e_06cda9e17597",
        "t12i990000_000000000000_000000000000",
        "q00i0099zZ_ffffffffffff_000000000001",
        "t10d00009z_0123456789ab_cdef01234567",
    }) |text| {
        const key = parse(text).?;
        var buf: [Ja4.text_len]u8 = undefined;
        try testing.expectEqualStrings(text, format(key, &buf));
    }
    // The largest `a` still fits 32 bits.
    try testing.expect(parse("q00i9999zz_000000000000_000000000000") != null);
    // DTLS, which nothing routez serves speaks.
    try testing.expect(parse("d13d1516h2_8daaf6152771_e5627efa2ab1") == null);
    for ([_][]const u8{ "x13d1516h2_8daaf6152771_e5627efa2ab1", "t14d1516h2_8daaf6152771_e5627efa2ab1", "t13x1516h2_8daaf6152771_e5627efa2ab1", "t13d1a16h2_8daaf6152771_e5627efa2ab1", "192.0.2.1" }) |bad| {
        try testing.expect(parse(bad) == null);
    }
}

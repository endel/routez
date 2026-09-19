//! What the `$ssl_client_*` variables say about a verified client
//! certificate, in nginx's formats: distinguished names per RFC 4514 (most
//! specific RDN first, `\XX` for bytes outside printable ASCII), the serial
//! in uppercase hex, the SHA-1 fingerprint in lowercase hex.
//!
//! Reads DER with its own bounds checks rather than std's parser, so it is
//! safe on any input and can be fuzzed alone.
const std = @import("std");

pub const Info = struct {
    s_dn: []const u8,
    i_dn: []const u8,
    serial: []const u8,
    fingerprint: []const u8,
};

pub const Error = error{ Malformed, OutOfMemory };

pub fn describe(arena: std.mem.Allocator, der: []const u8) Error!Info {
    const cert = try readTlv(der, 0, der.len);
    if (cert.tag != 0x30) return error.Malformed;
    const tbs = try readTlv(der, cert.start, cert.end);
    if (tbs.tag != 0x30) return error.Malformed;
    var pos = tbs.start;
    var el = try readTlv(der, pos, tbs.end);
    if (el.tag == 0xa0) {
        pos = el.end;
        el = try readTlv(der, pos, tbs.end);
    }
    if (el.tag != 0x02) return error.Malformed;
    const serial = der[el.start..el.end];
    const sig_alg = try readTlv(der, el.end, tbs.end);
    const issuer = try readTlv(der, sig_alg.end, tbs.end);
    const validity = try readTlv(der, issuer.end, tbs.end);
    const subject = try readTlv(der, validity.end, tbs.end);
    if (issuer.tag != 0x30 or subject.tag != 0x30) return error.Malformed;

    var fp: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(der, &fp, .{});
    return .{
        .s_dn = try formatName(arena, der[subject.start..subject.end]),
        .i_dn = try formatName(arena, der[issuer.start..issuer.end]),
        .serial = try serialHex(arena, serial),
        .fingerprint = try std.fmt.allocPrint(arena, "{x}", .{&fp}),
    };
}

fn serialHex(arena: std.mem.Allocator, raw: []const u8) Error![]const u8 {
    var s = raw;
    // A positive serial with its top bit set carries a leading zero byte.
    if (s.len > 1 and s[0] == 0) s = s[1..];
    return std.fmt.allocPrint(arena, "{X}", .{s});
}

/// `at` is where the element's tag is; `start..end` its contents.
const Tlv = struct { tag: u8, at: usize, start: usize, end: usize };

fn readTlv(b: []const u8, pos: usize, limit: usize) Error!Tlv {
    if (limit > b.len or pos >= limit or limit - pos < 2) return error.Malformed;
    const tag = b[pos];
    const first = b[pos + 1];
    var i = pos + 2;
    var len: usize = first;
    if (first >= 0x80) {
        const n: usize = first & 0x7f;
        if (n == 0 or n > 4 or n > limit - i) return error.Malformed;
        len = 0;
        for (b[i..][0..n]) |x| len = (len << 8) | x;
        i += n;
    }
    if (len > limit - i) return error.Malformed;
    return .{ .tag = tag, .at = pos, .start = i, .end = i + len };
}

/// A Name's contents (the RDNSequence inside its SEQUENCE) as an RFC 4514
/// string: RDNs in reverse order, joined with `,`, multi-valued ones with `+`.
pub fn formatName(arena: std.mem.Allocator, name: []const u8) Error![]const u8 {
    var rdns: std.ArrayList(Tlv) = .empty;
    var pos: usize = 0;
    while (pos < name.len) {
        const rdn = try readTlv(name, pos, name.len);
        if (rdn.tag != 0x31) return error.Malformed;
        try rdns.append(arena, rdn);
        pos = rdn.end;
    }
    var out: std.ArrayList(u8) = .empty;
    var i = rdns.items.len;
    while (i > 0) {
        i -= 1;
        if (i + 1 != rdns.items.len) try out.append(arena, ',');
        const rdn = rdns.items[i];
        var apos = rdn.start;
        var first = true;
        while (apos < rdn.end) {
            const atv = try readTlv(name, apos, rdn.end);
            apos = atv.end;
            if (atv.tag != 0x30) return error.Malformed;
            const oid = try readTlv(name, atv.start, atv.end);
            if (oid.tag != 0x06) return error.Malformed;
            const value = try readTlv(name, oid.end, atv.end);
            if (value.end != atv.end) return error.Malformed;
            if (!first) try out.append(arena, '+');
            first = false;
            try appendAttribute(arena, &out, name[oid.start..oid.end], name, value);
        }
    }
    return out.items;
}

const names = [_]struct { oid: []const u8, name: []const u8 }{
    .{ .oid = &.{ 0x55, 0x04, 0x03 }, .name = "CN" },
    .{ .oid = &.{ 0x55, 0x04, 0x06 }, .name = "C" },
    .{ .oid = &.{ 0x55, 0x04, 0x07 }, .name = "L" },
    .{ .oid = &.{ 0x55, 0x04, 0x08 }, .name = "ST" },
    .{ .oid = &.{ 0x55, 0x04, 0x09 }, .name = "STREET" },
    .{ .oid = &.{ 0x55, 0x04, 0x0a }, .name = "O" },
    .{ .oid = &.{ 0x55, 0x04, 0x0b }, .name = "OU" },
    .{ .oid = &.{ 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19 }, .name = "DC" },
    .{ .oid = &.{ 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01 }, .name = "UID" },
    .{ .oid = &.{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01 }, .name = "emailAddress" },
};

fn appendAttribute(arena: std.mem.Allocator, out: *std.ArrayList(u8), oid: []const u8, name: []const u8, value: Tlv) Error!void {
    const known = for (names) |n| {
        if (std.mem.eql(u8, n.oid, oid)) break n.name;
    } else null;
    if (known) |k| try out.appendSlice(arena, k) else try appendDottedOid(arena, out, oid);
    try out.append(arena, '=');
    const bytes = name[value.start..value.end];
    switch (value.tag) {
        // UTF8String, PrintableString, TeletexString, IA5String, VisibleString
        0x0c, 0x13, 0x14, 0x16, 0x1a => if (known != null) return appendEscaped(arena, out, bytes),
        // BMPString: UCS-2, big-endian.
        0x1e => if (known != null and bytes.len % 2 == 0) {
            var utf8: std.ArrayList(u8) = .empty;
            var i: usize = 0;
            while (i < bytes.len) : (i += 2) {
                const cp: u21 = std.mem.readInt(u16, bytes[i..][0..2], .big);
                var buf: [4]u8 = undefined;
                const n = std.unicode.utf8Encode(cp, &buf) catch return appendHexValue(arena, out, name[value.at..value.end]);
                try utf8.appendSlice(arena, buf[0..n]);
            }
            return appendEscaped(arena, out, utf8.items);
        },
        else => {},
    }
    // RFC 4514 §2.4: anything else as '#' and the hex of its BER encoding.
    try appendHexValue(arena, out, name[value.at..value.end]);
}

fn appendHexValue(arena: std.mem.Allocator, out: *std.ArrayList(u8), ber: []const u8) Error!void {
    try out.append(arena, '#');
    try out.print(arena, "{x}", .{ber});
}

fn appendDottedOid(arena: std.mem.Allocator, out: *std.ArrayList(u8), oid: []const u8) Error!void {
    if (oid.len == 0) return error.Malformed;
    var first = true;
    var v: u64 = 0;
    for (oid, 0..) |b, i| {
        if (v > (std.math.maxInt(u64) >> 7)) return error.Malformed;
        v = (v << 7) | (b & 0x7f);
        if (b & 0x80 != 0) {
            if (i == oid.len - 1) return error.Malformed;
            continue;
        }
        if (first) {
            const a: u64 = if (v < 40) 0 else if (v < 80) 1 else 2;
            try out.print(arena, "{d}.{d}", .{ a, v - a * 40 });
            first = false;
        } else {
            try out.print(arena, ".{d}", .{v});
        }
        v = 0;
    }
}

/// RFC 4514 §2.4 escaping, plus OpenSSL's: bytes outside printable ASCII
/// as `\XX`, which also keeps the result a valid header value.
fn appendEscaped(arena: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) Error!void {
    for (s, 0..) |c, i| {
        const special = switch (c) {
            '"', '+', ',', ';', '<', '>', '\\' => true,
            '#' => i == 0,
            ' ' => i == 0 or i == s.len - 1,
            else => false,
        };
        if (c < 0x20 or c >= 0x7f) {
            try out.print(arena, "\\{X:0>2}", .{c});
        } else if (special) {
            try out.append(arena, '\\');
            try out.append(arena, c);
        } else {
            try out.append(arena, c);
        }
    }
}

const testing = std.testing;

fn pemDer(pem: []const u8, buf: []u8) ![]const u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const start = std.mem.indexOf(u8, pem, begin).? + begin.len;
    const end = std.mem.indexOf(u8, pem, "-----END").?;
    const dec = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const n = try dec.decode(buf, pem[start..end]);
    return buf[0..n];
}

// openssl req -x509 -subj '/C=US/O=Ex, Inc./OU=a\+b/CN=alice "A" 1/emailAddress=alice@example.com' -set_serial 0x8a01
const test_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIICEjCCAbigAwIBAgIDAIoBMAoGCCqGSM49BAMCMGYxCzAJBgNVBAYTAlVTMREw
    \\DwYDVQQKDAhFeCwgSW5jLjEMMAoGA1UECwwDYStiMRQwEgYDVQQDDAthbGljZSAi
    \\QSIgMTEgMB4GCSqGSIb3DQEJARYRYWxpY2VAZXhhbXBsZS5jb20wIBcNMjYwMTAx
    \\MDAwMDAwWhgPMjA1NjAxMDEwMDAwMDBaMGYxCzAJBgNVBAYTAlVTMREwDwYDVQQK
    \\DAhFeCwgSW5jLjEMMAoGA1UECwwDYStiMRQwEgYDVQQDDAthbGljZSAiQSIgMTEg
    \\MB4GCSqGSIb3DQEJARYRYWxpY2VAZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggq
    \\hkjOPQMBBwNCAASCAlCzHy7hvkKlwFHXtFWrUybWQxSV7S1ryZ8dGyRZDXQcDdF8
    \\7DijXTu5uiuaNyRHjlGaObherVYT1Gd5mWcJo1MwUTAdBgNVHQ4EFgQUiv4zpVEJ
    \\OsEq4yyGjbv65sUMhSMwHwYDVR0jBBgwFoAUiv4zpVEJOsEq4yyGjbv65sUMhSMw
    \\DwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA4V6VYuoimOwLSDp4
    \\Jk2vpjtYurhlpDmCxXlcjQmhYDwCIAe5aV+/WLICW/0YLBpY999evakd7VATy5RX
    \\y2XY6eIV
    \\-----END CERTIFICATE-----
;

test "describe: RFC 4514 names, serial, fingerprint" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var buf: [2048]u8 = undefined;
    const der = try pemDer(test_pem, &buf);
    const info = try describe(arena_state.allocator(), der);
    try testing.expectEqualStrings("emailAddress=alice@example.com,CN=alice \\\"A\\\" 1,OU=a\\+b,O=Ex\\, Inc.,C=US", info.s_dn);
    try testing.expectEqualStrings(info.s_dn, info.i_dn);
    try testing.expectEqualStrings("8A01", info.serial);
    try testing.expectEqualStrings("eb1bfe1322bfe58d2c4863be87f27addf59f63e1", info.fingerprint);
}

test "formatName: escaping, unknown attributes, multi-valued RDNs" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // SET { CN=" #x\n" + 1.2.3.4=PrintableString "z" }, SET { O=UTF8 "é" }
    const name = [_]u8{
        0x31, 0x16, //
        0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, ' ', '#', 'x', '\n', //
        0x30, 0x07, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x13, 0x01, //
        0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x03, 0xc3, 0xa9, '#',
    };
    try testing.expectError(error.Malformed, formatName(a, &name)); // the second value is one byte short
    const good = [_]u8{
        0x31, 0x17, //
        0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, ' ', '#', 'x', '\n', //
        0x30, 0x08, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x13, 0x01, 'z', //
        0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
        0x04, 0xc3, 0xa9, '#',  ' ',
    };
    try testing.expectEqualStrings("O=\\C3\\A9#\\ ,CN=\\ #x\\0A+1.2.3.4=#13017a", try formatName(a, &good));
}

test "describe never fails badly on truncations" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var buf: [2048]u8 = undefined;
    const der = try pemDer(test_pem, &buf);
    for (0..der.len) |n| _ = describe(arena_state.allocator(), der[0..n]) catch {};
}

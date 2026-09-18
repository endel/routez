//! A small DER writer, enough for CSRs, certificates and EC keys.
const std = @import("std");

pub const Tag = struct {
    pub const integer = 0x02;
    pub const bit_string = 0x03;
    pub const octet_string = 0x04;
    pub const oid = 0x06;
    pub const utf8_string = 0x0c;
    pub const utc_time = 0x17;
    pub const generalized_time = 0x18;
    pub const sequence = 0x30;
    pub const set = 0x31;

    /// Context-specific, constructed: `[n] EXPLICIT` or a constructed `[n] IMPLICIT`.
    pub fn context(n: u5) u8 {
        return 0xa0 | @as(u8, n);
    }
    /// Context-specific, primitive: `[n] IMPLICIT` over a primitive type.
    pub fn contextPrimitive(n: u5) u8 {
        return 0x80 | @as(u8, n);
    }
};

/// Encoded OBJECT IDENTIFIER contents (without tag and length).
pub const Oid = struct {
    pub const ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }; // 1.2.840.10045.2.1
    pub const prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }; // 1.2.840.10045.3.1.7
    pub const ecdsa_with_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 }; // 1.2.840.10045.4.3.2
    pub const common_name = [_]u8{ 0x55, 0x04, 0x03 }; // 2.5.4.3
    pub const extension_request = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e }; // 1.2.840.113549.1.9.14
    pub const subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 }; // 2.5.29.17
};

/// Appends TLVs to a buffer. Constructed values are opened with `begin` and
/// closed with `end`, which back-fills the length.
pub const Writer = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayListUnmanaged(u8) = .empty,
    open: [16]usize = undefined,
    depth: usize = 0,

    pub fn init(gpa: std.mem.Allocator) Writer {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Writer) void {
        self.buf.deinit(self.gpa);
    }

    /// The encoding, owned by the caller. Every `begin` must have been closed.
    pub fn toOwnedSlice(self: *Writer) ![]u8 {
        std.debug.assert(self.depth == 0);
        return self.buf.toOwnedSlice(self.gpa);
    }

    pub fn begin(self: *Writer, tag: u8) !void {
        try self.buf.append(self.gpa, tag);
        self.open[self.depth] = self.buf.items.len;
        self.depth += 1;
    }

    pub fn end(self: *Writer) !void {
        self.depth -= 1;
        const start = self.open[self.depth];
        var len_buf: [5]u8 = undefined;
        const len_bytes = encodeLength(self.buf.items.len - start, &len_buf);
        try self.buf.insertSlice(self.gpa, start, len_bytes);
    }

    pub fn primitive(self: *Writer, tag: u8, contents: []const u8) !void {
        var len_buf: [5]u8 = undefined;
        try self.buf.append(self.gpa, tag);
        try self.buf.appendSlice(self.gpa, encodeLength(contents.len, &len_buf));
        try self.buf.appendSlice(self.gpa, contents);
    }

    /// Already-encoded TLVs, copied as is.
    pub fn raw(self: *Writer, bytes: []const u8) !void {
        try self.buf.appendSlice(self.gpa, bytes);
    }

    pub fn oid(self: *Writer, contents: []const u8) !void {
        try self.primitive(Tag.oid, contents);
    }

    /// A non-negative INTEGER from big-endian magnitude bytes.
    pub fn unsigned(self: *Writer, magnitude: []const u8) !void {
        var m = magnitude;
        while (m.len > 1 and m[0] == 0) m = m[1..];
        try self.buf.append(self.gpa, Tag.integer);
        var len_buf: [5]u8 = undefined;
        const pad = m.len == 0 or m[0] & 0x80 != 0;
        try self.buf.appendSlice(self.gpa, encodeLength(m.len + @intFromBool(pad), &len_buf));
        if (pad) try self.buf.append(self.gpa, 0);
        try self.buf.appendSlice(self.gpa, m);
    }

    pub fn small(self: *Writer, v: u8) !void {
        try self.unsigned(&.{v});
    }

    /// A BIT STRING with no unused bits.
    pub fn bitString(self: *Writer, bytes: []const u8) !void {
        try self.begin(Tag.bit_string);
        try self.buf.append(self.gpa, 0);
        try self.buf.appendSlice(self.gpa, bytes);
        try self.end();
    }

    /// UTCTime through 2049, GeneralizedTime after (RFC 5280 4.1.2.5).
    pub fn time(self: *Writer, epoch_seconds: u64) !void {
        const es: std.time.epoch.EpochSeconds = .{ .secs = epoch_seconds };
        const yd = es.getEpochDay().calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();
        var buf: [16]u8 = undefined;
        const args = .{ md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() };
        if (yd.year < 2050) {
            const s = std.fmt.bufPrint(&buf, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{yd.year % 100} ++ args) catch unreachable;
            try self.primitive(Tag.utc_time, s);
        } else {
            const s = std.fmt.bufPrint(&buf, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{yd.year} ++ args) catch unreachable;
            try self.primitive(Tag.generalized_time, s);
        }
    }
};

fn encodeLength(len: usize, buf: *[5]u8) []const u8 {
    if (len < 0x80) {
        buf[0] = @intCast(len);
        return buf[0..1];
    }
    var n: usize = 0;
    var v = len;
    while (v > 0) : (v >>= 8) n += 1;
    buf[0] = 0x80 | @as(u8, @intCast(n));
    for (0..n) |i| buf[1 + i] = @truncate(len >> @intCast(8 * (n - 1 - i)));
    return buf[0 .. 1 + n];
}

/// PEM armour, 64 base64 characters per line.
pub fn pem(gpa: std.mem.Allocator, label: []const u8, der_bytes: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const b64 = try gpa.alloc(u8, enc.calcSize(der_bytes.len));
    defer gpa.free(b64);
    _ = enc.encode(b64, der_bytes);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.print(gpa, "-----BEGIN {s}-----\n", .{label});
    var i: usize = 0;
    while (i < b64.len) : (i += 64) {
        try out.appendSlice(gpa, b64[i..@min(i + 64, b64.len)]);
        try out.append(gpa, '\n');
    }
    try out.print(gpa, "-----END {s}-----\n", .{label});
    return out.toOwnedSlice(gpa);
}

/// One element read back, for tests and for walking our own encodings.
pub const Element = struct {
    tag: u8,
    contents: []const u8,
    /// Bytes after this element.
    rest: []const u8,

    pub fn parse(bytes: []const u8) error{Truncated}!Element {
        if (bytes.len < 2) return error.Truncated;
        var len: usize = bytes[1];
        var hdr: usize = 2;
        if (len & 0x80 != 0) {
            const n = len & 0x7f;
            if (n == 0 or n > 4 or bytes.len < 2 + n) return error.Truncated;
            len = 0;
            for (bytes[2 .. 2 + n]) |b| len = (len << 8) | b;
            hdr += n;
        }
        if (bytes.len - hdr < len) return error.Truncated;
        return .{ .tag = bytes[0], .contents = bytes[hdr .. hdr + len], .rest = bytes[hdr + len ..] };
    }
};

test "lengths and integers" {
    const gpa = std.testing.allocator;
    var w: Writer = .init(gpa);
    defer w.deinit();
    try w.begin(Tag.sequence);
    try w.small(0);
    try w.unsigned(&.{ 0x00, 0x80 });
    try w.primitive(Tag.octet_string, &([_]u8{0xaa} ** 200));
    try w.end();
    const out = try w.toOwnedSlice();
    defer gpa.free(out);
    // 3 (INTEGER 0) + 4 (INTEGER 0x0080) + 3 + 200 (OCTET STRING, long form)
    try std.testing.expectEqualSlices(u8, &.{ 0x30, 0x81, 210, 0x02, 0x01, 0x00, 0x02, 0x02, 0x00, 0x80, 0x04, 0x81, 200 }, out[0..13]);
    const seq = try Element.parse(out);
    try std.testing.expectEqual(@as(usize, 210), seq.contents.len);
    try std.testing.expectEqual(@as(usize, 0), seq.rest.len);
}

test "time encoding switches at 2050" {
    const gpa = std.testing.allocator;
    var w: Writer = .init(gpa);
    defer w.deinit();
    try w.time(1_700_000_000); // 2023-11-14 22:13:20
    try w.time(2_556_144_000); // 2051-01-01 00:00:00
    try std.testing.expectEqualSlices(u8, "\x17\x0d231114221320Z\x18\x0f20510101000000Z", w.buf.items);
}

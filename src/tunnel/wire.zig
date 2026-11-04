//! What a tunnel adds to its session's streams and datagrams so they carry
//! players' WebTransport sessions as well as HTTP.
//!
//! Every stream the edge opens to the agent starts with a kind byte:
//! - `http`: an upstream connection of the edge's HTTP proxy. HTTP/1.1
//!   follows as the proxy wrote it.
//! - `session`: a player's session. Its token (a varint) and a `request`
//!   message follow, then messages both ways for as long as the session
//!   lasts. The agent answers `accept` or `refuse`; `close` ends it from
//!   either side, and so does the stream ending.
//! - `stream`: a stream of session `token` (a varint), a flags byte, then
//!   the stream's bytes. With `uni` the stream runs one way, away from
//!   whoever opened it: the other way ends at once, empty.
//! The agent opens `stream`s too, for the streams its local server opens.
//!
//! A datagram on the tunnel's session is a session's token, then the
//! player's datagram. A message is a varint type, a varint length and that
//! many bytes.
const std = @import("std");
const qpack = @import("quic").qpack;

pub const Kind = enum(u8) { http = 0, session = 1, stream = 2 };

pub const flag_uni: u8 = 1;

/// The longest head: a kind, a token and the flags.
pub const max_head = 1 + 8 + 1;

/// No message is longer: a CONNECT's headers fit easily.
pub const max_message = 64 * 1024;

pub const Head = struct {
    kind: Kind,
    token: u64 = 0,
    uni: bool = false,
    /// Bytes of the stream it took.
    len: usize,
};

/// The head `bytes` start with; null until all of it is there.
pub fn parseHead(bytes: []const u8) error{BadHead}!?Head {
    if (bytes.len == 0) return null;
    const kind = std.enums.fromInt(Kind, bytes[0]) orelse return error.BadHead;
    if (kind == .http) return .{ .kind = .http, .len = 1 };
    const t = getVarint(bytes[1..]) orelse return null;
    if (kind == .session) return .{ .kind = .session, .token = t.v, .len = 1 + t.len };
    if (bytes.len < 1 + t.len + 1) return null;
    const flags = bytes[1 + t.len];
    if (flags & ~flag_uni != 0) return error.BadHead;
    return .{ .kind = .stream, .token = t.v, .uni = flags & flag_uni != 0, .len = 1 + t.len + 1 };
}

/// A `session` or `stream` head, into `buf`.
pub fn head(buf: *[max_head]u8, kind: Kind, token: u64, uni: bool) []const u8 {
    buf[0] = @backingInt(kind);
    var n: usize = 1 + putVarint(buf[1..], token);
    if (kind == .stream) {
        buf[n] = if (uni) flag_uni else 0;
        n += 1;
    }
    return buf[0..n];
}

// ---- messages ----

pub const MessageType = enum(u8) { request = 0, accept = 1, refuse = 2, close = 3 };

pub const Message = union(MessageType) {
    request: struct { path: []const u8, headers: Headers },
    accept: Headers,
    refuse: u16,
    close: struct { code: u32, reason: []const u8 },
};

/// Encoded headers: a count, then each name and value length-prefixed.
pub const Headers = struct {
    bytes: []const u8,

    /// Up to `out.len` of them; the slices point into the message.
    pub fn decode(self: Headers, out: []qpack.Header) error{BadMessage}![]qpack.Header {
        var r: Cursor = .{ .bytes = self.bytes };
        const count = try r.varint();
        var n: usize = 0;
        for (0..count) |_| {
            const name = try r.chunk();
            const value = try r.chunk();
            if (n == out.len) continue;
            out[n] = .{ .name = name, .value = value };
            n += 1;
        }
        return out[0..n];
    }
};

pub fn writeRequest(a: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), path: []const u8, headers: []const qpack.Header) !void {
    try begin(a, out, .request, varintLen(path.len) + path.len + headersLen(headers));
    try putChunk(a, out, path);
    try putHeaders(a, out, headers);
}

pub fn writeAccept(a: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), headers: []const qpack.Header) !void {
    try begin(a, out, .accept, headersLen(headers));
    try putHeaders(a, out, headers);
}

pub fn writeRefuse(a: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), status: u16) !void {
    try begin(a, out, .refuse, varintLen(status));
    try putVarintList(a, out, status);
}

pub fn writeClose(a: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), code: u32, reason: []const u8) !void {
    const r = reason[0..@min(reason.len, 1024)];
    try begin(a, out, .close, varintLen(code) + r.len);
    try putVarintList(a, out, code);
    try out.appendSlice(a, r);
}

fn begin(a: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), t: MessageType, len: usize) !void {
    if (len > max_message) return error.MessageTooLong;
    try putVarintList(a, out, @backingInt(t));
    try putVarintList(a, out, len);
}

fn headersLen(headers: []const qpack.Header) usize {
    var n = varintLen(headers.len);
    for (headers) |h| n += varintLen(h.name.len) + h.name.len + varintLen(h.value.len) + h.value.len;
    return n;
}

fn putHeaders(a: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), headers: []const qpack.Header) !void {
    try putVarintList(a, out, headers.len);
    for (headers) |h| {
        try putChunk(a, out, h.name);
        try putChunk(a, out, h.value);
    }
}

fn putChunk(a: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), bytes: []const u8) !void {
    try putVarintList(a, out, bytes.len);
    try out.appendSlice(a, bytes);
}

fn putVarintList(a: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), v: u64) !void {
    var buf: [8]u8 = undefined;
    try out.appendSlice(a, buf[0..putVarint(&buf, v)]);
}

/// Messages from a byte stream that arrives in pieces.
pub const Reader = struct {
    buf: std.ArrayListUnmanaged(u8) = .empty,
    /// Where the next message starts; what is before it was read.
    start: usize = 0,

    pub fn deinit(self: *Reader, a: std.mem.Allocator) void {
        self.buf.deinit(a);
    }

    /// Invalidates the messages `next` returned.
    pub fn feed(self: *Reader, a: std.mem.Allocator, data: []const u8) !void {
        const rest = self.buf.items.len - self.start;
        std.mem.copyForwards(u8, self.buf.items[0..rest], self.buf.items[self.start..]);
        self.buf.items.len = rest;
        self.start = 0;
        if (rest + data.len > max_message + 16) return error.MessageTooLong;
        try self.buf.appendSlice(a, data);
    }

    /// The next whole message, valid until the next `feed`.
    pub fn next(self: *Reader) error{BadMessage}!?Message {
        var r: Cursor = .{ .bytes = self.buf.items[self.start..] };
        const t = r.varint() catch return null;
        const len = r.varint() catch return null;
        if (len > max_message) return error.BadMessage;
        if (r.bytes.len - r.pos < len) return null;
        const body = r.bytes[r.pos..][0..len];
        self.start += r.pos + len;
        var b: Cursor = .{ .bytes = body };
        const m: Message = switch (std.enums.fromInt(MessageType, std.math.cast(u8, t) orelse return error.BadMessage) orelse return error.BadMessage) {
            .request => .{ .request = .{ .path = try b.chunk(), .headers = .{ .bytes = body[b.pos..] } } },
            .accept => .{ .accept = .{ .bytes = body } },
            .refuse => .{ .refuse = std.math.cast(u16, try b.varint()) orelse return error.BadMessage },
            .close => .{ .close = .{ .code = std.math.cast(u32, try b.varint()) orelse return error.BadMessage, .reason = body[b.pos..] } },
        };
        return m;
    }
};

const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn varint(c: *Cursor) error{BadMessage}!u64 {
        const v = getVarint(c.bytes[c.pos..]) orelse return error.BadMessage;
        c.pos += v.len;
        return v.v;
    }

    fn chunk(c: *Cursor) error{BadMessage}![]const u8 {
        const n = try c.varint();
        if (c.bytes.len - c.pos < n) return error.BadMessage;
        defer c.pos += n;
        return c.bytes[c.pos..][0..n];
    }
};

// ---- QUIC varints (RFC 9000 §16) ----

pub fn varintLen(v: u64) usize {
    if (v < 1 << 6) return 1;
    if (v < 1 << 14) return 2;
    if (v < 1 << 30) return 4;
    return 8;
}

/// `v` (below 2^62) into `buf`; its length.
pub fn putVarint(buf: []u8, v: u64) usize {
    const n = varintLen(v);
    var x = v;
    var i = n;
    while (i > 0) {
        i -= 1;
        buf[i] = @truncate(x);
        x >>= 8;
    }
    buf[0] |= @as(u8, switch (n) {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        else => 0xc0,
    });
    return n;
}

pub fn getVarint(bytes: []const u8) ?struct { v: u64, len: usize } {
    if (bytes.len == 0) return null;
    const n = @as(usize, 1) << @intCast(bytes[0] >> 6);
    if (bytes.len < n) return null;
    var v: u64 = bytes[0] & 0x3f;
    for (bytes[1..n]) |b| v = v << 8 | b;
    return .{ .v = v, .len = n };
}

test "varints round-trip at every length" {
    var buf: [8]u8 = undefined;
    for ([_]u64{ 0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1 }) |v| {
        const n = putVarint(&buf, v);
        const got = getVarint(buf[0..n]).?;
        try std.testing.expectEqual(v, got.v);
        try std.testing.expectEqual(n, got.len);
        try std.testing.expect(getVarint(buf[0 .. n - 1]) == null);
    }
}

test "heads parse once whole" {
    var buf: [max_head]u8 = undefined;
    const h = head(&buf, .stream, 300, true);
    for (0..h.len) |i| try std.testing.expect(try parseHead(h[0..i]) == null);
    const got = (try parseHead(h)).?;
    try std.testing.expectEqual(Kind.stream, got.kind);
    try std.testing.expectEqual(@as(u64, 300), got.token);
    try std.testing.expect(got.uni);
    try std.testing.expectEqual(h.len, got.len);
    try std.testing.expectEqual(@as(usize, 1), (try parseHead("\x00GET /")).?.len);
    try std.testing.expectError(error.BadHead, parseHead("G"));
    try std.testing.expectError(error.BadHead, parseHead("\x02\x01\x80"));
}

test "messages split anywhere come out whole" {
    const a = std.testing.allocator;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(a);
    const hs = [_]qpack.Header{ .{ .name = "origin", .value = "https://game.example" }, .{ .name = "x-real-ip", .value = "192.0.2.1" } };
    try writeRequest(a, &out, "/play?room=1", &hs);
    try writeAccept(a, &out, hs[0..1]);
    try writeRefuse(a, &out, 503);
    try writeClose(a, &out, 7, "bye");

    var r: Reader = .{};
    defer r.deinit(a);
    var seen: usize = 0;
    var store: [4]qpack.Header = undefined;
    for (out.items) |byte| {
        try r.feed(a, &.{byte});
        while (try r.next()) |m| {
            switch (m) {
                .request => |q| {
                    try std.testing.expectEqualStrings("/play?room=1", q.path);
                    const got = try q.headers.decode(&store);
                    try std.testing.expectEqual(@as(usize, 2), got.len);
                    try std.testing.expectEqualStrings("192.0.2.1", got[1].value);
                },
                .accept => |h| try std.testing.expectEqualStrings("origin", (try h.decode(&store))[0].name),
                .refuse => |s| try std.testing.expectEqual(@as(u16, 503), s),
                .close => |c| {
                    try std.testing.expectEqual(@as(u32, 7), c.code);
                    try std.testing.expectEqualStrings("bye", c.reason);
                },
            }
            seen += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 4), seen);
}

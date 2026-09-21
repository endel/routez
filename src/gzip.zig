//! Streaming gzip for responses.
//!
//! A compressor costs about 300 KB: std's deflate tables are ~224 KB and its
//! window is another 64 KiB. That is past the allocator's largest size class, so
//! creating one per response meant an mmap, the page faults to first-touch it and
//! a munmap every time. Each worker keeps a few on a freelist instead (`Pool`).
//!
//! One is still created only for a response that qualifies, and a worker runs at
//! most `max_active` at once.
//!
//! The gzip framing is ours, around a raw deflate stream, because std's gzip
//! container hashes with a one-byte-at-a-time CRC32 that cost more than the
//! compression did. `Crc32` below reads eight bytes a round instead.
const std = @import("std");
const flate = std.compress.flate;
const common = @import("http/common.zig");
const Header = common.Header;
const encoding = @import("encoding.zig");

/// Responses compressing at once. Past this they go out uncompressed, so this
/// is a bandwidth cliff rather than a queue: at 64 a proxied row sent 4.5% of
/// its responses whole, which was 38 MB/s of wire traffic where 13 would do.
/// nginx caps nothing and holds a comparable amount of zlib state per response.
pub const max_active = 256;
/// std's minimum, and enlarging it gains nothing: the rebase that moves the
/// match history to the front of this buffer is also where std does the
/// matching, so a bigger buffer buys fewer memmoves of an amount that does not
/// show up next to the compression itself.
const window_len = flate.max_window_len;
/// Bodies known to be smaller than this aren't worth the CPU.
pub const min_length = 1024;
/// Encoders a worker keeps between responses. Compressing is synchronous, so
/// only the responses still streaming hold one and a handful covers the reuse;
/// keeping `max_active` of them would park 19 MB per worker for a feature that
/// may be idle.
pub const max_idle = 4;

/// deflate, no mtime, unknown OS: everything a response needs.
const gzip_header = [10]u8{ 0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff };

pub const Encoder = struct {
    alloc: std.mem.Allocator,
    out: std.Io.Writer.Allocating,
    window: []u8,
    c: flate.Compress,
    crc: Crc32 = .{},
    /// Uncompressed bytes, modulo 2^32, as the trailer states them.
    size: u32 = 0,
    /// Next on a `Pool` freelist; meaningless while in use.
    next: ?*Encoder = null,

    /// Heap-allocated: the compressor points at `out`.
    pub fn create(alloc: std.mem.Allocator) !*Encoder {
        const self = try alloc.create(Encoder);
        errdefer alloc.destroy(self);
        self.alloc = alloc;
        self.out = try .initCapacity(alloc, 16 * 1024);
        errdefer self.out.deinit();
        self.window = try alloc.alloc(u8, window_len);
        errdefer alloc.free(self.window);
        self.next = null;
        try self.start();
        return self;
    }

    pub fn destroy(self: *Encoder) void {
        self.out.deinit();
        self.alloc.free(self.window);
        self.alloc.destroy(self);
    }

    /// A fresh stream, header already in `out`.
    fn start(self: *Encoder) !void {
        self.crc = .{};
        self.size = 0;
        self.c = try flate.Compress.init(&self.out.writer, self.window, .raw, .level_4);
        try self.out.writer.writeAll(&gzip_header);
    }

    /// Ready for another response, keeping the tables and the window.
    fn reset(self: *Encoder) !void {
        self.out.clearRetainingCapacity();
        try self.start();
    }

    /// Compress `data`; compressed bytes accumulate in `output()`.
    pub fn write(self: *Encoder, data: []const u8) !void {
        self.crc.update(data);
        self.size +%= @truncate(data.len);
        try self.c.writer.writeAll(data);
    }

    /// Flush whatever the compressor holds, ending the gzip stream.
    pub fn finish(self: *Encoder) !void {
        try self.c.finish();
        try self.out.writer.writeInt(u32, self.crc.final(), .little);
        try self.out.writer.writeInt(u32, self.size, .little);
    }

    pub fn output(self: *Encoder) []const u8 {
        return self.out.written();
    }

    pub fn consume(self: *Encoder) void {
        self.out.clearRetainingCapacity();
    }
};

/// One worker's encoders: those in use, and up to `max_idle` waiting.
///
/// Touched only on its worker's loop thread, so no locks.
pub const Pool = struct {
    alloc: std.mem.Allocator,
    idle: ?*Encoder = null,
    idle_count: u32 = 0,
    /// Responses holding an encoder right now.
    active: u32 = 0,

    /// Null when `max_active` are already out, or the allocation failed: the
    /// caller then sends the response uncompressed.
    pub fn acquire(self: *Pool) ?*Encoder {
        if (self.active >= max_active) return null;
        const e = self.takeIdle() orelse Encoder.create(self.alloc) catch return null;
        self.active += 1;
        return e;
    }

    /// An idle encoder, reset and ready. Null when there is none, or resetting
    /// one failed, in which case the caller makes a fresh one.
    fn takeIdle(self: *Pool) ?*Encoder {
        const e = self.idle orelse return null;
        self.idle = e.next;
        self.idle_count -= 1;
        e.next = null;
        e.reset() catch {
            e.destroy();
            return null;
        };
        return e;
    }

    pub fn release(self: *Pool, e: *Encoder) void {
        std.debug.assert(self.active > 0);
        self.active -= 1;
        if (self.idle_count >= max_idle) return e.destroy();
        e.next = self.idle;
        self.idle = e;
        self.idle_count += 1;
    }

    pub fn deinit(self: *Pool) void {
        while (self.idle) |e| {
            self.idle = e.next;
            e.destroy();
        }
        self.idle_count = 0;
    }
};

/// CRC-32 (the one gzip wants), eight bytes a round off comptime tables.
///
/// std's is a single 256-entry table stepped one byte at a time, which showed up
/// as a third of the time spent compressing a response.
pub const Crc32 = struct {
    v: u32 = 0xffffffff,

    /// `tables[k][b]` folds byte `b` forward over `k` more zero bytes, so eight
    /// input bytes collapse into eight independent lookups.
    const tables = blk: {
        @setEvalBranchQuota(20_000);
        var t: [8][256]u32 = undefined;
        for (&t[0], 0..) |*e, i| {
            var c: u32 = i;
            for (0..8) |_| c = if (c & 1 != 0) 0xedb88320 ^ (c >> 1) else c >> 1;
            e.* = c;
        }
        for (1..8) |k| for (0..256) |i| {
            const prev = t[k - 1][i];
            t[k][i] = t[0][prev & 0xff] ^ (prev >> 8);
        };
        break :blk t;
    };

    pub fn update(self: *Crc32, bytes: []const u8) void {
        var c = self.v;
        var rest = bytes;
        while (rest.len >= 8) {
            const lo = std.mem.readInt(u32, rest[0..4], .little) ^ c;
            const hi = std.mem.readInt(u32, rest[4..8], .little);
            c = tables[7][lo & 0xff] ^ tables[6][(lo >> 8) & 0xff] ^
                tables[5][(lo >> 16) & 0xff] ^ tables[4][lo >> 24] ^
                tables[3][hi & 0xff] ^ tables[2][(hi >> 8) & 0xff] ^
                tables[1][(hi >> 16) & 0xff] ^ tables[0][hi >> 24];
            rest = rest[8..];
        }
        for (rest) |b| c = tables[0][(c ^ b) & 0xff] ^ (c >> 8);
        self.v = c;
    }

    pub fn final(self: *const Crc32) u32 {
        return ~self.v;
    }
};

/// Whether the client takes gzip over the original.
pub fn clientAccepts(accept_encoding: ?[]const u8) bool {
    var buf: [3]encoding.Coding = undefined;
    return encoding.Accept.parse(accept_encoding).rank(&.{.gzip}, &buf).len > 0;
}

/// Whether a response is one gzip would compress for a client that takes
/// it. Such a response varies by Accept-Encoding, compressed or not.
pub fn negotiable(status: u16, headers: []const Header) bool {
    if (status < 200 or status >= 300 or status == 204) return false;
    if (findHeader(headers, "content-encoding") != null) return false;
    if (encoding.noTransform(findHeader(headers, "cache-control"))) return false;
    return compressible(findHeader(headers, "content-type"));
}

/// Text-like types that compress well. Streams (SSE) are left alone: a
/// compressor holds data back, which defeats them.
pub fn compressible(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    const base = std.mem.trim(u8, ct[0 .. std.mem.indexOfScalar(u8, ct, ';') orelse ct.len], " \t");
    if (std.ascii.startsWithIgnoreCase(base, "text/")) return !std.ascii.eqlIgnoreCase(base, "text/event-stream");
    const types = [_][]const u8{
        "application/json",         "application/javascript", "application/xml",
        "application/wasm",         "image/svg+xml",          "application/manifest+json",
        "application/x-javascript", "application/ld+json",    "application/rss+xml",
    };
    for (types) |t| if (std.ascii.eqlIgnoreCase(base, t)) return true;
    return std.ascii.endsWithIgnoreCase(base, "+json") or std.ascii.endsWithIgnoreCase(base, "+xml");
}

pub fn findHeader(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

test "accept-encoding" {
    try std.testing.expect(clientAccepts("gzip, deflate, br"));
    try std.testing.expect(clientAccepts("br;q=1.0, gzip;q=0.8"));
    try std.testing.expect(!clientAccepts("gzip;q=0"));
    try std.testing.expect(!clientAccepts("br"));
    try std.testing.expect(!clientAccepts(null));
    try std.testing.expect(clientAccepts("*"));
    try std.testing.expect(!clientAccepts("gzip;q=0.5, identity"));
    try std.testing.expect(!clientAccepts("gzip;q=abc"));
}

test "negotiable responses" {
    const t = std.testing;
    const text = [_]Header{.{ .name = "Content-Type", .value = "text/plain" }};
    try t.expect(negotiable(200, &text));
    try t.expect(negotiable(206, &text));
    try t.expect(!negotiable(204, &text));
    try t.expect(!negotiable(304, &text));
    try t.expect(!negotiable(404, &text));
    try t.expect(!negotiable(200, &.{.{ .name = "content-type", .value = "image/png" }}));
    try t.expect(!negotiable(200, &.{ text[0], .{ .name = "Content-Encoding", .value = "br" } }));
    try t.expect(!negotiable(200, &.{ text[0], .{ .name = "cache-control", .value = "public, no-transform" } }));
}

test "compressible types" {
    try std.testing.expect(compressible("text/html; charset=utf-8"));
    try std.testing.expect(compressible("application/json"));
    try std.testing.expect(compressible("application/problem+json"));
    try std.testing.expect(!compressible("text/event-stream"));
    try std.testing.expect(!compressible("image/png"));
    try std.testing.expect(!compressible(null));
}

test "round trip" {
    const alloc = std.testing.allocator;
    const e = try Encoder.create(alloc);
    defer e.destroy();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(alloc);
    for (0..2000) |i| try input.print(alloc, "line {d} of some repetitive text\n", .{i % 50});
    var compressed: std.ArrayList(u8) = .empty;
    defer compressed.deinit(alloc);
    // Fed in uneven chunks, drained as it goes, like a response body.
    var off: usize = 0;
    var step: usize = 1;
    while (off < input.items.len) : (step = step * 3 % 7919 + 1) {
        const n = @min(step, input.items.len - off);
        try e.write(input.items[off .. off + n]);
        off += n;
        try compressed.appendSlice(alloc, e.output());
        e.consume();
    }
    try e.finish();
    try compressed.appendSlice(alloc, e.output());
    try std.testing.expect(compressed.items.len < input.items.len / 4);

    var in: std.Io.Reader = .fixed(compressed.items);
    var buf: [flate.max_window_len]u8 = undefined;
    var d: flate.Decompress = .init(&in, .gzip, &buf);
    const got = try d.reader.allocRemaining(alloc, .unlimited);
    defer alloc.free(got);
    try std.testing.expectEqualStrings(input.items, got);
}

test "the pool reuses encoders, keeps at most max_idle, and stops at max_active" {
    const alloc = std.testing.allocator;
    var pool: Pool = .{ .alloc = alloc };
    defer pool.deinit();

    // A released encoder comes back rather than being allocated again.
    const first = pool.acquire().?;
    pool.release(first);
    try std.testing.expectEqual(first, pool.acquire().?);
    try std.testing.expectEqual(@as(u32, 1), pool.active);

    // Past max_idle the extras are freed instead of parked.
    var held: [max_idle + 2]*Encoder = undefined;
    held[0] = first;
    for (held[1..]) |*e| e.* = pool.acquire().?;
    for (held) |e| pool.release(e);
    try std.testing.expectEqual(@as(u32, 0), pool.active);
    try std.testing.expectEqual(@as(u32, max_idle), pool.idle_count);

    // max_active is a hard ceiling; past it a response goes out uncompressed.
    var out: [max_active]*Encoder = undefined;
    for (&out) |*e| e.* = pool.acquire().?;
    try std.testing.expect(pool.acquire() == null);
    for (out) |e| pool.release(e);
    try std.testing.expectEqual(@as(u32, 0), pool.active);

    // A reused encoder still produces a valid stream.
    const e = pool.acquire().?;
    defer pool.release(e);
    try e.write("hello hello hello");
    try e.finish();
    try std.testing.expect(e.output().len > 0);
}

test "the crc matches std's, at every alignment and in pieces" {
    var data: [1000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    for ([_]usize{ 0, 1, 7, 8, 9, 63, 64, 511, 1000 }) |n| {
        var ours: Crc32 = .{};
        ours.update(data[0..n]);
        try std.testing.expectEqual(std.hash.Crc32.hash(data[0..n]), ours.final());
    }
    // Split anywhere and the running value carries across.
    var split: Crc32 = .{};
    split.update(data[0..3]);
    split.update(data[3..100]);
    split.update(data[100..]);
    try std.testing.expectEqual(std.hash.Crc32.hash(&data), split.final());
}

test "an encoder's output is a gzip stream std can read back" {
    const alloc = std.testing.allocator;
    const e = try Encoder.create(alloc);
    defer e.destroy();
    const body = "the quick brown fox jumps over the lazy dog, " ** 200;
    // In pieces, as a proxied response arrives.
    try e.write(body[0 .. body.len / 3]);
    try e.write(body[body.len / 3 ..]);
    try e.finish();

    const gz = e.output();
    try std.testing.expect(gz.len > 18);
    try std.testing.expectEqualSlices(u8, gzip_header[0..3], gz[0..3]);

    var in: std.Io.Reader = .fixed(gz);
    var win: [flate.max_window_len]u8 = undefined;
    var d: flate.Decompress = .init(&in, .gzip, &win);
    var plain: std.Io.Writer.Allocating = .init(alloc);
    defer plain.deinit();
    _ = try d.reader.streamRemaining(&plain.writer);
    try std.testing.expectEqualSlices(u8, body, plain.written());

    // And a reset encoder starts a fresh stream, not a continuation.
    try e.reset();
    try e.write("second");
    try e.finish();
    var in2: std.Io.Reader = .fixed(e.output());
    var d2: flate.Decompress = .init(&in2, .gzip, &win);
    var plain2: std.Io.Writer.Allocating = .init(alloc);
    defer plain2.deinit();
    _ = try d2.reader.streamRemaining(&plain2.writer);
    try std.testing.expectEqualSlices(u8, "second", plain2.written());
}

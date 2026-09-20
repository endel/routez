//! Streaming gzip for responses.
//!
//! A compressor costs about 300 KB: std's deflate tables are ~224 KB and its
//! window is another 64 KiB. That is past the allocator's largest size class, so
//! creating one per response meant an mmap, the page faults to first-touch it and
//! a munmap every time. Each worker keeps a few on a freelist instead (`Pool`).
//!
//! One is still created only for a response that qualifies, and a worker runs at
//! most `max_active` at once; past that responses go out uncompressed.
const std = @import("std");
const flate = std.compress.flate;
const common = @import("http/common.zig");
const Header = common.Header;
const encoding = @import("encoding.zig");

pub const max_active = 64;
/// Bodies known to be smaller than this aren't worth the CPU.
pub const min_length = 1024;
/// Encoders a worker keeps between responses. Compressing is synchronous, so
/// only the responses still streaming hold one and a handful covers the reuse;
/// keeping `max_active` of them would park 19 MB per worker for a feature that
/// may be idle.
pub const max_idle = 4;

pub const Encoder = struct {
    alloc: std.mem.Allocator,
    out: std.Io.Writer.Allocating,
    window: []u8,
    c: flate.Compress,
    /// Next on a `Pool` freelist; meaningless while in use.
    next: ?*Encoder = null,

    /// Heap-allocated: the compressor points at `out`.
    pub fn create(alloc: std.mem.Allocator) !*Encoder {
        const self = try alloc.create(Encoder);
        errdefer alloc.destroy(self);
        self.alloc = alloc;
        self.out = try .initCapacity(alloc, 16 * 1024);
        errdefer self.out.deinit();
        self.window = try alloc.alloc(u8, flate.max_window_len);
        errdefer alloc.free(self.window);
        self.c = try flate.Compress.init(&self.out.writer, self.window, .gzip, .level_4);
        return self;
    }

    pub fn destroy(self: *Encoder) void {
        self.out.deinit();
        self.alloc.free(self.window);
        self.alloc.destroy(self);
    }

    /// Ready for another response, keeping the tables and the window.
    fn reset(self: *Encoder) !void {
        self.out.clearRetainingCapacity();
        self.c = try flate.Compress.init(&self.out.writer, self.window, .gzip, .level_4);
    }

    /// Compress `data`; compressed bytes accumulate in `output()`.
    pub fn write(self: *Encoder, data: []const u8) !void {
        try self.c.writer.writeAll(data);
    }

    /// Flush whatever the compressor holds, ending the gzip stream.
    pub fn finish(self: *Encoder) !void {
        try self.c.finish();
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
        const e = if (self.idle) |head| blk: {
            self.idle = head.next;
            self.idle_count -= 1;
            head.next = null;
            head.reset() catch {
                head.destroy();
                break :blk null;
            };
            break :blk head;
        } else Encoder.create(self.alloc) catch null;
        if (e != null) self.active += 1;
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

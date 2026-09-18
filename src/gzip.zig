//! Streaming gzip for responses.
//!
//! A compressor costs about 300 KB (std's deflate tables plus its 64 KiB
//! window), so one is created only for a response that qualifies, and a
//! worker runs at most `max_active` at once; past that responses go out
//! uncompressed.
const std = @import("std");
const flate = std.compress.flate;
const common = @import("http/common.zig");
const Header = common.Header;

pub const max_active = 64;
/// Bodies known to be smaller than this aren't worth the CPU.
pub const min_length = 1024;

pub const Encoder = struct {
    alloc: std.mem.Allocator,
    out: std.Io.Writer.Allocating,
    window: []u8,
    c: flate.Compress,

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

/// Whether the client takes gzip: listed in Accept-Encoding with q > 0.
pub fn clientAccepts(accept_encoding: ?[]const u8) bool {
    const v = accept_encoding orelse return false;
    var it = std.mem.splitScalar(u8, v, ',');
    while (it.next()) |raw| {
        var parts = std.mem.splitScalar(u8, std.mem.trim(u8, raw, " \t"), ';');
        const coding = std.mem.trim(u8, parts.first(), " \t");
        if (!std.ascii.eqlIgnoreCase(coding, "gzip") and !std.mem.eql(u8, coding, "*")) continue;
        while (parts.next()) |param| {
            const p = std.mem.trim(u8, param, " \t");
            if (std.ascii.startsWithIgnoreCase(p, "q=")) {
                const q = std.fmt.parseFloat(f32, p[2..]) catch return false;
                return q > 0;
            }
        }
        return true;
    }
    return false;
}

/// Text-like types that compress well. Streams (SSE) are left alone: a
/// compressor holds data back, which defeats them.
pub fn compressible(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    const base = std.mem.trim(u8, ct[0 .. std.mem.indexOfScalar(u8, ct, ';') orelse ct.len], " \t");
    if (std.ascii.startsWithIgnoreCase(base, "text/")) return !std.ascii.eqlIgnoreCase(base, "text/event-stream");
    const types = [_][]const u8{
        "application/json",       "application/javascript", "application/xml",
        "application/wasm",       "image/svg+xml",          "application/manifest+json",
        "application/x-javascript", "application/ld+json",  "application/rss+xml",
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

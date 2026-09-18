//! Fuzz targets for everything that parses client or upstream bytes.
//!
//!   zig build fuzz -Doptimize=ReleaseSafe -Dfuzz-iterations=5000000
//!
//! Zig 0.16.0's `--fuzz` mode doesn't build (its test runner fails to
//! compile), so each target runs under a seeded mutation loop instead.
const std = @import("std");
const options = @import("fuzz_options");
const testing = std.testing;
const parser = @import("http1/parser.zig");
const router = @import("router.zig");
const static = @import("handlers/static.zig");
const common = @import("http/common.zig");

const request_seeds = [_][]const u8{
    "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc",
    "POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    "GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
};

test "fuzz: request head" {
    try mutate(struct {
        fn f(input: []const u8) anyerror!void {
            var hb: [64]parser.Header = undefined;
            const parsed = (parser.parseRequest(input, &hb, .{ .max_head = 4096, .max_headers = hb.len }) catch return) orelse return;
            const h = parsed.head;
            try testing.expect(parsed.len <= input.len);
            // Never both framings: that is the smuggling ambiguity.
            try testing.expect(!(h.chunked and h.content_length != null));
            try testing.expect(common.isToken(h.method));
            for (h.headers) |hdr| {
                try testing.expect(common.isToken(hdr.name));
                try testing.expect(common.isFieldValue(hdr.value));
            }
        }
    }.f, &request_seeds);
}

test "fuzz: response head" {
    try mutate(struct {
        fn f(input: []const u8) anyerror!void {
            var hb: [64]parser.Header = undefined;
            const parsed = (parser.parseResponse(input, &hb, .{ .max_head = 4096, .max_headers = hb.len }) catch return) orelse return;
            try testing.expect(parsed.head.status >= 100 and parsed.head.status <= 999);
            _ = parser.responseBodyKind(&parsed.head, "GET");
        }
    }.f, &.{"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"});
}

fn decodeWhole(input: []const u8, out: *std.ArrayList(u8)) !bool {
    var dec = parser.BodyDecoder.init(.chunked);
    var rest = input;
    while (rest.len > 0 and !dec.done) {
        const s = try dec.decode(rest);
        try out.appendSlice(testing.allocator, s.data);
        if (s.consumed == 0) break;
        rest = rest[s.consumed..];
    }
    return dec.done;
}

test "fuzz: chunked decoding is split-independent" {
    try mutate(struct {
        fn f(input: []const u8) anyerror!void {
            var whole: std.ArrayList(u8) = .empty;
            defer whole.deinit(testing.allocator);
            const whole_done = decodeWhole(input, &whole) catch return;

            // The same bytes one at a time must decode identically.
            var split: std.ArrayList(u8) = .empty;
            defer split.deinit(testing.allocator);
            var dec = parser.BodyDecoder.init(.chunked);
            for (input) |*b| {
                if (dec.done) break;
                const s = dec.decode(b[0..1]) catch return error.SplitDisagrees;
                try split.appendSlice(testing.allocator, s.data);
            }
            try testing.expectEqual(whole_done, dec.done);
            try testing.expectEqualSlices(u8, whole.items, split.items);
            try testing.expect(whole.items.len <= input.len);
        }
    }.f, &.{ "4\r\nWiki\r\n0\r\n\r\n", "1;x=y\r\na\r\n0\r\nT: v\r\n\r\n" });
}

test "fuzz: path normalization" {
    try mutate(struct {
        fn f(input: []const u8) anyerror!void {
            var buf: [4096]u8 = undefined;
            const t = router.normalizeTarget(input, &buf) catch return;
            const p = t.path;
            try testing.expect(p.len > 0 and p[0] == '/');
            try testing.expect(std.mem.indexOf(u8, p, "//") == null);
            try testing.expect(std.mem.indexOfScalar(u8, p, 0) == null);
            var it = std.mem.splitScalar(u8, p, '/');
            while (it.next()) |seg| {
                try testing.expect(!std.mem.eql(u8, seg, ".."));
                try testing.expect(!std.mem.eql(u8, seg, "."));
            }
            // Normalizing again is a no-op, once re-encoded.
            var enc: std.ArrayList(u8) = .empty;
            defer enc.deinit(testing.allocator);
            try router.encodePath(p, &enc, testing.allocator);
            var buf2: [4096 * 3]u8 = undefined;
            const t2 = try router.normalizeTarget(enc.items, &buf2);
            try testing.expectEqualStrings(p, t2.path);
        }
    }.f, &.{ "/a/../b/./c//d?x", "/%2e%2e/x", "http://h/x/y" });
}

test "fuzz: range header" {
    try mutate(struct {
        fn f(input: []const u8) anyerror!void {
            const size: u64 = 1000;
            switch (static.parseRange(input, size)) {
                .range => |r| try testing.expect(r.start < r.end and r.end <= size),
                else => {},
            }
        }
    }.f, &.{ "bytes=0-9", "bytes=-5", "bytes=10-" });
}

/// Run `target` on each seed, then on random mutations of them: byte flips,
/// insertions of protocol-significant bytes, deletions, splices and
/// truncations. A target error other than a clean parse rejection fails.
fn mutate(comptime target: fn ([]const u8) anyerror!void, seeds: []const []const u8) !void {
    for (seeds) |seed| try target(seed);
    var prng = std.Random.DefaultPrng.init(0x5eed_1e55);
    const r = prng.random();
    const interesting = "\r\n:;, \t%./0123456789abcdefABCDEF-\x00\xff";
    var buf: [2048]u8 = undefined;
    var i: u64 = 0;
    while (i < options.iterations) : (i += 1) {
        const seed = seeds[r.uintLessThan(usize, seeds.len)];
        var len: usize = @min(seed.len, buf.len);
        @memcpy(buf[0..len], seed[0..len]);
        const edits = 1 + r.uintLessThan(u8, 8);
        for (0..edits) |_| {
            switch (r.uintLessThan(u8, 5)) {
                0 => if (len > 0) {
                    buf[r.uintLessThan(usize, len)] = r.int(u8);
                },
                1 => if (len < buf.len) {
                    const at = r.uintAtMost(usize, len);
                    std.mem.copyBackwards(u8, buf[at + 1 .. len + 1], buf[at..len]);
                    buf[at] = interesting[r.uintLessThan(usize, interesting.len)];
                    len += 1;
                },
                2 => if (len > 0) {
                    const at = r.uintLessThan(usize, len);
                    std.mem.copyForwards(u8, buf[at .. len - 1], buf[at + 1 .. len]);
                    len -= 1;
                },
                3 => {
                    // Splice part of another seed in.
                    const other = seeds[r.uintLessThan(usize, seeds.len)];
                    if (other.len == 0) continue;
                    const from = r.uintLessThan(usize, other.len);
                    const n = @min(other.len - from, buf.len - len, 64);
                    const at = r.uintAtMost(usize, len);
                    std.mem.copyBackwards(u8, buf[at + n .. len + n], buf[at..len]);
                    @memcpy(buf[at .. at + n], other[from .. from + n]);
                    len += n;
                },
                else => len = r.uintAtMost(usize, len),
            }
        }
        target(buf[0..len]) catch |err| {
            std.debug.print("fuzz failure {s} on input ({d} bytes): {any}\n", .{ @errorName(err), len, buf[0..len] });
            return err;
        };
    }
}

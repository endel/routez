//! Content-coding negotiation (RFC 9110 §12.5.3) for precompressed files
//! and on-the-fly gzip.
const std = @import("std");
const common = @import("http/common.zig");
const Header = common.Header;

/// Codings a precompressed file may be stored in, as `path` + `suffix()`.
pub const Coding = enum {
    br,
    zstd,
    gzip,

    /// The Content-Encoding token.
    pub fn token(self: Coding) []const u8 {
        return @tagName(self);
    }

    /// The file-name suffix of a file precompressed with this coding.
    pub fn suffix(self: Coding) []const u8 {
        return switch (self) {
            .br => ".br",
            .zstd => ".zst",
            .gzip => ".gz",
        };
    }
};

/// Weights from an Accept-Encoding header, in thousandths (q=0.5 is 500);
/// null for a coding the header doesn't list.
pub const Accept = struct {
    br: ?u16 = null,
    zstd: ?u16 = null,
    gzip: ?u16 = null,
    identity: ?u16 = null,
    star: ?u16 = null,

    /// A missing header takes no coding but identity (as nginx and most
    /// servers do, though RFC 9110 would allow any). Entries whose q is
    /// malformed are skipped; the first entry for a coding counts.
    pub fn parse(header: ?[]const u8) Accept {
        var self: Accept = .{};
        const v = header orelse return self;
        var it = std.mem.splitScalar(u8, v, ',');
        while (it.next()) |raw| {
            var parts = std.mem.splitScalar(u8, raw, ';');
            const name = std.mem.trim(u8, parts.first(), " \t");
            var q: u16 = 1000;
            var bad = false;
            while (parts.next()) |param| {
                const p = std.mem.trim(u8, param, " \t");
                if (p.len >= 2 and (p[0] == 'q' or p[0] == 'Q') and p[1] == '=') {
                    q = parseQ(p[2..]) orelse {
                        bad = true;
                        break;
                    };
                }
            }
            if (bad) continue;
            const slot: *?u16 = if (std.ascii.eqlIgnoreCase(name, "br"))
                &self.br
            else if (std.ascii.eqlIgnoreCase(name, "zstd"))
                &self.zstd
            else if (std.ascii.eqlIgnoreCase(name, "gzip") or std.ascii.eqlIgnoreCase(name, "x-gzip"))
                &self.gzip
            else if (std.ascii.eqlIgnoreCase(name, "identity"))
                &self.identity
            else if (std.mem.eql(u8, name, "*"))
                &self.star
            else
                continue;
            if (slot.* == null) slot.* = q;
        }
        return self;
    }

    /// The coding's weight: its own entry, else `*`'s, else 0.
    pub fn weight(self: Accept, c: Coding) u16 {
        const own = switch (c) {
            .br => self.br,
            .zstd => self.zstd,
            .gzip => self.gzip,
        };
        return own orelse self.star orelse 0;
    }

    /// Identity is acceptable unless listed, or covered by `*`, with q=0.
    pub fn identityWeight(self: Accept) u16 {
        return self.identity orelse self.star orelse 1000;
    }

    /// The codings of `offered` the client takes, best first: by weight,
    /// then in `offered` order. A coding weighted below an explicit
    /// `identity` entry is left out, since the client would rather have
    /// the original; unlisted, identity ranks last.
    pub fn rank(self: Accept, offered: []const Coding, out: *[std.meta.fields(Coding).len]Coding) []const Coding {
        var n: usize = 0;
        const id = self.identity orelse 0;
        for (offered) |c| {
            const w = self.weight(c);
            if (w == 0 or w < id) continue;
            if (std.mem.indexOfScalar(Coding, out[0..n], c) != null) continue;
            // Insertion sort, stable: equal weights keep `offered` order.
            var i = n;
            while (i > 0 and self.weight(out[i - 1]) < w) : (i -= 1) out[i] = out[i - 1];
            out[i] = c;
            n += 1;
        }
        return out[0..n];
    }
};

/// A qvalue: "0" to "1" with up to three decimals.
fn parseQ(s: []const u8) ?u16 {
    if (s.len == 0 or s.len > 5 or (s[0] != '0' and s[0] != '1')) return null;
    var q: u16 = @as(u16, s[0] - '0') * 1000;
    if (s.len == 1) return q;
    if (s[1] != '.') return null;
    var scale: u16 = 100;
    for (s[2..]) |c| {
        if (!std.ascii.isDigit(c)) return null;
        q += @as(u16, c - '0') * scale;
        scale /= 10;
    }
    return if (q > 1000) null else q;
}

/// Whether a Cache-Control value forbids changing the body's encoding.
pub fn noTransform(cache_control: ?[]const u8) bool {
    const v = cache_control orelse return false;
    var it = std.mem.splitScalar(u8, v, ',');
    while (it.next()) |d| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, d, " \t"), "no-transform")) return true;
    }
    return false;
}

/// Add Accept-Encoding to `list`'s Vary, unless it's there already or Vary
/// is `*`. `list` needs spare capacity for one header.
pub fn addVary(a: std.mem.Allocator, list: *std.ArrayListUnmanaged(Header)) void {
    for (list.items) |*h| {
        if (!std.ascii.eqlIgnoreCase(h.name, "vary")) continue;
        var it = std.mem.splitScalar(u8, h.value, ',');
        while (it.next()) |f| {
            const t = std.mem.trim(u8, f, " \t");
            if (std.mem.eql(u8, t, "*") or std.ascii.eqlIgnoreCase(t, "accept-encoding")) return;
        }
        h.value = std.fmt.allocPrint(a, "{s}, Accept-Encoding", .{h.value}) catch return;
        return;
    }
    list.appendAssumeCapacity(.{ .name = "vary", .value = "Accept-Encoding" });
}

test "accept-encoding weights" {
    const t = std.testing;
    const a = Accept.parse("gzip, deflate, br;q=0.8");
    try t.expectEqual(1000, a.weight(.gzip));
    try t.expectEqual(800, a.weight(.br));
    try t.expectEqual(0, a.weight(.zstd));
    try t.expectEqual(1000, a.identityWeight());

    try t.expectEqual(0, Accept.parse(null).weight(.gzip));
    try t.expectEqual(0, Accept.parse("").weight(.gzip));
    try t.expectEqual(1000, Accept.parse("").identityWeight());
    try t.expectEqual(0, Accept.parse("gzip;q=0").weight(.gzip));
    try t.expectEqual(1000, Accept.parse("GZIP").weight(.gzip));
    try t.expectEqual(1000, Accept.parse("x-gzip").weight(.gzip));
    try t.expectEqual(500, Accept.parse("gzip ; Q=0.5").weight(.gzip));
    try t.expectEqual(1000, Accept.parse("gzip;q=1.000").weight(.gzip));
    try t.expectEqual(1, Accept.parse("gzip;q=0.001").weight(.gzip));
    try t.expectEqual(1000, Accept.parse("gzip;q=1.").weight(.gzip));
    // First entry wins.
    try t.expectEqual(0, Accept.parse("gzip;q=0, gzip").weight(.gzip));

    // `*` covers unlisted codings, identity included.
    const s = Accept.parse("*;q=0.3, br");
    try t.expectEqual(300, s.weight(.gzip));
    try t.expectEqual(1000, s.weight(.br));
    try t.expectEqual(300, s.identityWeight());
    try t.expectEqual(0, Accept.parse("*;q=0").identityWeight());
    try t.expectEqual(1000, Accept.parse("*;q=0, identity").identityWeight());
    try t.expectEqual(0, Accept.parse("identity;q=0").identityWeight());
}

test "accept-encoding malformed" {
    const t = std.testing;
    const bad = [_][]const u8{
        "gzip;q=",  "gzip;q=2",    "gzip;q=1.5",   "gzip;q=0.0001", "gzip;q=.5",
        "gzip;q=x", "gzip;q=-0.5", "gzip;q=1.001", "gzip;q=0.5x",
    };
    for (bad) |h| try t.expectEqual(0, Accept.parse(h).weight(.gzip));
    // A bad entry doesn't spoil the others.
    try t.expectEqual(1000, Accept.parse("br;q=abc, gzip").weight(.gzip));
    try t.expectEqual(0, Accept.parse("br;q=abc, gzip").weight(.br));
    try t.expectEqual(1000, Accept.parse(",,; ;gzip, ,").identityWeight());
    try t.expectEqual(1000, Accept.parse("gzip;level=9").weight(.gzip));
    try t.expectEqual(0, Accept.parse("gzipx, gz").weight(.gzip));
}

test "accept-encoding ranking" {
    const t = std.testing;
    var buf: [3]Coding = undefined;
    const all = [_]Coding{ .br, .zstd, .gzip };
    try t.expectEqualSlices(Coding, &.{ .br, .zstd, .gzip }, Accept.parse("gzip, zstd, br").rank(&all, &buf));
    try t.expectEqualSlices(Coding, &.{ .gzip, .br }, Accept.parse("gzip, br;q=0.9").rank(&all, &buf));
    try t.expectEqualSlices(Coding, &.{ .gzip, .br }, Accept.parse("gzip, br").rank(&.{ .gzip, .br }, &buf));
    try t.expectEqualSlices(Coding, &.{.gzip}, Accept.parse("gzip").rank(&all, &buf));
    try t.expectEqualSlices(Coding, &.{}, Accept.parse(null).rank(&all, &buf));
    try t.expectEqualSlices(Coding, &.{}, Accept.parse("gzip;q=0").rank(&all, &buf));
    try t.expectEqualSlices(Coding, &.{ .br, .zstd, .gzip }, Accept.parse("*").rank(&all, &buf));
    try t.expectEqualSlices(Coding, &.{.gzip}, Accept.parse("*;q=0, gzip").rank(&all, &buf));
    // Identity preferred over a coding: send the original.
    try t.expectEqualSlices(Coding, &.{}, Accept.parse("gzip;q=0.5, identity").rank(&all, &buf));
    try t.expectEqualSlices(Coding, &.{.br}, Accept.parse("br, gzip;q=0.5, identity;q=0.8").rank(&all, &buf));
    try t.expectEqualSlices(Coding, &.{.gzip}, Accept.parse("gzip, identity;q=0").rank(&all, &buf));
    try t.expectEqualSlices(Coding, &.{ .br, .zstd, .gzip }, Accept.parse("*;q=0.3, br").rank(&all, &buf));
    try t.expectEqualSlices(Coding, &.{ .br, .gzip }, Accept.parse("br;q=1.0, gzip;q=0.8").rank(&all, &buf));
    // Duplicates in the offer are ignored.
    try t.expectEqualSlices(Coding, &.{.gzip}, Accept.parse("gzip").rank(&.{ .gzip, .gzip }, &buf));
}

test "no-transform" {
    const t = std.testing;
    try t.expect(noTransform("no-transform"));
    try t.expect(noTransform("public, No-Transform, max-age=60"));
    try t.expect(!noTransform("no-transforms"));
    try t.expect(!noTransform("no-store"));
    try t.expect(!noTransform(null));
}

test "vary" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const t = std.testing;
    var list: std.ArrayListUnmanaged(Header) = .empty;
    try list.ensureTotalCapacity(a, 4);
    addVary(a, &list);
    try t.expectEqualStrings("Accept-Encoding", list.items[0].value);
    addVary(a, &list);
    try t.expectEqual(1, list.items.len);

    list.clearRetainingCapacity();
    list.appendAssumeCapacity(.{ .name = "Vary", .value = "Origin" });
    addVary(a, &list);
    try t.expectEqualStrings("Origin, Accept-Encoding", list.items[0].value);
    addVary(a, &list);
    try t.expectEqualStrings("Origin, Accept-Encoding", list.items[0].value);

    list.clearRetainingCapacity();
    list.appendAssumeCapacity(.{ .name = "vary", .value = "Origin, accept-encoding" });
    addVary(a, &list);
    try t.expectEqualStrings("Origin, accept-encoding", list.items[0].value);

    list.clearRetainingCapacity();
    list.appendAssumeCapacity(.{ .name = "vary", .value = "*" });
    addVary(a, &list);
    try t.expectEqualStrings("*", list.items[0].value);
    try t.expectEqual(1, list.items.len);
}

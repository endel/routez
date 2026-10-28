//! The heaviest senders: the fingerprints and networks most requests come
//! from lately, for `routez ctl top` and for upstream admission. A flood
//! usually comes from one tool or a few, so while it lasts its fingerprint
//! carries a share of requests far above the one it has when things are
//! calm. That, not a list of good or bad fingerprints, is what marks it.
//!
//! Each worker tallies its requests per key for a second in tables of its
//! own, then folds them into the process-wide `board`, whose lock is taken
//! once a second per worker. The board keeps the heaviest keys
//! (Space-Saving: a new key takes the slot of the lightest) with a request
//! rate decaying over ~10 s, and for fingerprints the share each had while
//! no upstream queued: its usual share.
//!
//! A fingerprint surges once it has a quarter of all requests and four
//! times its usual share. Under load, `Group.admit` puts its requests
//! behind everyone else's. Until the board has seen two minutes without
//! queueing it has no usual shares, and nothing surges.
const std = @import("std");
const fingerprint = @import("fingerprint.zig");
const client_limits = @import("client_limits.zig");

const Key = [16]u8;

/// Requests without a fingerprint: plain HTTP. It unpacks to a JA4 no
/// ClientHello has, SNI without extensions.
pub const no_fingerprint: Key = @splat(0);

/// Network lengths requests are tallied by, in the 16-byte form.
pub const v4_bits = 96 + 24;
pub const v6_bits = 64;

/// The network `ip` is tallied under.
pub fn network(ip: [16]u8) Key {
    return client_limits.network(ip, v4_bits - 96, v6_bits);
}

const rate_decay: f32 = 0.904837; // exp(-1/10): rates over ~10 s
const usual_decay: f32 = 0.998335; // exp(-1/600): usual shares over ~10 min
const warm_s = 120;
const surge_share: f32 = 0.25;
const surge_ratio: f32 = 4;
pub const max_surging = 4;

/// One worker's requests this second.
pub const Tally = struct {
    fingerprints: Counts(64) = .{},
    networks: Counts(128) = .{},
    /// Requests this second, kept in a table or not.
    requests: u32 = 0,
    /// Some upstream queued a request this second.
    pressure: bool = false,
    /// What the board found surging, as of the last fold.
    surging: [max_surging]Key = undefined,
    n_surging: u8 = 0,

    pub fn add(self: *Tally, fp: ?Key, net: Key) void {
        self.requests += 1;
        self.fingerprints.add(fp orelse no_fingerprint);
        self.networks.add(net);
    }

    pub fn isSurging(self: *const Tally, fp: ?Key) bool {
        const k = fp orelse no_fingerprint;
        for (self.surging[0..self.n_surging]) |s| if (std.mem.eql(u8, &s, &k)) return true;
        return false;
    }

    fn clear(self: *Tally) void {
        self.fingerprints.clear();
        self.networks.clear();
        self.requests = 0;
        self.pressure = false;
    }
};

/// Open addressing at half load; past `cap` keys a second, more go uncounted.
fn Counts(comptime cap: usize) type {
    return struct {
        const Self = @This();
        const slots = cap * 2;

        keys: [slots]Key = undefined,
        /// 0 marks a free slot.
        counts: [slots]u32 = @splat(0),
        len: u32 = 0,

        fn add(self: *Self, key: Key) void {
            var i: usize = @intCast(std.hash.Wyhash.hash(0, &key) & (slots - 1));
            while (self.counts[i] != 0) : (i = (i + 1) & (slots - 1)) {
                if (std.mem.eql(u8, &self.keys[i], &key)) {
                    self.counts[i] += 1;
                    return;
                }
            }
            if (self.len == cap) return;
            self.keys[i] = key;
            self.counts[i] = 1;
            self.len += 1;
        }

        fn clear(self: *Self) void {
            if (self.len == 0) return;
            @memset(&self.counts, 0);
            self.len = 0;
        }
    };
}

pub const Entry = struct {
    key: Key,
    /// Requests a second.
    rate: f32,
    /// Fingerprints only: the share of requests while nothing queued.
    usual: f32,
    surging: bool,
};

/// Every worker of every generation folds into it.
pub var board: Board = .{};

pub const Board = struct {
    mutex: std.Io.Mutex = .init,
    fingerprints: Heavy(64) = .{},
    networks: Heavy(64) = .{},
    /// Requests a second, over all keys.
    rate: f32 = 0,
    /// Requests folded in for `second`, not yet in the rates.
    pending: u32 = 0,
    second: i64 = 0,
    pressure: bool = false,
    /// Seconds with requests and no queueing, up to `warm_s`.
    calm_s: u32 = 0,
    surging: [max_surging]Key = undefined,
    n_surging: u8 = 0,

    /// Fold one worker's second in, and hand it back what surges.
    pub fn fold(self: *Board, io: std.Io, t: *Tally, now_s: i64) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.advance(now_s);
        for (t.fingerprints.keys, t.fingerprints.counts) |k, n| if (n != 0) self.fingerprints.add(k, n);
        for (t.networks.keys, t.networks.counts) |k, n| if (n != 0) self.networks.add(k, n);
        self.pending += t.requests;
        self.pressure = self.pressure or t.pressure;
        t.clear();
        t.surging = self.surging;
        t.n_surging = self.n_surging;
    }

    /// The heaviest keys of each kind, heaviest first, as of `now_s`.
    pub fn top(self: *Board, io: std.Io, now_s: i64, fps: []Entry, nets: []Entry) struct { fingerprints: []Entry, networks: []Entry, rate: f32 } {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.advance(now_s);
        return .{
            .fingerprints = self.fingerprints.heaviest(fps, self),
            .networks = self.networks.heaviest(nets, null),
            .rate = self.rate,
        };
    }

    /// Close the seconds before `now_s`: their requests go into the rates.
    fn advance(self: *Board, now_s: i64) void {
        if (now_s <= self.second) return;
        const gap = now_s - self.second;
        self.second = now_s;
        const calm = !self.pressure and self.pending > 0;
        if (calm and self.calm_s < warm_s) self.calm_s += 1;
        // Idle seconds since decay the rates too.
        const idle = std.math.pow(f32, rate_decay, @floatFromInt(@min(gap - 1, 600)));
        self.fingerprints.close(self.pending, calm, idle);
        self.networks.close(self.pending, false, idle);
        self.rate = (self.rate * rate_decay + @as(f32, @floatFromInt(self.pending)) * (1 - rate_decay)) * idle;
        self.pending = 0;
        self.pressure = false;

        self.n_surging = 0;
        if (self.calm_s < warm_s or self.rate <= 0) return;
        for (self.fingerprints.slots[0..self.fingerprints.len]) |*s| {
            if (!self.surges(s) or self.n_surging == max_surging) continue;
            self.surging[self.n_surging] = s.key;
            self.n_surging += 1;
        }
    }

    fn surges(self: *const Board, s: *const Slot) bool {
        const share = s.rate / self.rate;
        return share >= surge_share and share >= surge_ratio * s.usual;
    }
};

const Slot = struct { key: Key, rate: f32 = 0, pending: u32 = 0, usual: f32 = 0 };

fn Heavy(comptime cap: usize) type {
    return struct {
        const Self = @This();

        slots: [cap]Slot = undefined,
        len: usize = 0,

        fn add(self: *Self, key: Key, n: u32) void {
            for (self.slots[0..self.len]) |*s| if (std.mem.eql(u8, &s.key, &key)) {
                s.pending += n;
                return;
            };
            if (self.len < cap) {
                self.slots[self.len] = .{ .key = key, .pending = n };
                self.len += 1;
                return;
            }
            // Space-Saving: the lightest gives way, and its count stays,
            // so a newcomer is never under-counted.
            var min = &self.slots[0];
            for (self.slots[1..]) |*s| if (s.rate + @as(f32, @floatFromInt(s.pending)) < min.rate + @as(f32, @floatFromInt(min.pending))) {
                min = s;
            };
            min.* = .{ .key = key, .rate = min.rate, .pending = min.pending + n };
        }

        fn close(self: *Self, total: u32, calm: bool, idle: f32) void {
            for (self.slots[0..self.len]) |*s| {
                const n: f32 = @floatFromInt(s.pending);
                s.rate = (s.rate * rate_decay + n * (1 - rate_decay)) * idle;
                if (calm) s.usual = s.usual * usual_decay + n / @as(f32, @floatFromInt(total)) * (1 - usual_decay);
                s.pending = 0;
            }
        }

        fn heaviest(self: *const Self, out: []Entry, b: ?*const Board) []Entry {
            var sorted: [cap]Slot = undefined;
            const all = sorted[0..self.len];
            @memcpy(all, self.slots[0..self.len]);
            std.mem.sort(Slot, all, {}, struct {
                fn heavier(_: void, x: Slot, y: Slot) bool {
                    return x.rate > y.rate;
                }
            }.heavier);
            const n = @min(out.len, all.len);
            for (all[0..n], out[0..n]) |s, *e| e.* = .{
                .key = s.key,
                .rate = s.rate,
                .usual = s.usual,
                .surging = if (b) |bb| bb.calm_s >= warm_s and bb.rate > 0 and bb.surges(&s) else false,
            };
            return out[0..n];
        }
    };
}

const testing = std.testing;

fn fill(b: u8) Key {
    return @splat(b);
}

test "a tally counts per key, drops what overflows, and clears on fold" {
    var t: Tally = .{};
    for (0..3) |_| t.add(fill(1), fill(9));
    t.add(null, fill(9));
    try testing.expectEqual(@as(u32, 4), t.requests);
    try testing.expectEqual(@as(u32, 2), t.fingerprints.len);
    for (0..200) |i| t.add(fill(1), net6(@intCast(i)));
    try testing.expectEqual(@as(u32, 128), t.networks.len);
    var b: Board = .{};
    b.fold(testing.io, &t, 10);
    try testing.expectEqual(@as(u32, 0), t.requests);
    try testing.expectEqual(@as(u32, 0), t.networks.len);
    try testing.expectEqual(@as(u32, 204), b.pending);
}

fn net6(i: u8) Key {
    var k: Key = @splat(0);
    k[0] = 0x20;
    k[1] = i;
    return k;
}

test "rates follow the requests, and a newcomer takes the lightest slot" {
    var b: Board = .{};
    var t: Tally = .{};
    var s: i64 = 100;
    while (s < 160) : (s += 1) {
        for (0..90) |_| t.add(fill(1), fill(9));
        for (0..10) |_| t.add(fill(2), fill(9));
        b.fold(testing.io, &t, s);
    }
    var fps: [8]Entry = undefined;
    var nets: [8]Entry = undefined;
    const got = b.top(testing.io, s, &fps, &nets);
    try testing.expectEqual(@as(usize, 2), got.fingerprints.len);
    try testing.expectEqual(fill(1), got.fingerprints[0].key);
    try testing.expectApproxEqRel(@as(f32, 90), got.fingerprints[0].rate, 0.05);
    try testing.expectApproxEqRel(@as(f32, 100), got.rate, 0.05);
    try testing.expectApproxEqRel(@as(f32, 100), got.networks[0].rate, 0.05);

    // A full table: the lightest slot goes to the newcomer, count and all.
    var h: Heavy(2) = .{};
    h.add(fill(1), 5);
    h.add(fill(2), 1);
    h.add(fill(3), 1);
    try testing.expectEqual(fill(3), h.slots[1].key);
    try testing.expectEqual(@as(u32, 2), h.slots[1].pending);
}

test "a fingerprint surges past its usual share, once the board knows it" {
    var b: Board = .{};
    var t: Tally = .{};
    var s: i64 = 1000;
    // Calm: a browser carries 70%, a tool 1%. Not long enough to know them.
    const calm = struct {
        fn second(tt: *Tally) void {
            for (0..70) |_| tt.add(fill(1), fill(9));
            for (0..29) |_| tt.add(fill(3), fill(9));
            tt.add(fill(2), fill(9));
        }
    };
    for (0..60) |_| {
        calm.second(&t);
        b.fold(testing.io, &t, s);
        s += 1;
    }
    for (0..30) |_| {
        for (0..900) |_| t.add(fill(2), fill(8));
        calm.second(&t);
        t.pressure = true;
        b.fold(testing.io, &t, s);
        s += 1;
    }
    try testing.expect(!t.isSurging(fill(2)));
    // Two minutes calm, then the tool floods.
    for (0..warm_s) |_| {
        calm.second(&t);
        b.fold(testing.io, &t, s);
        s += 1;
    }
    for (0..30) |_| {
        for (0..900) |_| t.add(fill(2), fill(8));
        calm.second(&t);
        t.pressure = true;
        b.fold(testing.io, &t, s);
        s += 1;
    }
    try testing.expect(t.isSurging(fill(2)));
    // The browser holds its share of the rest: no surge. Plain HTTP isn't
    // in the board at all.
    try testing.expect(!t.isSurging(fill(1)));
    try testing.expect(!t.isSurging(null));
    // Its usual share didn't learn the flood.
    var fps: [8]Entry = undefined;
    var nets: [8]Entry = undefined;
    const got = b.top(testing.io, s, &fps, &nets);
    try testing.expectEqual(fill(2), got.fingerprints[0].key);
    try testing.expect(got.fingerprints[0].surging);
    try testing.expect(got.fingerprints[0].usual < 0.05);
    try testing.expectEqual(fill(8), got.networks[0].key);
}

test "idle seconds decay the rates" {
    var b: Board = .{};
    var t: Tally = .{};
    for (0..100) |_| t.add(fill(1), fill(9));
    b.fold(testing.io, &t, 10);
    b.advance(11);
    const r = b.rate;
    b.advance(31);
    try testing.expect(b.rate < r * 0.2);
}

test "the key of plain HTTP is a fingerprint no ClientHello has" {
    var buf: [fingerprint.Ja4.text_len]u8 = undefined;
    try testing.expectEqualStrings("t13d000000_000000000000_000000000000", fingerprint.format(no_fingerprint, &buf));
}

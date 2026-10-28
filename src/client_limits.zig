//! Per-client limits shared by every worker and every generation: the
//! connections each address holds (`limits.max_connections_per_ip`), the
//! `limit_req` buckets, and bans (`routez ctl ban`) of networks and of JA4
//! fingerprints.
//!
//! Entries are keyed by client address and zone, hashed with a random
//! SipHash key onto shards, each a chained hash table over a node pool
//! sized at creation, so steady-state operation never allocates. A shard's
//! mutex is held for a lookup and a few stores.
//!
//! Buckets use GCRA, the token bucket held as one timestamp: the time
//! the bucket would be full again. A ban holds the time it ends. An entry
//! past its time, or a connection count back at zero, carries no state and
//! is dropped.
//!
//! When a shard is full of live entries, a new client goes untracked:
//! allowed, and counted in `untracked`. Refusing instead would let anyone
//! with enough addresses (a single IPv6 /64 has 2^64) lock every new
//! client out; they can already sidestep these limits by spreading
//! requests over those addresses, so failing open gives nothing away.
const std = @import("std");
const quic = @import("quic");
const config = @import("config.zig");
const access = @import("access.zig");

const log = std.log.scoped(.limits);

/// An IPv6 address, or an IPv4 one in mapped form.
pub const Ip = [16]u8;

/// The zone of an address's connection count; `zoneId` never returns it.
pub const conn_zone: u32 = 0;
/// The bucket of an address's uncached `auth_basic` password checks;
/// `zoneId` never returns it either (its ids are odd).
pub const auth_zone: u32 = 2;

/// A ban's length for a JA4 fingerprint, packed as `fingerprint.zig` does,
/// in place of a network's: past 128 bits, masking leaves the key whole.
pub const fingerprint_bits: u8 = 255;

/// A length a ban may have: a network's, or a fingerprint's.
pub fn isBanLength(bits: u8) bool {
    return bits <= 128 or bits == fingerprint_bits;
}

/// The zone of a ban on a network `bits` long in the 16-byte form (an IPv4
/// /24 is 120), or on a fingerprint. Even, so `zoneId` never returns one.
pub fn banZone(bits: u8) u32 {
    return 4 + 2 * @as(u32, bits);
}

fn banBits(zone: u32) ?u8 {
    if (zone == banZone(fingerprint_bits)) return fingerprint_bits;
    if (zone < banZone(0) or zone > banZone(128) or zone & 1 != 0) return null;
    return @intCast((zone - banZone(0)) / 2);
}

/// The bucket of an address's browser check puzzles and verifies; past
/// the ban zones, even like them.
pub const check_zone: u32 = banZone(128) + 2;

/// Marks a node on the free list, so `nextBans` can scan nodes by index.
const free_zone: u32 = 1 << 31;

const default_shards = 64;
const none: u32 = 0;

pub const Table = struct {
    shards: []Shard,
    shard_shift: u7,
    key: [16]u8,
    /// Entries the table can hold.
    capacity: usize,
    /// Clients left unlimited because their shard was full.
    untracked: std.atomic.Value(u64) = .init(0),
    sweep_cursor: std.atomic.Value(u32) = .init(0),
    last_warn_ns: std.atomic.Value(i64) = .init(std.math.minInt(i64)),
    /// Bans of networks held, counted by `insert` and `remove`; while
    /// zero, `banned` reads nothing else.
    bans: std.atomic.Value(u32) = .init(0),
    /// Bans of fingerprints, the same way for `fingerprintBanned`.
    fingerprint_bans: std.atomic.Value(u32) = .init(0),
    /// A bit per prefix length ever banned, IPv4's (0 to 32) apart from
    /// IPv6's, so `banned` looks up only those of the client's family.
    /// Never cleared: a clear could race a ban being added at that length.
    ban_lengths_v4: std.atomic.Value(u64) = .init(0),
    ban_lengths_v6: [3]std.atomic.Value(u64) = @splat(.init(0)),
    /// Bumped by every `ban`, so workers know to look for connections a new
    /// ban covers.
    ban_epoch: std.atomic.Value(u32) = .init(0),

    const Node = struct {
        ip: Ip,
        zone: u32,
        /// Next node in the chain, as index + 1.
        next: u32,
        /// Open connections, or a bucket's full-again time in ns.
        value: i64,
    };

    const Shard = struct {
        mutex: std.Io.Mutex align(std.atomic.cache_line) = .init,
        /// Chain heads, as node index + 1.
        heads: []u32,
        nodes: []Node,
        /// Nodes handed out so far; the rest are untouched.
        used: u32 = 0,
        /// Free list, as node index + 1.
        free: u32 = none,
        len: std.atomic.Value(u32) = .init(0),
    };

    pub fn create(gpa: std.mem.Allocator, max_entries: u32) !*Table {
        return createSharded(gpa, max_entries, default_shards);
    }

    /// `shards` is a power of two.
    pub fn createSharded(gpa: std.mem.Allocator, max_entries: u32, shards: u32) !*Table {
        std.debug.assert(std.math.isPowerOfTwo(shards));
        const per_shard: u32 = @max(1, std.math.divCeil(u32, max_entries, shards) catch unreachable);
        const buckets = std.math.ceilPowerOfTwoAssert(u32, per_shard);
        const t = try gpa.create(Table);
        errdefer gpa.destroy(t);
        t.* = .{
            .shards = try gpa.alloc(Shard, shards),
            .shard_shift = @intCast(64 - @as(u7, std.math.log2_int(u32, shards))),
            .key = undefined,
            .capacity = @as(usize, per_shard) * shards,
        };
        quic.sys.randomBytes(&t.key);
        for (t.shards) |*s| {
            s.* = .{ .heads = try gpa.alloc(u32, buckets), .nodes = try gpa.alloc(Node, per_shard) };
            @memset(s.heads, none);
        }
        return t;
    }

    pub fn destroy(self: *Table, gpa: std.mem.Allocator) void {
        for (self.shards) |*s| {
            gpa.free(s.heads);
            gpa.free(s.nodes);
        }
        gpa.free(self.shards);
        gpa.destroy(self);
    }

    /// Entries held now.
    pub fn entries(self: *const Table) usize {
        var n: usize = 0;
        for (self.shards) |*s| n += s.len.load(.monotonic);
        return n;
    }

    pub const Admit = enum {
        /// Counted; call `releaseConn` when it closes.
        counted,
        refused,
        /// The table was full: let in without counting.
        untracked,
    };

    /// Count a connection from `ip` unless it already holds `limit`.
    pub fn acquireConn(self: *Table, io: std.Io, ip: Ip, limit: u32, now_ns: i64) Admit {
        const loc = self.locate(ip, conn_zone);
        const s = loc.shard;
        s.mutex.lockUncancelable(io);
        if (find(s, ip, conn_zone, loc.bucket)) |f| {
            defer s.mutex.unlock(io);
            const n = &s.nodes[f.index].value;
            if (n.* >= limit) return .refused;
            n.* += 1;
            return .counted;
        }
        if (limit == 0) {
            s.mutex.unlock(io);
            return .refused;
        }
        const ok = self.insert(s, ip, conn_zone, loc.bucket, 1, now_ns);
        s.mutex.unlock(io);
        if (ok) return .counted;
        self.noteFull(now_ns);
        return .untracked;
    }

    pub fn releaseConn(self: *Table, io: std.Io, ip: Ip) void {
        const loc = self.locate(ip, conn_zone);
        const s = loc.shard;
        s.mutex.lockUncancelable(io);
        defer s.mutex.unlock(io);
        const f = find(s, ip, conn_zone, loc.bucket) orelse return;
        const n = &s.nodes[f.index].value;
        n.* -= 1;
        if (n.* <= 0) self.remove(s, f);
    }

    /// GCRA admission for one request: `rate` per second on average, and
    /// `burst` more at once. `zone` comes from `zoneId`.
    pub fn allowRequest(self: *Table, io: std.Io, ip: Ip, zone: u32, rate: u32, burst: u32, now_ns: i64) bool {
        return self.allowEvery(io, ip, zone, @divTrunc(std.time.ns_per_s, @as(i64, rate)), burst, now_ns);
    }

    /// `allowRequest` at one event every `interval_ns`, for rates under one
    /// a second too.
    pub fn allowEvery(self: *Table, io: std.Io, ip: Ip, zone: u32, interval_ns: i64, burst: u32, now_ns: i64) bool {
        const interval: i64 = @max(1, interval_ns);
        const tolerance = interval * @as(i64, burst);
        const loc = self.locate(ip, zone);
        const s = loc.shard;
        s.mutex.lockUncancelable(io);
        if (find(s, ip, zone, loc.bucket)) |f| {
            defer s.mutex.unlock(io);
            const full_at = &s.nodes[f.index].value;
            const from = @max(full_at.*, now_ns);
            if (from - now_ns > tolerance) return false;
            full_at.* = from + interval;
            return true;
        }
        const ok = self.insert(s, ip, zone, loc.bucket, now_ns + interval, now_ns);
        s.mutex.unlock(io);
        if (!ok) self.noteFull(now_ns);
        return true;
    }

    /// Drop the expired entries of one shard, a different one each call.
    pub fn sweepStep(self: *Table, io: std.Io, now_ns: i64) void {
        const i = self.sweep_cursor.fetchAdd(1, .monotonic) % self.shards.len;
        const s = &self.shards[i];
        s.mutex.lockUncancelable(io);
        defer s.mutex.unlock(io);
        self.sweep(s, now_ns);
    }

    pub fn anyBans(self: *const Table) bool {
        return self.bans.load(.monotonic) != 0;
    }

    /// Whether a live ban covers `ip`: one lookup per prefix length banned
    /// in its family.
    pub fn banned(self: *Table, io: std.Io, ip: Ip, now_ns: i64) bool {
        if (access.isV4(ip)) {
            var set = self.ban_lengths_v4.load(.monotonic);
            while (set != 0) : (set &= set - 1) if (self.bannedAt(io, ip, 96 + @as(u8, @ctz(set)), now_ns)) return true;
            return false;
        }
        for (&self.ban_lengths_v6, 0..) |*word, w| {
            var set = word.load(.monotonic);
            while (set != 0) : (set &= set - 1) if (self.bannedAt(io, ip, @intCast(w * 64 + @ctz(set)), now_ns)) return true;
        }
        return false;
    }

    pub fn anyFingerprintBans(self: *const Table) bool {
        return self.fingerprint_bans.load(.monotonic) != 0;
    }

    /// Whether a live ban covers the fingerprint `key`; one atomic load
    /// while none is banned.
    pub fn fingerprintBanned(self: *Table, io: std.Io, key: [16]u8, now_ns: i64) bool {
        return self.anyFingerprintBans() and self.bannedAt(io, key, fingerprint_bits, now_ns);
    }

    fn bannedAt(self: *Table, io: std.Io, ip: Ip, bits: u8, now_ns: i64) bool {
        var net = ip;
        access.mask(&net, bits);
        const zone = banZone(bits);
        const loc = self.locate(net, zone);
        const s = loc.shard;
        s.mutex.lockUncancelable(io);
        defer s.mutex.unlock(io);
        const f = find(s, net, zone, loc.bucket) orelse return false;
        return s.nodes[f.index].value > now_ns;
    }

    /// Ban `net`/`bits` until `until_ns`, replacing the end of a ban it
    /// already has. `fingerprint_bits` bans the fingerprint `net`.
    pub fn ban(self: *Table, io: std.Io, net: Ip, bits: u8, until_ns: i64, now_ns: i64) error{TableFull}!void {
        var key = net;
        access.mask(&key, bits);
        const zone = banZone(bits);
        const loc = self.locate(key, zone);
        const s = loc.shard;
        s.mutex.lockUncancelable(io);
        defer s.mutex.unlock(io);
        if (find(s, key, zone, loc.bucket)) |f| {
            s.nodes[f.index].value = until_ns;
        } else {
            if (!self.insert(s, key, zone, loc.bucket, until_ns, now_ns)) {
                // A flood fills the table with buckets just when bans are
                // needed; dropping one only lets its client start afresh.
                if (!self.evictBucket(s)) return error.TableFull;
                const ok = self.insert(s, key, zone, loc.bucket, until_ns, now_ns);
                std.debug.assert(ok);
            }
            // Masked, a key keeps the mapped prefix only at 96 bits or more.
            if (bits == fingerprint_bits) {
                // Counted in `fingerprint_bans`; it has one length.
            } else if (access.isV4(key)) {
                _ = self.ban_lengths_v4.fetchOr(@as(u64, 1) << @intCast(bits - 96), .monotonic);
            } else {
                _ = self.ban_lengths_v6[bits / 64].fetchOr(@as(u64, 1) << @intCast(bits % 64), .monotonic);
            }
        }
        // Last: a worker that acquires the new epoch then finds the ban.
        _ = self.ban_epoch.fetchAdd(1, .release);
    }

    /// Lift the ban on exactly `net`/`bits`; false if there was none.
    pub fn unban(self: *Table, io: std.Io, net: Ip, bits: u8) bool {
        var key = net;
        access.mask(&key, bits);
        const zone = banZone(bits);
        const loc = self.locate(key, zone);
        const s = loc.shard;
        s.mutex.lockUncancelable(io);
        defer s.mutex.unlock(io);
        self.remove(s, find(s, key, zone, loc.bucket) orelse return false);
        return true;
    }

    /// `bits` is `fingerprint_bits` for a fingerprint.
    pub const Ban = struct { net: Ip, bits: u8, until_ns: i64 };

    /// Where `nextBans` carries on from.
    pub const BanCursor = struct { shard: u32 = 0, node: u32 = 0 };

    /// The next live bans, up to `out.len`, holding one shard's lock at a
    /// time; empty once every shard has been read. Bans added or lifted
    /// meanwhile may or may not show.
    pub fn nextBans(self: *Table, io: std.Io, cursor: *BanCursor, now_ns: i64, out: []Ban) []Ban {
        var n: usize = 0;
        while (cursor.shard < self.shards.len and n < out.len) {
            const s = &self.shards[cursor.shard];
            s.mutex.lockUncancelable(io);
            while (cursor.node < s.used and n < out.len) : (cursor.node += 1) {
                const node = &s.nodes[cursor.node];
                const bits = banBits(node.zone) orelse continue;
                if (node.value <= now_ns) continue;
                out[n] = .{ .net = node.ip, .bits = bits, .until_ns = node.value };
                n += 1;
            }
            const done = cursor.node >= s.used;
            s.mutex.unlock(io);
            if (done) cursor.* = .{ .shard = cursor.shard + 1 };
        }
        return out[0..n];
    }

    const Location = struct { shard: *Shard, bucket: u32 };

    fn locate(self: *Table, ip: Ip, zone: u32) Location {
        var msg: [20]u8 = undefined;
        msg[0..16].* = ip;
        std.mem.writeInt(u32, msg[16..20], zone, .little);
        const h = std.crypto.auth.siphash.SipHash64(1, 3).toInt(&msg, &self.key);
        const shard: usize = if (self.shards.len == 1) 0 else @intCast(h >> @intCast(self.shard_shift));
        const s = &self.shards[shard];
        return .{ .shard = s, .bucket = @as(u32, @truncate(h)) & @as(u32, @intCast(s.heads.len - 1)) };
    }

    fn noteFull(self: *Table, now_ns: i64) void {
        _ = self.untracked.fetchAdd(1, .monotonic);
        const last = self.last_warn_ns.load(.monotonic);
        if (now_ns -| last < 60 * std.time.ns_per_s) return;
        if (self.last_warn_ns.cmpxchgStrong(last, now_ns, .monotonic, .monotonic) != null) return;
        // Tests fail on any logged warning.
        if (!@import("builtin").is_test) log.warn("client limit table full ({d} entries): new clients go unlimited; raise limits.max_tracked_clients", .{self.capacity});
    }

    const Found = struct { index: u32, link: *u32 };

    fn find(s: *Shard, ip: Ip, zone: u32, bucket: u32) ?Found {
        var link = &s.heads[bucket];
        while (link.* != none) {
            const i = link.* - 1;
            const n = &s.nodes[i];
            if (n.zone == zone and std.mem.eql(u8, &n.ip, &ip)) return .{ .index = i, .link = link };
            link = &n.next;
        }
        return null;
    }

    fn insert(self: *Table, s: *Shard, ip: Ip, zone: u32, bucket: u32, value: i64, now_ns: i64) bool {
        const i = allocNode(s) orelse blk: {
            self.sweep(s, now_ns);
            break :blk allocNode(s) orelse return false;
        };
        s.nodes[i] = .{ .ip = ip, .zone = zone, .next = s.heads[bucket], .value = value };
        s.heads[bucket] = i + 1;
        _ = s.len.fetchAdd(1, .monotonic);
        if (self.banCount(zone)) |c| _ = c.fetchAdd(1, .monotonic);
        return true;
    }

    /// Drop one `limit_req` or `auth_basic` bucket of `s`; false when it holds
    /// only connection counts and bans.
    fn evictBucket(self: *Table, s: *Shard) bool {
        for (s.heads) |*head| {
            var link = head;
            while (link.* != none) {
                const i = link.* - 1;
                const n = &s.nodes[i];
                if (n.zone != conn_zone and banBits(n.zone) == null) {
                    self.remove(s, .{ .index = i, .link = link });
                    return true;
                }
                link = &n.next;
            }
        }
        return false;
    }

    fn allocNode(s: *Shard) ?u32 {
        if (s.free != none) {
            const i = s.free - 1;
            s.free = s.nodes[i].next;
            return i;
        }
        if (s.used == s.nodes.len) return null;
        s.used += 1;
        return s.used - 1;
    }

    /// The counter of the bans `zone` holds, if it is a ban zone.
    fn banCount(self: *Table, zone: u32) ?*std.atomic.Value(u32) {
        const bits = banBits(zone) orelse return null;
        return if (bits == fingerprint_bits) &self.fingerprint_bans else &self.bans;
    }

    fn remove(self: *Table, s: *Shard, f: Found) void {
        const n = &s.nodes[f.index];
        if (self.banCount(n.zone)) |c| _ = c.fetchSub(1, .monotonic);
        f.link.* = n.next;
        n.next = s.free;
        n.zone = free_zone;
        s.free = f.index + 1;
        _ = s.len.fetchSub(1, .monotonic);
    }

    fn sweep(self: *Table, s: *Shard, now_ns: i64) void {
        for (s.heads) |*head| {
            var link = head;
            while (link.* != none) {
                const i = link.* - 1;
                const n = &s.nodes[i];
                if (n.zone != conn_zone and n.value <= now_ns) {
                    self.remove(s, .{ .index = i, .link = link });
                } else {
                    link = &n.next;
                }
            }
        }
    }
};

/// The bucket a `limit_req` counts in: its named zone, else its location,
/// identified by what survives a reload (server name and first listen
/// address, location path or pattern), so buckets carry over.
pub fn zoneId(srv: *const config.Server, loc: *const config.Location) u32 {
    var h = std.hash.Wyhash.init(0);
    const lim = loc.limit_req.?;
    if (lim.zone) |z| {
        h.update("zone\x00");
        h.update(z);
    } else {
        h.update("location\x00");
        h.update(if (srv.server_names.len > 0) srv.server_names[0] else "");
        h.update("\x00");
        h.update(srv.listen[0].address);
        h.update(std.mem.asBytes(&srv.listen[0].port));
        h.update(@tagName(loc.match()));
        h.update(loc.pattern());
    }
    return @as(u32, @truncate(h.final())) | 1;
}

/// The bucket of a `limit_req` zone's refusals, for its `ban`: odd, as
/// `zoneId`'s are.
pub fn strikeZone(zone: u32) u32 {
    return zone ^ (1 << 30);
}

/// The network `ip` is counted under: its IPv4 /`v4` or its IPv6 /`v6`.
pub fn network(ip: Ip, v4: u8, v6: u8) Ip {
    var out = ip;
    access.mask(&out, if (access.isV4(ip)) 96 + v4 else v6);
    return out;
}

const testing = std.testing;

fn ip4(a: u8, b: u8, c: u8, d: u8) Ip {
    return .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d };
}

test "connection counts" {
    const t = try Table.createSharded(testing.allocator, 64, 4);
    defer t.destroy(testing.allocator);
    const io = testing.io;
    const a = ip4(10, 0, 0, 1);
    try testing.expectEqual(Table.Admit.counted, t.acquireConn(io, a, 2, 0));
    try testing.expectEqual(Table.Admit.counted, t.acquireConn(io, a, 2, 0));
    try testing.expectEqual(Table.Admit.refused, t.acquireConn(io, a, 2, 0));
    try testing.expectEqual(Table.Admit.counted, t.acquireConn(io, ip4(10, 0, 0, 2), 2, 0));
    t.releaseConn(io, a);
    try testing.expectEqual(Table.Admit.counted, t.acquireConn(io, a, 2, 0));
    t.releaseConn(io, a);
    t.releaseConn(io, a);
    t.releaseConn(io, ip4(10, 0, 0, 2));
    try testing.expectEqual(@as(usize, 0), t.entries());
}

test "request buckets: burst, refill, expiry" {
    const t = try Table.createSharded(testing.allocator, 64, 4);
    defer t.destroy(testing.allocator);
    const io = testing.io;
    const a = ip4(10, 0, 0, 1);
    const s = std.time.ns_per_s;
    // rate 2/s, burst 3: four at once, then one every 500 ms.
    var allowed: u32 = 0;
    for (0..10) |_| allowed += @intFromBool(t.allowRequest(io, a, 3, 2, 3, 100 * s));
    try testing.expectEqual(@as(u32, 4), allowed);
    try testing.expect(!t.allowRequest(io, a, 3, 2, 3, 100 * s + s / 4));
    try testing.expect(t.allowRequest(io, a, 3, 2, 3, 100 * s + s / 2));
    // Another zone for the same address is a separate bucket.
    try testing.expect(t.allowRequest(io, a, 5, 2, 0, 100 * s));
    try testing.expectEqual(@as(usize, 2), t.entries());
    // Full again after 2.5 s: gone at the next sweep.
    for (0..4) |_| t.sweepStep(io, 103 * s);
    try testing.expectEqual(@as(usize, 0), t.entries());
    try testing.expect(t.allowRequest(io, a, 3, 2, 3, 103 * s));
}

test "a full table evicts expired buckets, else fails open" {
    const t = try Table.createSharded(testing.allocator, 4, 1);
    defer t.destroy(testing.allocator);
    const io = testing.io;
    const s = std.time.ns_per_s;
    for (0..4) |i| _ = t.allowRequest(io, ip4(10, 0, 0, @intCast(i)), 3, 1, 0, 10 * s);
    try testing.expectEqual(@as(usize, 4), t.entries());
    // Nothing has expired: a fifth client is let through untracked.
    const e = ip4(10, 0, 1, 0);
    try testing.expect(t.allowRequest(io, e, 3, 1, 0, 10 * s));
    try testing.expect(t.allowRequest(io, e, 3, 1, 0, 10 * s));
    try testing.expectEqual(Table.Admit.untracked, t.acquireConn(io, e, 1, 10 * s));
    try testing.expectEqual(@as(u64, 3), t.untracked.load(.monotonic));
    // Once the buckets have refilled, their slots are reclaimed.
    try testing.expectEqual(Table.Admit.counted, t.acquireConn(io, e, 1, 12 * s));
    try testing.expect(t.allowRequest(io, e, 3, 1, 0, 12 * s));
    try testing.expect(!t.allowRequest(io, e, 3, 1, 0, 12 * s));
    try testing.expectEqual(@as(usize, 2), t.entries());
}

test "concurrent acquire and release stay consistent" {
    const t = try Table.createSharded(testing.allocator, 1024, 8);
    defer t.destroy(testing.allocator);
    const Hammer = struct {
        fn run(tbl: *Table, seed: u8, granted: *std.atomic.Value(u32)) void {
            const io = testing.io;
            var held: [64]Ip = undefined;
            var n: usize = 0;
            for (0..2000) |i| {
                const ip = ip4(10, 0, seed, @intCast(i % 16));
                if (tbl.acquireConn(io, ip, 1_000_000, 0) == .counted) {
                    _ = granted.fetchAdd(1, .monotonic);
                    held[n] = ip;
                    n += 1;
                }
                // Also contend on addresses shared with the other threads.
                if (tbl.acquireConn(io, ip4(10, 1, 0, @intCast(i % 8)), 1_000_000, 0) == .counted) tbl.releaseConn(io, ip4(10, 1, 0, @intCast(i % 8)));
                if (n == held.len) {
                    for (held) |h| tbl.releaseConn(io, h);
                    n = 0;
                }
            }
            for (held[0..n]) |h| tbl.releaseConn(io, h);
        }
    };
    var granted: std.atomic.Value(u32) = .init(0);
    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*th, i| th.* = try std.Thread.spawn(.{}, Hammer.run, .{ t, @as(u8, @intCast(i)), &granted });
    for (threads) |th| th.join();
    try testing.expectEqual(@as(u32, 4 * 2000), granted.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), t.entries());
    // And a shared limit is exact under contention: 4 threads, 10 slots.
    const Race = struct {
        fn run(tbl: *Table, won: *std.atomic.Value(u32)) void {
            for (0..100) |_| {
                if (tbl.acquireConn(testing.io, ip4(10, 2, 0, 1), 10, 0) == .counted) _ = won.fetchAdd(1, .monotonic);
            }
        }
    };
    var won: std.atomic.Value(u32) = .init(0);
    for (&threads) |*th| th.* = try std.Thread.spawn(.{}, Race.run, .{ t, &won });
    for (threads) |th| th.join();
    try testing.expectEqual(@as(u32, 10), won.load(.monotonic));
}

test "bans: addresses and networks, expiry, unban, listing" {
    const t = try Table.createSharded(testing.allocator, 64, 4);
    defer t.destroy(testing.allocator);
    const io = testing.io;
    const s = std.time.ns_per_s;
    try testing.expect(!t.anyBans());
    try t.ban(io, ip4(10, 0, 0, 1), 128, 20 * s, 10 * s);
    // Host bits past the prefix don't matter.
    try t.ban(io, ip4(192, 0, 2, 77), 120, 30 * s, 10 * s);
    try testing.expect(t.anyBans());
    try testing.expect(t.banned(io, ip4(10, 0, 0, 1), 10 * s));
    try testing.expect(!t.banned(io, ip4(10, 0, 0, 2), 10 * s));
    try testing.expect(t.banned(io, ip4(192, 0, 2, 200), 10 * s));
    try testing.expect(!t.banned(io, ip4(192, 0, 3, 1), 10 * s));
    // Over at its end, and gone at the next sweep.
    try testing.expect(!t.banned(io, ip4(10, 0, 0, 1), 20 * s));
    for (0..4) |_| t.sweepStep(io, 20 * s);
    try testing.expectEqual(@as(u32, 1), t.bans.load(.monotonic));
    // A second ban on the same network replaces the end.
    try t.ban(io, ip4(192, 0, 2, 0), 120, 25 * s, 20 * s);
    try testing.expectEqual(@as(u32, 1), t.bans.load(.monotonic));
    try testing.expect(!t.banned(io, ip4(192, 0, 2, 1), 25 * s));

    const v6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1 } ++ @as([8]u8, @splat(0x11));
    try t.ban(io, v6, 64, 40 * s, 20 * s);
    var other = v6;
    other[15] = 0x22;
    try testing.expect(t.banned(io, other, 20 * s));

    var cursor: Table.BanCursor = .{};
    var buf: [1]Table.Ban = undefined;
    var listed: usize = 0;
    while (true) {
        const got = t.nextBans(io, &cursor, 20 * s, &buf);
        if (got.len == 0) break;
        listed += got.len;
    }
    try testing.expectEqual(@as(usize, 2), listed);

    try testing.expect(t.unban(io, other, 64));
    try testing.expect(!t.unban(io, other, 64));
    try testing.expect(!t.banned(io, v6, 20 * s));
    try testing.expect(t.unban(io, ip4(192, 0, 2, 9), 120));
    try testing.expect(!t.anyBans());
    try testing.expectEqual(@as(usize, 0), t.entries());
    // A freed node no longer lists as a ban.
    cursor = .{};
    try testing.expectEqual(@as(usize, 0), t.nextBans(io, &cursor, 20 * s, &buf).len);
}

test "fingerprint bans: matched whole, counted apart from networks, listed" {
    const t = try Table.createSharded(testing.allocator, 64, 4);
    defer t.destroy(testing.allocator);
    const io = testing.io;
    const s = std.time.ns_per_s;
    var fp: [16]u8 = @splat(0xab);
    try t.ban(io, fp, fingerprint_bits, 20 * s, 10 * s);
    try testing.expect(t.anyFingerprintBans() and !t.anyBans());
    try testing.expect(t.fingerprintBanned(io, fp, 10 * s));
    // Nothing is masked: a key one bit off is another fingerprint, and no network.
    var other = fp;
    other[15] ^= 1;
    try testing.expect(!t.fingerprintBanned(io, other, 10 * s));
    try testing.expect(!t.banned(io, fp, 10 * s));
    try t.ban(io, ip4(10, 0, 0, 1), 128, 20 * s, 10 * s);
    try testing.expect(!t.fingerprintBanned(io, ip4(10, 0, 0, 1), 10 * s));

    var cursor: Table.BanCursor = .{};
    var buf: [4]Table.Ban = undefined;
    var fps: usize = 0;
    while (true) {
        const got = t.nextBans(io, &cursor, 10 * s, &buf);
        if (got.len == 0) break;
        for (got) |b| if (b.bits == fingerprint_bits) {
            try testing.expectEqual(fp, b.net);
            fps += 1;
        };
    }
    try testing.expectEqual(@as(usize, 1), fps);
    try testing.expect(!t.fingerprintBanned(io, fp, 20 * s));
    try testing.expect(t.unban(io, fp, fingerprint_bits));
    try testing.expect(!t.anyFingerprintBans() and t.anyBans());
    fp[0] = 0;
    try testing.expect(!t.unban(io, fp, fingerprint_bits));
}

test "a full table makes room for a ban from a bucket, never from connections or bans" {
    const t = try Table.createSharded(testing.allocator, 2, 1);
    defer t.destroy(testing.allocator);
    const io = testing.io;
    try t.ban(io, ip4(10, 0, 0, 1), 128, 100, 0);
    try t.ban(io, ip4(10, 0, 0, 2), 128, 100, 0);
    try testing.expectError(error.TableFull, t.ban(io, ip4(10, 0, 0, 3), 128, 100, 0));
    // An expired one makes room.
    try t.ban(io, ip4(10, 0, 0, 3), 128, 200, 150);
    try testing.expectEqual(@as(u32, 1), t.bans.load(.monotonic));

    // A live bucket gives way; a connection count doesn't.
    try testing.expect(t.allowRequest(io, ip4(10, 0, 1, 1), 3, 1, 0, 150));
    try t.ban(io, ip4(10, 0, 0, 4), 128, 200, 150);
    try testing.expectEqual(@as(u32, 2), t.bans.load(.monotonic));
    try testing.expect(t.unban(io, ip4(10, 0, 0, 4), 128));
    try testing.expectEqual(Table.Admit.counted, t.acquireConn(io, ip4(10, 0, 1, 2), 5, 150));
    try testing.expectError(error.TableFull, t.ban(io, ip4(10, 0, 0, 5), 128, 200, 150));
}

test "allowEvery: under one a second, as limit_req.ban counts refusals" {
    const t = try Table.createSharded(testing.allocator, 64, 4);
    defer t.destroy(testing.allocator);
    const io = testing.io;
    const s = std.time.ns_per_s;
    const a = ip4(10, 0, 0, 1);
    // More than 2 in 60 s: every 30 s, 2 at once.
    try testing.expect(t.allowEvery(io, a, strikeZone(3), 30 * s, 1, 100 * s));
    try testing.expect(t.allowEvery(io, a, strikeZone(3), 30 * s, 1, 100 * s));
    try testing.expect(!t.allowEvery(io, a, strikeZone(3), 30 * s, 1, 100 * s));
    try testing.expect(t.allowEvery(io, a, strikeZone(3), 30 * s, 1, 130 * s));
    try testing.expect(strikeZone(3) & 1 == 1 and strikeZone(3) != 3);
}

test "networks" {
    try testing.expectEqual(ip4(192, 0, 2, 0), network(ip4(192, 0, 2, 77), 24, 64));
    try testing.expectEqual(ip4(192, 0, 0, 0), network(ip4(192, 0, 2, 77), 20, 64));
    try testing.expectEqual(ip4(192, 0, 2, 77), network(ip4(192, 0, 2, 77), 32, 128));
    const v6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1 } ++ @as([8]u8, @splat(0x11));
    try testing.expectEqual([_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1 } ++ @as([8]u8, @splat(0)), network(v6, 24, 64));
    try testing.expectEqual([_]u8{ 0x20, 0x01, 0x0c } ++ @as([13]u8, @splat(0)), network(v6, 24, 22));
    try testing.expectEqual(v6, network(v6, 24, 128));
}

test "zone ids" {
    const loc_a: config.Location = .{ .prefix = "/a", .@"return" = .{}, .limit_req = .{ .rate = 1, .zone = "api" } };
    const loc_b: config.Location = .{ .prefix = "/b", .@"return" = .{}, .limit_req = .{ .rate = 1, .zone = "api" } };
    const loc_c: config.Location = .{ .prefix = "/a", .@"return" = .{}, .limit_req = .{ .rate = 1 } };
    const loc_d: config.Location = .{ .prefix = "/b", .@"return" = .{}, .limit_req = .{ .rate = 1 } };
    const srv: config.Server = .{ .listen = &.{.{ .port = 80 }}, .locations = &.{} };
    try testing.expectEqual(zoneId(&srv, &loc_a), zoneId(&srv, &loc_b));
    try testing.expect(zoneId(&srv, &loc_c) != zoneId(&srv, &loc_d));
    try testing.expect(zoneId(&srv, &loc_a) != zoneId(&srv, &loc_c));
    try testing.expect(zoneId(&srv, &loc_c) != conn_zone);
    try testing.expect(banBits(zoneId(&srv, &loc_a)) == null);
    try testing.expectEqual(@as(?u8, 120), banBits(banZone(120)));
    try testing.expectEqual(@as(?u8, fingerprint_bits), banBits(banZone(fingerprint_bits)));
    try testing.expect(banZone(fingerprint_bits) != check_zone);
    try testing.expect(banBits(auth_zone) == null and banBits(conn_zone) == null and banBits(free_zone) == null);
}

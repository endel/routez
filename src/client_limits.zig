//! Per-client limits shared by every worker and every generation: the
//! connections each address holds (`limits.max_connections_per_ip`) and the
//! `limit_req` buckets.
//!
//! Entries are keyed by client address and zone, hashed with a random
//! SipHash key onto shards, each a chained hash table over a node pool
//! sized at creation, so steady-state operation never allocates. A shard's
//! mutex is held for a lookup and a few stores.
//!
//! Buckets use GCRA, the token bucket held as one timestamp: the time
//! the bucket would be full again. An entry past that time, or a
//! connection count back at zero, carries no state and is dropped.
//!
//! When a shard is full of live entries, a new client goes untracked:
//! allowed, and counted in `untracked`. Refusing instead would let anyone
//! with enough addresses (a single IPv6 /64 has 2^64) lock every new
//! client out; they can already sidestep these limits by spreading
//! requests over those addresses, so failing open gives nothing away.
const std = @import("std");
const quic = @import("quic");
const config = @import("config.zig");

const log = std.log.scoped(.limits);

/// An IPv6 address, or an IPv4 one in mapped form.
pub const Ip = [16]u8;

/// The zone of an address's connection count; `zoneId` never returns it.
pub const conn_zone: u32 = 0;
/// The bucket of an address's uncached `auth_basic` password checks;
/// `zoneId` never returns it either (its ids are odd).
pub const auth_zone: u32 = 2;

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
        const ok = insert(s, ip, conn_zone, loc.bucket, 1, now_ns);
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
        if (n.* <= 0) remove(s, f);
    }

    /// GCRA admission for one request: `rate` per second on average, and
    /// `burst` more at once. `zone` comes from `zoneId`.
    pub fn allowRequest(self: *Table, io: std.Io, ip: Ip, zone: u32, rate: u32, burst: u32, now_ns: i64) bool {
        const interval: i64 = @max(1, @divTrunc(std.time.ns_per_s, @as(i64, rate)));
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
        const ok = insert(s, ip, zone, loc.bucket, now_ns + interval, now_ns);
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
        sweep(s, now_ns);
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

    fn insert(s: *Shard, ip: Ip, zone: u32, bucket: u32, value: i64, now_ns: i64) bool {
        const i = allocNode(s) orelse blk: {
            sweep(s, now_ns);
            break :blk allocNode(s) orelse return false;
        };
        s.nodes[i] = .{ .ip = ip, .zone = zone, .next = s.heads[bucket], .value = value };
        s.heads[bucket] = i + 1;
        _ = s.len.fetchAdd(1, .monotonic);
        return true;
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

    fn remove(s: *Shard, f: Found) void {
        const n = &s.nodes[f.index];
        f.link.* = n.next;
        n.next = s.free;
        s.free = f.index + 1;
        _ = s.len.fetchSub(1, .monotonic);
    }

    fn sweep(s: *Shard, now_ns: i64) void {
        for (s.heads) |*head| {
            var link = head;
            while (link.* != none) {
                const i = link.* - 1;
                const n = &s.nodes[i];
                if (n.zone != conn_zone and n.value <= now_ns) {
                    remove(s, .{ .index = i, .link = link });
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
}

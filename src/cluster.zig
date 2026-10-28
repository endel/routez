//! Ban sync between routez instances (`cluster`). A ban or unban made here,
//! through `routez ctl` or by `limit_req.ban`, goes to every peer in a
//! signed UDP datagram. Every 30 s each instance sends its peers a digest
//! of what it holds; a peer whose own digest differs pulls the whole list,
//! so a lost datagram or a restarted instance catches up.
//!
//! A ban is a key (network and length, or a fingerprint) with an end in
//! Unix seconds, so copies merge without coordination: the later version
//! (Unix ms when it was made, then the origin's id) wins. An unban is a tombstone kept until
//! the ban it lifted would have ended, so a late copy can't bring it back.
//!
//! Runs on the control thread; workers only ever see the client table.
const std = @import("std");
const quic = @import("quic");
const client_limits = @import("client_limits.zig");
const config = @import("config.zig");
const addr = @import("net/addr.zig");
const logs = @import("logs.zig");
const stats = @import("stats.zig");

const sys = quic.sys;
const posix = std.posix;
const log = std.log.scoped(.cluster);
const Ip = client_limits.Ip;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

/// How often each instance sends its peers a digest.
const digest_interval_ms = 30_000;
/// A tombstone's end when the ban it lifts isn't known here.
const unknown_lift_s = 24 * 3600;

const magic = "rzb1";
const mac_len = 16;
const header_len = magic.len + 1 + 4;
const entry_len = 16 + 1 + 1 + 8 + 8 + 4;
/// Entries a datagram carries, staying under 1200 bytes, which any path takes.
pub const per_datagram = 30;
const max_datagram = header_len + 1 + per_datagram * entry_len + mac_len;

const Kind = enum(u8) { bans = 1, digest = 2, pull = 3 };

pub const Key = struct { net: Ip, bits: u8 };

pub const Entry = struct {
    /// Unix seconds.
    end_s: i64,
    /// Unix milliseconds when it was made at `origin`; 0 for a ban this
    /// instance only reloaded, which anything a peer knows outranks.
    version: u64,
    origin: u32,
    /// An unban.
    lifted: bool,

    fn newer(a: Entry, b: Entry) bool {
        return a.version > b.version or (a.version == b.version and a.origin > b.origin);
    }
};

pub const Item = struct { key: Key, entry: Entry };

pub const Cluster = struct {
    gpa: std.mem.Allocator,
    fd: posix.fd_t,
    secret: []const u8,
    id: u32,
    peers: []posix.sockaddr.storage,
    known: std.AutoHashMapUnmanaged(Key, Entry) = .empty,
    /// The table's `ban_epoch` as of the last look for bans made here.
    seen_epoch: u32 = 0,
    next_digest_ms: i64 = 0,
    table_full_logged: bool = false,

    /// Bind `cfg.listen` and read `cfg.key_file`: at start, before `user`
    /// takes over.
    pub fn open(gpa: std.mem.Allocator, io: std.Io, cfg: config.Cluster) !*Cluster {
        const text = try std.Io.Dir.cwd().readFileAlloc(io, cfg.key_file, gpa, .limited(4096));
        errdefer gpa.free(text);
        const secret = std.mem.trimEnd(u8, text, "\r\n");
        if (secret.len < 32) return error.ShortKey;
        const here = try resolve(cfg.listen);
        const peers = try gpa.alloc(posix.sockaddr.storage, cfg.peers.len);
        errdefer gpa.free(peers);
        for (cfg.peers, peers) |p, *s| s.* = try resolve(p);
        const family: u32 = if (here.family == posix.AF.INET6) posix.AF.INET6 else posix.AF.INET;
        const fd = try sys.socket(family, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
        errdefer sys.close(fd);
        // A pull answers with the whole list at once: ~3 MB for 100k bans.
        const bufsz: c_int = 4 * 1024 * 1024;
        _ = std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&bufsz), @sizeOf(c_int));
        _ = std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&bufsz), @sizeOf(c_int));
        try sys.bind(fd, @ptrCast(&here), addr.storageLen(&here));
        const c = try gpa.create(Cluster);
        c.* = .{ .gpa = gpa, .fd = fd, .secret = secret, .id = @truncate(std.hash.Wyhash.hash(0, cfg.listen)), .peers = peers };
        return c;
    }

    fn resolve(text: []const u8) !posix.sockaddr.storage {
        const hp = try config.parseHostPort(text);
        return addr.toStorage(try addr.resolve(hp.host, hp.port));
    }

    /// Before the first wait: take in what the table holds (reloaded from
    /// bans_file) as the oldest version there is, and ask the peers for
    /// theirs.
    pub fn start(self: *Cluster, io: std.Io, table: *client_limits.Table) void {
        self.seen_epoch = table.ban_epoch.load(.acquire);
        self.scan(io, table, 0);
        self.send(.pull, &.{}, null);
        self.next_digest_ms = nowMs() + digest_interval_ms;
    }

    /// A ban or unban `routez ctl` made: to every peer at once.
    pub fn noteLocal(self: *Cluster, key: Key, end_s: i64, lifted: bool) void {
        const e: Entry = .{ .end_s = end_s, .version = @intCast(nowMs()), .origin = self.id, .lifted = lifted };
        self.known.put(self.gpa, key, e) catch return;
        self.sendItems(&.{.{ .key = key, .entry = e }}, null);
    }

    /// The end an unban's tombstone keeps: that of the ban it lifts.
    pub fn liftEnd(self: *const Cluster, key: Key) i64 {
        if (self.known.get(key)) |e| if (!e.lifted) return e.end_s;
        return sys.realtimeSeconds() + unknown_lift_s;
    }

    /// Every wake of the control thread: bans workers made, the digest when
    /// its time comes, and what ended.
    pub fn tick(self: *Cluster, io: std.Io, table: *client_limits.Table) void {
        const epoch = table.ban_epoch.load(.acquire);
        if (epoch != self.seen_epoch) {
            self.seen_epoch = epoch;
            self.scan(io, table, @intCast(nowMs()));
        }
        const now_ms = nowMs();
        if (now_ms < self.next_digest_ms) return;
        self.next_digest_ms = now_ms + digest_interval_ms;
        self.purge();
        var body: [12]u8 = undefined;
        self.digest(&body);
        self.send(.digest, &body, null);
    }

    /// Read every datagram waiting.
    pub fn receive(self: *Cluster, io: std.Io, table: *client_limits.Table) void {
        var buf: [max_datagram + 64]u8 = undefined;
        while (true) {
            var from: posix.sockaddr.storage = undefined;
            var from_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            const n = sys.recvfrom(self.fd, &buf, 0, @ptrCast(&from), &from_len) catch |err| switch (err) {
                error.WouldBlock => return,
                else => continue,
            };
            const peer = self.peerIndex(&from);
            const msg = if (peer != null) unseal(self.secret, buf[0..n]) else null;
            const m = msg orelse {
                stats.inc(&stats.cluster_rejected);
                continue;
            };
            switch (m.kind) {
                .bans => self.merge(io, table, m.body),
                .pull => self.sendAll(&self.peers[peer.?]),
                .digest => {
                    var mine: [12]u8 = undefined;
                    self.digest(&mine);
                    if (!std.mem.eql(u8, &mine, m.body)) self.send(.pull, &.{}, &self.peers[peer.?]);
                },
            }
        }
    }

    fn peerIndex(self: *const Cluster, from: *const posix.sockaddr.storage) ?usize {
        const a = addr.fromStorage(from) orelse return null;
        for (self.peers, 0..) |*p, i| {
            const b = addr.fromStorage(p) orelse continue;
            if (a.eql(&b)) return i;
        }
        return null;
    }

    /// Look for bans workers made or lengthened (`limit_req.ban`) and send
    /// them on, as `version`; 0 takes them in without sending.
    fn scan(self: *Cluster, io: std.Io, table: *client_limits.Table, version: u64) void {
        const now_ns = sys.nanoTimestamp();
        const now_s = sys.realtimeSeconds();
        var cursor: client_limits.Table.BanCursor = .{};
        var batch: [64]client_limits.Table.Ban = undefined;
        var out: [per_datagram]Item = undefined;
        var n: usize = 0;
        while (true) {
            const got = table.nextBans(io, &cursor, now_ns, &batch);
            if (got.len == 0) break;
            for (got) |b| {
                const key: Key = .{ .net = b.net, .bits = b.bits };
                const end_s = now_s + (std.math.divCeil(i64, b.until_ns - now_ns, std.time.ns_per_s) catch 0);
                // The same ban, give or take the rounding to seconds.
                if (self.known.get(key)) |e| if (!e.lifted and @abs(e.end_s - end_s) <= 2) continue;
                const e: Entry = .{ .end_s = end_s, .version = version, .origin = self.id, .lifted = false };
                self.known.put(self.gpa, key, e) catch return;
                if (version == 0) continue;
                out[n] = .{ .key = key, .entry = e };
                n += 1;
                if (n == out.len) {
                    self.sendItems(&out, null);
                    n = 0;
                }
            }
        }
        if (n > 0) self.sendItems(out[0..n], null);
    }

    fn merge(self: *Cluster, io: std.Io, table: *client_limits.Table, body: []const u8) void {
        const now_s = sys.realtimeSeconds();
        var it = decodeItems(body);
        while (it.next()) |item| {
            if (item.entry.end_s <= now_s) continue;
            if (self.known.get(item.key)) |e| if (!item.entry.newer(e)) continue;
            self.known.put(self.gpa, item.key, item.entry) catch return;
            stats.inc(&stats.cluster_received);
            if (item.entry.lifted) {
                _ = table.unban(io, item.key.net, item.key.bits);
                continue;
            }
            const now_ns = sys.nanoTimestamp();
            const left = @min(item.entry.end_s - now_s, config.max_ban_s);
            table.ban(io, item.key.net, item.key.bits, now_ns + left * std.time.ns_per_s, now_ns) catch {
                if (!self.table_full_logged) log.err("a peer's ban found the client table full; raise limits.max_tracked_clients", .{});
                self.table_full_logged = true;
                continue;
            };
        }
    }

    fn purge(self: *Cluster) void {
        const now_s = sys.realtimeSeconds();
        // Removing leaves a tombstone in place: iterating on is safe.
        var it = self.known.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.end_s <= now_s) self.known.removeByPtr(kv.key_ptr);
        }
    }

    /// What this instance holds: how many entries, and a hash over them
    /// all that doesn't depend on order.
    fn digest(self: *const Cluster, out: *[12]u8) void {
        var count: u32 = 0;
        var hash: u64 = 0;
        var it = self.known.iterator();
        while (it.next()) |kv| {
            var bytes: [entry_len]u8 = undefined;
            encodeItem(&bytes, .{ .key = kv.key_ptr.*, .entry = kv.value_ptr.* });
            hash ^= std.hash.Wyhash.hash(0, &bytes);
            count += 1;
        }
        std.mem.writeInt(u32, out[0..4], count, .big);
        std.mem.writeInt(u64, out[4..12], hash, .big);
    }

    fn sendAll(self: *Cluster, to: *const posix.sockaddr.storage) void {
        var out: [per_datagram]Item = undefined;
        var n: usize = 0;
        var it = self.known.iterator();
        while (it.next()) |kv| {
            out[n] = .{ .key = kv.key_ptr.*, .entry = kv.value_ptr.* };
            n += 1;
            if (n == out.len) {
                self.sendItems(&out, to);
                n = 0;
            }
        }
        if (n > 0) self.sendItems(out[0..n], to);
    }

    fn sendItems(self: *Cluster, items: []const Item, to: ?*const posix.sockaddr.storage) void {
        var body: [1 + per_datagram * entry_len]u8 = undefined;
        self.send(.bans, encodeItems(&body, items), to);
    }

    /// To `to`, or to every peer. A send the socket can't take now is
    /// dropped: the next digest makes up for it.
    fn send(self: *Cluster, kind: Kind, body: []const u8, to: ?*const posix.sockaddr.storage) void {
        var buf: [max_datagram]u8 = undefined;
        const dg = seal(self.secret, &buf, kind, self.id, body);
        if (to) |t| {
            _ = sys.sendto(self.fd, dg, 0, @ptrCast(t), addr.storageLen(t)) catch {};
            return;
        }
        for (self.peers) |*p| _ = sys.sendto(self.fd, dg, 0, @ptrCast(p), addr.storageLen(p)) catch {};
    }
};

fn nowMs() i64 {
    return logs.realtimeMs();
}

fn encodeItem(out: *[entry_len]u8, item: Item) void {
    out[0..16].* = item.key.net;
    out[16] = item.key.bits;
    out[17] = @intFromBool(item.entry.lifted);
    std.mem.writeInt(i64, out[18..26], item.entry.end_s, .big);
    std.mem.writeInt(u64, out[26..34], item.entry.version, .big);
    std.mem.writeInt(u32, out[34..38], item.entry.origin, .big);
}

fn encodeItems(out: []u8, items: []const Item) []const u8 {
    std.debug.assert(items.len <= per_datagram);
    out[0] = @intCast(items.len);
    for (items, 0..) |item, i| encodeItem(out[1 + i * entry_len ..][0..entry_len], item);
    return out[0 .. 1 + items.len * entry_len];
}

const ItemIterator = struct {
    rest: []const u8,
    left: u8,

    fn next(self: *ItemIterator) ?Item {
        if (self.left == 0 or self.rest.len < entry_len) return null;
        const b = self.rest[0..entry_len];
        self.rest = self.rest[entry_len..];
        self.left -= 1;
        if (!client_limits.isBanLength(b[16]) or b[17] > 1) return null;
        return .{
            .key = .{ .net = b[0..16].*, .bits = b[16] },
            .entry = .{
                .end_s = std.mem.readInt(i64, b[18..26], .big),
                .version = std.mem.readInt(u64, b[26..34], .big),
                .origin = std.mem.readInt(u32, b[34..38], .big),
                .lifted = b[17] == 1,
            },
        };
    }
};

fn decodeItems(body: []const u8) ItemIterator {
    if (body.len == 0) return .{ .rest = "", .left = 0 };
    return .{ .rest = body[1..], .left = body[0] };
}

fn seal(secret: []const u8, buf: []u8, kind: Kind, origin: u32, body: []const u8) []const u8 {
    buf[0..magic.len].* = magic.*;
    buf[magic.len] = @backingInt(kind);
    std.mem.writeInt(u32, buf[magic.len + 1 ..][0..4], origin, .big);
    @memcpy(buf[header_len..][0..body.len], body);
    const signed = header_len + body.len;
    var m: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&m, buf[0..signed], secret);
    buf[signed..][0..mac_len].* = m[0..mac_len].*;
    return buf[0 .. signed + mac_len];
}

const Message = struct { kind: Kind, body: []const u8 };

/// The message in `dg`, when it is one, signed with `secret`.
fn unseal(secret: []const u8, dg: []const u8) ?Message {
    if (dg.len < header_len + mac_len or !std.mem.eql(u8, dg[0..magic.len], magic)) return null;
    const signed = dg.len - mac_len;
    var m: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&m, dg[0..signed], secret);
    if (!std.crypto.timing_safe.eql([mac_len]u8, m[0..mac_len].*, dg[signed..][0..mac_len].*)) return null;
    const kind: Kind = switch (dg[magic.len]) {
        1 => .bans,
        2 => .digest,
        3 => .pull,
        else => return null,
    };
    return .{ .kind = kind, .body = dg[header_len..signed] };
}

const testing = std.testing;

test "a message opens only with its key, and untouched" {
    const key = "an instance key of 32 bytes ok!!";
    var buf: [max_datagram]u8 = undefined;
    const items = [_]Item{
        .{ .key = .{ .net = @splat(1), .bits = 120 }, .entry = .{ .end_s = 2000, .version = 7, .origin = 3, .lifted = false } },
        .{ .key = .{ .net = @splat(2), .bits = 64 }, .entry = .{ .end_s = 3000, .version = 9, .origin = 4, .lifted = true } },
        .{ .key = .{ .net = @splat(3), .bits = client_limits.fingerprint_bits }, .entry = .{ .end_s = 4000, .version = 11, .origin = 4, .lifted = false } },
    };
    var body: [1 + per_datagram * entry_len]u8 = undefined;
    const dg = seal(key, &buf, .bans, 3, encodeItems(&body, &items));
    try testing.expect(dg.len <= 1200);
    const m = unseal(key, dg).?;
    try testing.expectEqual(Kind.bans, m.kind);
    var it = decodeItems(m.body);
    try testing.expectEqual(items[0], it.next().?);
    try testing.expectEqual(items[1], it.next().?);
    try testing.expectEqual(items[2], it.next().?);
    try testing.expect(it.next() == null);
    try testing.expect(unseal("another key, also 32 bytes long!", dg) == null);
    var bent = buf;
    bent[header_len + 5] ^= 1;
    try testing.expect(unseal(key, bent[0..dg.len]) == null);
    try testing.expect(unseal(key, dg[0 .. dg.len - 1]) == null);
    // A full datagram fits under 1200 bytes.
    try testing.expect(max_datagram <= 1200);
}

test "the later version wins, then the higher origin" {
    const a: Entry = .{ .end_s = 10, .version = 5, .origin = 1, .lifted = false };
    try testing.expect((Entry{ .end_s = 10, .version = 6, .origin = 0, .lifted = true }).newer(a));
    try testing.expect((Entry{ .end_s = 99, .version = 5, .origin = 2, .lifted = false }).newer(a));
    try testing.expect(!(Entry{ .end_s = 99, .version = 4, .origin = 9, .lifted = false }).newer(a));
    // A ban only reloaded from bans_file loses to anything a peer made.
    try testing.expect(a.newer(.{ .end_s = 10, .version = 0, .origin = 9, .lifted = false }));
}

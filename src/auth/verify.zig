//! Password checks against htpasswd hashes, and the cache that keeps a
//! bcrypt check from running on every request.
const std = @import("std");
const htpasswd = @import("htpasswd.zig");
const Hash = htpasswd.Hash;

const bcrypt = std.crypto.pwhash.bcrypt;
const timing_safe = std.crypto.timing_safe;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// bcrypt reads no further; htpasswd truncates the same way.
pub const max_bcrypt_password = 72;

/// Whether `password` matches `hash`. bcrypt takes 2^cost rounds: tens to
/// hundreds of milliseconds at the usual costs, so run it off the event loop.
pub fn check(hash: *const Hash, password: []const u8) bool {
    return switch (hash.*) {
        .sha1 => |want| blk: {
            var got: [20]u8 = undefined;
            std.crypto.hash.Sha1.hash(password, &got, .{});
            break :blk timing_safe.eql([20]u8, got, want);
        },
        .bcrypt => |*s| bcryptMatches(s, password),
    };
}

fn bcryptMatches(s: *const [60]u8, password: []const u8) bool {
    const cost = std.fmt.parseInt(u6, s[4..6], 10) catch return false;
    var salt: [bcrypt.salt_length]u8 = undefined;
    htpasswd.radix64Decode(&salt, s[7..29]) catch return false;
    var want: [23]u8 = undefined;
    htpasswd.radix64Decode(&want, s[29..60]) catch return false;
    const pw = password[0..@min(password.len, max_bcrypt_password)];
    const got = bcrypt.bcrypt(pw, &salt, .{ .rounds_log = cost, .silently_truncate_password = true });
    return timing_safe.eql([23]u8, got, want);
}

/// Recently verified credentials, so a browser resending them with every
/// request costs one bcrypt, not one per request.
///
/// Entries are an HMAC, under a key drawn at start, of the stored hash, the
/// user and the password: a changed password (a different stored hash)
/// misses, and the table holds nothing that is fast to brute-force without
/// the key. Fixed size, set-associative; the soonest to expire is evicted.
/// Only successes are stored, so failed attempts can't flush it.
pub const Cache = struct {
    mutex: std.Io.Mutex = .init,
    key: [32]u8,
    sets: [set_count][ways]Entry = @splat(@splat(.{})),

    pub const set_count = 256;
    pub const ways = 4;
    pub const ttl_ns: i64 = 5 * 60 * std.time.ns_per_s;

    const Entry = struct {
        tag: [32]u8 = @splat(0),
        /// 0 for an empty slot.
        expires_ns: i64 = 0,
    };

    pub fn init(key: [32]u8) Cache {
        return .{ .key = key };
    }

    pub fn digest(self: *const Cache, stored: *const Hash, user: []const u8, password: []const u8) [32]u8 {
        var h = HmacSha256.init(&self.key);
        const stored_bytes: []const u8 = switch (stored.*) {
            .bcrypt => |*s| s,
            .sha1 => |*s| s,
        };
        for ([_][]const u8{ stored_bytes, user, password }) |part| {
            var len: [4]u8 = undefined;
            std.mem.writeInt(u32, &len, @intCast(part.len), .little);
            h.update(&len);
            h.update(part);
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }

    pub fn contains(self: *Cache, io: std.Io, d: [32]u8, now_ns: i64) bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        var found = false;
        for (&self.sets[d[0]]) |*e| {
            // Every way is compared, so the time taken doesn't say which matched.
            const live = e.expires_ns > now_ns;
            if (timing_safe.eql([32]u8, e.tag, d) and live) found = true;
        }
        return found;
    }

    pub fn insert(self: *Cache, io: std.Io, d: [32]u8, now_ns: i64) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const set = &self.sets[d[0]];
        var victim = &set[0];
        for (set) |*e| {
            if (std.mem.eql(u8, &e.tag, &d)) {
                victim = e;
                break;
            }
            if (e.expires_ns < victim.expires_ns) victim = e;
        }
        victim.* = .{ .tag = d, .expires_ns = now_ns + ttl_ns };
    }
};

const testing = std.testing;

fn parseOne(arena: std.mem.Allocator, line: []const u8) !Hash {
    var d: htpasswd.Diagnostic = .{};
    const f = try htpasswd.parse(arena, line, &d);
    var it = f.users.valueIterator();
    return it.next().?.*;
}

test "bcrypt and SHA from htpasswd verify" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // htpasswd -nbB -C 10 alice secret; htpasswd -nbs bob hunter2
    const alice = try parseOne(a, "alice:$2y$10$f/mtfnwsB2gGNc04FBRPnu07AK7xFpWb9z4jwcHSRI4vGLNN2IC82");
    try testing.expect(check(&alice, "secret"));
    try testing.expect(!check(&alice, "Secret"));
    try testing.expect(!check(&alice, ""));
    const bob = try parseOne(a, "bob:{SHA}87u9ZqY9S/F0eUBXjsPQEDUw4h0=");
    try testing.expect(check(&bob, "hunter2"));
    try testing.expect(!check(&bob, "hunter3"));
}

test "bcrypt truncates at 72 bytes, like htpasswd" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    // htpasswd -nbB -C 4 long <72 'a'> + "tail"
    const h = try parseOne(arena_state.allocator(), "long:$2y$04$BVp4Fww6nEJ4NKbbP3lmsuHCKO..tb3dTDC1U9StKELZxJNO9fDg.");
    const base = "a" ** 72;
    try testing.expect(check(&h, base ++ "tail"));
    try testing.expect(check(&h, base));
    try testing.expect(!check(&h, base[0..71]));
}

test "cache: hits until expiry, keyed by stored hash, user and password" {
    var key: [32]u8 = @splat(7);
    _ = &key;
    var c = Cache.init(key);
    const io = testing.io;
    const h: Hash = .{ .sha1 = @splat(1) };
    const other: Hash = .{ .sha1 = @splat(2) };
    const d = c.digest(&h, "alice", "pw");
    try testing.expect(!c.contains(io, d, 0));
    c.insert(io, d, 1000);
    try testing.expect(c.contains(io, d, 2000));
    try testing.expect(!c.contains(io, d, 1000 + Cache.ttl_ns));
    try testing.expect(!c.contains(io, c.digest(&other, "alice", "pw"), 2000));
    try testing.expect(!c.contains(io, c.digest(&h, "alicf", "pw"), 2000));
    try testing.expect(!c.contains(io, c.digest(&h, "alice", "pw2"), 2000));
    // "ab"+"c" and "a"+"bc" are different inputs.
    try testing.expect(!std.mem.eql(u8, &c.digest(&h, "ab", "c"), &c.digest(&h, "a", "bc")));
}

test "cache: a full set evicts the soonest to expire" {
    var c = Cache.init(@splat(3));
    const io = testing.io;
    var tags: [Cache.ways + 1][32]u8 = undefined;
    for (&tags, 0..) |*t, i| {
        t.* = @splat(@intCast(i + 1));
        t[0] = 9; // same set
        c.insert(io, t.*, @intCast(i * 10));
    }
    try testing.expect(!c.contains(io, tags[0], 50));
    for (tags[1..]) |t| try testing.expect(c.contains(io, t, 50));
}

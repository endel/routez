//! The browser check: a page that has the browser find a small SHA-256
//! proof of work, then trade it for a pass cookie. Flood tools that don't
//! run JavaScript never get past the page, which costs what serving a
//! static page costs. Locations ask for it with `browser_check`.
//!
//! Puzzles and passes are HMACs over the client's network and an expiry,
//! so nothing is stored: every worker, and every routez sharing the secret,
//! takes the passes any of them issued.
//!
//! - A puzzle is `HMAC("puzzle" ‖ scope ‖ difficulty ‖ expires)`, base64url.
//!   The browser finds a nonce such that `SHA-256(puzzle ‖ nonce)` starts
//!   with `difficulty` zero bits: 2^difficulty hashes on average.
//! - A pass is `expires ‖ HMAC("pass" ‖ scope ‖ expires)[0..16]`, base64url:
//!   32 characters.
//!
//! The scope is the client's IPv4 address, or its IPv6 /64 (privacy
//! addresses rotate inside it): a pass solved on one network is worthless
//! from another, so one solve can't be shared across a botnet.
const std = @import("std");
const client_limits = @import("client_limits.zig");

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const b64 = std.base64.url_safe_no_pad;

/// Requests for the check's own endpoints and assets start with this.
pub const prefix = "/.routez/check/";
/// How long a browser has to solve a puzzle.
pub const puzzle_ttl_s = 300;
/// A pass as its cookie value holds it.
pub const pass_len = b64.Encoder.calcSize(8 + 16);
/// A puzzle as the page gets it.
pub const puzzle_len = b64.Encoder.calcSize(Hmac.mac_length);
const max_nonce = 16;

pub const Check = struct {
    secret: []const u8,
    difficulty: u8,
    pass_ttl_s: u32,
    cookie: []const u8,
};

/// The network a puzzle or pass is bound to.
pub fn scope(ip: client_limits.Ip) client_limits.Ip {
    return client_limits.network(ip, 32, 64);
}

fn mac(c: *const Check, kind: []const u8, sc: client_limits.Ip, extra: []const u8, out: *[Hmac.mac_length]u8) void {
    var h = Hmac.init(c.secret);
    h.update(kind);
    h.update(&sc);
    h.update(extra);
    h.final(out);
}

/// The puzzle for `sc` that stops counting at `expires`.
pub fn puzzle(c: *const Check, sc: client_limits.Ip, expires: u64, out: *[puzzle_len]u8) []const u8 {
    var extra: [9]u8 = undefined;
    extra[0] = c.difficulty;
    std.mem.writeInt(u64, extra[1..9], expires, .big);
    var m: [Hmac.mac_length]u8 = undefined;
    mac(c, "puzzle", sc, &extra, &m);
    return b64.Encoder.encode(out, &m);
}

/// Whether `nonce` solves the puzzle `sc` got for `expires`, still in time.
pub fn solved(c: *const Check, sc: client_limits.Ip, expires: u64, nonce: []const u8, now_s: u64) bool {
    // `expires` is under the HMAC, so a client can't stretch it; the upper
    // bound turns away puzzles from a longer `puzzle_ttl_s` than this one.
    if (expires < now_s or expires > now_s + puzzle_ttl_s) return false;
    if (nonce.len == 0 or nonce.len > max_nonce) return false;
    for (nonce) |ch| if (!std.ascii.isDigit(ch) and !std.ascii.isLower(ch)) return false;
    var p: [puzzle_len]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(puzzle(c, sc, expires, &p));
    h.update(nonce);
    return leadingZeroBits(&h.finalResult()) >= c.difficulty;
}

/// The pass for `sc`, good until `expires`.
pub fn pass(c: *const Check, sc: client_limits.Ip, expires: u64, out: *[pass_len]u8) []const u8 {
    var raw: [8 + 16]u8 = undefined;
    std.mem.writeInt(u64, raw[0..8], expires, .big);
    var m: [Hmac.mac_length]u8 = undefined;
    mac(c, "pass", sc, raw[0..8], &m);
    raw[8..].* = m[0..16].*;
    return b64.Encoder.encode(out, &raw);
}

/// Whether `value` is a pass for `sc` that hasn't ended. Anything not shaped
/// like one costs no HMAC.
pub fn valid(c: *const Check, value: []const u8, sc: client_limits.Ip, now_s: u64) bool {
    if (value.len != pass_len) return false;
    var raw: [8 + 16]u8 = undefined;
    b64.Decoder.decode(&raw, value) catch return false;
    const expires = std.mem.readInt(u64, raw[0..8], .big);
    if (expires < now_s) return false;
    var m: [Hmac.mac_length]u8 = undefined;
    mac(c, "pass", sc, raw[0..8], &m);
    // Constant time: a forger learns nothing byte by byte from timings.
    return std.crypto.timing_safe.eql([16]u8, m[0..16].*, raw[8..].*);
}

fn leadingZeroBits(bytes: []const u8) u16 {
    var bits: u16 = 0;
    for (bytes) |b| {
        if (b != 0) return bits + @clz(b);
        bits += 8;
    }
    return bits;
}

/// The value of cookie `name` in `cookie` headers (HTTP/1.1 may send
/// several; HTTP/3's arrive joined).
pub fn cookieValue(headers: anytype, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (!std.ascii.eqlIgnoreCase(h.name, "cookie")) continue;
        var pairs = std.mem.splitScalar(u8, h.value, ';');
        while (pairs.next()) |pair| {
            const p = std.mem.trim(u8, pair, " \t");
            if (p.len > name.len and p[name.len] == '=' and std.mem.eql(u8, p[0..name.len], name)) return p[name.len + 1 ..];
        }
    }
    return null;
}

const testing = std.testing;

fn ip4(a: u8, b: u8, cc: u8, d: u8) client_limits.Ip {
    return .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, cc, d };
}

test "a pass holds for its network until it ends, and only there" {
    const c: Check = .{ .secret = "0123456789abcdef0123456789abcdef", .difficulty = 8, .pass_ttl_s = 60, .cookie = "routez_pass" };
    const here = scope(ip4(192, 0, 2, 7));
    var buf: [pass_len]u8 = undefined;
    const p = pass(&c, here, 1000, &buf);
    try testing.expectEqual(@as(usize, 32), p.len);
    try testing.expect(valid(&c, p, here, 1000));
    try testing.expect(!valid(&c, p, here, 1001));
    try testing.expect(!valid(&c, p, scope(ip4(192, 0, 2, 8)), 999));
    var forged = buf;
    forged[31] = if (forged[31] == 'A') 'B' else 'A';
    try testing.expect(!valid(&c, &forged, here, 999));
    try testing.expect(!valid(&c, "not a pass", here, 999));
    // An IPv6 client keeps its pass across its own /64.
    const v6a = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1 } ++ @as([8]u8, @splat(0x11));
    const v6b = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1 } ++ @as([8]u8, @splat(0x22));
    try testing.expect(valid(&c, pass(&c, scope(v6a), 1000, &buf), scope(v6b), 999));
    const other: Check = .{ .secret = "another secret, also 32 bytes ok", .difficulty = 8, .pass_ttl_s = 60, .cookie = "routez_pass" };
    try testing.expect(!valid(&other, pass(&c, here, 1000, &buf), here, 999));
}

test "a nonce solves only its puzzle, in time" {
    const c: Check = .{ .secret = "0123456789abcdef0123456789abcdef", .difficulty = 8, .pass_ttl_s = 60, .cookie = "routez_pass" };
    const here = scope(ip4(192, 0, 2, 7));
    // The browser's search: nonces in base 36.
    var n: u32 = 0;
    var text: [8]u8 = undefined;
    const nonce = while (true) : (n += 1) {
        const t = std.fmt.bufPrint(&text, "{d}", .{n}) catch unreachable;
        if (solved(&c, here, 1200, t, 1000)) break t;
    };
    // Fixed inputs: another network's puzzle is another hash, deterministically unsolved.
    try testing.expect(!solved(&c, scope(ip4(192, 0, 2, 8)), 1200, nonce, 1000));
    try testing.expect(!solved(&c, here, 1200, nonce, 1201));
    try testing.expect(!solved(&c, here, 1000 + puzzle_ttl_s + 1, nonce, 1000));
    try testing.expect(!solved(&c, here, 1200, "NOT-ok", 1000));
    try testing.expect(!solved(&c, here, 1200, "", 1000));
}

test "cookies" {
    const H = struct { name: []const u8, value: []const u8 };
    const hs = [_]H{ .{ .name = "accept", .value = "*/*" }, .{ .name = "Cookie", .value = "a=1; routez_passx=no" }, .{ .name = "cookie", .value = "b=2;  routez_pass=yes" } };
    try testing.expectEqualStrings("yes", cookieValue(&hs, "routez_pass").?);
    try testing.expectEqualStrings("1", cookieValue(&hs, "a").?);
    try testing.expect(cookieValue(&hs, "c") == null);
}

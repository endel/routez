//! The browser check's page and endpoints (`browser_check.zig`): the page
//! in place of what a visitor without a pass asked for, and under
//! `/.routez/check/` its scripts, puzzles and the verify that sets the pass.
const std = @import("std");
const quic = @import("quic");
const bc = @import("../browser_check.zig");
const client_limits = @import("../client_limits.zig");
const stats = @import("../stats.zig");
const Exchange = @import("../exchange.zig").Exchange;
const Header = @import("../http/common.zig").Header;

/// The page with the logo in it, built at compile time.
const page = blk: {
    const raw = @embedFile("../check/page.html");
    const marker = "<!--logo-->";
    @setEvalBranchQuota(raw.len * 4);
    const at = std.mem.indexOf(u8, raw, marker).?;
    break :blk raw[0..at] ++ @embedFile("routez.svg") ++ raw[at + marker.len ..];
};
const check_js = @embedFile("../check/check.js");
const worker_js = @embedFile("../check/worker.js");

fn nowSeconds() u64 {
    return @intCast(@max(0, quic.sys.realtimeSeconds()));
}

/// Whether the request carries a pass for its client.
pub fn hasPass(ex: *Exchange, c: *const bc.Check) bool {
    const value = bc.cookieValue(ex.req.headers, c.cookie) orelse return false;
    if (bc.valid(c, value, bc.scope(ex.req.client_ip), nowSeconds())) return true;
    stats.inc(&stats.check_invalid);
    return false;
}

/// The check page in place of what was asked for: 200, or with 503 for a
/// request an upstream had no place for (`.under_load`).
pub fn sendPage(ex: *Exchange, status: u16) void {
    stats.inc(&stats.check_pages);
    const headers = [_]Header{
        .{ .name = "content-type", .value = "text/html; charset=utf-8" },
        .{ .name = "cache-control", .value = "no-store" },
        .{ .name = "x-robots-tag", .value = "noindex" },
        .{ .name = "retry-after", .value = "1" },
    };
    ex.respondHead(&.{ .status = status, .headers = headers[0..if (status == 503) headers.len else headers.len - 1], .content_length = page.len });
    if (!ex.req.isHead()) ex.respondBody(page);
    ex.respondEnd();
}

/// A request under `/.routez/check/`.
pub fn serve(ex: *Exchange, c: *const bc.Check) void {
    const name = ex.req.path[bc.prefix.len..];
    const get = std.mem.eql(u8, ex.req.method, "GET") or ex.req.isHead();
    if (!get) return ex.sendError(405);
    if (std.mem.eql(u8, name, "check.js")) return asset(ex, check_js);
    if (std.mem.eql(u8, name, "worker.js")) return asset(ex, worker_js);
    const challenge = std.mem.eql(u8, name, "challenge");
    if (!challenge and !std.mem.eql(u8, name, "verify")) return ex.sendError(404);
    // Each costs an HMAC, and a check takes two: about 30 checks a minute,
    // room for an office or a carrier NAT behind one address.
    if (!ex.worker.allowCheck(ex.req.client_ip)) {
        stats.inc(&stats.requests_limited);
        return ex.sendRetryLater(429);
    }
    const sc = bc.scope(ex.req.client_ip);
    const now = nowSeconds();
    if (challenge) {
        var p: [bc.puzzle_len]u8 = undefined;
        var body: [128]u8 = undefined;
        const expires = now + bc.puzzle_ttl_s;
        const json = std.fmt.bufPrint(&body, "{{\"challenge\":\"{s}\",\"difficulty\":{d},\"expires\":{d}}}", .{ bc.puzzle(c, sc, expires, &p), c.difficulty, expires }) catch unreachable;
        return fixed(ex, 200, "application/json", json);
    }
    var expires: ?u64 = null;
    var nonce: []const u8 = "";
    var params = std.mem.splitScalar(u8, ex.req.query orelse "", '&');
    while (params.next()) |kv| {
        if (std.mem.startsWith(u8, kv, "expires=")) expires = std.fmt.parseInt(u64, kv["expires=".len..], 10) catch null;
        if (std.mem.startsWith(u8, kv, "nonce=")) nonce = kv["nonce=".len..];
    }
    if (expires == null or nonce.len == 0) return ex.sendError(400);
    if (!bc.solved(c, sc, expires.?, nonce, now)) return ex.sendError(403);
    var pass: [bc.pass_len]u8 = undefined;
    var cookie: [256]u8 = undefined;
    // A Secure cookie over plain HTTP is never stored: the page would loop.
    const secure = std.mem.eql(u8, ex.req.scheme, "https");
    const set = std.fmt.bufPrint(&cookie, "{s}={s}; Max-Age={d}; Path=/; HttpOnly; SameSite=Lax{s}", .{
        c.cookie, bc.pass(c, sc, now + c.pass_ttl_s, &pass), c.pass_ttl_s, if (secure) "; Secure" else "",
    }) catch unreachable;
    stats.inc(&stats.check_passes);
    const headers = [_]Header{ .{ .name = "set-cookie", .value = set }, .{ .name = "cache-control", .value = "no-store" } };
    ex.respondHead(&.{ .status = 204, .headers = &headers, .content_length = 0 });
    ex.respondEnd();
}

fn asset(ex: *Exchange, body: []const u8) void {
    const headers = [_]Header{
        .{ .name = "content-type", .value = "text/javascript; charset=utf-8" },
        .{ .name = "cache-control", .value = "public, max-age=3600" },
    };
    ex.respondHead(&.{ .status = 200, .headers = &headers, .content_length = body.len });
    if (!ex.req.isHead()) ex.respondBody(body);
    ex.respondEnd();
}

fn fixed(ex: *Exchange, status: u16, content_type: []const u8, body: []const u8) void {
    const headers = [_]Header{ .{ .name = "content-type", .value = content_type }, .{ .name = "cache-control", .value = "no-store" } };
    ex.respondHead(&.{ .status = status, .headers = &headers, .content_length = body.len });
    if (!ex.req.isHead()) ex.respondBody(body);
    ex.respondEnd();
}

test "the page holds the logo and loads its script" {
    try std.testing.expect(std.mem.indexOf(u8, page, "<svg") != null);
    try std.testing.expect(std.mem.indexOf(u8, page, "<!--logo-->") == null);
    try std.testing.expect(std.mem.indexOf(u8, page, bc.prefix ++ "check.js") != null);
}

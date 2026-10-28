//! A short-lived cache in front of an upstream (`microcache` on a
//! location). An answer to a GET is kept for `ttl_ms` and the same request
//! served from it meanwhile; one arriving while the first is still at the
//! upstream waits for that answer rather than going there too. A flood
//! hammering a few URLs reaches the app once per URL per TTL per worker,
//! however many clients it comes from.
//!
//! Kept: answers to a GET (a HEAD or a conditional GET is served from them
//! too, but never fetches one) with no body, `Authorization`, `Cookie` or
//! `Range`, whose status is 200, 203, 301, 302, 307, 308, 404 or 410, with
//! no `Set-Cookie`, no `Cache-Control` private, no-store, no-cache or zero
//! max-age, no `Vary` but on `Accept-Encoding`, and no `Content-Encoding`
//! but gzip. Clients that take gzip and those that don't are kept apart, as
//! are schemes. An answer not kept lets requests by until the TTL ends.
//!
//! Each worker has its own: no locks, and up to one fetch per worker.
const std = @import("std");
const config = @import("config.zig");
const common = @import("http/common.zig");
const socket = @import("net/socket.zig");
const timers = @import("timers.zig");
const stats = @import("stats.zig");
const gzip = @import("gzip.zig");
const Exchange = @import("exchange.zig").Exchange;
const Proxy = @import("handlers/proxy.zig").Proxy;
const Header = common.Header;

const kept_statuses = [_]u16{ 200, 203, 301, 302, 307, 308, 404, 410 };
/// Body bytes handed to the downstream at a time, under its high water.
const chunk = 64 * 1024;

pub const Lookup = union(enum) {
    /// Serve it (`serve`).
    hit: *Entry,
    /// The first request is at the upstream: wait for its answer.
    wait: *Entry,
    /// Go to the upstream and fill it; the caller holds a reference.
    fill: *Entry,
    /// Go to the upstream, the cache aside.
    pass,
};

pub const Cache = struct {
    alloc: std.mem.Allocator,
    timers: *timers.Timers,
    budget: u64,
    /// Bytes the entries in `map` hold.
    bytes: u64 = 0,
    map: std.StringHashMapUnmanaged(*Entry) = .empty,
    /// The entries in `map`, oldest first.
    oldest: ?*Entry = null,
    newest: ?*Entry = null,

    pub fn init(alloc: std.mem.Allocator, t: *timers.Timers, budget: u64) Cache {
        return .{ .alloc = alloc, .timers = t, .budget = budget };
    }

    /// At the worker's stop. An entry a reader still holds is left to it.
    pub fn deinit(self: *Cache) void {
        while (self.oldest) |e| self.remove(e);
        self.map.deinit(self.alloc);
    }

    pub fn lookup(self: *Cache, ex: *Exchange, loc: *const config.Location, mc: config.Location.Microcache) Lookup {
        const head = ex.req.isHead();
        if (!head and !std.mem.eql(u8, ex.req.method, "GET")) return .pass;
        if (ex.req.body != .none or ex.req.upgrade != null) return .pass;
        for ([_][]const u8{ "authorization", "cookie", "range" }) |h| if (ex.req.get(h) != null) return .pass;
        // Its answer may be a 304, which isn't one to keep.
        const conditional = ex.req.get("if-none-match") != null or ex.req.get("if-modified-since") != null;
        const reads_only = head or conditional;
        var key: std.ArrayList(u8) = .empty;
        key.print(ex.arena(), "{x}\x00{d}\x00{s}\x00{s}\x00", .{
            @intFromPtr(loc),
            @intFromBool(gzip.clientAccepts(ex.req.get("accept-encoding"))),
            ex.req.scheme,
            ex.req.authority,
        }) catch return .pass;
        // Exactly what goes upstream.
        Proxy.appendTarget(ex, loc, &key, ex.arena()) catch return .pass;
        const now = self.timers.now_ms;
        if (self.map.get(key.items)) |e| {
            switch (e.state) {
                .filling => return if (reads_only) .pass else .{ .wait = e },
                .ready => if (now < e.until_ms) return .{ .hit = e },
                .passed => if (now < e.until_ms) return .pass,
            }
            self.remove(e);
        }
        if (reads_only) return .pass;
        return .{ .fill = self.create(key.items, mc) catch return .pass };
    }

    fn create(self: *Cache, key: []const u8, mc: config.Location.Microcache) !*Entry {
        if (!self.room(key.len + @sizeOf(Entry))) return error.Full;
        const e = try self.alloc.create(Entry);
        errdefer self.alloc.destroy(e);
        const owned = try self.alloc.dupe(u8, key);
        errdefer self.alloc.free(owned);
        try self.map.put(self.alloc, owned, e);
        // The map's reference, and the filler's.
        e.* = .{ .cache = self, .key = owned, .ttl_ms = mc.ttl_ms, .max_bytes = mc.max_bytes, .refs = 2, .older = self.newest };
        if (self.newest) |n| n.newer = e else self.oldest = e;
        self.newest = e;
        e.count(owned.len + @sizeOf(Entry));
        stats.inc(&stats.microcache_misses);
        return e;
    }

    /// Out of the map: what it holds is no longer counted, and goes once
    /// its readers are done.
    fn remove(self: *Cache, e: *Entry) void {
        std.debug.assert(e.in_map);
        _ = self.map.remove(e.key);
        if (e.older) |o| o.newer = e.newer else self.oldest = e.newer;
        if (e.newer) |n| n.older = e.older else self.newest = e.older;
        e.in_map = false;
        e.uncount(e.counted);
        e.unref();
    }

    /// Whether `n` more bytes fit, after dropping the oldest answers that
    /// aren't being filled.
    fn room(self: *Cache, n: u64) bool {
        var at = self.oldest;
        while (self.bytes + n > self.budget) {
            const e = at orelse return false;
            at = e.newer;
            if (e.state != .filling) self.remove(e);
        }
        return true;
    }

    /// Drop what ended. Every second, from the worker's tick.
    pub fn sweep(self: *Cache) void {
        const now = self.timers.now_ms;
        var at = self.oldest;
        while (at) |e| {
            at = e.newer;
            if (e.state != .filling and e.until_ms <= now) self.remove(e);
        }
    }
};

pub const Entry = struct {
    cache: *Cache,
    /// The map's key, owned.
    key: []u8,
    state: State = .filling,
    /// Set by `drop`: the filler went away, and waiters look again.
    dropped: bool = false,
    /// Until when a ready entry serves and a passed one lets requests by.
    until_ms: i64 = 0,
    ttl_ms: u32,
    max_bytes: u32,
    /// The map's, the filler's, each reader's and a queued wake's.
    refs: u32,
    in_map: bool = true,
    older: ?*Entry = null,
    newer: ?*Entry = null,
    status: u16 = 0,
    headers: []Header = &.{},
    /// The names and values `headers` point into.
    head_bytes: []u8 = &.{},
    body: std.ArrayListUnmanaged(u8) = .empty,
    /// Bytes counted in `cache.bytes`.
    counted: u64 = 0,
    /// Requests waiting for the filler's answer, linked through
    /// `Proxy.cache_next` and `cache_prev`.
    waiting: ?*Proxy = null,
    wake: timers.Deferred = .{ .callback = onWake },

    pub const State = enum { filling, ready, passed };

    fn count(self: *Entry, n: u64) void {
        self.counted += n;
        if (!self.in_map) return;
        self.cache.bytes += n;
        stats.add(&stats.microcache_bytes, n);
    }

    fn uncount(self: *Entry, n: u64) void {
        self.counted -= n;
        self.cache.bytes -= n;
        _ = stats.microcache_bytes.fetchSub(n, .monotonic);
    }

    pub fn unref(self: *Entry) void {
        self.refs -= 1;
        if (self.refs > 0) return;
        const a = self.cache.alloc;
        a.free(self.key);
        a.free(self.headers);
        a.free(self.head_bytes);
        self.body.deinit(a);
        a.destroy(self);
    }

    /// The upstream's answer begins: kept if it may be, else the entry passes.
    pub fn begin(self: *Entry, status: u16, headers: []const Header, content_length: ?u64) void {
        if (self.state != .filling) return;
        if (!keepable(status, headers) or (content_length orelse 0) > self.max_bytes) return self.pass();
        var n: usize = 0;
        for (headers) |h| n += h.name.len + h.value.len;
        const body: usize = @intCast(content_length orelse 0);
        const size = n + headers.len * @sizeOf(Header);
        if (!self.in_map or !self.cache.room(size + body)) return self.pass();
        const a = self.cache.alloc;
        self.head_bytes = a.alloc(u8, n) catch return self.pass();
        self.headers = a.alloc(Header, headers.len) catch return self.pass();
        // A known length is held at once, so appending never grows it.
        self.body.ensureTotalCapacityPrecise(a, body) catch return self.pass();
        var at: usize = 0;
        for (headers, self.headers) |h, *out| {
            out.* = .{ .name = copy(self.head_bytes, &at, h.name), .value = copy(self.head_bytes, &at, h.value) };
        }
        self.count(size + self.body.capacity);
        self.status = status;
    }

    fn copy(buf: []u8, at: *usize, s: []const u8) []const u8 {
        @memcpy(buf[at.*..][0..s.len], s);
        defer at.* += s.len;
        return buf[at.*..][0..s.len];
    }

    /// More of its body.
    pub fn append(self: *Entry, data: []const u8) void {
        if (self.state != .filling or data.len == 0) return;
        const held = self.body.items.len + data.len <= self.body.capacity;
        if (self.body.items.len + data.len > self.max_bytes or (!held and !self.cache.room(data.len))) return self.pass();
        const before = self.body.capacity;
        self.body.appendSlice(self.cache.alloc, data) catch return self.pass();
        self.count(self.body.capacity - before);
        // Growing by more than asked for may have passed the budget.
        if (!self.cache.room(0)) return self.pass();
    }

    /// The answer is in whole: served until the TTL ends.
    pub fn done(self: *Entry) void {
        if (self.state != .filling) return;
        if (self.status == 0) return self.pass();
        self.state = .ready;
        self.until_ms = self.cache.timers.now_ms + self.ttl_ms;
        self.wakeWaiters();
    }

    /// Not an answer to keep: requests go by until the TTL ends, the
    /// waiters too.
    pub fn pass(self: *Entry) void {
        if (self.state != .filling) return;
        self.state = .passed;
        self.until_ms = self.cache.timers.now_ms + self.ttl_ms;
        const a = self.cache.alloc;
        if (self.in_map) self.uncount(self.counted - (self.key.len + @sizeOf(Entry)));
        a.free(self.headers);
        a.free(self.head_bytes);
        self.headers = &.{};
        self.head_bytes = &.{};
        self.body.clearAndFree(a);
        self.wakeWaiters();
    }

    /// The filler went before the upstream answered: forgotten, and the
    /// waiters look again, one of them to fill it anew.
    pub fn drop(self: *Entry) void {
        if (self.state != .filling) return;
        self.dropped = true;
        self.pass();
        if (self.in_map) self.cache.remove(self);
    }

    pub fn follow(self: *Entry, p: *Proxy) void {
        p.cache_prev = null;
        p.cache_next = self.waiting;
        if (self.waiting) |w| w.cache_prev = p;
        self.waiting = p;
    }

    pub fn unfollow(self: *Entry, p: *Proxy) void {
        if (p.cache_prev) |q| q.cache_next = p.cache_next else self.waiting = p.cache_next;
        if (p.cache_next) |q| q.cache_prev = p.cache_prev;
        p.cache_prev = null;
        p.cache_next = null;
    }

    /// Waiters hear on a later loop iteration, so none runs inside the
    /// filler's callbacks.
    fn wakeWaiters(self: *Entry) void {
        if (self.waiting == null or self.wake.queued) return;
        self.refs += 1;
        self.cache.timers.defer_(&self.wake);
    }

    fn onWake(d: *timers.Deferred) void {
        const self: *Entry = @fieldParentPtr("wake", d);
        while (self.waiting) |p| {
            self.unfollow(p);
            p.cacheWoken(self);
        }
        self.unref();
    }
};

fn keepable(status: u16, headers: []const Header) bool {
    if (std.mem.indexOfScalar(u16, &kept_statuses, status) == null) return false;
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "set-cookie")) return false;
        // The key tells only gzip clients from the rest: br or zstd would
        // reach a client that can't read it.
        if (std.ascii.eqlIgnoreCase(h.name, "content-encoding") and
            !std.ascii.eqlIgnoreCase(h.value, "gzip") and !std.ascii.eqlIgnoreCase(h.value, "identity")) return false;
        if (std.ascii.eqlIgnoreCase(h.name, "vary")) {
            var it = std.mem.tokenizeAny(u8, h.value, ", \t");
            while (it.next()) |v| if (!std.ascii.eqlIgnoreCase(v, "accept-encoding")) return false;
        }
        if (std.ascii.eqlIgnoreCase(h.name, "cache-control")) {
            var it = std.mem.tokenizeAny(u8, h.value, ", \t");
            while (it.next()) |d| {
                for ([_][]const u8{ "private", "no-store", "no-cache", "max-age=0", "s-maxage=0" }) |no| {
                    if (std.ascii.eqlIgnoreCase(d, no)) return false;
                }
            }
        }
    }
    return true;
}

/// Serve `e` as the response to `ex`, paced by the downstream.
pub fn serve(ex: *Exchange, e: *Entry) void {
    const r = ex.arena().create(Reader) catch return ex.sendError(500);
    e.refs += 1;
    r.* = .{ .entry = e };
    ex.handler = .{ .cached = r };
    ex.cache_status = "HIT";
    stats.inc(&stats.microcache_hits);
    ex.respondHead(&.{ .status = e.status, .headers = e.headers, .content_length = e.body.items.len });
    if (ex.req.isHead()) r.off = e.body.items.len;
    pump(ex);
}

pub const Reader = struct { entry: *Entry, off: usize = 0 };

/// Send while the downstream has room; resumed from `onDownstreamWritable`.
pub fn pump(ex: *Exchange) void {
    const r = ex.handler.cached;
    const body = r.entry.body.items;
    while (r.off < body.len) {
        if (ex.downstreamBuffered() > socket.high_water) return;
        const n = @min(body.len - r.off, chunk);
        const piece = body[r.off..][0..n];
        r.off += n;
        ex.respondBody(piece);
        if (ex.down == null) {
            // The encoder failed and aborted the response.
            release(ex);
            return ex.handlerReleased();
        }
    }
    release(ex);
    ex.respondEnd();
}

/// Let the entry go; also when the client went away.
pub fn release(ex: *Exchange) void {
    const r = ex.handler.cached;
    ex.handler = .none;
    r.entry.unref();
}

const testing = std.testing;

test "what may be kept" {
    try testing.expect(keepable(200, &.{.{ .name = "Content-Type", .value = "text/html" }}));
    try testing.expect(keepable(404, &.{.{ .name = "Vary", .value = "Accept-Encoding" }}));
    try testing.expect(keepable(200, &.{.{ .name = "cache-control", .value = "public, max-age=60" }}));
    try testing.expect(!keepable(500, &.{}));
    try testing.expect(!keepable(206, &.{}));
    try testing.expect(!keepable(200, &.{.{ .name = "Set-Cookie", .value = "a=1" }}));
    try testing.expect(!keepable(200, &.{.{ .name = "vary", .value = "accept-encoding, Cookie" }}));
    try testing.expect(keepable(200, &.{.{ .name = "Content-Encoding", .value = "gzip" }}));
    try testing.expect(!keepable(200, &.{.{ .name = "content-encoding", .value = "br" }}));
    for ([_][]const u8{ "private", "no-store", "max-age=0", "public, no-cache", "s-maxage=0" }) |cc| {
        try testing.expect(!keepable(200, &.{.{ .name = "Cache-Control", .value = cc }}));
    }
}

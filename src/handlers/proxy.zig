//! Reverse proxying to HTTP/1.1 upstreams.
//!
//! The request is forwarded as it arrives and the response streamed back as
//! it arrives, with backpressure both ways: upstream reads pause while the
//! client is behind, and the client's request body pauses while the
//! upstream is behind.
//!
//! A request is retried on another connection when nothing of the response
//! has been seen and the whole request is still on hand (it fit in the
//! replay buffer): after a connect failure, or when a pooled keep-alive
//! connection turns out to have been closed by the upstream.
const std = @import("std");
const common = @import("../http/common.zig");
const config = @import("../config.zig");
const parser = @import("../http1/parser.zig");
const router = @import("../router.zig");
const vars = @import("../http/vars.zig");
const socket = @import("../net/socket.zig");
const timers = @import("../timers.zig");
const upstream = @import("../upstream.zig");
const exchange = @import("../exchange.zig");
const Exchange = exchange.Exchange;
const Header = common.Header;

const log = std.log.scoped(.proxy);

/// Request bytes kept for a retry; larger requests are not retried.
const replay_limit = 64 * 1024;
const max_attempts = 4;

pub fn start(ex: *Exchange, loc: *const config.Location, target: []const u8) void {
    const group = ex.worker.findGroup(target) orelse return ex.sendError(502);
    const p = ex.worker.alloc.create(Proxy) catch return ex.sendError(500);
    p.* = .{ .ex = ex, .loc = loc, .group = group };
    ex.handler = .{ .proxy = p };

    p.framing = switch (ex.req.body) {
        .none => .none,
        .sized => .length,
        .streamed => .chunked,
        .unknown => .pending,
    };
    if (ex.req.upgrade != null) p.framing = .none;
    if (p.framing != .pending) {
        p.writeHead() catch return p.fail(500);
    }
    p.connectNext(false);
}

pub const Proxy = struct {
    ex: *Exchange,
    loc: *const config.Location,
    group: *upstream.Group,
    peer: ?*upstream.Peer = null,
    conn: ?*upstream.UpConn = null,
    tried: [max_attempts]*upstream.Peer = undefined,
    tried_len: usize = 0,
    attempts: u8 = 0,

    phase: Phase = .connecting,
    framing: Framing = .none,
    /// Every request byte produced so far, while it fits `replay_limit`.
    replay: std.ArrayListUnmanaged(u8) = .empty,
    replay_ok: bool = true,
    /// Request bytes produced before a connection was attached, once they
    /// outgrew the replay buffer.
    unsent: std.ArrayListUnmanaged(u8) = .empty,
    request_done: bool = false,

    /// Response bytes waiting for a complete head.
    in: std.ArrayListUnmanaged(u8) = .empty,
    decoder: parser.BodyDecoder = parser.BodyDecoder.init(.none),
    resp_keep_alive: bool = false,
    /// Bytes followed the response body; the connection can't be reused.
    trailing_garbage: bool = false,
    deadline: timers.Deadline = .{ .callback = onDeadline },
    /// Upstream reads paused because the client is behind.
    read_paused: bool = false,

    const Phase = enum { connecting, waiting_head, body, tunnel, done };
    const Framing = enum { none, length, chunked, pending };

    fn alloc(self: *Proxy) std.mem.Allocator {
        return self.ex.worker.alloc;
    }

    fn t(self: *Proxy) *timers.Timers {
        return &self.ex.worker.timers;
    }

    // ---- request side ----

    fn writeHead(self: *Proxy) !void {
        const ex = self.ex;
        const a = self.alloc();
        var head: std.ArrayList(u8) = .empty;
        defer head.deinit(a);

        try head.appendSlice(a, ex.req.method);
        try head.append(a, ' ');
        try self.appendTarget(&head);
        try head.appendSlice(a, " HTTP/1.1\r\n");
        const set = self.loc.proxy_set_headers;
        const host = if (findSet(set, "host")) |i| ex.setHeaderValue(i) else ex.req.authority;
        try head.print(a, "Host: {s}\r\n", .{host});

        var connection_values: [8][]const u8 = undefined;
        var n_conn: usize = 0;
        var xff: ?[]const u8 = null;
        for (ex.req.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "connection") and n_conn < connection_values.len) {
                connection_values[n_conn] = h.value;
                n_conn += 1;
            }
            if (std.ascii.eqlIgnoreCase(h.name, "x-forwarded-for")) xff = h.value;
        }
        for (ex.req.headers) |h| {
            if (common.isHopByHop(h.name)) continue;
            if (common.connectionListHas(connection_values[0..n_conn], h.name)) continue;
            if (skipForwarded(h.name)) continue;
            if (findSet(set, h.name) != null) continue;
            // Downstreams validate already; this write must never be what lets CRLF through.
            if (!common.isToken(h.name) or !common.isFieldValue(h.value)) continue;
            try head.print(a, "{s}: {s}\r\n", .{ h.name, h.value });
        }
        // Configured values replace these too.
        if (findSet(set, "x-forwarded-for") == null) {
            if (xff) |prev| {
                try head.print(a, "X-Forwarded-For: {s}, {s}\r\n", .{ prev, ex.req.hop_addr });
            } else {
                try head.print(a, "X-Forwarded-For: {s}\r\n", .{ex.req.hop_addr});
            }
        }
        if (findSet(set, "x-real-ip") == null) try head.print(a, "X-Real-IP: {s}\r\n", .{ex.req.client_addr});
        if (findSet(set, "x-forwarded-proto") == null) try head.print(a, "X-Forwarded-Proto: {s}\r\n", .{ex.req.scheme});
        if (findSet(set, "x-forwarded-host") == null) try head.print(a, "X-Forwarded-Host: {s}\r\n", .{ex.req.authority});
        for (set, 0..) |h, i| {
            const v = ex.setHeaderValue(i);
            if (v.len == 0 or std.ascii.eqlIgnoreCase(h.name, "host")) continue;
            try head.print(a, "{s}: {s}\r\n", .{ h.name, v });
        }

        switch (self.framing) {
            .length => try head.print(a, "Content-Length: {d}\r\n", .{ex.req.content_length.?}),
            .chunked => try head.appendSlice(a, "Transfer-Encoding: chunked\r\n"),
            .none, .pending => {},
        }
        if (ex.req.upgrade) |u| {
            try head.print(a, "Connection: upgrade\r\nUpgrade: {s}\r\n", .{u});
        } else {
            try head.appendSlice(a, "Connection: keep-alive\r\n");
        }
        try head.appendSlice(a, "\r\n");
        if (!self.send(head.items)) return error.OutOfMemory;
    }

    /// The request target sent upstream: what `proxy_pass`'s URI or
    /// `strip_prefix` make of the path, else the client's. After a rewrite,
    /// the new path in full, as nginx sends it.
    fn appendTarget(self: *Proxy, head: *std.ArrayList(u8)) !void {
        const ex = self.ex;
        const a = self.alloc();
        const path = ex.req.path;
        // The part of the path the location matched, to replace or strip.
        const matched: ?[]const u8 = self.loc.prefix orelse self.loc.exact;
        if (config.splitProxyPass(self.loc.proxy_pass.?).uri) |uri| {
            if (vars.has(uri)) {
                const target = try ex.expand(uri);
                if (std.mem.indexOfAny(u8, target, " \t") != null) return error.BadTarget;
                return head.appendSlice(a, target);
            }
            if (ex.rewritten) {
                try router.encodePath(path, head, a);
            } else {
                try head.appendSlice(a, uri);
                try router.encodePath(path[matched.?.len..], head, a);
            }
        } else if (self.loc.strip_prefix and std.mem.startsWith(u8, path, matched.?)) {
            const rest = path[matched.?.len..];
            if (rest.len == 0 or rest[0] != '/') try head.append(a, '/');
            try router.encodePath(rest, head, a);
        } else if (!ex.rewritten and ex.req.target.len > 0 and ex.req.target[0] == '/') {
            return head.appendSlice(a, ex.req.target);
        } else {
            try router.encodePath(path, head, a);
        }
        if (ex.req.query) |q| try head.print(a, "?{s}", .{q});
    }

    fn findSet(set: []const config.HeaderKV, name: []const u8) ?usize {
        for (set, 0..) |h, i| if (std.ascii.eqlIgnoreCase(h.name, name)) return i;
        return null;
    }

    fn skipForwarded(name: []const u8) bool {
        const list = [_][]const u8{ "x-forwarded-for", "x-real-ip", "x-forwarded-proto", "x-forwarded-host", "expect" };
        for (list) |n| if (std.ascii.eqlIgnoreCase(name, n)) return true;
        return false;
    }

    /// Queue request bytes for the upstream, keeping a replay copy.
    /// False on allocation failure.
    fn send(self: *Proxy, bytes: []const u8) bool {
        const a = self.alloc();
        const fits = self.replay_ok and self.replay.items.len + bytes.len <= replay_limit;
        const c = self.conn orelse {
            if (fits) {
                self.replay.appendSlice(a, bytes) catch return false;
                return true;
            }
            if (self.replay_ok) {
                // Too big to replay: what is held so far becomes the unsent prefix.
                std.mem.swap(std.ArrayListUnmanaged(u8), &self.replay, &self.unsent);
                self.replay.clearAndFree(a);
                self.replay_ok = false;
            }
            self.unsent.appendSlice(a, bytes) catch return false;
            return true;
        };
        if (fits) {
            self.replay.appendSlice(a, bytes) catch return false;
        } else if (self.replay_ok) {
            self.replay_ok = false;
            self.replay.clearAndFree(a);
        }
        c.send(bytes);
        return true;
    }

    pub fn onRequestBody(self: *Proxy, data: []const u8) void {
        if (self.phase == .done) return;
        if (self.phase == .tunnel) {
            if (self.conn) |c| c.send(data);
            return self.checkRequestBackpressure();
        }
        if (self.framing == .pending) {
            self.framing = .chunked;
            self.writeHead() catch return self.fail(500);
        }
        const ok = switch (self.framing) {
            .chunked => blk: {
                var buf: [20]u8 = undefined;
                break :blk self.send(std.fmt.bufPrint(&buf, "{x}\r\n", .{data.len}) catch unreachable) and
                    self.send(data) and self.send("\r\n");
            },
            .length => self.send(data),
            .none, .pending => true,
        };
        if (!ok) return self.fail(500);
        self.armDeadline();
        self.checkRequestBackpressure();
    }

    fn checkRequestBackpressure(self: *Proxy) void {
        const c = self.conn orelse return;
        if (c.sock.buffered() > socket.high_water) self.ex.pauseRequestBody(true);
    }

    pub fn onRequestEnd(self: *Proxy) void {
        if (self.phase == .done) return;
        self.request_done = true;
        self.armDeadline();
        if (self.phase == .tunnel) {
            // The client closed its side of the tunnel.
            return self.complete(false);
        }
        switch (self.framing) {
            .pending => {
                self.framing = .none;
                self.writeHead() catch return self.fail(500);
            },
            .chunked => if (!self.send("0\r\n\r\n")) return self.fail(500),
            .length, .none => {},
        }
    }

    // ---- connection management ----

    /// Attach a connection to the next peer. `same_peer` retries the current
    /// peer on a fresh connection (a stale pooled one failed).
    fn connectNext(self: *Proxy, same_peer: bool) void {
        const peer = if (same_peer and self.peer != null) self.peer.? else blk: {
            if (self.tried_len >= self.tried.len) return self.fail(502);
            const p = self.group.pick(self.ex.req.client_addr, self.tried[0..self.tried_len]) orelse return self.fail(502);
            self.tried[self.tried_len] = p;
            self.tried_len += 1;
            break :blk p;
        };
        self.attempts += 1;
        self.peer = peer;
        self.ex.upstream_addr = peer.label;
        const c = peer.acquire(self) catch {
            peer.recordFailure();
            return self.retryOrFail(502);
        };
        self.conn = c;
        self.phase = if (c.reused) .waiting_head else .connecting;
        if (!c.reused) self.t().set(&self.deadline, self.group.cfg.connect_timeout_ms);
        if (self.replay_ok) {
            c.send(self.replay.items);
        } else {
            c.send(self.unsent.items);
            self.unsent.clearAndFree(self.alloc());
        }
        if (c.reused) {
            c.sock.startReading();
            self.armDeadline();
        }
    }

    fn detachConn(self: *Proxy, reusable: bool) void {
        const c = self.conn orelse return;
        self.conn = null;
        self.peer.?.release(c, reusable);
    }

    /// Nothing of the response was seen: try again if the request can be replayed.
    fn retryOrFail(self: *Proxy, status: u16) void {
        self.detachConn(false);
        if (!self.replay_ok or self.attempts >= max_attempts) return self.fail(status);
        self.in.clearRetainingCapacity();
        self.connectNext(false);
    }

    pub fn onUpstreamConnected(self: *Proxy, err: ?anyerror) void {
        if (err) |e| {
            log.warn("connect to {s} failed: {s}", .{ self.peer.?.label, @errorName(e) });
            self.peer.?.recordFailure();
            return self.retryOrFail(502);
        }
        self.phase = .waiting_head;
        self.armDeadline();
    }

    /// The upstream timeout covers the upstream being slow, never us: it is
    /// off while upstream reads are paused for a slow client, and while the
    /// request body is still coming from the client with nothing queued for
    /// the upstream (the client connection's own timeout covers that).
    fn armDeadline(self: *Proxy) void {
        const c = self.conn orelse return;
        const waiting_on_us = switch (self.phase) {
            .connecting, .tunnel, .done => return,
            .waiting_head => self.read_paused or (!self.request_done and c.sock.buffered() == 0),
            .body => self.read_paused,
        };
        if (waiting_on_us) {
            self.t().clear(&self.deadline);
        } else {
            self.t().set(&self.deadline, self.group.cfg.read_timeout_ms);
        }
    }

    pub fn onUpstreamWritable(self: *Proxy) void {
        if (self.phase == .done) return;
        self.armDeadline();
        self.ex.pauseRequestBody(false);
    }

    pub fn onDownstreamWritable(self: *Proxy) void {
        const c = self.conn orelse return;
        if (!self.read_paused or self.ex.downstreamBuffered() >= socket.low_water) return;
        self.read_paused = false;
        c.sock.resumeRead();
        self.armDeadline();
    }

    // ---- response side ----

    pub fn onUpstreamData(self: *Proxy, data: []const u8) void {
        // Head and body out in one send. The downstream outlives this call
        // (its frees are deferred), the exchange may not.
        const down = self.ex.down;
        if (down) |d| d.setCork(true);
        defer if (down) |d| d.setCork(false);
        switch (self.phase) {
            .connecting, .done => return,
            .tunnel => {
                self.ex.respondBody(data);
                return self.checkResponseBackpressure();
            },
            .waiting_head => {
                self.in.appendSlice(self.alloc(), data) catch return self.fail(502);
                self.armDeadline();
                self.parseHead();
            },
            .body => {
                self.armDeadline();
                self.forwardBody(data);
            },
        }
    }

    fn parseHead(self: *Proxy) void {
        const ex = self.ex;
        while (true) {
            var hbuf: [128]Header = undefined;
            const limits: parser.Limits = .{ .max_head = ex.worker.cfg.limits.max_header_bytes * 2, .max_headers = hbuf.len };
            const parsed = parser.parseResponse(self.in.items, &hbuf, limits) catch |err| {
                log.warn("bad response from {s}: {s}", .{ self.peer.?.label, @errorName(err) });
                self.peer.?.recordFailure();
                return self.fail(502);
            } orelse return;
            const head = parsed.head;

            if (head.status == 101) {
                if (ex.req.upgrade == null) return self.fail(502);
                return self.startTunnel(&head, parsed.len);
            }
            if (head.status < 200) {
                // Interim responses (100 Continue, 103) are not relayed.
                self.consumeIn(parsed.len);
                continue;
            }

            self.peer.?.recordSuccess();
            const kind = parser.responseBodyKind(&head, ex.req.method);
            self.decoder = parser.BodyDecoder.init(kind);
            self.resp_keep_alive = head.keep_alive and kind != .until_close;

            var out: [128]Header = undefined;
            const headers = filterResponseHeaders(head.headers, &out);
            const content_length: ?u64 = switch (kind) {
                .length => |n| n,
                .none => if (ex.req.isHead()) head.content_length else if (common.statusHasNoBody(head.status)) null else 0,
                else => null,
            };
            self.phase = .body;
            ex.respondHead(&.{ .status = head.status, .headers = headers, .content_length = content_length });

            // The head slices point into `in`; they are dead from here on.
            const rest_len = self.in.items.len - parsed.len;
            if (rest_len == 0) {
                self.in.clearRetainingCapacity();
                if (self.decoder.done) return self.complete(true);
                return;
            }
            // Move the leftover body out so `in` can be freed.
            // forwardBody may free `self`: keep the allocator in a local.
            const a = self.alloc();
            var rest: std.ArrayListUnmanaged(u8) = .empty;
            rest.appendSlice(a, self.in.items[parsed.len..]) catch return self.fail(502);
            defer rest.deinit(a);
            self.in.clearAndFree(self.alloc());
            return self.forwardBody(rest.items);
        }
    }

    fn consumeIn(self: *Proxy, n: usize) void {
        const rest = self.in.items.len - n;
        std.mem.copyForwards(u8, self.in.items[0..rest], self.in.items[n..]);
        self.in.items.len = rest;
    }

    fn forwardBody(self: *Proxy, data_in: []const u8) void {
        var data = data_in;
        while (data.len > 0) {
            if (self.decoder.done) {
                self.trailing_garbage = true;
                break;
            }
            const step = self.decoder.decode(data) catch {
                log.warn("bad chunked body from {s}", .{self.peer.?.label});
                return self.abortResponse();
            };
            if (step.data.len > 0) self.ex.respondBody(step.data);
            data = data[step.consumed..];
            if (step.consumed == 0) break;
        }
        if (self.decoder.done) return self.complete(true);
        self.checkResponseBackpressure();
    }

    fn checkResponseBackpressure(self: *Proxy) void {
        const c = self.conn orelse return;
        if (self.read_paused or self.ex.downstreamBuffered() <= socket.high_water) return;
        self.read_paused = true;
        c.sock.pauseRead();
        self.armDeadline();
    }

    fn startTunnel(self: *Proxy, head: *const parser.ResponseHead, head_len: usize) void {
        const ex = self.ex;
        self.peer.?.recordSuccess();
        var out: [128]Header = undefined;
        var n: usize = 0;
        for (head.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "connection") or std.ascii.eqlIgnoreCase(h.name, "server") or std.ascii.eqlIgnoreCase(h.name, "date")) continue;
            if (n == out.len) break;
            out[n] = h;
            n += 1;
        }
        if (n < out.len) {
            out[n] = .{ .name = "connection", .value = "upgrade" };
            n += 1;
        }
        self.phase = .tunnel;
        self.t().clear(&self.deadline);
        ex.respondHead(&.{ .status = 101, .headers = out[0..n] });
        ex.startTunnel();
        ex.pauseRequestBody(false);
        if (self.in.items.len > head_len) ex.respondBody(self.in.items[head_len..]);
        self.in.clearAndFree(self.alloc());
        // Nothing is replayable once the upgrade is through.
        self.replay.clearAndFree(self.alloc());
        self.unsent.clearAndFree(self.alloc());
        self.replay_ok = false;
    }

    pub fn onUpstreamEof(self: *Proxy) void {
        switch (self.phase) {
            .done => {},
            .connecting, .waiting_head => {
                const c = self.conn.?;
                if (c.reused and self.in.items.len == 0) {
                    // The pool handed us a connection the upstream had closed.
                    self.detachConn(false);
                    if (!self.replay_ok) return self.fail(502);
                    return self.connectNext(true);
                }
                self.peer.?.recordFailure();
                if (self.in.items.len == 0) return self.retryOrFail(502);
                self.fail(502);
            },
            .body => {
                if (self.decoder.finishOnEof()) return self.complete(false);
                self.abortResponse();
            },
            .tunnel => self.complete(false),
        }
    }

    fn onDeadline(d: *timers.Deadline) void {
        const self: *Proxy = @fieldParentPtr("deadline", d);
        switch (self.phase) {
            .connecting => {
                log.warn("connect to {s} timed out", .{self.peer.?.label});
                self.peer.?.recordFailure();
                self.retryOrFail(504);
            },
            .waiting_head => {
                log.warn("{s} timed out waiting for a response", .{self.peer.?.label});
                self.fail(504);
            },
            .body => self.abortResponse(),
            .tunnel, .done => {},
        }
    }

    // ---- endings ----

    /// Response finished normally.
    fn complete(self: *Proxy, clean: bool) void {
        const reusable = clean and self.resp_keep_alive and !self.trailing_garbage and self.request_done and self.phase == .body;
        self.phase = .done;
        // Pool the connection first: finishing may start the client's next
        // pipelined request, which can then reuse it.
        self.detachConn(reusable);
        self.ex.respondEnd();
        self.finish(false);
    }

    /// Error before the response started: answer with `status`.
    fn fail(self: *Proxy, status: u16) void {
        if (self.phase == .done) return;
        self.phase = .done;
        self.ex.sendError(status);
        self.finish(false);
    }

    /// Error after the response started.
    fn abortResponse(self: *Proxy) void {
        if (self.phase == .done) return;
        self.phase = .done;
        self.ex.respondAbort();
        self.finish(false);
    }

    pub fn onDownstreamGone(self: *Proxy) void {
        self.phase = .done;
        self.finish(false);
    }

    /// Release everything and free the proxy and, through it, the exchange.
    fn finish(self: *Proxy, reusable: bool) void {
        self.t().clear(&self.deadline);
        self.detachConn(reusable);
        const a = self.alloc();
        self.replay.deinit(a);
        self.unsent.deinit(a);
        self.in.deinit(a);
        const ex = self.ex;
        a.destroy(self);
        ex.handlerReleased();
    }
};

/// Drop hop-by-hop headers, headers the upstream's Connection names, and the
/// upstream's Date/Server (the downstream writes its own).
fn filterResponseHeaders(headers: []const Header, out: []Header) []const Header {
    var connection_values: [8][]const u8 = undefined;
    var n_conn: usize = 0;
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "connection") and n_conn < connection_values.len) {
            connection_values[n_conn] = h.value;
            n_conn += 1;
        }
    }
    var n: usize = 0;
    for (headers) |h| {
        if (common.isHopByHop(h.name)) continue;
        if (std.ascii.eqlIgnoreCase(h.name, "date") or std.ascii.eqlIgnoreCase(h.name, "server")) continue;
        if (common.connectionListHas(connection_values[0..n_conn], h.name)) continue;
        if (n == out.len) break;
        out[n] = h;
        n += 1;
    }
    return out[0..n];
}

test "response header filtering" {
    const in = [_]Header{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "Connection", .value = "close, X-Secret" },
        .{ .name = "X-Secret", .value = "1" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Server", .value = "upstream" },
        .{ .name = "Set-Cookie", .value = "a=1" },
    };
    var out: [8]Header = undefined;
    const got = filterResponseHeaders(&in, &out);
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqualStrings("Content-Type", got[0].name);
    try std.testing.expectEqualStrings("Set-Cookie", got[1].name);
}

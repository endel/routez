//! One request and the handler producing its response.
//!
//! The downstream (an HTTP/1.1 connection today, an HTTP/3 stream later)
//! talks to the exchange through `on*` events, and the exchange answers
//! through the `Downstream` interface, so handlers never see the protocol.
//!
//! Lifetime: created by the downstream once a request head is parsed; after
//! the exchange calls `Downstream.finish`/`abort`, or the downstream calls
//! `onDownstreamGone`, the two are detached. The exchange frees itself once
//! detached and its handler has released everything (e.g. an upstream conn).
const std = @import("std");
const common = @import("http/common.zig");
const config = @import("config.zig");
const router = @import("router.zig");
const Worker = @import("worker.zig").Worker;
const static = @import("handlers/static.zig");
const proxy = @import("handlers/proxy.zig");
const Header = common.Header;
const stats = @import("stats.zig");
const gzip = @import("gzip.zig");

pub const Response = struct {
    status: u16,
    /// End-to-end headers only; the downstream adds framing, Date, Server.
    headers: []const Header = &.{},
    /// Null when the length isn't known up front (streamed).
    content_length: ?u64 = null,
};

pub const Downstream = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        sendHead: *const fn (*anyopaque, *const Response) void,
        sendBody: *const fn (*anyopaque, []const u8) void,
        /// Response complete. The downstream detaches from the exchange.
        finish: *const fn (*anyopaque) void,
        /// Response failed after it started; the client must see an error
        /// (connection or stream reset). The downstream detaches.
        abort: *const fn (*anyopaque) void,
        /// Response bytes queued but not yet sent.
        buffered: *const fn (*anyopaque) usize,
        setRequestBodyPaused: *const fn (*anyopaque, bool) void,
        /// After a 101 head: raw bytes in both directions from here on.
        startTunnel: *const fn (*anyopaque) void,
    };
};

pub const Protocol = enum {
    http10,
    http11,
    http3,

    pub fn text(self: Protocol) []const u8 {
        return switch (self) {
            .http10 => "HTTP/1.0",
            .http11 => "HTTP/1.1",
            .http3 => "HTTP/3",
        };
    }
};

pub const BodyMode = enum {
    none,
    /// Content-Length known.
    sized,
    /// Length unknown until the end (chunked, or HTTP/3 without content-length).
    streamed,
    /// HTTP/3 without content-length on a method that rarely has a body:
    /// decided by whether data or the end of the stream arrives first.
    unknown,
};

/// Request data, copied into the exchange's arena.
pub const Request = struct {
    method: []const u8,
    /// As received, for access logs and proxying.
    target: []const u8,
    path: []const u8,
    query: ?[]const u8,
    authority: []const u8,
    /// Excludes Host and HTTP/3 pseudo-headers.
    headers: []const Header,
    content_length: ?u64,
    body: BodyMode,
    /// `Upgrade` value when the client asked for a protocol switch.
    upgrade: ?[]const u8,
    protocol: Protocol,
    scheme: []const u8,
    client_addr: []const u8,

    pub fn get(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    pub fn isHead(self: *const Request) bool {
        return std.mem.eql(u8, self.method, "HEAD");
    }
};

/// What the downstream hands over to create an exchange; slices may be
/// transient, `create` copies them.
pub const RequestInit = struct {
    method: []const u8,
    target: []const u8,
    authority: ?[]const u8,
    headers: []const Header,
    content_length: ?u64,
    body: BodyMode,
    upgrade: ?[]const u8 = null,
    protocol: Protocol,
    scheme: []const u8,
    client_addr: []const u8,
    vhosts: *const router.VirtualHosts,
};

pub const Exchange = struct {
    worker: *Worker,
    arena_state: std.heap.ArenaAllocator,
    down: ?Downstream,
    req: Request,
    server: *const config.Server,
    location: ?*const config.Location,

    handler: union(enum) {
        none,
        static: static.State,
        proxy: *proxy.Proxy,
    } = .none,

    status: u16 = 0,
    bytes_sent: u64 = 0,
    start_ms: i64,
    head_sent: bool = false,
    done: bool = false,
    /// Set when the response ended by abort rather than finish.
    failed: bool = false,
    upstream_addr: ?[]const u8 = null,
    /// Set when this response is being gzip-compressed.
    gz: ?*gzip.Encoder = null,

    pub fn create(worker: *Worker, down: Downstream, init: RequestInit) !*Exchange {
        const ex = try worker.alloc.create(Exchange);
        errdefer worker.alloc.destroy(ex);
        ex.* = .{
            .worker = worker,
            .arena_state = .init(worker.alloc),
            .down = down,
            .req = undefined,
            .server = init.vhosts.select(init.authority),
            .location = null,
            .start_ms = worker.timers.now_ms,
        };
        errdefer ex.arena_state.deinit();
        const a = ex.arena_state.allocator();
        stats.inc(&stats.requests);
        if (init.protocol == .http3) stats.inc(&stats.requests_h3);

        const headers = try a.alloc(Header, init.headers.len);
        for (init.headers, headers) |src, *dst| {
            dst.* = .{ .name = try a.dupe(u8, src.name), .value = try a.dupe(u8, src.value) };
        }
        const target = try a.dupe(u8, init.target);
        const path_buf = try a.alloc(u8, target.len + 2);
        const norm = router.normalizeTarget(target, path_buf) catch router.Target{ .path = "", .query = null };

        ex.req = .{
            .method = try a.dupe(u8, init.method),
            .target = target,
            .path = norm.path,
            .query = norm.query,
            .authority = try a.dupe(u8, init.authority orelse ""),
            .headers = headers,
            .content_length = init.content_length,
            .body = init.body,
            .upgrade = if (init.upgrade) |u| try a.dupe(u8, u) else null,
            .protocol = init.protocol,
            .scheme = init.scheme,
            .client_addr = try a.dupe(u8, init.client_addr),
        };
        return ex;
    }

    pub fn arena(self: *Exchange) std.mem.Allocator {
        return self.arena_state.allocator();
    }

    /// Route and hand the request to its handler.
    pub fn start(self: *Exchange) void {
        if (self.req.path.len == 0) return self.sendError(400);
        const loc = router.matchLocation(self.server, self.req.path) orelse return self.sendError(404);
        self.location = loc;
        if (loc.limit_req) |lim| {
            if (!self.worker.allowRequest(loc, lim, self.req.client_addr)) {
                const headers = [_]Header{ .{ .name = "retry-after", .value = "1" }, .{ .name = "content-type", .value = "text/plain" } };
                self.respondHead(&.{ .status = 429, .headers = &headers, .content_length = 0 });
                return self.respondEnd();
            }
        }
        const max_body = self.worker.cfg.limits.max_body_bytes;
        if (max_body != 0 and (self.req.content_length orelse 0) > max_body) return self.sendError(413);

        if (loc.@"return") |ret| return self.sendFixed(ret.status, ret.content_type, ret.body);
        if (loc.stub_status) {
            var buf: [512]u8 = undefined;
            return self.sendFixed(200, "text/plain; charset=utf-8", stats.format(&buf, self.worker.quicConnectionCount()));
        }
        if (loc.root) |root| return static.start(self, loc, root);
        if (loc.proxy_pass) |target| return proxy.start(self, loc, target);
        // webtransport_pass only means something to a CONNECT over HTTP/3.
        return self.sendError(404);
    }

    // ---- downstream events ----

    pub fn onRequestBody(self: *Exchange, data: []const u8) void {
        switch (self.handler) {
            .proxy => |p| p.onRequestBody(data),
            else => {},
        }
    }

    pub fn onRequestEnd(self: *Exchange) void {
        switch (self.handler) {
            .proxy => |p| p.onRequestEnd(),
            else => {},
        }
    }

    pub fn onDownstreamWritable(self: *Exchange) void {
        switch (self.handler) {
            .static => static.pump(self),
            .proxy => |p| p.onDownstreamWritable(),
            .none => {},
        }
    }

    /// The client went away. The exchange must not touch the downstream
    /// again, and may be freed before this returns.
    pub fn onDownstreamGone(self: *Exchange) void {
        self.down = null;
        if (!self.done) {
            self.done = true;
            self.failed = true;
            if (self.status == 0) self.status = 499;
            self.logAccess();
        }
        switch (self.handler) {
            .static => {
                static.release(self);
                self.destroy();
            },
            // Frees the exchange through handlerReleased once the upstream side is let go.
            .proxy => |p| p.onDownstreamGone(),
            .none => self.destroy(),
        }
    }

    // ---- response side, used by handlers ----

    pub fn respondHead(self: *Exchange, resp_in: *const Response) void {
        const final = resp_in.status >= 200 or resp_in.status == 101;
        if (final) {
            self.status = resp_in.status;
            self.head_sent = true;
        }
        const d = self.down orelse return;
        const loc = self.location orelse return d.vtable.sendHead(d.ptr, resp_in);
        if (!final or (loc.add_headers.len == 0 and !loc.gzip)) return d.vtable.sendHead(d.ptr, resp_in);

        // Rebuild the header list: add_headers, then gzip's changes.
        var resp = resp_in.*;
        const a = self.arena();
        var list: std.ArrayListUnmanaged(Header) = .empty;
        list.ensureTotalCapacity(a, resp.headers.len + loc.add_headers.len + 2) catch return d.vtable.sendHead(d.ptr, resp_in);
        list.appendSliceAssumeCapacity(resp.headers);
        for (loc.add_headers) |h| list.appendAssumeCapacity(.{ .name = h.name, .value = h.value });
        if (loc.gzip and self.startGzip(&resp, list.items)) {
            for (list.items) |*h| {
                // The compressed body is a different representation.
                if (std.ascii.eqlIgnoreCase(h.name, "etag") and !std.mem.startsWith(u8, h.value, "W/")) {
                    h.value = std.fmt.allocPrint(a, "W/{s}", .{h.value}) catch h.value;
                }
            }
            list.appendAssumeCapacity(.{ .name = "content-encoding", .value = "gzip" });
            if (gzip.findHeader(list.items, "vary")) |v| {
                for (list.items) |*h| if (std.ascii.eqlIgnoreCase(h.name, "vary")) {
                    h.value = std.fmt.allocPrint(a, "{s}, Accept-Encoding", .{v}) catch v;
                };
            } else {
                list.appendAssumeCapacity(.{ .name = "vary", .value = "Accept-Encoding" });
            }
            resp.content_length = null;
        }
        resp.headers = list.items;
        d.vtable.sendHead(d.ptr, &resp);
    }

    /// Start compressing this response if it qualifies.
    fn startGzip(self: *Exchange, resp: *const Response, headers: []const Header) bool {
        if (self.req.isHead()) return false;
        if (resp.status < 200 or resp.status >= 300 or resp.status == 204 or resp.status == 206) return false;
        if (resp.content_length) |n| if (n < gzip.min_length) return false;
        if (gzip.findHeader(headers, "content-encoding") != null) return false;
        if (!gzip.compressible(gzip.findHeader(headers, "content-type"))) return false;
        if (!gzip.clientAccepts(self.req.get("accept-encoding"))) return false;
        if (self.worker.gzip_active >= gzip.max_active) return false;
        self.gz = gzip.Encoder.create(self.worker.alloc) catch return false;
        self.worker.gzip_active += 1;
        return true;
    }

    fn releaseGzip(self: *Exchange) void {
        const e = self.gz orelse return;
        e.destroy();
        self.gz = null;
        self.worker.gzip_active -= 1;
    }

    pub fn respondBody(self: *Exchange, data: []const u8) void {
        const d = self.down orelse return;
        if (self.gz) |e| {
            e.write(data) catch return self.respondAbort();
            const out = e.output();
            self.bytes_sent += out.len;
            if (out.len > 0) d.vtable.sendBody(d.ptr, out);
            e.consume();
            return;
        }
        self.bytes_sent += data.len;
        d.vtable.sendBody(d.ptr, data);
    }

    /// Response complete. Frees the exchange if no handler holds it.
    pub fn respondEnd(self: *Exchange) void {
        if (self.done) return;
        if (self.gz) |e| {
            if (self.down) |d| {
                e.finish() catch {
                    self.releaseGzip();
                    return self.respondAbort();
                };
                const out = e.output();
                self.bytes_sent += out.len;
                if (out.len > 0) d.vtable.sendBody(d.ptr, out);
            }
            self.releaseGzip();
        }
        self.done = true;
        self.logAccess();
        if (self.down) |d| {
            self.down = null;
            d.vtable.finish(d.ptr);
        }
        if (self.handler == .none) self.destroy();
    }

    /// End a response that already started, signalling failure to the client.
    /// Frees the exchange if no handler holds it.
    pub fn respondAbort(self: *Exchange) void {
        if (self.done) return;
        self.done = true;
        self.failed = true;
        self.logAccess();
        if (self.down) |d| {
            self.down = null;
            d.vtable.abort(d.ptr);
        }
        if (self.handler == .none) self.destroy();
    }

    pub fn downstreamBuffered(self: *const Exchange) usize {
        const d = self.down orelse return 0;
        return d.vtable.buffered(d.ptr);
    }

    pub fn pauseRequestBody(self: *Exchange, paused: bool) void {
        const d = self.down orelse return;
        d.vtable.setRequestBodyPaused(d.ptr, paused);
    }

    pub fn startTunnel(self: *Exchange) void {
        const d = self.down orelse return;
        d.vtable.startTunnel(d.ptr);
    }

    pub fn sendFixed(self: *Exchange, status: u16, content_type: []const u8, body: []const u8) void {
        const headers = [_]Header{.{ .name = "content-type", .value = content_type }};
        self.respondHead(&.{ .status = status, .headers = &headers, .content_length = body.len });
        if (!self.req.isHead()) self.respondBody(body);
        self.respondEnd();
    }

    /// A small HTML error page. If the response already started, the only
    /// honest signal left is an abort.
    pub fn sendError(self: *Exchange, status: u16) void {
        if (self.done) return;
        if (self.head_sent) return self.respondAbort();
        var buf: [256]u8 = undefined;
        const reason = common.reason(status);
        const body = std.fmt.bufPrint(&buf, "<html><head><title>{d} {s}</title></head><body><h1>{d} {s}</h1></body></html>\n", .{ status, reason, status, reason }) catch unreachable;
        self.sendFixed(status, "text/html; charset=utf-8", body);
    }

    /// Called by a handler once it holds nothing that refers to the exchange.
    /// Frees the exchange if the response is over.
    pub fn handlerReleased(self: *Exchange) void {
        self.handler = .none;
        if (self.done) self.destroy();
    }

    fn destroy(self: *Exchange) void {
        std.debug.assert(self.done and self.down == null and self.handler == .none);
        self.releaseGzip();
        self.arena_state.deinit();
        self.worker.alloc.destroy(self);
    }

    fn logAccess(self: *Exchange) void {
        if (!self.worker.cfg.access_log) return;
        var buf: [2048]u8 = undefined;
        const elapsed = self.worker.timers.now_ms - self.start_ms;
        const line = std.fmt.bufPrint(&buf, "{s} \"{s} {s} {s}\" {d} {d} {d}ms host={s}{s}{s}{s}\n", .{
            self.req.client_addr,
            self.req.method,
            if (self.req.target.len > 512) self.req.target[0..512] else self.req.target,
            self.req.protocol.text(),
            self.status,
            self.bytes_sent,
            elapsed,
            self.req.authority,
            if (self.upstream_addr != null) " upstream=" else "",
            self.upstream_addr orelse "",
            if (self.failed) " aborted" else "",
        }) catch return;
        self.worker.accessLog(line);
    }
};

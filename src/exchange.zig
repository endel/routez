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

/// URI changes a request may go through (rewrites that match the
/// locations again) before it is taken for a loop: nginx's limit.
const max_uri_changes = 10;
const gzip = @import("gzip.zig");
const encoding = @import("encoding.zig");
const vars = @import("http/vars.zig");
const access_log = @import("access_log.zig");
const timers = @import("timers.zig");
const logs = @import("logs.zig");
const log = std.log.scoped(.rewrite);
const access = @import("access.zig");
const guard = @import("guard.zig");
const tls = @import("net/tls.zig");
const client_cert = @import("net/client_cert.zig");
const htpasswd = @import("auth/htpasswd.zig");
const auth_pool = @import("auth/pool.zig");
const basic = @import("auth/basic.zig");
const regex = @import("regex.zig");
const realip = @import("realip.zig");
const socket = @import("net/socket.zig");

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
        /// `finish`, for a downstream that can tell when the response has
        /// gone out: true when some of it is still queued, and the
        /// downstream then calls `ex.onFlushed` once it is sent or lost.
        finishTracked: ?*const fn (*anyopaque, *Exchange) bool = null,
        /// Bytes of the current response queued and never handed to the
        /// socket, read before `abort` (which drops them).
        unsent: ?*const fn (*anyopaque) u64 = null,
        /// Response failed after it started; the client must see an error
        /// (connection or stream reset). The downstream detaches.
        abort: *const fn (*anyopaque) void,
        /// Response bytes queued but not yet sent.
        buffered: *const fn (*anyopaque) usize,
        setRequestBodyPaused: *const fn (*anyopaque, bool) void,
        /// After a 101 head: raw bytes in both directions from here on.
        startTunnel: *const fn (*anyopaque) void,
        /// Whether the body may go out as file ranges (`sendFile`).
        canSendFile: ?*const fn (*anyopaque) bool = null,
        /// Queue a range of a file as body bytes. Takes the range's hold
        /// whatever the answer.
        sendFile: ?*const fn (*anyopaque, socket.FileOut) FileSend = null,
        /// Hold output back (true) until released (false), so pieces
        /// produced in one callback leave in one send.
        cork: ?*const fn (*anyopaque, bool) void = null,
    };

    pub fn setCork(self: Downstream, on: bool) void {
        if (self.vtable.cork) |f| f(self.ptr, on);
    }
};

pub const FileSend = enum {
    sent,
    /// Not now: send this range as bytes.
    busy,
    /// Not for this response.
    unsupported,
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
    /// The client: the one a trusted proxy names, else the connection's.
    client_addr: []const u8,
    /// The client's IP (IPv4 mapped), keying per-client limits.
    client_ip: [16]u8,
    /// Where the request came from before `real_ip_header` was applied: the
    /// PROXY protocol's client or the TCP/QUIC peer. X-Forwarded-For gets it.
    hop_addr: []const u8,
    /// The TCP or QUIC peer (`$realip_remote_addr`).
    peer_addr: []const u8,

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
    /// The connection's client: the PROXY protocol's, else the peer.
    client_addr: []const u8,
    client_ip: [16]u8,
    /// The TCP peer, when the PROXY protocol named another client.
    peer_addr: ?[]const u8 = null,
    vhosts: *const router.VirtualHosts,
    /// The connection's client certificate; meaningful over TLS and QUIC.
    client_cert: tls.ClientCert = .{},
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
        static: *static.Transfer,
        proxy: *proxy.Proxy,
        /// Waiting for a verifier thread to check a password.
        auth: *auth_pool.Job,
    } = .none,

    status: u16 = 0,
    bytes_sent: u64 = 0,
    start_ms: i64,
    head_sent: bool = false,
    done: bool = false,
    /// Set when the response ended by abort rather than finish, or didn't
    /// all reach the socket.
    failed: bool = false,
    /// Finished, and waiting for the downstream's `onFlushed` to log.
    flushing: bool = false,
    /// Response bytes (head and framing included) that never reached the
    /// socket; `$body_bytes_sent` leaves them out.
    unsent: u64 = 0,
    /// For the downstream's queue of exchanges awaiting `onFlushed`.
    flush_next: ?*Exchange = null,
    flush_start: u64 = 0,
    flush_mark: u64 = 0,
    upstream_addr: ?[]const u8 = null,
    /// Set when this response is being gzip-compressed.
    gz: ?*gzip.Encoder = null,
    /// The location's `add_headers` and `proxy_set_headers` values with
    /// variables expanded; null when none has a variable.
    add_values: ?[]const []const u8 = null,
    set_values: ?[]const []const u8 = null,
    /// The verified client certificate, when the server asks for one and
    /// the connection's handshake ran under that server's policy.
    client_cert: ?*const vars.ClientCert = null,
    /// A TLS connection whose handshake ran under another server's client
    /// certificate policy (SNI named one server, Host another): 421.
    cert_misdirected: bool = false,
    /// Set once `auth_basic` accepted the user.
    remote_user: []const u8 = "",
    /// The user whose password a verifier thread is checking.
    pending_user: []const u8 = "",
    /// Groups of the last regex that matched, `$1`..`$9`.
    captures: regex.Captures = .{},
    /// A rewrite changed `req.path` or `req.query`; `req.target` is still
    /// what the client sent.
    rewritten: bool = false,

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
            // Only the access log reads it.
            .start_ms = if (worker.cfg.access_log) timers.nowMs() else 0,
        };
        errdefer ex.arena_state.deinit();
        const a = ex.arena_state.allocator();
        stats.inc(&stats.requests);
        if (init.protocol == .http3) stats.inc(&stats.requests_h3);

        const headers = try a.alloc(Header, init.headers.len);
        for (init.headers, headers) |src, *dst| {
            dst.* = .{ .name = try a.dupe(u8, src.name), .value = try a.dupe(u8, src.value) };
        }
        const hop_addr = try a.dupe(u8, init.client_addr);
        var client_addr = hop_addr;
        var client_ip = init.client_ip;
        if (realip.fromHeaders(&worker.shared.real_ip, init.client_ip, init.headers)) |ip| {
            var buf: [64]u8 = undefined;
            client_ip = ip;
            client_addr = try a.dupe(u8, socket.formatIpKey(ip, &buf));
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
            .client_addr = client_addr,
            .client_ip = client_ip,
            .hop_addr = hop_addr,
            .peer_addr = if (init.peer_addr) |p| try a.dupe(u8, p) else hop_addr,
        };
        // By transport: an HTTP/3 request may claim any :scheme.
        if (init.client_cert.secure) {
            if (worker.shared.guards.clientAuth(ex.server)) |want| {
                if (init.client_cert.auth != want) {
                    ex.cert_misdirected = true;
                } else if (init.client_cert.der) |der| {
                    // Verified in the handshake; this only formats it.
                    const info = client_cert.describe(a, der) catch null;
                    if (info) |i| {
                        const c = try a.create(vars.ClientCert);
                        c.* = .{ .s_dn = i.s_dn, .i_dn = i.i_dn, .serial = i.serial, .fingerprint = i.fingerprint };
                        ex.client_cert = c;
                    }
                }
            }
        }
        return ex;
    }

    pub fn arena(self: *Exchange) std.mem.Allocator {
        return self.arena_state.allocator();
    }

    /// Route and hand the request to its handler.
    pub fn start(self: *Exchange) void {
        if (self.req.path.len == 0) return self.sendError(400);
        // HTTP-01 validation comes over plain HTTP, ahead of any location.
        if (std.mem.eql(u8, self.req.scheme, "http")) {
            if (self.worker.shared.challenges) |ch| {
                if (ch.lookup(self.worker.io, self.arena(), self.req.path)) |key_auth| {
                    return self.sendFixed(200, "application/octet-stream", key_auth);
                }
            }
        }
        const loc = self.route() orelse return;
        self.add_values = self.expandAll(loc.add_headers) catch return self.sendError(400);
        self.location = loc;
        if (loc.limit_req) |lim| {
            if (!self.worker.allowRequest(self.server, loc, lim, self.req.client_ip)) {
                stats.inc(&stats.requests_limited);
                return self.sendRetryLater(429);
            }
        }
        const pol = self.worker.shared.guards.policy(loc);
        if (access.check(pol.rules, self.req.client_ip) == .deny) return self.sendError(403);
        if (self.cert_misdirected) return self.sendError(421);
        if (pol.require_client_cert and self.client_cert == null) return self.sendError(403);
        if (pol.auth) |auth| switch (self.checkPassword(auth)) {
            .ok => {},
            .denied => return self.sendUnauthorized(auth),
            .limited => return self.sendRetryLater(429),
            .busy => return self.sendRetryLater(503),
            .pending => {
                // Held in the downstream until the verdict: nothing to hand it to yet.
                self.pauseRequestBody(true);
                return;
            },
        };
        self.dispatch(loc);
    }

    /// The server's rewrites, then the location and its rewrites, matched
    /// again after each URI change. Null once a response has been sent.
    fn route(self: *Exchange) ?*const config.Location {
        switch (self.rewrite(self.server.rewrite, null)) {
            .responded => return null,
            .done, .stop, .restart => {},
        }
        var changes: u8 = 0;
        while (true) {
            const loc = router.matchLocation(self.server, self.req.path, self.matcher(), &self.captures) orelse {
                self.sendError(404);
                return null;
            };
            switch (self.rewrite(loc.rewrite, loc)) {
                .responded => return null,
                .done, .stop => return loc,
                .restart => {
                    changes += 1;
                    if (changes > max_uri_changes) {
                        log.warn("rewrite cycle: {s} changed {d} times, now {s}", .{ self.req.target, changes, self.req.path });
                        self.sendError(500);
                        return null;
                    }
                },
            }
        }
    }

    const Rewritten = enum {
        /// No rule changed the URI.
        done,
        /// `break`: stay in this location.
        stop,
        /// Match the locations again.
        restart,
        responded,
    };

    fn rewrite(self: *Exchange, rules: []const config.Rewrite, loc: ?*const config.Location) Rewritten {
        var changed = false;
        for (rules) |*rule| {
            var caps: regex.Captures = .{};
            if (!self.matcher().find(rule, self.req.path, &caps)) continue;
            self.captures = caps;
            const uri = self.rewriteUri(rule) catch {
                self.sendError(500);
                return .responded;
            };
            if (rule.redirects()) {
                if (loc) |l| {
                    self.add_values = self.expandAll(l.add_headers) catch null;
                    self.location = l;
                }
                self.sendRedirect(if (rule.flag == .permanent) 301 else 302, uri);
                return .responded;
            }
            if (uri.len == 0 or uri[0] != '/') {
                self.sendError(500);
                return .responded;
            }
            const buf = self.arena().alloc(u8, uri.len + 2) catch {
                self.sendError(500);
                return .responded;
            };
            // Groups are percent-encoded, so this decodes what the client sent once.
            const t = router.normalizeTarget(uri, buf) catch {
                self.sendError(400);
                return .responded;
            };
            self.req.path = t.path;
            self.req.query = t.query;
            self.rewritten = true;
            changed = true;
            switch (rule.flag) {
                .last => return .restart,
                .@"break" => return .stop,
                .none, .redirect, .permanent => {},
            }
        }
        return if (changed) .restart else .done;
    }

    /// `rule`'s replacement, expanded, with the query string handled as
    /// nginx does.
    fn rewriteUri(self: *Exchange, rule: *const config.Rewrite) ![]const u8 {
        var uri = try self.expand(rule.replacement);
        const keep_args = !std.mem.endsWith(u8, rule.replacement, "?");
        if (!keep_args) uri = uri[0 .. uri.len - 1];
        const args = self.req.query orelse return uri;
        if (!keep_args) return uri;
        const sep: u8 = if (std.mem.indexOfScalar(u8, uri, '?') != null) '&' else '?';
        return std.fmt.allocPrint(self.arena(), "{s}{c}{s}", .{ uri, sep, args });
    }

    fn sendRedirect(self: *Exchange, status: u16, location: []const u8) void {
        var buf: [256]u8 = undefined;
        const reason = common.reason(status);
        const body = std.fmt.bufPrint(&buf, "<html><head><title>{d} {s}</title></head><body><h1>{d} {s}</h1></body></html>\n", .{ status, reason, status, reason }) catch unreachable;
        const headers = [_]Header{ .{ .name = "location", .value = location }, .{ .name = "content-type", .value = "text/html; charset=utf-8" } };
        self.respondHead(&.{ .status = status, .headers = &headers, .content_length = body.len });
        if (!self.req.isHead()) self.respondBody(body);
        self.respondEnd();
    }

    /// Past every check: run the location's handler.
    fn dispatch(self: *Exchange, loc: *const config.Location) void {
        self.set_values = self.expandAll(loc.proxy_set_headers) catch return self.sendError(400);
        if (self.remote_user.len > 0) self.add_values = self.expandAll(loc.add_headers) catch return self.sendError(400);
        const max_body = self.worker.cfg.limits.max_body_bytes;
        if (max_body != 0 and (self.req.content_length orelse 0) > max_body) return self.sendError(413);

        if (loc.@"return") |ret| return self.sendReturn(ret);
        if (loc.stub_status) {
            var buf: [512]u8 = undefined;
            return self.sendFixed(200, "text/plain; charset=utf-8", stats.format(&buf, self.worker.quicConnectionCount()));
        }
        if (loc.metrics) return self.sendMetrics();
        if (loc.root) |root| return static.start(self, loc, root);
        if (loc.proxy_pass) |target| return proxy.start(self, loc, config.splitProxyPass(target).target);
        // webtransport_pass only means something to a CONNECT over HTTP/3.
        return self.sendError(404);
    }

    const PasswordCheck = enum { ok, denied, limited, busy, pending };

    fn checkPassword(self: *Exchange, auth: guard.Auth) PasswordCheck {
        var buf: [htpasswd.max_credentials]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        switch (basic.check(self.worker, auth, self.req.get("authorization"), self.req.client_ip, &buf, onPasswordChecked)) {
            .ok => |user| {
                self.remote_user = self.arena().dupe(u8, user) catch return .busy;
                return .ok;
            },
            .pending => |p| {
                p.job.ctx = self;
                self.handler = .{ .auth = p.job };
                // Out of memory here still leaves the verdict to come; it just logs no user.
                self.pending_user = self.arena().dupe(u8, p.user) catch "";
                return .pending;
            },
            .denied => return .denied,
            .limited => return .limited,
            .busy => return .busy,
        }
    }

    /// A verifier thread's verdict, on the worker's thread.
    fn onPasswordChecked(job: *auth_pool.Job) void {
        const self: *Exchange = @ptrCast(@alignCast(job.ctx.?));
        self.handler = .none;
        self.pauseRequestBody(false);
        const loc = self.location.?;
        if (!job.ok) return self.sendUnauthorized(self.worker.shared.guards.policy(loc).auth.?);
        self.remote_user = self.pending_user;
        self.dispatch(loc);
    }

    fn sendUnauthorized(self: *Exchange, auth: guard.Auth) void {
        const body = "<html><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1></body></html>\n";
        const headers = [_]Header{ .{ .name = "www-authenticate", .value = auth.challenge }, .{ .name = "content-type", .value = "text/html; charset=utf-8" } };
        self.respondHead(&.{ .status = 401, .headers = &headers, .content_length = body.len });
        if (!self.req.isHead()) self.respondBody(body);
        self.respondEnd();
    }

    pub fn sendRetryLater(self: *Exchange, status: u16) void {
        const headers = [_]Header{ .{ .name = "retry-after", .value = "1" }, .{ .name = "content-type", .value = "text/plain" } };
        self.respondHead(&.{ .status = status, .headers = &headers, .content_length = 0 });
        self.respondEnd();
    }

    // ---- downstream events ----

    pub fn onRequestBody(self: *Exchange, data: []const u8) void {
        stats.add(&stats.request_bytes, data.len);
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
            .none, .auth => {},
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
            self.finished();
        }
        switch (self.handler) {
            .static => {
                static.detach(self);
                self.destroy();
            },
            // Frees the exchange through handlerReleased once the upstream side is let go.
            .proxy => |p| p.onDownstreamGone(),
            .auth => |job| {
                // The verdict still arrives; nobody is there for it.
                job.ctx = null;
                self.handler = .none;
                self.destroy();
            },
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
        for (loc.add_headers, 0..) |h, i| {
            list.appendAssumeCapacity(.{ .name = h.name, .value = if (self.add_values) |v| v[i] else h.value });
        }
        if (loc.gzip and gzip.negotiable(resp.status, list.items)) {
            encoding.addVary(a, &list);
            if (self.startGzip(&resp)) {
                for (list.items) |*h| {
                    // The compressed body is a different representation.
                    if (std.ascii.eqlIgnoreCase(h.name, "etag") and !std.mem.startsWith(u8, h.value, "W/")) {
                        h.value = std.fmt.allocPrint(a, "W/{s}", .{h.value}) catch h.value;
                    }
                }
                list.appendAssumeCapacity(.{ .name = "content-encoding", .value = "gzip" });
                resp.content_length = null;
            }
        }
        resp.headers = list.items;
        d.vtable.sendHead(d.ptr, &resp);
    }

    /// Start compressing this negotiable response if the client takes gzip
    /// and it's worth it. HEAD gets the headers GET would, and no encoder.
    fn startGzip(self: *Exchange, resp: *const Response) bool {
        // A range of the compressed body isn't what the client asked for.
        if (resp.status == 206) return false;
        if (resp.content_length) |n| if (n < gzip.min_length) return false;
        if (!gzip.clientAccepts(self.req.get("accept-encoding"))) return false;
        if (self.req.isHead()) return true;
        self.gz = self.worker.gzip.acquire() orelse return false;
        return true;
    }

    fn releaseGzip(self: *Exchange) void {
        const e = self.gz orelse return;
        self.gz = null;
        self.worker.gzip.release(e);
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
        if (self.down) |d| {
            self.down = null;
            if (d.vtable.finishTracked) |f| {
                self.flushing = f(d.ptr, self);
            } else {
                d.vtable.finish(d.ptr);
            }
        }
        // Logged once sent, like nginx: a client gone meanwhile shows.
        if (self.flushing) return;
        self.finished();
        if (self.handler == .none) self.destroy();
    }

    /// The downstream sent the rest of a finished response (`unsent` 0), or
    /// lost `unsent` bytes of it. Frees the exchange if no handler holds it.
    pub fn onFlushed(self: *Exchange, unsent: u64) void {
        self.flushing = false;
        self.unsent = unsent;
        self.finished();
        if (self.handler == .none) self.destroy();
    }

    /// End a response that already started, signalling failure to the client.
    /// Frees the exchange if no handler holds it.
    pub fn respondAbort(self: *Exchange) void {
        if (self.done) return;
        self.done = true;
        self.failed = true;
        if (self.down) |d| {
            if (d.vtable.unsent) |u| self.unsent = u(d.ptr);
        }
        self.finished();
        if (self.down) |d| {
            self.down = null;
            d.vtable.abort(d.ptr);
        }
        if (self.handler == .none) self.destroy();
    }

    /// Whether the body may go out as file ranges: an untransformed body
    /// over a downstream that can sendfile.
    pub fn canSendFile(self: *const Exchange) bool {
        const d = self.down orelse return false;
        const can = d.vtable.canSendFile orelse return false;
        return self.gz == null and can(d.ptr);
    }

    /// Send a file range as body bytes; see `Downstream.VTable.sendFile`.
    pub fn respondFile(self: *Exchange, f: socket.FileOut) FileSend {
        const d = self.down orelse {
            f.release(f.hold);
            return .unsupported;
        };
        const send = d.vtable.sendFile orelse {
            f.release(f.hold);
            return .unsupported;
        };
        const r = send(d.ptr, f);
        if (r == .sent) self.bytes_sent += f.len;
        return r;
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

    fn matcher(self: *Exchange) router.Matcher {
        return .{ .routes = self.worker.shared.routes, .scratch = &self.worker.regex_scratch };
    }

    fn varRequest(self: *const Exchange) vars.Request {
        return .{
            .scheme = self.req.scheme,
            .authority = self.req.authority,
            .default_host = if (self.server.server_names.len > 0) self.server.server_names[0] else "",
            .target = self.req.target,
            .path = self.req.path,
            .query = self.req.query,
            .remote_addr = self.req.client_addr,
            .realip_remote_addr = self.req.peer_addr,
            .remote_user = self.remote_user,
            .client_cert = self.client_cert,
            .captures = &self.captures,
        };
    }

    /// Expand `template`'s variables for this request; InvalidValue when the
    /// result isn't a valid header value.
    pub fn expand(self: *Exchange, template: []const u8) error{ OutOfMemory, InvalidValue }![]const u8 {
        if (!vars.has(template)) return template;
        return vars.expand(self.arena(), template, self.varRequest());
    }

    fn expandAll(self: *Exchange, headers: []const config.HeaderKV) !?[]const []const u8 {
        for (headers) |h| {
            if (vars.has(h.value)) break;
        } else return null;
        const out = try self.arena().alloc([]const u8, headers.len);
        for (headers, out) |h, *v| v.* = try self.expand(h.value);
        return out;
    }

    /// The configured value of `proxy_set_headers[i]`, expanded.
    pub fn setHeaderValue(self: *const Exchange, i: usize) []const u8 {
        if (self.set_values) |v| return v[i];
        return self.location.?.proxy_set_headers[i].value;
    }

    fn sendReturn(self: *Exchange, ret: config.Location.Return) void {
        const location = ret.location orelse return self.sendFixed(ret.status, ret.content_type, ret.body);
        const value = self.expand(location) catch return self.sendError(400);
        const headers = [_]Header{ .{ .name = "location", .value = value }, .{ .name = "content-type", .value = ret.content_type } };
        self.respondHead(&.{ .status = ret.status, .headers = &headers, .content_length = ret.body.len });
        if (!self.req.isHead()) self.respondBody(ret.body);
        self.respondEnd();
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
        self.sendErrorWith(status, &.{});
    }

    /// `sendError` with up to three more headers.
    pub fn sendErrorWith(self: *Exchange, status: u16, extra: []const Header) void {
        if (self.done) return;
        if (self.head_sent) return self.respondAbort();
        var buf: [256]u8 = undefined;
        const reason = common.reason(status);
        const body = std.fmt.bufPrint(&buf, "<html><head><title>{d} {s}</title></head><body><h1>{d} {s}</h1></body></html>\n", .{ status, reason, status, reason }) catch unreachable;
        var headers: [4]Header = undefined;
        headers[0] = .{ .name = "content-type", .value = "text/html; charset=utf-8" };
        const n = @min(extra.len, headers.len - 1);
        @memcpy(headers[1..][0..n], extra[0..n]);
        self.respondHead(&.{ .status = status, .headers = headers[0 .. n + 1], .content_length = body.len });
        if (!self.req.isHead()) self.respondBody(body);
        self.respondEnd();
    }

    /// Called by a handler once it holds nothing that refers to the exchange.
    /// Frees the exchange if the response is over.
    pub fn handlerReleased(self: *Exchange) void {
        self.handler = .none;
        if (self.done and !self.flushing) self.destroy();
    }

    fn destroy(self: *Exchange) void {
        std.debug.assert(self.done and !self.flushing and self.down == null and self.handler == .none);
        self.releaseGzip();
        self.arena_state.deinit();
        self.worker.alloc.destroy(self);
    }

    fn sendMetrics(self: *Exchange) void {
        var out: std.Io.Writer.Allocating = .init(self.arena());
        self.worker.metrics(&out.writer) catch return self.sendError(500);
        self.sendFixed(200, "text/plain; version=0.0.4; charset=utf-8", out.written());
    }

    /// The response is over, sent or not: count it and log it.
    fn finished(self: *Exchange) void {
        if (self.unsent > 0) {
            self.failed = true;
            self.bytes_sent -|= self.unsent;
        }
        stats.response(self.req.protocol == .http3, self.status);
        stats.add(&stats.response_bytes, self.bytes_sent);
        if (!self.worker.cfg.access_log) return;
        const elapsed = timers.nowMs() - self.start_ms;
        switch (self.worker.shared.access_format) {
            .main => {},
            .template => |t| {
                const entry: access_log.Entry = .{
                    .req = self.varRequest(),
                    .method = self.req.method,
                    .protocol = self.req.protocol.text(),
                    .headers = self.req.headers,
                    .status = self.status,
                    .body_bytes = self.bytes_sent,
                    .elapsed_ms = elapsed,
                    .upstream_addr = self.upstream_addr,
                    .completed = !self.failed,
                    .now_ms = logs.realtimeMs(),
                };
                const line = access_log.render(t, self.arena(), &entry) catch return;
                return self.worker.accessLog(line);
            },
        }
        var buf: [2048]u8 = undefined;
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

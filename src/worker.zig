//! A worker thread: one libxev loop running every listener, client
//! connection and upstream connection it owns. Workers share nothing but the
//! config; each binds its listeners with SO_REUSEPORT.
const std = @import("std");
const builtin = @import("builtin");
const quic = @import("quic");
const xev = quic.event_loop.Xev;
const config = @import("config.zig");
const common = @import("http/common.zig");
const router = @import("router.zig");
const timers = @import("timers.zig");
const upstream = @import("upstream.zig");
const tls = @import("net/tls.zig");
const acme = @import("acme.zig");
const H1Conn = @import("http1/server_conn.zig").Conn;
const stats = @import("stats.zig");
const socket = @import("net/socket.zig");
const UdpProxy = @import("udp_proxy.zig").UdpProxy;
const h3_server = @import("h3/server.zig");
pub const H3Listener = h3_server.Listener(.h3);
/// A QUIC listener that also relays WebTransport sessions.
pub const WtListener = h3_server.Listener(.webtransport);

pub const QuicListener = union(enum) {
    h3: *H3Listener,
    wt: *WtListener,

    fn address(self: QuicListener) []const u8 {
        return switch (self) {
            inline else => |l| l.address,
        };
    }
    fn port(self: QuicListener) u16 {
        return switch (self) {
            inline else => |l| l.port,
        };
    }
    fn addServer(self: QuicListener, srv: *const config.Server) !void {
        switch (self) {
            inline else => |l| try l.addServer(srv),
        }
    }
    fn start(self: QuicListener) void {
        switch (self) {
            inline else => |l| l.start(),
        }
    }
    fn stop(self: QuicListener) void {
        switch (self) {
            inline else => |l| l.stop(),
        }
    }
    fn drain(self: QuicListener) void {
        switch (self) {
            inline else => |l| l.server.drain(),
        }
    }
    fn isDrained(self: QuicListener) bool {
        return switch (self) {
            inline else => |l| l.server.isDrained(),
        };
    }
    fn isStopped(self: QuicListener) bool {
        return switch (self) {
            inline else => |l| l.server.isStopped(),
        };
    }
    fn deinit(self: QuicListener) void {
        switch (self) {
            inline else => |l| l.server.deinit(),
        }
    }
    fn liveConnections(self: QuicListener) usize {
        return switch (self) {
            inline else => |l| l.liveConnections(),
        };
    }
};

const log = std.log.scoped(.worker);

/// How long a stopping worker waits for in-flight requests.
const drain_timeout_ms = 10_000;

pub const Worker = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    cfg: *const config.Config,
    shared: *const Shared,
    id: usize,
    loop: xev.Loop,
    timers: timers.Timers,
    date: common.DateCache = .{},

    listeners: std.ArrayListUnmanaged(*Listener) = .empty,
    udp_proxies: std.ArrayListUnmanaged(*UdpProxy) = .empty,
    quic_listeners: std.ArrayListUnmanaged(QuicListener) = .empty,
    groups: std.ArrayListUnmanaged(*upstream.Group) = .empty,
    group_names: std.ArrayListUnmanaged([]const u8) = .empty,

    conns_head: ?*H1Conn = null,
    conn_count: u32 = 0,
    per_ip: std.AutoHashMapUnmanaged([16]u8, u32) = .empty,
    /// limit_req token buckets, keyed by location and client address.
    rate_buckets: std.AutoHashMapUnmanaged(u64, RateBucket) = .empty,
    rate_sweep_ms: i64 = 0,
    gzip_active: u32 = 0,

    stop_async: xev.Async,
    stop_c: xev.Completion = .{},
    stopping: bool = false,
    /// Drain is over; waiting for QUIC servers to get off the loop.
    finishing: bool = false,
    finish_started_ms: i64 = 0,
    stop_deadline: timers.Deadline = .{ .callback = onDrainTimeout },

    /// Built once in main and shared read-only by all workers.
    pub const Shared = struct {
        tls_listeners: []const TlsListener,
        /// Pending HTTP-01 challenges, answered on plain-HTTP listeners.
        challenges: ?*acme.Challenges = null,

        pub const TlsListener = struct { address: []const u8, port: u16, cfg: *const tls.ServerConfig };

        pub fn tlsFor(self: *const Shared, address: []const u8, port: u16) ?*const tls.ServerConfig {
            for (self.tls_listeners) |l| {
                if (l.port == port and std.mem.eql(u8, l.address, address)) return l.cfg;
            }
            return null;
        }
    };

    pub fn create(alloc: std.mem.Allocator, io: std.Io, cfg: *const config.Config, shared: *const Shared, id: usize) !*Worker {
        const w = try alloc.create(Worker);
        errdefer alloc.destroy(w);
        w.* = .{
            .alloc = alloc,
            .io = io,
            .cfg = cfg,
            .shared = shared,
            .id = id,
            .loop = try xev.Loop.init(.{}),
            .timers = undefined,
            .stop_async = try xev.Async.init(),
        };
        w.timers = try timers.Timers.init(&w.loop);
        w.timers.on_tick = onTick;
        try w.setupUpstreams();
        try w.setupListeners();
        try w.setupQuicListeners();
        for (cfg.udp_proxies) |*u| try w.udp_proxies.append(alloc, try UdpProxy.create(w, u));
        return w;
    }

    pub fn destroy(self: *Worker) void {
        for (self.groups.items) |g| g.deinit();
        self.groups.deinit(self.alloc);
        self.group_names.deinit(self.alloc);
        for (self.listeners.items) |l| l.destroy();
        self.listeners.deinit(self.alloc);
        self.timers.deinit();
        self.stop_async.deinit();
        self.loop.deinit();
        self.alloc.destroy(self);
    }

    fn setupUpstreams(self: *Worker) !void {
        for (self.cfg.upstreams) |up| {
            try self.addGroup(up.name, up);
        }
        // proxy_pass / webtransport_pass to a literal host:port gets an implicit group.
        for (self.cfg.servers) |srv| {
            for (srv.locations) |loc| {
                const target = loc.proxy_pass orelse loc.webtransport_pass orelse continue;
                try self.addImplicitGroup(target, loc.webtransport_pass != null);
            }
        }
        for (self.cfg.udp_proxies) |u| try self.addImplicitGroup(u.proxy_pass, false);
    }

    fn addImplicitGroup(self: *Worker, target: []const u8, h3: bool) !void {
        if (self.findGroup(target) != null) return;
        const servers = try self.alloc.alloc([]const u8, 1);
        servers[0] = target;
        try self.addGroup(target, .{ .name = target, .servers = servers, .h3 = h3 });
    }

    fn addGroup(self: *Worker, name: []const u8, up: config.Upstream) !void {
        const g = try upstream.Group.init(self, up);
        try self.groups.append(self.alloc, g);
        try self.group_names.append(self.alloc, name);
    }

    pub fn findGroup(self: *Worker, name: []const u8) ?*upstream.Group {
        for (self.group_names.items, self.groups.items) |n, g| {
            if (std.mem.eql(u8, n, name)) return g;
        }
        return null;
    }

    fn setupListeners(self: *Worker) !void {
        // One TCP listener per address:port, shared by the servers naming it.
        for (self.cfg.servers) |*srv| {
            for (srv.listen) |l| {
                if (!l.tcp) continue;
                if (self.findListener(l.address, l.port)) |existing| {
                    if ((existing.tls_config != null) != l.tls) {
                        log.err("listen {s}:{d}: servers disagree on tls", .{ l.address, l.port });
                        return error.InvalidConfig;
                    }
                    try existing.addServer(srv);
                    continue;
                }
                const tc: ?*const tls.ServerConfig = if (l.tls) self.shared.tlsFor(l.address, l.port) orelse return error.InvalidConfig else null;
                const lst = try Listener.create(self, l, tc);
                try lst.addServer(srv);
                try self.listeners.append(self.alloc, lst);
            }
        }
    }

    fn setupQuicListeners(self: *Worker) !void {
        for (self.cfg.servers) |*srv| {
            for (srv.listen) |l| {
                if (!l.quic) continue;
                if (self.findQuicListener(l.address, l.port)) |existing| {
                    try existing.addServer(srv);
                    continue;
                }
                const tc = self.shared.tlsFor(l.address, l.port) orelse return error.InvalidConfig;
                const ql: QuicListener = if (self.wantsWebTransport(l.address, l.port))
                    .{ .wt = try WtListener.create(self, l, tc) }
                else
                    .{ .h3 = try H3Listener.create(self, l, tc) };
                try ql.addServer(srv);
                try self.quic_listeners.append(self.alloc, ql);
            }
        }
    }

    /// Whether any server on this QUIC port relays WebTransport.
    fn wantsWebTransport(self: *Worker, address: []const u8, port: u16) bool {
        for (self.cfg.servers) |srv| {
            const here = for (srv.listen) |l| {
                if (l.quic and l.port == port and std.mem.eql(u8, l.address, address)) break true;
            } else false;
            if (!here) continue;
            for (srv.locations) |loc| if (loc.webtransport_pass != null) return true;
        }
        return false;
    }

    fn findQuicListener(self: *Worker, address: []const u8, port: u16) ?QuicListener {
        for (self.quic_listeners.items) |l| {
            if (l.port() == port and std.mem.eql(u8, l.address(), address)) return l;
        }
        return null;
    }

    fn quicConnections(self: *Worker) usize {
        var n: usize = 0;
        for (self.quic_listeners.items) |l| n += l.liveConnections();
        return n;
    }

    fn findListener(self: *Worker, address: []const u8, port: u16) ?*Listener {
        for (self.listeners.items) |l| {
            if (l.port == port and std.mem.eql(u8, l.address, address)) return l;
        }
        return null;
    }

    pub fn run(self: *Worker) !void {
        self.timers.start();
        self.stop_async.wait(&self.loop, &self.stop_c, Worker, self, onStopSignal);
        for (self.listeners.items) |l| l.start();
        for (self.udp_proxies.items) |u| u.start();
        for (self.quic_listeners.items) |q| q.start();
        try self.loop.run(.until_done);
        log.info("worker {d} stopped", .{self.id});
    }

    /// Ask the worker to drain and exit. Safe from any thread or a signal handler.
    pub fn requestStop(self: *Worker) void {
        self.stop_async.notify() catch {};
    }

    fn onStopSignal(ud: ?*Worker, _: *xev.Loop, _: *xev.Completion, r: xev.Async.WaitError!void) xev.CallbackAction {
        _ = r catch {};
        const self = ud.?;
        if (self.stopping) return .disarm;
        self.stopping = true;
        log.info("worker {d} draining {d} connection(s)", .{ self.id, self.conn_count });
        // Stop taking new clients here, so they reach a newer generation.
        for (self.listeners.items) |l| l.stopAccepting();
        for (self.udp_proxies.items) |u| u.stop();
        var c = self.conns_head;
        while (c) |conn| {
            c = conn.next;
            conn.closeIfIdle();
        }
        for (self.groups.items) |g| {
            for (g.peers) |*p| p.closeIdle();
        }
        // GOAWAY: in-flight HTTP/3 requests finish, new ones go elsewhere.
        for (self.quic_listeners.items) |q| q.drain();
        self.timers.set(&self.stop_deadline, drain_timeout_ms);
        return .disarm;
    }

    fn onTick(t: *timers.Timers) void {
        const self: *Worker = @fieldParentPtr("timers", t);
        self.sweepRateBuckets();
        if (self.finishing) return self.pollFinish();
        if (self.stopping and self.conn_count == 0 and self.quicDrained()) self.finishStop();
    }

    fn onDrainTimeout(d: *timers.Deadline) void {
        const self: *Worker = @fieldParentPtr("stop_deadline", d);
        log.warn("worker {d}: {d} connection(s) still open at shutdown", .{ self.id, self.conn_count });
        self.finishStop();
    }

    fn quicDrained(self: *Worker) bool {
        for (self.quic_listeners.items) |q| if (!q.isDrained()) return false;
        return true;
    }

    fn finishStop(self: *Worker) void {
        if (self.finishing) return;
        self.finishing = true;
        self.finish_started_ms = self.timers.now_ms;
        self.timers.clear(&self.stop_deadline);
        // Anything still open after the drain window is closed outright.
        for (self.quic_listeners.items) |q| q.stop();
        self.pollFinish();
    }

    /// Exit the loop once the QUIC servers are off it, or after a second.
    fn pollFinish(self: *Worker) void {
        const all_stopped = for (self.quic_listeners.items) |q| {
            if (!q.isStopped()) break false;
        } else true;
        if (!all_stopped and self.timers.now_ms - self.finish_started_ms < 1000) return;
        if (all_stopped) {
            // Closes their sockets; nothing of theirs is left on the loop.
            for (self.quic_listeners.items) |q| q.deinit();
            self.quic_listeners.clearRetainingCapacity();
        }
        // Client connections that outlived the drain: close their sockets
        // so a reload doesn't leak them. Their memory goes with the process.
        var c = self.conns_head;
        while (c) |conn| : (c = conn.next) _ = std.c.close(conn.sock.fd());
        self.timers.stop();
        self.loop.stop();
    }

    pub fn addConn(self: *Worker, c: *H1Conn) void {
        c.prev = null;
        c.next = self.conns_head;
        if (self.conns_head) |h| h.prev = c;
        self.conns_head = c;
        self.conn_count += 1;
        stats.inc(&stats.active_tcp);
    }

    pub fn removeConn(self: *Worker, c: *H1Conn) void {
        if (c.prev) |p| p.next = c.next else self.conns_head = c.next;
        if (c.next) |n| n.prev = c.prev;
        self.conn_count -= 1;
        stats.dec(&stats.active_tcp);
        if (c.ip_key) |k| self.releaseIp(k);
    }

    /// Count a connection against its client address; false when over the limit.
    fn acquireIp(self: *Worker, key: [16]u8) bool {
        const limit = self.cfg.limits.max_connections_per_ip;
        const gop = self.per_ip.getOrPut(self.alloc, key) catch return true;
        if (!gop.found_existing) gop.value_ptr.* = 0;
        if (gop.value_ptr.* >= limit) return false;
        gop.value_ptr.* += 1;
        return true;
    }

    fn releaseIp(self: *Worker, key: [16]u8) void {
        const v = self.per_ip.getPtr(key) orelse return;
        v.* -= 1;
        if (v.* == 0) _ = self.per_ip.remove(key);
    }

    const RateBucket = struct { milli_tokens: i64, last_ms: i64 };

    /// Token bucket check for `limit_req`: `rate` tokens per second, holding
    /// at most `burst + 1`. Counted per worker.
    pub fn allowRequest(self: *Worker, loc: *const config.Location, lim: config.Location.LimitReq, client: []const u8) bool {
        const now = self.timers.now_ms;
        const key = std.hash.Wyhash.hash(@intFromPtr(loc), client);
        const cap: i64 = (@as(i64, lim.burst) + 1) * 1000;
        const gop = self.rate_buckets.getOrPut(self.alloc, key) catch return true;
        if (!gop.found_existing) gop.value_ptr.* = .{ .milli_tokens = cap, .last_ms = now };
        const b = gop.value_ptr;
        // `rate` tokens per second is `rate` milli-tokens per millisecond.
        b.milli_tokens = @min(cap, b.milli_tokens + (now - b.last_ms) * @as(i64, lim.rate));
        b.last_ms = now;
        if (b.milli_tokens < 1000) return false;
        b.milli_tokens -= 1000;
        return true;
    }

    /// Forget buckets idle long enough to have refilled.
    fn sweepRateBuckets(self: *Worker) void {
        const now = self.timers.now_ms;
        if (now - self.rate_sweep_ms < 10_000) return;
        self.rate_sweep_ms = now;
        var stale: std.ArrayListUnmanaged(u64) = .empty;
        defer stale.deinit(self.alloc);
        var it = self.rate_buckets.iterator();
        while (it.next()) |e| {
            if (now - e.value_ptr.last_ms > 60_000) stale.append(self.alloc, e.key_ptr.*) catch break;
        }
        for (stale.items) |k| _ = self.rate_buckets.remove(k);
    }

    /// Live QUIC connections on this worker.
    pub fn quicConnectionCount(self: *Worker) usize {
        return self.quicConnections();
    }

    pub fn dateHeader(self: *Worker) []const u8 {
        return self.date.get(quic.sys.realtimeSeconds());
    }

    pub fn accessLog(self: *Worker, line: []const u8) void {
        _ = self;
        // One write(2) per line keeps lines from different workers whole.
        _ = std.c.write(2, line.ptr, line.len);
    }
};

pub const Listener = struct {
    worker: *Worker,
    address: []const u8,
    port: u16,
    tcp: xev.TCP,
    accept_c: xev.Completion = .{},
    servers: std.ArrayListUnmanaged(*const config.Server) = .empty,
    vhosts: router.VirtualHosts = .{ .servers = &.{} },
    tls_config: ?*const tls.ServerConfig,
    alt_svc: ?[]const u8 = null,
    alt_svc_buf: [48]u8 = undefined,
    retry: timers.Deadline = .{ .callback = onRetryAccept },
    cancel_c: xev.Completion = .{},
    accepting: bool = false,
    closed: bool = false,

    fn create(w: *Worker, l: config.Listen, tc: ?*const tls.ServerConfig) !*Listener {
        const addr = try std.Io.net.IpAddress.parse(l.address, l.port);
        const tcp = try xev.TCP.init(addr);
        errdefer _ = std.c.close(tcp.fd);
        const one: c_int = 1;
        // Every worker binds the same port; the kernel spreads connections.
        _ = std.c.setsockopt(tcp.fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, std.mem.asBytes(&one), @sizeOf(c_int));
        try tcp.bind(addr);
        try tcp.listen(1024);

        const self = try w.alloc.create(Listener);
        self.* = .{ .worker = w, .address = l.address, .port = l.port, .tcp = tcp, .tls_config = tc };
        if (l.quic) {
            self.alt_svc = std.fmt.bufPrint(&self.alt_svc_buf, "h3=\":{d}\"; ma=86400", .{l.port}) catch null;
        }
        if (w.id == 0) log.info("listening on {s}:{d}{s}", .{ l.address, l.port, if (tc != null) " (tls)" else "" });
        return self;
    }

    fn addServer(self: *Listener, srv: *const config.Server) !void {
        try self.servers.append(self.worker.alloc, srv);
        self.vhosts = .{ .servers = self.servers.items };
        for (srv.listen) |l| {
            if (l.port == self.port and l.quic and self.alt_svc == null) {
                self.alt_svc = std.fmt.bufPrint(&self.alt_svc_buf, "h3=\":{d}\"; ma=86400", .{l.port}) catch null;
            }
        }
    }

    fn destroy(self: *Listener) void {
        if (!self.closed) _ = std.c.close(self.tcp.fd);
        self.servers.deinit(self.worker.alloc);
        self.worker.alloc.destroy(self);
    }

    fn start(self: *Listener) void {
        if (self.closed) return;
        self.accepting = true;
        self.tcp.accept(&self.worker.loop, &self.accept_c, Listener, self, onAccept);
    }

    /// Stop accepting and close the listening socket, so the kernel sends
    /// new connections to the other listeners on this port.
    fn stopAccepting(self: *Listener) void {
        if (self.closed) return;
        self.closed = true;
        self.worker.timers.clear(&self.retry);
        // Serve what is already queued: closing a listener resets the
        // connections in its backlog, which a reload shouldn't do.
        while (socket.acceptNow(self.tcp.fd)) |fd| {
            stats.inc(&stats.accepted);
            _ = H1Conn.create(self.worker, self, xev.TCP.initFd(fd)) catch {
                _ = std.c.close(fd);
            };
        }
        if (!self.accepting) {
            _ = std.c.close(self.tcp.fd);
            return;
        }
        self.cancel_c = .{
            .op = .{ .cancel = .{ .c = &self.accept_c } },
            .userdata = self,
            .callback = onAcceptCancelled,
        };
        self.worker.loop.add(&self.cancel_c);
    }

    fn onAcceptCancelled(ud: ?*anyopaque, _: *xev.Loop, _: *xev.Completion, _: xev.Result) xev.CallbackAction {
        const self: *Listener = @ptrCast(@alignCast(ud.?));
        // libxev's epoll backend accepts on a dup of the fd and doesn't close
        // it when the accept is cancelled; left open, it keeps the socket in
        // the SO_REUSEPORT group, taking connections nobody will accept.
        const flags = &self.accept_c.flags;
        if (comptime @hasField(@TypeOf(flags.*), "dup_fd")) {
            if (flags.dup and flags.dup_fd > 0) {
                _ = std.c.close(flags.dup_fd);
                flags.dup_fd = 0;
            }
        }
        _ = std.c.close(self.tcp.fd);
        return .disarm;
    }

    fn onAccept(ud: ?*Listener, _: *xev.Loop, _: *xev.Completion, r: xev.AcceptError!xev.TCP) xev.CallbackAction {
        const self = ud.?;
        const w = self.worker;
        if (self.closed) {
            self.accepting = false;
            if (r) |tcp| _ = std.c.close(tcp.fd) else |_| {}
            return .disarm;
        }
        const tcp = r catch |err| {
            self.accepting = false;
            // Usually fd exhaustion; retry shortly instead of spinning.
            log.warn("accept on :{d}: {s}", .{ self.port, @errorName(err) });
            w.timers.set(&self.retry, 100);
            return .disarm;
        };
        if (w.stopping or w.conn_count >= w.cfg.limits.max_connections) {
            _ = std.c.close(tcp.fd);
            return .rearm;
        }
        stats.inc(&stats.accepted);
        var ip_key: ?[16]u8 = null;
        if (w.cfg.limits.max_connections_per_ip != 0) {
            if (socket.peerIpKey(tcp.fd)) |k| {
                if (!w.acquireIp(k)) {
                    stats.inc(&stats.refused_per_ip);
                    _ = std.c.close(tcp.fd);
                    return .rearm;
                }
                ip_key = k;
            }
        }
        const conn = H1Conn.create(w, self, tcp) catch |err| {
            log.warn("connection setup: {s}", .{@errorName(err)});
            if (ip_key) |k| w.releaseIp(k);
            _ = std.c.close(tcp.fd);
            return .rearm;
        };
        conn.ip_key = ip_key;
        return .rearm;
    }

    fn onRetryAccept(d: *timers.Deadline) void {
        const self: *Listener = @fieldParentPtr("retry", d);
        self.start();
    }
};

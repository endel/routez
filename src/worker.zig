//! A worker thread: one libxev loop running every listener, client
//! connection and upstream connection it owns. Workers share the config and
//! a few process-wide tables; each binds its listeners with SO_REUSEPORT.
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
const steering = @import("steering.zig");
const socket = @import("net/socket.zig");
const UdpProxy = @import("udp_proxy.zig").UdpProxy;
const Tunnel = @import("tcp_proxy.zig").Tunnel;
const h3_server = @import("h3/server.zig");
const access_log = @import("access_log.zig");
const gzip = @import("gzip.zig");
const logs = @import("logs.zig");
const privileges = @import("privileges.zig");
const client_limits = @import("client_limits.zig");
const guard = @import("guard.zig");
const auth_pool = @import("auth/pool.zig");
const file_io = @import("file_io.zig");
const ofc = @import("open_file_cache.zig");
const regex = @import("regex.zig");
const realip = @import("realip.zig");
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
    fn inject(self: QuicListener, d: *const steering.Datagram) void {
        switch (self) {
            inline else => |l| l.server.injectDatagram(d.bytes, d.peer, d.local, d.ecn),
        }
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
    /// Connections accepted since the server started.
    fn accepted(self: QuicListener) u64 {
        return switch (self) {
            inline else => |l| l.server.conn_mgr.next_entry_id - 1,
        };
    }
    fn socket(self: QuicListener) std.posix.socket_t {
        return switch (self) {
            inline else => |l| l.server.sockfd,
        };
    }
};

/// The generation a reload replaces, whose listening sockets the new one
/// takes over.
pub const Predecessor = struct {
    /// The old worker at this one's index, if there was one.
    same: ?*const Worker = null,
    all: []const *Worker = &.{},

    /// The TCP listener to share: the same worker's, else, once root is
    /// dropped and a fresh bind would fail, any worker's.
    fn tcp(self: Predecessor, address: []const u8, port: u16) ?*const Listener {
        if (self.same) |w| if (w.findListenerConst(address, port)) |l| return l;
        if (!privileges.dropped) return null;
        for (self.all) |w| if (w.findListenerConst(address, port)) |l| return l;
        return null;
    }

    /// A dup of the QUIC socket to take over; only once root is dropped,
    /// before which a fresh one joins the SO_REUSEPORT group.
    fn quic(self: Predecessor, address: []const u8, port: u16) !?std.posix.socket_t {
        if (!privileges.dropped) return null;
        if (self.same) |w| if (w.findQuicListenerConst(address, port)) |q| return try dupFd(q.socket());
        for (self.all) |w| if (w.findQuicListenerConst(address, port)) |q| return try dupFd(q.socket());
        return null;
    }

    fn udp(self: Predecessor, address: []const u8, port: u16) !?std.posix.socket_t {
        if (!privileges.dropped) return null;
        if (self.same) |w| if (w.findUdpProxyConst(address, port)) |u| return try dupFd(u.fd);
        for (self.all) |w| if (w.findUdpProxyConst(address, port)) |u| return try dupFd(u.fd);
        return null;
    }
};

/// A client connection the worker owns: an HTTP connection or a layer-4
/// tunnel. Both are counted against `max_connections`, drained at a stop and
/// released from the per-IP table, so what the accept path tracks lives here
/// once instead of once per kind.
pub const Client = struct {
    next: ?*Client = null,
    prev: ?*Client = null,
    /// Set when counted against a per-IP limit.
    ip_key: ?[16]u8 = null,
    kind: enum { http, tunnel },

    /// Close if nothing is in flight; `force` closes mid-request ones too.
    /// A tunnel has no request boundary to wait for, so it just goes.
    pub fn closeIfIdle(self: *Client, force: bool) void {
        switch (self.kind) {
            .http => H1Conn.fromClient(self).closeIfIdle(force),
            .tunnel => Tunnel.fromClient(self).abort(),
        }
    }

    /// Outlived the drain: close the sockets so a reload doesn't leak them.
    /// The memory goes with the process.
    pub fn abandon(self: *Client) void {
        switch (self.kind) {
            .http => {
                const conn = H1Conn.fromClient(self);
                conn.abandonFlushes();
                _ = std.c.close(conn.sock.fd());
            },
            .tunnel => Tunnel.fromClient(self).abandon(),
        }
    }
};

pub fn dupFd(fd: std.posix.fd_t) !std.posix.fd_t {
    const d = std.c.fcntl(fd, std.c.F.DUPFD_CLOEXEC, @as(c_int, 0));
    if (d < 0) return error.DupFailed;
    return d;
}

/// Log a failed bind, explaining the one a dropped root can't do.
pub fn bindFailed(what: []const u8, address: []const u8, port: u16, err: anyerror) void {
    if (privileges.dropped and port < 1024 and err == error.AccessDenied) {
        log.err("{s} {s}:{d}: ports below 1024 need root, which the server gave up at start; restart it to add this one", .{ what, address, port });
    } else {
        log.err("{s} {s}:{d}: {s}", .{ what, address, port, @errorName(err) });
    }
}

const log = std.log.scoped(.worker);

/// How often a worker may say it is refusing connections at the cap.
const max_conn_log_interval_ms = 60_000;

/// How long a stopping worker waits for in-flight requests.
const drain_timeout_ms = 10_000;
/// How long a stopping worker waits for the first request on a connection.
const fresh_grace_ms = 1_000;

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

    conns_head: ?*Client = null,
    conn_count: u32 = 0,
    /// When the max_connections warning last went out, to throttle it.
    max_conn_logged_ms: i64 = std.math.minInt(i64) / 2,
    gzip: gzip.Pool,
    /// For regex locations and rewrites; sized for this generation's largest.
    regex_scratch: regex.Scratch = .{},

    stop_async: xev.Async,
    /// QUIC datagrams other workers received for our connections.
    inbox: steering.Inbox,
    /// Password checks the verifier threads finished for our requests.
    auth_inbox: auth_pool.Inbox,
    /// File work the I/O threads finished for our requests.
    file_inbox: file_io.Inbox,
    /// Static files looked up lately.
    files: ofc.Cache,
    inbox_drain: std.ArrayListUnmanaged(steering.Datagram) = .empty,
    stop_c: xev.Completion = .{},
    stopping: bool = false,
    /// Drain is over; waiting for QUIC servers to get off the loop.
    finishing: bool = false,
    finish_started_ms: i64 = 0,
    stop_deadline: timers.Deadline = .{ .callback = onDrainTimeout },
    stop_started_ms: i64 = 0,
    /// Connections that never sent a request have been closed.
    fresh_closed: bool = false,
    /// QUIC counts last added to the process-wide stats.
    quic_accepted_pub: u64 = 0,
    quic_active_pub: u64 = 0,

    /// Built once in main and shared read-only by all workers.
    pub const Shared = struct {
        tls_listeners: []const TlsListener,
        /// Pending HTTP-01 challenges, answered on plain-HTTP listeners.
        challenges: ?*acme.Challenges = null,
        /// Same in every worker and generation: a Retry token or stateless
        /// reset from one worker must hold up at any other.
        quic_keys: QuicKeys,
        /// Trust anchors for each verified TLS upstream, and QUIC ones with a
        /// client certificate, by upstream name.
        upstream_cas: []const UpstreamCa = &.{},
        /// Client certificates presented to upstreams, by upstream name.
        upstream_certs: []const UpstreamCert = &.{},
        /// Proxies trusted to name the client.
        real_ip: realip.Trust = .{},
        access_format: access_log.Format = .main,
        /// Where access log lines go.
        access_fd: std.posix.fd_t = 2,
        /// Per-client limits, shared with every other generation; null
        /// until a config uses them.
        clients: ?*client_limits.Table = null,
        /// IP rules, user files and client-certificate policies.
        guards: *const guard.Guards,
        /// Compiled regexes of locations and rewrites.
        routes: *const router.Routes,
        /// bcrypt verifier threads, shared with every other generation;
        /// null until a config uses `auth_basic`.
        auth_pool: ?*auth_pool.Pool = null,
        /// File I/O threads, shared with every other generation; null
        /// until a config serves files.
        file_pool: ?*file_io.Pool = null,
        /// `open_file_cache.max` within the descriptor budget.
        open_file_cache_max: u32 = 0,
        /// `limits.max_connections` within the descriptor budget, per worker.
        max_connections: u32 = 0,

        pub const QuicKeys = struct { retry: [16]u8, reset: [16]u8 };

        pub const TlsListener = struct { address: []const u8, port: u16, cfg: *const tls.ServerConfig };

        pub const UpstreamCa = struct { upstream: []const u8, bundle: *const std.crypto.Certificate.Bundle };

        pub const UpstreamCert = struct { upstream: []const u8, cert: *const quic.tls13.ServerCertificate };

        pub fn upstreamCert(self: *const Shared, upstream_name: []const u8) ?quic.tls13.ServerCertificate {
            for (self.upstream_certs) |u| {
                if (std.mem.eql(u8, u.upstream, upstream_name)) return u.cert.*;
            }
            return null;
        }

        pub fn upstreamCa(self: *const Shared, upstream_name: []const u8) ?*const std.crypto.Certificate.Bundle {
            for (self.upstream_cas) |u| {
                if (std.mem.eql(u8, u.upstream, upstream_name)) return u.bundle;
            }
            return null;
        }

        pub fn tlsFor(self: *const Shared, address: []const u8, port: u16) ?*const tls.ServerConfig {
            for (self.tls_listeners) |l| {
                if (l.port == port and std.mem.eql(u8, l.address, address)) return l.cfg;
            }
            return null;
        }
    };

    /// On a reload, `prev` has the sockets to share rather than reopen.
    pub fn create(alloc: std.mem.Allocator, io: std.Io, cfg: *const config.Config, shared: *const Shared, id: usize, prev: Predecessor) !*Worker {
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
            .inbox = try steering.Inbox.init(io, alloc),
            .auth_inbox = try auth_pool.Inbox.init(io),
            .file_inbox = try file_io.Inbox.init(io),
            .files = .init(alloc, .{
                .max = shared.open_file_cache_max,
                .valid_ms = cfg.open_file_cache.valid_ms,
                .inactive_ms = cfg.open_file_cache.inactive_ms,
            }),
            .gzip = .{ .alloc = alloc },
        };
        w.timers = try timers.Timers.init(&w.loop);
        w.timers.on_tick = onTick;
        w.regex_scratch = try regex.Scratch.init(alloc, shared.routes.max_states);
        errdefer w.regex_scratch.deinit(alloc);
        errdefer w.closeSockets();
        try w.setupUpstreams();
        try w.setupListeners(prev);
        try w.setupTcpProxies(prev);
        try w.setupQuicListeners(prev);
        for (cfg.udp_proxies) |*u| try w.udp_proxies.append(alloc, try UdpProxy.create(w, u, try prev.udp(u.address, u.port)));
        return w;
    }

    pub fn destroy(self: *Worker) void {
        self.regex_scratch.deinit(self.alloc);
        for (self.groups.items) |g| g.deinit();
        self.groups.deinit(self.alloc);
        self.group_names.deinit(self.alloc);
        self.closeSockets();
        self.listeners.deinit(self.alloc);
        self.timers.deinit();
        self.stop_async.deinit();
        self.auth_inbox.wake.deinit();
        self.file_inbox.wake.deinit();
        self.loop.deinit();
        self.alloc.destroy(self);
    }

    /// For a worker that never ran: close what it bound or took over, so a
    /// failed reload leaves nothing in an SO_REUSEPORT group.
    fn closeSockets(self: *Worker) void {
        for (self.listeners.items) |l| l.destroy();
        self.listeners.clearRetainingCapacity();
        for (self.quic_listeners.items) |q| q.deinit();
        self.quic_listeners.clearRetainingCapacity();
        for (self.udp_proxies.items) |u| _ = std.c.close(u.fd);
        self.udp_proxies.clearRetainingCapacity();
    }

    fn setupUpstreams(self: *Worker) !void {
        for (self.cfg.upstreams) |up| {
            try self.addGroup(up.name, up);
        }
        // proxy_pass / webtransport_pass to a literal host:port gets an implicit group.
        for (self.cfg.servers) |srv| {
            for (srv.locations) |loc| {
                const target = if (loc.proxy_pass) |p| config.splitProxyPass(p).target else loc.webtransport_pass orelse continue;
                try self.addImplicitGroup(target, loc.webtransport_pass != null);
            }
        }
        for (self.cfg.udp_proxies) |u| try self.addImplicitGroup(u.proxy_pass, false);
        for (self.cfg.tcp_proxies) |t| try self.addImplicitGroup(t.proxy_pass, false);
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

    fn setupListeners(self: *Worker, prev: Predecessor) !void {
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
                const lst = try Listener.create(self, l, tc, null, prev.tcp(l.address, l.port));
                try lst.addServer(srv);
                try self.listeners.append(self.alloc, lst);
            }
        }
    }

    fn setupTcpProxies(self: *Worker, prev: Predecessor) !void {
        for (self.cfg.tcp_proxies) |*t| {
            if (self.findListener(t.address, t.port) != null) {
                log.err("tcp_proxy {s}:{d}: already listening there", .{ t.address, t.port });
                return error.InvalidConfig;
            }
            const group = self.findGroup(t.proxy_pass) orelse return error.UnknownUpstream;
            const l: config.Listen = .{ .address = t.address, .port = t.port };
            const l4: Listener.L4 = .{ .cfg = t, .group = group };
            try self.listeners.append(self.alloc, try Listener.create(self, l, null, l4, prev.tcp(t.address, t.port)));
        }
    }

    fn setupQuicListeners(self: *Worker, prev: Predecessor) !void {
        for (self.cfg.servers) |*srv| {
            for (srv.listen) |l| {
                if (!l.quic) continue;
                if (self.findQuicListener(l.address, l.port)) |existing| {
                    try existing.addServer(srv);
                    continue;
                }
                const tc = self.shared.tlsFor(l.address, l.port) orelse return error.InvalidConfig;
                const sock = try prev.quic(l.address, l.port);
                const ql: QuicListener = if (self.wantsWebTransport(l.address, l.port))
                    .{ .wt = try WtListener.create(self, l, tc, sock) }
                else
                    .{ .h3 = try H3Listener.create(self, l, tc, sock) };
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

    fn findQuicListenerConst(self: *const Worker, address: []const u8, port: u16) ?QuicListener {
        for (self.quic_listeners.items) |l| {
            if (l.port() == port and std.mem.eql(u8, l.address(), address)) return l;
        }
        return null;
    }

    fn findUdpProxyConst(self: *const Worker, address: []const u8, port: u16) ?*const UdpProxy {
        for (self.udp_proxies.items) |u| {
            if (u.cfg.port == port and std.mem.eql(u8, u.cfg.address, address)) return u;
        }
        return null;
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

    fn findListenerConst(self: *const Worker, address: []const u8, port: u16) ?*const Listener {
        for (self.listeners.items) |l| {
            if (l.port == port and std.mem.eql(u8, l.address, address)) return l;
        }
        return null;
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
        self.inbox.wake.wait(&self.loop, &self.inbox.wake_c, Worker, self, onInbox);
        self.auth_inbox.wake.wait(&self.loop, &self.auth_inbox.wake_c, Worker, self, onAuthInbox);
        self.file_inbox.wake.wait(&self.loop, &self.file_inbox.wake_c, Worker, self, onFileInbox);
        steering.registry.register(self.io, self.alloc, steering.serverId(self.id), &self.inbox) catch {};
        defer steering.registry.unregister(self.io, steering.serverId(self.id));
        for (self.listeners.items) |l| l.start();
        for (self.udp_proxies.items) |u| u.start();
        for (self.quic_listeners.items) |q| q.start();
        try self.loop.run(.until_done);
        self.files.deinit();
        self.gzip.deinit();
        log.info("worker {d} stopped", .{self.id});
    }

    fn onInbox(ud: ?*Worker, _: *xev.Loop, _: *xev.Completion, r: xev.Async.WaitError!void) xev.CallbackAction {
        _ = r catch {};
        const self = ud.?;
        self.inbox_drain.clearRetainingCapacity();
        self.inbox.drain(&self.inbox_drain);
        for (self.inbox_drain.items) |*d| {
            stats.inc(&stats.quic_steered);
            const port = std.mem.bigToNative(u16, @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&d.local))).port);
            for (self.quic_listeners.items) |q| {
                if (q.port() == port) {
                    q.inject(d);
                    break;
                }
            }
            self.alloc.free(d.bytes);
        }
        return .rearm;
    }

    fn onAuthInbox(ud: ?*Worker, _: *xev.Loop, _: *xev.Completion, r: xev.Async.WaitError!void) xev.CallbackAction {
        _ = r catch {};
        const self = ud.?;
        self.auth_inbox.drain(self.alloc);
        return .rearm;
    }

    fn onFileInbox(ud: ?*Worker, _: *xev.Loop, _: *xev.Completion, r: xev.Async.WaitError!void) xev.CallbackAction {
        _ = r catch {};
        ud.?.file_inbox.drain();
        return .rearm;
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
            conn.closeIfIdle(false);
        }
        for (self.groups.items) |g| {
            for (g.peers) |*p| p.closeIdle();
        }
        // GOAWAY: in-flight HTTP/3 requests finish, new ones go elsewhere.
        for (self.quic_listeners.items) |q| q.drain();
        self.stop_started_ms = self.timers.now_ms;
        self.timers.set(&self.stop_deadline, drain_timeout_ms);
        return .disarm;
    }

    fn onTick(t: *timers.Timers) void {
        const self: *Worker = @fieldParentPtr("timers", t);
        if (self.shared.clients) |tbl| tbl.sweepStep(self.io, quic.sys.nanoTimestamp());
        self.files.sweep(self.timers.now_ms);
        self.publishQuicStats();
        for (self.quic_listeners.items) |q| switch (q) {
            .wt => |l| l.relay.checkPaused(),
            .h3 => {},
        };
        if (self.finishing) return self.pollFinish();
        if (self.stopping and !self.fresh_closed and self.timers.now_ms - self.stop_started_ms >= fresh_grace_ms) {
            // A connection that stays silent mustn't hold up the stop.
            self.fresh_closed = true;
            var c = self.conns_head;
            while (c) |conn| {
                c = conn.next;
                conn.closeIfIdle(true);
            }
        }
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
            self.publishQuicStats();
            // Closes their sockets; nothing of theirs is left on the loop.
            for (self.quic_listeners.items) |q| q.deinit();
            self.quic_listeners.clearRetainingCapacity();
        }
        var c = self.conns_head;
        while (c) |conn| : (c = conn.next) {
            conn.abandon();
            if (conn.ip_key) |k| self.releaseIp(k);
            conn.ip_key = null;
        }
        _ = stats.active_quic.fetchSub(self.quic_active_pub, .monotonic);
        self.quic_active_pub = 0;
        self.timers.stop();
        self.loop.stop();
    }

    /// Bring the process-wide QUIC counts up to date with this worker's.
    fn publishQuicStats(self: *Worker) void {
        var accepted: u64 = 0;
        var active: u64 = 0;
        for (self.quic_listeners.items) |q| {
            accepted += q.accepted();
            active += q.liveConnections();
        }
        if (accepted > self.quic_accepted_pub) {
            stats.add(&stats.accepted_quic, accepted - self.quic_accepted_pub);
            self.quic_accepted_pub = accepted;
        }
        if (active > self.quic_active_pub) {
            stats.add(&stats.active_quic, active - self.quic_active_pub);
        } else {
            _ = stats.active_quic.fetchSub(self.quic_active_pub - active, .monotonic);
        }
        self.quic_active_pub = active;
    }

    /// Prometheus metrics; upstream servers as this worker's config has them.
    pub fn metrics(self: *Worker, w: *std.Io.Writer) !void {
        var views: std.ArrayListUnmanaged(stats.UpstreamView) = .empty;
        defer views.deinit(self.alloc);
        for (self.groups.items) |g| for (g.peers) |*p| {
            try views.append(self.alloc, .{ .stats = p.stats, .health_checked = g.cfg.health != null });
        };
        try stats.prometheus(w, views.items, self.shared.clients);
    }

    pub fn addClient(self: *Worker, c: *Client) void {
        c.prev = null;
        c.next = self.conns_head;
        if (self.conns_head) |h| h.prev = c;
        self.conns_head = c;
        self.conn_count += 1;
        stats.inc(&stats.active_tcp);
    }

    pub fn removeClient(self: *Worker, c: *Client) void {
        if (c.prev) |p| p.next = c.next else self.conns_head = c.next;
        if (c.next) |n| n.prev = c.prev;
        self.conn_count -= 1;
        stats.dec(&stats.active_tcp);
        if (c.ip_key) |k| self.releaseIp(k);
    }

    /// Count a connection against its client address, process-wide. A
    /// trusted proxy isn't: it speaks for many clients.
    pub fn admitIp(self: *Worker, key: [16]u8) client_limits.Table.Admit {
        if (self.cfg.limits.max_connections_per_ip == 0 or self.shared.real_ip.trusted(key)) return .untracked;
        const t = self.shared.clients orelse return .untracked;
        return t.acquireConn(self.io, key, self.cfg.limits.max_connections_per_ip, quic.sys.nanoTimestamp());
    }

    fn releaseIp(self: *Worker, key: [16]u8) void {
        if (self.shared.clients) |t| t.releaseConn(self.io, key);
    }

    /// `limit_req` for one request, counted across all workers.
    pub fn allowRequest(self: *Worker, srv: *const config.Server, loc: *const config.Location, lim: config.Location.LimitReq, client: [16]u8) bool {
        const t = self.shared.clients orelse return true;
        return t.allowRequest(self.io, client, client_limits.zoneId(srv, loc), lim.rate, lim.burst, quic.sys.nanoTimestamp());
    }

    /// Live QUIC connections on this worker.
    pub fn quicConnectionCount(self: *Worker) usize {
        return self.quicConnections();
    }

    pub fn dateHeader(self: *Worker) []const u8 {
        return self.date.get(quic.sys.realtimeSeconds());
    }

    pub fn accessLog(self: *Worker, line: []const u8) void {
        // O_APPEND and one write(2) per line keep lines from different
        // workers whole.
        logs.writeAll(self.shared.access_fd, line);
    }
};

pub const Listener = struct {
    pub const L4 = struct { cfg: *const config.TcpProxy, group: *upstream.Group };

    worker: *Worker,
    address: []const u8,
    port: u16,
    tcp: xev.TCP,
    accept_c: xev.Completion = .{},
    servers: std.ArrayListUnmanaged(*const config.Server) = .empty,
    vhosts: router.VirtualHosts = .{ .servers = &.{} },
    /// Set on a `tcp_proxies` listener: accepted sockets become layer-4
    /// tunnels instead of HTTP connections.
    l4: ?L4,
    tls_config: ?*const tls.ServerConfig,
    /// Connections open with a PROXY protocol header.
    proxy_protocol: bool,
    alt_svc: ?[]const u8 = null,
    alt_svc_buf: [48]u8 = undefined,
    retry: timers.Deadline = .{ .callback = onRetryAccept },
    cancel_c: xev.Completion = .{},
    accepting: bool = false,
    accept_errors: u8 = 0,
    closed: bool = false,

    /// With `inherit` (the same listener in the worker being replaced),
    /// share its socket: closing a listening socket resets the connections
    /// queued on it, and a SYN racing the close is refused.
    fn create(w: *Worker, l: config.Listen, tc: ?*const tls.ServerConfig, l4: ?L4, inherit: ?*const Listener) !*Listener {
        const tcp = if (inherit) |old| xev.TCP.initFd(try dupFd(old.tcp.fd)) else openListener(l) catch |err| {
            bindFailed("listen", l.address, l.port, err);
            return err;
        };
        errdefer _ = std.c.close(tcp.fd);

        const self = try w.alloc.create(Listener);
        self.* = .{ .worker = w, .address = l.address, .port = l.port, .tcp = tcp, .tls_config = tc, .l4 = l4, .proxy_protocol = l.proxy_protocol };
        if (l.quic) {
            self.alt_svc = std.fmt.bufPrint(&self.alt_svc_buf, "h3=\":{d}\"; ma=86400", .{l.port}) catch null;
        }
        if (w.id == 0) log.info("listening on {s}:{d}{s}", .{ l.address, l.port, if (l4 != null) " (tcp proxy)" else if (tc != null) " (tls)" else "" });
        return self;
    }

    fn openListener(l: config.Listen) !xev.TCP {
        const addr = try std.Io.net.IpAddress.parse(l.address, l.port);
        const tcp = try xev.TCP.init(addr);
        errdefer _ = std.c.close(tcp.fd);
        const one: c_int = 1;
        // Every worker binds the same port; the kernel spreads connections.
        _ = std.c.setsockopt(tcp.fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, std.mem.asBytes(&one), @sizeOf(c_int));
        try tcp.bind(addr);
        // The kernel clamps this to net.core.somaxconn, which is where
        // operators tune the accept queue.
        try tcp.listen(std.math.maxInt(u16));
        return tcp;
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

    /// Stop accepting and close our fd for the listening socket: the new
    /// generation's dup keeps a shared socket open, and an unshared one
    /// leaves the SO_REUSEPORT group.
    fn stopAccepting(self: *Listener) void {
        if (self.closed) return;
        self.closed = true;
        self.worker.timers.clear(&self.retry);
        // Serve what is already queued: closing an unshared listener resets
        // the connections in its backlog.
        while (socket.acceptNow(self.tcp.fd)) |fd| self.serve(xev.TCP.initFd(fd));
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
        if (self.closed) {
            if (r) |tcp| {
                self.serve(tcp);
                return .rearm;
            } else |_| {}
            // kqueue reports the cancel here (Canceled). epoll doesn't, and
            // disarming would close the dup'd fd the queued cancel then
            // deletes from epoll: EBADF, a panic, or someone else's fd.
            return if (xev.backend == .epoll) .rearm else .disarm;
        }
        const tcp = r catch |err| {
            // Another loop sharing the socket (a reload) took the connection:
            // EAGAIN, which libxev's epoll backend reports as `Unknown`.
            // Only a streak means fd exhaustion; then back off, not spin.
            self.accept_errors +|= 1;
            if (self.accept_errors < 8) return .rearm;
            self.accept_errors = 0;
            self.accepting = false;
            log.warn("accept on :{d}: {s}", .{ self.port, @errorName(err) });
            self.worker.timers.set(&self.retry, 100);
            return .disarm;
        };
        self.accept_errors = 0;
        self.serve(tcp);
        return .rearm;
    }

    fn serve(self: *Listener, tcp: xev.TCP) void {
        const w = self.worker;
        if (w.conn_count >= w.shared.max_connections) {
            stats.inc(&stats.refused_max_connections);
            // At most once a minute per worker: the counter carries volume.
            if (w.timers.now_ms - w.max_conn_logged_ms >= max_conn_log_interval_ms) {
                w.max_conn_logged_ms = w.timers.now_ms;
                log.warn("worker {d} at limits.max_connections ({d} per worker): refusing connections", .{ w.id, w.shared.max_connections });
            }
            _ = std.c.close(tcp.fd);
            return;
        }
        stats.inc(&stats.accepted);
        // libxev's epoll accept leaves the socket blocking, and a direct
        // send or sendfile into a full socket would stall the whole loop.
        if (xev.backend == .epoll) socket.setNonBlocking(tcp.fd);
        var ip_key: ?[16]u8 = null;
        if (self.proxy_protocol) {
            // Counted per IP once the header names the client.
            const peer = socket.peerIpKey(tcp.fd);
            if (peer == null or !w.shared.real_ip.trusted(peer.?)) {
                stats.inc(&stats.refused_proxy_protocol);
                _ = std.c.close(tcp.fd);
                return;
            }
        } else if (w.cfg.limits.max_connections_per_ip != 0) {
            if (socket.peerIpKey(tcp.fd)) |k| switch (w.admitIp(k)) {
                .counted => ip_key = k,
                .untracked => {},
                .refused => {
                    stats.inc(&stats.refused_per_ip);
                    _ = std.c.close(tcp.fd);
                    return;
                },
            };
        }
        if (self.l4) |l4| {
            const tunnel = Tunnel.create(w, l4.cfg, l4.group, tcp) catch |err| {
                if (err != error.NoPeer) log.warn("tunnel setup: {s}", .{@errorName(err)});
                if (ip_key) |k| w.releaseIp(k);
                _ = std.c.close(tcp.fd);
                return;
            };
            tunnel.link.ip_key = ip_key;
            return;
        }
        const conn = H1Conn.create(w, self, tcp) catch |err| {
            log.warn("connection setup: {s}", .{@errorName(err)});
            if (ip_key) |k| w.releaseIp(k);
            _ = std.c.close(tcp.fd);
            return;
        };
        conn.client.ip_key = ip_key;
    }

    fn onRetryAccept(d: *timers.Deadline) void {
        const self: *Listener = @fieldParentPtr("retry", d);
        self.start();
    }
};

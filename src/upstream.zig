//! Upstream groups for one worker: peers, pooled keep-alive connections,
//! load balancing, passive failure tracking and active health checks.
//!
//! State is per worker (no locks), so with N workers each keeps its own pool
//! and health view, and health probes run N times per interval.
const std = @import("std");
const quic = @import("quic");
const xev = quic.event_loop.Xev;
const config = @import("config.zig");
const addr = @import("net/addr.zig");
const socket = @import("net/socket.zig");
const timers = @import("timers.zig");
const parser = @import("http1/parser.zig");
const Worker = @import("worker.zig").Worker;
const Proxy = @import("handlers/proxy.zig").Proxy;

const log = std.log.scoped(.upstream);

/// How long an idle pooled connection is kept.
const idle_timeout_ms = 60_000;

pub const Group = struct {
    worker: *Worker,
    cfg: config.Upstream,
    peers: []Peer,
    rr: usize = 0,
    health_tick: timers.Deadline = .{ .callback = onHealthTick },

    pub fn init(worker: *Worker, cfg: config.Upstream) !*Group {
        const g = try worker.alloc.create(Group);
        errdefer worker.alloc.destroy(g);
        g.* = .{ .worker = worker, .cfg = cfg, .peers = try worker.alloc.alloc(Peer, cfg.servers.len) };
        for (cfg.servers, g.peers) |text, *p| {
            const hp = config.parseHostPort(text) catch unreachable; // validated at load
            const ip = addr.resolve(hp.host, hp.port) catch |err| {
                log.err("upstream '{s}': cannot resolve {s}: {s}", .{ cfg.name, text, @errorName(err) });
                return err;
            };
            p.* = .{ .group = g, .addr = ip, .label = text, .host = hp.host };
        }
        if (cfg.health != null) worker.timers.set(&g.health_tick, 0);
        return g;
    }

    pub fn deinit(self: *Group) void {
        self.worker.timers.clear(&self.health_tick);
        for (self.peers) |*p| p.closeIdle();
        self.worker.alloc.free(self.peers);
        self.worker.alloc.destroy(self);
    }

    /// Choose a peer, skipping `tried`. When every candidate is marked down by
    /// passive checks, fall back to one of them rather than fail outright;
    /// peers failing active health checks are never chosen.
    pub fn pick(self: *Group, client_addr: []const u8, tried: []const *Peer) ?*Peer {
        const now = self.worker.timers.now_ms;
        if (self.choose(client_addr, tried, now, false)) |p| return p;
        return self.choose(client_addr, tried, now, true);
    }

    fn choose(self: *Group, client_addr: []const u8, tried: []const *Peer, now: i64, ignore_passive: bool) ?*Peer {
        const n = self.peers.len;
        const eligible = struct {
            fn f(p: *Peer, t: []const *Peer, now_: i64, ignore: bool) bool {
                for (t) |x| if (x == p) return false;
                if (!p.health_ok) return false;
                return ignore or p.down_until <= now_;
            }
        }.f;
        switch (self.cfg.balance) {
            .round_robin => {
                for (0..n) |i| {
                    const p = &self.peers[(self.rr + i) % n];
                    if (eligible(p, tried, now, ignore_passive)) {
                        self.rr = (self.rr + i + 1) % n;
                        return p;
                    }
                }
            },
            .least_conn => {
                var best: ?*Peer = null;
                for (0..n) |i| {
                    const p = &self.peers[(self.rr + i) % n];
                    if (!eligible(p, tried, now, ignore_passive)) continue;
                    if (best == null or p.active < best.?.active) best = p;
                }
                if (best != null) self.rr = (self.rr + 1) % n;
                return best;
            },
            .ip_hash => {
                const start = std.hash.Wyhash.hash(0, client_addr) % n;
                for (0..n) |i| {
                    const p = &self.peers[(start + i) % n];
                    if (eligible(p, tried, now, ignore_passive)) return p;
                }
            },
        }
        return null;
    }

    fn onHealthTick(d: *timers.Deadline) void {
        const self: *Group = @fieldParentPtr("health_tick", d);
        const h = self.cfg.health.?;
        for (self.peers) |*p| {
            if (p.probe == null) Probe.start(p, h) catch |err| log.warn("health probe for {s}: {s}", .{ p.label, @errorName(err) });
        }
        self.worker.timers.set(&self.health_tick, h.interval_ms);
    }
};

pub const Peer = struct {
    group: *Group,
    addr: std.Io.net.IpAddress,
    label: []const u8,
    host: []const u8,
    /// Connections serving a request right now (including connecting ones).
    active: u32 = 0,
    idle_head: ?*UpConn = null,
    idle_count: u16 = 0,
    fails: u16 = 0,
    down_until: i64 = 0,
    health_ok: bool = true,
    health_streak: u16 = 0,
    probe: ?*Probe = null,

    pub fn recordFailure(self: *Peer) void {
        self.fails += 1;
        if (self.fails >= self.group.cfg.max_fails) {
            self.fails = 0;
            self.down_until = self.group.worker.timers.now_ms + self.group.cfg.fail_timeout_ms;
            log.warn("upstream {s} marked down for {d}ms", .{ self.label, self.group.cfg.fail_timeout_ms });
        }
    }

    pub fn recordSuccess(self: *Peer) void {
        self.fails = 0;
    }

    /// Take a pooled connection or open a new one, bound to `user`.
    pub fn acquire(self: *Peer, user: *Proxy) !*UpConn {
        self.active += 1;
        errdefer self.active -= 1;
        while (self.idle_head) |c| {
            self.unlinkIdle(c);
            if (!c.sock.isOpen()) continue;
            c.user = user;
            c.state = .busy;
            c.reused = true;
            c.peer.group.worker.timers.clear(&c.idle_deadline);
            return c;
        }
        const w = self.group.worker;
        const c = try w.alloc.create(UpConn);
        c.* = .{ .peer = self, .sock = undefined, .user = user };
        c.sock.connect(c, &w.loop, &w.timers, w.alloc, self.addr) catch |err| {
            w.alloc.destroy(c);
            return err;
        };
        return c;
    }

    /// Give a connection back. Only keep it if the response was fully read
    /// and the request fully sent, so the next user starts on a clean stream.
    pub fn release(self: *Peer, c: *UpConn, reusable: bool) void {
        self.active -= 1;
        c.user = null;
        if (!reusable or !c.sock.isOpen() or self.idle_count >= self.group.cfg.keepalive or self.group.worker.stopping) {
            c.state = .closing;
            c.sock.abort();
            return;
        }
        c.state = .idle;
        c.idle_next = self.idle_head;
        c.idle_prev = null;
        if (self.idle_head) |h| h.idle_prev = c;
        self.idle_head = c;
        self.idle_count += 1;
        // Keep a read armed so an upstream close is noticed while idle.
        c.sock.resumeRead();
        c.sock.startReading();
        self.group.worker.timers.set(&c.idle_deadline, idle_timeout_ms);
    }

    fn unlinkIdle(self: *Peer, c: *UpConn) void {
        if (c.state != .idle) return;
        if (c.idle_prev) |p| p.idle_next = c.idle_next else self.idle_head = c.idle_next;
        if (c.idle_next) |n| n.idle_prev = c.idle_prev;
        c.idle_next = null;
        c.idle_prev = null;
        c.state = .busy;
        self.idle_count -= 1;
    }

    fn healthResult(self: *Peer, ok: bool) void {
        const h = self.group.cfg.health orelse return;
        if (ok == self.health_ok) {
            self.health_streak = 0;
            return;
        }
        self.health_streak += 1;
        const needed = if (ok) h.rise else h.fall;
        if (self.health_streak >= needed) {
            self.health_ok = ok;
            self.health_streak = 0;
            log.info("upstream {s} is {s}", .{ self.label, if (ok) "healthy" else "unhealthy" });
            if (ok) {
                // A passing check outranks an older passive failure streak.
                self.down_until = 0;
                self.fails = 0;
            } else {
                self.closeIdle();
            }
        }
    }

    pub fn closeIdle(self: *Peer) void {
        while (self.idle_head) |c| {
            self.unlinkIdle(c);
            c.state = .closing;
            c.peer.group.worker.timers.clear(&c.idle_deadline);
            c.sock.abort();
        }
    }
};

/// One HTTP/1.1 connection to a peer, pooled between requests.
pub const UpConn = struct {
    peer: *Peer,
    sock: socket.Socket(UpConn),
    user: ?*Proxy,
    state: enum { busy, idle, closing } = .busy,
    reused: bool = false,
    idle_next: ?*UpConn = null,
    idle_prev: ?*UpConn = null,
    idle_deadline: timers.Deadline = .{ .callback = onIdleTimeout },

    pub fn onSocketConnect(self: *UpConn, err: ?anyerror) void {
        if (self.user) |u| u.onUpstreamConnected(err);
    }

    pub fn onSocketData(self: *UpConn, data: []const u8) void {
        if (self.user) |u| return u.onUpstreamData(data);
        // Bytes on an idle connection are a protocol error; drop it.
        self.dropIdle();
    }

    pub fn onSocketEof(self: *UpConn) void {
        if (self.user) |u| return u.onUpstreamEof();
        self.dropIdle();
    }

    pub fn onSocketWritable(self: *UpConn) void {
        if (self.user) |u| u.onUpstreamWritable();
    }

    pub fn onSocketClosed(self: *UpConn) void {
        std.debug.assert(self.user == null);
        self.peer.unlinkIdle(self);
        const w = self.peer.group.worker;
        w.timers.clear(&self.idle_deadline);
        w.alloc.destroy(self);
    }

    fn dropIdle(self: *UpConn) void {
        self.peer.unlinkIdle(self);
        self.state = .closing;
        self.peer.group.worker.timers.clear(&self.idle_deadline);
        self.sock.abort();
    }

    fn onIdleTimeout(d: *timers.Deadline) void {
        const self: *UpConn = @fieldParentPtr("idle_deadline", d);
        if (self.state == .idle) self.dropIdle();
    }
};

/// An active health check: `GET path` over a fresh connection, judged by
/// the status line alone.
pub const Probe = struct {
    peer: *Peer,
    sock: socket.Socket(Probe),
    deadline: timers.Deadline = .{ .callback = onTimeout },
    in: std.ArrayListUnmanaged(u8) = .empty,
    finished: bool = false,

    fn start(peer: *Peer, h: config.Upstream.Health) !void {
        const w = peer.group.worker;
        const p = try w.alloc.create(Probe);
        p.* = .{ .peer = peer, .sock = undefined };
        p.sock.connect(p, &w.loop, &w.timers, w.alloc, peer.addr) catch |err| {
            w.alloc.destroy(p);
            peer.healthResult(false);
            return err;
        };
        peer.probe = p;
        var buf: [1024]u8 = undefined;
        const req = std.fmt.bufPrint(&buf, "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: routez-health\r\nConnection: close\r\n\r\n", .{ h.path, peer.host }) catch "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
        p.sock.write(req);
        w.timers.set(&p.deadline, h.timeout_ms);
    }

    fn done(self: *Probe, ok: bool) void {
        if (self.finished) return;
        self.finished = true;
        self.peer.probe = null;
        self.peer.healthResult(ok);
        self.peer.group.worker.timers.clear(&self.deadline);
        self.sock.abort();
    }

    pub fn onSocketConnect(self: *Probe, err: ?anyerror) void {
        if (err != null) self.done(false);
    }

    pub fn onSocketData(self: *Probe, data: []const u8) void {
        const alloc = self.peer.group.worker.alloc;
        self.in.appendSlice(alloc, data) catch return self.done(false);
        const line_end = std.mem.indexOf(u8, self.in.items, "\r\n") orelse {
            if (self.in.items.len > 1024) self.done(false);
            return;
        };
        const line = self.in.items[0..line_end];
        if (line.len < 12 or !std.mem.startsWith(u8, line, "HTTP/1.")) return self.done(false);
        const status = std.fmt.parseInt(u16, line[9..12], 10) catch return self.done(false);
        const h = self.peer.group.cfg.health.?;
        const ok = if (h.expect_status) |want| status == want else status >= 200 and status < 400;
        self.done(ok);
    }

    pub fn onSocketEof(self: *Probe) void {
        self.done(false);
    }

    pub fn onSocketWritable(_: *Probe) void {}

    pub fn onSocketClosed(self: *Probe) void {
        const w = self.peer.group.worker;
        if (!self.finished) {
            self.finished = true;
            self.peer.probe = null;
        }
        w.timers.clear(&self.deadline);
        self.in.deinit(w.alloc);
        w.alloc.destroy(self);
    }

    fn onTimeout(d: *timers.Deadline) void {
        const self: *Probe = @fieldParentPtr("deadline", d);
        self.done(false);
    }
};

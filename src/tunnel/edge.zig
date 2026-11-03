//! The edge's half of `routez tunnel`: agents' sessions, and the streams
//! that carry the HTTP proxy's upstream connections down to them.
//!
//! An agent opens a WebTransport session on a `tunnel_accept` location and
//! claims a name. A request a `tunnel_pass` location takes for that name
//! goes through the ordinary proxy (`handlers/proxy.zig`) to a one-peer
//! upstream group whose connections are socketpairs (`upstream.UpConn`).
//! The far end of each comes here, through the registry, to the worker
//! holding the session, which opens a stream to the agent and pipes the two
//! together (`pipe.zig`). The agent connects each stream to its local server.
//!
//! Known gap: a socketpair has no reset, so a local server resetting its
//! connection reaches the proxy as a plain close. A body read until the
//! close can then pass for complete; a sized or chunked one cannot.
const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const xev = event_loop.Xev;
const ConnEntry = quic.connection_manager.ConnEntry;
const findHeader = quic.webtransport_protocol.findHeader;
const config = @import("../config.zig");
const upstream = @import("../upstream.zig");
const exchange = @import("../exchange.zig");
const proxy = @import("../handlers/proxy.zig");
const socket = @import("../net/socket.zig");
const wt_relay = @import("../h3/wt_relay.zig");
const reg = @import("registry.zig");
const pipe_mod = @import("pipe.zig");
const Worker = @import("../worker.zig").Worker;
const stats = @import("../stats.zig");

const log = std.log.scoped(.tunnel);
const registry = &reg.registry;

/// The agent asks for a name with this header, and hears the one it got,
/// and where it is served, in these.
pub const name_header = "routez-tunnel-name";
pub const url_header = "routez-tunnel-url";

const Key = struct { conn: u64, id: u64 };
const EdgePipe = pipe_mod.Pipe(Edge, false);

/// One agent's session.
pub const Tunnel = struct {
    entry: *ConnEntry,
    sid: u64,
    /// The registry's, for this claim of `name`.
    id: u64,
    name: []u8,

    pub fn session(self: *Tunnel) event_loop.Session {
        return .{ .entry = self.entry };
    }

    pub fn backlog(self: *Tunnel, stream: u64) u64 {
        const s = self.session();
        return s.streamBufferedBytes(stream) orelse 0;
    }
};

/// A worker's tunnels, and the pipes to them.
pub const Edge = struct {
    pub const Link = Tunnel;

    worker: *Worker,
    inbox: reg.Inbox,
    handoffs: std.ArrayListUnmanaged(reg.Handoff) = .empty,
    /// By connection and session.
    tunnels: std.AutoArrayHashMapUnmanaged(Key, *Tunnel) = .empty,
    pipes: EdgePipe.Set = .{},
    /// `tunnel_pass` groups by tunnel name, made on first use and kept for
    /// the worker's life: a few hundred bytes for each name ever reached.
    groups: std.StringHashMapUnmanaged(*upstream.Group) = .empty,

    pub fn init(w: *Worker) !Edge {
        return .{ .worker = w, .inbox = try .init(w.io, w.alloc) };
    }

    pub fn start(self: *Edge) void {
        self.inbox.wake.wait(&self.worker.loop, &self.inbox.wake_c, Edge, self, onInbox);
    }

    /// The worker is stopping, and quic-zig tells agents so
    /// (WT_DRAIN_SESSION). Each tunnel serves on until its agent's next
    /// session takes the name over.
    pub fn drain(self: *Edge) void {
        for (self.tunnels.values()) |t| registry.drain(self.worker.io, t.name, t.id);
    }

    /// The loop is done: no tunnel here takes another connection, and
    /// pipes the drain left open close with nothing more on the loop.
    pub fn stop(self: *Edge) void {
        registry.dropInbox(self.worker.io, &self.inbox);
        for (self.pipes.map.values()) |p| if (!p.sock.fd_closed) {
            _ = std.c.close(p.sock.fd());
        };
    }

    pub fn deinit(self: *Edge) void {
        const a = self.worker.alloc;
        var it = self.groups.iterator();
        while (it.next()) |e| {
            e.value_ptr.*.deinit();
            a.free(e.key_ptr.*);
        }
        self.groups.deinit(a);
        for (self.tunnels.values()) |t| self.free(t);
        self.tunnels.deinit(a);
        self.pipes.deinit(a);
        self.handoffs.deinit(a);
        self.inbox.deinit();
    }

    // ---- sessions ----

    /// A CONNECT to a `tunnel_accept` location, past its checks.
    pub fn accept(self: *Edge, session: *event_loop.Session, session_id: u64, headers: []const qpack.Header, ta: config.Location.TunnelAccept) void {
        self.open(session, session_id, headers, ta) catch |err| wt_relay.answer(session, session_id, switch (err) {
            error.BadName => "400",
            error.Taken => "409",
            else => "503",
        }, null);
    }

    fn open(self: *Edge, session: *event_loop.Session, session_id: u64, headers: []const qpack.Header, ta: config.Location.TunnelAccept) !void {
        const w = self.worker;
        const a = w.alloc;
        var name_buf: [63]u8 = undefined;
        var name: []const u8 = undefined;
        var id: u64 = undefined;
        if (findHeader(headers, name_header)) |want| {
            name = label(want, &name_buf) orelse return error.BadName;
            id = try registry.claim(w.io, name, &self.inbox);
        } else {
            // Ten tries at a fresh random name; failing that, something is wrong.
            for (0..10) |_| {
                name = randomName(&name_buf);
                id = registry.claim(w.io, name, &self.inbox) catch |err| switch (err) {
                    error.Taken => continue,
                    else => |e| return e,
                };
                break;
            } else return error.NoFreeName;
        }
        errdefer registry.release(w.io, name, id);
        const t = try a.create(Tunnel);
        errdefer a.destroy(t);
        t.* = .{ .entry = session.entry, .sid = session_id, .id = id, .name = try a.dupe(u8, name) };
        errdefer a.free(t.name);
        const key: Key = .{ .conn = session.id(), .id = session_id };
        try self.tunnels.put(a, key, t);
        errdefer _ = self.tunnels.swapRemove(key);
        var url_buf: [320]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "https://{s}.{s}", .{ t.name, ta.domain }) catch "";
        try session.acceptSessionWithHeaders(session_id, &.{
            .{ .name = name_header, .value = t.name },
            .{ .name = url_header, .value = url },
        });
        stats.inc(&stats.tunnels_open);
        var addr_buf: [64]u8 = undefined;
        log.info("tunnel {s} open from {s}: {s}", .{ t.name, socket.formatSockaddr(session.entry.conn.peerAddress(), &addr_buf), url });
    }

    /// The session is over: its pipes close, and its name is free again.
    fn close(self: *Edge, t: *Tunnel) void {
        registry.release(self.worker.io, t.name, t.id);
        _ = self.tunnels.swapRemove(.{ .conn = t.entry.id, .id = t.sid });
        self.pipes.detach(t);
        log.info("tunnel {s} closed", .{t.name});
        stats.dec(&stats.tunnels_open);
        self.free(t);
    }

    fn free(self: *Edge, t: *Tunnel) void {
        self.worker.alloc.free(t.name);
        self.worker.alloc.destroy(t);
    }

    fn tunnelFor(self: *Edge, session: *event_loop.Session, session_id: u64) ?*Tunnel {
        if (self.tunnels.count() == 0) return null;
        return self.tunnels.get(.{ .conn = session.id(), .id = session_id });
    }

    // ---- events from the WebTransport listener; true when they were ours ----

    pub fn onSessionClosed(self: *Edge, session: *event_loop.Session, session_id: u64) bool {
        const t = self.tunnelFor(session, session_id) orelse return false;
        self.close(t);
        return true;
    }

    /// An agent opened a stream: tunnels carry none that way.
    pub fn onAgentStream(self: *Edge, session: *event_loop.Session, session_id: u64, stream: u64) bool {
        _ = self.tunnelFor(session, session_id) orelse return false;
        session.resetStream(stream, pipe_mod.gone_error);
        return true;
    }

    pub fn onStreamData(self: *Edge, session: *event_loop.Session, stream: u64, data: []const u8, fin: bool) bool {
        const p = self.pipes.get(session.id(), stream) orelse return false;
        p.onStreamData(data, fin);
        return true;
    }

    pub fn onStreamAbort(self: *Edge, session: *event_loop.Session, stream: u64) bool {
        const p = self.pipes.get(session.id(), stream) orelse return false;
        p.onStreamAbort();
        return true;
    }

    pub fn onWritable(self: *Edge, session: *event_loop.Session, stream: ?u64) bool {
        const p = self.pipes.get(session.id(), stream orelse return false) orelse return false;
        p.onWritable();
        return true;
    }

    pub fn checkPaused(self: *Edge) void {
        self.pipes.checkPaused();
    }

    // ---- pipes ----

    fn onInbox(ud: ?*Edge, _: *xev.Loop, _: *xev.Completion, r: xev.Async.WaitError!void) xev.CallbackAction {
        _ = r catch {};
        const self = ud.?;
        self.inbox.drain(&self.handoffs);
        for (self.handoffs.items) |h| self.openPipe(h);
        self.handoffs.clearRetainingCapacity();
        return .rearm;
    }

    /// A stream to the agent for a connection handed over. Refused, the
    /// connection just closes: the proxy answers 502.
    fn openPipe(self: *Edge, h: reg.Handoff) void {
        const w = self.worker;
        const t = for (self.tunnels.values()) |t| {
            if (t.id == h.id) break t;
        } else {
            _ = std.c.close(h.fd);
            return;
        };
        var s = t.session();
        const stream = s.openBidiStream(t.sid, null) catch |err| {
            log.warn("tunnel {s}: no stream for a connection: {s}", .{ t.name, @errorName(err) });
            _ = std.c.close(h.fd);
            return;
        };
        const p = w.alloc.create(EdgePipe) catch {
            s.resetStream(stream, pipe_mod.gone_error);
            _ = std.c.close(h.fd);
            return;
        };
        p.* = .{ .owner = self, .link = t, .conn = t.entry.id, .stream = stream, .sock = undefined };
        p.sock.init(p, &w.loop, &w.timers, w.alloc, xev.TCP.initFd(h.fd));
        self.pipes.add(w.alloc, p) catch return p.sock.abort();
        p.sock.startReading();
    }

    // ---- tunnel_pass ----

    /// The group for tunnel `name`, made on first use; null while no
    /// tunnel by that name is open.
    fn group(self: *Edge, name: []const u8) !?*upstream.Group {
        const w = self.worker;
        if (!registry.has(w.io, name)) return null;
        if (self.groups.get(name)) |g| return g;
        const key = try w.alloc.dupe(u8, name);
        errdefer w.alloc.free(key);
        // One counter for every tunnel: names come and go, and the list never shrinks.
        const g = try upstream.Group.initDialed(w, key, &dial, try stats.peer(w.io, "tunnel", "*"));
        errdefer g.deinit();
        try self.groups.put(w.alloc, key, g);
        return g;
    }
};

/// A connection to tunnel `p.label`: one end of a socketpair for the
/// proxy, the other handed to the tunnel's worker.
fn dial(p: *upstream.Peer) anyerror!std.posix.socket_t {
    const w = p.group.worker;
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPair;
    for (fds) |fd| socket.setNonBlocking(fd);
    const remote = registry.handOff(w.io, p.label, fds[1], &w.tunnels.inbox) catch |err| {
        _ = std.c.close(fds[0]);
        _ = std.c.close(fds[1]);
        return err;
    };
    stats.inc(&stats.tunnel_streams);
    if (remote) stats.inc(&stats.tunnel_streams_cross_worker);
    return fds[0];
}

/// A `tunnel_pass` location's handler.
pub fn pass(ex: *exchange.Exchange, loc: *const config.Location) void {
    var buf: [63]u8 = undefined;
    const name = nameOfHost(ex.req.authority, &buf) orelse return ex.sendError(404);
    const g = (ex.worker.tunnels.group(name) catch return ex.sendError(500)) orelse return ex.sendError(404);
    proxy.startGroup(ex, loc, g);
}

/// The tunnel a host names: its first label, if it has more than one.
fn nameOfHost(authority: []const u8, buf: *[63]u8) ?[]const u8 {
    const dot = std.mem.indexOfScalar(u8, authority, '.') orelse return null;
    return label(authority[0..dot], buf);
}

/// `text` lowercased, if it is a DNS label.
fn label(text: []const u8, buf: *[63]u8) ?[]const u8 {
    if (!config.isDnsLabel(text)) return null;
    return std.ascii.lowerString(buf, text);
}

fn randomName(buf: *[63]u8) []const u8 {
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    var raw: [8]u8 = undefined;
    quic.sys.randomBytes(&raw);
    for (raw, buf[0..raw.len]) |r, *o| o.* = alphabet[r % alphabet.len];
    return buf[0..raw.len];
}

test "a tunnel is named by its host's first label" {
    var buf: [63]u8 = undefined;
    try std.testing.expectEqualStrings("game", nameOfHost("Game.play.example.com:8443", &buf).?);
    try std.testing.expectEqualStrings("a-1", nameOfHost("a-1.example.com", &buf).?);
    try std.testing.expect(nameOfHost("localhost:8080", &buf) == null);
    try std.testing.expect(nameOfHost(".example.com", &buf) == null);
    try std.testing.expect(nameOfHost("-a.example.com", &buf) == null);
    try std.testing.expect(nameOfHost("a_b.example.com", &buf) == null);
    const long: [64]u8 = @splat('x');
    try std.testing.expect(label(&long, &buf) == null);
    try std.testing.expectEqual(@as(usize, 63), label(long[0..63], &buf).?.len);
}

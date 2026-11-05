//! The edge's half of `routez tunnel`: agents' sessions, and the streams
//! that carry the HTTP proxy's upstream connections and players'
//! WebTransport sessions down to them.
//!
//! An agent opens a WebTransport session on a `tunnel_accept` location and
//! claims a name. A request a `tunnel_pass` location takes for that name
//! goes through the ordinary proxy (`handlers/proxy.zig`) to a one-peer
//! upstream group whose connections are socketpairs (`upstream.UpConn`).
//! The far end of each comes here, through the registry, to the worker
//! holding the session, which opens a stream to the agent and pipes the two
//! together (`pipe.zig`). The agent connects each stream to its local server.
//!
//! A player's WebTransport session on a `tunnel_pass` location is ended on
//! the player's worker (`players.zig`); its streams reach the agent the same
//! way, as socketpairs handed to the tunnel's worker, and the agent's
//! streams for it come back as socketpairs handed to the player's. What
//! each stream carries is in its first bytes (`wire.zig`).
//!
//! Each tunnel's usage goes to the log, hourly and when it closes:
//!
//!     tunnel game usage: user=alice secs=3600 to_local=1830 from_local=5242880 player_sessions=2
//!     tunnel game closed: user=alice secs=412 to_local=0 from_local=0 player_sessions=0
//!
//! A line counts from the tunnel's previous one (or its opening), so the sum
//! of a user's lines is what their tunnels carried. `user` is auth_basic's
//! (`-` without it); `to_local` and `from_local` are payload bytes on the
//! tunnel's session, toward the local server and back from it, HTTP and
//! players' streams and datagrams alike. A tunnel that comes back after a
//! reload or a reconnect is a new one, so its line restarts the count.
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
const wire = @import("wire.zig");
const players = @import("players.zig");
const Worker = @import("../worker.zig").Worker;
const stats = @import("../stats.zig");
const htpasswd = @import("../auth/htpasswd.zig");

const log = std.log.scoped(.tunnel);
const registry = &reg.registry;

/// The agent asks for a name with this header, and hears the one it got,
/// and where it is served, in these.
pub const name_header = "routez-tunnel-name";
pub const url_header = "routez-tunnel-url";

pub const Key = struct { conn: u64, id: u64 };
pub const EdgePipe = pipe_mod.Pipe(Edge, false);

/// A tunnel's usage line comes this often, and at its close.
const usage_interval_ms = std.time.ms_per_hour;

/// One agent's session.
pub const Tunnel = struct {
    link: Edge.Link,
    /// The registry's, for this claim of `name`.
    id: u64,
    name: []u8,
    /// auth_basic's user, or "-".
    user: []u8,
    /// Since the last usage line: when, and players' sessions opened.
    since_ms: i64,
    player_sessions: u64 = 0,
};

/// A stream the agent opened, until its head says where it goes.
const Incoming = struct {
    tunnel: *Tunnel,
    head: [wire.max_head]u8 = undefined,
    len: usize = 0,
};

/// A worker's tunnels, the players' sessions it ended, and the pipes to them.
pub const Edge = struct {
    /// A session a pipe's stream is on: an agent's or a player's.
    pub const Link = struct {
        entry: *ConnEntry,
        sid: u64,
        /// Counted by its pipes; read for a tunnel's usage.
        carried: pipe_mod.Carried = .{},

        pub fn session(self: *Link) event_loop.Session {
            return .{ .entry = self.entry };
        }

        pub fn backlog(self: *Link, stream: u64) u64 {
            const s = self.session();
            return s.streamBufferedBytes(stream) orelse 0;
        }
    };

    worker: *Worker,
    inbox: reg.Inbox,
    handoffs: std.ArrayListUnmanaged(reg.Handoff) = .empty,
    datagrams: reg.Datagrams = .{},
    /// A datagram for an agent, behind its session's token.
    datagram_buf: std.ArrayListUnmanaged(u8) = .empty,
    /// By connection and session.
    tunnels: std.AutoArrayHashMapUnmanaged(Key, *Tunnel) = .empty,
    /// By connection and stream.
    incoming: std.AutoArrayHashMapUnmanaged(Key, Incoming) = .empty,
    pipes: EdgePipe.Set = .{},
    players: players.Players = .{},
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
        self.players.stop();
    }

    pub fn deinit(self: *Edge) void {
        const a = self.worker.alloc;
        var it = self.groups.iterator();
        while (it.next()) |e| {
            e.value_ptr.*.deinit();
            a.free(e.key_ptr.*);
        }
        self.groups.deinit(a);
        for (self.tunnels.values()) |t| {
            self.logUsage(t, "closed");
            self.free(t);
        }
        self.tunnels.deinit(a);
        self.incoming.deinit(a);
        self.pipes.deinit(a);
        self.players.deinit(a);
        self.handoffs.deinit(a);
        self.datagrams.deinit(a);
        self.datagram_buf.deinit(a);
        self.inbox.deinit();
    }

    // ---- sessions ----

    /// A CONNECT to a `tunnel_accept` location, past its checks.
    pub fn accept(self: *Edge, session: *event_loop.Session, session_id: u64, headers: []const qpack.Header, loc: *const config.Location) void {
        self.open(session, session_id, headers, loc) catch |err| wt_relay.answer(session, session_id, switch (err) {
            error.BadName => "400",
            error.Taken => "409",
            else => "503",
        }, null);
    }

    /// A player's CONNECT to a `tunnel_pass` location, past its checks.
    pub fn connectPlayer(self: *Edge, session: *event_loop.Session, session_id: u64, path: []const u8, headers: []const qpack.Header) void {
        self.players.connect(session, session_id, path, headers);
    }

    fn open(self: *Edge, session: *event_loop.Session, session_id: u64, headers: []const qpack.Header, loc: *const config.Location) !void {
        const w = self.worker;
        const a = w.alloc;
        const ta = loc.tunnel_accept.?;
        // auth_basic has passed the credentials by now.
        var cred_buf: [htpasswd.max_credentials]u8 = undefined;
        defer std.crypto.secureZero(u8, &cred_buf);
        const user = if (w.shared.guards.policy(loc).auth == null) "-" else if (htpasswd.parseAuthorization(findHeader(headers, "authorization") orelse "", &cred_buf)) |c| c.user else "-";
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
        t.* = .{ .link = .{ .entry = session.entry, .sid = session_id }, .id = id, .name = try a.dupe(u8, name), .user = &.{}, .since_ms = w.timers.now_ms };
        errdefer a.free(t.name);
        t.user = try a.dupe(u8, user);
        errdefer a.free(t.user);
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
        log.info("tunnel {s} open from {s} for {s}: {s}", .{ t.name, socket.formatSockaddr(session.entry.conn.peerAddress(), &addr_buf), t.user, url });
    }

    /// The session is over: its pipes close, and its name is free again.
    fn close(self: *Edge, t: *Tunnel) void {
        registry.release(self.worker.io, t.name, t.id);
        _ = self.tunnels.swapRemove(.{ .conn = t.link.entry.id, .id = t.link.sid });
        var i: usize = 0;
        while (i < self.incoming.count()) {
            if (self.incoming.values()[i].tunnel == t) self.incoming.swapRemoveAt(i) else i += 1;
        }
        self.pipes.detach(&t.link);
        self.logUsage(t, "closed");
        stats.dec(&stats.tunnels_open);
        self.free(t);
    }

    /// The line the module's doc describes; the next one counts from here.
    fn logUsage(self: *Edge, t: *Tunnel, what: []const u8) void {
        const now = self.worker.timers.now_ms;
        log.info("tunnel {s} {s}: user={s} secs={d} to_local={d} from_local={d} player_sessions={d}", .{
            t.name, what, t.user, @divTrunc(now - t.since_ms, std.time.ms_per_s), t.link.carried.sent, t.link.carried.received, t.player_sessions,
        });
        t.since_ms = now;
        t.link.carried = .{};
        t.player_sessions = 0;
    }

    fn free(self: *Edge, t: *Tunnel) void {
        self.worker.alloc.free(t.user);
        self.worker.alloc.free(t.name);
        self.worker.alloc.destroy(t);
    }

    fn tunnelFor(self: *Edge, session: *event_loop.Session, session_id: u64) ?*Tunnel {
        if (self.tunnels.count() == 0) return null;
        return self.tunnels.get(.{ .conn = session.id(), .id = session_id });
    }

    fn tunnelById(self: *Edge, id: u64) ?*Tunnel {
        for (self.tunnels.values()) |t| if (t.id == id) return t;
        return null;
    }

    // ---- events from the WebTransport listener; true when they were ours ----

    pub fn onSessionClosed(self: *Edge, session: *event_loop.Session, session_id: u64, error_code: u32, reason: []const u8) bool {
        if (self.tunnelFor(session, session_id)) |t| {
            self.close(t);
            return true;
        }
        return self.players.onSessionClosed(session, session_id, error_code, reason);
    }

    pub fn onConnectionClosed(self: *Edge, session: *event_loop.Session) void {
        self.players.onConnectionClosed(session);
    }

    /// The peer opened a stream: an agent's, for a stream its local server
    /// opened, or a player's.
    pub fn onSessionStream(self: *Edge, session: *event_loop.Session, session_id: u64, stream: u64, bidi: bool) bool {
        const t = self.tunnelFor(session, session_id) orelse return self.players.onStream(session, session_id, stream, bidi);
        // Agents open bidirectional streams only, each with a head.
        if (!bidi) {
            session.stopSending(stream, pipe_mod.gone_error);
            return true;
        }
        self.incoming.put(self.worker.alloc, .{ .conn = session.id(), .id = stream }, .{ .tunnel = t }) catch
            session.resetStream(stream, pipe_mod.gone_error);
        return true;
    }

    pub fn onStreamData(self: *Edge, session: *event_loop.Session, stream: u64, data: []const u8, fin: bool) bool {
        if (self.pipes.get(session.id(), stream)) |p| {
            p.onStreamData(data, fin);
            return true;
        }
        if (self.incoming.count() == 0) return false;
        const key: Key = .{ .conn = session.id(), .id = stream };
        const in = self.incoming.getPtr(key) orelse return false;
        const take = @min(data.len, in.head.len - in.len);
        @memcpy(in.head[in.len..][0..take], data[0..take]);
        const before = in.len;
        in.len += take;
        const parsed = wire.parseHead(in.head[0..in.len]) catch {
            _ = self.incoming.swapRemove(key);
            refuseStream(session, stream);
            return true;
        };
        const h = parsed orelse {
            if (fin) {
                _ = self.incoming.swapRemove(key);
                refuseStream(session, stream);
            }
            return true;
        };
        const t = in.tunnel;
        _ = self.incoming.swapRemove(key);
        if (h.kind != .stream) {
            refuseStream(session, stream);
            return true;
        }
        self.agentStream(t, stream, h, data[h.len - before ..], fin);
        return true;
    }

    pub fn onStreamAbort(self: *Edge, session: *event_loop.Session, stream: u64) bool {
        if (self.pipes.get(session.id(), stream)) |p| {
            p.onStreamAbort();
            return true;
        }
        return self.incoming.swapRemove(.{ .conn = session.id(), .id = stream });
    }

    pub fn onWritable(self: *Edge, session: *event_loop.Session, stream: ?u64) bool {
        const p = self.pipes.get(session.id(), stream orelse return false) orelse return false;
        p.onWritable();
        return true;
    }

    /// An agent's datagram for a player, behind the player session's token;
    /// or a player's.
    pub fn onDatagram(self: *Edge, session: *event_loop.Session, session_id: u64, data: []const u8) bool {
        const t = self.tunnelFor(session, session_id) orelse return self.players.onDatagram(session, session_id, data);
        const token = wire.getVarint(data) orelse return true;
        t.link.carried.received += data.len - token.len;
        registry.datagramToPlayer(self.worker.io, token.v, t.id, data[token.len..]);
        return true;
    }

    /// Every tick.
    pub fn tick(self: *Edge) void {
        self.pipes.checkPaused();
        const now = self.worker.timers.now_ms;
        for (self.tunnels.values()) |t| if (now - t.since_ms >= usage_interval_ms) self.logUsage(t, "usage");
    }

    // ---- pipes ----

    fn onInbox(ud: ?*Edge, _: *xev.Loop, _: *xev.Completion, r: xev.Async.WaitError!void) xev.CallbackAction {
        _ = r catch {};
        const self = ud.?;
        self.inbox.drain(&self.handoffs, &self.datagrams);
        for (self.handoffs.items) |h| switch (h.to) {
            .agent => |id| self.openPipe(id, h.fd, false),
            .session => |id| self.openPipe(id, h.fd, true),
            .player => |p| self.players.openStream(p.token, p.uni, h.fd),
        };
        self.handoffs.clearRetainingCapacity();
        for (self.datagrams.list.items) |d| {
            const bytes = self.datagrams.data(d);
            if (d.tunnel == 0) {
                self.players.datagram(d.token, bytes);
            } else if (self.tunnelById(d.tunnel)) |t| {
                self.sendToAgent(t, d.token, bytes);
            }
        }
        self.datagrams.clear();
        return .rearm;
    }

    /// A player's datagram on the tunnel's session, behind its token. One
    /// too big for the session is dropped, as the network would.
    fn sendToAgent(self: *Edge, t: *Tunnel, token: u64, bytes: []const u8) void {
        const a = self.worker.alloc;
        self.datagram_buf.clearRetainingCapacity();
        self.datagram_buf.ensureTotalCapacity(a, wire.max_head + bytes.len) catch return;
        var buf: [8]u8 = undefined;
        self.datagram_buf.appendSliceAssumeCapacity(buf[0..wire.putVarint(&buf, token)]);
        self.datagram_buf.appendSliceAssumeCapacity(bytes);
        var s = t.link.session();
        s.sendDatagram(t.link.sid, self.datagram_buf.items) catch return;
        t.link.carried.sent += bytes.len;
    }

    /// A stream to the agent of tunnel `id` for a connection handed over,
    /// or for a player's new session (`session`). Refused, the connection
    /// just closes: the proxy answers 502.
    fn openPipe(self: *Edge, id: u64, fd: std.posix.fd_t, session: bool) void {
        const t = self.tunnelById(id) orelse {
            _ = std.c.close(fd);
            return;
        };
        if (session) t.player_sessions += 1;
        var s = t.link.session();
        const stream = s.openBidiStream(t.link.sid, null) catch |err| {
            log.warn("tunnel {s}: no stream for a connection: {s}", .{ t.name, @errorName(err) });
            _ = std.c.close(fd);
            return;
        };
        const p = self.newPipe(&t.link, stream, fd) orelse {
            s.resetStream(stream, pipe_mod.gone_error);
            return;
        };
        p.sock.startReading();
    }

    /// The agent opened `stream` for a player's session: the player's
    /// worker gets the other end of a socketpair for it.
    fn agentStream(self: *Edge, t: *Tunnel, stream: u64, h: wire.Head, rest: []const u8, fin: bool) void {
        var s = t.link.session();
        const fds = socketPair() orelse return refuseStream(&s, stream);
        registry.toPlayer(self.worker.io, h.token, t.id, fds[1], h.uni) catch {
            _ = std.c.close(fds[0]);
            _ = std.c.close(fds[1]);
            return refuseStream(&s, stream);
        };
        const p = self.newPipe(&t.link, stream, fds[0]) orelse return refuseStream(&s, stream);
        if (rest.len > 0 or fin) p.onStreamData(rest, fin);
        p.sock.startReading();
    }

    /// A pipe for `stream` on `link`'s session and the socket `fd`, which
    /// it owns; null (and `fd` closed) when there is no room for one.
    pub fn newPipe(self: *Edge, link: *Edge.Link, stream: u64, fd: std.posix.fd_t) ?*EdgePipe {
        const w = self.worker;
        const p = w.alloc.create(EdgePipe) catch {
            _ = std.c.close(fd);
            return null;
        };
        p.* = .{ .owner = self, .link = link, .conn = link.entry.id, .stream = stream, .sock = undefined };
        p.sock.init(p, &w.loop, &w.timers, w.alloc, xev.TCP.initFd(fd));
        self.pipes.add(w.alloc, p) catch {
            // The close frees it.
            p.link = null;
            p.sock.abort();
            return null;
        };
        return p;
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

pub fn refuseStream(s: *event_loop.Session, stream: u64) void {
    s.resetStream(stream, pipe_mod.gone_error);
    s.stopSending(stream, pipe_mod.gone_error);
}

/// A nonblocking stream socketpair.
pub fn socketPair() ?[2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return null;
    for (fds) |fd| socket.setNonBlocking(fd);
    return fds;
}

/// A connection to tunnel `p.label`: one end of a socketpair for the
/// proxy, the other handed to the tunnel's worker.
fn dial(p: *upstream.Peer) anyerror!std.posix.socket_t {
    const w = p.group.worker;
    const fds = socketPair() orelse return error.SocketPair;
    // The stream's head, ahead of the proxy's bytes; an empty socketpair takes it.
    const kind = [1]u8{@backingInt(wire.Kind.http)};
    if (std.c.write(fds[0], &kind, 1) != 1) {
        _ = std.c.close(fds[0]);
        _ = std.c.close(fds[1]);
        return error.SocketPair;
    }
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
pub fn nameOfHost(authority: []const u8, buf: *[63]u8) ?[]const u8 {
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

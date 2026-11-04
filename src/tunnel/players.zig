//! Players' WebTransport sessions on a `tunnel_pass` location: ended on the
//! player's worker and carried to the agent, which opens the same session
//! on its local server.
//!
//! The session's control stream to the agent (`wire.zig`'s `session`) and
//! each of its streams are socketpairs handed to the tunnel's worker, as the
//! HTTP proxy's connections are; streams the local server opens come back
//! the same way. As in `wt_relay`, the player's session is accepted only
//! once the local server accepted its own, with the headers it answered,
//! and the player's CONNECT carries X-Forwarded-For and X-Real-IP. A
//! datagram goes through the registry to the tunnel's worker, which sends it
//! on the agent's session behind the session's token; one too big for that
//! session is dropped.
const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const xev = event_loop.Xev;
const findHeader = quic.webtransport_protocol.findHeader;
const edge_mod = @import("edge.zig");
const Edge = edge_mod.Edge;
const Key = edge_mod.Key;
const reg = @import("registry.zig");
const wire = @import("wire.zig");
const pipe_mod = @import("pipe.zig");
const socket = @import("../net/socket.zig");
const wt_relay = @import("../h3/wt_relay.zig");
const stats = @import("../stats.zig");

const log = std.log.scoped(.tunnel);
const registry = &reg.registry;

/// A worker's players' sessions.
pub const Players = struct {
    by_session: std.AutoArrayHashMapUnmanaged(Key, *Player) = .empty,
    by_token: std.AutoHashMapUnmanaged(u64, *Player) = .empty,

    fn edge(self: *Players) *Edge {
        return @fieldParentPtr("players", self);
    }

    /// The loop is done: the control sockets close with nothing more on it.
    pub fn stop(self: *Players) void {
        for (self.by_session.values()) |p| if (!p.ctl.fd_closed) {
            p.ctl.fd_closed = true;
            _ = std.c.close(p.ctl.fd());
        };
    }

    pub fn deinit(self: *Players, a: std.mem.Allocator) void {
        for (self.by_session.values()) |p| p.free();
        self.by_session.deinit(a);
        self.by_token.deinit(a);
    }

    /// A player's CONNECT: to the tunnel its host names, or 404.
    pub fn connect(self: *Players, session: *event_loop.Session, session_id: u64, path: []const u8, headers: []const qpack.Header) void {
        var name_buf: [63]u8 = undefined;
        const name = edge_mod.nameOfHost(findHeader(headers, ":authority") orelse "", &name_buf) orelse
            return wt_relay.answer(session, session_id, "404", null);
        self.open(session, session_id, name, path, headers) catch |err| {
            if (err == error.NoTunnel) return wt_relay.answer(session, session_id, "404", null);
            log.warn("tunnel {s}: a player's session: {s}", .{ name, @errorName(err) });
            wt_relay.answer(session, session_id, "503", null);
        };
    }

    fn open(self: *Players, session: *event_loop.Session, session_id: u64, name: []const u8, path: []const u8, headers: []const qpack.Header) !void {
        const e = self.edge();
        const w = e.worker;
        const a = w.alloc;
        const s = try registry.openSession(w.io, name, &e.inbox);
        if (s.remote) stats.inc(&stats.tunnel_player_sessions_cross_worker);
        errdefer registry.closeSession(w.io, s.token);

        // The control stream's head and the CONNECT, for the agent.
        var arena_state: std.heap.ArenaAllocator = .init(a);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var hello: std.ArrayListUnmanaged(u8) = .empty;
        var head_buf: [wire.max_head]u8 = undefined;
        try hello.appendSlice(arena, wire.head(&head_buf, .session, s.token, false));
        try wire.writeRequest(arena, &hello, path, try wt_relay.forwardFor(arena, w, session, headers));

        const fds = edge_mod.socketPair() orelse return error.SocketPair;
        const p = a.create(Player) catch |err| {
            _ = std.c.close(fds[0]);
            _ = std.c.close(fds[1]);
            return err;
        };
        p.* = .{ .players = self, .link = .{ .entry = session.entry, .sid = session_id }, .token = s.token, .ctl = undefined };
        p.ctl.init(p, &w.loop, &w.timers, a, xev.TCP.initFd(fds[0]));
        p.ctl.write(hello.items);
        const key: Key = .{ .conn = session.id(), .id = session_id };
        self.put(a, key, p) catch |err| {
            _ = std.c.close(fds[1]);
            p.drop();
            return err;
        };
        registry.toAgent(w.io, s.token, fds[1]) catch |err| {
            _ = std.c.close(fds[1]);
            p.forget();
            p.drop();
            return err;
        };
        p.ctl.startReading();
        stats.inc(&stats.tunnel_player_sessions);
    }

    fn put(self: *Players, a: std.mem.Allocator, key: Key, p: *Player) !void {
        try self.by_session.put(a, key, p);
        self.by_token.put(a, p.token, p) catch |err| {
            _ = self.by_session.swapRemove(key);
            return err;
        };
    }

    fn playerFor(self: *Players, session: *event_loop.Session, session_id: u64) ?*Player {
        if (self.by_session.count() == 0) return null;
        return self.by_session.get(.{ .conn = session.id(), .id = session_id });
    }

    // ---- events from the WebTransport listener; true when they were ours ----

    pub fn onSessionClosed(self: *Players, session: *event_loop.Session, session_id: u64, error_code: u32, reason: []const u8) bool {
        const p = self.playerFor(session, session_id) orelse return false;
        p.ended(error_code, reason);
        return true;
    }

    pub fn onConnectionClosed(self: *Players, session: *event_loop.Session) void {
        var i: usize = 0;
        while (i < self.by_session.count()) {
            const p = self.by_session.values()[i];
            if (p.link.entry.id == session.id()) p.ended(0, "") else i += 1;
        }
    }

    /// The player opened a stream: the agent gets a socketpair's end for it.
    pub fn onStream(self: *Players, session: *event_loop.Session, session_id: u64, stream: u64, bidi: bool) bool {
        const p = self.playerFor(session, session_id) orelse return false;
        const e = self.edge();
        if (p.state != .accepted) return refuse(session, stream, bidi);
        const fds = edge_mod.socketPair() orelse return refuse(session, stream, bidi);
        const pipe = e.newPipe(&p.link, stream, fds[0]) orelse {
            _ = std.c.close(fds[1]);
            return refuse(session, stream, bidi);
        };
        var head_buf: [wire.max_head]u8 = undefined;
        pipe.sock.write(wire.head(&head_buf, .stream, p.token, !bidi));
        if (!bidi) pipe.inOnly();
        registry.toAgent(e.worker.io, p.token, fds[1]) catch {
            _ = std.c.close(fds[1]);
            pipe.detach();
            return refuse(session, stream, bidi);
        };
        pipe.sock.startReading();
        return true;
    }

    pub fn onDatagram(self: *Players, session: *event_loop.Session, session_id: u64, data: []const u8) bool {
        const p = self.playerFor(session, session_id) orelse return false;
        if (p.state == .accepted) registry.datagramToAgent(self.edge().worker.io, p.token, data);
        return true;
    }

    // ---- from the agent, through the inbox ----

    /// The local server opened a stream: open the player's, on `fd`. One
    /// opened as the local server accepted can beat its accept here: the
    /// accept comes over the control socket, the stream through the inbox.
    pub fn openStream(self: *Players, token: u64, uni: bool, fd: std.posix.fd_t) void {
        const p = self.by_token.get(token) orelse {
            _ = std.c.close(fd);
            return;
        };
        switch (p.state) {
            .accepted => p.openStream(uni, fd),
            .waiting => if (p.early.items.len < Player.max_early) {
                p.early.append(p.alloc(), .{ .fd = fd, .uni = uni }) catch {
                    _ = std.c.close(fd);
                };
            } else {
                _ = std.c.close(fd);
            },
            .gone => _ = std.c.close(fd),
        }
    }

    pub fn datagram(self: *Players, token: u64, bytes: []const u8) void {
        const p = self.by_token.get(token) orelse return;
        if (p.state != .accepted) return;
        var s = p.link.session();
        s.sendDatagram(p.link.sid, bytes) catch {};
    }
};

/// Refuse a stream the player opened; true, for the event hooks.
fn refuse(session: *event_loop.Session, stream: u64, bidi: bool) bool {
    // A unidirectional stream has no side of ours to reset.
    if (bidi) session.resetStream(stream, pipe_mod.gone_error);
    session.stopSending(stream, pipe_mod.gone_error);
    return true;
}

/// One player's session, and its control stream to the agent.
pub const Player = struct {
    players: *Players,
    link: Edge.Link,
    token: u64,
    /// The control stream, as a socketpair's end.
    ctl: socket.Socket(Player, false),
    reader: wire.Reader = .{},
    state: enum { waiting, accepted, gone } = .waiting,
    /// The local server's streams that came before its accept, in order.
    early: std.ArrayListUnmanaged(Early) = .empty,

    const Early = struct { fd: std.posix.fd_t, uni: bool };
    /// More than this before the accept is no game server's opening.
    const max_early = 64;

    fn alloc(p: *Player) std.mem.Allocator {
        return p.players.edge().worker.alloc;
    }

    fn openStream(p: *Player, uni: bool, fd: std.posix.fd_t) void {
        var s = p.link.session();
        const stream = (if (uni) s.openUniStream(p.link.sid, null) else s.openBidiStream(p.link.sid, null)) catch |err| {
            log.warn("a player's session: no stream for the local server's: {s}", .{@errorName(err)});
            _ = std.c.close(fd);
            return;
        };
        const pipe = p.players.edge().newPipe(&p.link, stream, fd) orelse return s.resetStream(stream, pipe_mod.gone_error);
        if (uni) pipe.outOnly();
        pipe.sock.startReading();
    }

    /// Closing them tells the agent, as the local server's streams' resets.
    fn dropEarly(p: *Player) void {
        for (p.early.items) |e| _ = std.c.close(e.fd);
        p.early.clearAndFree(p.alloc());
    }

    /// The player's side ended: the agent hears why, and the rest closes.
    fn ended(p: *Player, code: u32, reason: []const u8) void {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(p.alloc());
        wire.writeClose(p.alloc(), &out, code, reason) catch {};
        p.ctl.write(out.items);
        p.finish();
        p.ctl.closeAfterFlush();
    }

    /// The agent's side is gone or broken: so is the player's session.
    fn fail(p: *Player, why: []const u8) void {
        if (p.state == .gone) return;
        var s = p.link.session();
        if (p.state == .waiting) {
            wt_relay.answer(&s, p.link.sid, "502", null);
        } else {
            s.closeSessionWithError(p.link.sid, wt_relay.relay_error, why) catch {};
        }
        p.finish();
        p.ctl.abort();
    }

    /// Off the maps and the registry, and the session's streams closed. The
    /// control socket's close frees it.
    fn finish(p: *Player) void {
        if (p.state == .gone) return;
        stats.dec(&stats.tunnel_player_sessions);
        p.forget();
        p.players.edge().pipes.detach(&p.link);
        p.dropEarly();
        p.state = .gone;
    }

    fn forget(p: *Player) void {
        const pl = p.players;
        _ = pl.by_session.swapRemove(.{ .conn = p.link.entry.id, .id = p.link.sid });
        _ = pl.by_token.remove(p.token);
        registry.closeSession(pl.edge().worker.io, p.token);
    }

    /// Never opened: closing the socket frees it.
    fn drop(p: *Player) void {
        p.state = .gone;
        p.ctl.abort();
    }

    fn free(p: *Player) void {
        p.dropEarly();
        p.reader.deinit(p.alloc());
        p.alloc().destroy(p);
    }

    fn onMessage(p: *Player, m: wire.Message) void {
        var s = p.link.session();
        switch (m) {
            .accept => |encoded| {
                if (p.state != .waiting) return p.fail("accepted twice");
                var got: [32]qpack.Header = undefined;
                var extra: [32]qpack.Header = undefined;
                const hs = encoded.decode(&got) catch return p.fail("bad accept");
                s.acceptSessionWithHeaders(p.link.sid, wt_relay.endToEnd(hs, &extra)) catch return p.fail("accept failed");
                p.state = .accepted;
                for (p.early.items) |e| p.openStream(e.uni, e.fd);
                p.early.clearAndFree(p.alloc());
            },
            .refuse => |status| {
                if (p.state != .waiting) return p.fail("refused once accepted");
                var buf: [8]u8 = undefined;
                const text = if (status >= 200 and status <= 599) std.fmt.bufPrint(&buf, "{d}", .{status}) catch "502" else "502";
                wt_relay.answer(&s, p.link.sid, text, null);
                p.finish();
                p.ctl.closeAfterFlush();
            },
            .close => |c| {
                if (p.state == .waiting) {
                    wt_relay.answer(&s, p.link.sid, "502", null);
                } else {
                    s.closeSessionWithError(p.link.sid, c.code, c.reason) catch {};
                }
                p.finish();
                p.ctl.closeAfterFlush();
            },
            .request => p.fail("bad control stream"),
        }
    }

    // ---- the control socket ----

    pub fn onSocketData(p: *Player, data: []const u8) void {
        if (p.state == .gone) return;
        p.reader.feed(p.alloc(), data) catch return p.fail("bad control stream");
        while (p.state != .gone) {
            const m = (p.reader.next() catch return p.fail("bad control stream")) orelse return;
            p.onMessage(m);
        }
    }

    /// Without a `close`: the agent, or its tunnel, went away. Once we
    /// closed, it is only the flush ending.
    pub fn onSocketEof(p: *Player) void {
        p.fail("tunnel gone");
    }

    pub fn onSocketWritable(_: *Player) void {}

    pub fn onSocketClosed(p: *Player) void {
        p.fail("tunnel gone");
        p.free();
    }
};

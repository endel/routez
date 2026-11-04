//! The agent's half of players' WebTransport sessions. Each one the edge
//! carries down the tunnel (`players.zig`) is opened again on the local
//! server, by a QUIC client of its own on the agent's loop, and paired with
//! it stream for stream; datagrams pass behind the session's token.
//!
//! Backpressure as in `wt_relay`: a stream whose destination has more than
//! `high_water` unsent, or whose session credit refused bytes now held
//! here, pauses its source until the destination's `onWritable` or
//! `checkPaused` (every tick) finds it caught up.
//!
//! The local server's certificate isn't checked: the server is this
//! machine's or one its user named, and a game server in development is
//! usually self-signed.
const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const wire = @import("wire.zig");
const pipe_mod = @import("pipe.zig");
const socket = @import("../net/socket.zig");
const wt = @import("../h3/wt_relay.zig");
const agent_mod = @import("agent.zig");
const Agent = agent_mod.Agent;
const Conn = agent_mod.Conn;

const log = std.log.scoped(.tunnel);

const high_water = socket.high_water;
const low_water = socket.low_water;
const gone_error = pipe_mod.gone_error;

/// A local server that hasn't accepted a session by then fails it.
const local_handshake_ms = 5_000;

pub const Key = struct { conn: u64, stream: u64 };

const LocalClient = event_loop.Client(LocalHandler);

/// A tunnel stream that is a session's control stream or one of its streams.
const Endpoint = union(enum) { ctl: *Session, pair: *Pair };

/// The agent's players' sessions.
pub const Sessions = struct {
    by_token: std.AutoArrayHashMapUnmanaged(u64, *Session) = .empty,
    /// By tunnel connection serial and stream.
    streams: std.AutoHashMapUnmanaged(Key, Endpoint) = .empty,
    /// Ended, their clients stopping; freed once off the loop.
    retired: std.ArrayListUnmanaged(*Session) = .empty,

    fn agent(self: *Sessions) *Agent {
        return @fieldParentPtr("wt", self);
    }

    /// Nothing open and nothing stopping.
    pub fn idle(self: *const Sessions) bool {
        return self.by_token.count() == 0 and self.retired.items.len == 0;
    }

    /// Sessions on tunnel connection `c`.
    pub fn on(self: *const Sessions, c: *Conn) usize {
        var n: usize = 0;
        for (self.by_token.values()) |s| n += @intFromBool(s.conn == c);
        return n;
    }

    /// `c` is gone: its sessions end, with no word to the edge.
    pub fn detach(self: *Sessions, c: *Conn) void {
        var i: usize = 0;
        while (i < self.by_token.count()) {
            const s = self.by_token.values()[i];
            if (s.conn == c) s.end(.tunnel) else i += 1;
        }
    }

    /// Every tick.
    pub fn tick(self: *Sessions) void {
        var i: usize = 0;
        while (i < self.by_token.count()) {
            const s = self.by_token.values()[i];
            // The local server never answered, or went without a word.
            if (s.started and s.client.conn.isClosed()) {
                if (s.state == .opening) {
                    const o = self.agent().opts;
                    log.warn("a player's WebTransport session: nothing answered at {s}:{d} (UDP)", .{ o.wt_host, o.wt.getPort() });
                    s.sendRefuse(502);
                } else s.sendClose(gone_error, "local server gone");
                s.end(.local);
                continue;
            }
            i += 1;
            for (s.pairs.values()) |p| p.resumeCaughtUp();
        }
        i = 0;
        while (i < self.retired.items.len) {
            const s = self.retired.items[i];
            if (!s.client.isStopped()) {
                i += 1;
                continue;
            }
            _ = self.retired.swapRemove(i);
            s.client.deinit();
            s.free();
        }
    }

    // ---- from the tunnel ----

    /// The edge opened `stream` for a player's session.
    pub fn openSession(self: *Sessions, c: *Conn, stream: u64, token: u64, rest: []const u8, fin: bool) void {
        const a = self.agent().alloc;
        var cs = c.session();
        if (self.by_token.contains(token)) return refuse(&cs, stream);
        const s = a.create(Session) catch return refuse(&cs, stream);
        s.* = .{ .sessions = self, .conn = c, .ctl = stream, .token = token, .arena_state = .init(a), .handler = .{ .s = s }, .client = undefined };
        self.by_token.put(a, token, s) catch {
            s.free();
            return refuse(&cs, stream);
        };
        self.streams.put(a, .{ .conn = c.serial, .stream = stream }, .{ .ctl = s }) catch {
            _ = self.by_token.swapRemove(token);
            s.free();
            return refuse(&cs, stream);
        };
        if (rest.len > 0 or fin) s.onCtlData(rest, fin);
    }

    /// The edge opened `stream` for a stream a player opened.
    pub fn openStream(self: *Sessions, c: *Conn, stream: u64, token: u64, uni: bool, rest: []const u8, fin: bool) void {
        var cs = c.session();
        const s = self.by_token.get(token) orelse return refuse(&cs, stream);
        if (s.conn != c or s.state != .open) return refuse(&cs, stream);
        var ls = s.client.clientSession();
        const local = (if (uni) ls.openUniStream(s.local_sid, null) else ls.openBidiStream(s.local_sid, null)) catch return refuse(&cs, stream);
        const p = s.pair(stream, local) orelse {
            ls.resetStream(local, gone_error);
            return refuse(&cs, stream);
        };
        if (uni) {
            // Our way of the tunnel's stream ends empty.
            p.down_done = true;
            cs.closeStream(stream);
        }
        if (rest.len > 0 or fin) p.fromTunnel(rest, fin);
    }

    /// True when `stream` was a session's.
    pub fn onTunnelData(self: *Sessions, c: *Conn, stream: u64, data: []const u8, fin: bool) bool {
        if (self.streams.count() == 0) return false;
        switch (self.streams.get(.{ .conn = c.serial, .stream = stream }) orelse return false) {
            .ctl => |s| s.onCtlData(data, fin),
            .pair => |p| p.fromTunnel(data, fin),
        }
        return true;
    }

    /// The edge reset the stream (`reset`) or asked us to stop sending on it.
    pub fn onTunnelAbort(self: *Sessions, c: *Conn, stream: u64, reset: bool, code: u32) bool {
        if (self.streams.count() == 0) return false;
        switch (self.streams.get(.{ .conn = c.serial, .stream = stream }) orelse return false) {
            .ctl => |s| {
                s.closeLocal(gone_error, "edge gone");
                s.end(.edge);
            },
            .pair => |p| if (reset) p.tunnelReset(code) else p.tunnelStopped(code),
        }
        return true;
    }

    pub fn onTunnelWritable(self: *Sessions, c: *Conn, stream: u64) bool {
        if (self.streams.count() == 0) return false;
        switch (self.streams.get(.{ .conn = c.serial, .stream = stream }) orelse return false) {
            .ctl => |s| {
                var cs = c.session();
                _ = wt.drain(self.agent().alloc, &cs, c.sid, s.ctl, &s.ctl_held);
            },
            .pair => |p| p.tunnelWritable(),
        }
        return true;
    }

    /// A datagram for a player's session, behind its token.
    pub fn onTunnelDatagram(self: *Sessions, c: *Conn, data: []const u8) void {
        const t = wire.getVarint(data) orelse return;
        const s = self.by_token.get(t.v) orelse return;
        if (s.conn != c or s.state != .open) return;
        var ls = s.client.clientSession();
        ls.sendDatagram(s.local_sid, data[t.len..]) catch {};
    }
};

fn refuse(cs: *event_loop.ClientSession, stream: u64) void {
    cs.resetStream(stream, gone_error);
    cs.stopSending(stream, gone_error);
}

/// One player's session: its control stream on the tunnel, and the local
/// server's session.
const Session = struct {
    sessions: *Sessions,
    /// Null once the tunnel connection is gone.
    conn: ?*Conn,
    ctl: u64,
    token: u64,
    reader: wire.Reader = .{},
    /// Control messages the tunnel's session credit refused.
    ctl_held: wt.Held = .{},
    /// The local client borrows its config from here.
    arena_state: std.heap.ArenaAllocator,
    handler: LocalHandler,
    client: LocalClient,
    started: bool = false,
    local_sid: u64 = 0,
    state: enum { requested, opening, open } = .requested,
    /// By local stream.
    pairs: std.AutoArrayHashMapUnmanaged(u64, *Pair) = .empty,

    fn alloc(s: *Session) std.mem.Allocator {
        return s.sessions.agent().alloc;
    }

    fn free(s: *Session) void {
        const a = s.alloc();
        s.reader.deinit(a);
        s.ctl_held.bytes.deinit(a);
        s.pairs.deinit(a);
        s.arena_state.deinit();
        a.destroy(s);
    }

    fn onCtlData(s: *Session, data: []const u8, fin: bool) void {
        s.reader.feed(s.alloc(), data) catch return s.fail();
        while (true) {
            const m = (s.reader.next() catch return s.fail()) orelse break;
            switch (m) {
                .request => |r| {
                    if (s.state != .requested) return s.fail();
                    s.open(r.path, r.headers) catch |err| {
                        log.warn("a player's session: {s}", .{@errorName(err)});
                        s.sendRefuse(502);
                        return s.end(.local);
                    };
                },
                .close => |cl| {
                    s.closeLocal(cl.code, cl.reason);
                    return s.end(.edge);
                },
                .accept, .refuse => return s.fail(),
            }
        }
        if (fin) {
            s.closeLocal(gone_error, "edge gone");
            s.end(.edge);
        }
    }

    /// The control stream broke: so does the session.
    fn fail(s: *Session) void {
        s.closeLocal(gone_error, "bad control stream");
        s.end(.edge);
    }

    fn open(s: *Session, path: []const u8, encoded: wire.Headers) !void {
        const ag = s.sessions.agent();
        const arena = s.arena_state.allocator();
        var store: [64]qpack.Header = undefined;
        const got = try encoded.decode(&store);
        const headers = try arena.alloc(qpack.Header, got.len);
        for (got, headers) |h, *d| d.* = .{ .name = try arena.dupe(u8, h.name), .value = try arena.dupe(u8, h.value) };
        var ip_buf: [64]u8 = undefined;
        s.client = try LocalClient.init(ag.alloc, &s.handler, .{
            .address = try arena.dupe(u8, socket.formatIp(ag.opts.wt, &ip_buf)),
            .port = ag.opts.wt.getPort(),
            .server_name = ag.opts.wt_host,
            .path = try arena.dupe(u8, path),
            .connect_headers = headers,
            .ipv6 = ag.opts.wt == .ip6,
            .skip_cert_verify = true,
            .loop = &ag.loop,
            .conn_config = .{
                .max_datagram_frame_size = (event_loop.ClientConfig{}).max_datagram_frame_size,
                .handshake_timeout = local_handshake_ms,
            },
        });
        s.started = true;
        s.state = .opening;
        s.client.start();
    }

    // ---- to the edge ----

    fn send(s: *Session, bytes: []const u8) void {
        const c = s.conn orelse return;
        var cs = c.session();
        _ = wt.forward(s.alloc(), &cs, c.sid, s.ctl, &s.ctl_held, bytes, false);
    }

    fn sendMessage(s: *Session, comptime write: anytype, args: anytype) void {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(s.alloc());
        @call(.auto, write, .{ s.alloc(), &out } ++ args) catch return;
        s.send(out.items);
    }

    fn sendRefuse(s: *Session, status: u16) void {
        s.sendMessage(wire.writeRefuse, .{status});
    }

    fn sendClose(s: *Session, code: u32, reason: []const u8) void {
        s.sendMessage(wire.writeClose, .{ code, reason });
    }

    /// Close the local server's session, if it is open.
    fn closeLocal(s: *Session, code: u32, reason: []const u8) void {
        if (s.state != .open) return;
        var ls = s.client.clientSession();
        ls.closeSessionWithError(s.local_sid, code, reason) catch {};
    }

    /// Tear down; `gone` is the side already over, not to be written to
    /// (its control stream, for the edge).
    fn end(s: *Session, gone: enum { local, edge, tunnel }) void {
        const ss = s.sessions;
        _ = ss.by_token.swapRemove(s.token);
        const c = s.conn;
        if (c) |conn| _ = ss.streams.remove(.{ .conn = conn.serial, .stream = s.ctl });
        for (s.pairs.values()) |p| {
            if (c) |conn| {
                _ = ss.streams.remove(.{ .conn = conn.serial, .stream = p.tunnel_stream });
                if (gone != .tunnel) {
                    var cs = conn.session();
                    if (!p.down_done) cs.resetStream(p.tunnel_stream, gone_error);
                    if (!p.up_done) cs.stopSending(p.tunnel_stream, gone_error);
                }
            }
            p.free(s.alloc());
        }
        s.pairs.clearRetainingCapacity();
        if (c) |conn| if (gone != .tunnel) {
            var cs = conn.session();
            // A control message still held dies with the session. The edge's
            // way ends once it has read ours.
            if (s.ctl_held.empty()) cs.closeStream(s.ctl) else cs.resetStream(s.ctl, gone_error);
        };
        s.conn = null;
        if (gone == .tunnel) s.closeLocal(gone_error, "tunnel gone");
        if (!s.started) return s.free();
        s.client.stop();
        ss.retired.append(s.alloc(), s) catch {};
    }

    // ---- the local server's streams ----

    fn pair(s: *Session, tunnel_stream: u64, local_stream: u64) ?*Pair {
        const a = s.alloc();
        const c = s.conn orelse return null;
        const p = a.create(Pair) catch return null;
        p.* = .{ .s = s, .tunnel_stream = tunnel_stream, .local_stream = local_stream };
        s.pairs.put(a, local_stream, p) catch {
            a.destroy(p);
            return null;
        };
        s.sessions.streams.put(a, .{ .conn = c.serial, .stream = tunnel_stream }, .{ .pair = p }) catch {
            _ = s.pairs.swapRemove(local_stream);
            a.destroy(p);
            return null;
        };
        return p;
    }

    /// The local server opened a stream: one to the edge for it.
    fn localStream(s: *Session, stream: u64, uni: bool) void {
        var ls = s.client.clientSession();
        const c = s.conn orelse return refuseLocal(&ls, stream, uni);
        var cs = c.session();
        const ts = cs.openBidiStream(c.sid, null) catch |err| {
            log.warn("a player's session: no tunnel stream for the local server's: {s}", .{@errorName(err)});
            return refuseLocal(&ls, stream, uni);
        };
        const p = s.pair(ts, stream) orelse {
            refuse(&cs, ts);
            return refuseLocal(&ls, stream, uni);
        };
        // Whatever the edge sends back on a unidirectional stream is nothing.
        p.up_done = uni;
        var head_buf: [wire.max_head]u8 = undefined;
        _ = wt.forward(s.alloc(), &cs, c.sid, ts, &p.to_tunnel, wire.head(&head_buf, .stream, s.token, uni), false);
    }
};

fn refuseLocal(ls: *event_loop.ClientSession, stream: u64, uni: bool) void {
    if (!uni) ls.resetStream(stream, gone_error);
    ls.stopSending(stream, gone_error);
}

/// A tunnel stream and a local server's stream, each the other's.
const Pair = struct {
    s: *Session,
    tunnel_stream: u64,
    local_stream: u64,
    /// The tunnel-to-local way is over, or never ran.
    up_done: bool = false,
    /// The local-to-tunnel way is over, or never ran.
    down_done: bool = false,
    /// We stopped reading the tunnel's stream: the local one is behind.
    tunnel_paused: bool = false,
    /// We stopped reading the local stream: the tunnel's is behind.
    local_paused: bool = false,
    to_local: wt.Held = .{},
    to_tunnel: wt.Held = .{},

    fn free(p: *Pair, a: std.mem.Allocator) void {
        p.to_local.bytes.deinit(a);
        p.to_tunnel.bytes.deinit(a);
        a.destroy(p);
    }

    fn alloc(p: *Pair) std.mem.Allocator {
        return p.s.alloc();
    }

    fn local(p: *Pair) event_loop.ClientSession {
        return p.s.client.clientSession();
    }

    /// Both ways are over: forget the pair.
    fn maybeDone(p: *Pair) void {
        if (!p.up_done or !p.down_done) return;
        const s = p.s;
        _ = s.pairs.swapRemove(p.local_stream);
        if (s.conn) |c| _ = s.sessions.streams.remove(.{ .conn = c.serial, .stream = p.tunnel_stream });
        p.free(s.alloc());
    }

    fn localBacklog(p: *Pair) u64 {
        return p.s.client.conn.streamBufferedBytes(p.local_stream) orelse 0;
    }

    fn tunnelBacklog(p: *Pair) u64 {
        const c = p.s.conn orelse return 0;
        return c.backlog(p.tunnel_stream);
    }

    fn fromTunnel(p: *Pair, data: []const u8, fin: bool) void {
        if (p.up_done) return;
        var ls = p.local();
        const sent = wt.forward(p.alloc(), &ls, p.s.local_sid, p.local_stream, &p.to_local, data, fin);
        if (fin) {
            if (sent) {
                p.up_done = true;
                p.maybeDone();
            }
            return;
        }
        if (!p.tunnel_paused and (!sent or p.localBacklog() > high_water)) {
            const c = p.s.conn orelse return;
            var cs = c.session();
            cs.pauseStream(p.tunnel_stream) catch return;
            p.tunnel_paused = true;
        }
    }

    fn fromLocal(p: *Pair, data: []const u8, fin: bool) void {
        if (p.down_done) return;
        const c = p.s.conn orelse return;
        var cs = c.session();
        const sent = wt.forward(p.alloc(), &cs, c.sid, p.tunnel_stream, &p.to_tunnel, data, fin);
        if (fin) {
            if (sent) {
                p.down_done = true;
                p.maybeDone();
            }
            return;
        }
        if (!p.local_paused and (!sent or p.tunnelBacklog() > high_water)) {
            var ls = p.local();
            ls.pauseStream(p.local_stream) catch return;
            p.local_paused = true;
        }
    }

    fn tunnelWritable(p: *Pair) void {
        const c = p.s.conn orelse return;
        var cs = c.session();
        const fin = p.to_tunnel.fin;
        if (!wt.drain(p.alloc(), &cs, c.sid, p.tunnel_stream, &p.to_tunnel)) return;
        if (fin) {
            p.down_done = true;
            return p.maybeDone();
        }
        p.resumeCaughtUp();
    }

    fn localWritable(p: *Pair) void {
        var ls = p.local();
        const fin = p.to_local.fin;
        if (!wt.drain(p.alloc(), &ls, p.s.local_sid, p.local_stream, &p.to_local)) return;
        if (fin) {
            p.up_done = true;
            return p.maybeDone();
        }
        p.resumeCaughtUp();
    }

    fn resumeCaughtUp(p: *Pair) void {
        if (p.tunnel_paused and p.to_local.empty() and p.localBacklog() < low_water) {
            p.tunnel_paused = false;
            if (p.s.conn) |c| {
                var cs = c.session();
                cs.resumeStream(p.tunnel_stream);
            }
        }
        if (p.local_paused and p.to_tunnel.empty() and p.tunnelBacklog() < low_water) {
            p.local_paused = false;
            var ls = p.local();
            ls.resumeStream(p.local_stream);
        }
    }

    fn tunnelReset(p: *Pair, code: u32) void {
        if (!p.up_done) {
            var ls = p.local();
            ls.resetStream(p.local_stream, code);
            p.to_local.bytes.clearAndFree(p.alloc());
            p.up_done = true;
        }
        p.maybeDone();
    }

    fn tunnelStopped(p: *Pair, code: u32) void {
        if (!p.down_done) {
            var ls = p.local();
            ls.stopSending(p.local_stream, code);
            p.to_tunnel.bytes.clearAndFree(p.alloc());
            p.down_done = true;
        }
        p.maybeDone();
    }

    fn localReset(p: *Pair, code: u32) void {
        if (!p.down_done) {
            if (p.s.conn) |c| {
                var cs = c.session();
                cs.resetStream(p.tunnel_stream, code);
            }
            p.to_tunnel.bytes.clearAndFree(p.alloc());
            p.down_done = true;
        }
        p.maybeDone();
    }

    fn localStopped(p: *Pair, code: u32) void {
        if (!p.up_done) {
            if (p.s.conn) |c| {
                var cs = c.session();
                cs.stopSending(p.tunnel_stream, code);
            }
            p.to_local.bytes.clearAndFree(p.alloc());
            p.up_done = true;
        }
        p.maybeDone();
    }
};

/// The local server's session's events.
const LocalHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;
    s: *Session,

    /// Null once the session has ended: its client is only stopping.
    fn live(self: *LocalHandler) ?*Session {
        return if (self.s.sessions.by_token.get(self.s.token) == self.s) self.s else null;
    }

    fn pairOf(self: *LocalHandler, stream: u64) ?*Pair {
        const s = self.live() orelse return null;
        return s.pairs.get(stream);
    }

    pub fn onSessionReady(self: *LocalHandler, _: *event_loop.ClientSession, session_id: u64, headers: []const qpack.Header) void {
        const s = self.live() orelse return;
        s.local_sid = session_id;
        s.state = .open;
        s.sendMessage(wire.writeAccept, .{headers});
    }

    pub fn onSessionRejected(self: *LocalHandler, _: *event_loop.ClientSession, _: u64, status: []const u8) void {
        const s = self.live() orelse return;
        s.sendRefuse(std.fmt.parseInt(u16, status, 10) catch 502);
        s.end(.local);
    }

    pub fn onSessionClosed(self: *LocalHandler, _: *event_loop.ClientSession, _: u64, error_code: u32, reason: []const u8) void {
        const s = self.live() orelse return;
        if (s.state == .open) s.sendClose(error_code, reason) else s.sendRefuse(502);
        s.end(.local);
    }

    pub fn onBidiStream(self: *LocalHandler, _: *event_loop.ClientSession, _: u64, stream_id: u64) void {
        const s = self.live() orelse return;
        s.localStream(stream_id, false);
    }

    pub fn onUniStream(self: *LocalHandler, _: *event_loop.ClientSession, _: u64, stream_id: u64) void {
        const s = self.live() orelse return;
        s.localStream(stream_id, true);
    }

    pub fn onStreamData(self: *LocalHandler, _: *event_loop.ClientSession, stream_id: u64, data: []const u8, fin: bool) void {
        if (self.pairOf(stream_id)) |p| p.fromLocal(data, fin);
    }

    pub fn onWritable(self: *LocalHandler, _: *event_loop.ClientSession, _: u64, stream_id: ?u64) void {
        if (self.pairOf(stream_id orelse return)) |p| p.localWritable();
    }

    pub fn onDatagram(self: *LocalHandler, _: *event_loop.ClientSession, _: u64, data: []const u8) void {
        const s = self.live() orelse return;
        const c = s.conn orelse return;
        const ag = s.sessions.agent();
        ag.datagram_buf.clearRetainingCapacity();
        ag.datagram_buf.ensureTotalCapacity(ag.alloc, wire.max_head + data.len) catch return;
        var buf: [8]u8 = undefined;
        ag.datagram_buf.appendSliceAssumeCapacity(buf[0..wire.putVarint(&buf, s.token)]);
        ag.datagram_buf.appendSliceAssumeCapacity(data);
        var cs = c.session();
        cs.sendDatagram(c.sid, ag.datagram_buf.items) catch {};
    }

    pub fn onStreamReset(self: *LocalHandler, _: *event_loop.ClientSession, _: u64, stream_id: u64, error_code: u32) void {
        if (self.pairOf(stream_id)) |p| p.localReset(error_code);
    }

    pub fn onStopSending(self: *LocalHandler, _: *event_loop.ClientSession, _: u64, stream_id: u64, error_code: u32) void {
        if (self.pairOf(stream_id)) |p| p.localStopped(error_code);
    }
};

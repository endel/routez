//! WebTransport relay: terminate the client's session, open the same session
//! on an upstream with quic-zig's client (on the worker's loop), and pair
//! streams and datagrams one to one.
//!
//! The downstream session is accepted only once the upstream accepted its
//! own, so the client can't open streams before there is somewhere to put
//! them. When one side's stream backs up (unsent bytes past `high_water`),
//! reading the paired stream on the other side pauses, so the sender is held
//! by QUIC flow control; `checkPaused` resumes it once the backlog drains.
//! Datagrams are unreliable and simply forwarded.
const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const ConnEntry = quic.connection_manager.ConnEntry;
const common = @import("../http/common.zig");
const router = @import("../router.zig");
const socket = @import("../net/socket.zig");
const timers = @import("../timers.zig");
const upstream = @import("../upstream.zig");
const Worker = @import("../worker.zig").Worker;

const log = std.log.scoped(.wt_relay);

const Key = struct { conn: u64, id: u64 };

const high_water = socket.high_water;
const low_water = socket.low_water;

/// WebTransport session error for "the other side went away".
const relay_error: u32 = 0;

pub fn Relay(comptime Listener: type) type {
    return struct {
        const Self = @This();

        sessions: std.AutoHashMapUnmanaged(Key, *RSession) = .empty,
        down_streams: std.AutoHashMapUnmanaged(Key, *Pair) = .empty,

        const UpClient = event_loop.Client(UpHandler);

        /// One relayed session.
        const RSession = struct {
            relay: *Self,
            worker: *Worker,
            arena_state: std.heap.ArenaAllocator,
            down_entry: *ConnEntry,
            down_conn: u64,
            down_sid: u64,
            peer: *upstream.Peer,
            up: *Up,
            up_sid: ?u64 = null,
            accepted: bool = false,
            by_up: std.AutoHashMapUnmanaged(u64, *Pair) = .empty,

            fn down(self: *RSession) event_loop.Session {
                return .{ .entry = self.down_entry };
            }

            fn upSession(self: *RSession) event_loop.ClientSession {
                const c = &self.up.client;
                return .{ .conn = c.conn, .h3_conn = c.h3_conn, .wt_conn = c.wt_conn, .stopping = &c.stopping };
            }

            fn pair(self: *RSession, down_stream: u64, up_stream: u64) void {
                const a = self.worker.alloc;
                const p = a.create(Pair) catch return;
                p.* = .{ .rs = self, .down_stream = down_stream, .up_stream = up_stream };
                self.relay.down_streams.put(a, .{ .conn = self.down_conn, .id = down_stream }, p) catch {
                    a.destroy(p);
                    return;
                };
                self.by_up.put(a, up_stream, p) catch {
                    _ = self.relay.down_streams.remove(.{ .conn = self.down_conn, .id = down_stream });
                    a.destroy(p);
                };
            }

            fn unpair(self: *RSession, p: *Pair) void {
                _ = self.relay.down_streams.remove(.{ .conn = self.down_conn, .id = p.down_stream });
                _ = self.by_up.remove(p.up_stream);
                self.worker.alloc.destroy(p);
            }

            /// Tear the relay down. `from_down`/`from_up` name the side that
            /// is already gone and must not be written to.
            fn close(self: *RSession, code: u32, reason: []const u8, from_down: bool, from_up: bool) void {
                const a = self.worker.alloc;
                if (!from_down) {
                    var d = self.down();
                    if (self.accepted) {
                        d.closeSessionWithError(self.down_sid, code, reason) catch {};
                    } else {
                        d.resetRequest(self.down_sid, @intFromEnum(event_loop.H3Error.connect_error));
                    }
                }
                if (!from_up) {
                    if (self.up_sid) |sid| {
                        var u = self.upSession();
                        u.closeSessionWithError(sid, code, reason) catch {};
                    }
                }
                var it = self.by_up.valueIterator();
                while (it.next()) |p| {
                    _ = self.relay.down_streams.remove(.{ .conn = self.down_conn, .id = p.*.down_stream });
                    a.destroy(p.*);
                }
                self.by_up.deinit(a);
                _ = self.relay.sessions.remove(.{ .conn = self.down_conn, .id = self.down_sid });
                self.peer.active -= 1;
                self.up.retire();
                self.arena_state.deinit();
                a.destroy(self);
            }
        };

        const Pair = struct {
            rs: *RSession,
            down_stream: u64,
            up_stream: u64,
            /// We stopped reading the client's stream: the upstream is behind.
            down_paused: bool = false,
            /// We stopped reading the upstream's stream: the client is behind.
            up_paused: bool = false,

            fn upBacklog(p: *const Pair) u64 {
                return p.rs.up.client.conn.streamBufferedBytes(p.up_stream) orelse 0;
            }

            fn downBacklog(p: *const Pair) u64 {
                const d = p.rs.down();
                return d.streamBufferedBytes(p.down_stream) orelse 0;
            }
        };

        /// The upstream client and its handler; outlives its session until
        /// the client is off the loop.
        const Up = struct {
            rs: ?*RSession,
            worker: *Worker,
            handler: UpHandler,
            client: UpClient,
            reap: timers.Deadline = .{ .callback = onReap },

            fn retire(self: *Up) void {
                self.rs = null;
                self.client.stop();
                self.worker.timers.set(&self.reap, 0);
            }

            fn flush(self: *Up) void {
                self.client.flush();
            }

            fn onReap(d: *timers.Deadline) void {
                const self: *Up = @fieldParentPtr("reap", d);
                if (!self.client.isStopped()) {
                    self.worker.timers.set(&self.reap, timers.Timers.tick_ms);
                    return;
                }
                self.client.deinit();
                self.worker.alloc.destroy(self);
            }
        };

        const UpHandler = struct {
            pub const protocol: event_loop.Protocol = .webtransport;
            up: *Up,

            fn rs(self: *UpHandler) ?*RSession {
                return self.up.rs;
            }

            pub fn onSessionReady(self: *UpHandler, _: *event_loop.ClientSession, session_id: u64, headers: []const qpack.Header) void {
                const r = self.rs() orelse return;
                r.up_sid = session_id;
                // Relay the negotiated subprotocol and other end-to-end headers.
                var extra: [32]qpack.Header = undefined;
                var n: usize = 0;
                for (headers) |h| {
                    if (h.name.len == 0 or h.name[0] == ':') continue;
                    if (common.isHopByHop(h.name) or std.mem.eql(u8, h.name, "date") or std.mem.eql(u8, h.name, "server")) continue;
                    if (n == extra.len) break;
                    extra[n] = h;
                    n += 1;
                }
                var d = r.down();
                d.acceptSessionWithHeaders(r.down_sid, extra[0..n]) catch return r.close(relay_error, "accept failed", false, false);
                r.accepted = true;
            }

            pub fn onSessionRejected(self: *UpHandler, _: *event_loop.ClientSession, _: u64, status: []const u8) void {
                const r = self.rs() orelse return;
                log.warn("upstream {s} refused the session: {s}", .{ r.peer.label, status });
                r.close(relay_error, "upstream refused", false, true);
            }

            pub fn onSessionClosed(self: *UpHandler, _: *event_loop.ClientSession, _: u64, error_code: u32, reason: []const u8) void {
                const r = self.rs() orelse return;
                r.close(error_code, reason, false, true);
            }

            pub fn onBidiStream(self: *UpHandler, _: *event_loop.ClientSession, _: u64, stream_id: u64) void {
                const r = self.rs() orelse return;
                var d = r.down();
                const ds = d.openBidiStream(r.down_sid, null) catch return;
                r.pair(ds, stream_id);
            }

            pub fn onUniStream(self: *UpHandler, _: *event_loop.ClientSession, _: u64, stream_id: u64) void {
                const r = self.rs() orelse return;
                var d = r.down();
                const ds = d.openUniStream(r.down_sid, null) catch return;
                r.pair(ds, stream_id);
            }

            pub fn onStreamData(self: *UpHandler, _: *event_loop.ClientSession, stream_id: u64, data: []const u8, fin: bool) void {
                const r = self.rs() orelse return;
                const p = r.by_up.get(stream_id) orelse return;
                var d = r.down();
                if (data.len > 0) d.sendStreamData(p.down_stream, data) catch {};
                if (fin) return d.closeStream(p.down_stream);
                if (!p.up_paused and p.downBacklog() > high_water) {
                    var u = r.upSession();
                    u.pauseStream(p.up_stream) catch return;
                    p.up_paused = true;
                }
            }

            pub fn onDatagram(self: *UpHandler, _: *event_loop.ClientSession, _: u64, data: []const u8) void {
                const r = self.rs() orelse return;
                var d = r.down();
                d.sendDatagram(r.down_sid, data) catch {};
            }

            pub fn onStreamReset(self: *UpHandler, _: *event_loop.ClientSession, _: u64, stream_id: u64, error_code: u32) void {
                const r = self.rs() orelse return;
                const p = r.by_up.get(stream_id) orelse return;
                var d = r.down();
                d.resetStream(p.down_stream, error_code);
            }

            pub fn onStopSending(self: *UpHandler, _: *event_loop.ClientSession, _: u64, stream_id: u64, error_code: u32) void {
                const r = self.rs() orelse return;
                const p = r.by_up.get(stream_id) orelse return;
                var d = r.down();
                d.stopSending(p.down_stream, error_code);
            }
        };

        // ---- downstream events, from the listener's handler ----

        pub fn onConnectRequest(self: *Self, l: *Listener, session: *event_loop.Session, session_id: u64, path: []const u8, headers: []const qpack.Header) void {
            const w = l.worker;
            // These headers are re-sent upstream verbatim.
            if (!@import("server.zig").validFields(headers)) return refuse(session, session_id);
            var authority: ?[]const u8 = null;
            for (headers) |h| {
                if (std.mem.eql(u8, h.name, ":authority")) authority = h.value;
            }
            const srv = l.vhosts.select(authority);
            var path_buf: [2048]u8 = undefined;
            const target = router.normalizeTarget(path, &path_buf) catch return refuse(session, session_id);
            const loc = router.matchLocation(srv, target.path) orelse return refuse(session, session_id);
            const name = loc.webtransport_pass orelse return refuse(session, session_id);
            const group = w.findGroup(name) orelse return refuse(session, session_id);
            var client_buf: [64]u8 = undefined;
            const client_addr = socket.formatSockaddr(session.entry.conn.peerAddress(), &client_buf);
            const peer = group.pick(client_addr, &.{}) orelse return refuse(session, session_id);

            self.open(w, session, session_id, path, headers, group, peer) catch |err| {
                log.warn("relay to {s}: {s}", .{ peer.label, @errorName(err) });
                refuse(session, session_id);
            };
        }

        fn refuse(session: *event_loop.Session, session_id: u64) void {
            const headers = [_]qpack.Header{.{ .name = ":status", .value = "404" }};
            session.sendResponse(session_id, &headers, "") catch {};
        }

        fn open(self: *Self, w: *Worker, session: *event_loop.Session, session_id: u64, path: []const u8, headers: []const qpack.Header, group: *upstream.Group, peer: *upstream.Peer) !void {
            const a = w.alloc;
            const r = try a.create(RSession);
            errdefer a.destroy(r);
            r.* = .{
                .relay = self,
                .worker = w,
                .arena_state = .init(a),
                .down_entry = session.entry,
                .down_conn = session.id(),
                .down_sid = session_id,
                .peer = peer,
                .up = undefined,
            };
            errdefer r.arena_state.deinit();
            const arena = r.arena_state.allocator();

            // Everything the client config borrows lives in the session arena.
            var fwd: std.ArrayListUnmanaged(qpack.Header) = .empty;
            for (headers) |h| {
                if (h.name.len == 0 or h.name[0] == ':') continue;
                if (common.isHopByHop(h.name)) continue;
                try fwd.append(arena, .{ .name = try arena.dupe(u8, h.name), .value = try arena.dupe(u8, h.value) });
            }
            var addr_buf: [64]u8 = undefined;
            const addr_text = try arena.dupe(u8, switch (peer.addr) {
                .ip4 => |ip| try std.fmt.bufPrint(&addr_buf, "{d}.{d}.{d}.{d}", .{ ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3] }),
                .ip6 => |ip| socket.formatIp6(ip.bytes, &addr_buf),
            });

            const cfg = group.cfg;
            const up = try a.create(Up);
            errdefer a.destroy(up);
            up.* = .{ .rs = r, .worker = w, .handler = .{ .up = up }, .client = undefined };
            up.client = try UpClient.init(a, &up.handler, .{
                .address = addr_text,
                .port = peer.addr.getPort(),
                .server_name = try arena.dupe(u8, peer.host),
                .path = try arena.dupe(u8, path),
                .connect_headers = fwd.items,
                .ipv6 = peer.addr == .ip6,
                .ca = if (cfg.tls_ca) |ca| .{ .file = ca } else if (cfg.tls_verify) .system else .none,
                .skip_cert_verify = cfg.tls_ca == null and !cfg.tls_verify,
                .loop = &w.loop,
            });
            r.up = up;
            try self.sessions.put(a, .{ .conn = r.down_conn, .id = session_id }, r);
            peer.active += 1;
            up.client.start();
        }

        fn sessionFor(self: *Self, session: *event_loop.Session, session_id: u64) ?*RSession {
            return self.sessions.get(.{ .conn = session.id(), .id = session_id });
        }

        pub fn onStream(self: *Self, session: *event_loop.Session, session_id: u64, stream_id: u64, bidi: bool) void {
            const r = self.sessionFor(session, session_id) orelse return;
            const sid = r.up_sid orelse return;
            var u = r.upSession();
            const us = (if (bidi) u.openBidiStream(sid, null) else u.openUniStream(sid, null)) catch {
                session.resetStream(stream_id, relay_error);
                return;
            };
            r.pair(stream_id, us);
            r.up.flush();
        }

        pub fn onStreamData(self: *Self, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
            const p = self.down_streams.get(.{ .conn = session.id(), .id = stream_id }) orelse return;
            const r = p.rs;
            var u = r.upSession();
            if (data.len > 0) u.sendStreamData(p.up_stream, data) catch {};
            if (fin) u.closeStream(p.up_stream);
            r.up.flush();
            if (!fin and !p.down_paused and p.upBacklog() > high_water) {
                session.pauseStream(stream_id) catch return;
                p.down_paused = true;
            }
        }

        /// Resume streams whose destination has caught up. Called on every
        /// worker tick.
        pub fn checkPaused(self: *Self) void {
            var it = self.down_streams.valueIterator();
            while (it.next()) |pp| {
                const p = pp.*;
                if (p.down_paused and p.upBacklog() < low_water) {
                    p.down_paused = false;
                    var d = p.rs.down();
                    d.resumeStream(p.down_stream);
                }
                if (p.up_paused and p.downBacklog() < low_water) {
                    p.up_paused = false;
                    var u = p.rs.upSession();
                    u.resumeStream(p.up_stream);
                    p.rs.up.flush();
                }
            }
        }

        pub fn onDatagram(self: *Self, session: *event_loop.Session, session_id: u64, data: []const u8) void {
            const r = self.sessionFor(session, session_id) orelse return;
            const sid = r.up_sid orelse return;
            var u = r.upSession();
            u.sendDatagram(sid, data) catch {};
            r.up.flush();
        }

        pub fn onStreamReset(self: *Self, session: *event_loop.Session, _: u64, stream_id: u64, error_code: u32) void {
            const p = self.down_streams.get(.{ .conn = session.id(), .id = stream_id }) orelse return;
            var u = p.rs.upSession();
            u.resetStream(p.up_stream, error_code);
            p.rs.up.flush();
        }

        pub fn onStopSending(self: *Self, session: *event_loop.Session, _: u64, stream_id: u64, error_code: u32) void {
            const p = self.down_streams.get(.{ .conn = session.id(), .id = stream_id }) orelse return;
            var u = p.rs.upSession();
            u.stopSending(p.up_stream, error_code);
            p.rs.up.flush();
        }

        pub fn onSessionClosed(self: *Self, session: *event_loop.Session, session_id: u64, error_code: u32, reason: []const u8) void {
            const r = self.sessionFor(session, session_id) orelse return;
            r.close(error_code, reason, true, false);
        }

        pub fn onWritable(_: *Self, _: *event_loop.Session, _: u64, _: ?u64) void {}

        pub fn onConnectionClosed(self: *Self, session: *event_loop.Session) void {
            const conn = session.id();
            var doomed: [64]*RSession = undefined;
            while (true) {
                var n: usize = 0;
                var it = self.sessions.iterator();
                while (it.next()) |e| {
                    if (e.key_ptr.conn != conn) continue;
                    doomed[n] = e.value_ptr.*;
                    n += 1;
                    if (n == doomed.len) break;
                }
                if (n == 0) return;
                for (doomed[0..n]) |r| r.close(relay_error, "client gone", true, false);
            }
        }
    };
}

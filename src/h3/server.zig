//! HTTP/3 listener: a quic-zig `Server` on the worker's loop, with each
//! request stream adapted to the exchange `Downstream` interface.
const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const config = @import("../config.zig");
const common = @import("../http/common.zig");
const exchange = @import("../exchange.zig");
const router = @import("../router.zig");
const socket = @import("../net/socket.zig");
const timers = @import("../timers.zig");
const tls = @import("../net/tls.zig");
const wt_relay = @import("wt_relay.zig");
const steering = @import("../steering.zig");

fn onForeign(ctx: ?*anyopaque, dg: *const event_loop.ForeignDatagram) void {
    const w: *Worker = @ptrCast(@alignCast(ctx.?));
    steering.registry.route(w.io, dg);
}
const worker_mod = @import("../worker.zig");
const Worker = worker_mod.Worker;
const Exchange = exchange.Exchange;
const Header = common.Header;

const log = std.log.scoped(.h3);

/// Request body that arrives after a pause but before quic-zig stops
/// delivering (the rest of the current poll). Flow control holds back
/// everything else, so past this something is wrong and the stream is reset.
const max_paused_body = 1024 * 1024;

/// Field names are lowercase tokens (after an optional ':' for pseudo-headers)
/// and values are VCHAR/SP/HTAB/obs-text: no CR, LF or NUL.
pub fn validFields(headers: []const qpack.Header) bool {
    for (headers) |h| {
        const name = if (h.name.len > 0 and h.name[0] == ':') h.name[1..] else h.name;
        if (!common.isToken(name)) return false;
        for (name) |c| if (std.ascii.isUpper(c)) return false;
        if (!common.isFieldValue(h.value)) return false;
    }
    return true;
}

test "field validation" {
    try std.testing.expect(validFields(&.{ .{ .name = ":path", .value = "/" }, .{ .name = "x-a", .value = "b c" } }));
    try std.testing.expect(!validFields(&.{.{ .name = "x-evil", .value = "a\r\nX-Injected: 1" }}));
    try std.testing.expect(!validFields(&.{.{ .name = "X-Upper", .value = "a" }}));
    try std.testing.expect(!validFields(&.{.{ .name = "bad name", .value = "a" }}));
    try std.testing.expect(!validFields(&.{.{ .name = "x", .value = "a\x00" }}));
}

pub fn Listener(comptime proto: event_loop.Protocol) type {
    return struct {
        const Self = @This();
        pub const Server = event_loop.Server(Handler);

        worker: *Worker,
        address: []const u8,
        port: u16,
        servers: std.ArrayListUnmanaged(*const config.Server) = .empty,
        vhosts: router.VirtualHosts = .{ .servers = &.{} },
        handler: Handler,
        server: Server,
        streams: std.AutoHashMapUnmanaged(StreamKey, *Stream) = .empty,
        relay: wt_relay.Relay(Self) = .{},
        alpn: [1][]const u8 = .{"h3"},

        /// `sock`, when given, is a bound socket to take over; it is ours
        /// even if this fails.
        pub fn create(w: *Worker, l: config.Listen, tc: *const tls.ServerConfig, sock: ?std.posix.socket_t) !*Self {
            errdefer if (sock) |fd| {
                _ = std.c.close(fd);
            };
            const self = try w.alloc.create(Self);
            errdefer w.alloc.destroy(self);
            self.* = .{
                .worker = w,
                .address = l.address,
                .port = l.port,
                .handler = .{ .listener = undefined },
                .server = undefined,
            };
            self.handler.listener = self;
            const certs = tc.certs;
            const is_v6 = std.mem.indexOfScalar(u8, l.address, ':') != null;
            // An explicit conn_config replaces quic-zig's defaults, so restate them.
            var conn_config: quic.connection.ConnectionConfig = .{
                .token_key = w.shared.quic_keys.retry,
                .max_idle_timeout = w.cfg.limits.quic_idle_timeout_ms,
            };
            if (proto != .h3) conn_config.max_datagram_frame_size = (event_loop.Config{}).max_datagram_frame_size;
            self.server = Server.init(w.alloc, &self.handler, .{
                .socket = sock,
                .conn_config = conn_config,
                .address = l.address,
                .port = l.port,
                .ipv6 = is_v6,
                .tls_config = .{
                    .cert_chain_der = certs[0].cert.cert_chain_der,
                    .private_key_bytes = certs[0].cert.private_key_bytes,
                    .private_key_algorithm = certs[0].cert.private_key_algorithm,
                    .certs = certs,
                    .alpn = &self.alpn,
                    .ticket_key = tc.ticket_key,
                },
                .loop = &w.loop,
                .reuse_port = true,
                .max_connections = w.cfg.limits.max_connections,
                .recv_buffer_size = 4 * 1024 * 1024,
                // Our id in every connection ID, so a sibling worker that gets
                // our packets after a client's address changes can pass them on.
                .quic_lb = steering.lbConfig(w.id),
                .foreign_datagram = .{ .ctx = w, .func = onForeign },
                .retry_token_key = w.shared.quic_keys.retry,
                .static_reset_key = w.shared.quic_keys.reset,
                .send_buffer_size = 4 * 1024 * 1024,
            }) catch |err| {
                if (sock == null) worker_mod.bindFailed("quic", l.address, l.port, err);
                return err;
            };
            if (w.id == 0) log.info("listening on {s}:{d} (quic{s})", .{ l.address, l.port, if (proto == .webtransport) ", webtransport" else "" });
            return self;
        }

        pub fn addServer(self: *Self, srv: *const config.Server) !void {
            try self.servers.append(self.worker.alloc, srv);
            self.vhosts = .{ .servers = self.servers.items };
        }

        pub fn start(self: *Self) void {
            self.server.start();
        }

        /// Close every connection (CONNECTION_CLOSE); in-flight requests fail.
        pub fn stop(self: *Self) void {
            self.server.stop();
        }

        pub fn liveConnections(self: *Self) usize {
            return self.server.conn_mgr.entries.items.len;
        }

        fn streamFor(self: *Self, session: *event_loop.Session, stream_id: u64) ?*Stream {
            return self.streams.get(.{ .conn = session.id(), .stream = stream_id });
        }

        fn removeStream(self: *Self, s: *Stream) void {
            _ = self.streams.remove(.{ .conn = s.conn_id, .stream = s.stream_id });
        }

        // ---- the quic-zig handler ----

        pub const Handler = struct {
            pub const protocol: event_loop.Protocol = proto;
            listener: *Self,

            pub fn onRequest(self: *Handler, session: *event_loop.Session, stream_id: u64, headers: []const qpack.Header) void {
                self.listener.startRequest(session, stream_id, headers);
            }

            pub fn onData(self: *Handler, session: *event_loop.Session, stream_id: u64, data: []const u8) void {
                const s = self.listener.streamFor(session, stream_id) orelse return;
                s.onBody(data);
            }

            pub fn onRequestEnd(self: *Handler, session: *event_loop.Session, stream_id: u64) void {
                const s = self.listener.streamFor(session, stream_id) orelse return;
                s.onEnd();
            }

            pub fn onRequestCancelled(self: *Handler, session: *event_loop.Session, stream_id: u64, _: u64) void {
                const s = self.listener.streamFor(session, stream_id) orelse return;
                s.gone();
            }

            pub fn onWritable(self: *Handler, session: *event_loop.Session, session_id: u64, stream_id: ?u64) void {
                const sid = stream_id orelse session_id;
                if (self.listener.streamFor(session, sid)) |s| return s.onWritable();
                if (proto == .webtransport) self.listener.relay.onWritable(session, session_id, stream_id);
            }

            pub fn onConnectionClosed(self: *Handler, session: *event_loop.Session) void {
                const l = self.listener;
                const conn = session.id();
                var doomed: std.ArrayListUnmanaged(*Stream) = .empty;
                defer doomed.deinit(l.worker.alloc);
                var it = l.streams.iterator();
                while (it.next()) |e| {
                    if (e.key_ptr.conn == conn) doomed.append(l.worker.alloc, e.value_ptr.*) catch {};
                }
                for (doomed.items) |s| s.gone();
                if (proto == .webtransport) l.relay.onConnectionClosed(session);
            }

            // WebTransport. Only a `.webtransport` server ever calls these.

            pub fn onConnectRequest(self: *Handler, session: *event_loop.Session, session_id: u64, path: []const u8, headers: []const qpack.Header) void {
                self.listener.relay.onConnectRequest(self.listener, session, session_id, path, headers);
            }

            pub fn onBidiStream(self: *Handler, session: *event_loop.Session, session_id: u64, stream_id: u64) void {
                self.listener.relay.onStream(session, session_id, stream_id, true);
            }

            pub fn onUniStream(self: *Handler, session: *event_loop.Session, session_id: u64, stream_id: u64) void {
                self.listener.relay.onStream(session, session_id, stream_id, false);
            }

            pub fn onStreamData(self: *Handler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
                self.listener.relay.onStreamData(session, stream_id, data, fin);
            }

            pub fn onDatagram(self: *Handler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
                self.listener.relay.onDatagram(session, session_id, data);
            }

            pub fn onStreamReset(self: *Handler, session: *event_loop.Session, session_id: u64, stream_id: u64, error_code: u32) void {
                self.listener.relay.onStreamReset(session, session_id, stream_id, error_code);
            }

            pub fn onStopSending(self: *Handler, session: *event_loop.Session, session_id: u64, stream_id: u64, error_code: u32) void {
                self.listener.relay.onStopSending(session, session_id, stream_id, error_code);
            }

            pub fn onSessionClosed(self: *Handler, session: *event_loop.Session, session_id: u64, error_code: u32, reason: []const u8) void {
                self.listener.relay.onSessionClosed(session, session_id, error_code, reason);
            }
        };

        // ---- requests ----

        fn startRequest(self: *Self, session: *event_loop.Session, stream_id: u64, headers: []const qpack.Header) void {
            const a = self.worker.alloc;
            var method: ?[]const u8 = null;
            var path: ?[]const u8 = null;
            var authority: ?[]const u8 = null;
            var scheme: []const u8 = "https";
            var content_length: ?u64 = null;
            var fwd: [256]Header = undefined;
            var n: usize = 0;
            var cookies: std.ArrayListUnmanaged(u8) = .empty;
            defer cookies.deinit(a);
            // These become HTTP/1.1 upstream: a CR or LF here would inject
            // headers or a whole request (RFC 9114 §4.2 makes them malformed).
            if (!validFields(headers)) return reject(session, stream_id, 400);
            for (headers) |h| {
                if (h.name.len > 0 and h.name[0] == ':') {
                    if (std.mem.eql(u8, h.name, ":method")) method = h.value;
                    if (std.mem.eql(u8, h.name, ":path")) path = h.value;
                    if (std.mem.eql(u8, h.name, ":authority")) authority = h.value;
                    if (std.mem.eql(u8, h.name, ":scheme")) scheme = h.value;
                    continue;
                }
                if (std.mem.eql(u8, h.name, "host")) {
                    if (authority == null) authority = h.value;
                    continue;
                }
                if (std.mem.eql(u8, h.name, "content-length")) {
                    content_length = std.fmt.parseInt(u64, h.value, 10) catch return reject(session, stream_id, 400);
                }
                // HTTP/3 splits cookies into separate fields; HTTP/1.1 wants one.
                if (std.mem.eql(u8, h.name, "cookie")) {
                    if (cookies.items.len > 0) cookies.appendSlice(a, "; ") catch {};
                    cookies.appendSlice(a, h.value) catch {};
                    continue;
                }
                // Connection-specific fields are malformed in HTTP/3 (RFC 9114 §4.2).
                if (std.mem.eql(u8, h.name, "connection") or std.mem.eql(u8, h.name, "transfer-encoding") or
                    std.mem.eql(u8, h.name, "keep-alive") or std.mem.eql(u8, h.name, "upgrade") or std.mem.eql(u8, h.name, "proxy-connection"))
                {
                    return reject(session, stream_id, 400);
                }
                if (n == fwd.len) return reject(session, stream_id, 431);
                fwd[n] = .{ .name = h.name, .value = h.value };
                n += 1;
            }
            if (cookies.items.len > 0 and n < fwd.len) {
                fwd[n] = .{ .name = "cookie", .value = cookies.items };
                n += 1;
            }
            const m = method orelse return reject(session, stream_id, 400);
            const p = path orelse return reject(session, stream_id, 400);

            const body: exchange.BodyMode = if (content_length) |cl|
                (if (cl > 0) .sized else .none)
            else if (std.mem.eql(u8, m, "GET") or std.mem.eql(u8, m, "HEAD"))
                .none
            else
                .unknown;

            const s = a.create(Stream) catch return reject(session, stream_id, 500);
            s.* = .{
                .listener = self,
                .entry = session.entry,
                .conn_id = session.id(),
                .stream_id = stream_id,
                .is_head = std.mem.eql(u8, m, "HEAD"),
            };
            self.streams.put(a, .{ .conn = s.conn_id, .stream = stream_id }, s) catch {
                a.destroy(s);
                return reject(session, stream_id, 500);
            };

            var addr_buf: [64]u8 = undefined;
            const peer = session.entry.conn.peerAddress();
            const client = socket.formatSockaddr(peer, &addr_buf);
            const ex = Exchange.create(self.worker, s.downstream(), .{
                .method = m,
                .target = p,
                .authority = authority,
                .headers = fwd[0..n],
                .content_length = if (body == .sized) content_length else null,
                .body = body,
                .protocol = .http3,
                .scheme = scheme,
                .client_addr = client,
                .client_ip = socket.ipKey(peer) orelse @splat(0),
                .vhosts = &self.vhosts,
            }) catch {
                s.destroy();
                return reject(session, stream_id, 500);
            };
            s.ex = ex;
            ex.start();
        }

        fn reject(session: *event_loop.Session, stream_id: u64, status: u16) void {
            var buf: [4]u8 = undefined;
            const code = std.fmt.bufPrint(&buf, "{d}", .{status}) catch unreachable;
            const headers = [_]qpack.Header{ .{ .name = ":status", .value = code }, .{ .name = "content-length", .value = "0" } };
            session.sendResponse(stream_id, &headers, "") catch {};
        }

        const StreamKey = struct { conn: u64, stream: u64 };

        /// One request stream, as the exchange's downstream.
        pub const Stream = struct {
            listener: *Self,
            entry: *quic.connection_manager.ConnEntry,
            conn_id: u64,
            stream_id: u64,
            ex: ?*Exchange = null,
            is_head: bool,
            ended: bool = false,
            paused: bool = false,
            body_done: bool = false,
            waiting_writable: bool = false,
            pending: std.ArrayListUnmanaged(u8) = .empty,
            /// Resumes a paused body, reports a failed write, or frees a
            /// detached stream, outside the exchange's call stack.
            deferred: timers.Deferred = .{ .callback = onDeferred },
            failed: bool = false,
            /// The exchange is done with us; free once no deferred callback is queued.
            detached: bool = false,

            fn session(self: *Stream) event_loop.Session {
                return .{ .entry = self.entry };
            }

            fn onBody(self: *Stream, data: []const u8) void {
                const ex = self.ex orelse return;
                if (self.paused or self.pending.items.len > 0) {
                    if (self.pending.items.len + data.len > max_paused_body) return self.resetAndGone();
                    self.pending.appendSlice(self.listener.worker.alloc, data) catch return self.resetAndGone();
                    return;
                }
                ex.onRequestBody(data);
            }

            fn onEnd(self: *Stream) void {
                if (self.ended) return;
                self.ended = true;
                if (self.paused or self.pending.items.len > 0) return;
                self.deliverEnd();
            }

            fn deliverEnd(self: *Stream) void {
                if (self.body_done) return;
                self.body_done = true;
                if (self.ex) |ex| ex.onRequestEnd();
            }

            fn onWritable(self: *Stream) void {
                self.waiting_writable = false;
                if (self.ex) |ex| ex.onDownstreamWritable();
            }

            /// The client or its connection went away.
            fn gone(self: *Stream) void {
                if (self.ex) |ex| {
                    self.ex = null;
                    ex.onDownstreamGone();
                }
                self.detach();
            }

            fn resetAndGone(self: *Stream) void {
                var s = self.session();
                s.resetRequest(self.stream_id, @intFromEnum(event_loop.H3Error.internal_error));
                self.gone();
            }

            fn onDeferred(d: *timers.Deferred) void {
                const self: *Stream = @fieldParentPtr("deferred", d);
                if (self.detached) return self.destroy();
                if (self.failed) return self.gone();
                if (self.paused) return;
                const ex = self.ex orelse return;
                if (self.pending.items.len > 0) {
                    const data = self.pending.toOwnedSlice(self.listener.worker.alloc) catch return;
                    defer self.listener.worker.alloc.free(data);
                    ex.onRequestBody(data);
                }
                if (self.ex == null or self.paused) return;
                if (self.ended) return self.deliverEnd();
                // Only now: what quic-zig held back must follow what we held.
                var s = self.session();
                s.resumeRequestBody(self.stream_id);
            }

            fn detach(self: *Stream) void {
                if (self.detached) return;
                self.detached = true;
                self.ex = null;
                self.listener.removeStream(self);
                if (!self.deferred.queued) self.destroy();
            }

            fn destroy(self: *Stream) void {
                const a = self.listener.worker.alloc;
                self.pending.deinit(a);
                a.destroy(self);
            }

            fn downstream(self: *Stream) exchange.Downstream {
                return .{ .ptr = self, .vtable = &vtable };
            }

            const vtable: exchange.Downstream.VTable = .{
                .sendHead = dsSendHead,
                .sendBody = dsSendBody,
                .finish = dsFinish,
                .abort = dsAbort,
                .buffered = dsBuffered,
                .setRequestBodyPaused = dsSetPaused,
                .startTunnel = dsStartTunnel,
            };

            fn cast(ptr: *anyopaque) *Stream {
                return @ptrCast(@alignCast(ptr));
            }

            fn dsSendHead(ptr: *anyopaque, r: *const exchange.Response) void {
                const self = cast(ptr);
                const a = self.listener.worker.alloc;
                var arena_state = std.heap.ArenaAllocator.init(a);
                defer arena_state.deinit();
                const arena = arena_state.allocator();

                var list: std.ArrayListUnmanaged(qpack.Header) = .empty;
                const status = std.fmt.allocPrint(arena, "{d}", .{r.status}) catch return self.fail();
                list.append(arena, .{ .name = ":status", .value = status }) catch return self.fail();
                const interim = r.status < 200;
                if (!interim) {
                    list.append(arena, .{ .name = "server", .value = "routez" }) catch return self.fail();
                    list.append(arena, .{ .name = "date", .value = self.listener.worker.dateHeader() }) catch return self.fail();
                    if (r.content_length) |cl| {
                        if (!common.statusHasNoBody(r.status)) {
                            const v = std.fmt.allocPrint(arena, "{d}", .{cl}) catch return self.fail();
                            list.append(arena, .{ .name = "content-length", .value = v }) catch return self.fail();
                        }
                    }
                }
                for (r.headers) |h| {
                    if (common.isHopByHop(h.name)) continue;
                    // Field names must be lowercase in HTTP/3.
                    const name = std.ascii.allocLowerString(arena, h.name) catch return self.fail();
                    list.append(arena, .{ .name = name, .value = h.value }) catch return self.fail();
                }
                var s = self.session();
                s.sendResponseHeaders(self.stream_id, list.items) catch return self.fail();
            }

            fn dsSendBody(ptr: *anyopaque, data: []const u8) void {
                const self = cast(ptr);
                if (self.is_head or data.len == 0) return;
                var s = self.session();
                s.sendResponseData(self.stream_id, data) catch return self.fail();
                if (!self.waiting_writable and (s.streamBufferedBytes(self.stream_id) orelse 0) > socket.high_water) {
                    self.waiting_writable = true;
                    s.notifyWritable(0, self.stream_id, socket.low_water) catch {
                        self.waiting_writable = false;
                    };
                }
            }

            fn dsFinish(ptr: *anyopaque) void {
                const self = cast(ptr);
                var s = self.session();
                s.finishResponse(self.stream_id, null) catch {};
                self.detach();
            }

            fn dsAbort(ptr: *anyopaque) void {
                const self = cast(ptr);
                var s = self.session();
                s.resetRequest(self.stream_id, @intFromEnum(event_loop.H3Error.internal_error));
                self.detach();
            }

            /// Writing to the stream failed; the exchange hears about it as
            /// the client going away, on a later iteration.
            fn fail(self: *Stream) void {
                if (self.failed) return;
                var s = self.session();
                s.resetRequest(self.stream_id, @intFromEnum(event_loop.H3Error.internal_error));
                self.failed = true;
                self.listener.worker.timers.defer_(&self.deferred);
            }

            fn dsBuffered(ptr: *anyopaque) usize {
                const self = cast(ptr);
                const s = self.session();
                return @intCast(s.streamBufferedBytes(self.stream_id) orelse 0);
            }

            fn dsSetPaused(ptr: *anyopaque, paused: bool) void {
                const self = cast(ptr);
                if (self.paused == paused) return;
                self.paused = paused;
                if (paused) {
                    // Leaves the body unread in QUIC, so the client's stream
                    // window holds it back.
                    var s = self.session();
                    s.pauseRequestBody(self.stream_id) catch {};
                    return;
                }
                // Deferred: we're inside an exchange callback.
                self.listener.worker.timers.defer_(&self.deferred);
            }

            fn dsStartTunnel(ptr: *anyopaque) void {
                // Upgrade has no meaning in HTTP/3 (that is extended CONNECT).
                dsAbort(ptr);
            }
        };
    };
}

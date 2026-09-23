//! Layer-4 TCP forwarding, the TCP half of `udp_proxy.zig`: bytes both ways
//! between a client and an upstream server, with nothing parsed and no TLS
//! terminated. For protocols routez doesn't speak (a database, an SSH or
//! game server) behind the same balancer, health checks and limits as the
//! HTTP proxy.
//!
//! The listener, its reload handover, `max_connections` and the per-IP count
//! are the worker's (`worker.Listener`, `worker.Client`); a tunnel here owns
//! only the two sockets and the bytes between them.
const std = @import("std");
const quic = @import("quic");
const xev = quic.event_loop.Xev;
const config = @import("config.zig");
const socket = @import("net/socket.zig");
const splice = @import("net/splice.zig");
const stats = @import("stats.zig");
const timers = @import("timers.zig");
const upstream = @import("upstream.zig");
const worker_mod = @import("worker.zig");
const Worker = worker_mod.Worker;

const log = std.log.scoped(.tcp_proxy);

/// Queued bytes past which a tunnel stops reading the other side. Below the
/// HTTP path's `high_water`: a byte relay gains nothing from reading far
/// ahead of a slow peer, and every queued chunk is heap.
const pause_above = 2 * socket.low_water;

/// Reads that filled the buffer in a row before a direction is handed to the
/// kernel. Small exchanges never reach it, which is the point: routez is
/// ahead of both competitors on the keep-alive layer-4 row, and a pipe there
/// would only add syscalls.
const splice_after = 4;

const Relay = if (splice.supported) splice.Relay(Tunnel) else void;

pub const Tunnel = struct {
    worker: *Worker,
    cfg: *const config.TcpProxy,
    peer: *upstream.Peer,
    client: Side(false),
    server: Side(true),
    deadline: timers.Deadline = .{ .callback = onIdleTimeout },
    /// The worker's connection bookkeeping: list links and the per-IP count.
    link: worker_mod.Client = .{ .kind = .tunnel },
    /// Sockets whose close has been delivered. Both abort together when a
    /// tunnel fails, so the tunnel outlives the first callback.
    sides_closed: u8 = 0,
    /// Bulk forwarding through the kernel, one per direction, started only
    /// once a direction has proved itself bulk. See `net/splice.zig`.
    up: Relay = undefined,
    down: Relay = undefined,

    /// One direction. Only the upstream side connects, which is what
    /// `Socket`'s `connects` parameter costs a completion for.
    fn Side(comptime connects: bool) type {
        return struct {
            const Self = @This();
            sock: socket.Socket(Self, connects),
            tunnel: *Tunnel,
            /// Sends this side's bytes on, and pauses when it falls behind.
            from_client: bool,
            /// Reads in a row that filled the buffer: a stream that keeps
            /// coming, and worth splicing.
            full_reads: u8 = 0,

            pub fn onSocketData(self: *Self, data: []const u8) void {
                self.tunnel.forward(self.from_client, data);
                if (comptime !splice.supported) return;
                if (data.len < socket.read_buffer_size) {
                    self.full_reads = 0;
                    return;
                }
                self.full_reads += 1;
                if (self.full_reads >= splice_after) self.tunnel.startRelay(self.from_client);
            }

            pub fn onSocketEof(self: *Self) void {
                self.tunnel.halfClose(self.from_client);
            }

            pub fn onSocketWritable(self: *Self) void {
                // This side drained: let the side feeding it read again.
                const t = self.tunnel;
                if (self.from_client) t.server.sock.resumeRead() else t.client.sock.resumeRead();
            }

            pub fn onSocketConnect(self: *Self, err: ?anyerror) void {
                self.tunnel.onConnected(err);
            }

            pub fn onSocketClosed(self: *Self) void {
                self.tunnel.onSideClosed();
            }
        };
    }

    pub fn fromClient(c: *worker_mod.Client) *Tunnel {
        return @alignCast(@fieldParentPtr("link", c));
    }

    /// The caller keeps the accepted socket on error, as `H1Conn.create` has
    /// it, and owns closing it.
    pub fn create(w: *Worker, cfg: *const config.TcpProxy, group: *upstream.Group, tcp: xev.TCP) !*Tunnel {
        var addr_buf: [64]u8 = undefined;
        // Only ip_hash reads the address, and formatting it costs a syscall.
        const client_addr = if (group.cfg.balance == .ip_hash) socket.peerAddress(tcp.fd, &addr_buf) else "";
        const peer = group.pick(client_addr, &.{}) orelse {
            log.warn("no upstream for :{d}", .{cfg.port});
            return error.NoPeer;
        };

        const self = try w.alloc.create(Tunnel);
        errdefer w.alloc.destroy(self);
        self.* = .{
            .worker = w,
            .cfg = cfg,
            .peer = peer,
            .client = .{ .sock = undefined, .tunnel = self, .from_client = true },
            .server = .{ .sock = undefined, .tunnel = self, .from_client = false },
            .up = if (splice.supported) .{ .owner = self, .from_client = true } else {},
            .down = if (splice.supported) .{ .owner = self, .from_client = false } else {},
        };
        // Connect first: nothing owns the accepted socket until it succeeds.
        try self.server.sock.connect(&self.server, &w.loop, &w.timers, w.alloc, peer.addr);
        self.client.sock.init(&self.client, &w.loop, &w.timers, w.alloc, tcp);
        peer.attach();
        w.addClient(&self.link);
        // Nothing flows until the upstream answers; the client's own reads
        // start there.
        w.timers.set(&self.deadline, group.cfg.connect_timeout_ms);
        return self;
    }

    fn onConnected(self: *Tunnel, err: ?anyerror) void {
        if (err) |e| {
            log.warn("connect to {s}: {s}", .{ self.peer.label, @errorName(e) });
            self.peer.recordFailure();
            return self.abort();
        }
        self.peer.recordSuccess();
        self.client.sock.startReading();
        self.touch();
    }

    /// Send one side's bytes on, and stop reading it while the other is
    /// behind; that side's writable callback resumes us. The two sockets are
    /// different types (only the upstream connects), hence the two arms.
    fn forward(self: *Tunnel, from_client: bool, data: []const u8) void {
        if (from_client) {
            self.server.sock.write(data);
            if (self.server.sock.buffered() >= pause_above) self.client.sock.pauseRead();
        } else {
            self.client.sock.write(data);
            if (self.client.sock.buffered() >= pause_above) self.server.sock.pauseRead();
        }
        self.touch();
    }

    /// One side sent everything it had: pass the FIN on and let the other
    /// direction finish.
    fn halfClose(self: *Tunnel, from_client: bool) void {
        if (from_client) self.server.sock.closeAfterFlush() else self.client.sock.closeAfterFlush();
        self.touch();
    }

    /// Hand one direction to the kernel. Bytes still queued for the far side
    /// would land after the spliced ones, so only a destination the kernel
    /// has caught up with can be taken over; a direction that never gets
    /// there keeps copying, which costs nothing it wasn't paying already.
    fn startRelay(self: *Tunnel, from_client: bool) void {
        if (comptime !splice.supported) return;
        // The two sockets are different types, hence the two arms, as in
        // `forward`.
        if (from_client) {
            self.handOver(&self.up, &self.client.sock, &self.server.sock);
        } else {
            self.handOver(&self.down, &self.server.sock, &self.client.sock);
        }
    }

    fn handOver(self: *Tunnel, relay: *Relay, src: anytype, dst: anytype) void {
        if (relay.isRunning()) return;
        if (!src.isOpen() or !dst.isOpen()) return;
        if (dst.writing or dst.buffered() != 0) return;
        // The relay's completions outlive this call; the fds have to too.
        self.client.sock.retain();
        self.server.sock.retain();
        if (!relay.start(&self.worker.loop, src.fd(), dst.fd())) {
            self.client.sock.release();
            self.server.sock.release();
            return;
        }
        src.beginRelay();
    }

    pub fn onRelayEof(self: *Tunnel, from_client: bool) void {
        if (from_client) self.client.sock.readEnded() else self.server.sock.readEnded();
    }

    pub fn onRelayError(self: *Tunnel, _: bool) void {
        self.abort();
    }

    pub fn onRelayProgress(self: *Tunnel, _: bool, n: usize) void {
        stats.add(&stats.tcp_spliced_bytes, n);
        self.touch();
    }

    /// Nothing is armed against the fds any more.
    pub fn onRelayDone(self: *Tunnel, _: bool) void {
        self.client.sock.release();
        self.server.sock.release();
    }

    pub fn abort(self: *Tunnel) void {
        self.client.sock.abort();
        self.server.sock.abort();
    }

    /// Both sockets outlived the worker's drain.
    pub fn abandon(self: *Tunnel) void {
        if (comptime splice.supported) {
            self.up.abandon();
            self.down.abandon();
        }
        _ = std.c.close(self.client.sock.fd());
        _ = std.c.close(self.server.sock.fd());
    }

    /// Called for each socket as it closes; the second one frees the tunnel.
    fn onSideClosed(self: *Tunnel) void {
        self.sides_closed += 1;
        if (self.sides_closed < 2) {
            // Let the side still open finish what it has queued.
            if (self.client.sock.state != .closed) self.client.sock.closeAfterFlush();
            if (self.server.sock.state != .closed) self.server.sock.closeAfterFlush();
            return;
        }
        const w = self.worker;
        w.timers.clear(&self.deadline);
        self.peer.detach();
        w.removeClient(&self.link);
        w.alloc.destroy(self);
    }

    fn touch(self: *Tunnel) void {
        self.worker.timers.set(&self.deadline, self.cfg.idle_timeout_ms);
    }

    fn onIdleTimeout(d: *timers.Deadline) void {
        const self: *Tunnel = @fieldParentPtr("deadline", d);
        // Still connecting: the upstream never answered.
        if (self.server.sock.connecting) self.peer.recordFailure();
        self.abort();
    }
};

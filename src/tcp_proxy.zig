//! Layer-4 TCP forwarding, the TCP half of `udp_proxy.zig`: bytes both ways
//! between a client and an upstream server, with nothing parsed and no TLS
//! terminated. For protocols routez doesn't speak (a database, an SSH or
//! game server) behind the same balancer, health checks and limits as the
//! HTTP proxy.
//!
//! The listener, its reload handover and `max_connections` are the worker's
//! (`worker.Listener`); a tunnel here owns only the two sockets.
const std = @import("std");
const quic = @import("quic");
const xev = quic.event_loop.Xev;
const config = @import("config.zig");
const socket = @import("net/socket.zig");
const timers = @import("timers.zig");
const upstream = @import("upstream.zig");
const worker_mod = @import("worker.zig");
const Worker = worker_mod.Worker;

const log = std.log.scoped(.tcp_proxy);

pub const Tunnel = struct {
    worker: *Worker,
    cfg: *const config.TcpProxy,
    peer: *upstream.Peer,
    client: Side(.client),
    server: Side(.server),
    deadline: timers.Deadline = .{ .callback = onIdleTimeout },
    /// Set once the upstream answers, so a failure to connect is the peer's.
    connected: bool = false,
    next: ?*Tunnel = null,
    prev: ?*Tunnel = null,

    const Which = enum { client, server };

    /// One direction's socket. The client's is accepted and the server's
    /// connects, which is what `Socket`'s `connects` parameter distinguishes.
    fn Side(comptime which: Which) type {
        return struct {
            const Self = @This();
            sock: socket.Socket(Self, which == .server),

            fn tunnel(self: *Self) *Tunnel {
                return @alignCast(@fieldParentPtr(@tagName(which), self));
            }

            pub fn onSocketData(self: *Self, data: []const u8) void {
                self.tunnel().forward(which, data);
            }

            pub fn onSocketEof(self: *Self) void {
                self.tunnel().halfClose(which);
            }

            pub fn onSocketWritable(self: *Self) void {
                // This side drained: let the other one read again.
                const t = self.tunnel();
                if (which == .client) t.server.sock.resumeRead() else t.client.sock.resumeRead();
            }

            pub fn onSocketConnect(self: *Self, err: ?anyerror) void {
                self.tunnel().onConnected(err);
            }

            pub fn onSocketClosed(self: *Self) void {
                self.tunnel().onSideClosed();
            }
        };
    }

    /// Takes the accepted socket: on success the tunnel owns it, and on
    /// failure it is closed here.
    pub fn create(w: *Worker, cfg: *const config.TcpProxy, group: *upstream.Group, tcp: xev.TCP) !void {
        var addr_buf: [64]u8 = undefined;
        const client_addr = socket.peerAddress(tcp.fd, &addr_buf);
        const peer = group.pick(client_addr, &.{}) orelse {
            log.warn("no upstream for :{d}", .{cfg.port});
            _ = std.c.close(tcp.fd);
            return error.NoPeer;
        };

        const self = try w.alloc.create(Tunnel);
        errdefer w.alloc.destroy(self);
        self.* = .{ .worker = w, .cfg = cfg, .peer = peer, .client = undefined, .server = undefined };
        self.client.sock.init(&self.client, &w.loop, &w.timers, w.alloc, tcp);
        self.server.sock.connect(&self.server, &w.loop, &w.timers, w.alloc, peer.addr) catch |err| {
            log.warn("connect to {s}: {s}", .{ peer.label, @errorName(err) });
            peer.recordFailure();
            self.client.sock.abort();
            return err;
        };
        peer.active += 1;
        w.addTunnel(self);
        // Nothing flows until the upstream answers; the client's own reads
        // start there.
        w.timers.set(&self.deadline, group.cfg.connect_timeout_ms);
    }

    fn onConnected(self: *Tunnel, err: ?anyerror) void {
        if (err) |e| {
            log.warn("connect to {s}: {s}", .{ self.peer.label, @errorName(e) });
            self.peer.recordFailure();
            return self.abort();
        }
        self.connected = true;
        self.peer.recordSuccess();
        self.client.sock.startReading();
        self.touch();
    }

    fn forward(self: *Tunnel, comptime from: Which, data: []const u8) void {
        const out = if (from == .client) &self.server.sock else &self.client.sock;
        const in = if (from == .client) &self.client.sock else &self.server.sock;
        out.write(data);
        // Stop reading this side while the other is behind; its writable
        // callback resumes us.
        if (out.buffered() >= socket.high_water) in.pauseRead();
        self.touch();
    }

    /// One side sent everything it had: pass the FIN on and let the other
    /// direction finish.
    fn halfClose(self: *Tunnel, comptime from: Which) void {
        if (from == .client) self.server.sock.closeAfterFlush() else self.client.sock.closeAfterFlush();
        self.touch();
    }

    fn abort(self: *Tunnel) void {
        self.client.sock.abort();
        self.server.sock.abort();
    }

    /// Called for each socket as it closes; the last one frees the tunnel.
    fn onSideClosed(self: *Tunnel) void {
        if (self.client.sock.state != .closed or self.server.sock.state != .closed) {
            return self.abort();
        }
        const w = self.worker;
        w.timers.clear(&self.deadline);
        self.peer.active -= 1;
        w.removeTunnel(self);
        w.alloc.destroy(self);
    }

    fn touch(self: *Tunnel) void {
        self.worker.timers.set(&self.deadline, self.cfg.idle_timeout_ms);
    }

    fn onIdleTimeout(d: *timers.Deadline) void {
        const self: *Tunnel = @fieldParentPtr("deadline", d);
        if (!self.connected) self.peer.recordFailure();
        self.abort();
    }

    /// The worker is stopping: a layer-4 tunnel has no request boundary to
    /// wait for.
    pub fn stop(self: *Tunnel) void {
        self.abort();
    }
};

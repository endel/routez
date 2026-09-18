//! Hands a QUIC datagram to the worker that owns its connection.
//!
//! Every worker binds the same UDP port with SO_REUSEPORT, and the kernel
//! picks a socket by 4-tuple. When a client's address changes (NAT
//! rebinding, a network switch) its packets can land on another worker. Each
//! worker's QUIC server encodes its own id in every connection ID it issues
//! (QUIC-LB); a server that receives a packet for another id hands it here,
//! and the owner injects it on its own loop thread.
//!
//! The registry spans config generations, so during a reload the old and the
//! new workers still reach each other's connections.
const std = @import("std");
const quic = @import("quic");
const xev = quic.event_loop.Xev;
const posix = std.posix;

pub const Datagram = struct {
    bytes: []u8,
    peer: posix.sockaddr.storage,
    local: posix.sockaddr.storage,
    ecn: u2,
};

/// A worker's queue of datagrams handed over by other workers.
pub const Inbox = struct {
    io: std.Io,
    alloc: std.mem.Allocator,
    mutex: std.Io.Mutex = .init,
    queue: std.ArrayListUnmanaged(Datagram) = .empty,
    wake: xev.Async,
    wake_c: xev.Completion = .{},
    /// Upper bound on queued bytes; beyond it datagrams are dropped, as the
    /// network would.
    queued_bytes: usize = 0,

    const max_queued_bytes = 4 * 1024 * 1024;

    pub fn init(io: std.Io, alloc: std.mem.Allocator) !Inbox {
        return .{ .io = io, .alloc = alloc, .wake = try xev.Async.init() };
    }

    pub fn deinit(self: *Inbox) void {
        for (self.queue.items) |d| self.alloc.free(d.bytes);
        self.queue.deinit(self.alloc);
        self.wake.deinit();
    }

    /// Called from another worker's thread.
    pub fn push(self: *Inbox, dg: *const quic.event_loop.ForeignDatagram) void {
        const copy = self.alloc.dupe(u8, dg.bytes) catch return;
        self.mutex.lockUncancelable(self.io);
        const accepted = self.queued_bytes + copy.len <= max_queued_bytes;
        if (accepted) {
            self.queue.append(self.alloc, .{ .bytes = copy, .peer = dg.peer, .local = dg.local, .ecn = dg.ecn }) catch {};
            self.queued_bytes += copy.len;
        }
        self.mutex.unlock(self.io);
        if (!accepted) return self.alloc.free(copy);
        self.wake.notify() catch {};
    }

    /// Take everything queued; the caller frees each `bytes`.
    pub fn drain(self: *Inbox, out: *std.ArrayListUnmanaged(Datagram)) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        std.mem.swap(std.ArrayListUnmanaged(Datagram), out, &self.queue);
        self.queued_bytes = 0;
    }
};

/// Process-wide map from QUIC-LB server id to the owning worker's inbox.
pub const Registry = struct {
    mutex: std.Io.Mutex = .init,
    map: std.AutoHashMapUnmanaged(u16, *Inbox) = .empty,

    pub fn register(self: *Registry, io: std.Io, alloc: std.mem.Allocator, id: u16, inbox: *Inbox) !void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        try self.map.put(alloc, id, inbox);
    }

    pub fn unregister(self: *Registry, io: std.Io, id: u16) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        _ = self.map.remove(id);
    }

    /// Hand `dg` to its owner, if that worker still exists.
    pub fn route(self: *Registry, io: std.Io, dg: *const quic.event_loop.ForeignDatagram) void {
        if (dg.server_id.len != 2) return;
        const id = std.mem.readInt(u16, dg.server_id[0..2], .big);
        self.mutex.lockUncancelable(io);
        const inbox = self.map.get(id);
        // Pushing under the registry lock keeps the inbox alive: a worker
        // unregisters before freeing it.
        if (inbox) |i| i.push(dg);
        self.mutex.unlock(io);
    }
};

pub var registry: Registry = .{};

/// The QUIC-LB server id for a worker. Ids of live workers never collide:
/// worker ids only grow, and 65535 generations of workers would have to
/// overlap for two to share one.
pub fn serverId(worker_id: usize) u16 {
    return @truncate(worker_id + 1);
}

pub fn lbConfig(worker_id: usize) quic.quic_lb.Config {
    var cfg: quic.quic_lb.Config = .{ .config_id = 0, .server_id_len = 2, .nonce_len = 8 };
    std.mem.writeInt(u16, cfg.server_id[0..2], serverId(worker_id), .big);
    return cfg;
}

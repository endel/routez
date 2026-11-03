//! Which worker holds each tunnel, and how an upstream connection gets there.
//!
//! An agent's session lands on whichever worker the kernel handed its first
//! packet; a request for its tunnel lands on any worker. The request's
//! worker opens a socketpair, keeps one end as an ordinary upstream
//! connection (`upstream.Peer.acquire`) and hands the other end here. The
//! tunnel's worker relays that end over a stream of the session
//! (`edge.zig`). The kernel's socket buffers then carry the bytes, and the
//! backpressure, between the two threads; nothing else is shared.
const std = @import("std");
const quic = @import("quic");
const xev = quic.event_loop.Xev;

/// One end of a socketpair, for the tunnel `id`.
pub const Handoff = struct { id: u64, fd: std.posix.fd_t };

/// A worker's queue of handed-off connections.
pub const Inbox = struct {
    io: std.Io,
    alloc: std.mem.Allocator,
    mutex: std.Io.Mutex = .init,
    queue: std.ArrayListUnmanaged(Handoff) = .empty,
    wake: xev.Async,
    wake_c: xev.Completion = .{},

    pub fn init(io: std.Io, alloc: std.mem.Allocator) !Inbox {
        return .{ .io = io, .alloc = alloc, .wake = try xev.Async.init() };
    }

    /// After `Registry.dropInbox`: nothing can be queued any more.
    pub fn deinit(self: *Inbox) void {
        for (self.queue.items) |h| _ = std.c.close(h.fd);
        self.queue.deinit(self.alloc);
        self.wake.deinit();
    }

    fn push(self: *Inbox, h: Handoff) !void {
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            try self.queue.append(self.alloc, h);
        }
        self.wake.notify() catch {}; // outside the lock, which `drain` waits on
    }

    /// Take everything queued; the caller owns each fd.
    pub fn drain(self: *Inbox, out: *std.ArrayListUnmanaged(Handoff)) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        std.mem.swap(std.ArrayListUnmanaged(Handoff), out, &self.queue);
    }
};

/// Process-wide map from tunnel name to the worker holding it. It spans
/// config generations, so a request on a new generation still reaches a
/// tunnel an old one holds while it drains.
pub const Registry = struct {
    mutex: std.Io.Mutex = .init,
    /// Keys are owned here.
    by_name: std.StringHashMapUnmanaged(Entry) = .empty,
    /// A tunnel that comes back under its old name gets a new id, so a
    /// connection handed to the one before it isn't relayed to it.
    next_id: u64 = 1,

    const Entry = struct { id: u64, inbox: *Inbox, draining: bool = false };
    const gpa = std.heap.smp_allocator;

    /// Take `name` for a tunnel whose streams `inbox` relays; its id. A
    /// draining holder gives it up: that is its agent coming back.
    pub fn claim(self: *Registry, io: std.Io, name: []const u8, inbox: *Inbox) error{ Taken, OutOfMemory }!u64 {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const gop = try self.by_name.getOrPut(gpa, name);
        if (gop.found_existing and !gop.value_ptr.draining) return error.Taken;
        if (!gop.found_existing) gop.key_ptr.* = gpa.dupe(u8, name) catch |err| {
            self.by_name.removeByPtr(gop.key_ptr);
            return err;
        };
        const id = self.next_id;
        self.next_id += 1;
        gop.value_ptr.* = .{ .id = id, .inbox = inbox };
        return id;
    }

    /// Tunnel `id`'s worker is stopping: it keeps `name` until its agent,
    /// told to go, comes back on a worker that isn't.
    pub fn drain(self: *Registry, io: std.Io, name: []const u8, id: u64) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const e = self.by_name.getPtr(name) orelse return;
        if (e.id == id) e.draining = true;
    }

    /// Give `name` up, if tunnel `id` still holds it.
    pub fn release(self: *Registry, io: std.Io, name: []const u8, id: u64) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const e = self.by_name.getEntry(name) orelse return;
        if (e.value_ptr.id != id) return;
        const key = e.key_ptr.*;
        self.by_name.removeByPtr(e.key_ptr);
        gpa.free(key);
    }

    pub fn has(self: *Registry, io: std.Io, name: []const u8) bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.by_name.contains(name);
    }

    /// Pass `fd` to the worker holding `name`, which owns it from here on;
    /// whether that is another worker than the one `from` belongs to. On
    /// error the caller still owns it.
    pub fn handOff(self: *Registry, io: std.Io, name: []const u8, fd: std.posix.fd_t, from: *const Inbox) error{ NoTunnel, OutOfMemory }!bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const e = self.by_name.get(name) orelse return error.NoTunnel;
        try e.inbox.push(.{ .id = e.id, .fd = fd });
        return e.inbox != from;
    }

    /// A worker is going away: forget every tunnel it held. Held under the
    /// lock `handOff` takes, so nothing reaches the inbox after this.
    pub fn dropInbox(self: *Registry, io: std.Io, inbox: *Inbox) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        while (true) {
            var it = self.by_name.iterator();
            const e = while (it.next()) |e| {
                if (e.value_ptr.inbox == inbox) break e;
            } else return;
            const key = e.key_ptr.*;
            self.by_name.removeByPtr(e.key_ptr);
            gpa.free(key);
        }
    }
};

pub var registry: Registry = .{};

test "a name is held by one tunnel at a time" {
    const io = std.testing.io;
    var r: Registry = .{};
    var inbox = try Inbox.init(io, std.testing.allocator);
    defer inbox.deinit();
    const first = try r.claim(io, "game", &inbox);
    try std.testing.expectError(error.Taken, r.claim(io, "game", &inbox));
    try std.testing.expect(r.has(io, "game"));

    // A stale release (an older tunnel by that name) leaves it alone.
    r.release(io, "game", first + 100);
    try std.testing.expect(r.has(io, "game"));
    r.release(io, "game", first);
    try std.testing.expect(!r.has(io, "game"));
    try std.testing.expectError(error.NoTunnel, r.handOff(io, "game", -1, &inbox));

    const second = try r.claim(io, "game", &inbox);
    try std.testing.expect(second != first);
    // Draining, it goes to the next claim; the old holder's release is stale.
    r.drain(io, "game", second);
    const third = try r.claim(io, "game", &inbox);
    r.release(io, "game", second);
    try std.testing.expect(r.has(io, "game"));
    try std.testing.expectError(error.Taken, r.claim(io, "game", &inbox));
    _ = third;
    _ = try r.claim(io, "other", &inbox);
    r.dropInbox(io, &inbox);
    try std.testing.expect(!r.has(io, "game") and !r.has(io, "other"));
    r.by_name.deinit(Registry.gpa);
}

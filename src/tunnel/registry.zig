//! Which worker holds each tunnel, and how an upstream connection gets there.
//!
//! An agent's session lands on whichever worker the kernel handed its first
//! packet; a request for its tunnel lands on any worker. The request's
//! worker opens a socketpair, keeps one end as an ordinary upstream
//! connection (`upstream.Peer.acquire`) and hands the other end here. The
//! tunnel's worker relays that end over a stream of the session
//! (`edge.zig`). The kernel's socket buffers then carry the bytes, and the
//! backpressure, between the two threads; nothing else is shared.
//!
//! A player's WebTransport session is ended on its own worker (`players.zig`)
//! and gets a token here, naming both workers. Its streams cross as
//! socketpairs, either way, and its datagrams through the inboxes' queues:
//! they are unreliable, so a full queue drops them.
const std = @import("std");
const quic = @import("quic");
const xev = quic.event_loop.Xev;

/// One end of a socketpair, and what to do with it.
pub const Handoff = struct {
    fd: std.posix.fd_t,
    to: union(enum) {
        /// Open a stream to the agent of tunnel `id` and relay the fd on it.
        agent: u64,
        /// The same, for a player's new session: its control stream.
        session: u64,
        /// Open a stream to the player of session `token`.
        player: struct { token: u64, uni: bool },
    },
};

/// A datagram queued for a worker: for an agent, `tunnel` is its tunnel's id
/// and the token goes ahead of the bytes; for a player, `tunnel` is 0.
pub const Datagram = struct { tunnel: u64, token: u64, off: u32, len: u32 };

pub const Datagrams = struct {
    list: std.ArrayListUnmanaged(Datagram) = .empty,
    bytes: std.ArrayListUnmanaged(u8) = .empty,

    pub fn data(self: *const Datagrams, d: Datagram) []const u8 {
        return self.bytes.items[d.off..][0..d.len];
    }

    pub fn clear(self: *Datagrams) void {
        self.list.clearRetainingCapacity();
        self.bytes.clearRetainingCapacity();
    }

    pub fn deinit(self: *Datagrams, a: std.mem.Allocator) void {
        self.list.deinit(a);
        self.bytes.deinit(a);
    }
};

/// Past this many queued for one worker, datagrams are dropped.
const max_queued_datagrams = 4096;

/// A worker's queue of handed-off connections and datagrams.
pub const Inbox = struct {
    io: std.Io,
    /// Thread-safe: other workers queue with it.
    alloc: std.mem.Allocator,
    mutex: std.Io.Mutex = .init,
    queue: std.ArrayListUnmanaged(Handoff) = .empty,
    datagrams: Datagrams = .{},
    wake: xev.Async,
    wake_c: xev.Completion = .{},

    pub fn init(io: std.Io, alloc: std.mem.Allocator) !Inbox {
        return .{ .io = io, .alloc = alloc, .wake = try xev.Async.init() };
    }

    /// After `Registry.dropInbox`: nothing can be queued any more.
    pub fn deinit(self: *Inbox) void {
        for (self.queue.items) |h| _ = std.c.close(h.fd);
        self.queue.deinit(self.alloc);
        self.datagrams.deinit(self.alloc);
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

    fn pushDatagram(self: *Inbox, tunnel: u64, token: u64, bytes: []const u8) void {
        const first = blk: {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const q = &self.datagrams;
            if (q.list.items.len >= max_queued_datagrams) return;
            const off = q.bytes.items.len;
            q.bytes.appendSlice(self.alloc, bytes) catch return;
            q.list.append(self.alloc, .{ .tunnel = tunnel, .token = token, .off = @intCast(off), .len = @intCast(bytes.len) }) catch {
                q.bytes.items.len = off;
                return;
            };
            break :blk q.list.items.len == 1 and self.queue.items.len == 0;
        };
        // One wake per batch: the drain takes everything queued.
        if (first) self.wake.notify() catch {};
    }

    /// Take everything queued, swapping in the caller's (emptied) lists;
    /// the caller owns each fd.
    pub fn drain(self: *Inbox, out: *std.ArrayListUnmanaged(Handoff), dgrams: *Datagrams) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        std.mem.swap(std.ArrayListUnmanaged(Handoff), out, &self.queue);
        std.mem.swap(Datagrams, dgrams, &self.datagrams);
    }
};

/// Process-wide map from tunnel name to the worker holding it, and from
/// players' session tokens to the workers on both ends. It spans config
/// generations, so a request on a new generation still reaches a tunnel an
/// old one holds while it drains.
pub const Registry = struct {
    mutex: std.Io.Mutex = .init,
    /// Keys are owned here.
    by_name: std.StringHashMapUnmanaged(Entry) = .empty,
    sessions: std.AutoHashMapUnmanaged(u64, Session) = .empty,
    /// A tunnel that comes back under its old name gets a new id, so a
    /// connection handed to the one before it isn't relayed to it.
    next_id: u64 = 1,
    next_token: u64 = 1,

    const Entry = struct { id: u64, inbox: *Inbox, draining: bool = false };
    /// A player's session through tunnel `tunnel`: `agent` is the inbox of
    /// the tunnel's worker, `player` the one of the player's. It keeps the
    /// tunnel it opened on, even once the name has moved to another.
    const Session = struct { tunnel: u64, agent: *Inbox, player: *Inbox };
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
        try e.inbox.push(.{ .fd = fd, .to = .{ .agent = e.id } });
        return e.inbox != from;
    }

    // ---- players' sessions ----

    /// A token for a player's session through tunnel `name`, whose events
    /// go to `player`; the tunnel's id, and whether another worker holds it.
    pub fn openSession(self: *Registry, io: std.Io, name: []const u8, player: *Inbox) error{ NoTunnel, OutOfMemory }!struct { token: u64, tunnel: u64, remote: bool } {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const e = self.by_name.get(name) orelse return error.NoTunnel;
        const token = self.next_token;
        try self.sessions.put(gpa, token, .{ .tunnel = e.id, .agent = e.inbox, .player = player });
        self.next_token += 1;
        return .{ .token = token, .tunnel = e.id, .remote = e.inbox != player };
    }

    pub fn closeSession(self: *Registry, io: std.Io, token: u64) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        _ = self.sessions.remove(token);
    }

    /// Pass `fd` to session `token`'s tunnel, for a stream to its agent:
    /// the session's control stream (`control`), or one of its streams. On
    /// error the caller still owns it.
    pub fn toAgent(self: *Registry, io: std.Io, token: u64, fd: std.posix.fd_t, control: bool) error{ NoSession, OutOfMemory }!void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const s = self.sessions.get(token) orelse return error.NoSession;
        try s.agent.push(.{ .fd = fd, .to = if (control) .{ .session = s.tunnel } else .{ .agent = s.tunnel } });
    }

    /// Pass `fd` to session `token`'s player, if the session is tunnel
    /// `tunnel`'s: an agent names only its own. On error the caller still
    /// owns it.
    pub fn toPlayer(self: *Registry, io: std.Io, token: u64, tunnel: u64, fd: std.posix.fd_t, uni: bool) error{ NoSession, OutOfMemory }!void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const s = self.sessions.get(token) orelse return error.NoSession;
        if (s.tunnel != tunnel) return error.NoSession;
        try s.player.push(.{ .fd = fd, .to = .{ .player = .{ .token = token, .uni = uni } } });
    }

    pub fn datagramToAgent(self: *Registry, io: std.Io, token: u64, bytes: []const u8) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const s = self.sessions.get(token) orelse return;
        s.agent.pushDatagram(s.tunnel, token, bytes);
    }

    /// As `toPlayer`, for a datagram.
    pub fn datagramToPlayer(self: *Registry, io: std.Io, token: u64, tunnel: u64, bytes: []const u8) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const s = self.sessions.get(token) orelse return;
        if (s.tunnel != tunnel) return;
        s.player.pushDatagram(0, token, bytes);
    }

    /// A worker is going away: forget every tunnel and session it held.
    /// Held under the lock the pushes take, so nothing reaches the inbox
    /// after this.
    pub fn dropInbox(self: *Registry, io: std.Io, inbox: *Inbox) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        while (true) {
            var it = self.by_name.iterator();
            const e = while (it.next()) |e| {
                if (e.value_ptr.inbox == inbox) break e;
            } else break;
            const key = e.key_ptr.*;
            self.by_name.removeByPtr(e.key_ptr);
            gpa.free(key);
        }
        while (true) {
            var it = self.sessions.iterator();
            const token = while (it.next()) |e| {
                if (e.value_ptr.agent == inbox or e.value_ptr.player == inbox) break e.key_ptr.*;
            } else return;
            _ = self.sessions.remove(token);
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

test "a session's streams and datagrams reach only its own tunnel and player" {
    const io = std.testing.io;
    var r: Registry = .{};
    var agent = try Inbox.init(io, std.testing.allocator);
    defer agent.deinit();
    var player = try Inbox.init(io, std.testing.allocator);
    defer player.deinit();
    const id = try r.claim(io, "game", &agent);
    const s = try r.openSession(io, "game", &player);
    try std.testing.expectEqual(id, s.tunnel);

    // Another tunnel can't reach into it.
    try std.testing.expectError(error.NoSession, r.toPlayer(io, s.token, id + 1, -1, false));
    r.datagramToPlayer(io, s.token, id + 1, "forged");
    r.datagramToPlayer(io, s.token, id, "hello");
    r.datagramToAgent(io, s.token, "hi");

    var got: std.ArrayListUnmanaged(Handoff) = .empty;
    defer got.deinit(std.testing.allocator);
    var dgrams: Datagrams = .{};
    defer dgrams.deinit(std.testing.allocator);
    player.drain(&got, &dgrams);
    try std.testing.expectEqual(@as(usize, 1), dgrams.list.items.len);
    try std.testing.expectEqualStrings("hello", dgrams.data(dgrams.list.items[0]));
    dgrams.clear();
    agent.drain(&got, &dgrams);
    try std.testing.expectEqual(id, dgrams.list.items[0].tunnel);
    try std.testing.expectEqualStrings("hi", dgrams.data(dgrams.list.items[0]));

    // The session outlives its tunnel's name moving on.
    r.release(io, "game", id);
    try std.testing.expectError(error.NoTunnel, r.openSession(io, "game", &player));
    dgrams.clear();
    r.datagramToAgent(io, s.token, "still");
    agent.drain(&got, &dgrams);
    try std.testing.expectEqual(@as(usize, 1), dgrams.list.items.len);

    r.closeSession(io, s.token);
    try std.testing.expectError(error.NoSession, r.toAgent(io, s.token, -1, false));
    _ = try r.claim(io, "game", &agent);
    _ = try r.openSession(io, "game", &player);
    r.dropInbox(io, &player);
    try std.testing.expectEqual(@as(usize, 0), r.sessions.count());
    r.dropInbox(io, &agent);
    r.by_name.deinit(Registry.gpa);
    r.sessions.deinit(Registry.gpa);
}

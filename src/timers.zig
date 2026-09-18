//! Coarse deadlines and deferred callbacks for one worker loop.
//!
//! Every timeout in the server (header, keep-alive, connect, read, linger)
//! only needs ~100 ms precision, so instead of one xev.Timer per object — each
//! needing its own cancel completion — objects embed a `Deadline` and a single
//! periodic tick scans the armed ones.
const std = @import("std");
const quic = @import("quic");
const xev = quic.event_loop.Xev;

pub fn nowMs() i64 {
    return @divTrunc(quic.sys.nanoTimestamp(), std.time.ns_per_ms);
}

pub const Deadline = struct {
    at_ms: i64 = 0,
    callback: *const fn (*Deadline) void,
    prev: ?*Deadline = null,
    next: ?*Deadline = null,
    fire_next: ?*Deadline = null,
    state: enum { idle, armed, firing } = .idle,

    pub fn armed(self: *const Deadline) bool {
        return self.state == .armed;
    }
};

/// Deferred work that must not run inside the caller's stack frame (freeing
/// an object whose method is still executing).
pub const Deferred = struct {
    callback: *const fn (*Deferred) void,
    next: ?*Deferred = null,
    queued: bool = false,
};

pub const Timers = struct {
    loop: *xev.Loop,
    tick_timer: xev.Timer,
    tick_c: xev.Completion = .{},
    defer_timer: xev.Timer,
    defer_c: xev.Completion = .{},
    defer_armed: bool = false,
    head: ?*Deadline = null,
    deferred_head: ?*Deferred = null,
    deferred_tail: ?*Deferred = null,
    now_ms: i64,
    stopped: bool = false,
    /// Called on every tick, after deadlines fire.
    on_tick: ?*const fn (*Timers) void = null,

    pub const tick_ms = 100;

    pub fn init(loop: *xev.Loop) !Timers {
        return .{
            .loop = loop,
            .tick_timer = try xev.Timer.init(),
            .defer_timer = try xev.Timer.init(),
            .now_ms = nowMs(),
        };
    }

    pub fn deinit(self: *Timers) void {
        self.tick_timer.deinit();
        self.defer_timer.deinit();
    }

    pub fn start(self: *Timers) void {
        self.tick_timer.run(self.loop, &self.tick_c, tick_ms, Timers, self, onTick);
    }

    /// Stop the periodic tick so the loop can run dry.
    pub fn stop(self: *Timers) void {
        self.stopped = true;
    }

    /// Arm (or re-arm) `d` to fire `ms` from now.
    pub fn set(self: *Timers, d: *Deadline, ms: u32) void {
        // The cached tick time can be up to a tick old; don't fire early.
        self.now_ms = nowMs();
        d.at_ms = self.now_ms + ms;
        if (d.state == .armed) return;
        d.state = .armed;
        d.prev = null;
        d.next = self.head;
        if (self.head) |h| h.prev = d;
        self.head = d;
    }

    pub fn clear(self: *Timers, d: *Deadline) void {
        switch (d.state) {
            .idle => {},
            // Still on this tick's fire list; skip it there.
            .firing => d.state = .idle,
            .armed => self.unlink(d),
        }
    }

    fn unlink(self: *Timers, d: *Deadline) void {
        if (d.prev) |p| p.next = d.next else self.head = d.next;
        if (d.next) |n| n.prev = d.prev;
        d.prev = null;
        d.next = null;
        d.state = .idle;
    }

    /// Run `d.callback` on a later loop iteration.
    pub fn defer_(self: *Timers, d: *Deferred) void {
        if (d.queued) return;
        d.queued = true;
        d.next = null;
        if (self.deferred_tail) |t| t.next = d else self.deferred_head = d;
        self.deferred_tail = d;
        if (!self.defer_armed) {
            self.defer_armed = true;
            self.defer_timer.run(self.loop, &self.defer_c, 0, Timers, self, onDefer);
        }
    }

    fn onDefer(ud: ?*Timers, _: *xev.Loop, _: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        _ = r catch {};
        const self = ud.?;
        self.defer_armed = false;
        self.now_ms = nowMs();
        // Callbacks may queue more; those run on the next round.
        var d = self.deferred_head;
        self.deferred_head = null;
        self.deferred_tail = null;
        while (d) |cur| {
            d = cur.next;
            cur.queued = false;
            cur.next = null;
            cur.callback(cur);
        }
        return .disarm;
    }

    fn onTick(ud: ?*Timers, _: *xev.Loop, c: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
        _ = r catch {};
        const self = ud.?;
        self.now_ms = nowMs();
        self.fireExpired();
        if (self.on_tick) |f| f(self);
        if (self.stopped) return .disarm;
        self.tick_timer.run(self.loop, c, tick_ms, Timers, self, onTick);
        return .disarm;
    }

    fn fireExpired(self: *Timers) void {
        // Collect first: callbacks may clear or re-arm any deadline.
        var expired: ?*Deadline = null;
        var d = self.head;
        while (d) |cur| {
            d = cur.next;
            if (cur.at_ms <= self.now_ms) {
                self.unlink(cur);
                cur.state = .firing;
                cur.fire_next = expired;
                expired = cur;
            }
        }
        while (expired) |cur| {
            expired = cur.fire_next;
            cur.fire_next = null;
            if (cur.state != .firing) continue;
            cur.state = .idle;
            cur.callback(cur);
        }
    }
};

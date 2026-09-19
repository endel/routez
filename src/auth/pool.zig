//! bcrypt checks off the event loop.
//!
//! A bcrypt check takes 50-250 ms at the usual costs; on a worker it would
//! stall every connection that worker holds. Workers hand checks to a few
//! verifier threads here, and get the verdict back through their `Inbox`,
//! which wakes their loop. The queue is bounded: when it is full a request
//! is refused (503) rather than queued behind minutes of work, and each
//! client's uncached checks are rate-limited before they get here (see
//! `Exchange`), so one client can't fill it.
const std = @import("std");
const quic = @import("quic");
const xev = quic.event_loop.Xev;
const htpasswd = @import("htpasswd.zig");
const verify = @import("verify.zig");

pub const Job = struct {
    hash: htpasswd.Hash,
    password: [verify.max_bcrypt_password]u8 = undefined,
    password_len: u8 = 0,
    /// The user wasn't in the file: `hash` is the decoy, and the check
    /// fails whatever it computes.
    decoy: bool = false,
    /// Cache entry to add on success.
    digest: [32]u8,
    ok: bool = false,

    inbox: *Inbox,
    /// The waiting request; the worker nulls it when the request goes away.
    /// Only the worker's thread touches it.
    ctx: ?*anyopaque,
    on_done: *const fn (*Job) void,
    next: ?*Job = null,

    pub fn setPassword(self: *Job, password: []const u8) void {
        const n = @min(password.len, self.password.len);
        @memcpy(self.password[0..n], password[0..n]);
        self.password_len = @intCast(n);
    }

    pub fn destroy(self: *Job, gpa: std.mem.Allocator) void {
        std.crypto.secureZero(u8, &self.password);
        gpa.destroy(self);
    }
};

/// A FIFO of jobs, linked through `Job.next`.
const Queue = struct {
    head: ?*Job = null,
    tail: ?*Job = null,
    len: u32 = 0,

    fn push(q: *Queue, j: *Job) void {
        j.next = null;
        if (q.tail) |t| t.next = j else q.head = j;
        q.tail = j;
        q.len += 1;
    }

    fn pop(q: *Queue) ?*Job {
        const j = q.head orelse return null;
        q.head = j.next;
        if (q.head == null) q.tail = null;
        q.len -= 1;
        return j;
    }

    fn take(q: *Queue) ?*Job {
        const h = q.head;
        q.* = .{};
        return h;
    }
};

pub const Pool = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    queue: Queue = .{},
    cache: verify.Cache,
    threads: []std.Thread = &.{},

    /// Checks waiting for a thread, beyond which requests are refused.
    pub const max_queued = 128;

    /// Created once, for the life of the process: every generation uses it.
    pub fn create(gpa: std.mem.Allocator, io: std.Io) !*Pool {
        const p = try gpa.create(Pool);
        var key: [32]u8 = undefined;
        quic.sys.randomBytes(&key);
        p.* = .{ .io = io, .cache = .init(key) };
        const cpus = std.Thread.getCpuCount() catch 2;
        const n = std.math.clamp(cpus / 2, 1, 4);
        p.threads = try gpa.alloc(std.Thread, n);
        for (p.threads) |*t| t.* = try std.Thread.spawn(.{}, run, .{p});
        return p;
    }

    /// Queue a check; false when the queue is full. The job comes back
    /// through its inbox either way it goes.
    pub fn submit(self: *Pool, job: *Job) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.queue.len >= max_queued) return false;
        self.queue.push(job);
        self.cond.signal(self.io);
        return true;
    }

    fn run(self: *Pool) void {
        while (true) {
            self.mutex.lockUncancelable(self.io);
            while (self.queue.head == null) self.cond.waitUncancelable(self.io, &self.mutex);
            const job = self.queue.pop().?;
            self.mutex.unlock(self.io);

            const ok = verify.check(&job.hash, job.password[0..job.password_len]);
            job.ok = ok and !job.decoy;
            if (job.ok) self.cache.insert(self.io, job.digest, quic.sys.nanoTimestamp());
            job.inbox.push(job);
        }
    }
};

/// A worker's finished jobs, handed over from verifier threads.
pub const Inbox = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    done: Queue = .{},
    wake: xev.Async,
    wake_c: xev.Completion = .{},

    pub fn init(io: std.Io) !Inbox {
        return .{ .io = io, .wake = try xev.Async.init() };
    }

    fn push(self: *Inbox, job: *Job) void {
        self.mutex.lockUncancelable(self.io);
        self.done.push(job);
        self.mutex.unlock(self.io);
        self.wake.notify() catch {};
    }

    /// On the worker's thread: run each finished job's callback, unless
    /// its request went away, and free it.
    pub fn drain(self: *Inbox, gpa: std.mem.Allocator) void {
        self.mutex.lockUncancelable(self.io);
        var j = self.done.take();
        self.mutex.unlock(self.io);
        while (j) |job| {
            j = job.next;
            if (job.ctx != null) job.on_done(job);
            job.destroy(gpa);
        }
    }
};

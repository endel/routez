//! Blocking file work (open, stat, read) off the event loop.
//!
//! A read from a cold or stalled disk can block for as long as the disk
//! takes; on a worker it would stall every connection that worker holds.
//! Workers hand such work to a few I/O threads here and get it back through
//! their `Inbox`, which wakes their loop.
//!
//! Every submitted job comes back to its worker exactly once, through
//! `Job.done`, even when the request that submitted it went away meanwhile:
//! the owner keeps the job's memory until then, and decides there what is
//! left to do (for an abandoned request, close the file and free).
//!
//! The pool is process-wide and outlives every generation, so a job must not
//! point into a generation's config: a thread stuck on a dead disk may hold
//! one past the generation's end.
const std = @import("std");
const builtin = @import("builtin");
const quic = @import("quic");
const xev = quic.event_loop.Xev;

pub const Job = struct {
    /// Runs on an I/O thread. Touches only memory the job's owner keeps
    /// until `done`.
    work: *const fn (*Job) void,
    /// Runs on the submitting worker's loop thread once `work` returns.
    done: *const fn (*Job) void,
    inbox: *Inbox,
    next: ?*Job = null,
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
    threads: []std.Thread = &.{},
    stopping: bool = false,

    /// New work (`submit` with `bounded`) waiting for a thread, beyond which
    /// it is refused. Follow-up reads of a response already being served
    /// are always taken: each response has at most one queued, so they are
    /// bounded by the responses let in.
    pub const max_queued = 1024;

    pub fn create(gpa: std.mem.Allocator, io: std.Io, threads: u16) !*Pool {
        const p = try gpa.create(Pool);
        errdefer gpa.destroy(p);
        p.* = .{ .io = io };
        p.threads = try gpa.alloc(std.Thread, @max(threads, 1));
        var started: usize = 0;
        errdefer {
            p.stop(started);
            gpa.free(p.threads);
        }
        for (p.threads) |*t| {
            t.* = try std.Thread.spawn(.{}, run, .{p});
            started += 1;
        }
        return p;
    }

    /// Stop the threads once the queue is empty, and free. Only tests do:
    /// the server keeps its pool for the life of the process.
    pub fn destroy(self: *Pool, gpa: std.mem.Allocator) void {
        self.stop(self.threads.len);
        gpa.free(self.threads);
        gpa.destroy(self);
    }

    fn stop(self: *Pool, started: usize) void {
        self.mutex.lockUncancelable(self.io);
        self.stopping = true;
        self.cond.broadcast(self.io);
        self.mutex.unlock(self.io);
        for (self.threads[0..started]) |t| t.join();
    }

    pub fn threadCount(self: *const Pool) usize {
        return self.threads.len;
    }

    /// Queue `job`; false when `bounded` and the queue is full, and then
    /// the job doesn't come back.
    pub fn submit(self: *Pool, job: *Job, bounded: bool) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (bounded and self.queue.len >= max_queued) return false;
        self.queue.push(job);
        self.cond.signal(self.io);
        return true;
    }

    fn run(self: *Pool) void {
        while (true) {
            self.mutex.lockUncancelable(self.io);
            while (self.queue.head == null and !self.stopping) self.cond.waitUncancelable(self.io, &self.mutex);
            const job = self.queue.pop() orelse {
                self.mutex.unlock(self.io);
                return;
            };
            self.mutex.unlock(self.io);
            job.work(job);
            job.inbox.push(job);
        }
    }
};

/// A worker's finished jobs, handed over from I/O threads.
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

    /// On the worker's thread: hand each finished job back to its owner.
    pub fn drain(self: *Inbox) void {
        self.mutex.lockUncancelable(self.io);
        var j = self.done.take();
        self.mutex.unlock(self.io);
        while (j) |job| {
            j = job.next;
            job.done(job);
        }
    }
};

/// What serving a file needs from its metadata.
pub const Meta = struct {
    kind: std.Io.File.Kind,
    size: u64,
    mtime_s: i64,
    inode: u64,

    pub fn of(st: std.Io.File.Stat) Meta {
        return .{ .kind = st.kind, .size = st.size, .mtime_s = @intCast(@divTrunc(st.mtime.nanoseconds, std.time.ns_per_s)), .inode = @intCast(st.inode) };
    }
};

/// Attempts for the loop thread that succeed only when the kernel can answer
/// from its caches, and otherwise fail with `error.WouldBlock` so the work
/// goes to the pool. Cached files then cost no round trip. Linux only:
/// elsewhere nothing says whether a call would wait.
pub const cached = if (builtin.os.tag == .linux) linux_cached else struct {
    pub fn enabled() bool {
        return false;
    }
    pub fn open(_: [:0]const u8) linux_cached.OpenError!std.Io.File {
        return error.WouldBlock;
    }
    pub fn stat(_: std.Io.File) error{WouldBlock}!Meta {
        return error.WouldBlock;
    }
    pub fn read(_: std.Io.File, _: []u8, _: u64) error{ WouldBlock, Unsupported }!usize {
        return error.WouldBlock;
    }
};

const linux_cached = struct {
    const linux = std.os.linux;
    var unsupported = std.atomic.Value(bool).init(false);

    pub fn enabled() bool {
        return !unsupported.load(.monotonic);
    }

    pub const OpenError = error{ WouldBlock, FileNotFound, NotDir, NameTooLong };

    /// openat2 with RESOLVE_CACHED: fails unless every path component is in
    /// the dentry cache. O_NONBLOCK keeps a FIFO from waiting for a writer.
    /// Only a definite miss is reported as one; anything else (permissions
    /// included) is left to the pool's authoritative open.
    pub fn open(path: [:0]const u8) OpenError!std.Io.File {
        const How = extern struct { flags: u64, mode: u64, resolve: u64 };
        const resolve_cached = 0x20;
        var how: How = .{ .flags = @as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NONBLOCK = true })), .mode = 0, .resolve = resolve_cached };
        const rc = linux.syscall4(.openat2, @bitCast(@as(isize, linux.AT.FDCWD)), @intFromPtr(path.ptr), @intFromPtr(&how), @sizeOf(How));
        switch (linux.errno(rc)) {
            .SUCCESS => return .{ .handle = @intCast(rc), .flags = .{ .nonblocking = false } },
            .NOENT => return error.FileNotFound,
            .NOTDIR => return error.NotDir,
            .NAMETOOLONG => return error.NameTooLong,
            // Kernels before 5.12, or a sandbox without openat2.
            .NOSYS, .INVAL, .@"2BIG" => {
                unsupported.store(true, .monotonic);
                return error.WouldBlock;
            },
            else => return error.WouldBlock,
        }
    }

    /// Attributes as cached: an open local file's inode is in memory, and
    /// a network filesystem isn't asked.
    pub fn stat(file: std.Io.File) error{WouldBlock}!Meta {
        var stx: linux.Statx = undefined;
        const rc = linux.statx(file.handle, "", linux.AT.EMPTY_PATH | linux.AT.STATX_DONT_SYNC, .{ .TYPE = true, .SIZE = true, .MTIME = true, .INO = true }, &stx);
        if (linux.errno(rc) != .SUCCESS) return error.WouldBlock;
        if (!stx.mask.TYPE or !stx.mask.SIZE or !stx.mask.MTIME or !stx.mask.INO) return error.WouldBlock;
        const kind: std.Io.File.Kind = if (linux.S.ISREG(stx.mode)) .file else if (linux.S.ISDIR(stx.mode)) .directory else .unknown;
        return .{ .kind = kind, .size = stx.size, .mtime_s = stx.mtime.sec, .inode = stx.ino };
    }

    /// preadv2 with RWF_NOWAIT: only what's in the page cache, possibly
    /// short. `Unsupported` when the filesystem can't tell.
    pub fn read(file: std.Io.File, buf: []u8, offset: u64) error{ WouldBlock, Unsupported }!usize {
        const iov = [_]std.posix.iovec{.{ .base = buf.ptr, .len = buf.len }};
        const rc = linux.preadv2(file.handle, &iov, 1, @intCast(offset), linux.RWF.NOWAIT);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .OPNOTSUPP => error.Unsupported,
            else => error.WouldBlock,
        };
    }
};

/// Page-cache residency of an open file, for reads where cache-only ones
/// aren't supported (macOS; overlayfs and tmpfs on Linux). The file is
/// mapped but never touched, so a truncation can't fault; mincore says
/// which pages are cached, and those are read with a plain pread.
pub const Residency = struct {
    map: []align(std.heap.page_size_min) u8,

    pub fn init(file: std.Io.File, size: u64) ?Residency {
        if (size == 0 or size > std.math.maxInt(usize)) return null;
        const m = std.posix.mmap(null, @intCast(size), .{ .READ = true }, .{ .TYPE = .SHARED }, file.handle, 0) catch return null;
        return .{ .map = m };
    }

    pub fn deinit(self: Residency) void {
        std.posix.munmap(self.map);
    }

    /// Whether all of `[offset, offset + len)` is in the page cache.
    pub fn cached(self: Residency, offset: u64, len: usize) bool {
        const page = std.heap.pageSize();
        if (offset >= self.map.len) return false;
        const start = std.mem.alignBackward(usize, @intCast(offset), page);
        const end = @min(@as(usize, @intCast(offset)) + len, self.map.len);
        var vec: [256]u8 = undefined;
        if ((end - start + page - 1) / page > vec.len) return false;
        std.posix.mincore(@alignCast(self.map.ptr + start), end - start, &vec) catch return false;
        for (vec[0 .. (end - start + page - 1) / page]) |v| if (v & 1 == 0) return false;
        return true;
    }
};

// ---- tests ----

/// A job whose work blocks until the test releases it, like a read from a
/// stalled disk.
const TestJob = struct {
    job: Job,
    gate: ?*std.Io.Event = null,
    worked: bool = false,
    done_count: u32 = 0,
    /// Stands in for the request: cleared when it goes away mid-job.
    owner: ?*u32 = null,
    /// The job's memory, freed by `done` once abandoned.
    gpa: ?std.mem.Allocator = null,

    fn work(j: *Job) void {
        const self: *TestJob = @fieldParentPtr("job", j);
        if (self.gate) |g| g.waitUncancelable(std.testing.io);
        self.worked = true;
    }

    fn done(j: *Job) void {
        const self: *TestJob = @fieldParentPtr("job", j);
        self.done_count += 1;
        if (self.owner) |o| o.* += 1;
        if (self.gpa) |gpa| if (self.owner == null) gpa.destroy(self);
    }
};

const TestLoop = struct {
    loop: xev.Loop,
    inbox: Inbox,

    fn init(self: *TestLoop) !void {
        self.loop = try xev.Loop.init(.{});
        self.inbox = try Inbox.init(std.testing.io);
        self.inbox.wake.wait(&self.loop, &self.inbox.wake_c, TestLoop, self, onWake);
    }

    fn deinit(self: *TestLoop) void {
        self.inbox.wake.deinit();
        self.loop.deinit();
    }

    fn onWake(ud: ?*TestLoop, _: *xev.Loop, _: *xev.Completion, r: xev.Async.WaitError!void) xev.CallbackAction {
        _ = r catch {};
        ud.?.inbox.drain();
        return .rearm;
    }

    /// Run the loop until `cond` holds, or fail after a few seconds.
    fn runUntil(self: *TestLoop, ctx: anytype, comptime cond: fn (@TypeOf(ctx)) bool) !void {
        const deadline = quic.sys.nanoTimestamp() + 5 * std.time.ns_per_s;
        while (!cond(ctx)) {
            if (quic.sys.nanoTimestamp() > deadline) return error.Timeout;
            try self.loop.run(.no_wait);
            std.Thread.yield() catch {};
        }
    }
};

test "a stalled job doesn't hold up the others" {
    const io = std.testing.io;
    var tl: TestLoop = undefined;
    try tl.init();
    defer tl.deinit();
    const pool = try Pool.create(std.testing.allocator, io, 2);
    defer pool.destroy(std.testing.allocator);

    var gate: std.Io.Event = .unset;
    var slow: TestJob = .{ .job = .{ .work = TestJob.work, .done = TestJob.done, .inbox = &tl.inbox }, .gate = &gate };
    var fast: TestJob = .{ .job = .{ .work = TestJob.work, .done = TestJob.done, .inbox = &tl.inbox } };
    try std.testing.expect(pool.submit(&slow.job, true));
    try std.testing.expect(pool.submit(&fast.job, true));
    try tl.runUntil(&fast, struct {
        fn f(j: *TestJob) bool {
            return j.done_count == 1;
        }
    }.f);
    try std.testing.expect(!slow.worked);
    try std.testing.expectEqual(0, slow.done_count);

    gate.set(io);
    try tl.runUntil(&slow, struct {
        fn f(j: *TestJob) bool {
            return j.done_count == 1;
        }
    }.f);
    try std.testing.expect(slow.worked);
    try std.testing.expectEqual(1, fast.done_count);
}

test "a request that goes away mid-job gets nothing, and the job is freed" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var tl: TestLoop = undefined;
    try tl.init();
    defer tl.deinit();
    const pool = try Pool.create(gpa, io, 1);
    defer pool.destroy(gpa);

    var gate: std.Io.Event = .unset;
    var deliveries: u32 = 0;
    const job = try gpa.create(TestJob);
    job.* = .{ .job = .{ .work = TestJob.work, .done = TestJob.done, .inbox = &tl.inbox }, .gate = &gate, .owner = &deliveries, .gpa = gpa };
    try std.testing.expect(pool.submit(&job.job, true));
    // The request is gone while its work is blocked.
    job.owner = null;
    gate.set(io);

    // A later job on the same thread comes back only after the abandoned
    // one did, so once it's in, the abandoned one was handled (and freed:
    // the testing allocator fails the test on a leak).
    var after: TestJob = .{ .job = .{ .work = TestJob.work, .done = TestJob.done, .inbox = &tl.inbox } };
    try std.testing.expect(pool.submit(&after.job, true));
    try tl.runUntil(&after, struct {
        fn f(j: *TestJob) bool {
            return j.done_count == 1;
        }
    }.f);
    try std.testing.expectEqual(0, deliveries);
}

test "residency sees pages a read brought in" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var data: [100_000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);
    try tmp.dir.writeFile(io, .{ .sub_path = "f", .data = &data });
    const file = try tmp.dir.openFile(io, "f", .{});
    defer file.close(io);
    var buf: [data.len]u8 = undefined;
    _ = try file.readPositional(io, &.{&buf}, 0);
    const r = Residency.init(file, data.len).?;
    defer r.deinit();
    try std.testing.expect(r.cached(0, 32 * 1024));
    try std.testing.expect(r.cached(90_000, 10_000));
    try std.testing.expect(!r.cached(data.len, 1));
}

test "new work is refused once the queue is full; follow-ups are not" {
    const io = std.testing.io;
    var tl: TestLoop = undefined;
    try tl.init();
    defer tl.deinit();
    const pool = try Pool.create(std.testing.allocator, io, 1);
    defer pool.destroy(std.testing.allocator);

    var gate: std.Io.Event = .unset;
    var blocker: TestJob = .{ .job = .{ .work = TestJob.work, .done = TestJob.done, .inbox = &tl.inbox }, .gate = &gate };
    try std.testing.expect(pool.submit(&blocker.job, true));
    // Wait for the thread to take it, so the queue holds only what follows.
    while (true) {
        pool.mutex.lockUncancelable(io);
        const empty = pool.queue.len == 0;
        pool.mutex.unlock(io);
        if (empty) break;
        std.Thread.yield() catch {};
    }
    const jobs = try std.testing.allocator.alloc(TestJob, Pool.max_queued + 1);
    defer std.testing.allocator.free(jobs);
    for (jobs) |*j| j.* = .{ .job = .{ .work = TestJob.work, .done = TestJob.done, .inbox = &tl.inbox } };
    for (jobs[0..Pool.max_queued]) |*j| try std.testing.expect(pool.submit(&j.job, true));
    try std.testing.expect(!pool.submit(&jobs[Pool.max_queued].job, true));
    try std.testing.expect(pool.submit(&jobs[Pool.max_queued].job, false));

    gate.set(io);
    try tl.runUntil(jobs, struct {
        fn f(js: []TestJob) bool {
            for (js) |j| if (j.done_count != 1) return false;
            return true;
        }
    }.f);
}

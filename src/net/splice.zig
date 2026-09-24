//! Layer-4 relaying through the kernel. `splice(2)` moves a socket's bytes
//! into a pipe and out the other socket, so bulk forwarding never copies
//! them into the process at all. Linux only; elsewhere a tunnel keeps
//! reading and writing the bytes itself.
//!
//! One `Relay` drives one direction. It holds a pipe from the worker's pool
//! and two completions: a poll that fires when the source has bytes, and an
//! empty write that lands when the destination drains. The pipe is the
//! backpressure — nothing is queued anywhere else, so there is no high-water
//! mark to pick.
//!
//! `Owner` receives events through these methods:
//!   - `onRelayEof(owner, from_client)`: the source finished and the pipe is
//!     empty. The owner passes the FIN on.
//!   - `onRelayError(owner, from_client)`: the owner aborts.
//!   - `onRelayProgress(owner, from_client, bytes)`: bytes moved.
//!   - `onRelayDone(owner, from_client)`: nothing is armed and the pipe is
//!     back; the fds may now be closed. Always follows an eof or an error.
const std = @import("std");
const builtin = @import("builtin");
const quic = @import("quic");
const xev = quic.event_loop.Xev;
const socket = @import("socket.zig");

pub const supported = builtin.os.tag == .linux;

/// What one splice asks for; the pipe's own capacity is the real cap.
const chunk = 1 << 20;
/// Pipefuls moved in one wake-up before handing the loop back, so one busy
/// tunnel can't hold a worker.
const pump_budget = 16;

const Pipe = [2]std.posix.fd_t;

/// Per-worker free list of pipes. A pipe only comes back empty, so a reused
/// one never carries another tunnel's bytes. Beyond this many, tunnels make
/// and drop their own rather than hold fds a worker isn't using.
const pool_max = 32;
threadlocal var pool: [pool_max]Pipe = undefined;
threadlocal var pool_len: usize = 0;

fn takePipe() ?Pipe {
    if (pool_len > 0) {
        pool_len -= 1;
        return pool[pool_len];
    }
    const linux = std.os.linux;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .NONBLOCK = true, .CLOEXEC = true })) != .SUCCESS) return null;
    return .{ fds[0], fds[1] };
}

fn givePipe(p: Pipe) void {
    if (pool_len < pool_max) {
        pool[pool_len] = p;
        pool_len += 1;
        return;
    }
    closePipe(p);
}

pub fn closePipe(p: Pipe) void {
    _ = std.c.close(p[0]);
    _ = std.c.close(p[1]);
}

const Moved = struct {
    n: usize,
    status: enum { ok, again, failed },
};

fn spliceOnce(fd_in: std.posix.fd_t, fd_out: std.posix.fd_t, len: usize) Moved {
    const linux = std.os.linux;
    const nonblock: usize = 0x2; // SPLICE_F_NONBLOCK
    const rc = linux.syscall6(
        .splice,
        @bitCast(@as(isize, fd_in)),
        0,
        @bitCast(@as(isize, fd_out)),
        0,
        len,
        nonblock,
    );
    return switch (linux.errno(rc)) {
        .SUCCESS => .{ .n = rc, .status = .ok },
        .AGAIN, .INTR => .{ .n = 0, .status = .again },
        else => .{ .n = 0, .status = .failed },
    };
}

pub fn Relay(comptime Owner: type) type {
    return struct {
        const Self = @This();

        owner: *Owner,
        /// Which direction this is, for the owner's callbacks.
        from_client: bool,
        loop: *xev.Loop = undefined,
        src: std.posix.socket_t = -1,
        dst: std.posix.socket_t = -1,
        pipe: Pipe = .{ -1, -1 },
        in_pipe: usize = 0,

        poll_c: xev.Completion = .{},
        write_c: xev.Completion = .{},
        running: bool = false,
        src_eof: bool = false,

        /// What `pump` stopped on.
        const Next = enum { poll_src, wait_dst, eof, failed };

        /// Take over `src`'s read side. False when no pipe was to be had, and
        /// the caller keeps relaying the bytes itself.
        pub fn start(self: *Self, loop: *xev.Loop, src: std.posix.socket_t, dst: std.posix.socket_t) bool {
            const p = takePipe() orelse return false;
            self.loop = loop;
            self.src = src;
            self.dst = dst;
            self.pipe = p;
            self.in_pipe = 0;
            self.src_eof = false;
            self.running = true;
            self.step(self.pump());
            return true;
        }

        pub fn isRunning(self: *const Self) bool {
            return self.running;
        }

        /// The worker is going away with the loop; drop the pipe without
        /// waiting for anything.
        pub fn abandon(self: *Self) void {
            if (!self.running) return;
            self.running = false;
            closePipe(self.pipe);
        }

        /// Move what there is, and say what to wait for. Never blocks.
        fn pump(self: *Self) Next {
            var moved: usize = 0;
            var rounds: usize = 0;
            defer if (moved > 0) Owner.onRelayProgress(self.owner, self.from_client, moved);
            while (true) {
                while (self.in_pipe > 0) {
                    const r = spliceOnce(self.pipe[0], self.dst, self.in_pipe);
                    switch (r.status) {
                        .ok => {
                            if (r.n == 0) return .failed;
                            self.in_pipe -= r.n;
                            moved += r.n;
                        },
                        .again => return .wait_dst,
                        .failed => return .failed,
                    }
                }
                if (self.src_eof) return .eof;
                rounds += 1;
                if (rounds > pump_budget) return .poll_src;
                const r = spliceOnce(self.src, self.pipe[1], chunk);
                switch (r.status) {
                    .ok => {
                        if (r.n == 0) {
                            self.src_eof = true;
                            return .eof;
                        }
                        self.in_pipe += r.n;
                    },
                    .again => return .poll_src,
                    .failed => return .failed,
                }
            }
        }

        /// Arm what `pump` asked for, from outside a completion callback.
        fn step(self: *Self, next: Next) void {
            switch (next) {
                .poll_src => xev.TCP.initFd(self.src).poll(self.loop, &self.poll_c, .read, Self, self, onPollable),
                .wait_dst => xev.TCP.initFd(self.dst).write(self.loop, &self.write_c, socket.wait_writable, Self, self, onWritable),
                .eof => self.finish(false),
                .failed => self.finish(true),
            }
        }

        /// Same, from inside the completion's own callback: waiting on the
        /// same thing again has to be `.rearm`, since the loop removes the
        /// registration once this returns.
        fn stepFromCallback(self: *Self, next: Next, comptime from_poll: bool) xev.CallbackAction {
            if (if (from_poll) next == .poll_src else next == .wait_dst) return .rearm;
            self.step(next);
            return .disarm;
        }

        fn onPollable(ud: ?*Self, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, r: xev.PollError!xev.PollEvent) xev.CallbackAction {
            const self = ud.?;
            _ = r catch return self.stepFromCallback(.failed, true);
            return self.stepFromCallback(self.pump(), true);
        }

        fn onWritable(ud: ?*Self, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
            const self = ud.?;
            _ = r catch return self.stepFromCallback(.failed, false);
            return self.stepFromCallback(self.pump(), false);
        }

        /// The direction is over: hand the pipe back and tell the owner, which
        /// may then close the sockets.
        fn finish(self: *Self, failed: bool) void {
            if (!self.running) return;
            self.running = false;
            // Only an empty pipe is worth keeping; the bytes left in a failed
            // one belong to a connection that is going away.
            if (self.in_pipe == 0) givePipe(self.pipe) else closePipe(self.pipe);
            if (failed) Owner.onRelayError(self.owner, self.from_client) else Owner.onRelayEof(self.owner, self.from_client);
            // Nothing is armed here: `finish` is only reached from `step`,
            // and the fd the loop is about to deregister is still open,
            // because a socket closes its own from a deferred callback.
            Owner.onRelayDone(self.owner, self.from_client);
        }
    };
}

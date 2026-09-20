//! A TCP connection on the worker's libxev loop.
//!
//! Wraps `xev.TCP` with what every connection in the server needs: one
//! re-armed read, ordered writes with a double buffer (the in-flight slice
//! must not move while the kernel reads it), read pausing for backpressure,
//! and a close that waits for in-flight operations before releasing the fd.
//!
//! `Owner` receives events through these methods:
//!   - `onSocketData(owner, bytes)`: bytes are only valid during the call.
//!   - `onSocketEof(owner)`: the peer finished sending, or the connection
//!     failed. The owner usually aborts.
//!   - `onSocketWritable(owner)`: output drained below `low_water`.
//!   - `onSocketSent(owner)`, optional: a queued write went (partly) out,
//!     also while flushing before a close.
//!   - `onSocketConnect(owner, ?anyerror)`: outcome of `connect`.
//!   - `onSocketClosed(owner)`: the fd is closed and no callback will follow;
//!     the owner may free itself. Always called from a deferred callback,
//!     never from inside `abort`.
const std = @import("std");
const builtin = @import("builtin");
const quic = @import("quic");
const xev = quic.event_loop.Xev;
const timers = @import("../timers.zig");

pub const read_buffer_size = 16 * 1024;
/// With epoll every socket on a thread reads into one buffer, so an idle
/// connection doesn't hold 16 KiB: epoll reads only just before running that
/// read's callback. Other backends can read ahead and queue the callback
/// (kqueue does), so there each socket keeps its own. Either way,
/// `onSocketData` bytes are gone once the call returns.
const shared_read_buf = xev.backend == .epoll;
threadlocal var thread_read_buf: [read_buffer_size]u8 = undefined;
/// SIGPIPE is ignored process-wide; MSG_NOSIGNAL covers Linux regardless.
const send_flags: c_int = if (builtin.os.tag == .linux) std.posix.MSG.NOSIGNAL else 0;
/// Owners stop producing output above this.
pub const high_water = 256 * 1024;
pub const low_water = 64 * 1024;

/// A range of a file to send as-is (sendfile), after the bytes queued
/// before it. `release(hold)` is called once the socket is done with it.
pub const FileOut = struct {
    fd: std.posix.fd_t,
    offset: u64,
    len: u64,
    hold: *anyopaque,
    release: *const fn (*anyopaque) void,
};

/// `connects` gives the socket a connect completion; sockets that only ever
/// come from accept save its space on every connection.
pub fn Socket(comptime Owner: type, comptime connects: bool) type {
    return struct {
        const Self = @This();

        tcp: xev.TCP,
        loop: *xev.Loop,
        timers: *timers.Timers,
        alloc: std.mem.Allocator,
        owner: *Owner,

        read_c: xev.Completion = .{},
        write_c: xev.Completion = .{},
        connect_c: if (connects) xev.Completion else void = if (connects) .{} else {},
        closed_cb: timers.Deferred = .{ .callback = onDeferredClose },

        reading: bool = false,
        read_paused: bool = false,
        /// Writes only queue until `uncork`, which sends them in one go.
        corked: bool = false,
        writing: bool = false,
        connecting: bool = false,

        /// Slice being written by the kernel; never appended to while `writing`.
        active: std.ArrayListUnmanaged(u8) = .empty,
        active_off: usize = 0,
        pending: std.ArrayListUnmanaged(u8) = .empty,
        /// Sent once `active` and the first `file_before` bytes of
        /// `pending` are; bytes queued after it wait for it.
        file: ?FileOut = null,
        file_before: usize = 0,
        /// Bytes ever queued, and those the kernel took: what was queued up
        /// to some point has been sent once `sent_total` reaches it.
        queued_total: u64 = 0,
        sent_total: u64 = 0,

        state: State = .open,
        fd_closed: bool = false,
        own_read_buf: if (shared_read_buf) void else [read_buffer_size]u8 = undefined,

        pub const State = enum {
            open,
            /// Write what is queued, then half-close and wait for the peer's FIN.
            flushing,
            /// Write side shut; reading and discarding until EOF.
            lingering,
            closing,
            closed,
        };

        pub fn init(self: *Self, owner: *Owner, loop: *xev.Loop, t: *timers.Timers, alloc: std.mem.Allocator, tcp: xev.TCP) void {
            self.* = .{ .tcp = tcp, .loop = loop, .timers = t, .alloc = alloc, .owner = owner };
            setNoSigpipe(tcp.fd);
            // A response is often a head write then a body write; with Nagle
            // the second waits on the client's delayed ACK (~40 ms on Linux).
            setNoDelay(tcp.fd);
        }

        pub fn fd(self: *const Self) std.posix.socket_t {
            return self.tcp.fd;
        }

        pub fn isOpen(self: *const Self) bool {
            return self.state == .open;
        }

        /// Open a socket and start connecting. Completion arrives in
        /// `onSocketConnect`. Writes queued meanwhile are sent once connected.
        pub fn connect(self: *Self, owner: *Owner, loop: *xev.Loop, t: *timers.Timers, alloc: std.mem.Allocator, addr: std.Io.net.IpAddress) !void {
            if (!connects) @compileError("this socket never connects");
            const tcp = try xev.TCP.init(addr);
            self.init(owner, loop, t, alloc, tcp);
            self.connecting = true;
            self.tcp.connect(loop, &self.connect_c, addr, Self, self, onConnect);
        }

        fn onConnect(ud: ?*Self, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, r: xev.ConnectError!void) xev.CallbackAction {
            const self = ud.?;
            self.connecting = false;
            if (self.state == .closing) {
                self.maybeFinishClose();
                return .disarm;
            }
            r catch |err| {
                Owner.onSocketConnect(self.owner, err);
                return .disarm;
            };
            setNoDelay(self.tcp.fd);
            Owner.onSocketConnect(self.owner, null);
            if (self.state == .open or self.state == .flushing) self.kickWrite();
            if (self.state == .open) self.startReading();
            return .disarm;
        }

        pub fn startReading(self: *Self) void {
            if (self.reading or self.connecting or self.read_paused) return;
            if (self.state == .closing or self.state == .closed) return;
            self.reading = true;
            self.tcp.read(self.loop, &self.read_c, .{ .slice = self.readBuf() }, Self, self, onRead);
        }

        fn readBuf(self: *Self) *[read_buffer_size]u8 {
            return if (shared_read_buf) &thread_read_buf else &self.own_read_buf;
        }

        pub fn pauseRead(self: *Self) void {
            self.read_paused = true;
        }

        pub fn resumeRead(self: *Self) void {
            if (!self.read_paused) return;
            self.read_paused = false;
            self.startReading();
        }

        fn onRead(ud: ?*Self, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.ReadBuffer, r: xev.ReadError!usize) xev.CallbackAction {
            const self = ud.?;
            const n = r catch {
                self.reading = false;
                switch (self.state) {
                    .open, .flushing => Owner.onSocketEof(self.owner),
                    .lingering => self.abort(),
                    .closing, .closed => {},
                }
                self.maybeFinishClose();
                return .disarm;
            };
            switch (self.state) {
                .open, .flushing => Owner.onSocketData(self.owner, self.readBuf()[0..n]),
                .lingering => {},
                .closing, .closed => {},
            }
            if (self.state == .closing or self.state == .closed) {
                self.reading = false;
                self.maybeFinishClose();
                return .disarm;
            }
            if (self.read_paused and self.state != .lingering) {
                self.reading = false;
                return .disarm;
            }
            return .rearm;
        }

        /// Queue bytes for sending. Dropped silently once the socket is closing.
        pub fn write(self: *Self, data_in: []const u8) void {
            if (self.state != .open) return;
            if (data_in.len == 0) return;
            self.queued_total += data_in.len;
            var data = data_in;
            // Nothing queued: try the kernel directly. A write completion
            // costs an epoll registration round trip (and on epoll a dup of
            // the fd), which most writes to a healthy socket don't need.
            if (!self.corked and !self.writing and !self.connecting and self.buffered() == 0) {
                const rc = std.c.send(self.tcp.fd, data.ptr, data.len, send_flags);
                if (rc > 0) {
                    const n: usize = @intCast(rc);
                    self.sent_total += n;
                    if (n == data.len) return;
                    data = data[n..];
                }
                // An error (not EAGAIN) resurfaces on the queued write below.
            }
            self.pending.appendSlice(self.alloc, data) catch {
                self.abort();
                return;
            };
            self.kickWrite();
        }

        /// Hold writes back until `uncork`, so a response's pieces leave in
        /// one send (one segment for the peer to read).
        pub fn cork(self: *Self) void {
            self.corked = true;
        }

        pub fn uncork(self: *Self) void {
            if (!self.corked) return;
            self.corked = false;
            if (self.state != .open and self.state != .flushing) return;
            const sent_before = self.sent_total;
            // A producer that stopped at high_water waits for onSocketWritable,
            // which only a write completion would otherwise give it.
            const was_full = self.buffered() >= low_water;
            if (!self.writing and !self.connecting and self.active_off >= self.active.items.len) {
                // What goes ahead of a queued file, or everything.
                const n = if (self.file != null) self.file_before else self.pending.items.len;
                if (n > 0) {
                    const rc = std.c.send(self.tcp.fd, self.pending.items.ptr, n, send_flags);
                    if (rc > 0) {
                        const sent: usize = @intCast(rc);
                        self.sent_total += sent;
                        const rest = self.pending.items.len - sent;
                        std.mem.copyForwards(u8, self.pending.items[0..rest], self.pending.items[sent..]);
                        self.pending.items.len = rest;
                        if (self.file != null) self.file_before -= sent;
                    }
                }
            }
            // kickWrite may sendfile directly too.
            self.kickWrite();
            if (self.sent_total == sent_before) return;
            if (@hasDecl(Owner, "onSocketSent") and self.state != .closing and self.state != .closed) Owner.onSocketSent(self.owner);
            if (was_full and self.state == .open and self.buffered() < low_water) Owner.onSocketWritable(self.owner);
        }

        /// Reserve `n` bytes at the end of the output queue to fill in place.
        /// Must be followed by `commit`.
        pub fn reserve(self: *Self, n: usize) ?[]u8 {
            if (self.state != .open) return null;
            self.pending.ensureUnusedCapacity(self.alloc, n) catch {
                self.abort();
                return null;
            };
            return self.pending.unusedCapacitySlice()[0..n];
        }

        pub fn commit(self: *Self, n: usize) void {
            self.pending.items.len += n;
            self.queued_total += n;
            self.kickWrite();
        }

        /// Queue a file range after the bytes queued so far; false (and the
        /// range released) when one is already queued that this doesn't
        /// continue, or the socket is closing. The range must be in the
        /// page cache: sendfile reads it on this thread.
        pub fn sendFile(self: *Self, f: FileOut) bool {
            if (self.state != .open or self.connecting) {
                f.release(f.hold);
                return false;
            }
            if (self.file) |*cur| {
                const continues = cur.fd == f.fd and cur.offset + cur.len == f.offset and self.pending.items.len == self.file_before;
                f.release(f.hold);
                if (!continues) return false;
                cur.len += f.len;
                self.queued_total += f.len;
                return true;
            }
            self.queued_total += f.len;
            self.file = f;
            self.file_before = self.pending.items.len;
            self.kickWrite();
            return true;
        }

        /// Bytes queued and not yet accepted by the kernel.
        pub fn buffered(self: *const Self) usize {
            const file_len: usize = if (self.file) |f| @intCast(f.len) else 0;
            return (self.active.items.len - self.active_off) + self.pending.items.len + file_len;
        }

        /// Bytes the kernel holds for us that we have not read yet.
        ///
        /// A connection whose next request is still in the receive queue looks
        /// idle to everything that only inspects our own buffers. Closing it
        /// then sends RST and the client loses that request.
        pub fn unread(self: *const Self) usize {
            var n: c_int = 0;
            if (std.c.ioctl(self.tcp.fd, std.c.T.FIONREAD, &n) != 0) return 0;
            return if (n > 0) @intCast(n) else 0;
        }

        fn kickWrite(self: *Self) void {
            if (self.writing or self.connecting or self.corked) return;
            if (self.state == .closing or self.state == .closed or self.state == .lingering) return;
            while (self.active_off >= self.active.items.len) {
                self.active.clearRetainingCapacity();
                self.active_off = 0;
                if (self.file != null) {
                    if (self.file_before > 0) {
                        // The bytes ahead of the file go first.
                        self.active.appendSlice(self.alloc, self.pending.items[0..self.file_before]) catch return self.abort();
                        const rest = self.pending.items.len - self.file_before;
                        std.mem.copyForwards(u8, self.pending.items[0..rest], self.pending.items[self.file_before..]);
                        self.pending.items.len = rest;
                        self.file_before = 0;
                        break;
                    }
                    switch (self.sendFileNow()) {
                        .done, .copied => continue,
                        .blocked => {
                            // An empty write completes once the socket is writable.
                            self.writing = true;
                            self.tcp.write(self.loop, &self.write_c, .{ .slice = &.{} }, Self, self, onWrite);
                            return;
                        },
                        .failed => return self.abort(),
                    }
                }
                if (self.pending.items.len == 0) {
                    if (self.state == .flushing) self.finishFlush();
                    return;
                }
                std.mem.swap(std.ArrayListUnmanaged(u8), &self.active, &self.pending);
                self.pending.clearRetainingCapacity();
            }
            self.writing = true;
            self.tcp.write(self.loop, &self.write_c, .{ .slice = self.active.items[self.active_off..] }, Self, self, onWrite);
        }

        /// sendfile until the range is out or the socket is full. Where the
        /// file can't be sent that way, a piece of it is copied into
        /// `active` instead (a plain read: the range is cached).
        fn sendFileNow(self: *Self) enum { done, blocked, copied, failed } {
            const f = &self.file.?;
            while (f.len > 0) {
                const r = sendfile(self.tcp.fd, f.fd, f.offset, f.len);
                f.offset += r.sent;
                f.len -= r.sent;
                self.sent_total += r.sent;
                switch (r.status) {
                    .ok => if (r.sent == 0) return .failed, // the file shrank
                    .again => return .blocked,
                    .unsupported => {
                        const n: usize = @intCast(@min(f.len, 64 * 1024));
                        self.active.ensureTotalCapacity(self.alloc, n) catch return .failed;
                        const rc = std.c.pread(f.fd, self.active.allocatedSlice().ptr, n, @intCast(f.offset));
                        if (rc <= 0) return .failed;
                        const got: usize = @intCast(rc);
                        self.active.items.len = got;
                        f.offset += got;
                        f.len -= got;
                        if (f.len == 0) self.dropFile();
                        return .copied;
                    },
                    .failed => return .failed,
                }
            }
            self.dropFile();
            return .done;
        }

        fn dropFile(self: *Self) void {
            const f = self.file orelse return;
            self.file = null;
            self.file_before = 0;
            f.release(f.hold);
        }

        fn onWrite(ud: ?*Self, _: *xev.Loop, _: *xev.Completion, _: xev.TCP, _: xev.WriteBuffer, r: xev.WriteError!usize) xev.CallbackAction {
            const self = ud.?;
            self.writing = false;
            if (self.state == .closing or self.state == .closed) {
                self.maybeFinishClose();
                return .disarm;
            }
            const n = r catch {
                self.dropOutput();
                if (self.state == .open) Owner.onSocketEof(self.owner) else self.abort();
                self.maybeFinishClose();
                return .disarm;
            };
            self.active_off += n;
            self.sent_total += n;
            if (self.active_off >= self.active.items.len) {
                self.active.clearRetainingCapacity();
                self.active_off = 0;
            }
            self.kickWrite();
            if (@hasDecl(Owner, "onSocketSent") and self.state != .closing and self.state != .closed) Owner.onSocketSent(self.owner);
            if (self.state == .open and self.buffered() < low_water) Owner.onSocketWritable(self.owner);
            return .disarm;
        }

        /// Send what is queued, then close gracefully.
        pub fn closeAfterFlush(self: *Self) void {
            if (self.state != .open) return;
            self.state = .flushing;
            if (!self.writing and !self.connecting) self.kickWrite();
        }

        fn finishFlush(self: *Self) void {
            // Half-close so the peer sees the whole response before any RST
            // that closing with unread input would trigger.
            _ = std.c.shutdown(self.tcp.fd, std.posix.SHUT.WR);
            self.state = .lingering;
            self.read_paused = false;
            self.startReading();
        }

        /// Close now, discarding queued output. Idempotent.
        pub fn abort(self: *Self) void {
            switch (self.state) {
                .closing, .closed => return,
                else => {},
            }
            self.state = .closing;
            self.dropOutput();
            // Wakes any in-flight read or write so it completes promptly.
            _ = std.c.shutdown(self.tcp.fd, std.posix.SHUT.RDWR);
            self.maybeFinishClose();
        }

        fn dropOutput(self: *Self) void {
            if (!self.writing) {
                self.active.clearAndFree(self.alloc);
                self.active_off = 0;
            }
            self.pending.clearAndFree(self.alloc);
            self.dropFile();
        }

        fn maybeFinishClose(self: *Self) void {
            if (self.state != .closing) return;
            if (self.reading or self.writing or self.connecting) return;
            self.state = .closed;
            self.dropFile();
            // The fd is closed from the deferred callback, not here: this
            // may run inside a completion's callback, and libxev's epoll
            // backend deregisters that fd after the callback returns.
            self.active.clearAndFree(self.alloc);
            self.pending.clearAndFree(self.alloc);
            self.timers.defer_(&self.closed_cb);
        }

        fn onDeferredClose(d: *timers.Deferred) void {
            const self: *Self = @fieldParentPtr("closed_cb", d);
            if (!self.fd_closed) {
                self.fd_closed = true;
                _ = std.c.close(self.tcp.fd);
            }
            Owner.onSocketClosed(self.owner);
        }
    };
}

const SendfileResult = struct {
    sent: u64,
    status: enum { ok, again, unsupported, failed },
};

/// One non-blocking sendfile of up to `len` bytes of `file` at `offset`.
fn sendfile(sock: std.posix.socket_t, file: std.posix.fd_t, offset: u64, len: u64) SendfileResult {
    if (comptime builtin.os.tag == .linux) {
        var off: i64 = @intCast(offset);
        const rc = std.os.linux.sendfile(sock, file, &off, @intCast(@min(len, 0x7fff_f000)));
        return switch (std.os.linux.errno(rc)) {
            .SUCCESS => .{ .sent = rc, .status = .ok },
            .AGAIN, .INTR => .{ .sent = 0, .status = .again },
            .INVAL, .NOSYS, .OPNOTSUPP => .{ .sent = 0, .status = .unsupported },
            else => .{ .sent = 0, .status = .failed },
        };
    } else if (comptime builtin.os.tag.isDarwin()) {
        // Darwin reports what went out through `n`, also on EAGAIN.
        var n: std.c.off_t = @intCast(@min(len, std.math.maxInt(i32)));
        const rc = std.c.sendfile(file, sock, @intCast(offset), &n, null, 0);
        const sent: u64 = @intCast(n);
        if (rc == 0) return .{ .sent = sent, .status = .ok };
        return switch (std.posix.errno(rc)) {
            .AGAIN, .INTR => .{ .sent = sent, .status = .again },
            .OPNOTSUPP, .NOTSOCK, .INVAL => .{ .sent = sent, .status = if (sent > 0) .again else .unsupported },
            else => .{ .sent = sent, .status = .failed },
        };
    } else {
        return .{ .sent = 0, .status = .unsupported };
    }
}

/// Accept one queued connection without waiting; null when none is queued.
pub fn acceptNow(listen_fd: std.posix.socket_t) ?std.posix.socket_t {
    if (comptime builtin.os.tag == .linux) {
        const fd = std.c.accept4(listen_fd, null, null, std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC);
        return if (fd < 0) null else fd;
    }
    const fd = std.c.accept(listen_fd, null, null);
    if (fd < 0) return null;
    setNonBlocking(fd);
    _ = std.c.fcntl(fd, std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC));
    return fd;
}

pub fn setNonBlocking(fd: std.posix.socket_t) void {
    const nonblock: u32 = @bitCast(std.c.O{ .NONBLOCK = true });
    _ = std.c.fcntl(fd, std.c.F.SETFL, @as(c_int, @bitCast(nonblock)));
}

/// Caps the kernel's send buffer (and stops it growing on its own).
pub fn setSendBuffer(fd: std.posix.socket_t, bytes: c_int) void {
    _ = std.c.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&bytes), @sizeOf(c_int));
}

pub fn setNoDelay(fd: std.posix.socket_t) void {
    const one: c_int = 1;
    _ = std.c.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&one), @sizeOf(c_int));
}

fn setNoSigpipe(fd: std.posix.socket_t) void {
    if (comptime builtin.os.tag.isDarwin()) {
        const one: c_int = 1;
        _ = std.c.setsockopt(fd, std.posix.SOL.SOCKET, std.c.SO.NOSIGPIPE, std.mem.asBytes(&one), @sizeOf(c_int));
    }
}

/// The peer's IP as 16 bytes (IPv4 in mapped form), for per-client limits.
pub fn peerIpKey(fd: std.posix.socket_t) ?[16]u8 {
    var storage: std.posix.sockaddr.storage = undefined;
    var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    if (std.c.getpeername(fd, @ptrCast(&storage), &len) != 0) return null;
    return ipKey(&storage);
}

/// An address's IP as 16 bytes, IPv4 (plain or mapped) in mapped form.
pub fn ipKey(storage: *const std.posix.sockaddr.storage) ?[16]u8 {
    const sa: *const std.posix.sockaddr = @ptrCast(storage);
    var key = [_]u8{0} ** 16;
    switch (sa.family) {
        std.posix.AF.INET => {
            const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(storage));
            key[10] = 0xff;
            key[11] = 0xff;
            @memcpy(key[12..16], std.mem.asBytes(&in.addr));
        },
        std.posix.AF.INET6 => {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(storage));
            key = in6.addr;
        },
        else => return null,
    }
    return key;
}

/// The peer's address as text, for logs and X-Forwarded-For.
pub fn peerAddress(fd: std.posix.socket_t, buf: []u8) []const u8 {
    var storage: std.posix.sockaddr.storage = undefined;
    var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    if (std.c.getpeername(fd, @ptrCast(&storage), &len) != 0) return "-";
    return formatSockaddr(&storage, buf);
}

pub fn formatSockaddr(storage: *const std.posix.sockaddr.storage, buf: []u8) []const u8 {
    const sa: *const std.posix.sockaddr = @ptrCast(storage);
    switch (sa.family) {
        std.posix.AF.INET => {
            const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(storage));
            const b = std.mem.asBytes(&in.addr);
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch "-";
        },
        std.posix.AF.INET6 => {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(storage));
            return formatIpKey(in6.addr, buf);
        },
        else => return "-",
    }
}

/// An `ipKey` as text; IPv4-mapped addresses read better in their v4 form.
pub fn formatIpKey(key: [16]u8, buf: []u8) []const u8 {
    if (std.mem.eql(u8, key[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ key[12], key[13], key[14], key[15] }) catch "-";
    }
    return formatIp6(key, buf);
}

/// RFC 5952 text form: lowercase, longest zero run compressed.
pub fn formatIp6(addr: [16]u8, buf: []u8) []const u8 {
    var groups: [8]u16 = undefined;
    for (&groups, 0..) |*g, i| g.* = std.mem.readInt(u16, addr[i * 2 ..][0..2], .big);
    var best_start: usize = 8;
    var best_len: usize = 0;
    var i: usize = 0;
    while (i < 8) {
        if (groups[i] != 0) {
            i += 1;
            continue;
        }
        var j = i;
        while (j < 8 and groups[j] == 0) j += 1;
        if (j - i > best_len and j - i >= 2) {
            best_start = i;
            best_len = j - i;
        }
        i = j;
    }
    var w: std.Io.Writer = .fixed(buf);
    i = 0;
    while (i < 8) {
        if (i == best_start) {
            w.writeAll("::") catch return "-";
            i += best_len;
            continue;
        }
        if (i != 0 and i != best_start + best_len) w.writeByte(':') catch return "-";
        w.print("{x}", .{groups[i]}) catch return "-";
        i += 1;
    }
    return w.buffered();
}

test "ipv6 formatting" {
    var buf: [64]u8 = undefined;
    var a = [_]u8{0} ** 16;
    a[15] = 1;
    try std.testing.expectEqualStrings("::1", formatIp6(a, &buf));
    const b = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectEqualStrings("2001:db8::1", formatIp6(b, &buf));
    const c = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectEqualStrings("2001:db8:1:0:1::1", formatIp6(c, &buf));
}

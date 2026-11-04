//! A WebTransport stream paired with a socket: bytes both ways, nothing
//! parsed. At the edge the socket is one end of a socketpair whose other
//! end is an upstream connection of the HTTP proxy, or a player's stream on
//! another worker; at the agent it is a connection to the local server.
//!
//! Backpressure as in the WebTransport relay: reading the stream pauses
//! while the socket has more than `high_water` queued, and reading the
//! socket pauses while the stream has, or while the session's credit
//! (WT_MAX_DATA) refused bytes we now hold. `checkPaused`, on every tick,
//! resumes a socket once the stream's backlog drains, since QUIC says
//! nothing when it does.
//!
//! Endings map one to one: a socket's FIN is the stream's FIN and a reset
//! (or any failure) is a stream reset, both ways, so an upstream body read
//! until the close ends complete only when the local server closed cleanly.
//! Each way ends on its own (a half-close); the socket closes once both have.
const std = @import("std");
const socket = @import("../net/socket.zig");
const wt = @import("../h3/wt_relay.zig");

const high_water = socket.high_water;
const low_water = socket.low_water;

/// WebTransport stream error for "the other side went away".
pub const gone_error = wt.relay_error;

/// `Owner` outlives its pipes, which it keeps in `pipes: Set`.
/// `Owner.Link` holds the session: `session()`, `sid` and
/// `backlog(stream)` (bytes QUIC has yet to send). A link can go before its
/// pipes, which `Set.detach` handles. `connects`: the socket is dialled
/// (the agent's) rather than handed over (the edge's).
pub fn Pipe(comptime Owner: type, comptime connects: bool) type {
    return struct {
        const Self = @This();
        const Link = Owner.Link;

        /// An owner's pipes, by connection and stream.
        pub const Set = struct {
            map: std.AutoArrayHashMapUnmanaged(Key, *Self) = .empty,

            const Key = struct { conn: u64, stream: u64 };

            pub fn deinit(set: *Set, a: std.mem.Allocator) void {
                set.map.deinit(a);
            }

            /// On failure the caller aborts `p`'s socket, whose close frees it.
            pub fn add(set: *Set, a: std.mem.Allocator, p: *Self) !void {
                try set.map.put(a, .{ .conn = p.conn, .stream = p.stream }, p);
            }

            pub fn get(set: *const Set, conn: u64, stream: u64) ?*Self {
                if (set.map.count() == 0) return null;
                return set.map.get(.{ .conn = conn, .stream = stream });
            }

            /// `link`'s session is gone.
            pub fn detach(set: *Set, link: *Link) void {
                for (set.map.values()) |p| if (p.link == link) p.detach();
            }

            /// Every tick: QUIC says nothing when a stream's backlog drains.
            pub fn checkPaused(set: *Set) void {
                for (set.map.values()) |p| p.checkPaused();
            }
        };

        owner: *Owner,
        /// Null once the session is gone: the stream is no more.
        link: ?*Link,
        /// The connection the stream is on, for the owner's maps.
        conn: u64 = 0,
        stream: u64,
        sock: socket.Socket(Self, connects),
        /// What the session credit refused, bound for the stream, and
        /// the FIN after it once the socket's input ended cleanly.
        held: wt.Held = .{},
        /// Our side of the stream is over: FIN or reset sent.
        sent_end: bool = false,
        /// The peer's side is over: FIN or reset received.
        recv_end: bool = false,
        /// We stopped reading the stream: the socket is behind.
        stream_paused: bool = false,
        /// We stopped reading the socket: the stream is behind.
        sock_paused: bool = false,

        pub fn alloc(self: *Self) std.mem.Allocator {
            return self.sock.alloc;
        }

        // ---- the stream ----

        /// The stream only comes in: nothing goes out on it (a peer's
        /// unidirectional stream).
        pub fn inOnly(self: *Self) void {
            self.sent_end = true;
        }

        /// The stream only goes out: the socket hears at once that nothing
        /// will come.
        pub fn outOnly(self: *Self) void {
            self.recv_end = true;
            self.sock.shutdownAfterFlush();
        }

        pub fn onStreamData(self: *Self, data: []const u8, fin: bool) void {
            if (data.len > 0) self.sock.write(data);
            if (fin) {
                self.recv_end = true;
                return if (self.sent_end) self.sock.closeAfterFlush() else self.sock.shutdownAfterFlush();
            }
            if (!self.stream_paused and self.sock.buffered() > high_water) {
                const l = self.link orelse return;
                var s = l.session();
                s.pauseStream(self.stream) catch return;
                self.stream_paused = true;
            }
        }

        /// The peer reset the stream, or asked us to stop sending on it.
        pub fn onStreamAbort(self: *Self) void {
            self.recv_end = true;
            self.endStream(true);
            self.sock.reset();
        }

        pub fn onWritable(self: *Self) void {
            const l = self.link orelse return;
            var s = l.session();
            const fin = self.held.fin;
            if (!wt.drain(self.alloc(), &s, l.sid, self.stream, &self.held)) return;
            if (fin) {
                self.sent_end = true;
                if (self.recv_end) return self.sock.closeAfterFlush();
            }
            self.checkPaused();
        }

        /// Resume whichever side has caught up.
        pub fn checkPaused(self: *Self) void {
            const l = self.link orelse return;
            if (self.sock_paused and self.held.empty() and l.backlog(self.stream) < low_water) {
                self.sock_paused = false;
                self.sock.resumeRead();
            }
            if (self.stream_paused and self.sock.buffered() < low_water) {
                self.stream_paused = false;
                var s = l.session();
                s.resumeStream(self.stream);
            }
        }

        /// Answer on the stream in the socket's place (it never connected),
        /// then end both.
        pub fn replyAndClose(self: *Self, bytes: []const u8) void {
            if (self.link) |l| if (!self.sent_end) {
                var s = l.session();
                _ = wt.sendSome(&s, self.stream, bytes);
                self.endStream(false);
            };
            self.sock.abort();
        }

        /// The session is gone: nothing more goes on the stream, and the
        /// socket closes.
        pub fn detach(self: *Self) void {
            self.link = null;
            self.sent_end = true;
            self.recv_end = true;
            self.sock.reset();
        }

        fn endStream(self: *Self, reset: bool) void {
            if (self.sent_end) return;
            self.sent_end = true;
            const l = self.link orelse return;
            var s = l.session();
            if (reset) s.resetStream(self.stream, gone_error) else s.closeStream(self.stream);
        }

        // ---- the socket ----

        pub fn onSocketData(self: *Self, data: []const u8) void {
            const l = self.link orelse return;
            if (self.sent_end) return;
            var s = l.session();
            var rest = data;
            if (self.held.empty()) rest = data[wt.sendSome(&s, self.stream, data)..];
            if (rest.len > 0) {
                self.held.bytes.appendSlice(self.alloc(), rest) catch return self.onStreamAbort();
                s.notifyWritable(l.sid, self.stream, @min(self.held.bytes.items.len, wt.writable_chunk)) catch {};
            }
            if (!self.sock_paused and (!self.held.empty() or l.backlog(self.stream) > high_water)) {
                self.sock.pauseRead();
                self.sock_paused = true;
            }
        }

        pub fn onSocketEof(self: *Self) void {
            if (self.sock.failed) {
                self.held.bytes.clearAndFree(self.alloc());
                self.endStream(true);
                return self.sock.reset();
            }
            // Held bytes go first; `onWritable` sends the FIN after them.
            if (self.held.empty()) self.endStream(false) else self.held.fin = true;
            // The other direction may still be running; the stream's own
            // end closes the socket.
            if (self.recv_end and self.sent_end) self.sock.closeAfterFlush();
        }

        pub fn onSocketWritable(self: *Self) void {
            self.checkPaused();
        }

        pub fn onSocketConnect(self: *Self, err: ?anyerror) void {
            if (comptime @hasDecl(Owner, "pipeConnected")) self.owner.pipeConnected(self, err);
        }

        pub fn onSocketClosed(self: *Self) void {
            // Bytes still held die with the pipe: a reset, so the far side
            // can't take what it got for the whole.
            self.endStream(!self.held.empty());
            if (!self.recv_end) if (self.link) |l| {
                var s = l.session();
                s.stopSending(self.stream, gone_error);
            };
            _ = self.owner.pipes.map.swapRemove(.{ .conn = self.conn, .stream = self.stream });
            self.held.bytes.deinit(self.alloc());
            self.alloc().destroy(self);
        }
    };
}

//! A WebTransport upstream that reads slowly: at most `budget` bytes per
//! 100 ms per stream, pausing the stream in between. When a stream ends it
//! answers "got <n>" with the byte count. Used to check that the relay
//! holds a fast client back instead of buffering. Usage: PORT CERT KEY
//! [CREDIT_KIB], the last granting each session only that much WebTransport
//! session credit (WT_MAX_DATA), so a sender runs into it.
//!
//! Like a game server, it also opens streams of its own: a session on
//! `/push` gets a unidirectional "uni-hello" and a bidirectional stream that
//! starts "bidi-hello" and answers like the others. A unidirectional stream
//! from the client is answered on one of the server's, and datagrams are
//! echoed.
const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const xev = event_loop.Xev;

const budget = 800 * 1024;

const Stream = struct { entry: *event_loop.ConnEntry, id: u64, window: usize = 0, total: usize = 0, paused: bool = false };

const Handler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;
    /// Keyed by connection and stream: stream ids restart on every connection.
    streams: std.AutoHashMapUnmanaged(Key, Stream) = .empty,
    /// Each connection's session, for the streams we open.
    sessions: std.AutoHashMapUnmanaged(u64, u64) = .empty,

    const Key = struct { conn: u64, stream: u64 };

    /// Paused streams hold a pointer to their connection; drop them with it.
    pub fn onConnectionClosed(self: *Handler, session: *event_loop.Session) void {
        var doomed: std.ArrayListUnmanaged(Key) = .empty;
        defer doomed.deinit(std.heap.page_allocator);
        var it = self.streams.keyIterator();
        while (it.next()) |k| if (k.conn == session.id()) doomed.append(std.heap.page_allocator, k.*) catch {};
        for (doomed.items) |k| _ = self.streams.remove(k);
        _ = self.sessions.remove(session.id());
    }

    /// Answers each forwarding header the relay sent as `echo-<name>`, which
    /// the relay passes back to the client.
    pub fn onConnectRequest(self: *Handler, session: *event_loop.Session, session_id: u64, path: []const u8, headers: []const quic.qpack.Header) void {
        var names: [4][32]u8 = undefined;
        var echo: [4]quic.qpack.Header = undefined;
        var n: usize = 0;
        for (headers) |h| {
            if (n == echo.len) break;
            if (!std.mem.startsWith(u8, h.name, "x-forwarded-") and !std.mem.eql(u8, h.name, "x-real-ip")) continue;
            echo[n] = .{ .name = std.fmt.bufPrint(&names[n], "echo-{s}", .{h.name}) catch continue, .value = h.value };
            n += 1;
        }
        session.acceptSessionWithHeaders(session_id, echo[0..n]) catch {};
        self.sessions.put(std.heap.page_allocator, session.id(), session_id) catch {};
        if (!std.mem.eql(u8, path, "/push")) return;
        const uni = session.openUniStream(session_id, null) catch return;
        session.sendStreamData(uni, "uni-hello") catch {};
        session.closeStream(uni);
        const bidi = session.openBidiStream(session_id, null) catch return;
        session.sendStreamData(bidi, "bidi-hello") catch {};
    }

    pub fn onDatagram(_: *Handler, session: *event_loop.Session, session_id: u64, data: []const u8) void {
        session.sendDatagram(session_id, data) catch {};
    }

    pub fn onStreamData(self: *Handler, session: *event_loop.Session, stream_id: u64, data: []const u8, fin: bool) void {
        const key: Key = .{ .conn = session.id(), .stream = stream_id };
        const gop = self.streams.getOrPut(std.heap.page_allocator, key) catch return;
        if (!gop.found_existing) gop.value_ptr.* = .{ .entry = session.entry, .id = stream_id };
        const s = gop.value_ptr;
        s.total += data.len;
        s.window += data.len;
        if (fin) {
            var buf: [32]u8 = undefined;
            const got = std.fmt.bufPrint(&buf, "got {d}", .{s.total}) catch unreachable;
            // The client's unidirectional streams (ids 2 mod 4) can't carry the answer.
            const reply = if (stream_id & 3 == 2) blk: {
                const sid = self.sessions.get(session.id()) orelse break :blk null;
                break :blk session.openUniStream(sid, null) catch null;
            } else stream_id;
            if (reply) |r| {
                session.sendStreamData(r, got) catch {};
                session.closeStream(r);
            }
            _ = self.streams.remove(key);
            return;
        }
        if (s.window >= budget and !s.paused) {
            session.pauseStream(stream_id) catch return;
            s.paused = true;
        }
    }

    /// Every 100 ms: a fresh budget, and paused streams resume.
    fn tick(self: *Handler) void {
        var it = self.streams.valueIterator();
        while (it.next()) |s| {
            s.window = 0;
            if (s.paused) {
                s.paused = false;
                var session: event_loop.Session = .{ .entry = s.entry };
                session.resumeStream(s.id);
            }
        }
    }
};

var handler: Handler = .{};

fn onTimer(_: ?*void, loop: *xev.Loop, c: *xev.Completion, r: xev.Timer.RunError!void) xev.CallbackAction {
    _ = r catch {};
    handler.tick();
    timer.run(loop, c, 100, void, null, onTimer);
    return .disarm;
}

var timer: xev.Timer = undefined;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const port = try std.fmt.parseInt(u16, args[1], 10);
    var credits: quic.webtransport_flow_control.Credits = .default;
    if (args.len > 4) credits.max_data = try std.fmt.parseInt(u64, args[4], 10) * 1024;
    var server = try event_loop.Server(Handler).init(std.heap.page_allocator, &handler, .{
        .port = port,
        .cert_path = args[2],
        .key_path = args[3],
        .wt_credits = credits,
    });
    defer server.deinit();
    timer = try xev.Timer.init();
    var tc: xev.Completion = .{};
    server.start();
    timer.run(server.eventLoop(), &tc, 100, void, null, onTimer);
    try server.eventLoop().run(.until_done);
}

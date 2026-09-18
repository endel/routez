//! A WebTransport upstream that reads slowly: at most `budget` bytes per
//! 100 ms per stream, pausing the stream in between. When a stream ends it
//! answers "got <n>" with the byte count. Used to check that the relay
//! holds a fast client back instead of buffering. Usage: PORT CERT KEY
//! [CREDIT_KIB], the last granting each session only that much WebTransport
//! session credit (WT_MAX_DATA), so a sender runs into it.
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

    const Key = struct { conn: u64, stream: u64 };

    /// Paused streams hold a pointer to their connection; drop them with it.
    pub fn onConnectionClosed(self: *Handler, session: *event_loop.Session) void {
        var doomed: std.ArrayListUnmanaged(Key) = .empty;
        defer doomed.deinit(std.heap.page_allocator);
        var it = self.streams.keyIterator();
        while (it.next()) |k| if (k.conn == session.id()) doomed.append(std.heap.page_allocator, k.*) catch {};
        for (doomed.items) |k| _ = self.streams.remove(k);
    }

    pub fn onConnectRequest(_: *Handler, session: *event_loop.Session, session_id: u64, _: []const u8, _: []const quic.qpack.Header) void {
        session.acceptSession(session_id) catch {};
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
            session.sendStreamData(stream_id, std.fmt.bufPrint(&buf, "got {d}", .{s.total}) catch unreachable) catch {};
            session.closeStream(stream_id);
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

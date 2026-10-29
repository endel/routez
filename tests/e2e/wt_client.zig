//! WebTransport check for the relay: one bidi stream and one datagram, both
//! must come back echoed. Exits 0 on success, 1 on failure or timeout; a
//! refused session prints `wt-rejected <status>`.
const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;

const Client = struct {
    pub const protocol: event_loop.Protocol = .webtransport;
    stream_echo: std.ArrayListUnmanaged(u8) = .empty,
    stream_done: bool = false,
    datagram_ok: bool = false,
    failed: bool = false,
    payload: []const u8,
    flood: bool = false,
    headers_only: bool = false,
    ready: bool = false,
    rejected: ?[3]u8 = null,

    pub fn onSessionReady(self: *Client, session: *event_loop.ClientSession, session_id: u64, headers: []const quic.qpack.Header) void {
        if (self.headers_only) {
            for (headers) |h| if (std.mem.startsWith(u8, h.name, "echo-")) std.debug.print("{s}: {s}\n", .{ h.name, h.value });
            self.ready = true;
            return session.closeConnection();
        }
        const sid = session.openBidiStream(session_id, null) catch return self.fail(session);
        session.sendStreamData(sid, self.payload) catch return self.fail(session);
        session.closeStream(sid);
        // Flood mode sends no datagram: the slow upstream doesn't echo.
        if (self.flood) {
            self.datagram_ok = true;
            return;
        }
        session.sendDatagram(session_id, "ping") catch return self.fail(session);
    }

    pub fn onStreamData(self: *Client, session: *event_loop.ClientSession, _: u64, data: []const u8, fin: bool) void {
        self.stream_echo.appendSlice(std.heap.page_allocator, data) catch return self.fail(session);
        if (fin) self.stream_done = true;
        self.maybeDone(session);
    }

    pub fn onDatagram(self: *Client, session: *event_loop.ClientSession, _: u64, data: []const u8) void {
        if (std.mem.endsWith(u8, data, "ping")) self.datagram_ok = true;
        self.maybeDone(session);
    }

    pub fn onSessionRejected(self: *Client, session: *event_loop.ClientSession, _: u64, status: []const u8) void {
        self.rejected = if (status.len == 3) status[0..3].* else "???".*;
        self.fail(session);
    }

    fn maybeDone(self: *Client, session: *event_loop.ClientSession) void {
        if (self.stream_done and self.datagram_ok) session.closeConnection();
    }

    fn fail(self: *Client, session: *event_loop.ClientSession) void {
        self.failed = true;
        session.closeConnection();
    }
};

pub fn main(init: std.process.Init) !u8 {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const port = try std.fmt.parseInt(u16, args[1], 10);
    const ca = args[2];
    // Flood mode (a size in MiB as the third argument) sends that much to
    // the slow upstream, which answers "got <n>". Otherwise quic-zig's echo
    // server answers each chunk as "Echo: <chunk>" from a 1 KB buffer.
    const flood_mib: usize = if (args.len > 3) try std.fmt.parseInt(usize, args[3], 10) else 0;
    const payload = try init.arena.allocator().alloc(u8, if (flood_mib > 0) flood_mib * 1024 * 1024 else 500);
    for (payload, 0..) |*b, i| b.* = 'a' + @as(u8, @intCast(i % 26));

    // A fifth argument, "headers", claims an address in forwarding headers
    // and prints the echo-* headers wt-slow-server answers with.
    const headers_only = args.len > 5 and std.mem.eql(u8, args[5], "headers");
    const forged = [_]quic.qpack.Header{
        .{ .name = "x-forwarded-for", .value = "203.0.113.7" },
        .{ .name = "x-real-ip", .value = "198.51.100.1" },
        .{ .name = "x-forwarded-proto", .value = "http" },
    };

    var handler: Client = .{ .payload = payload, .flood = flood_mib > 0, .headers_only = headers_only };
    var client = try event_loop.Client(Client).init(std.heap.page_allocator, &handler, .{
        .port = port,
        .server_name = "localhost",
        .ca = .{ .file = ca },
        .path = if (args.len > 4) args[4] else "/.well-known/webtransport",
        .connect_headers = if (headers_only) &forged else &.{},
    });
    defer client.deinit();
    try client.run();

    var want_buf: [32]u8 = undefined;
    const echoed = if (handler.flood)
        std.mem.eql(u8, handler.stream_echo.items, try std.fmt.bufPrint(&want_buf, "got {d}", .{payload.len}))
    else
        std.mem.startsWith(u8, handler.stream_echo.items, "Echo: ") and std.mem.endsWith(u8, handler.stream_echo.items, payload);
    if (handler.rejected) |status| {
        std.debug.print("wt-rejected {s}\n", .{&status});
        return 1;
    }
    const done = if (handler.headers_only) handler.ready else echoed and handler.datagram_ok;
    if (!handler.failed and done) {
        std.debug.print("wt-ok\n", .{});
        return 0;
    }
    std.debug.print("wt-fail stream={d}/{d} done={} datagram={}\n", .{ handler.stream_echo.items.len, payload.len, handler.stream_done, handler.datagram_ok });
    return 1;
}

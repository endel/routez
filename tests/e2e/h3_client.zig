//! Sequential HTTP/3 GETs over one connection, for the migration check:
//! exits 0 once `count` responses of 200 came back, 1 on failure or after
//! 15 s. Usage: h3-test-client PORT CA_FILE COUNT [idle]
//! With `idle` the connection is left open after the last response, for
//! checking the server's idle timeout.
const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;

const Client = struct {
    pub const protocol: event_loop.Protocol = .h3;
    want: u32,
    idle: bool = false,
    done: u32 = 0,
    ok: bool = true,

    fn send(self: *Client, session: *event_loop.ClientSession) void {
        const headers = [_]qpack.Header{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "127.0.0.1" },
            .{ .name = ":path", .value = "/" },
        };
        _ = session.sendRequest(&headers, null) catch {
            self.ok = false;
            session.closeConnection();
        };
    }

    pub fn onConnected(self: *Client, session: *event_loop.ClientSession) void {
        self.send(session);
    }

    pub fn onHeaders(self: *Client, _: *event_loop.ClientSession, _: u64, headers: []const qpack.Header) void {
        for (headers) |h| {
            if (std.mem.eql(u8, h.name, ":status") and !std.mem.eql(u8, h.value, "200")) self.ok = false;
        }
    }

    pub fn onData(_: *Client, session: *event_loop.ClientSession, _: u64, _: usize) void {
        var buf: [4096]u8 = undefined;
        while (session.recvBody(&buf) > 0) {}
    }

    pub fn onFinished(self: *Client, session: *event_loop.ClientSession, _: u64) void {
        self.done += 1;
        if (!self.ok) return session.closeConnection();
        if (self.done >= self.want) {
            if (self.idle) return std.debug.print("h3-idle\n", .{});
            return session.closeConnection();
        }
        self.send(session);
    }
};

fn watchdog() void {
    quic.sys.sleepNs(15 * std.time.ns_per_s);
    std.debug.print("h3-fail timeout\n", .{});
    std.process.exit(1);
}

pub fn main(init: std.process.Init) !u8 {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const port = try std.fmt.parseInt(u16, args[1], 10);
    const want = try std.fmt.parseInt(u32, args[3], 10);
    (try std.Thread.spawn(.{}, watchdog, .{})).detach();

    var handler: Client = .{ .want = want, .idle = args.len > 4 and std.mem.eql(u8, args[4], "idle") };
    var client = try event_loop.Client(Client).init(std.heap.page_allocator, &handler, .{
        .port = port,
        .server_name = "localhost",
        .ca = .{ .file = args[2] },
    });
    defer client.deinit();
    try client.run();

    if (handler.ok and handler.done >= want) {
        std.debug.print("h3-ok {d}\n", .{handler.done});
        return 0;
    }
    std.debug.print("h3-fail done={d}/{d}\n", .{ handler.done, want });
    return 1;
}

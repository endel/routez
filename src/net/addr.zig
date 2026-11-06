const std = @import("std");
const netdb = @import("quic").sys.netdb;
const IpAddress = std.Io.net.IpAddress;

/// Resolve `host` (literal or name, via getaddrinfo) and `port`. Blocking;
/// only used at startup.
pub fn resolve(host: []const u8, port: u16) !IpAddress {
    var one: [1]IpAddress = undefined;
    _ = try resolveAll(host, port, &one);
    return one[0];
}

/// Every address `host` resolves to, in the resolver's order and without
/// repeats, up to `out.len`; how many. Blocking.
pub fn resolveAll(host: []const u8, port: u16, out: []IpAddress) !usize {
    if (IpAddress.parse(host, port)) |a| {
        out[0] = a;
        return 1;
    } else |_| {}
    var host_buf: [256]u8 = undefined;
    const host_z = std.fmt.bufPrintSentinel(&host_buf, "{s}", .{host}, 0) catch return error.NameTooLong;
    var port_buf: [8]u8 = undefined;
    const port_z = std.fmt.bufPrintSentinel(&port_buf, "{d}", .{port}, 0) catch unreachable;
    var hints = std.mem.zeroes(netdb.addrinfo);
    hints.family = std.posix.AF.UNSPEC;
    hints.socktype = std.posix.SOCK.DGRAM; // one entry per address, not per socket type
    var res: ?*netdb.addrinfo = null;
    if (netdb.getaddrinfo(host_z, port_z, &hints, &res) != 0) return error.UnknownHostName;
    defer if (res) |r| netdb.freeaddrinfo(r);
    var n: usize = 0;
    var it = res;
    while (it) |ai| : (it = ai.next) {
        if (n == out.len) break;
        const sa = ai.addr orelse continue;
        var storage = std.mem.zeroes(std.posix.sockaddr.storage);
        const len = @min(@as(usize, ai.addrlen), @sizeOf(std.posix.sockaddr.storage));
        @memcpy(std.mem.asBytes(&storage)[0..len], @as([*]const u8, @ptrCast(sa))[0..len]);
        const a = fromStorage(&storage) orelse continue;
        const seen = for (out[0..n]) |o| {
            if (o.eql(&a)) break true;
        } else false;
        if (!seen) {
            out[n] = a;
            n += 1;
        }
    }
    if (n == 0) return error.UnknownHostName;
    return n;
}

pub fn storageLen(sa: *const std.posix.sockaddr.storage) std.posix.socklen_t {
    const base: *const std.posix.sockaddr = @ptrCast(sa);
    return if (base.family == std.posix.AF.INET6) @sizeOf(std.posix.sockaddr.in6) else @sizeOf(std.posix.sockaddr.in);
}

pub fn toStorage(ip: std.Io.net.IpAddress) std.posix.sockaddr.storage {
    var s = std.mem.zeroes(std.posix.sockaddr.storage);
    switch (ip) {
        .ip4 => |a| {
            const in: *std.posix.sockaddr.in = @ptrCast(@alignCast(&s));
            in.* = .{ .port = std.mem.nativeToBig(u16, a.port), .addr = @bitCast(a.bytes) };
        },
        .ip6 => |a| {
            const in6: *std.posix.sockaddr.in6 = @ptrCast(@alignCast(&s));
            in6.* = .{ .port = std.mem.nativeToBig(u16, a.port), .flowinfo = a.flow, .addr = a.bytes, .scope_id = a.interface.index };
        },
    }
    return s;
}

pub fn fromStorage(storage: *const std.posix.sockaddr.storage) ?IpAddress {
    const sa: *const std.posix.sockaddr = @ptrCast(storage);
    switch (sa.family) {
        std.posix.AF.INET => {
            const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(storage));
            return .{ .ip4 = .{ .bytes = std.mem.toBytes(in.addr), .port = std.mem.bigToNative(u16, in.port) } };
        },
        std.posix.AF.INET6 => {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(storage));
            return .{ .ip6 = .{
                .bytes = in6.addr,
                .port = std.mem.bigToNative(u16, in6.port),
                .flow = in6.flowinfo,
                .interface = .{ .index = in6.scope_id },
            } };
        },
        else => return null,
    }
}

test "resolve literal" {
    const a = try resolve("127.0.0.1", 8080);
    try std.testing.expectEqual(@as(u16, 8080), a.getPort());
    const b = try resolve("::1", 9);
    try std.testing.expect(b == .ip6);
}

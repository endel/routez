const std = @import("std");
const quic = @import("quic");
const IpAddress = std.Io.net.IpAddress;

/// Resolve `host` (literal or name, via getaddrinfo) and `port`. Blocking;
/// only used at startup.
pub fn resolve(host: []const u8, port: u16) !IpAddress {
    if (IpAddress.parse(host, port)) |a| return a else |_| {}
    const storage = try quic.sys.resolveHost(host, port);
    return fromStorage(&storage) orelse error.UnknownHostName;
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

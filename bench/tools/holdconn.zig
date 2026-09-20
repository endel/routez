//! Opens many TCP connections to one address and holds them, for the rows that
//! ask what an idle or stalled client costs the server.
//!
//!     holdconn <host:port> --count N [--mode idle|partial|slow] [--seconds N]
//!                          [--request PATH] [--rate N]
//!
//!   idle     complete one request, then hold the connection doing nothing, so
//!            the cost is a parked keep-alive connection
//!   partial  send a request head that never ends (slowloris), one header line
//!            every few seconds to stay inside any header timeout
//!   slow     request a body, then read it a little at a time, so the server
//!            has to hold the response
//!
//! Prints one JSON line when the hold is over. Linux only, on libc, like
//! bench/tools/udpload.zig.
const std = @import("std");
const linux = std.os.linux;

extern "c" fn socket(domain: c_int, sock_type: c_int, protocol: c_int) c_int;
extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: u32) c_int;
extern "c" fn send(fd: c_int, buf: *const anyopaque, len: usize, flags: c_int) isize;
extern "c" fn recv(fd: c_int, buf: *anyopaque, len: usize, flags: c_int) isize;
extern "c" fn poll(fds: [*]linux.pollfd, n: c_ulong, timeout: c_int) c_int;
extern "c" fn setsockopt(fd: c_int, level: c_int, opt: c_int, val: *const anyopaque, len: u32) c_int;
extern "c" fn write(fd: c_int, buf: *const anyopaque, n: usize) isize;

const SockAddr = extern struct {
    family: u16 = linux.AF.INET,
    port: u16,
    addr: u32,
    zero: [8]u8 = @splat(0),
};

fn die(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("holdconn: " ++ fmt ++ "\n", args);
    std.process.exit(2);
}

fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn sleepNs(ns: u64) void {
    const ts = linux.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = linux.nanosleep(&ts, null);
}

fn parseTarget(text: []const u8) SockAddr {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse die("want host:port, got {s}", .{text});
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch die("bad port in {s}", .{text});
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, text[0..colon], '.');
    for (&octets) |*o| {
        const part = it.next() orelse die("want an IPv4 address, got {s}", .{text[0..colon]});
        o.* = std.fmt.parseInt(u8, part, 10) catch die("bad address {s}", .{text[0..colon]});
    }
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(octets) };
}

const Mode = enum { idle, partial, slow };

const Opts = struct {
    count: usize = 10_000,
    seconds: u64 = 10,
    mode: Mode = .idle,
    request: []const u8 = "/ping",
    /// Connections opened per second; 0 is as fast as the kernel allows.
    rate: u64 = 0,
};

pub fn main(init: std.process.Init) !u8 {
    const alloc = init.arena.allocator();
    const args = try init.minimal.args.toSlice(alloc);
    if (args.len < 3) die(
        "usage: holdconn <host:port> --count N [--mode idle|partial|slow] [--seconds N] [--request PATH] [--rate N]",
        .{},
    );
    const target = parseTarget(args[1]);
    var o: Opts = .{};
    var i: usize = 2;
    while (i + 1 < args.len) : (i += 2) {
        const v = args[i + 1];
        if (std.mem.eql(u8, args[i], "--count")) {
            o.count = try std.fmt.parseInt(usize, v, 10);
        } else if (std.mem.eql(u8, args[i], "--seconds")) {
            o.seconds = try std.fmt.parseInt(u64, v, 10);
        } else if (std.mem.eql(u8, args[i], "--request")) {
            o.request = v;
        } else if (std.mem.eql(u8, args[i], "--rate")) {
            o.rate = try std.fmt.parseInt(u64, v, 10);
        } else if (std.mem.eql(u8, args[i], "--mode")) {
            o.mode = std.meta.stringToEnum(Mode, v) orelse die("unknown mode {s}", .{v});
        } else die("unknown option {s}", .{args[i]});
    }

    const pfds = try alloc.alloc(linux.pollfd, o.count);
    var head: [512]u8 = undefined;
    const full = try std.fmt.bufPrint(&head, "GET {s} HTTP/1.1\r\nHost: bench\r\nConnection: keep-alive\r\n\r\n", .{o.request});
    // A head with no blank line: the server must keep waiting for the rest.
    const partial = try std.fmt.bufPrint(head[full.len..], "GET {s} HTTP/1.1\r\nHost: bench\r\n", .{o.request});

    var opened: usize = 0;
    var failed: usize = 0;
    var rbuf: [4096]u8 = undefined;
    const start = nowNs();
    const interval_ns: u64 = if (o.rate == 0) 0 else std.time.ns_per_s / o.rate;
    var next = start;
    for (pfds) |*pfd| {
        if (interval_ns != 0) {
            const now = nowNs();
            if (now < next) sleepNs(next - now);
            next += interval_ns;
        }
        const fd = socket(linux.AF.INET, linux.SOCK.STREAM, 0);
        if (fd < 0) {
            failed += 1;
            pfd.* = .{ .fd = -1, .events = 0, .revents = 0 };
            continue;
        }
        if (connect(fd, &target, @sizeOf(SockAddr)) < 0) {
            failed += 1;
            pfd.* = .{ .fd = -1, .events = 0, .revents = 0 };
            continue;
        }
        pfd.* = .{ .fd = fd, .events = linux.POLL.IN, .revents = 0 };
        switch (o.mode) {
            .idle, .slow => {
                _ = send(fd, full.ptr, full.len, 0);
                // Read the head so the exchange really completed, then stop:
                // in .idle the connection is parked, in .slow the body is left
                // for the server to hold.
                _ = recv(fd, &rbuf, if (o.mode == .idle) rbuf.len else 64, 0);
            },
            .partial => _ = send(fd, partial.ptr, partial.len, 0),
        }
        opened += 1;
    }
    const connect_us = (nowNs() - start) / std.time.ns_per_us;

    // Hold. In .partial, dribble a header now and then so no header timeout
    // ends the connection before the measurement does.
    const until = nowNs() + o.seconds * std.time.ns_per_s;
    var closed: usize = 0;
    var ticks: usize = 0;
    while (nowNs() < until) : (ticks += 1) {
        sleepNs(std.time.ns_per_s);
        if (o.mode == .partial and ticks % 5 == 4) {
            for (pfds) |pfd| {
                if (pfd.fd < 0) continue;
                _ = send(pfd.fd, "X-Pad: 1\r\n", 10, 0);
            }
        }
        if (o.mode == .slow) {
            for (pfds) |pfd| {
                if (pfd.fd < 0) continue;
                _ = recv(pfd.fd, &rbuf, 1024, 0); // a trickle, not the whole body
            }
        }
        // A server that hung up sets POLLHUP or returns 0 from recv.
        if (poll(pfds.ptr, pfds.len, 0) > 0) {
            for (pfds) |*pfd| {
                if (pfd.fd < 0 or pfd.revents & (linux.POLL.HUP | linux.POLL.ERR) == 0) continue;
                closed += 1;
                pfd.fd = -1;
            }
        }
    }

    var buf: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "{{\"opened\":{d},\"failed\":{d},\"closed_by_server\":{d},\"connect_us\":{d},\"mode\":\"{s}\"}}\n", .{ opened, failed, closed, connect_us, @tagName(o.mode) });
    _ = write(1, line.ptr, line.len);
    return 0;
}

//! UDP echo server and load generator for the layer-4 rows.
//!
//!     udpload server <port> [ports...]
//!     udpload client <host:port> [--flows N] [--pps N] [--seconds N] [--size N]
//!
//! The client holds `flows` sockets, each connected, so a proxy sees that many
//! client flows and replies come back on the same 4-tuple. It sends at a fixed
//! total rate and times each round trip into a log2 histogram with 8 buckets per
//! octave (about 9% resolution), the shape bench/ws/client.cjs uses. One JSON
//! line on stdout.
//!
//! Linux only, like the suites that run it, and straight on libc: the socket
//! calls are a handful and this stays independent of the server's own helpers.
const std = @import("std");
const linux = std.os.linux;

extern "c" fn socket(domain: c_int, sock_type: c_int, protocol: c_int) c_int;
extern "c" fn bind(fd: c_int, addr: *const anyopaque, len: u32) c_int;
extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: u32) c_int;
extern "c" fn send(fd: c_int, buf: *const anyopaque, len: usize, flags: c_int) isize;
extern "c" fn recv(fd: c_int, buf: *anyopaque, len: usize, flags: c_int) isize;
extern "c" fn sendto(fd: c_int, buf: *const anyopaque, len: usize, flags: c_int, addr: *const anyopaque, alen: u32) isize;
extern "c" fn recvfrom(fd: c_int, buf: *anyopaque, len: usize, flags: c_int, addr: ?*anyopaque, alen: ?*u32) isize;
extern "c" fn poll(fds: [*]linux.pollfd, n: c_ulong, timeout: c_int) c_int;
extern "c" fn setsockopt(fd: c_int, level: c_int, opt: c_int, val: *const anyopaque, len: u32) c_int;
extern "c" fn write(fd: c_int, buf: *const anyopaque, n: usize) isize;

const SUB_BITS = 3; // buckets per octave = 8
const BUCKETS = 64 << SUB_BITS;

const Hist = struct {
    counts: [BUCKETS]u64 = @splat(0),
    n: u64 = 0,

    fn add(self: *Hist, us: u64) void {
        const v = us + 1;
        const octave = 63 - @clz(v);
        const idx: usize = if (octave < SUB_BITS)
            @intCast(v)
        else
            @intCast((octave << SUB_BITS) | ((v >> @intCast(octave - SUB_BITS)) & ((1 << SUB_BITS) - 1)));
        self.counts[@min(idx, BUCKETS - 1)] += 1;
        self.n += 1;
    }

    /// Upper bound of the bucket: the conservative reading of a log2 histogram.
    fn bound(idx: usize) u64 {
        if (idx < (1 << SUB_BITS)) return idx;
        const octave = idx >> SUB_BITS;
        const sub = idx & ((1 << SUB_BITS) - 1);
        return ((@as(u64, 1) << SUB_BITS) + sub + 1) << @intCast(octave - SUB_BITS);
    }

    fn percentile(self: *const Hist, p: f64) u64 {
        if (self.n == 0) return 0;
        const want: u64 = @intFromFloat(@ceil(p / 100.0 * @as(f64, @floatFromInt(self.n))));
        var seen: u64 = 0;
        for (self.counts, 0..) |c, i| {
            seen += c;
            if (seen >= want) return bound(i);
        }
        return bound(BUCKETS - 1);
    }
};

/// Monotonic nanoseconds. std.time carries only constants, and this tool is
/// Linux-only, so read the clock directly.
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

fn die(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("udpload: " ++ fmt ++ "\n", args);
    std.process.exit(2);
}

const SockAddr = extern struct {
    family: u16 = linux.AF.INET,
    port: u16, // network order
    addr: u32, // network order
    zero: [8]u8 = @splat(0),
};

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

fn setInt(fd: c_int, opt: u32, value: c_int) void {
    _ = setsockopt(fd, linux.SOL.SOCKET, @intCast(opt), &value, @sizeOf(c_int));
}

fn udpSocket() c_int {
    const fd = socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    if (fd < 0) die("socket failed", .{});
    // A short queue would drop datagrams before the process saw them, which
    // would read as proxy loss. rmem_max may cap this; the suite records it.
    setInt(fd, linux.SO.RCVBUF, 8 << 20);
    return fd;
}

fn runServer(ports: []const []const u8) !void {
    const alloc = std.heap.smp_allocator;
    const fds = try alloc.alloc(linux.pollfd, ports.len);
    for (ports, fds) |p, *pfd| {
        const port = std.fmt.parseInt(u16, p, 10) catch die("bad port {s}", .{p});
        const fd = udpSocket();
        setInt(fd, linux.SO.REUSEADDR, 1);
        const sa = SockAddr{ .port = std.mem.nativeToBig(u16, port), .addr = 0 };
        if (bind(fd, &sa, @sizeOf(SockAddr)) < 0) die("bind :{d} failed", .{port});
        pfd.* = .{ .fd = fd, .events = linux.POLL.IN, .revents = 0 };
    }
    var buf: [2048]u8 = undefined;
    while (true) {
        if (poll(fds.ptr, fds.len, -1) < 0) continue;
        for (fds) |pfd| {
            if (pfd.revents & linux.POLL.IN == 0) continue;
            while (true) {
                var from: [128]u8 align(8) = undefined;
                var from_len: u32 = from.len;
                const n = recvfrom(pfd.fd, &buf, buf.len, 0, &from, &from_len);
                if (n <= 0) break;
                _ = sendto(pfd.fd, &buf, @intCast(n), 0, &from, from_len);
            }
        }
    }
}

const Client = struct {
    flows: usize = 100,
    pps: u64 = 10_000,
    seconds: u64 = 10,
    size: usize = 64,
};

fn runClient(target: SockAddr, cfg: Client) !void {
    const alloc = std.heap.smp_allocator;
    const pfds = try alloc.alloc(linux.pollfd, cfg.flows);
    for (pfds) |*pfd| {
        const fd = udpSocket();
        if (connect(fd, &target, @sizeOf(SockAddr)) < 0) die("connect failed", .{});
        // Non-blocking: a reply that hasn't arrived must not stall the sender.
        const flags = linux.fcntl(fd, linux.F.GETFL, 0);
        _ = linux.fcntl(fd, linux.F.SETFL, flags | @as(usize, 0o4000)); // O_NONBLOCK
        pfd.* = .{ .fd = fd, .events = linux.POLL.IN, .revents = 0 };
    }

    const size = @max(cfg.size, 16);
    const payload = try alloc.alloc(u8, size);
    @memset(payload, 'x');
    const rbuf = try alloc.alloc(u8, size + 64);

    var hist: Hist = .{};
    var sent: u64 = 0;
    var received: u64 = 0;
    const start = nowNs();
    const end = start + cfg.seconds * std.time.ns_per_s;
    const interval_ns: u64 = @max(1, std.time.ns_per_s / @max(1, cfg.pps));

    var next = start;
    var i: usize = 0;
    var now = start;
    while (now < end) : (now = nowNs()) {
        if (now < next) {
            sleepNs(@min(next - now, std.time.ns_per_ms));
            continue;
        }
        next += interval_ns;
        std.mem.writeInt(u64, payload[0..8], now, .little);
        if (send(pfds[i % cfg.flows].fd, payload.ptr, size, 0) > 0) sent += 1;
        i += 1;
        // Amortize the poll over a batch: one per send would dominate the run.
        if (i % 64 == 0) drain(pfds, rbuf, &hist, &received);
    }
    // Replies still in flight arrived late; count them before declaring loss.
    var spins: usize = 0;
    while (spins < 200) : (spins += 1) {
        const before = received;
        drain(pfds, rbuf, &hist, &received);
        if (received == before) sleepNs(std.time.ns_per_ms);
    }
    // The send window, separate from the drain that follows it: the achieved
    // rate is sends over the window, not over the whole run.
    const send_us: u64 = (now - start) / std.time.ns_per_us;
    const elapsed_us: u64 = (nowNs() - start) / std.time.ns_per_us;
    var buf: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(
        &buf,
        "{{\"flows\":{d},\"target_pps\":{d},\"sent\":{d},\"received\":{d}," ++
            "\"send_us\":{d},\"elapsed_us\":{d}," ++
            "\"p50_us\":{d},\"p99_us\":{d},\"p999_us\":{d},\"size\":{d}}}\n",
        .{
            cfg.flows,           cfg.pps,             sent,                  received,
            send_us,             elapsed_us,          hist.percentile(50),   hist.percentile(99),
            hist.percentile(99.9), size,
        },
    );
    _ = write(1, line.ptr, line.len);
}

/// Reads whatever has come back. poll first, so a run with many flows does not
/// spend itself on recv calls for sockets that have nothing: scanning every
/// socket after every send is quadratic in the flow count, and at 10k flows that
/// alone held the rate down to a few hundred a second.
fn drain(pfds: []linux.pollfd, rbuf: []u8, hist: *Hist, received: *u64) void {
    if (poll(pfds.ptr, pfds.len, 0) <= 0) return;
    for (pfds) |pfd| {
        if (pfd.revents & linux.POLL.IN == 0) continue;
        while (true) {
            const n = recv(pfd.fd, rbuf.ptr, rbuf.len, 0);
            if (n < 8) break;
            const t0 = std.mem.readInt(u64, rbuf[0..8], .little);
            const rtt: u64 = nowNs() -| t0;
            hist.add(rtt / std.time.ns_per_us);
            received.* += 1;
        }
    }
}

pub fn main(init: std.process.Init) !u8 {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3) die(
        "usage: udpload server <port>... | udpload client <host:port> [--flows N] [--pps N] [--seconds N] [--size N]",
        .{},
    );
    if (std.mem.eql(u8, args[1], "server")) {
        try runServer(args[2..]);
        return 0;
    }
    if (!std.mem.eql(u8, args[1], "client")) die("unknown mode {s}", .{args[1]});
    var cfg: Client = .{};
    var i: usize = 3;
    while (i + 1 < args.len) : (i += 2) {
        const v = args[i + 1];
        if (std.mem.eql(u8, args[i], "--flows")) {
            cfg.flows = try std.fmt.parseInt(usize, v, 10);
        } else if (std.mem.eql(u8, args[i], "--pps")) {
            cfg.pps = try std.fmt.parseInt(u64, v, 10);
        } else if (std.mem.eql(u8, args[i], "--seconds")) {
            cfg.seconds = try std.fmt.parseInt(u64, v, 10);
        } else if (std.mem.eql(u8, args[i], "--size")) {
            cfg.size = try std.fmt.parseInt(usize, v, 10);
        } else die("unknown option {s}", .{args[i]});
    }
    try runClient(parseTarget(args[2]), cfg);
    return 0;
}

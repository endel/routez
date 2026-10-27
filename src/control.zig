//! The control socket behind `routez ctl`. A line protocol: one command a
//! line, each answered by a line `ok` or `error: <reason>`:
//!
//!     ban <address>[/<prefix>] <seconds>
//!     unban <address>[/<prefix>]
//!     bans        a "<network> <seconds left>" line per ban, then ok
//!
//! Bans live in the client table (`client_limits.zig`), so every worker and
//! generation sees one at once; they last until they end or the process
//! exits. One thread serves one client at a time with blocking I/O: this is
//! for operators and their tools, never on a request's path.
const std = @import("std");
const quic = @import("quic");
const client_limits = @import("client_limits.zig");
const access = @import("access.zig");
const socket = @import("net/socket.zig");
const logs = @import("logs.zig");

const sys = quic.sys;
const posix = std.posix;
const log = std.log.scoped(.control);

/// Where `routez ctl` looks without `-s`.
pub const default_path = "/run/routez.sock";

/// Longest command line; a longer one ends the session.
const max_line = 256;
/// A client silent this long is dropped, so it can't hold the socket.
const idle_timeout_s = 5;
/// About ten years.
const max_ban_s = 10 * 365 * 24 * 3600;

/// The socket `listen` bound, kept for the life of the process.
var bound_buf: [@sizeOf(@FieldType(std.c.sockaddr.un, "path"))]u8 = undefined;
pub var bound: []const u8 = "";

fn address(path: []const u8) error{NameTooLong}!std.c.sockaddr.un {
    var addr: std.c.sockaddr.un = .{ .path = @splat(0) };
    if (path.len >= addr.path.len) return error.NameTooLong;
    @memcpy(addr.path[0..path.len], path);
    return addr;
}

/// Bind `path`, mode 0600, taking over a socket a previous run left there.
pub fn listen(io: std.Io, path: []const u8) !posix.fd_t {
    const addr = try address(path);
    const fd = try sys.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer sys.close(fd);
    // Created owner-only, so there's no moment it is open wider.
    const old_mask = std.c.umask(0o177);
    defer _ = std.c.umask(old_mask);
    sys.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))) catch |err| {
        if (err != error.AddressInUse or !stale(io, path, &addr)) return err;
        try std.Io.Dir.cwd().deleteFile(io, path);
        try sys.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
    };
    try sys.listen(fd, 8);
    @memcpy(bound_buf[0..path.len], path);
    bound = bound_buf[0..path.len];
    return fd;
}

/// Remove the socket at exit. May fail once `user` took over; the next
/// start replaces it then.
pub fn unlink(io: std.Io) void {
    if (bound.len > 0) std.Io.Dir.cwd().deleteFile(io, bound) catch {};
}

/// A socket file nothing listens on: left by a run that didn't remove it.
fn stale(io: std.Io, path: []const u8, addr: *const std.c.sockaddr.un) bool {
    const st = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return false;
    if (st.kind != .unix_domain_socket) return false;
    const fd = sys.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch return false;
    defer sys.close(fd);
    return std.c.connect(fd, @ptrCast(addr), @sizeOf(std.c.sockaddr.un)) != 0;
}

/// Serve `fd` for the life of the process.
pub fn spawn(io: std.Io, fd: posix.fd_t, table: *client_limits.Table) !void {
    const t = try std.Thread.spawn(.{}, run, .{ io, fd, table });
    t.detach();
}

fn run(io: std.Io, fd: posix.fd_t, table: *client_limits.Table) void {
    while (true) {
        const c = sys.accept(fd) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionAborted => continue,
            else => {
                log.err("accept: {s}", .{@errorName(err)});
                // Out of descriptors, say: don't spin on it.
                sys.sleepNs(std.time.ns_per_s);
                continue;
            },
        };
        defer sys.close(c);
        serve(io, c, table) catch {};
    }
}

fn serve(io: std.Io, c: posix.fd_t, table: *client_limits.Table) !void {
    const tv: posix.timeval = .{ .sec = idle_timeout_s, .usec = 0 };
    _ = std.c.setsockopt(c, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(posix.timeval));
    var in: [max_line]u8 = undefined;
    var len: usize = 0;
    var out: Out = .{ .file = .{ .fd = c } };
    while (true) {
        // 0 on EOF, and on the timeout (EAGAIN).
        const n = try sys.read(c, in[len..]);
        if (n == 0) return;
        len += n;
        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, in[0..len], start, '\n')) |nl| {
            try execute(io, table, std.mem.trimEnd(u8, in[start..nl], "\r"), &out);
            start = nl + 1;
        }
        try out.flush();
        std.mem.copyForwards(u8, &in, in[start..len]);
        len -= start;
        if (len == in.len) {
            try out.print("error: line longer than {d} bytes\n", .{max_line});
            return out.flush();
        }
    }
}

/// Replies, buffered and written in full.
const Out = struct {
    file: sys.File,
    buf: [4096]u8 = undefined,
    len: usize = 0,

    /// Room for any one line this module writes.
    const max_reply = 128;

    fn print(self: *Out, comptime fmt: []const u8, args: anytype) !void {
        if (self.buf.len - self.len < max_reply) try self.flush();
        const s = std.fmt.bufPrint(self.buf[self.len..], fmt, args) catch return;
        self.len += s.len;
    }

    fn flush(self: *Out) !void {
        defer self.len = 0;
        try self.file.writeAll(self.buf[0..self.len]);
    }
};

fn parseNet(text: ?[]const u8) ?access.Rule {
    const r = access.parse(.deny, text orelse return null) catch return null;
    // `all` or a /0: banning everyone is a firewall's job, not a typo's.
    // An IPv4 /0 is 96 bits of the mapped form.
    if (r.bits == 0 or (r.bits == 96 and access.isV4(r.net))) return null;
    return r;
}

fn execute(io: std.Io, table: *client_limits.Table, line: []const u8, out: *Out) !void {
    var words = std.mem.tokenizeAny(u8, line, " \t");
    const cmd = words.next() orelse return;
    var buf: [64]u8 = undefined;
    if (std.mem.eql(u8, cmd, "ban")) {
        const net = parseNet(words.next());
        const secs = std.fmt.parseInt(u32, words.next() orelse "", 10) catch 0;
        if (net == null or secs == 0 or secs > max_ban_s or words.next() != null)
            return out.print("error: usage: ban <address>[/<prefix>] <seconds>, 1 to {d} seconds\n", .{max_ban_s});
        const now = sys.nanoTimestamp();
        table.ban(io, net.?.net, net.?.bits, now + @as(i64, secs) * std.time.ns_per_s, now) catch
            return out.print("error: the client table is full; raise limits.max_tracked_clients\n", .{});
        log.info("banned {s} for {d} s", .{ formatNet(net.?.net, net.?.bits, &buf), secs });
        return out.print("ok\n", .{});
    }
    if (std.mem.eql(u8, cmd, "unban")) {
        const net = parseNet(words.next());
        if (net == null or words.next() != null) return out.print("error: usage: unban <address>[/<prefix>]\n", .{});
        if (!table.unban(io, net.?.net, net.?.bits)) return out.print("error: not banned\n", .{});
        log.info("unbanned {s}", .{formatNet(net.?.net, net.?.bits, &buf)});
        return out.print("ok\n", .{});
    }
    if (std.mem.eql(u8, cmd, "bans")) {
        if (words.next() != null) return out.print("error: usage: bans\n", .{});
        const now = sys.nanoTimestamp();
        var cursor: client_limits.Table.BanCursor = .{};
        var batch: [64]client_limits.Table.Ban = undefined;
        while (true) {
            const got = table.nextBans(io, &cursor, now, &batch);
            if (got.len == 0) break;
            for (got) |b| {
                const left = std.math.divCeil(i64, b.until_ns - now, std.time.ns_per_s) catch 0;
                try out.print("{s} {d}\n", .{ formatNet(b.net, b.bits, &buf), left });
            }
        }
        return out.print("ok\n", .{});
    }
    try out.print("error: unknown command '{s}'\n", .{printable(cmd, buf[0..32])});
}

/// An address alone when the ban is on one, else in CIDR form.
fn formatNet(net: client_limits.Ip, bits: u8, buf: *[64]u8) []const u8 {
    const v4 = access.isV4(net);
    const shown = if (v4) bits -| 96 else bits;
    const ip = socket.formatIpKey(net, buf[0..48]);
    if (shown == @as(u8, if (v4) 32 else 128)) return ip;
    const suffix = std.fmt.bufPrint(buf[ip.len..], "/{d}", .{shown}) catch return ip;
    return buf[0 .. ip.len + suffix.len];
}

/// `text` cut short and with control bytes replaced, for echoing back.
fn printable(text: []const u8, buf: []u8) []const u8 {
    const n = @min(text.len, buf.len);
    for (text[0..n], buf[0..n]) |c, *o| o.* = if (c < 0x20 or c >= 0x7f) '?' else c;
    return buf[0..n];
}

/// `routez ctl [-s <socket>] <command>...`: send one command and print the
/// reply; 0 when it is `ok`.
pub fn client(path: []const u8, words: []const [:0]const u8) u8 {
    var line: [max_line]u8 = undefined;
    var w: std.Io.Writer = .fixed(&line);
    for (words) |word| w.print("{s} ", .{word}) catch {
        std.debug.print("routez ctl: command too long\n", .{});
        return 2;
    };
    line[w.end - 1] = '\n';

    const addr = address(path) catch {
        std.debug.print("routez ctl: socket path too long\n", .{});
        return 2;
    };
    const fd = sys.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch |err| {
        std.debug.print("routez ctl: {s}\n", .{@errorName(err)});
        return 1;
    };
    defer sys.close(fd);
    const rc = std.c.connect(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
    if (rc != 0) {
        std.debug.print("routez ctl: can't connect to {s}: {s}\n", .{ path, @tagName(posix.errno(rc)) });
        return 1;
    }
    (sys.File{ .fd = fd }).writeAll(line[0..w.end]) catch {
        std.debug.print("routez ctl: {s} closed the connection\n", .{path});
        return 1;
    };
    _ = std.c.shutdown(fd, posix.SHUT.WR);

    // Only the last line says how it went; earlier ones are a listing.
    var buf: [4096]u8 = undefined;
    var tail: [4]u8 = "\n\n\n\n".*;
    while (true) {
        const n = sys.read(fd, &buf) catch 0;
        if (n == 0) break;
        logs.writeAll(1, buf[0..n]);
        const got = buf[0..n];
        if (got.len >= tail.len) {
            tail = got[got.len - tail.len ..][0..tail.len].*;
        } else {
            std.mem.copyForwards(u8, &tail, tail[got.len..]);
            @memcpy(tail[tail.len - got.len ..], got);
        }
    }
    return if (std.mem.eql(u8, &tail, "\nok\n")) 0 else 1;
}

const testing = std.testing;

fn run1(table: *client_limits.Table, line: []const u8, out: *Out) []const u8 {
    out.len = 0;
    execute(testing.io, table, line, out) catch unreachable;
    return out.buf[0..out.len];
}

test "commands" {
    const t = try client_limits.Table.createSharded(testing.allocator, 64, 4);
    defer t.destroy(testing.allocator);
    var out: Out = .{ .file = .{ .fd = -1 } };
    try testing.expectEqualStrings("ok\n", run1(t, "ban 192.0.2.7 60", &out));
    try testing.expectEqualStrings("ok\n", run1(t, "ban 198.51.100.9/24 3600", &out));
    try testing.expectEqualStrings("ok\n", run1(t, "ban  2001:db8::1/64\t60", &out));
    try testing.expect(t.banned(testing.io, .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }, sys.nanoTimestamp()));

    const list = run1(t, "bans", &out);
    try testing.expect(std.mem.indexOf(u8, list, "192.0.2.7 60\n") != null);
    try testing.expect(std.mem.indexOf(u8, list, "198.51.100.0/24 3600\n") != null);
    try testing.expect(std.mem.indexOf(u8, list, "2001:db8::/64 60\n") != null);
    try testing.expect(std.mem.endsWith(u8, list, "ok\n"));

    try testing.expectEqualStrings("ok\n", run1(t, "unban 198.51.100.0/24", &out));
    try testing.expectEqualStrings("error: not banned\n", run1(t, "unban 198.51.100.0/24", &out));
    // Lifting an address doesn't lift the network it's in, or the reverse.
    try testing.expectEqualStrings("error: not banned\n", run1(t, "unban 2001:db8::1", &out));

    for ([_][]const u8{ "ban all 60", "ban 0.0.0.0/0 60", "ban 192.0.2.1", "ban 192.0.2.1 0", "ban 192.0.2.1 x", "ban 192.0.2.1 60 more", "ban nope 60", "unban", "bans now" }) |bad| {
        try testing.expect(std.mem.startsWith(u8, run1(t, bad, &out), "error: usage"));
    }
    try testing.expectEqualStrings("error: unknown command 'ba?n'\n", run1(t, "ba\x1bn", &out));
    try testing.expectEqualStrings("", run1(t, "   ", &out));
}

//! The control socket behind `routez ctl`. A line protocol: one command a
//! line, each answered by a line `ok` or `error: <reason>`:
//!
//!     ban <target> <seconds>
//!     unban <target>
//!     bans        a "<target> <seconds left>" line per ban, then ok
//!     top         the heaviest senders lately (`senders.zig`), then ok:
//!                 "fingerprint <ja4> <req/s> <share>% usual <share>%[ surging]"
//!                 and "network <network> <req/s> <share>%" lines, heaviest
//!                 first, then "total <req/s>"; plain HTTP's fingerprint is `-`
//!
//! A target is an address, a network (`<address>/<prefix>`), or a JA4
//! fingerprint (`t13d1516h2_8daaf6152771_e5627efa2ab1`).
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
const cluster = @import("cluster.zig");
const fingerprint = @import("fingerprint.zig");
const senders = @import("senders.zig");

const sys = quic.sys;
const posix = std.posix;
const log = std.log.scoped(.control);

/// Where `routez ctl` looks without `-s`.
pub const default_path = "/run/routez.sock";

/// Longest command line; a longer one ends the session.
const max_line = 256;
/// A client silent this long is dropped, so it can't hold the socket.
const idle_timeout_s = 5;
const max_ban_s = @import("config.zig").max_ban_s;

/// The socket `listen` bound, kept for the life of the process.
var bound_buf: [@sizeOf(@FieldType(std.c.sockaddr.un, "path"))]u8 = undefined;
pub var bound: []const u8 = "";
/// Where `keepBans` keeps them, or empty.
pub var bans_path: []const u8 = "";
/// The table `spawn` serves, for the save at exit.
var served: ?*client_limits.Table = null;
/// Ban sync with other instances, when `cluster` is set.
var sync: ?*cluster.Cluster = null;
/// How often the thread wakes for `sync`: bans workers made go out, and
/// the digest when its time comes.
const sync_tick_ms = 1000;
/// How often the thread looks for bans workers made (`limit_req.ban`) to save.
const save_interval_ms = 5000;

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

/// At exit: save the bans, and remove the socket. The removal may fail
/// once `user` took over; the next start replaces it then.
pub fn shutdown(io: std.Io) void {
    if (served) |t| saveBans(io, t);
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

/// Load the bans `path` holds, skipping those that ended, and keep them
/// there from now on (`bans_file`). A missing file is a first start.
pub fn keepBans(io: std.Io, path: []const u8, table: *client_limits.Table) !void {
    const gpa = std.heap.smp_allocator;
    bans_path = try gpa.dupe(u8, path);
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 << 20)) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer gpa.free(text);
    const now_ns = sys.nanoTimestamp();
    const now_s = sys.realtimeSeconds();
    var loaded: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |line| {
        n += 1;
        var words = std.mem.tokenizeAny(u8, line, " \t\r");
        const net = parseTarget(words.next() orelse continue);
        const end_s = std.fmt.parseInt(i64, words.next() orelse "", 10) catch null;
        if (net == null or end_s == null or words.next() != null) {
            // Tests fail on any logged warning.
            if (!@import("builtin").is_test) log.warn("bans_file {s}:{d}: not \"<target> <end, Unix seconds>\"", .{ path, n });
            continue;
        }
        if (end_s.? <= now_s) continue;
        const left = @min(end_s.? - now_s, max_ban_s);
        table.ban(io, net.?.net, net.?.bits, now_ns + left * std.time.ns_per_s, now_ns) catch {
            log.err("bans_file {s}:{d}: the client table is full; raise limits.max_tracked_clients", .{ path, n });
            break;
        };
        loaded += 1;
    }
    log.info("bans_file {s}: {d} ban(s)", .{ path, loaded });
}

/// Rewrite `bans_file` with the live bans, a "<target> <end, Unix seconds>"
/// line each, replacing it whole.
fn saveBans(io: std.Io, table: *client_limits.Table) void {
    if (bans_path.len == 0) return;
    writeBans(io, table) catch |err| log.err("bans_file {s}: {s}", .{ bans_path, @errorName(err) });
}

fn writeBans(io: std.Io, table: *client_limits.Table) !void {
    var af = try std.Io.Dir.cwd().createFileAtomic(io, bans_path, .{ .permissions = .fromMode(0o600), .replace = true });
    defer af.deinit(io);
    const now_ns = sys.nanoTimestamp();
    const now_s = sys.realtimeSeconds();
    var cursor: client_limits.Table.BanCursor = .{};
    var batch: [64]client_limits.Table.Ban = undefined;
    var lines: [batch.len * Out.max_reply]u8 = undefined;
    while (true) {
        const got = table.nextBans(io, &cursor, now_ns, &batch);
        if (got.len == 0) break;
        var w: std.Io.Writer = .fixed(&lines);
        for (got) |b| {
            var buf: [64]u8 = undefined;
            const left = std.math.divCeil(i64, b.until_ns - now_ns, std.time.ns_per_s) catch 0;
            try w.print("{s} {d}\n", .{ formatTarget(b.net, b.bits, &buf), now_s + left });
        }
        try af.file.writeStreamingAll(io, w.buffered());
    }
    try af.file.sync(io);
    try af.replace(io);
}

/// Serve the control socket `fd`, and ban sync `with`, for the life of the
/// process.
pub fn spawn(io: std.Io, fd: ?posix.fd_t, with: ?*cluster.Cluster, table: *client_limits.Table) !void {
    served = table;
    sync = with;
    const t = try std.Thread.spawn(.{}, run, .{ io, fd, table });
    t.detach();
}

fn run(io: std.Io, ctl: ?posix.fd_t, table: *client_limits.Table) void {
    // As `user` by now: a bans_file it can't write shows at start.
    var saved = table.ban_epoch.load(.acquire);
    var saved_at = monoMs();
    saveBans(io, table);
    if (sync) |s| s.start(io, table);
    const timeout: c_int = if (sync != null) sync_tick_ms else if (bans_path.len > 0) save_interval_ms else -1;
    while (true) {
        var pfds: [2]std.c.pollfd = undefined;
        var n: usize = 0;
        if (ctl) |fd| {
            pfds[n] = .{ .fd = fd, .events = std.c.POLL.IN, .revents = 0 };
            n += 1;
        }
        if (sync) |s| {
            pfds[n] = .{ .fd = s.fd, .events = std.c.POLL.IN, .revents = 0 };
            n += 1;
        }
        const ready = std.c.poll(&pfds, @intCast(n), timeout);
        if (sync) |s| {
            if (ready > 0 and pfds[n - 1].revents != 0) s.receive(io, table);
            s.tick(io, table);
        }
        const epoch = table.ban_epoch.load(.acquire);
        if (epoch != saved and monoMs() - saved_at >= save_interval_ms) {
            saved = epoch;
            saved_at = monoMs();
            saveBans(io, table);
        }
        const fd = ctl orelse continue;
        if (ready <= 0 or pfds[0].revents == 0) continue;
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
        // Once per session, however many commands it sent.
        var changed = false;
        serve(io, c, table, &changed) catch {};
        if (changed) {
            saved = table.ban_epoch.load(.acquire);
            saved_at = monoMs();
            saveBans(io, table);
        }
    }
}

fn serve(io: std.Io, c: posix.fd_t, table: *client_limits.Table, changed: *bool) !void {
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
            try execute(io, table, std.mem.trimEnd(u8, in[start..nl], "\r"), &out, changed);
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

fn monoMs() i64 {
    return @divTrunc(sys.nanoTimestamp(), std.time.ns_per_ms);
}

/// A ban's target: a network, or a fingerprint as `fingerprint_bits`.
fn parseTarget(text: ?[]const u8) ?cluster.Key {
    const t = text orelse return null;
    if (fingerprint.parse(t)) |key| return .{ .net = key, .bits = client_limits.fingerprint_bits };
    const r = access.parse(.deny, t) catch return null;
    // `all` or a /0: banning everyone is a firewall's job, not a typo's.
    // An IPv4 /0 is 96 bits of the mapped form.
    if (r.bits == 0 or (r.bits == 96 and access.isV4(r.net))) return null;
    return .{ .net = r.net, .bits = r.bits };
}

fn formatTarget(net: [16]u8, bits: u8, buf: *[64]u8) []const u8 {
    if (bits == client_limits.fingerprint_bits) return fingerprint.format(net, buf[0..fingerprint.Ja4.text_len]);
    return socket.formatNet(net, bits, buf);
}

fn execute(io: std.Io, table: *client_limits.Table, line: []const u8, out: *Out, changed: *bool) !void {
    var words = std.mem.tokenizeAny(u8, line, " \t");
    const cmd = words.next() orelse return;
    var buf: [64]u8 = undefined;
    if (std.mem.eql(u8, cmd, "ban")) {
        const net = parseTarget(words.next());
        const secs = std.fmt.parseInt(u32, words.next() orelse "", 10) catch 0;
        if (net == null or secs == 0 or secs > max_ban_s or words.next() != null)
            return out.print("error: usage: ban <address>[/<prefix>]|<ja4> <seconds>, 1 to {d} seconds\n", .{max_ban_s});
        const now = sys.nanoTimestamp();
        table.ban(io, net.?.net, net.?.bits, now + @as(i64, secs) * std.time.ns_per_s, now) catch
            return out.print("error: the client table is full; raise limits.max_tracked_clients\n", .{});
        log.info("banned {s} for {d} s", .{ formatTarget(net.?.net, net.?.bits, &buf), secs });
        if (sync) |s| s.noteLocal(.{ .net = net.?.net, .bits = net.?.bits }, sys.realtimeSeconds() + secs, false);
        changed.* = true;
        return out.print("ok\n", .{});
    }
    if (std.mem.eql(u8, cmd, "unban")) {
        const net = parseTarget(words.next());
        if (net == null or words.next() != null) return out.print("error: usage: unban <address>[/<prefix>]|<ja4>\n", .{});
        if (!table.unban(io, net.?.net, net.?.bits)) return out.print("error: not banned\n", .{});
        if (sync) |s| {
            const key: cluster.Key = .{ .net = net.?.net, .bits = net.?.bits };
            s.noteLocal(key, s.liftEnd(key), true);
        }
        log.info("unbanned {s}", .{formatTarget(net.?.net, net.?.bits, &buf)});
        changed.* = true;
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
                try out.print("{s} {d}\n", .{ formatTarget(b.net, b.bits, &buf), left });
            }
        }
        return out.print("ok\n", .{});
    }
    if (std.mem.eql(u8, cmd, "top")) {
        if (words.next() != null) return out.print("error: usage: top\n", .{});
        var fps: [10]senders.Entry = undefined;
        var nets: [10]senders.Entry = undefined;
        const got = senders.board.top(io, @divTrunc(sys.nanoTimestamp(), std.time.ns_per_s), &fps, &nets);
        const total = @max(got.rate, std.math.floatMin(f32));
        for (got.fingerprints) |e| {
            const name = if (std.mem.eql(u8, &e.key, &senders.no_fingerprint)) "-" else fingerprint.format(e.key, buf[0..fingerprint.Ja4.text_len]);
            try out.print("fingerprint {s} {d:.1} {d:.1}% usual {d:.1}%{s}\n", .{ name, e.rate, e.rate / total * 100, e.usual * 100, if (e.surging) " surging" else "" });
        }
        for (got.networks) |e| {
            const bits: u8 = if (access.isV4(e.key)) senders.v4_bits else senders.v6_bits;
            try out.print("network {s} {d:.1} {d:.1}%\n", .{ socket.formatNet(e.key, bits, &buf), e.rate, e.rate / total * 100 });
        }
        try out.print("total {d:.1}\n", .{got.rate});
        return out.print("ok\n", .{});
    }
    try out.print("error: unknown command '{s}'\n", .{printable(cmd, buf[0..32])});
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
    var changed = false;
    execute(testing.io, table, line, out, &changed) catch unreachable;
    return out.buf[0..out.len];
}

test "commands" {
    const t = try client_limits.Table.createSharded(testing.allocator, 64, 4);
    defer t.destroy(testing.allocator);
    var out: Out = .{ .file = .{ .fd = -1 } };
    try testing.expectEqualStrings("ok\n", run1(t, "ban 192.0.2.7 60", &out));
    try testing.expectEqualStrings("ok\n", run1(t, "ban 198.51.100.9/24 3600", &out));
    try testing.expectEqualStrings("ok\n", run1(t, "ban  2001:db8::1/64\t60", &out));
    try testing.expectEqualStrings("ok\n", run1(t, "ban t13d1516h2_8daaf6152771_e5627efa2ab1 600", &out));
    try testing.expect(t.fingerprintBanned(testing.io, fingerprint.parse("t13d1516h2_8daaf6152771_e5627efa2ab1").?, sys.nanoTimestamp()));
    try testing.expect(t.banned(testing.io, .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }, sys.nanoTimestamp()));

    const list = run1(t, "bans", &out);
    try testing.expect(std.mem.indexOf(u8, list, "192.0.2.7 60\n") != null);
    try testing.expect(std.mem.indexOf(u8, list, "198.51.100.0/24 3600\n") != null);
    try testing.expect(std.mem.indexOf(u8, list, "2001:db8::/64 60\n") != null);
    try testing.expect(std.mem.indexOf(u8, list, "t13d1516h2_8daaf6152771_e5627efa2ab1 600\n") != null);
    try testing.expect(std.mem.endsWith(u8, list, "ok\n"));

    try testing.expectEqualStrings("ok\n", run1(t, "unban 198.51.100.0/24", &out));
    try testing.expectEqualStrings("error: not banned\n", run1(t, "unban 198.51.100.0/24", &out));
    // Lifting an address doesn't lift the network it's in, or the reverse.
    try testing.expectEqualStrings("error: not banned\n", run1(t, "unban 2001:db8::1", &out));
    try testing.expectEqualStrings("ok\n", run1(t, "unban t13d1516h2_8daaf6152771_e5627efa2ab1", &out));
    try testing.expect(!t.anyFingerprintBans());

    for ([_][]const u8{ "ban all 60", "ban 0.0.0.0/0 60", "ban 192.0.2.1", "ban 192.0.2.1 0", "ban 192.0.2.1 x", "ban 192.0.2.1 60 more", "ban nope 60", "ban t13d1516h2_8daaf6152771 60", "unban", "bans now" }) |bad| {
        try testing.expect(std.mem.startsWith(u8, run1(t, bad, &out), "error: usage"));
    }
    try testing.expectEqualStrings("error: unknown command 'ba?n'\n", run1(t, "ba\x1bn", &out));
    try testing.expect(std.mem.endsWith(u8, run1(t, "top", &out), "ok\n"));
    try testing.expect(std.mem.startsWith(u8, run1(t, "top 5", &out), "error: usage"));
    try testing.expectEqualStrings("", run1(t, "   ", &out));
}

test "bans_file: loaded skipping ended and malformed lines, saved whole" {
    const t = try client_limits.Table.createSharded(testing.allocator, 64, 4);
    defer t.destroy(testing.allocator);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const now = sys.realtimeSeconds();
    var text: [256]u8 = undefined;
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "bans", .data = try std.fmt.bufPrint(&text,
        \\192.0.2.7 {d}
        \\198.51.100.0/24 {d}
        \\not a ban
        \\2001:db8::/48 {d}
        \\q13d0312h3_55b375c5d22e_06cda9e17597 {d}
        \\
    , .{ now + 600, now - 1, now + 60, now + 60 }) });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "bans", testing.allocator);
    defer testing.allocator.free(path);
    try keepBans(testing.io, path, t);
    defer {
        std.heap.smp_allocator.free(bans_path);
        bans_path = "";
    }
    try testing.expectEqual(@as(u32, 2), t.bans.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), t.fingerprint_bans.load(.monotonic));
    try testing.expect(!t.banned(testing.io, client_limits.network(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 1 }, 32, 128), sys.nanoTimestamp()));

    var out: Out = .{ .file = .{ .fd = -1 } };
    try testing.expectEqualStrings("ok\n", run1(t, "unban 192.0.2.7", &out));
    saveBans(testing.io, t);
    const saved = try tmp.dir.readFileAlloc(testing.io, "bans", testing.allocator, .limited(4096));
    defer testing.allocator.free(saved);
    // One line per ban, in table order.
    var found: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, saved, '\n');
    while (lines.next()) |line| {
        var words = std.mem.tokenizeScalar(u8, line, ' ');
        const target = words.next().?;
        try testing.expect(std.mem.eql(u8, target, "2001:db8::/48") or std.mem.eql(u8, target, "q13d0312h3_55b375c5d22e_06cda9e17597"));
        const end = try std.fmt.parseInt(i64, words.next().?, 10);
        try testing.expect(end >= now + 59 and end <= now + 61);
        found += 1;
    }
    try testing.expectEqual(@as(usize, 2), found);
}

//! Where log lines go. std.log writes to stderr, which `error_log`
//! redirects to a file; access log files are shared by the generations
//! naming them. SIGUSR1 reopens every file by path, for log rotation.
//!
//! A file is reopened by dup2(2) onto the descriptor already in use, so a
//! worker writing concurrently lands whole in the old file or the new one:
//! no line is lost and no descriptor is ever closed under a writer.
const std = @import("std");
const access_log = @import("access_log.zig");

/// Least severe level logged; `std.log.Level` as an integer.
pub var level: std.atomic.Value(u8) = .init(@intFromEnum(std.log.Level.info));

pub fn setLevel(l: std.log.Level) void {
    level.store(@intFromEnum(l), .monotonic);
}

/// `std_options.logFn`: `2026/09/18 20:00:32 [info] scope: message`, one
/// write(2) per line so lines from different threads don't interleave.
pub fn logFn(
    comptime l: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(l) > level.load(.monotonic)) return;
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(buf[0 .. buf.len - 1]);
    const t = access_log.civil(@divFloor(realtimeMs(), 1000));
    const prefix = comptime "[" ++ l.asText() ++ "] " ++ (if (scope == .default) "" else @tagName(scope) ++ ": ");
    w.print("{d:0>4}/{d:0>2}/{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} " ++ prefix ++ format, .{ t.year, t.month, t.day, t.hour, t.minute, t.second } ++ args) catch {};
    const n = w.end;
    buf[n] = '\n';
    writeAll(2, buf[0 .. n + 1]);
}

pub fn realtimeMs() i64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts) != 0) return 0;
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
}

/// Write a whole line; lines are small, so a short write means a full disk
/// or a closed pipe, where retrying won't help.
pub fn writeAll(fd: std.posix.fd_t, bytes: []const u8) void {
    var rest = bytes;
    while (rest.len > 0) {
        const n = std.c.write(fd, rest.ptr, rest.len);
        if (n <= 0) {
            if (n < 0 and std.posix.errno(n) == .INTR) continue;
            return;
        }
        rest = rest[@intCast(n)..];
    }
}

/// An open log file, shared by every generation naming its path.
pub const File = struct {
    path: [:0]const u8,
    fd: std.posix.fd_t,
    refs: u32,
};

var mutex: std.Io.Mutex = .init;
var files: std.ArrayListUnmanaged(*File) = .empty;
/// `error_log`'s path while stderr is redirected to it.
var error_path: ?[:0]const u8 = null;

fn open(path: [:0]const u8) !std.posix.fd_t {
    const fd = std.c.open(path, .{ .ACCMODE = .WRONLY, .APPEND = true, .CREAT = true, .CLOEXEC = true }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return switch (std.posix.errno(fd)) {
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .ISDIR => error.IsDir,
        else => error.OpenFailed,
    };
    return fd;
}

/// The open file for `path`, opened now if no generation has it.
pub fn acquire(io: std.Io, path: []const u8) !*File {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    for (files.items) |f| if (std.mem.eql(u8, f.path, path)) {
        f.refs += 1;
        return f;
    };
    const gpa = std.heap.smp_allocator;
    const path_z = try gpa.dupeZ(u8, path);
    errdefer gpa.free(path_z);
    const f = try gpa.create(File);
    errdefer gpa.destroy(f);
    f.* = .{ .path = path_z, .fd = try open(path_z), .refs = 1 };
    errdefer _ = std.c.close(f.fd);
    try files.append(gpa, f);
    return f;
}

/// Once no generation holds it, the file is closed. Its writers are gone
/// by then: a generation releases its files after its workers exit.
pub fn release(io: std.Io, f: *File) void {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    f.refs -= 1;
    if (f.refs > 0) return;
    for (files.items, 0..) |x, i| if (x == f) {
        _ = files.swapRemove(i);
        break;
    };
    _ = std.c.close(f.fd);
    std.heap.smp_allocator.free(f.path);
    std.heap.smp_allocator.destroy(f);
}

/// Send stderr to `path`, or leave it where it is when null.
pub fn setErrorLog(io: std.Io, path: ?[]const u8) !void {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    const p = path orelse return;
    if (error_path) |cur| if (std.mem.eql(u8, cur, p)) return;
    const gpa = std.heap.smp_allocator;
    const path_z = try gpa.dupeZ(u8, p);
    errdefer gpa.free(path_z);
    try redirect(path_z, 2);
    if (error_path) |old| gpa.free(old);
    error_path = path_z;
}

fn redirect(path: [:0]const u8, target: std.posix.fd_t) !void {
    const fd = try open(path);
    defer _ = std.c.close(fd);
    if (std.c.dup2(fd, target) < 0) return error.Dup2Failed;
}

/// SIGUSR1: reopen every file by its path, after a rotation renamed it.
/// A file that can't be reopened keeps going to the old one.
pub fn reopenAll(io: std.Io) void {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    if (error_path) |p| redirect(p, 2) catch |err| std.log.err("reopening {s}: {s}", .{ p, @errorName(err) });
    for (files.items) |f| redirect(f.path, f.fd) catch |err| std.log.err("reopening {s}: {s}", .{ f.path, @errorName(err) });
}

/// Give the open files to the user the server is about to become, so a
/// file it later reopens by path (the same inode, if nothing rotated it)
/// stays writable.
pub fn chownAll(io: std.Io, uid: std.posix.uid_t, gid: std.posix.gid_t) void {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    if (error_path != null) _ = std.c.fchown(2, uid, gid);
    for (files.items) |f| _ = std.c.fchown(f.fd, uid, gid);
}

test "access log files are shared by path and reopened in place" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/access.log", .{dir});

    const a = try acquire(io, path);
    const b = try acquire(io, path);
    try std.testing.expectEqual(a, b);
    const fd = a.fd;
    writeAll(fd, "one\n");
    var rot_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rotated = try std.fmt.bufPrint(&rot_buf, "{s}/access.log.1", .{dir});
    try std.Io.Dir.cwd().rename(path, std.Io.Dir.cwd(), rotated, io);
    reopenAll(io);
    try std.testing.expectEqual(fd, a.fd);
    writeAll(fd, "two\n");
    release(io, b);
    release(io, a);

    var read_buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("one\n", try std.Io.Dir.cwd().readFile(io, rotated, &read_buf));
    try std.testing.expectEqualStrings("two\n", try std.Io.Dir.cwd().readFile(io, path, &read_buf));
}

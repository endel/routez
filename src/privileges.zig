//! Dropping root once the listeners are bound (`user` and `group` in the
//! config).
//!
//! The process never regains root, so everything a reload needs from it
//! comes from the running generation: listening sockets are handed over
//! rather than bound again (Linux also refuses a new SO_REUSEPORT socket
//! from another user), and a reload that adds a port below 1024 fails.
const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");

const log = std.log.scoped(.main);

pub const Ids = struct {
    uid: std.posix.uid_t,
    gid: std.posix.gid_t,
    /// For the supplementary groups; null for a numeric `user`.
    name: ?[:0]const u8,
};

/// Set once the process runs as `user`: a reload must then take its
/// sockets over from the previous generation.
pub var dropped: bool = false;

const c = struct {
    extern "c" fn setgroups(n: if (builtin.os.tag == .linux) usize else c_int, list: [*]const std.posix.gid_t) c_int;
    extern "c" fn initgroups(user: [*:0]const u8, gid: if (builtin.os.tag == .linux) std.posix.gid_t else c_int) c_int;
};

/// Look up `user` and `group` (names or numeric ids).
pub fn resolve(arena: std.mem.Allocator, user: []const u8, group: ?[]const u8) !Ids {
    var ids: Ids = undefined;
    var buf: [16 * 1024]u8 = undefined;
    if (std.fmt.parseInt(std.posix.uid_t, user, 10)) |uid| {
        ids = .{ .uid = uid, .gid = undefined, .name = null };
        if (group == null) {
            // A numeric user may have no passwd entry; then it needs a group.
            var pw: std.c.passwd = undefined;
            var res: ?*std.c.passwd = null;
            if (getpwuid_r(uid, &pw, &buf, buf.len, &res) != 0 or res == null) return error.UnknownUser;
            ids.gid = pw.gid;
        }
    } else |_| {
        const name = try arena.dupeZ(u8, user);
        var pw: std.c.passwd = undefined;
        var res: ?*std.c.passwd = null;
        if (std.c.getpwnam_r(name, &pw, &buf, buf.len, &res) != 0 or res == null) return error.UnknownUser;
        ids = .{ .uid = pw.uid, .gid = pw.gid, .name = name };
    }
    if (group) |g| {
        if (std.fmt.parseInt(std.posix.gid_t, g, 10)) |gid| {
            ids.gid = gid;
        } else |_| {
            const name = try arena.dupeZ(u8, g);
            var gr: std.c.group = undefined;
            var res: ?*std.c.group = null;
            if (std.c.getgrnam_r(name, &gr, &buf, buf.len, &res) != 0 or res == null) return error.UnknownGroup;
            ids.gid = gr.gid;
        }
    }
    return ids;
}

extern "c" fn getpwuid_r(uid: std.posix.uid_t, pwd: *std.c.passwd, buf: [*]u8, buflen: usize, result: *?*std.c.passwd) c_int;

/// Switch the whole process (libc applies it to every thread) to `ids`.
/// Not being root is no error: there is nothing to drop.
pub fn drop(ids: Ids) !void {
    if (std.c.geteuid() != 0) {
        if (std.c.geteuid() != ids.uid) log.warn("user: not running as root, staying uid {d}", .{std.c.geteuid()});
        return;
    }
    // macOS takes the gid as a c_int; nobody's is -2 there.
    const gid_arg = if (builtin.os.tag == .linux) ids.gid else @as(c_int, @bitCast(ids.gid));
    const groups_rc = if (ids.name) |n| c.initgroups(n, gid_arg) else c.setgroups(1, &[_]std.posix.gid_t{ids.gid});
    if (groups_rc != 0) return error.SetGroupsFailed;
    if (std.c.setgid(ids.gid) != 0) return error.SetGidFailed;
    if (std.c.setuid(ids.uid) != 0) return error.SetUidFailed;
    // Proof that root is gone for good, not just the effective id.
    if (std.c.getuid() != ids.uid or std.c.geteuid() != ids.uid or std.c.getegid() != ids.gid) return error.DropIncomplete;
    if (ids.uid != 0 and std.c.setuid(0) == 0) return error.DropIncomplete;
    dropped = true;
}

/// Hand ACME storage to `ids` before dropping: the account key and
/// certificates are written there for the life of the process.
pub fn prepareAcmeStorage(io: std.Io, arena: std.mem.Allocator, cfg: *const config.Config, ids: Ids) !void {
    const storage = @import("acme/storage.zig");
    for (cfg.servers) |srv| {
        const acme = (srv.tls orelse continue).acme orelse continue;
        const ca_dir = try storage.caDir(arena, acme);
        _ = try std.Io.Dir.cwd().createDirPathStatus(io, ca_dir, .fromMode(0o700));
        try chownPath(arena, acme.storage, ids);
        try chownPath(arena, ca_dir, ids);
        var dir = try std.Io.Dir.cwd().openDir(io, ca_dir, .{ .iterate = true });
        defer dir.close(io);
        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            if (entry.kind != .file) continue;
            try chownPath(arena, try std.fs.path.join(arena, &.{ ca_dir, entry.name }), ids);
        }
    }
}

fn chownPath(arena: std.mem.Allocator, path: []const u8, ids: Ids) !void {
    const z = try arena.dupeZ(u8, path);
    const rc = chown(z, ids.uid, ids.gid);
    if (rc != 0) {
        log.err("chown {s}: {s}", .{ path, @tagName(std.posix.errno(rc)) });
        return error.ChownFailed;
    }
}

extern "c" fn chown(path: [*:0]const u8, uid: std.posix.uid_t, gid: std.posix.gid_t) c_int;

test "resolve numeric and named ids" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const root = try resolve(a, "root", null);
    try std.testing.expectEqual(@as(std.posix.uid_t, 0), root.uid);
    try std.testing.expectEqualStrings("root", root.name.?);
    const numeric = try resolve(a, "0", "12345");
    try std.testing.expectEqual(@as(std.posix.uid_t, 0), numeric.uid);
    try std.testing.expectEqual(@as(std.posix.gid_t, 12345), numeric.gid);
    try std.testing.expectEqual(@as(?[:0]const u8, null), numeric.name);
    try std.testing.expectError(error.UnknownUser, resolve(a, "no-such-user-routez", null));
    try std.testing.expectError(error.UnknownGroup, resolve(a, "root", "no-such-group-routez"));
}

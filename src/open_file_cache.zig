//! Open descriptors and metadata of static files, like nginx's
//! `open_file_cache`: a hot file costs no open or stat per request, and on
//! macOS no round trip to an I/O thread.
//!
//! One cache per worker, touched only on its loop thread: no locks, and
//! plain reference counts. Workers belong to a generation, so a reload
//! (which may change roots) starts with empty caches.
//!
//! Keyed by the full filesystem path (a precompressed variant is its own
//! path). Entries record a regular file (descriptor, size, mtime, inode), a
//! path that doesn't exist, or a directory. After `valid_ms` an entry is no
//! longer served: the path is opened and stat-ed again, and the entry kept
//! if it still names the same file, unchanged; replaced otherwise. So a
//! change on disk is seen within `valid_ms`. A file truncated in place
//! within that window is still announced at its old length; its response
//! ends early with an aborted connection, as without the cache.
//!
//! A response (or a socket sending from the file) holds a reference: an
//! entry evicted or replaced meanwhile keeps its descriptor until the last
//! one is gone.
const std = @import("std");
const file_io = @import("file_io.zig");
const log = std.log.scoped(.open_file_cache);

pub const Settings = struct {
    /// Entries per worker; 0 disables the cache.
    max: u32,
    valid_ms: u32,
    inactive_ms: u32,
};

pub const Outcome = enum { file, missing, directory };

pub const Entry = struct {
    gpa: std.mem.Allocator,
    outcome: Outcome,
    /// `.file` only.
    file: std.Io.File = undefined,
    meta: file_io.Meta = undefined,
    /// References besides the table's.
    refs: u32 = 1,
    /// Null until adopted by a cache.
    cache: ?*Cache = null,
    in_table: bool = false,
    key: []const u8 = "",
    validated_ms: i64 = 0,
    used_ms: i64 = 0,
    prev: ?*Entry = null,
    next: ?*Entry = null,
    /// Page-cache residency, mapped on first need.
    residency: ?file_io.Residency = null,
    mapped: bool = false,
    /// The filesystem answers cache-only reads (RWF_NOWAIT).
    nowait: bool = true,

    /// A new entry with one reference; takes `file` for `.file`.
    pub fn create(gpa: std.mem.Allocator, outcome: Outcome, file: std.Io.File, meta: file_io.Meta) !*Entry {
        const e = try gpa.create(Entry);
        e.* = .{ .gpa = gpa, .outcome = outcome, .file = file, .meta = meta };
        return e;
    }

    pub fn retain(e: *Entry) void {
        e.refs += 1;
    }

    pub fn release(e: *Entry) void {
        std.debug.assert(e.refs > 0);
        e.refs -= 1;
        if (e.refs == 0 and !e.in_table) e.destroy();
    }

    fn destroy(e: *Entry) void {
        if (e.residency) |r| r.deinit();
        if (e.outcome == .file) _ = std.c.close(e.file.handle);
        if (e.key.len > 0) e.gpa.free(e.key);
        e.gpa.destroy(e);
    }

    /// Whether `[offset, offset + len)` is in the page cache.
    pub fn resident(e: *Entry, offset: u64, len: usize) bool {
        if (!e.mapped) {
            e.mapped = true;
            e.residency = file_io.Residency.init(e.file, e.meta.size);
        }
        const r = e.residency orelse return false;
        return r.cached(offset, len);
    }

    fn sameAs(e: *const Entry, o: *const Entry) bool {
        if (e.outcome != o.outcome) return false;
        if (e.outcome != .file) return true;
        return e.meta.inode == o.meta.inode and e.meta.size == o.meta.size and e.meta.mtime_s == o.meta.mtime_s;
    }
};

/// What looking at a path found. Only `entry` is cached.
pub const Answer = union(enum) {
    /// One reference, for the caller.
    entry: *Entry,
    /// Permission denied: not cached, the next request asks again.
    denied,
    /// Neither a regular file nor a directory.
    special,
    /// Anything else, answered with 500.
    other,
};

/// Open and stat `path`, blocking. On an I/O thread.
pub fn probe(gpa: std.mem.Allocator, io: std.Io, path: [:0]const u8) Answer {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| return switch (err) {
        error.FileNotFound, error.NotDir, error.NameTooLong, error.BadPathName => negative(gpa, .missing),
        error.IsDir => negative(gpa, .directory),
        error.AccessDenied, error.PermissionDenied => .denied,
        else => .other,
    };
    const st = file.stat(io) catch {
        file.close(io);
        return .other;
    };
    return found(gpa, file, file_io.Meta.of(st));
}

/// `probe` answered from the kernel's caches only (Linux), on the loop.
pub fn probeCached(gpa: std.mem.Allocator, path: [:0]const u8) error{WouldBlock}!Answer {
    const file = file_io.cached.open(path) catch |err| return switch (err) {
        error.WouldBlock => error.WouldBlock,
        error.FileNotFound, error.NotDir, error.NameTooLong => negative(gpa, .missing),
    };
    const meta = file_io.cached.stat(file) catch {
        _ = std.c.close(file.handle);
        return error.WouldBlock;
    };
    return found(gpa, file, meta);
}

fn negative(gpa: std.mem.Allocator, outcome: Outcome) Answer {
    const e = Entry.create(gpa, outcome, undefined, undefined) catch return .other;
    return .{ .entry = e };
}

fn found(gpa: std.mem.Allocator, file: std.Io.File, meta: file_io.Meta) Answer {
    const outcome: Outcome = switch (meta.kind) {
        .file => .file,
        .directory => .directory,
        else => {
            _ = std.c.close(file.handle);
            return .special;
        },
    };
    if (outcome != .file) _ = std.c.close(file.handle);
    const e = Entry.create(gpa, outcome, file, meta) catch {
        if (outcome == .file) _ = std.c.close(file.handle);
        return .other;
    };
    return .{ .entry = e };
}

pub const Cache = struct {
    gpa: std.mem.Allocator,
    settings: Settings,
    map: std.StringHashMapUnmanaged(*Entry) = .empty,
    /// Most recently used first.
    head: ?*Entry = null,
    tail: ?*Entry = null,

    pub fn init(gpa: std.mem.Allocator, settings: Settings) Cache {
        return .{ .gpa = gpa, .settings = settings };
    }

    /// Drop every entry; those still referenced close when released.
    pub fn deinit(self: *Cache) void {
        while (self.tail) |e| self.evict(e);
        self.map.deinit(self.gpa);
    }

    pub fn count(self: *const Cache) usize {
        return self.map.count();
    }

    /// The entry for `path` if still valid, with a reference for the caller.
    pub fn get(self: *Cache, path: []const u8, now_ms: i64) ?*Entry {
        const e = self.map.get(path) orelse return null;
        if (now_ms - e.validated_ms >= self.settings.valid_ms) return null;
        e.used_ms = now_ms;
        self.unlink(e);
        self.pushFront(e);
        e.retain();
        return e;
    }

    /// Take `fresh` (a new entry from `probe`, whose reference the caller
    /// keeps) into the cache under `path`. An entry already there that
    /// names the same unchanged file is revalidated and returned instead,
    /// with `fresh`'s reference moved to it. Already adopted: `fresh`.
    pub fn adopt(self: *Cache, path: []const u8, fresh: *Entry, now_ms: i64) *Entry {
        if (fresh.cache != null) return fresh;
        fresh.cache = self;
        if (self.settings.max == 0) return fresh;
        if (self.map.get(path)) |old| {
            if (old.sameAs(fresh)) {
                old.validated_ms = now_ms;
                old.used_ms = now_ms;
                self.unlink(old);
                self.pushFront(old);
                old.retain();
                fresh.release();
                return old;
            }
            self.evict(old);
        }
        while (self.map.count() >= self.settings.max) self.evict(self.tail.?);
        const key = self.gpa.dupe(u8, path) catch return fresh;
        self.map.put(self.gpa, key, fresh) catch {
            self.gpa.free(key);
            return fresh;
        };
        fresh.key = key;
        fresh.in_table = true;
        fresh.validated_ms = now_ms;
        fresh.used_ms = now_ms;
        self.pushFront(fresh);
        return fresh;
    }

    /// Close entries unused for `inactive_ms`.
    pub fn sweep(self: *Cache, now_ms: i64) void {
        while (self.tail) |e| {
            if (now_ms - e.used_ms < self.settings.inactive_ms) return;
            self.evict(e);
        }
    }

    fn evict(self: *Cache, e: *Entry) void {
        _ = self.map.remove(e.key);
        self.unlink(e);
        e.in_table = false;
        if (e.refs == 0) e.destroy();
    }

    fn unlink(self: *Cache, e: *Entry) void {
        if (e.prev) |p| p.next = e.next else self.head = e.next;
        if (e.next) |n| n.prev = e.prev else self.tail = e.prev;
        e.prev = null;
        e.next = null;
    }

    fn pushFront(self: *Cache, e: *Entry) void {
        e.next = self.head;
        if (self.head) |h| h.prev = e else self.tail = e;
        self.head = e;
    }
};

/// Entries each worker may keep: `max`, lowered so all workers' cached
/// descriptors stay within a quarter of the descriptor limit.
pub fn capMax(max: u32, workers: u16, nofile: u64) u32 {
    const budget = nofile / 4 / @max(workers, 1);
    return @intCast(@min(max, budget));
}

pub fn effectiveMax(max: u32, workers: u16) u32 {
    if (max == 0) return 0;
    const lim = std.posix.getrlimit(.NOFILE) catch return max;
    const capped = capMax(max, workers, lim.cur);
    if (capped < max) log.info("max lowered to {d} entries per worker: RLIMIT_NOFILE is {d} across {d} worker(s)", .{ capped, lim.cur, workers });
    return capped;
}

// ---- tests ----

const testing = std.testing;

fn fdOpen(fd: std.posix.fd_t) bool {
    return std.c.fcntl(fd, std.c.F.GETFD) != -1;
}

const TestDir = struct {
    tmp: testing.TmpDir,
    root: [:0]u8,

    fn init() !TestDir {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
        return .{ .tmp = tmp, .root = root };
    }

    fn deinit(self: *TestDir) void {
        testing.allocator.free(self.root);
        self.tmp.cleanup();
    }

    fn path(self: *const TestDir, buf: []u8, name: []const u8) ![:0]const u8 {
        return std.fmt.bufPrintZ(buf, "{s}/{s}", .{ self.root, name });
    }

    fn write(self: *const TestDir, name: []const u8, data: []const u8) !void {
        try self.tmp.dir.writeFile(testing.io, .{ .sub_path = name, .data = data });
    }
};

fn probeAdopt(c: *Cache, path: [:0]const u8, now: i64) !*Entry {
    return switch (probe(testing.allocator, testing.io, path)) {
        .entry => |e| c.adopt(path, e, now),
        else => error.Unexpected,
    };
}

test "hits, misses and negative entries" {
    var d = try TestDir.init();
    defer d.deinit();
    try d.write("a.txt", "hello");
    var c = Cache.init(testing.allocator, .{ .max = 10, .valid_ms = 1000, .inactive_ms = 60_000 });
    defer c.deinit();
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const a = try d.path(&buf, "a.txt");

    try testing.expect(c.get(a, 0) == null);
    const e = try probeAdopt(&c, a, 0);
    try testing.expectEqual(Outcome.file, e.outcome);
    try testing.expectEqual(5, e.meta.size);
    const hit = c.get(a, 500).?;
    try testing.expectEqual(e, hit);
    hit.release();
    e.release();

    var buf2: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const missing = try d.path(&buf2, "nope");
    const n = try probeAdopt(&c, missing, 0);
    try testing.expectEqual(Outcome.missing, n.outcome);
    n.release();
    // Created meanwhile: still missing until the entry expires.
    try d.write("nope", "x");
    const n2 = c.get(missing, 999).?;
    try testing.expectEqual(Outcome.missing, n2.outcome);
    n2.release();
    try testing.expect(c.get(missing, 1000) == null);
    const n3 = try probeAdopt(&c, missing, 1000);
    try testing.expectEqual(Outcome.file, n3.outcome);
    n3.release();
    try testing.expectEqual(2, c.count());
}

test "a file renamed over is seen once the entry expires; an unchanged one keeps its descriptor" {
    var d = try TestDir.init();
    defer d.deinit();
    try d.write("f", "old");
    var c = Cache.init(testing.allocator, .{ .max = 10, .valid_ms = 1000, .inactive_ms = 60_000 });
    defer c.deinit();
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const f = try d.path(&buf, "f");

    const first = try probeAdopt(&c, f, 0);
    // Revalidated unchanged: the same entry, the new descriptor closed.
    const again = try probeAdopt(&c, f, 1500);
    try testing.expectEqual(first, again);
    again.release();

    try d.write("g", "brand new");
    try d.tmp.dir.rename("g", d.tmp.dir, "f", testing.io);
    const stale = c.get(f, 2000).?;
    try testing.expectEqual(3, stale.meta.size);
    stale.release();
    try testing.expect(c.get(f, 2500) == null);
    const fresh = try probeAdopt(&c, f, 2500);
    try testing.expect(fresh != first);
    try testing.expectEqual(9, fresh.meta.size);
    // The response still reading the old file keeps its descriptor.
    try testing.expect(fdOpen(first.file.handle));
    var rbuf: [3]u8 = undefined;
    try testing.expectEqual(3, try first.file.readPositional(testing.io, &.{&rbuf}, 0));
    try testing.expectEqualStrings("old", &rbuf);
    const fd = first.file.handle;
    first.release();
    try testing.expect(!fdOpen(fd));
    fresh.release();
    try testing.expectEqual(1, c.count());
}

test "eviction never closes a descriptor still in use" {
    var d = try TestDir.init();
    defer d.deinit();
    var c = Cache.init(testing.allocator, .{ .max = 2, .valid_ms = 1000, .inactive_ms = 5000 });
    defer c.deinit();
    var names: [3][std.Io.Dir.max_path_bytes]u8 = undefined;
    var entries: [3]*Entry = undefined;
    for (&entries, 0..) |*e, i| {
        const name = [_]u8{ 'f', '0' + @as(u8, @intCast(i)) };
        try d.write(&name, "data");
        e.* = try probeAdopt(&c, try d.path(&names[i], &name), @intCast(i));
    }
    // f0 was least recently used: out of the table, open while referenced.
    try testing.expectEqual(2, c.count());
    try testing.expect(!entries[0].in_table);
    try testing.expect(fdOpen(entries[0].file.handle));
    const fd0 = entries[0].file.handle;
    entries[0].release();
    try testing.expect(!fdOpen(fd0));

    // Unused past inactive_ms: swept, f2 still referenced.
    entries[1].release();
    const fd1 = entries[1].file.handle;
    c.sweep(10_000);
    try testing.expectEqual(0, c.count());
    try testing.expect(!fdOpen(fd1));
    try testing.expect(fdOpen(entries[2].file.handle));
    entries[2].release();
}

test "disabled cache: entries live as long as their references" {
    var d = try TestDir.init();
    defer d.deinit();
    try d.write("f", "x");
    var c = Cache.init(testing.allocator, .{ .max = 0, .valid_ms = 1000, .inactive_ms = 5000 });
    defer c.deinit();
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const e = try probeAdopt(&c, try d.path(&buf, "f"), 0);
    try testing.expectEqual(0, c.count());
    const fd = e.file.handle;
    e.release();
    try testing.expect(!fdOpen(fd));
}

test "descriptor budget" {
    try testing.expectEqual(1000, capMax(1000, 1, 1_048_576));
    try testing.expectEqual(64, capMax(1000, 1, 256));
    try testing.expectEqual(16, capMax(1000, 4, 256));
    try testing.expectEqual(0, capMax(1000, 4, 8));
    try testing.expectEqual(1000, capMax(1000, 2, std.math.maxInt(u64)));
}

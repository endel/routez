//! Static files under a location's `root` (nginx `root` semantics: the full
//! request path is appended to the root).
//!
//! Opening, stat-ing and reading happen on the file I/O threads
//! (`file_io.zig`), so a slow disk stalls only the requests reading from it.
//! A response takes one round trip there to find its file (try_files
//! entries, precompressed variants) and read the first chunk, then one per
//! further chunk. At most one read is out at a time, and the next is only
//! asked for while the downstream has room.
//!
//! Most requests take none: every path looked at goes into the worker's
//! open-file cache (`open_file_cache.zig`), and where the kernel can tell an
//! answer is cached, the loop takes it itself: the lookup on Linux (openat2
//! with RESOLVE_CACHED), reads everywhere (RWF_NOWAIT, else mincore).
//!
//! Over plain HTTP/1.1, cached ranges of an untransformed body go out with
//! sendfile. Only cached ones: sendfile reads the file on the calling
//! thread, so a cold page would stall the worker.
const std = @import("std");
const build_options = @import("build_options");
const common = @import("../http/common.zig");
const config = @import("../config.zig");
const Exchange = @import("../exchange.zig").Exchange;
const socket = @import("../net/socket.zig");
const Header = common.Header;
const encoding = @import("../encoding.zig");
const gzip = @import("../gzip.zig");
const file_io = @import("../file_io.zig");
const ofc = @import("../open_file_cache.zig");
const timers = @import("../timers.zig");
const Coding = encoding.Coding;

const chunk_size = 32 * 1024;
/// A body this size or smaller is read on the worker's loop rather than handed to
/// the file I/O threads, whether or not the page cache is known to hold it.
///
/// The handoff is two futex round trips and an eventfd wakeup, and under load it
/// queues: a set of 10k small files, most of them missing the open-file cache,
/// spent 2.4 ms per request waiting for four threads while the worker sat at 85%.
/// Being wrong about the page cache costs that one worker a single disk read
/// instead. nginx makes the same trade, and only moves reads off the loop when
/// asked with `aio on`.
///
/// The whole remaining body has to fit, not just the next chunk: a large file
/// read a chunk at a time still belongs on the threads, and taking its first
/// chunk here would find a file truncated under a cached entry before the head
/// was queued, answering with nothing instead of a short body.
const inline_read_max = 64 * 1024;
/// Most handed to one sendfile segment; within what `Residency.cached`
/// checks in one call.
const sendfile_chunk = 256 * 1024;
/// A body this size or smaller is handed to sendfile without first asking
/// whether the page cache holds it.
///
/// The check is a `mincore` per chunk, and on the 100 KB row it was 4.5% of the
/// server's CPU, which nginx does not spend. It is there so a cold range cannot
/// stall the loop inside sendfile, and up to this size that stall is one disk
/// read: the same trade as `inline_read_max`. Above it a body is worth asking
/// about, since a cold 256 KB range would hold the loop for every chunk of it.
const sendfile_trust_max = 1024 * 1024;
const n_codings = std.meta.fields(Coding).len;
const vary: Header = .{ .name = "vary", .value = "Accept-Encoding" };

/// A path looked at for this response, and what was there.
const Probe = struct {
    path: [:0]const u8,
    answer: ofc.Answer,
};

/// One response's file work. Kept on the heap until its last job is back,
/// so a request that goes away mid-read leaves the I/O thread nothing
/// freed to write into.
pub const Transfer = struct {
    job: file_io.Job,
    /// Null once the request went away with a job out; the job's return
    /// then frees the transfer.
    ex: ?*Exchange,
    loc: *const config.Location,
    io: std.Io,
    gpa: std.mem.Allocator,
    cache: *ofc.Cache,
    /// Holds `candidates` and `probes`: the I/O thread reads them, so they
    /// can't live in the exchange's arena.
    arena: std.heap.ArenaAllocator,
    /// A job is out: until it's back, the fields below are the I/O thread's.
    busy: bool = false,

    // What to look for.
    candidates: []const [:0]const u8 = &.{},
    /// try_files: the status once every candidate failed, from its `=code`.
    fallback: ?u16 = null,
    try_files: bool,
    dir_request: bool,
    /// The location's precompressed codings, and those the client takes,
    /// best first.
    offered: [n_codings]Coding = undefined,
    offered_len: u8 = 0,
    accepted: [n_codings]Coding = undefined,
    accepted_len: u8 = 0,
    /// Read the first chunk along with the lookup.
    prefetch: bool = false,

    // What was found.
    /// Paths answered so far, each holding its entry: a lookup that the
    /// loop gave up on continues on an I/O thread from here.
    probes: std.ArrayListUnmanaged(Probe) = .empty,
    result: Result = .{ .status = 500 },
    /// The file served, while looking: an entry of `probes`.
    found: ?*ofc.Entry = null,
    /// The file served, once looked up; holds a reference.
    entry: ?*ofc.Entry = null,
    coding: ?Coding = null,
    /// The candidate served (or whose variant is), which gives the type.
    chosen: usize = 0,
    /// A variant exists for a path looked at, so the answer depended on
    /// Accept-Encoding.
    varied: bool = false,

    // The body.
    offset: u64 = 0,
    end: u64 = 0,
    /// Bytes the last read left in `buf`; 0 when it failed.
    filled: usize = 0,
    /// The downstream may take the body as file ranges.
    sendfile: bool = false,
    /// Hand ranges to sendfile without asking the page cache first; see
    /// `sendfile_trust_max`.
    trust_sendfile: bool = false,
    /// Its own allocation: with it inline the transfer would outgrow the
    /// allocator's slabs and cost an mmap per request.
    buf: ?*[chunk_size]u8 = null,

    const Result = union(enum) { found, status: u16, redirect_dir };

    comptime {
        std.debug.assert(@sizeOf(Transfer) <= 4096);
    }

    fn create(ex: *Exchange, loc: *const config.Location, root: []const u8) !*Transfer {
        const gpa = ex.worker.alloc;
        const t = try gpa.create(Transfer);
        t.* = .{
            .job = .{ .work = lookupWork, .done = lookupDone, .inbox = &ex.worker.file_inbox },
            .ex = ex,
            .loc = loc,
            .io = ex.worker.io,
            .gpa = gpa,
            .cache = &ex.worker.files,
            .arena = .init(gpa),
            .try_files = loc.try_files.len > 0,
            .dir_request = ex.req.path[ex.req.path.len - 1] == '/',
        };
        errdefer t.destroy();
        const a = t.arena.allocator();
        if (t.try_files) {
            const list = try a.alloc([:0]const u8, loc.try_files.len);
            var n: usize = 0;
            for (loc.try_files) |entry| {
                if (config.tryFilesStatus(entry)) |status| {
                    t.fallback = status;
                    break;
                }
                list[n] = try std.mem.concatWithSentinel(a, u8, &.{ root, try tryPath(a, entry, ex.req.path, loc.index) }, 0);
                n += 1;
            }
            t.candidates = list[0..n];
        } else {
            const full = try std.mem.concatWithSentinel(a, u8, &.{ root, ex.req.path, if (t.dir_request) loc.index else "" }, 0);
            t.candidates = try a.dupe([:0]const u8, &.{full});
        }
        for (loc.precompressed) |c| {
            if (std.mem.indexOfScalar(Coding, t.offered[0..t.offered_len], c) != null) continue;
            t.offered[t.offered_len] = c;
            t.offered_len += 1;
        }
        if (t.offered_len > 0) {
            var buf: [n_codings]Coding = undefined;
            const ranked = encoding.Accept.parse(ex.req.get("accept-encoding")).rank(t.offered[0..t.offered_len], &buf);
            @memcpy(t.accepted[0..ranked.len], ranked);
            t.accepted_len = @intCast(ranked.len);
        }
        // Only when the whole body will go out from byte 0.
        t.prefetch = !ex.req.isHead() and ex.req.get("range") == null and
            ex.req.get("if-none-match") == null and ex.req.get("if-modified-since") == null;
        return t;
    }

    fn destroy(t: *Transfer) void {
        std.debug.assert(!t.busy);
        t.dropProbes();
        if (t.entry) |e| e.release();
        if (t.buf) |b| t.gpa.destroy(b);
        t.arena.deinit();
        t.gpa.destroy(t);
    }

    fn dropProbes(t: *Transfer) void {
        for (t.probes.items) |p| switch (p.answer) {
            .entry => |e| e.release(),
            else => {},
        };
        t.probes.clearRetainingCapacity();
        t.found = null;
    }

    /// Forget a lookup's conclusions, to run it again on an I/O thread;
    /// the paths it answered stay answered.
    fn resetLookup(t: *Transfer) void {
        t.found = null;
        t.coding = null;
        t.chosen = 0;
        t.varied = false;
    }

    /// Hand the paths looked at to the cache and keep the file served.
    fn settle(t: *Transfer) void {
        const now = timers.nowMs();
        for (t.probes.items) |*p| switch (p.answer) {
            .entry => |*e| {
                const kept = t.cache.adopt(p.path, e.*, now);
                if (t.found == e.*) t.found = kept;
                e.* = kept;
            },
            else => {},
        };
        if (t.found) |f| {
            f.retain();
            t.entry = f;
        }
        t.dropProbes();
    }

    // ---- on an I/O thread, or cache-only on the loop ----

    fn lookupWork(job: *file_io.Job) void {
        const t: *Transfer = @alignCast(@fieldParentPtr("job", job));
        t.result = t.lookup(false) catch unreachable;
        if (t.result == .found and t.prefetch) t.read(t.found.?, 0, t.found.?.meta.size);
    }

    fn readWork(job: *file_io.Job) void {
        const t: *Transfer = @alignCast(@fieldParentPtr("job", job));
        t.read(t.entry.?, t.offset, t.end);
    }

    /// What's at `path`: answered before, from the cache, or by the kernel.
    /// `on_loop`: without waiting, else WouldBlock.
    fn probe(t: *Transfer, path: [:0]const u8, comptime on_loop: bool) error{WouldBlock}!ofc.Answer {
        for (t.probes.items) |p| if (std.mem.eql(u8, p.path, path)) return p.answer;
        const answer = if (on_loop) blk: {
            if (t.cache.get(path, timers.nowMs())) |e| break :blk ofc.Answer{ .entry = e };
            if (slowRead(path) or !file_io.cached.enabled()) return error.WouldBlock;
            break :blk try ofc.probeCached(t.gpa, path);
        } else ofc.probe(t.gpa, t.io, path);
        const a = t.arena.allocator();
        const stored = a.dupeZ(u8, path) catch return drop(answer);
        t.probes.append(a, .{ .path = stored, .answer = answer }) catch return drop(answer);
        return answer;
    }

    fn drop(answer: ofc.Answer) ofc.Answer {
        switch (answer) {
            .entry => |e| e.release(),
            else => {},
        }
        return .other;
    }

    /// The first candidate naming a regular file, or with a variant the
    /// client takes. `on_loop`: giving up with WouldBlock (leaving
    /// `resetLookup` to the caller) where the answer isn't cached.
    fn lookup(t: *Transfer, comptime on_loop: bool) error{WouldBlock}!Result {
        for (t.candidates, 0..) |path, i| {
            const last = i + 1 == t.candidates.len and t.fallback == null;
            const e = switch (try t.probe(path, on_loop)) {
                .entry => |e| e,
                .denied => {
                    if (last) return .{ .status = 403 };
                    continue;
                },
                .special => {
                    if (last) return .{ .status = 404 };
                    continue;
                },
                .other => return .{ .status = 500 },
            };
            switch (e.outcome) {
                .missing => {
                    if (try t.variant(path, i, on_loop)) return .found;
                    if (last) return .{ .status = 404 };
                },
                .directory => {
                    if (!t.try_files) return if (t.dir_request) .{ .status = 403 } else .redirect_dir;
                    if (last) return .{ .status = 404 };
                },
                .file => {
                    if (try t.variant(path, i, on_loop)) return .found;
                    t.found = e;
                    t.chosen = i;
                    return .found;
                },
            }
        }
        return .{ .status = t.fallback orelse 404 };
    }

    /// Find the best variant of `path` the client takes, if one exists as
    /// a regular file. It sits beside `path`, so it's no further from root.
    /// Also notes whether any variant exists, taken or not.
    fn variant(t: *Transfer, path: []const u8, i: usize, comptime on_loop: bool) error{WouldBlock}!bool {
        if (t.offered_len == 0) return false;
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        for (t.accepted[0..t.accepted_len]) |c| {
            const vpath = std.fmt.bufPrintZ(&buf, "{s}{s}", .{ path, c.suffix() }) catch continue;
            const e = switch (try t.probe(vpath, on_loop)) {
                .entry => |e| e,
                else => continue,
            };
            if (e.outcome != .file) continue;
            t.varied = true;
            t.found = e;
            t.coding = c;
            t.chosen = i;
            return true;
        }
        if (!t.varied) for (t.offered[0..t.offered_len]) |c| {
            if (std.mem.indexOfScalar(Coding, t.accepted[0..t.accepted_len], c) != null) continue;
            const vpath = std.fmt.bufPrintZ(&buf, "{s}{s}", .{ path, c.suffix() }) catch continue;
            switch (try t.probe(vpath, on_loop)) {
                .entry => |e| if (e.outcome == .file) {
                    t.varied = true;
                    break;
                },
                else => {},
            }
        };
        return false;
    }

    fn read(t: *Transfer, e: *ofc.Entry, offset: u64, end: u64) void {
        const want: usize = @intCast(@min(end -| offset, chunk_size));
        if (want == 0) {
            t.filled = 0;
            return;
        }
        if (slowRead(t.candidates[t.chosen])) std.Io.sleep(t.io, .fromMilliseconds(1000), .awake) catch {};
        t.filled = e.file.readPositional(t.io, &.{t.buf.?[0..want]}, offset) catch 0;
    }

    /// The next chunk from the page cache, on the loop; false when it isn't
    /// there to take without waiting.
    fn readCached(t: *Transfer) bool {
        if (slowRead(t.candidates[t.chosen])) return false;
        const e = t.entry.?;
        const want: usize = @intCast(@min(t.end - t.offset, chunk_size));
        const buf = t.buf.?[0..want];
        // Small enough that the read costs less than asking whether it would.
        if (t.end - t.offset <= inline_read_max) {
            t.read(e, t.offset, t.end);
            return true;
        }
        if (file_io.cached.readEnabled()) {
            if (file_io.cached.read(e.file, buf, t.offset)) |n| {
                t.filled = n;
                return true;
            } else |err| switch (err) {
                error.WouldBlock => return false,
                // file_io remembers this for the process; fall through to
                // residency for this request.
                error.Unsupported => {},
            }
        }
        if (!e.resident(t.offset, want)) return false;
        t.filled = e.file.readPositional(t.io, &.{buf}, t.offset) catch 0;
        return true;
    }

    // ---- back on the loop ----

    fn lookupDone(job: *file_io.Job) void {
        const t: *Transfer = @alignCast(@fieldParentPtr("job", job));
        t.busy = false;
        const ex = t.ex orelse return t.destroy();
        t.looked(ex);
    }

    fn looked(t: *Transfer, ex: *Exchange) void {
        t.settle();
        switch (t.result) {
            .found => serve(ex, t),
            .status => |status| {
                const varied = t.varied;
                release(ex);
                ex.sendErrorWith(status, if (varied) &.{vary} else &.{});
            },
            .redirect_dir => {
                release(ex);
                redirectToDir(ex);
            },
        }
    }

    fn readDone(job: *file_io.Job) void {
        const t: *Transfer = @alignCast(@fieldParentPtr("job", job));
        t.busy = false;
        const ex = t.ex orelse return t.destroy();
        if (send(ex, t)) pump(ex);
    }
};

/// Test builds (`-Dfault-injection`): files named *slow-read* read as if
/// from a stalled disk: never from cache, and 1 s per read.
fn slowRead(path: []const u8) bool {
    return build_options.fault_injection and std.mem.indexOf(u8, path, "slow-read") != null;
}

pub fn start(ex: *Exchange, loc: *const config.Location, root: []const u8) void {
    const is_head = ex.req.isHead();
    if (!is_head and !std.mem.eql(u8, ex.req.method, "GET")) {
        const headers = [_]Header{ .{ .name = "allow", .value = "GET, HEAD" }, .{ .name = "content-type", .value = "text/plain" } };
        ex.respondHead(&.{ .status = 405, .headers = &headers, .content_length = 0 });
        return ex.respondEnd();
    }
    const pool = ex.worker.shared.file_pool orelse return ex.sendError(500);
    const t = Transfer.create(ex, loc, root) catch return ex.sendError(500);
    ex.handler = .{ .static = t };
    if (t.lookup(true)) |result| {
        t.result = result;
        return t.looked(ex);
    } else |_| t.resetLookup();
    if (t.prefetch) t.buf = t.gpa.create([chunk_size]u8) catch {
        release(ex);
        return ex.sendError(500);
    };
    t.busy = true;
    if (!pool.submit(&t.job, true)) {
        t.busy = false;
        release(ex);
        return ex.sendRetryLater(503);
    }
}

/// A `try_files` entry as a path under root. Config validation keeps `..`
/// out of the entries and the request path is normalized, so the result
/// can't climb out of root.
fn tryPath(a: std.mem.Allocator, entry: []const u8, path: []const u8, index: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var rest = entry;
    if (std.mem.startsWith(u8, entry, "$uri")) {
        try out.appendSlice(a, path);
        rest = entry["$uri".len..];
    }
    for (rest) |c| {
        if (c == '/' and out.items.len > 0 and out.items[out.items.len - 1] == '/') continue;
        try out.append(a, c);
    }
    if (out.items.len == 0 or out.items[out.items.len - 1] == '/') try out.appendSlice(a, index);
    return out.items;
}

/// Answer with the file found: conditional requests, ranges, body.
/// A precompressed variant is its own representation: its size, mtime and
/// ETag, and ranges count its bytes. The candidate names the original,
/// which gives the type.
fn serve(ex: *Exchange, t: *Transfer) void {
    const a = ex.arena();
    const loc = t.loc;
    const st = t.entry.?.meta;
    const is_head = ex.req.isHead();
    const content_type = mimeType(t.candidates[t.chosen]);
    const mtime_s = st.mtime_s;
    const etag = (if (t.coding) |c|
        std.fmt.allocPrint(a, "\"{x}-{x}-{s}\"", .{ mtime_s, st.size, c.token() })
    else
        std.fmt.allocPrint(a, "\"{x}-{x}\"", .{ mtime_s, st.size })) catch return fail(ex);
    const lm_buf = a.create([29]u8) catch return fail(ex);
    const last_modified = common.formatHttpDate(mtime_s, lm_buf);
    // Whether another client could get another coding of this path.
    const varies = t.varied or (loc.gzip and gzip.compressible(content_type));

    if (notModified(ex, etag, mtime_s)) {
        release(ex);
        const headers = [_]Header{ .{ .name = "etag", .value = etag }, .{ .name = "last-modified", .value = last_modified }, vary };
        ex.respondHead(&.{ .status = 304, .headers = headers[0..if (varies) 3 else 2] });
        return ex.respondEnd();
    }

    var range_start: u64 = 0;
    var range_end: u64 = st.size;
    var status: u16 = 200;
    var content_range: ?[]const u8 = null;
    if (ex.req.get("range")) |range| {
        const if_range_ok = if (ex.req.get("if-range")) |ir| std.mem.eql(u8, ir, etag) else true;
        if (if_range_ok) switch (parseRange(range, st.size)) {
            .ignore => {},
            .unsatisfiable => {
                release(ex);
                const cr = std.fmt.allocPrint(a, "bytes */{d}", .{st.size}) catch return ex.sendError(500);
                const headers = [_]Header{ .{ .name = "content-range", .value = cr }, vary };
                ex.respondHead(&.{ .status = 416, .headers = headers[0..if (t.varied) 2 else 1], .content_length = 0 });
                return ex.respondEnd();
            },
            .range => |r| {
                range_start = r.start;
                range_end = r.end;
                status = 206;
                content_range = std.fmt.allocPrint(a, "bytes {d}-{d}/{d}", .{ r.start, r.end - 1, st.size }) catch return fail(ex);
            },
        };
    }

    var headers: [7]Header = undefined;
    var n: usize = 0;
    headers[n] = .{ .name = "content-type", .value = content_type };
    n += 1;
    headers[n] = .{ .name = "etag", .value = etag };
    n += 1;
    headers[n] = .{ .name = "last-modified", .value = last_modified };
    n += 1;
    headers[n] = .{ .name = "accept-ranges", .value = "bytes" };
    n += 1;
    if (content_range) |cr| {
        headers[n] = .{ .name = "content-range", .value = cr };
        n += 1;
    }
    if (t.coding) |c| {
        headers[n] = .{ .name = "content-encoding", .value = c.token() };
        n += 1;
    }
    if (varies) {
        headers[n] = vary;
        n += 1;
    }

    t.offset = range_start;
    t.end = range_end;
    ex.respondHead(&.{ .status = status, .headers = headers[0..n], .content_length = range_end - range_start });
    if (is_head) return finish(ex);
    // A body that fits one read costs a read and a write either way.
    t.sendfile = range_end - range_start > chunk_size and ex.canSendFile();
    // Up to a point, risking a blocking page-in inside sendfile beats asking
    // about residency first: that check is a syscall per chunk.
    t.trust_sendfile = range_end - range_start <= sendfile_trust_max;
    // The prefetch read from 0 and there's no range: it's the body's start.
    if (t.prefetch and t.filled > 0) {
        if (!send(ex, t)) return;
    }
    pump(ex);
}

fn fail(ex: *Exchange) void {
    release(ex);
    ex.sendError(500);
}

fn redirectToDir(ex: *Exchange) void {
    const a = ex.arena();
    const location = std.fmt.allocPrint(a, "{s}/{s}{s}", .{
        ex.req.path,
        if (ex.req.query != null) "?" else "",
        ex.req.query orelse "",
    }) catch return ex.sendError(500);
    const headers = [_]Header{ .{ .name = "location", .value = location }, .{ .name = "content-type", .value = "text/plain" } };
    ex.respondHead(&.{ .status = 301, .headers = &headers, .content_length = 0 });
    ex.respondEnd();
}

fn notModified(ex: *Exchange, etag: []const u8, mtime_s: i64) bool {
    if (ex.req.get("if-none-match")) |inm| {
        var it = std.mem.tokenizeAny(u8, inm, ", ");
        while (it.next()) |tag| {
            const t = if (std.mem.startsWith(u8, tag, "W/")) tag[2..] else tag;
            if (std.mem.eql(u8, t, "*") or std.mem.eql(u8, t, etag)) return true;
        }
        return false;
    }
    if (ex.req.get("if-modified-since")) |ims| {
        if (common.parseHttpDate(ims)) |since| return mtime_s <= since;
    }
    return false;
}

/// Send what the last read brought; false when that ended the response.
fn send(ex: *Exchange, t: *Transfer) bool {
    const n: usize = @intCast(@min(t.filled, t.end - t.offset));
    t.filled = 0;
    if (n == 0) {
        // File shrank or failed mid-response: the length is already promised.
        release(ex);
        ex.respondAbort();
        return false;
    }
    t.offset += n;
    ex.respondBody(t.buf.?[0..n]);
    if (ex.down == null) {
        // The encoder failed and aborted the response.
        release(ex);
        ex.handlerReleased();
        return false;
    }
    return true;
}

/// Send the body while the downstream has room: as file ranges where it
/// takes them, else chunks from the page cache, else one read at a time
/// from an I/O thread. Resumed from `onDownstreamWritable`.
pub fn pump(ex: *Exchange) void {
    const t = ex.handler.static;
    while (true) {
        if (t.busy) return;
        if (t.offset >= t.end) return finish(ex);
        if (ex.downstreamBuffered() > socket.high_water) return;
        if (t.sendfile and sendRange(ex, t)) continue;
        if (t.buf == null) t.buf = t.gpa.create([chunk_size]u8) catch {
            release(ex);
            return ex.respondAbort();
        };
        if (!t.readCached()) break;
        if (!send(ex, t)) return;
    }
    t.job.work = Transfer.readWork;
    t.job.done = Transfer.readDone;
    t.busy = true;
    _ = ex.worker.shared.file_pool.?.submit(&t.job, false);
}

/// Hand the next range to the downstream to sendfile, if it's cached;
/// false to send it some other way.
fn sendRange(ex: *Exchange, t: *Transfer) bool {
    const e = t.entry.?;
    const len: usize = @intCast(@min(t.end - t.offset, sendfile_chunk));
    if (slowRead(t.candidates[t.chosen])) return false;
    if (!t.trust_sendfile and !e.resident(t.offset, len)) return false;
    e.retain();
    switch (ex.respondFile(.{ .fd = e.file.handle, .offset = t.offset, .len = len, .hold = e, .release = releaseEntry })) {
        .sent => {
            t.offset += len;
            return true;
        },
        .busy => return false,
        .unsupported => {
            t.sendfile = false;
            return false;
        },
    }
}

fn releaseEntry(hold: *anyopaque) void {
    const e: *ofc.Entry = @ptrCast(@alignCast(hold));
    e.release();
}

fn finish(ex: *Exchange) void {
    release(ex);
    ex.respondEnd();
}

/// Free the transfer (closing its file) and drop the handler state.
pub fn release(ex: *Exchange) void {
    switch (ex.handler) {
        .static => |t| t.destroy(),
        else => return,
    }
    ex.handler = .none;
}

/// The request went away: free the transfer, or leave that to its job's
/// return if one is out.
pub fn detach(ex: *Exchange) void {
    const t = ex.handler.static;
    ex.handler = .none;
    if (t.busy) t.ex = null else t.destroy();
}

pub const RangeResult = union(enum) {
    ignore,
    unsatisfiable,
    range: struct { start: u64, end: u64 },
};

/// A single `bytes=` range. Multiple ranges are served as the full body.
pub fn parseRange(value: []const u8, size: u64) RangeResult {
    const prefix = "bytes=";
    if (!std.mem.startsWith(u8, value, prefix)) return .ignore;
    const spec = std.mem.trim(u8, value[prefix.len..], " ");
    if (std.mem.indexOfScalar(u8, spec, ',') != null) return .ignore;
    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return .ignore;
    const first = spec[0..dash];
    const last = spec[dash + 1 ..];
    if (first.len == 0) {
        // suffix range: last N bytes
        const n = std.fmt.parseInt(u64, last, 10) catch return .ignore;
        if (n == 0 or size == 0) return .unsatisfiable;
        return .{ .range = .{ .start = size - @min(n, size), .end = size } };
    }
    const s = std.fmt.parseInt(u64, first, 10) catch return .ignore;
    if (s >= size) return .unsatisfiable;
    var e: u64 = size;
    if (last.len > 0) {
        const l = std.fmt.parseInt(u64, last, 10) catch return .ignore;
        if (l < s) return .ignore;
        // Clamp before +1: the last byte position can be up to 2^64-1.
        e = @min(l, size - 1) + 1;
    }
    return .{ .range = .{ .start = s, .end = e } };
}

pub fn mimeType(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
    const table = [_]struct { []const u8, []const u8 }{
        .{ ".html", "text/html; charset=utf-8" },
        .{ ".htm", "text/html; charset=utf-8" },
        .{ ".css", "text/css; charset=utf-8" },
        .{ ".js", "text/javascript; charset=utf-8" },
        .{ ".mjs", "text/javascript; charset=utf-8" },
        .{ ".json", "application/json" },
        .{ ".map", "application/json" },
        .{ ".txt", "text/plain; charset=utf-8" },
        .{ ".xml", "application/xml" },
        .{ ".svg", "image/svg+xml" },
        .{ ".png", "image/png" },
        .{ ".jpg", "image/jpeg" },
        .{ ".jpeg", "image/jpeg" },
        .{ ".gif", "image/gif" },
        .{ ".webp", "image/webp" },
        .{ ".avif", "image/avif" },
        .{ ".ico", "image/x-icon" },
        .{ ".woff", "font/woff" },
        .{ ".woff2", "font/woff2" },
        .{ ".wasm", "application/wasm" },
        .{ ".pdf", "application/pdf" },
        .{ ".mp4", "video/mp4" },
        .{ ".webm", "video/webm" },
        .{ ".mp3", "audio/mpeg" },
    };
    for (table) |entry| {
        if (std.ascii.eqlIgnoreCase(ext, entry[0])) return entry[1];
    }
    return "application/octet-stream";
}

test "range parsing" {
    const t = std.testing;
    try t.expectEqual(RangeResult{ .range = .{ .start = 0, .end = 10 } }, parseRange("bytes=0-9", 100));
    try t.expectEqual(RangeResult{ .range = .{ .start = 90, .end = 100 } }, parseRange("bytes=-10", 100));
    try t.expectEqual(RangeResult{ .range = .{ .start = 50, .end = 100 } }, parseRange("bytes=50-", 100));
    try t.expectEqual(RangeResult{ .range = .{ .start = 50, .end = 100 } }, parseRange("bytes=50-500", 100));
    try t.expectEqual(RangeResult.unsatisfiable, parseRange("bytes=100-", 100));
    try t.expectEqual(RangeResult.ignore, parseRange("bytes=0-1,5-6", 100));
    try t.expectEqual(RangeResult.ignore, parseRange("items=0-1", 100));
    try t.expectEqual(RangeResult{ .range = .{ .start = 5, .end = 100 } }, parseRange("bytes=5-18446744073709551615", 100));
    try t.expectEqual(RangeResult{ .range = .{ .start = 0, .end = 100 } }, parseRange("bytes=-18446744073709551615", 100));
}

test "try_files paths" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const t = std.testing;
    try t.expectEqualStrings("/app/x", try tryPath(a, "$uri", "/app/x", "index.html"));
    try t.expectEqualStrings("/app/x/index.html", try tryPath(a, "$uri/", "/app/x", "index.html"));
    try t.expectEqualStrings("/app/x/index.html", try tryPath(a, "$uri/", "/app/x/", "index.html"));
    try t.expectEqualStrings("/index.html", try tryPath(a, "$uri/", "/", "index.html"));
    try t.expectEqualStrings("/app/x.html", try tryPath(a, "$uri.html", "/app/x", "index.html"));
    try t.expectEqualStrings("/index.html", try tryPath(a, "/index.html", "/deep/link", "index.html"));
    try t.expectEqualStrings("/spa/index.html", try tryPath(a, "/spa/", "/deep/link", "index.html"));
}

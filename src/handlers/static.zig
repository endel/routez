//! Static files under a location's `root` (nginx `root` semantics: the full
//! request path is appended to the root).
//!
//! Files are read with positional reads on the loop thread, paced by the
//! downstream's buffered bytes. That is fine for page-cached content; a cold
//! disk stalls the worker for the duration of each read.
const std = @import("std");
const common = @import("../http/common.zig");
const config = @import("../config.zig");
const Exchange = @import("../exchange.zig").Exchange;
const socket = @import("../net/socket.zig");
const Header = common.Header;

pub const State = struct {
    file: std.Io.File,
    offset: u64,
    end: u64,
};

const chunk_size = 32 * 1024;

pub fn start(ex: *Exchange, loc: *const config.Location, root: []const u8) void {
    const is_head = ex.req.isHead();
    if (!is_head and !std.mem.eql(u8, ex.req.method, "GET")) {
        const headers = [_]Header{ .{ .name = "allow", .value = "GET, HEAD" }, .{ .name = "content-type", .value = "text/plain" } };
        ex.respondHead(&.{ .status = 405, .headers = &headers, .content_length = 0 });
        return ex.respondEnd();
    }

    const a = ex.arena();
    const dir_request = ex.req.path[ex.req.path.len - 1] == '/';
    const full = std.mem.concat(a, u8, &.{ root, ex.req.path, if (dir_request) loc.index else "" }) catch return ex.sendError(500);
    const io = ex.worker.io;

    const file = std.Io.Dir.cwd().openFile(io, full, .{}) catch |err| return ex.sendError(switch (err) {
        error.FileNotFound, error.NotDir, error.NameTooLong, error.BadPathName => 404,
        error.AccessDenied, error.PermissionDenied => 403,
        error.IsDir => return redirectToDir(ex),
        else => 500,
    });
    const st = file.stat(io) catch {
        file.close(io);
        return ex.sendError(500);
    };
    switch (st.kind) {
        .file => {},
        .directory => {
            file.close(io);
            if (dir_request) return ex.sendError(403);
            return redirectToDir(ex);
        },
        else => {
            file.close(io);
            return ex.sendError(404);
        },
    }

    const mtime_s: i64 = @intCast(@divTrunc(st.mtime.nanoseconds, std.time.ns_per_s));
    const etag = std.fmt.allocPrint(a, "\"{x}-{x}\"", .{ mtime_s, st.size }) catch return closeAndFail(ex, file);
    const lm_buf = a.create([29]u8) catch return closeAndFail(ex, file);
    const last_modified = common.formatHttpDate(mtime_s, lm_buf);

    if (notModified(ex, etag, mtime_s)) {
        file.close(io);
        const headers = [_]Header{ .{ .name = "etag", .value = etag }, .{ .name = "last-modified", .value = last_modified } };
        ex.respondHead(&.{ .status = 304, .headers = &headers });
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
                file.close(io);
                const cr = std.fmt.allocPrint(a, "bytes */{d}", .{st.size}) catch return ex.sendError(500);
                const headers = [_]Header{.{ .name = "content-range", .value = cr }};
                ex.respondHead(&.{ .status = 416, .headers = &headers, .content_length = 0 });
                return ex.respondEnd();
            },
            .range => |r| {
                range_start = r.start;
                range_end = r.end;
                status = 206;
                content_range = std.fmt.allocPrint(a, "bytes {d}-{d}/{d}", .{ r.start, r.end - 1, st.size }) catch return closeAndFail(ex, file);
            },
        };
    }

    var headers: [6]Header = undefined;
    var n: usize = 0;
    headers[n] = .{ .name = "content-type", .value = mimeType(full) };
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

    ex.handler = .{ .static = .{ .file = file, .offset = range_start, .end = range_end } };
    ex.respondHead(&.{ .status = status, .headers = headers[0..n], .content_length = range_end - range_start });
    if (is_head) return finish(ex);
    pump(ex);
}

fn closeAndFail(ex: *Exchange, file: std.Io.File) void {
    file.close(ex.worker.io);
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

/// Send file data until the downstream buffers enough; resumed from
/// `onDownstreamWritable`.
pub fn pump(ex: *Exchange) void {
    const st = &ex.handler.static;
    var buf: [chunk_size]u8 = undefined;
    while (st.offset < st.end and ex.downstreamBuffered() < socket.high_water) {
        const want: usize = @intCast(@min(st.end - st.offset, buf.len));
        const n = st.file.readPositional(ex.worker.io, &.{buf[0..want]}, st.offset) catch 0;
        if (n == 0) {
            // File shrank or failed mid-response: the length is already promised.
            release(ex);
            return ex.respondAbort();
        }
        st.offset += n;
        ex.respondBody(buf[0..n]);
        if (ex.down == null) return;
    }
    if (st.offset >= st.end) finish(ex);
}

fn finish(ex: *Exchange) void {
    release(ex);
    ex.respondEnd();
}

/// Close the file and drop the handler state.
pub fn release(ex: *Exchange) void {
    switch (ex.handler) {
        .static => |st| st.file.close(ex.worker.io),
        else => return,
    }
    ex.handler = .none;
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

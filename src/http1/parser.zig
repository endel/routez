//! HTTP/1.1 message heads and body framing (RFC 9112).
//!
//! Heads are parsed only once complete (`\r\n\r\n` seen), which keeps the
//! parser a pure function over a buffer; the caller bounds the buffer by
//! `Limits.max_head`. Parsed slices point into that buffer.
//!
//! Framing is strict where ambiguity enables request smuggling: requests with
//! both Content-Length and Transfer-Encoding, conflicting Content-Lengths,
//! transfer codings other than a final `chunked`, obs-fold, and whitespace
//! before the colon are all rejected.
const std = @import("std");
const common = @import("../http/common.zig");
pub const Header = common.Header;

pub const Version = enum {
    http10,
    http11,

    pub fn text(self: Version) []const u8 {
        return switch (self) {
            .http10 => "HTTP/1.0",
            .http11 => "HTTP/1.1",
        };
    }
};

pub const Limits = struct {
    max_head: usize = 16 * 1024,
    max_headers: usize = 100,
};

pub const Error = error{
    BadRequest,
    HeadTooLarge,
    TooManyHeaders,
    VersionNotSupported,
    /// A transfer coding we don't implement.
    NotImplemented,
};

pub const RequestHead = struct {
    method: []const u8,
    target: []const u8,
    version: Version,
    headers: []Header,
    content_length: ?u64 = null,
    chunked: bool = false,
    keep_alive: bool,
    host: ?[]const u8 = null,
    expect_continue: bool = false,
    /// The `Upgrade` value, when `Connection` also lists `upgrade`.
    upgrade: ?[]const u8 = null,

    pub fn hasBody(self: *const RequestHead) bool {
        return self.chunked or (self.content_length orelse 0) > 0;
    }

    pub fn get(self: *const RequestHead, name: []const u8) ?[]const u8 {
        return getHeader(self.headers, name);
    }
};

pub const ResponseHead = struct {
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []Header,
    content_length: ?u64 = null,
    chunked: bool = false,
    /// Transfer-Encoding present but not ending in chunked: body runs to close.
    other_coding: bool = false,
    keep_alive: bool,

    pub fn get(self: *const ResponseHead, name: []const u8) ?[]const u8 {
        return getHeader(self.headers, name);
    }
};

pub fn Parsed(comptime T: type) type {
    return struct { head: T, len: usize };
}

pub fn getHeader(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

/// Index just past the blank line ending the head, or null if not there yet.
/// `from` lets the caller resume scanning after bytes it already searched.
pub fn findHeadEnd(buf: []const u8, from: usize) ?usize {
    const start = if (from >= 3) from - 3 else 0;
    const idx = std.mem.indexOfPos(u8, buf, start, "\r\n\r\n") orelse return null;
    return idx + 4;
}

const Lines = struct {
    buf: []const u8,
    pos: usize = 0,

    fn next(self: *Lines) ?[]const u8 {
        const end = std.mem.indexOfPos(u8, self.buf, self.pos, "\r\n") orelse return null;
        const line = self.buf[self.pos..end];
        self.pos = end + 2;
        return line;
    }
};

fn parseVersion(s: []const u8) Error!Version {
    if (std.mem.eql(u8, s, "HTTP/1.1")) return .http11;
    if (std.mem.eql(u8, s, "HTTP/1.0")) return .http10;
    if (s.len == 8 and std.mem.startsWith(u8, s, "HTTP/") and std.ascii.isDigit(s[5]) and s[6] == '.' and std.ascii.isDigit(s[7])) {
        return error.VersionNotSupported;
    }
    return error.BadRequest;
}

/// Split header lines into `out`. Returns the filled prefix.
fn parseHeaderLines(lines: *Lines, out: []Header) Error![]Header {
    var n: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) return out[0..n];
        // obs-fold
        if (line[0] == ' ' or line[0] == '\t') return error.BadRequest;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadRequest;
        const name = line[0..colon];
        if (!common.isToken(name)) return error.BadRequest;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (!common.isFieldValue(value)) return error.BadRequest;
        if (n == out.len) return error.TooManyHeaders;
        out[n] = .{ .name = name, .value = value };
        n += 1;
    }
    return error.BadRequest;
}

const Framing = struct {
    content_length: ?u64 = null,
    chunked: bool = false,
    has_te: bool = false,
    other_coding: bool = false,
    close: bool = false,
    keep_alive_token: bool = false,
    upgrade_token: bool = false,
};

fn scanFraming(headers: []const Header) Error!Framing {
    var f: Framing = .{};
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "content-length")) {
            // A list of identical values is allowed (RFC 9110 §8.6); anything else is not.
            var it = std.mem.splitScalar(u8, h.value, ',');
            while (it.next()) |raw| {
                const v = std.mem.trim(u8, raw, " \t");
                if (v.len == 0 or v.len > 19) return error.BadRequest;
                for (v) |c| if (!std.ascii.isDigit(c)) return error.BadRequest;
                const n = std.fmt.parseInt(u64, v, 10) catch return error.BadRequest;
                if (f.content_length) |prev| {
                    if (prev != n) return error.BadRequest;
                }
                f.content_length = n;
            }
        } else if (std.ascii.eqlIgnoreCase(h.name, "transfer-encoding")) {
            f.has_te = true;
            var it = std.mem.splitScalar(u8, h.value, ',');
            while (it.next()) |raw| {
                const v = std.mem.trim(u8, raw, " \t");
                if (v.len == 0) continue;
                // chunked must be last and appear once
                if (f.chunked) return error.BadRequest;
                if (std.ascii.eqlIgnoreCase(v, "chunked")) {
                    f.chunked = true;
                } else {
                    f.other_coding = true;
                }
            }
        } else if (std.ascii.eqlIgnoreCase(h.name, "connection")) {
            var it = std.mem.tokenizeAny(u8, h.value, ", \t");
            while (it.next()) |tok| {
                if (std.ascii.eqlIgnoreCase(tok, "close")) f.close = true;
                if (std.ascii.eqlIgnoreCase(tok, "keep-alive")) f.keep_alive_token = true;
                if (std.ascii.eqlIgnoreCase(tok, "upgrade")) f.upgrade_token = true;
            }
        }
    }
    return f;
}

pub fn parseRequest(buf: []const u8, headers_out: []Header, limits: Limits) Error!?Parsed(RequestHead) {
    // RFC 9112 §2.2: ignore empty lines before the request line.
    var skip: usize = 0;
    while (skip + 1 < buf.len and buf[skip] == '\r' and buf[skip + 1] == '\n' and skip < 8) skip += 2;
    const body = buf[skip..];

    const end = findHeadEnd(body, 0) orelse {
        if (buf.len > limits.max_head) return error.HeadTooLarge;
        return null;
    };
    if (end > limits.max_head) return error.HeadTooLarge;

    var lines: Lines = .{ .buf = body[0..end] };
    const request_line = lines.next() orelse return error.BadRequest;
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.BadRequest;
    const target = parts.next() orelse return error.BadRequest;
    const version_text = parts.next() orelse return error.BadRequest;
    if (parts.next() != null) return error.BadRequest;
    if (!common.isToken(method)) return error.BadRequest;
    if (target.len == 0) return error.BadRequest;
    for (target) |c| if (c <= 0x20 or c == 0x7f) return error.BadRequest;
    const version = try parseVersion(version_text);

    const max = @min(headers_out.len, limits.max_headers);
    const headers = try parseHeaderLines(&lines, headers_out[0..max]);
    const f = try scanFraming(headers);

    var head: RequestHead = .{
        .method = method,
        .target = target,
        .version = version,
        .headers = headers,
        .keep_alive = switch (version) {
            .http11 => !f.close,
            .http10 => f.keep_alive_token and !f.close,
        },
    };

    if (f.has_te) {
        if (version == .http10) return error.BadRequest;
        if (f.content_length != null) return error.BadRequest;
        if (f.other_coding or !f.chunked) return error.NotImplemented;
        head.chunked = true;
    } else {
        head.content_length = f.content_length;
    }

    var host_count: usize = 0;
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "host")) {
            host_count += 1;
            head.host = h.value;
        } else if (std.ascii.eqlIgnoreCase(h.name, "expect")) {
            if (std.ascii.eqlIgnoreCase(h.value, "100-continue")) head.expect_continue = true;
        } else if (std.ascii.eqlIgnoreCase(h.name, "upgrade")) {
            if (f.upgrade_token) head.upgrade = h.value;
        }
    }
    if (host_count > 1) return error.BadRequest;
    if (version == .http11 and host_count == 0) return error.BadRequest;

    return .{ .head = head, .len = skip + end };
}

pub fn parseResponse(buf: []const u8, headers_out: []Header, limits: Limits) Error!?Parsed(ResponseHead) {
    const end = findHeadEnd(buf, 0) orelse {
        if (buf.len > limits.max_head) return error.HeadTooLarge;
        return null;
    };
    if (end > limits.max_head) return error.HeadTooLarge;

    var lines: Lines = .{ .buf = buf[0..end] };
    const status_line = lines.next() orelse return error.BadRequest;
    if (status_line.len < 12 or status_line[8] != ' ') return error.BadRequest;
    const version = try parseVersion(status_line[0..8]);
    const code_text = status_line[9..12];
    for (code_text) |c| if (!std.ascii.isDigit(c)) return error.BadRequest;
    const status = std.fmt.parseInt(u16, code_text, 10) catch return error.BadRequest;
    if (status < 100) return error.BadRequest;
    if (status_line.len > 12 and status_line[12] != ' ') return error.BadRequest;
    const reason_text = if (status_line.len > 13) status_line[13..] else "";

    const max = @min(headers_out.len, limits.max_headers);
    const headers = try parseHeaderLines(&lines, headers_out[0..max]);
    const f = try scanFraming(headers);

    var head: ResponseHead = .{
        .version = version,
        .status = status,
        .reason = reason_text,
        .headers = headers,
        .keep_alive = switch (version) {
            .http11 => !f.close,
            .http10 => f.keep_alive_token and !f.close,
        },
    };
    if (f.has_te) {
        // RFC 9112 §6.3: TE overrides Content-Length; a non-chunked final
        // coding means the body runs until close.
        head.chunked = f.chunked;
        head.other_coding = !f.chunked;
        if (!f.chunked) head.keep_alive = false;
    } else {
        head.content_length = f.content_length;
    }
    return .{ .head = head, .len = end };
}

/// How the body following a head is delimited.
pub const BodyKind = union(enum) {
    none,
    length: u64,
    chunked,
    until_close,
};

pub fn requestBodyKind(head: *const RequestHead) BodyKind {
    if (head.chunked) return .chunked;
    if (head.content_length) |n| return if (n == 0) .none else .{ .length = n };
    return .none;
}

pub fn responseBodyKind(head: *const ResponseHead, request_method: []const u8) BodyKind {
    if (std.mem.eql(u8, request_method, "HEAD")) return .none;
    if (common.statusHasNoBody(head.status)) return .none;
    if (std.mem.eql(u8, request_method, "CONNECT") and head.status / 100 == 2) return .none;
    if (head.chunked) return .chunked;
    if (head.other_coding) return .until_close;
    if (head.content_length) |n| return if (n == 0) .none else .{ .length = n };
    return .until_close;
}

/// Incremental body decoder. Feed input; get back how much was consumed and
/// at most one contiguous run of body bytes (a slice of the input).
pub const BodyDecoder = struct {
    kind: Kind,
    remaining: u64 = 0,
    state: ChunkState = .size,
    digits: u8 = 0,
    ext_bytes: u16 = 0,
    trailer_bytes: u16 = 0,
    done: bool = false,

    pub const Kind = enum { none, length, chunked, until_close };

    const ChunkState = enum { size, ext, size_lf, data, data_cr, data_lf, trailer_start, trailer, trailer_lf, final_lf };

    pub const DecodeError = error{BadChunk};

    pub const Step = struct { consumed: usize, data: []const u8 };

    pub fn init(kind: BodyKind) BodyDecoder {
        return switch (kind) {
            .none => .{ .kind = .none, .done = true },
            .length => |n| .{ .kind = .length, .remaining = n },
            .chunked => .{ .kind = .chunked },
            .until_close => .{ .kind = .until_close },
        };
    }

    pub fn decode(self: *BodyDecoder, input: []const u8) DecodeError!Step {
        if (self.done) return .{ .consumed = 0, .data = &.{} };
        switch (self.kind) {
            .none => return .{ .consumed = 0, .data = &.{} },
            .until_close => return .{ .consumed = input.len, .data = input },
            .length => {
                const n: usize = @intCast(@min(self.remaining, input.len));
                self.remaining -= n;
                if (self.remaining == 0) self.done = true;
                return .{ .consumed = n, .data = input[0..n] };
            },
            .chunked => return self.decodeChunked(input),
        }
    }

    /// For `until_close` bodies the connection closing is the end.
    pub fn finishOnEof(self: *BodyDecoder) bool {
        if (self.kind == .until_close) self.done = true;
        return self.done;
    }

    fn decodeChunked(self: *BodyDecoder, input: []const u8) DecodeError!Step {
        var i: usize = 0;
        while (i < input.len) {
            const c = input[i];
            switch (self.state) {
                .size => {
                    if (std.fmt.charToDigit(c, 16)) |d| {
                        if (self.digits == 16) return error.BadChunk;
                        self.remaining = (self.remaining << 4) | d;
                        self.digits += 1;
                    } else |_| {
                        if (self.digits == 0) return error.BadChunk;
                        switch (c) {
                            ';', ' ', '\t' => self.state = .ext,
                            '\r' => self.state = .size_lf,
                            else => return error.BadChunk,
                        }
                    }
                    i += 1;
                },
                .ext => {
                    if (c == '\r') {
                        self.state = .size_lf;
                    } else if (c == '\n') {
                        return error.BadChunk;
                    } else {
                        self.ext_bytes += 1;
                        if (self.ext_bytes > 4096) return error.BadChunk;
                    }
                    i += 1;
                },
                .size_lf => {
                    if (c != '\n') return error.BadChunk;
                    i += 1;
                    self.digits = 0;
                    self.ext_bytes = 0;
                    self.state = if (self.remaining == 0) .trailer_start else .data;
                },
                .data => {
                    const n: usize = @intCast(@min(self.remaining, input.len - i));
                    self.remaining -= n;
                    if (self.remaining == 0) self.state = .data_cr;
                    return .{ .consumed = i + n, .data = input[i .. i + n] };
                },
                .data_cr => {
                    if (c != '\r') return error.BadChunk;
                    self.state = .data_lf;
                    i += 1;
                },
                .data_lf => {
                    if (c != '\n') return error.BadChunk;
                    self.state = .size;
                    i += 1;
                },
                .trailer_start => {
                    self.state = if (c == '\r') .final_lf else .trailer;
                    if (c == '\n') return error.BadChunk;
                    i += 1;
                },
                .trailer => {
                    if (c == '\r') {
                        self.state = .trailer_lf;
                    } else if (c == '\n') {
                        return error.BadChunk;
                    }
                    self.trailer_bytes += 1;
                    if (self.trailer_bytes > 8192) return error.BadChunk;
                    i += 1;
                },
                .trailer_lf => {
                    if (c != '\n') return error.BadChunk;
                    self.state = .trailer_start;
                    i += 1;
                },
                .final_lf => {
                    if (c != '\n') return error.BadChunk;
                    self.done = true;
                    return .{ .consumed = i + 1, .data = &.{} };
                },
            }
        }
        return .{ .consumed = i, .data = &.{} };
    }
};

const testing = std.testing;

test "parse simple request" {
    var hb: [16]Header = undefined;
    const raw = "GET /index.html?x=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\nextra";
    const p = (try parseRequest(raw, &hb, .{})).?;
    try testing.expectEqualStrings("GET", p.head.method);
    try testing.expectEqualStrings("/index.html?x=1", p.head.target);
    try testing.expectEqualStrings("example.com", p.head.host.?);
    try testing.expect(p.head.keep_alive);
    try testing.expectEqual(raw.len - "extra".len, p.len);
}

test "incomplete head returns null" {
    var hb: [16]Header = undefined;
    try testing.expectEqual(@as(?Parsed(RequestHead), null), try parseRequest("GET / HTTP/1.1\r\nHost: a\r\n", &hb, .{}));
}

test "smuggling defenses" {
    var hb: [16]Header = undefined;
    const cases = [_][]const u8{
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
        "GET / HTTP/1.1\r\nHost : a\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
        "GET / HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        "GET /a b HTTP/1.1\r\nHost: a\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\n2\r\n\r\n",
    };
    for (cases) |c| {
        if (parseRequest(c, &hb, .{})) |_| {
            std.debug.print("accepted: {s}\n", .{c});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    try testing.expectError(error.NotImplemented, parseRequest("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n", &hb, .{}));
    try testing.expectError(error.VersionNotSupported, parseRequest("GET / HTTP/2.0\r\nHost: a\r\n\r\n", &hb, .{}));
}

test "head size limit" {
    var hb: [16]Header = undefined;
    const big = "GET / HTTP/1.1\r\nHost: a\r\nX: " ++ "a" ** 100;
    try testing.expectError(error.HeadTooLarge, parseRequest(big, &hb, .{ .max_head = 64 }));
}

test "http/1.0 keep-alive" {
    var hb: [16]Header = undefined;
    const a = (try parseRequest("GET / HTTP/1.0\r\n\r\n", &hb, .{})).?;
    try testing.expect(!a.head.keep_alive);
    const b = (try parseRequest("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", &hb, .{})).?;
    try testing.expect(b.head.keep_alive);
}

test "upgrade detection" {
    var hb: [16]Header = undefined;
    const p = (try parseRequest("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", &hb, .{})).?;
    try testing.expectEqualStrings("websocket", p.head.upgrade.?);
}

test "parse response" {
    var hb: [16]Header = undefined;
    const p = (try parseResponse("HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabc", &hb, .{})).?;
    try testing.expectEqual(@as(u16, 404), p.head.status);
    try testing.expectEqualStrings("Not Found", p.head.reason);
    try testing.expectEqual(BodyKind{ .length = 3 }, responseBodyKind(&p.head, "GET"));
    try testing.expectEqual(BodyKind.none, responseBodyKind(&p.head, "HEAD"));
    const q = (try parseResponse("HTTP/1.1 200 \r\n\r\n", &hb, .{})).?;
    try testing.expectEqual(BodyKind.until_close, responseBodyKind(&q.head, "GET"));
    const r = (try parseResponse("HTTP/1.1 204\r\n\r\n", &hb, .{})).?;
    try testing.expectEqual(BodyKind.none, responseBodyKind(&r.head, "GET"));
}

fn decodeAll(dec: *BodyDecoder, input: []const u8, step: usize, out: *std.ArrayList(u8)) !void {
    var pos: usize = 0;
    while (pos < input.len and !dec.done) {
        const end = @min(pos + step, input.len);
        var chunk = input[pos..end];
        while (chunk.len > 0 and !dec.done) {
            const s = try dec.decode(chunk);
            try out.appendSlice(testing.allocator, s.data);
            chunk = chunk[s.consumed..];
            pos += s.consumed;
            if (s.consumed == 0) break;
        }
    }
}

test "chunked decoding in every split" {
    const body = "4\r\nWiki\r\n5;ext=1\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\nTrailer: x\r\n\r\n";
    var step: usize = 1;
    while (step <= body.len) : (step += 1) {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(testing.allocator);
        var dec = BodyDecoder.init(.chunked);
        try decodeAll(&dec, body, step, &out);
        try testing.expect(dec.done);
        try testing.expectEqualStrings("Wikipedia in\r\n\r\nchunks.", out.items);
    }
}

test "chunked rejects garbage" {
    var dec = BodyDecoder.init(.chunked);
    try testing.expectError(error.BadChunk, dec.decode("zz\r\n"));
    var dec2 = BodyDecoder.init(.chunked);
    try testing.expectError(error.BadChunk, dec2.decode("11111111111111111\r\n"));
    var dec3 = BodyDecoder.init(.chunked);
    const s = try dec3.decode("1\r\nab");
    try testing.expectEqualStrings("a", s.data);
    try testing.expectError(error.BadChunk, dec3.decode("1\r\nab"[s.consumed..]));
}

test "length decoding" {
    var dec = BodyDecoder.init(.{ .length = 3 });
    const s = try dec.decode("abcdef");
    try testing.expectEqualStrings("abc", s.data);
    try testing.expect(dec.done);
}

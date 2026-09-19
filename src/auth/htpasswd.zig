//! htpasswd files and `Authorization: Basic` credentials.
//!
//! Accepted hashes: bcrypt (`$2y$`, `$2b$`, `$2a$`; `htpasswd -B`), and
//! `{SHA}` (`htpasswd -s`), which is unsalted SHA-1 and logged as weak.
//! Refused at load, with the line named: apr1 (`$apr1$`, iterated MD5),
//! crypt(3) formats (`$1$`, `$5$`, `$6$`, DES) and plain text. They are
//! either weak or need a libc crypt, and failing at `-t` beats a login that
//! can never work.
const std = @import("std");

pub const Hash = union(enum) {
    /// The whole 60-character string: `$2y$10$` + 22 salt + 31 hash chars.
    bcrypt: [60]u8,
    sha1: [20]u8,
};

pub const File = struct {
    users: std.StringHashMapUnmanaged(Hash) = .empty,
    /// Checked instead when the user is unknown, so a missing user costs
    /// what a wrong password does and timing doesn't tell them apart.
    decoy: Hash = .{ .sha1 = @splat(0) },
    /// Some entries are `{SHA}`.
    has_sha1: bool = false,

    pub fn lookup(self: *const File, name: []const u8) ?Hash {
        return self.users.get(name);
    }
};

pub const ParseError = error{ InvalidFile, OutOfMemory };

/// Where a parse failed, for the config error.
pub const Diagnostic = struct {
    line: usize = 0,
    reason: []const u8 = "",
};

/// Lowest and highest bcrypt cost accepted. Above 16 a single check takes
/// seconds and a handful of logins would occupy every verifier thread.
pub const min_cost = 4;
pub const max_cost = 16;

/// Parse htpasswd `text`; names and hashes are copied into `arena`.
/// Blank lines and `#` comments are skipped.
pub fn parse(arena: std.mem.Allocator, text: []const u8, diag: *Diagnostic) ParseError!File {
    var file: File = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    var n: usize = 0;
    while (lines.next()) |raw| {
        n += 1;
        diag.line = n;
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0 or line[0] == '#') continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return fail(diag, "expected user:hash");
        const name = line[0..colon];
        // htpasswd writes user:hash, and some tools a trailing :comment.
        var rest = line[colon + 1 ..];
        if (std.mem.indexOfScalar(u8, rest, ':')) |c| rest = rest[0..c];
        if (name.len == 0) return fail(diag, "empty user name");
        for (name) |c| if (c < 0x20 or c == 0x7f) return fail(diag, "control character in user name");
        const hash = try parseHash(rest, diag);
        const gop = try file.users.getOrPut(arena, try arena.dupe(u8, name));
        if (gop.found_existing) return fail(diag, "duplicate user");
        gop.value_ptr.* = hash;
        switch (hash) {
            .bcrypt => if (file.decoy != .bcrypt) {
                file.decoy = hash;
            },
            .sha1 => file.has_sha1 = true,
        }
    }
    return file;
}

fn fail(diag: *Diagnostic, reason: []const u8) error{InvalidFile} {
    diag.reason = reason;
    return error.InvalidFile;
}

fn parseHash(s: []const u8, diag: *Diagnostic) error{InvalidFile}!Hash {
    if (std.mem.startsWith(u8, s, "$2y$") or std.mem.startsWith(u8, s, "$2b$") or std.mem.startsWith(u8, s, "$2a$")) {
        if (s.len != 60 or s[6] != '$') return fail(diag, "malformed bcrypt hash");
        const cost = std.fmt.parseInt(u8, s[4..6], 10) catch return fail(diag, "malformed bcrypt hash");
        if (cost < min_cost or cost > max_cost) return fail(diag, "bcrypt cost outside 4..16");
        for (s[7..]) |c| if (radix64Value(c) == null) return fail(diag, "malformed bcrypt hash");
        return .{ .bcrypt = s[0..60].* };
    }
    if (std.mem.startsWith(u8, s, "{SHA}")) {
        var out: [20]u8 = undefined;
        const b64 = s[5..];
        const dec = std.base64.standard.Decoder;
        // decode trusts the destination to be sized for the input.
        const n = dec.calcSizeForSlice(b64) catch return fail(diag, "malformed {SHA} hash");
        if (b64.len != 28 or n != out.len) return fail(diag, "malformed {SHA} hash");
        dec.decode(&out, b64) catch return fail(diag, "malformed {SHA} hash");
        return .{ .sha1 = out };
    }
    if (std.mem.startsWith(u8, s, "$apr1$")) return fail(diag, "apr1 (MD5) hashes are not accepted; recreate the entry with htpasswd -B");
    if (std.mem.startsWith(u8, s, "$")) return fail(diag, "crypt(3) hashes are not accepted; use htpasswd -B");
    return fail(diag, "plain-text or DES crypt passwords are not accepted; use htpasswd -B");
}

// bcrypt's own base64: ./A-Za-z0-9, most significant bits first, no padding.
fn radix64Value(c: u8) ?u6 {
    return switch (c) {
        '.' => 0,
        '/' => 1,
        'A'...'Z' => @intCast(c - 'A' + 2),
        'a'...'z' => @intCast(c - 'a' + 28),
        '0'...'9' => @intCast(c - '0' + 54),
        else => null,
    };
}

/// Decode bcrypt base64 into `out`, ignoring bits past its end.
pub fn radix64Decode(out: []u8, in: []const u8) error{Invalid}!void {
    var acc: u32 = 0;
    var nbits: u5 = 0;
    var o: usize = 0;
    for (in) |c| {
        const v = radix64Value(c) orelse return error.Invalid;
        acc = (acc << 6) | v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (o == out.len) return;
            out[o] = @truncate(acc >> nbits);
            o += 1;
        }
    }
    if (o != out.len) return error.Invalid;
}

pub const Credentials = struct { user: []const u8, password: []const u8 };

/// Longest `user:password` accepted, decoded. Real ones are far shorter;
/// the cap bounds the work an attacker's header can cause.
pub const max_credentials = 1024;

/// The user and password of an `Authorization: Basic` value, decoded into
/// `buf`. Null for another scheme or a malformed value.
pub fn parseAuthorization(value: []const u8, buf: *[max_credentials]u8) ?Credentials {
    const v = std.mem.trim(u8, value, " \t");
    if (v.len < 6 or !std.ascii.eqlIgnoreCase(v[0..5], "basic") or (v[5] != ' ' and v[5] != '\t')) return null;
    const b64 = std.mem.trim(u8, v[6..], " \t");
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(b64) catch return null;
    if (n > buf.len) return null;
    dec.decode(buf[0..n], b64) catch return null;
    const text = buf[0..n];
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return null;
    // RFC 7617 §2: no control characters in the user-id.
    for (text[0..colon]) |c| if (c < 0x20 or c == 0x7f) return null;
    return .{ .user = text[0..colon], .password = text[colon + 1 ..] };
}

const testing = std.testing;

test "htpasswd: bcrypt and SHA entries, comments, a decoy" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var d: Diagnostic = .{};
    const f = try parse(arena_state.allocator(),
        \\# users
        \\alice:$2y$10$f/mtfnwsB2gGNc04FBRPnu07AK7xFpWb9z4jwcHSRI4vGLNN2IC82
        \\
        \\bob:{SHA}87u9ZqY9S/F0eUBXjsPQEDUw4h0=
        \\carol:$2b$05$abcdefghijklmnopqrstuuJ4uIHhlqZ3E5T8kcCzOPBxK0d6u6RWu:comment
    ++ "\r\n", &d);
    try testing.expect(f.lookup("alice").? == .bcrypt);
    try testing.expect(f.lookup("bob").? == .sha1);
    try testing.expect(f.lookup("carol").? == .bcrypt);
    try testing.expect(f.lookup("dave") == null);
    try testing.expect(f.decoy == .bcrypt);
    try testing.expect(f.has_sha1);
}

test "htpasswd: weak and malformed entries are refused with the line" {
    const cases = [_]struct { text: []const u8, line: usize }{
        .{ .text = "carol:$apr1$kGdr5LQA$DXpLyEflTeI.UIQIoXQ1E1", .line = 1 },
        .{ .text = "# x\ndave:UZzuLbuXcO8Rk", .line = 2 },
        .{ .text = "eve:pw", .line = 1 },
        .{ .text = "f:$6$salt$hash", .line = 1 },
        .{ .text = "g:$2y$10$short", .line = 1 },
        .{ .text = "h:$2y$03$f/mtfnwsB2gGNc04FBRPnu07AK7xFpWb9z4jwcHSRI4vGLNN2IC82", .line = 1 },
        .{ .text = "i:$2y$17$f/mtfnwsB2gGNc04FBRPnu07AK7xFpWb9z4jwcHSRI4vGLNN2IC82", .line = 1 },
        .{ .text = "j:$2y$10$f/mtfnwsB2gGNc04FBRPnu07AK7xFpWb9z4jwcHSRI4vGLNN2IC8!", .line = 1 },
        .{ .text = "k:{SHA}notbase64", .line = 1 },
        .{ .text = "l:{SHA}AAAAAAAAAAAAAAAAAAAAAAAAAAAA", .line = 1 }, // 21 bytes, unpadded
        .{ .text = "nocolon", .line = 1 },
        .{ .text = ":{SHA}87u9ZqY9S/F0eUBXjsPQEDUw4h0=", .line = 1 },
        .{ .text = "a:{SHA}87u9ZqY9S/F0eUBXjsPQEDUw4h0=\na:{SHA}87u9ZqY9S/F0eUBXjsPQEDUw4h0=", .line = 2 },
    };
    for (cases) |c| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        var d: Diagnostic = .{};
        try testing.expectError(error.InvalidFile, parse(arena_state.allocator(), c.text, &d));
        try testing.expectEqual(c.line, d.line);
    }
}

test "Authorization: Basic" {
    var buf: [max_credentials]u8 = undefined;
    const c = parseAuthorization("Basic YWxpY2U6czNjcjN0OndpdGg6Y29sb25z", &buf).?;
    try testing.expectEqualStrings("alice", c.user);
    try testing.expectEqualStrings("s3cr3t:with:colons", c.password);
    try testing.expectEqualStrings("bob", parseAuthorization("basic  Ym9iOg== ", &buf).?.user);
    try testing.expect(parseAuthorization("Bearer YWxpY2U6eA==", &buf) == null);
    try testing.expect(parseAuthorization("Basic", &buf) == null);
    try testing.expect(parseAuthorization("Basic !!!", &buf) == null);
    try testing.expect(parseAuthorization("Basic YWxpY2U=", &buf) == null); // no colon
    try testing.expect(parseAuthorization("BasicYWxpY2U6eA==", &buf) == null);
    try testing.expect(parseAuthorization("Basic YQFiOmM=", &buf) == null); // control char in user
}

test "radix64 decodes bcrypt's salt and hash" {
    var salt: [16]u8 = undefined;
    try radix64Decode(&salt, "f/mtfnwsB2gGNc04FBRPnu");
    var hash: [23]u8 = undefined;
    try radix64Decode(&hash, "07AK7xFpWb9z4jwcHSRI4vGLNN2IC82");
    try testing.expectError(error.Invalid, radix64Decode(&hash, "07AK7x"));
    try testing.expectError(error.Invalid, radix64Decode(&salt, "f/mtfnwsB2gGNc04FBRP!u"));
}

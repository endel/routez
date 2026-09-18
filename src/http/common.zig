//! Protocol-neutral HTTP pieces shared by HTTP/1.1 and HTTP/3.
const std = @import("std");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Headers that describe one connection hop and must not be forwarded
/// (RFC 9110 §7.6.1), plus framing headers each hop recomputes.
pub fn isHopByHop(name: []const u8) bool {
    const list = [_][]const u8{
        "connection",     "keep-alive",         "proxy-connection",
        "te",             "trailer",            "transfer-encoding",
        "upgrade",        "proxy-authenticate", "proxy-authorization",
        "content-length",
    };
    for (list) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

/// Whether the comma-separated `Connection` values name `name`.
pub fn connectionListHas(connection_values: []const []const u8, name: []const u8) bool {
    for (connection_values) |v| {
        var it = std.mem.tokenizeAny(u8, v, ", \t");
        while (it.next()) |tok| {
            if (std.ascii.eqlIgnoreCase(tok, name)) return true;
        }
    }
    return false;
}

pub fn isTokenChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

pub fn isToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!isTokenChar(c)) return false;
    return true;
}

/// field-value characters: VCHAR, SP, HTAB, obs-text. Rejects CR, LF, NUL.
pub fn isFieldValue(s: []const u8) bool {
    for (s) |c| {
        if (c == '\t' or c == ' ') continue;
        if (c < 0x21 or c == 0x7f) return false;
    }
    return true;
}

pub fn reason(status: u16) []const u8 {
    return switch (status) {
        100 => "Continue",
        101 => "Switching Protocols",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        else => "Unknown",
    };
}

/// A response status that never carries content (RFC 9110 §6.4.1).
pub fn statusHasNoBody(status: u16) bool {
    return (status >= 100 and status < 200) or status == 204 or status == 304;
}

/// IMF-fixdate, e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
pub fn formatHttpDate(epoch_seconds: i64, buf: *[29]u8) []const u8 {
    const secs: u64 = @intCast(@max(epoch_seconds, 0));
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    // 1970-01-01 was a Thursday.
    const wdays = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    return std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        wdays[@intCast(day.day % 7)],
        md.day_index + 1,
        months[@intFromEnum(md.month) - 1],
        yd.year,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

/// Parse IMF-fixdate. Obsolete RFC 850 / asctime forms return null.
pub fn parseHttpDate(s: []const u8) ?i64 {
    // "Sun, 06 Nov 1994 08:49:37 GMT"
    if (s.len != 29 or s[3] != ',' or !std.mem.eql(u8, s[26..], "GMT")) return null;
    const day = std.fmt.parseInt(u8, s[5..7], 10) catch return null;
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    var month: u8 = 0;
    for (months, 1..) |m, i| {
        if (std.mem.eql(u8, s[8..11], m)) month = @intCast(i);
    }
    if (month == 0) return null;
    const year = std.fmt.parseInt(u16, s[12..16], 10) catch return null;
    const hh = std.fmt.parseInt(u8, s[17..19], 10) catch return null;
    const mm = std.fmt.parseInt(u8, s[20..22], 10) catch return null;
    const ss = std.fmt.parseInt(u8, s[23..25], 10) catch return null;
    if (year < 1970 or day == 0 or day > 31 or hh > 23 or mm > 59 or ss > 60) return null;
    var days: i64 = 0;
    var y: u16 = 1970;
    while (y < year) : (y += 1) days += std.time.epoch.getDaysInYear(y);
    var m: u8 = 1;
    while (m < month) : (m += 1) {
        days += std.time.epoch.getDaysInMonth(year, @enumFromInt(m));
    }
    days += day - 1;
    return days * 86400 + @as(i64, hh) * 3600 + @as(i64, mm) * 60 + ss;
}

/// Cached Date header value, refreshed at most once per second.
pub const DateCache = struct {
    second: i64 = -1,
    buf: [29]u8 = undefined,

    pub fn get(self: *DateCache, now_s: i64) []const u8 {
        if (now_s != self.second) {
            _ = formatHttpDate(now_s, &self.buf);
            self.second = now_s;
        }
        return &self.buf;
    }
};

test "http date round trip" {
    var buf: [29]u8 = undefined;
    try std.testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", formatHttpDate(784111777, &buf));
    try std.testing.expectEqual(@as(?i64, 784111777), parseHttpDate("Sun, 06 Nov 1994 08:49:37 GMT"));
    try std.testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", formatHttpDate(0, &buf));
}

test "connection list" {
    try std.testing.expect(connectionListHas(&.{"keep-alive, Upgrade"}, "upgrade"));
    try std.testing.expect(!connectionListHas(&.{"close"}, "upgrade"));
}

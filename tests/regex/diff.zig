//! Driver for differential.py: one case per stdin line,
//! `<pattern hex> <0|1 case-insensitive> <input hex>`, answered with the
//! match's group spans (`start,end`, `-` for unset), `nomatch` or `error`.
const std = @import("std");
const regex = @import("regex");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    var in_buf: [64 * 1024]u8 = undefined;
    var out_buf: [64 * 1024]u8 = undefined;
    var in = std.Io.File.stdin().reader(init.io, &in_buf);
    var out = std.Io.File.stdout().writer(init.io, &out_buf);
    const w = &out.interface;
    while (in.interface.takeDelimiter('\n') catch null) |line| {
        var it = std.mem.splitScalar(u8, line, ' ');
        const pattern = try hex(gpa, it.next() orelse continue);
        defer gpa.free(pattern);
        const ci = std.mem.eql(u8, it.next() orelse "0", "1");
        const input = try hex(gpa, it.next() orelse "");
        defer gpa.free(input);
        const re = regex.Regex.compile(gpa, pattern, .{ .case_insensitive = ci }, null) catch {
            try w.writeAll("error\n");
            continue;
        };
        defer re.deinit(gpa);
        var scratch = try regex.Scratch.init(gpa, re.states());
        defer scratch.deinit(gpa);
        var caps: regex.Captures = .{};
        if (!re.match(input, &scratch, &caps)) {
            try w.writeAll("nomatch\n");
            continue;
        }
        for (0..@min(@as(usize, re.groups), regex.max_groups) + 1) |g| {
            if (g > 0) try w.writeByte(' ');
            if (caps.get(g)) |s| {
                const start = s.ptr - input.ptr;
                try w.print("{d},{d}", .{ start, start + s.len });
            } else try w.writeByte('-');
        }
        try w.writeByte('\n');
    }
    try w.flush();
}

fn hex(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

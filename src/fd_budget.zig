//! How `RLIMIT_NOFILE` is split between the things that hold descriptors.
//!
//! Every worker's clients, the upstream connection each proxied one opens,
//! and the open-file cache all draw on one process-wide limit, so the shares
//! live together and add up to the whole rather than being guessed apart.
const std = @import("std");

const log = std.log.scoped(.fd_budget);

/// Connections hold two descriptors when proxied (client and upstream), so
/// half the limit covers the worst case; the cache takes a quarter, and the
/// rest is listeners, logs, certificates and the file I/O pool.
pub const Share = enum {
    connections,
    open_files,

    fn divisor(self: Share) u64 {
        return switch (self) {
            .connections => 2,
            .open_files => 4,
        };
    }
};

/// `max`, lowered to this share of `nofile` spread over `workers`.
pub fn cap(share: Share, max: u32, workers: u16, nofile: u64) u32 {
    const budget = nofile / share.divisor() / @max(workers, 1);
    return @intCast(@min(max, budget));
}

/// `cap` against the live limit, saying so when it bites.
pub fn effective(share: Share, what: []const u8, max: u32, workers: u16) u32 {
    if (max == 0) return 0;
    const lim = std.posix.getrlimit(.NOFILE) catch return max;
    const capped = cap(share, max, workers, lim.cur);
    if (capped < max) {
        log.warn("{s} lowered to {d} per worker: RLIMIT_NOFILE is {d} across {d} worker(s)", .{ what, capped, lim.cur, workers });
    }
    return capped;
}

// ---- tests ----

test cap {
    const testing = std.testing;
    // Room to spare: the configured value stands.
    try testing.expectEqual(@as(u32, 10_000), cap(.connections, 10_000, 4, 1 << 20));
    try testing.expectEqual(@as(u32, 1_000), cap(.open_files, 1_000, 4, 1 << 20));
    // Tight limit: each share takes its slice, and they leave a quarter over.
    try testing.expectEqual(@as(u32, 8_192), cap(.connections, 10_000, 4, 65_536));
    try testing.expectEqual(@as(u32, 4_096), cap(.open_files, 10_000, 4, 65_536));
    try testing.expectEqual(@as(u32, 512), cap(.connections, 100_000, 1, 1024));
    // Nothing to give: the caller serves nothing rather than overrunning.
    try testing.expectEqual(@as(u32, 0), cap(.open_files, 1_000, 4, 8));
    try testing.expectEqual(@as(u32, 1_000), cap(.open_files, 1_000, 2, std.math.maxInt(u64)));
}

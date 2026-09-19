//! `auth_basic` for one request or CONNECT: the `Authorization` header
//! against the location's user file.
const std = @import("std");
const quic = @import("quic");
const guard = @import("../guard.zig");
const htpasswd = @import("htpasswd.zig");
const verify = @import("verify.zig");
const pool = @import("pool.zig");
const client_limits = @import("../client_limits.zig");
const Worker = @import("../worker.zig").Worker;

/// Uncached password checks a client may start per second, and in a burst,
/// counted across workers. Each costs a verifier thread tens of
/// milliseconds; a correct password is cached and costs nothing after.
pub const checks_per_s = 5;
pub const checks_burst = 10;

pub const Outcome = union(enum) {
    /// The user, a slice of the caller's buffer.
    ok: []const u8,
    denied,
    /// This client started too many uncached checks: 429.
    limited,
    /// The verifier queue is full: 503.
    busy,
    /// Queued. Set the job's `ctx` before returning to the loop: the
    /// verdict comes to `on_done`, on this worker's thread.
    pending: struct { job: *pool.Job, user: []const u8 },
};

/// SHA entries and cached bcrypt ones are settled here; anything else goes
/// to a verifier thread. An unknown user is checked against the file's
/// decoy, so it takes as long as a wrong password.
pub fn check(
    w: *Worker,
    auth: guard.Auth,
    authorization: ?[]const u8,
    client_ip: [16]u8,
    buf: *[htpasswd.max_credentials]u8,
    on_done: *const fn (*pool.Job) void,
) Outcome {
    const cred = htpasswd.parseAuthorization(authorization orelse return .denied, buf) orelse return .denied;
    const known = auth.file.lookup(cred.user);
    const hash = known orelse auth.file.decoy;
    if (hash == .sha1) return if (verify.check(&hash, cred.password) and known != null) .{ .ok = cred.user } else .denied;

    const p = w.shared.auth_pool.?;
    const now = quic.sys.nanoTimestamp();
    const digest = p.cache.digest(&hash, cred.user, cred.password);
    if (known != null and p.cache.contains(w.io, digest, now)) return .{ .ok = cred.user };
    if (w.shared.clients) |t| {
        if (!t.allowRequest(w.io, client_ip, client_limits.auth_zone, checks_per_s, checks_burst, now)) return .limited;
    }
    const job = w.alloc.create(pool.Job) catch return .busy;
    job.* = .{ .hash = hash, .decoy = known == null, .digest = digest, .inbox = &w.auth_inbox, .ctx = null, .on_done = on_done };
    job.setPassword(cred.password);
    if (!p.submit(job)) {
        job.destroy(w.alloc);
        return .busy;
    }
    return .{ .pending = .{ .job = job, .user = cred.user } };
}

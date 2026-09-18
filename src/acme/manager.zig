//! The process's ACME thread: obtains and renews certificates for servers
//! configured with `tls.acme`, and hands HTTP-01 responses to the workers.
//!
//! There is one `Manager` per process, outliving config generations. Each
//! generation that starts replaces its job list. When a certificate lands on
//! disk and the current configuration still wants it, `on_renewed` asks the
//! supervisor for a reload, whose new generation loads the new file while
//! the old one drains.
const std = @import("std");
const quic = @import("quic");
const config = @import("../config.zig");
const x509 = @import("x509.zig");
const storage = @import("storage.zig");
const Client = @import("client.zig").Client;
const ChallengeSink = @import("client.zig").ChallengeSink;

const log = std.log.scoped(.acme);

/// Pending HTTP-01 tokens and their key authorizations, written by the ACME
/// thread and read by every worker.
pub const Challenges = struct {
    mutex: std.Io.Mutex = .init,
    gpa: std.mem.Allocator,
    map: std.StringHashMapUnmanaged([]u8) = .empty,

    pub const path_prefix = "/.well-known/acme-challenge/";

    pub fn put(self: *Challenges, io: std.Io, token: []const u8, key_authorization: []const u8) error{OutOfMemory}!void {
        const k = try self.gpa.dupe(u8, token);
        errdefer self.gpa.free(k);
        const v = try self.gpa.dupe(u8, key_authorization);
        errdefer self.gpa.free(v);
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const gop = try self.map.getOrPut(self.gpa, k);
        if (gop.found_existing) {
            self.gpa.free(k);
            self.gpa.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = v;
    }

    pub fn remove(self: *Challenges, io: std.Io, token: []const u8) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const kv = self.map.fetchRemove(token) orelse return;
        self.gpa.free(kv.key);
        self.gpa.free(kv.value);
    }

    /// The key authorization for a request path, copied into `a`.
    pub fn lookup(self: *Challenges, io: std.Io, a: std.mem.Allocator, path: []const u8) ?[]u8 {
        if (!std.mem.startsWith(u8, path, path_prefix)) return null;
        const token = path[path_prefix.len..];
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const v = self.map.get(token) orelse return null;
        return a.dupe(u8, v) catch null;
    }
};

/// One certificate to keep current: a server's names under its ACME settings.
pub const Job = struct {
    names: []const []const u8,
    acme: config.Acme,

    fn eql(a: Job, b: Job) bool {
        if (!config.sameNames(a.names, b.names)) return false;
        return std.mem.eql(u8, a.acme.directory, b.acme.directory) and std.mem.eql(u8, a.acme.storage, b.acme.storage);
    }

    fn dupe(j: Job, a: std.mem.Allocator) !Job {
        const names = try a.alloc([]const u8, j.names.len);
        for (names, j.names) |*d, s| d.* = try a.dupe(u8, s);
        var acme = j.acme;
        acme.directory = try a.dupe(u8, j.acme.directory);
        acme.storage = try a.dupe(u8, j.acme.storage);
        if (j.acme.email) |e| acme.email = try a.dupe(u8, e);
        if (j.acme.ca_file) |f| acme.ca_file = try a.dupe(u8, f);
        return .{ .names = names, .acme = acme };
    }
};

/// The certificates `cfg` asks ACME for, one per distinct name list.
pub fn jobsFor(a: std.mem.Allocator, cfg: *const config.Config) ![]Job {
    var jobs: std.ArrayListUnmanaged(Job) = .empty;
    for (cfg.servers) |srv| {
        const acme = (srv.tls orelse continue).acme orelse continue;
        const job: Job = .{ .names = srv.server_names, .acme = acme };
        for (jobs.items) |j| {
            if (j.eql(job)) break;
        } else try jobs.append(a, job);
    }
    return jobs.items;
}

/// What the thread remembers about one certificate between rounds.
const State = struct {
    /// Leave the CA alone until then (awake-clock seconds).
    retry_at_s: i64 = 0,
    failures: u6 = 0,
    /// Finalized, not downloaded yet: the order and the key its CSR used.
    order_url: ?[]u8 = null,
    cert_key: ?x509.KeyPair = null,
    /// Issued but not stored yet: chain then key, ready to write.
    bundle: ?[]u8 = null,

    fn clearOrder(st: *State, gpa: std.mem.Allocator) void {
        if (st.order_url) |u| gpa.free(u);
        st.order_url = null;
        st.cert_key = null;
    }
};

/// Seconds before trying a certificate again after `failures` failures in a
/// row: 1 min doubling to 32 min, since CAs rate-limit failed validations,
/// but never sooner than the CA's Retry-After. A certificate the CA got wrong
/// would come back the same, so that waits for the next check.
fn backoffFor(failures: u6, retry_after_s: ?u32, mismatch: bool, check_interval_s: u32) i64 {
    var backoff: i64 = @as(i64, 60) << (@max(failures, 1) - 1);
    if (retry_after_s) |r| backoff = @max(backoff, r);
    if (mismatch) backoff = @max(backoff, check_interval_s);
    return backoff;
}

pub const Manager = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    challenges: Challenges,
    /// Called on the ACME thread once a certificate the current
    /// configuration uses has been written.
    on_renewed: *const fn () void,

    mutex: std.Io.Mutex = .init,
    jobs_arena: std.heap.ArenaAllocator,
    jobs: []const Job = &.{},
    wake: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    /// Only touched by the thread.
    states: std.StringHashMapUnmanaged(State) = .empty,

    pub fn create(gpa: std.mem.Allocator, io: std.Io, on_renewed: *const fn () void) !*Manager {
        const m = try gpa.create(Manager);
        m.* = .{ .gpa = gpa, .io = io, .challenges = .{ .gpa = gpa }, .on_renewed = on_renewed, .jobs_arena = .init(gpa) };
        return m;
    }

    /// Adopt the certificate list of a newly started generation. Starts the
    /// thread the first time there is something to do.
    pub fn setJobs(self: *Manager, cfg: *const config.Config) !void {
        var fresh: std.heap.ArenaAllocator = .init(self.gpa);
        errdefer fresh.deinit();
        const a = fresh.allocator();
        const src = try jobsFor(a, cfg);
        const owned = try a.alloc(Job, src.len);
        for (owned, src) |*d, s| d.* = try s.dupe(a);

        self.mutex.lockUncancelable(self.io);
        var old = self.jobs_arena;
        self.jobs_arena = fresh;
        self.jobs = owned;
        self.mutex.unlock(self.io);
        old.deinit();

        if (owned.len == 0) return;
        if (self.thread == null) {
            self.thread = try std.Thread.spawn(.{}, run, .{self});
            // Blocked in network I/O at shutdown is fine; the process exits.
            self.thread.?.detach();
        }
        self.wake.store(true, .release);
    }

    fn snapshot(self: *Manager, a: std.mem.Allocator) ![]Job {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const out = try a.alloc(Job, self.jobs.len);
        for (out, self.jobs) |*d, s| d.* = try s.dupe(a);
        return out;
    }

    fn stillWanted(self: *Manager, job: Job) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.jobs) |j| if (j.eql(job)) return true;
        return false;
    }

    fn nowSeconds(self: *Manager) i64 {
        return std.Io.Clock.awake.now(self.io).toSeconds();
    }

    fn stateFor(self: *Manager, path: []const u8) !*State {
        const gop = try self.states.getOrPut(self.gpa, path);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.gpa.dupe(u8, path) catch |err| {
                self.states.removeByPtr(gop.key_ptr);
                return err;
            };
            gop.value_ptr.* = .{};
        }
        return gop.value_ptr;
    }

    fn run(self: *Manager) void {
        while (true) {
            self.wake.store(false, .release);
            var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
            defer arena_state.deinit();
            const a = arena_state.allocator();
            const jobs = self.snapshot(a) catch &.{};

            const round_start = self.nowSeconds();
            var next_s: i64 = 3600;
            var renewed = false;
            for (jobs, 0..) |job, i| {
                if (i == 0 or job.acme.check_interval_s < next_s) next_s = job.acme.check_interval_s;
                const path = storage.bundlePath(a, job.acme, job.names) catch continue;
                const st = self.stateFor(path) catch continue;
                const now = self.nowSeconds();
                if (now < st.retry_at_s) {
                    next_s = @min(next_s, st.retry_at_s - now);
                    continue;
                }
                // Work in hand (an order or a certificate) goes on regardless.
                if (st.order_url == null and st.bundle == null and !self.due(job)) continue;
                var retry_after: ?u32 = null;
                self.attemptWithDeadline(job, path, st, &retry_after) catch |err| {
                    st.failures = @min(st.failures + 1, 6);
                    const backoff = backoffFor(st.failures, retry_after, err == error.CertificateMismatch, job.acme.check_interval_s);
                    st.retry_at_s = self.nowSeconds() + backoff;
                    next_s = @min(next_s, backoff);
                    log.err("certificate for {s}: {s}; retrying in {d} s", .{ job.names[0], @errorName(err), backoff });
                    continue;
                };
                st.failures = 0;
                // A job dropped by a reload meanwhile mustn't reload again.
                if (self.stillWanted(job)) renewed = true;
            }
            const took = self.nowSeconds() - round_start;
            if (took > 60) log.warn("certificate round took {d} s", .{took});
            // One reload for the whole round.
            if (renewed) self.on_renewed();

            var waited: i64 = 0;
            while (waited < next_s and !self.wake.load(.acquire)) : (waited += 1) {
                self.io.sleep(.fromSeconds(1), .awake) catch {};
            }
        }
    }

    /// Whether `job` needs a certificate now: none stored for these names, or
    /// one inside the renewal window. A file that can't be read for other
    /// reasons is left alone: ordering wouldn't help and costs CA limits.
    fn due(self: *Manager, job: Job) bool {
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const path = storage.bundlePath(a, job.acme, job.names) catch return false;
        const b = storage.loadBundle(a, path, job.names) catch |err| switch (err) {
            error.FileNotFound, error.NamesNotCovered, error.CorruptBundle => return true,
            else => {
                log.err("{s}: {s}; not renewing until it can be read", .{ path, @errorName(err) });
                return false;
            },
        };
        return storage.renewalDue(b, quic.sys.realtimeSeconds(), job.acme.renew_days);
    }

    fn challengeSink(self: *Manager) ChallengeSink {
        const S = struct {
            fn put(ctx: *anyopaque, token: []const u8, ka: []const u8) error{OutOfMemory}!void {
                const m: *Manager = @ptrCast(@alignCast(ctx));
                return m.challenges.put(m.io, token, ka);
            }
            fn remove(ctx: *anyopaque, token: []const u8) void {
                const m: *Manager = @ptrCast(@alignCast(ctx));
                m.challenges.remove(m.io, token);
            }
        };
        return .{ .ptr = self, .put = S.put, .remove = S.remove };
    }

    /// `attempt` bounded by `order_timeout_s`: a CA that stops answering
    /// would otherwise hold the thread, and every other certificate, forever.
    fn attemptWithDeadline(self: *Manager, job: Job, path: []const u8, st: *State, retry_after: *?u32) anyerror!void {
        var done: std.atomic.Value(bool) = .init(false);
        var future = self.io.concurrent(attemptTask, .{ self, job, path, st, retry_after, &done }) catch {
            return self.attempt(job, path, st, retry_after);
        };
        const deadline = self.nowSeconds() + job.acme.order_timeout_s;
        while (!done.load(.acquire)) {
            if (self.nowSeconds() >= deadline) {
                // Interrupts the blocked socket call; the task unwinds.
                future.cancel(self.io) catch |err| {
                    if (err == error.Canceled) {
                        log.err("{s}: no result from the CA within {d} s; attempt abandoned", .{ job.names[0], job.acme.order_timeout_s });
                        return error.AcmeTimeout;
                    }
                    return err;
                };
                return;
            }
            self.io.sleep(.fromMilliseconds(200), .awake) catch {};
        }
        return future.await(self.io);
    }

    fn attemptTask(self: *Manager, job: Job, path: []const u8, st: *State, retry_after: *?u32, done: *std.atomic.Value(bool)) anyerror!void {
        defer done.store(true, .release);
        return self.attempt(job, path, st, retry_after);
    }

    /// Order (or resume the order for) `job`'s certificate and store it.
    /// Progress is kept in `st`, so a failure after issuance neither loses
    /// the certificate nor orders another.
    fn attempt(self: *Manager, job: Job, path: []const u8, st: *State, retry_after: *?u32) anyerror!void {
        if (st.bundle == null) {
            try storage.probeWritable(self.io, job.acme);
            const account = try storage.loadOrCreateAccountKey(self.gpa, self.io, job.acme);
            var client = try Client.init(self.gpa, self.io, job.acme.directory, job.acme.ca_file, account);
            defer client.deinit();
            errdefer retry_after.* = client.retry_after_s;
            try client.register(job.acme.email);

            const chain_pem = if (st.order_url) |url| blk: {
                log.info("resuming the order for {s}", .{job.names[0]});
                break :blk client.resumeOrder(url) catch |err| {
                    // Gone or failed at the CA: next time, a new order.
                    if (err == error.AcmeOrderFailed or err == error.AcmeRequestFailed) st.clearOrder(self.gpa);
                    return err;
                };
            } else blk: {
                log.info("requesting a certificate for {s} from {s}", .{ job.names[0], job.acme.directory });
                st.cert_key = x509.KeyPair.generate(self.io);
                break :blk client.issue(job.names, st.cert_key.?, self.challengeSink(), &st.order_url) catch |err| {
                    if (st.order_url == null) st.cert_key = null;
                    return err;
                };
            };
            defer self.gpa.free(chain_pem);
            const cert_key = st.cert_key.?;
            st.clearOrder(self.gpa);

            var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
            defer arena_state.deinit();
            const a = arena_state.allocator();
            const chain = quic.tls13.parsePemCertChain(a, chain_pem) catch return error.CertificateMismatch;
            if (x509.coveredUntil(chain[0], job.names) == null) return error.CertificateMismatch;
            const key_pem = try x509.privateKeyPem(a, cert_key);
            defer std.crypto.secureZero(u8, key_pem);
            st.bundle = try std.mem.concat(self.gpa, u8, &.{ chain_pem, if (std.mem.endsWith(u8, chain_pem, "\n")) "" else "\n", key_pem });
        }
        const bundle = st.bundle.?;
        try storage.writeAtomic(self.io, path, bundle);
        std.crypto.secureZero(u8, bundle);
        self.gpa.free(bundle);
        st.bundle = null;
        log.info("certificate for {s} stored in {s}", .{ job.names[0], path });
    }
};

test "challenge lookup by path" {
    const io = std.testing.io;
    var c: Challenges = .{ .gpa = std.testing.allocator };
    defer c.map.deinit(c.gpa);
    try c.put(io, "tok", "tok.thumb");
    try c.put(io, "tok", "tok.thumb2");
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectEqualStrings("tok.thumb2", c.lookup(io, arena_state.allocator(), "/.well-known/acme-challenge/tok").?);
    try std.testing.expect(c.lookup(io, arena_state.allocator(), "/.well-known/acme-challenge/other") == null);
    try std.testing.expect(c.lookup(io, arena_state.allocator(), "/tok") == null);
    c.remove(io, "tok");
    try std.testing.expect(c.lookup(io, arena_state.allocator(), "/.well-known/acme-challenge/tok") == null);
}

test "jobs are deduplicated by names and CA" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try config.parse(a,
        \\.{ .servers = .{
        \\    .{ .listen = .{ .{ .port = 80 }, .{ .port = 443, .tls = true } }, .server_names = .{"a.example"},
        \\       .tls = .{ .acme = .{} }, .locations = .{.{ .prefix = "/", .root = "x" }} },
        \\    .{ .listen = .{.{ .port = 8443, .tls = true }}, .server_names = .{"a.example"},
        \\       .tls = .{ .acme = .{} }, .locations = .{.{ .prefix = "/", .root = "x" }} },
        \\    .{ .listen = .{.{ .port = 8443, .tls = true }}, .server_names = .{"b.example"},
        \\       .tls = .{ .acme = .{} }, .locations = .{.{ .prefix = "/", .root = "x" }} },
        \\} }
    , "test");
    try std.testing.expectEqual(@as(usize, 2), (try jobsFor(a, &cfg)).len);
}

test "backoff honours Retry-After" {
    try std.testing.expectEqual(@as(i64, 60), backoffFor(1, null, false, 43200));
    try std.testing.expectEqual(@as(i64, 1920), backoffFor(6, null, false, 43200));
    // A rate limit's Retry-After outlasts the exponential backoff.
    try std.testing.expectEqual(@as(i64, 7200), backoffFor(1, 7200, false, 43200));
    try std.testing.expectEqual(@as(i64, 120), backoffFor(2, 30, false, 43200));
    try std.testing.expectEqual(@as(i64, 43200), backoffFor(1, null, true, 43200));
}

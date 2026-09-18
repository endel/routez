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
        if (a.names.len != b.names.len) return false;
        for (a.names, b.names) |x, y| if (!std.mem.eql(u8, x, y)) return false;
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

    fn run(self: *Manager) void {
        var failures: u6 = 0;
        while (true) {
            self.wake.store(false, .release);
            var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
            defer arena_state.deinit();
            const jobs = self.snapshot(arena_state.allocator()) catch &.{};

            var next_s: u64 = 3600;
            var failed = false;
            var renewed = false;
            for (jobs, 0..) |job, i| {
                if (i == 0 or job.acme.check_interval_s < next_s) next_s = job.acme.check_interval_s;
                if (!self.due(job)) continue;
                self.obtain(job) catch |err| {
                    log.err("certificate for {s}: {s}", .{ job.names[0], @errorName(err) });
                    failed = true;
                    continue;
                };
                // A job dropped by a reload meanwhile mustn't reload again.
                if (self.stillWanted(job)) renewed = true;
            }
            // One reload for the whole round.
            if (renewed) self.on_renewed();
            if (failed) {
                // 1 min doubling to 32 min: CAs rate-limit failed validations.
                failures = @min(failures + 1, 6);
                next_s = @min(next_s, @as(u64, 60) << (failures - 1));
            } else failures = 0;

            var waited: u64 = 0;
            while (waited < next_s and !self.wake.load(.acquire)) : (waited += 1) {
                self.io.sleep(.fromSeconds(1), .awake) catch {};
            }
        }
    }

    /// Whether `job` needs a certificate now: none stored, or one that is
    /// unusable or inside the renewal window.
    fn due(self: *Manager, job: Job) bool {
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const path = storage.bundlePath(a, job.acme, job.names) catch return true;
        const b = storage.loadBundle(a, path, job.names) catch return true;
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

    fn obtain(self: *Manager, job: Job) !void {
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        log.info("requesting a certificate for {s} from {s}", .{ job.names[0], job.acme.directory });

        const account = try storage.loadOrCreateAccountKey(self.gpa, self.io, job.acme);
        var client = try Client.init(self.gpa, self.io, job.acme.directory, job.acme.ca_file, account);
        defer client.deinit();
        try client.register(job.acme.email);

        const cert_key = x509.KeyPair.generate(self.io);
        const chain_pem = try client.issue(job.names, cert_key, self.challengeSink());
        defer self.gpa.free(chain_pem);

        const chain = try quic.tls13.parsePemCertChain(a, chain_pem);
        const not_after = x509.coveredUntil(chain[0], job.names) orelse return error.CertificateMismatch;
        const key_pem = try x509.privateKeyPem(a, cert_key);
        defer std.crypto.secureZero(u8, key_pem);
        const bundle = try std.mem.concat(a, u8, &.{ chain_pem, if (std.mem.endsWith(u8, chain_pem, "\n")) "" else "\n", key_pem });
        defer std.crypto.secureZero(u8, bundle);
        const path = try storage.bundlePath(a, job.acme, job.names);
        try storage.writeAtomic(self.io, path, bundle);
        log.info("certificate for {s} stored in {s}, valid for {d} days", .{ job.names[0], path, @divTrunc(@as(i64, @intCast(not_after)) - quic.sys.realtimeSeconds(), 86400) });
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

const std = @import("std");
const quic = @import("quic");
const config = @import("config.zig");
const tls = @import("net/tls.zig");
const acme = @import("acme.zig");
const worker_mod = @import("worker.zig");
const Worker = worker_mod.Worker;
const logs = @import("logs.zig");
const stats = @import("stats.zig");
const access_log = @import("access_log.zig");
const privileges = @import("privileges.zig");
const client_limits = @import("client_limits.zig");
const build_options = @import("build_options");

pub const std_options: std.Options = .{
    // Everything is compiled in; `log_level` in the config filters at run time.
    .log_level = .debug,
    .logFn = logs.logFn,
    // quic-zig logs every handshake step and frame on the default scope.
    .log_scope_levels = &.{
        // quic-zig reports a peer's normal CONNECTION_CLOSE as a warning.
        .{ .scope = .default, .level = .err },
        .{ .scope = .event_loop, .level = .warn },
    },
};

const log = std.log.scoped(.main);

const usage =
    \\usage: routez [-t] [config.zon]
    \\  -t   check the configuration and exit
    \\
;

/// Written by the signal handler and the ACME thread, read by `main`: the
/// one thing a handler can safely do.
var signal_pipe: [2]std.posix.fd_t = .{ -1, -1 };

fn onSignal(sig: std.posix.SIG) callconv(.c) void {
    const b: u8 = switch (sig) {
        .HUP => 'r',
        .USR1 => 'l',
        else => 's',
    };
    _ = std.c.write(signal_pipe[1], @ptrCast(&b), 1);
}

/// A certificate changed on disk: reload the running configuration.
fn onCertificateRenewed() void {
    const b: u8 = 'c';
    _ = std.c.write(signal_pipe[1], @ptrCast(&b), 1);
}

/// One loaded config and the workers running it. A reload starts a new
/// generation beside the old one (listeners use SO_REUSEPORT), then drains
/// the old one.
const Generation = struct {
    arena_state: std.heap.ArenaAllocator,
    /// The config text this generation runs, reused when only certificates change.
    source: [:0]const u8,
    cfg: config.Config,
    shared: Worker.Shared,
    workers: []*Worker,
    threads: []std.Thread,
    access_file: ?*logs.File = null,

    /// Start workers on `source` if given, else on the file at `path`.
    /// `prev` is the running generation being replaced, whose listening
    /// sockets are shared. Its workers only read them before `prev.stop()`.
    fn start(io: std.Io, path: []const u8, source: ?[:0]const u8, first_id: usize, manager: *acme.Manager, prev: ?*const Generation) !*Generation {
        const alloc = std.heap.smp_allocator;
        const g = try alloc.create(Generation);
        g.* = .{ .arena_state = .init(alloc), .source = undefined, .cfg = undefined, .shared = undefined, .workers = &.{}, .threads = &.{} };
        errdefer {
            if (g.access_file) |f| logs.release(io, f);
            g.arena_state.deinit();
            alloc.destroy(g);
        }
        const arena = g.arena_state.allocator();
        // Certificates written up to here are the ones this generation loads.
        const certificates_seen = manager.reloadStarting();
        g.source = if (source) |s| try arena.dupeZ(u8, s) else config.readSource(io, arena, path) catch |err| {
            log.err("{s}: {s}", .{ path, @errorName(err) });
            return err;
        };
        g.cfg = config.parse(arena, g.source, path) catch |err| {
            log.err("{s}: {s}", .{ path, @errorName(err) });
            return err;
        };
        // At start, before binding, so all of it lands in the error log; on
        // a reload once nothing else can fail.
        if (prev == null) try applyLogging(io, &g.cfg);
        // Resolved before binding anything, so a typo fails fast.
        const ids = try resolveUser(arena, &g.cfg);
        if (prev != null) if (ids) |u| if (!privileges.dropped or u.uid != std.c.getuid()) {
            log.warn("user {s}: a change of user takes effect at the next restart", .{g.cfg.user.?});
        };
        g.shared = try loadShared(arena, io, &g.cfg);
        g.shared.challenges = &manager.challenges;
        g.shared.clients = try clientTable(&g.cfg);
        g.shared.access_format = try access_log.compile(arena, g.cfg.access_log_format, g.cfg.access_log_escape);
        if (g.cfg.access_log) if (g.cfg.access_log_path) |p| {
            g.access_file = logs.acquire(io, p) catch |err| {
                log.err("access_log_path {s}: {s}", .{ p, @errorName(err) });
                return err;
            };
            g.shared.access_fd = g.access_file.?.fd;
        };

        const workers = try arena.alloc(*Worker, g.cfg.workers);
        var created: usize = 0;
        errdefer for (workers[0..created]) |w| w.destroy();
        for (workers, 0..) |*w, i| {
            const pred: worker_mod.Predecessor = if (prev) |p| .{ .same = if (i < p.workers.len) p.workers[i] else null, .all = p.workers } else .{};
            w.* = Worker.create(alloc, io, &g.cfg, &g.shared, first_id + i, pred) catch |err| {
                log.err("worker {d}: {s}", .{ i, @errorName(err) });
                return err;
            };
            created += 1;
        }
        g.workers = workers;
        if (prev != null) try applyLogging(io, &g.cfg);
        // Listeners are bound and logs open: nothing left that needs root.
        if (prev == null) if (ids) |u| {
            privileges.prepareAcmeStorage(io, arena, &g.cfg, u) catch |err| {
                log.err("acme storage for user {s}: {s}", .{ g.cfg.user.?, @errorName(err) });
                return err;
            };
            logs.chownAll(io, u.uid, u.gid);
            privileges.drop(u) catch |err| {
                log.err("dropping to user {s}: {s}; refusing to serve as root", .{ g.cfg.user.?, @errorName(err) });
                return err;
            };
            if (privileges.dropped) log.info("running as uid {d}, gid {d}", .{ u.uid, u.gid });
        };
        g.threads = try arena.alloc(std.Thread, workers.len);
        for (g.threads, workers) |*t, w| t.* = try std.Thread.spawn(.{}, runWorker, .{w});
        // After the listeners are up, so HTTP-01 challenges can be answered.
        manager.reloadApplied(certificates_seen);
        manager.setJobs(&g.cfg) catch |err| log.err("acme: {s}", .{@errorName(err)});
        return g;
    }

    fn stop(self: *Generation) void {
        for (self.workers) |w| w.requestStop();
    }

    /// Wait for the workers to drain, then free the generation. Workers'
    /// own memory is left alone: a connection that outlived the drain window
    /// may still point into it.
    fn join(self: *Generation, io: std.Io) void {
        for (self.threads) |t| t.join();
        if (self.access_file) |f| logs.release(io, f);
        self.arena_state.deinit();
        std.heap.smp_allocator.destroy(self);
    }
};

/// Created for the first config that limits clients, then kept for the
/// life of the process: every generation counts in it, so connections the
/// old one accepted are released where they were counted and buckets
/// carry over a reload.
var client_table: ?*client_limits.Table = null;
var client_table_size: u32 = 0;

fn clientTable(cfg: *const config.Config) !?*client_limits.Table {
    const wanted = cfg.limits.max_connections_per_ip != 0 or limitsRequests(cfg);
    if (client_table) |t| {
        if (wanted and cfg.limits.max_tracked_clients != client_table_size)
            log.warn("limits.max_tracked_clients: a change takes effect at the next restart", .{});
        return t;
    }
    if (!wanted) return null;
    client_table = try client_limits.Table.create(std.heap.smp_allocator, cfg.limits.max_tracked_clients);
    client_table_size = cfg.limits.max_tracked_clients;
    return client_table;
}

fn limitsRequests(cfg: *const config.Config) bool {
    for (cfg.servers) |srv| for (srv.locations) |loc| if (loc.limit_req != null) return true;
    return false;
}

fn applyLogging(io: std.Io, cfg: *const config.Config) !void {
    logs.setErrorLog(io, cfg.error_log) catch |err| {
        log.err("error_log {s}: {s}", .{ cfg.error_log.?, @errorName(err) });
        return err;
    };
    logs.setLevel(cfg.log_level);
}

fn resolveUser(arena: std.mem.Allocator, cfg: *const config.Config) !?privileges.Ids {
    const user = cfg.user orelse return null;
    return privileges.resolve(arena, user, cfg.group) catch |err| {
        log.err("user {s}{s}{s}: {s}", .{ user, if (cfg.group != null) ", group " else "", cfg.group orelse "", @errorName(err) });
        return err;
    };
}

/// TLS material per listener, loaded once and shared read-only by the
/// workers. One ticket key per generation lets any worker resume a session.
/// Generated once per process, so they survive reloads.
var quic_keys: Worker.Shared.QuicKeys = undefined;

fn loadShared(arena: std.mem.Allocator, io: std.Io, cfg: *const config.Config) !Worker.Shared {
    var ticket_key: [16]u8 = undefined;
    quic.sys.randomBytes(&ticket_key);
    var tls_listeners: std.ArrayListUnmanaged(Worker.Shared.TlsListener) = .empty;
    for (cfg.servers) |srv| {
        for (srv.listen) |l| {
            if (!l.tls and !l.quic) continue;
            if (sharedHas(tls_listeners.items, l.address, l.port)) continue;
            var on_listener: std.ArrayListUnmanaged(*const config.Server) = .empty;
            for (cfg.servers) |*other| {
                for (other.listen) |ol| {
                    if ((ol.tls or ol.quic) and ol.port == l.port and std.mem.eql(u8, ol.address, l.address)) {
                        try on_listener.append(arena, other);
                        break;
                    }
                }
            }
            const tc = tls.ServerConfig.load(arena, io, on_listener.items, ticket_key, &.{"http/1.1"}) catch |err| {
                log.err("tls for {s}:{d}: {s}", .{ l.address, l.port, @errorName(err) });
                return err;
            };
            try tls_listeners.append(arena, .{ .address = l.address, .port = l.port, .cfg = tc });
        }
    }
    return .{ .tls_listeners = tls_listeners.items, .quic_keys = quic_keys, .upstream_cas = try loadUpstreamCas(arena, cfg) };
}

/// One bundle per `tls_ca` file, and the system store at most once.
fn loadUpstreamCas(arena: std.mem.Allocator, cfg: *const config.Config) ![]const Worker.Shared.UpstreamCa {
    const Bundle = std.crypto.Certificate.Bundle;
    var out: std.ArrayListUnmanaged(Worker.Shared.UpstreamCa) = .empty;
    var loaded: std.ArrayListUnmanaged(struct { path: ?[]const u8, bundle: *const Bundle }) = .empty;
    for (cfg.upstreams) |up| {
        if (!up.tls or (!up.tls_verify and up.tls_ca == null)) continue;
        const bundle = for (loaded.items) |l| {
            const same = if (l.path) |p| up.tls_ca != null and std.mem.eql(u8, p, up.tls_ca.?) else up.tls_ca == null;
            if (same) break l.bundle;
        } else blk: {
            const b = try arena.create(Bundle);
            b.* = (if (up.tls_ca) |path| quic.ca_bundle.loadFile(arena, path) else quic.ca_bundle.loadSystem(arena)) catch |err| {
                log.err("upstream '{s}': loading {s}: {s}", .{ up.name, up.tls_ca orelse "system CA store", @errorName(err) });
                return err;
            };
            try loaded.append(arena, .{ .path = up.tls_ca, .bundle = b });
            break :blk b;
        };
        try out.append(arena, .{ .upstream = up.name, .bundle = bundle });
    }
    return out.items;
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var path: []const u8 = "routez.zon";
    var check_only = false;
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "-t")) {
            check_only = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage});
            return 0;
        } else {
            path = arg;
        }
    }

    if (check_only) {
        var check_arena: std.heap.ArenaAllocator = .init(std.heap.smp_allocator);
        defer check_arena.deinit();
        const cfg = config.load(init.io, check_arena.allocator(), path) catch |err| {
            log.err("{s}: {s}", .{ path, @errorName(err) });
            return 1;
        };
        _ = resolveUser(check_arena.allocator(), &cfg) catch return 1;
        _ = loadShared(check_arena.allocator(), init.io, &cfg) catch return 1;
        log.info("{s}: configuration ok", .{path});
        return 0;
    }

    quic.sys.randomBytes(&quic_keys.retry);
    quic.sys.randomBytes(&quic_keys.reset);
    if (std.c.pipe(&signal_pipe) != 0) return error.PipeFailed;
    const ignore: std.posix.Sigaction = .{ .handler = .{ .handler = std.posix.SIG.IGN }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.PIPE, &ignore, null);
    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onSignal }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
    std.posix.sigaction(.HUP, &act, null);
    std.posix.sigaction(.USR1, &act, null);
    stats.version = build_options.version;
    stats.start_time_s = quic.sys.realtimeSeconds();

    const manager = try acme.Manager.create(std.heap.smp_allocator, init.io, onCertificateRenewed);
    var next_id: usize = 0;
    var gen = Generation.start(init.io, path, null, next_id, manager, null) catch return 1;
    next_id += gen.workers.len;
    stats.workers.store(gen.workers.len, .monotonic);
    log.info("{d} worker(s) running, config {s}", .{ gen.workers.len, path });

    while (true) {
        var b: u8 = 0;
        const n = std.c.read(signal_pipe[0], @ptrCast(&b), 1);
        if (n != 1) continue; // EINTR
        if (b == 'l') {
            logs.reopenAll(init.io);
            log.info("reopened log files", .{});
            continue;
        }
        if (b == 'r' or b == 'c') {
            // A new certificate reloads the same config text, not whatever
            // the file holds now: edits wait for their SIGHUP.
            if (b == 'r') log.info("reloading {s}", .{path}) else log.info("reloading for a new certificate", .{});
            const fresh = Generation.start(init.io, path, if (b == 'c') gen.source else null, next_id, manager, gen) catch {
                stats.inc(&stats.reload_failures);
                log.err("reload failed; keeping the running configuration", .{});
                continue;
            };
            stats.inc(&stats.reloads);
            stats.workers.store(fresh.workers.len, .monotonic);
            next_id += fresh.workers.len;
            const old = gen;
            gen = fresh;
            old.stop();
            // Joined on its own thread so a second signal isn't held up.
            const t = std.Thread.spawn(.{}, Generation.join, .{ old, init.io }) catch {
                old.join(init.io);
                continue;
            };
            t.detach();
            log.info("reloaded: {d} worker(s)", .{gen.workers.len});
            continue;
        }
        gen.stop();
        gen.join(init.io);
        log.info("stopped (quic steered: {d})", .{@import("stats.zig").quic_steered.load(.monotonic)});
        return 0;
    }
}

fn sharedHas(list: []const Worker.Shared.TlsListener, address: []const u8, port: u16) bool {
    for (list) |l| if (l.port == port and std.mem.eql(u8, l.address, address)) return true;
    return false;
}

fn runWorker(w: *Worker) void {
    w.run() catch |err| log.err("worker {d}: {s}", .{ w.id, @errorName(err) });
}

test {
    _ = @import("config.zig");
    _ = @import("timers.zig");
    _ = @import("net/socket.zig");
    _ = @import("net/addr.zig");
    _ = @import("http/common.zig");
    _ = @import("http/vars.zig");
    _ = @import("http1/parser.zig");
    _ = @import("router.zig");
    _ = @import("handlers/static.zig");
    _ = @import("handlers/proxy.zig");
    _ = @import("worker.zig");
    _ = @import("udp_proxy.zig");
    _ = @import("h3/server.zig");
    _ = @import("gzip.zig");
    _ = @import("acme.zig");
    _ = @import("steering.zig");
    _ = @import("access_log.zig");
    _ = @import("logs.zig");
    _ = @import("privileges.zig");
    _ = @import("stats.zig");
    _ = @import("client_limits.zig");
}

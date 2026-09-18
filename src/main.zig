const std = @import("std");
const quic = @import("quic");
const config = @import("config.zig");
const tls = @import("net/tls.zig");
const acme = @import("acme.zig");
const worker_mod = @import("worker.zig");
const Worker = worker_mod.Worker;

pub const std_options: std.Options = .{
    .log_level = .info,
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
    const b: u8 = if (sig == .HUP) 'r' else 's';
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

    /// Start workers on `source` if given, else on the file at `path`.
    fn start(io: std.Io, path: []const u8, source: ?[:0]const u8, first_id: usize, manager: *acme.Manager) !*Generation {
        const alloc = std.heap.smp_allocator;
        const g = try alloc.create(Generation);
        g.* = .{ .arena_state = .init(alloc), .source = undefined, .cfg = undefined, .shared = undefined, .workers = &.{}, .threads = &.{} };
        errdefer {
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
        g.shared = try loadShared(arena, io, &g.cfg);
        g.shared.challenges = &manager.challenges;

        const workers = try arena.alloc(*Worker, g.cfg.workers);
        var created: usize = 0;
        errdefer for (workers[0..created]) |w| w.destroy();
        for (workers, 0..) |*w, i| {
            w.* = Worker.create(alloc, io, &g.cfg, &g.shared, first_id + i) catch |err| {
                log.err("worker {d}: {s}", .{ i, @errorName(err) });
                return err;
            };
            created += 1;
        }
        g.workers = workers;
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
    fn join(self: *Generation) void {
        for (self.threads) |t| t.join();
        self.arena_state.deinit();
        std.heap.smp_allocator.destroy(self);
    }
};

/// TLS material per listener, loaded once and shared read-only by the
/// workers. One ticket key per generation lets any worker resume a session.
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
    return .{ .tls_listeners = tls_listeners.items };
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
        _ = loadShared(check_arena.allocator(), init.io, &cfg) catch return 1;
        log.info("{s}: configuration ok", .{path});
        return 0;
    }

    if (std.c.pipe(&signal_pipe) != 0) return error.PipeFailed;
    const ignore: std.posix.Sigaction = .{ .handler = .{ .handler = std.posix.SIG.IGN }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.PIPE, &ignore, null);
    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onSignal }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
    std.posix.sigaction(.HUP, &act, null);

    const manager = try acme.Manager.create(std.heap.smp_allocator, init.io, onCertificateRenewed);
    var next_id: usize = 0;
    var gen = Generation.start(init.io, path, null, next_id, manager) catch return 1;
    next_id += gen.workers.len;
    log.info("{d} worker(s) running, config {s}", .{ gen.workers.len, path });

    while (true) {
        var b: u8 = 0;
        const n = std.c.read(signal_pipe[0], @ptrCast(&b), 1);
        if (n != 1) continue; // EINTR
        if (b == 'r' or b == 'c') {
            // A new certificate reloads the same config text, not whatever
            // the file holds now: edits wait for their SIGHUP.
            if (b == 'r') log.info("reloading {s}", .{path}) else log.info("reloading for a new certificate", .{});
            const fresh = Generation.start(init.io, path, if (b == 'c') gen.source else null, next_id, manager) catch {
                log.err("reload failed; keeping the running configuration", .{});
                continue;
            };
            next_id += fresh.workers.len;
            const old = gen;
            gen = fresh;
            old.stop();
            // Joined on its own thread so a second signal isn't held up.
            const t = std.Thread.spawn(.{}, Generation.join, .{old}) catch {
                old.join();
                continue;
            };
            t.detach();
            log.info("reloaded: {d} worker(s)", .{gen.workers.len});
            continue;
        }
        gen.stop();
        gen.join();
        log.info("stopped", .{});
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
    _ = @import("http1/parser.zig");
    _ = @import("router.zig");
    _ = @import("handlers/static.zig");
    _ = @import("handlers/proxy.zig");
    _ = @import("worker.zig");
    _ = @import("udp_proxy.zig");
    _ = @import("h3/server.zig");
    _ = @import("gzip.zig");
    _ = @import("acme.zig");
}

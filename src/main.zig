const std = @import("std");
const quic = @import("quic");
const config = @import("config.zig");
const tls = @import("net/tls.zig");
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

var workers: []*Worker = &.{};

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    for (workers) |w| w.requestStop();
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

    const cfg = config.load(init.io, arena, path) catch |err| {
        log.err("{s}: {s}", .{ path, @errorName(err) });
        return 1;
    };
    if (check_only) {
        log.info("{s}: configuration ok", .{path});
        return 0;
    }

    // TLS material per listener, loaded once and shared read-only by all
    // workers. One ticket key for the process lets any worker resume a session.
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
            const tc = tls.ServerConfig.load(arena, on_listener.items, ticket_key, &.{"http/1.1"}) catch |err| {
                log.err("tls for {s}:{d}: {s}", .{ l.address, l.port, @errorName(err) });
                return 1;
            };
            try tls_listeners.append(arena, .{ .address = l.address, .port = l.port, .cfg = tc });
        }
    }
    const shared: Worker.Shared = .{ .tls_listeners = tls_listeners.items };

    // Workers outlive main's scopes and are torn down with the process.
    const alloc = std.heap.smp_allocator;
    const list = try arena.alloc(*Worker, cfg.workers);
    for (list, 0..) |*w, i| {
        w.* = Worker.create(alloc, init.io, &cfg, &shared, i) catch |err| {
            log.err("worker {d}: {s}", .{ i, @errorName(err) });
            return 1;
        };
    }
    workers = list;

    const ignore: std.posix.Sigaction = .{ .handler = .{ .handler = std.posix.SIG.IGN }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.PIPE, &ignore, null);
    const stop: std.posix.Sigaction = .{ .handler = .{ .handler = onSignal }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.INT, &stop, null);
    std.posix.sigaction(.TERM, &stop, null);

    const threads = try arena.alloc(std.Thread, list.len - 1);
    for (threads, list[1..]) |*t, w| {
        t.* = try std.Thread.spawn(.{}, runWorker, .{w});
    }
    log.info("{d} worker(s) running, config {s}", .{ list.len, path });
    runWorker(list[0]);
    for (threads) |t| t.join();
    log.info("stopped", .{});
    return 0;
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
}

//! `routez tunnel`: share a server on this machine through a routez edge.
//!
//! The agent opens a WebTransport session to the edge's `tunnel_accept`
//! location and keeps it open, reconnecting when it drops. The edge opens a
//! stream on the session for each upstream connection its proxy makes to
//! the tunnel (`edge.zig`); the agent connects each stream to the local
//! server and pipes the two together (`pipe.zig`). The stream carries the
//! proxy's HTTP/1.1 as-is, WebSocket upgrades included. A player's
//! WebTransport session comes as streams of its own (`wire.zig`), which the
//! agent opens again on the local server (`local_wt.zig`).
const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const qpack = quic.qpack;
const xev = event_loop.Xev;
const findHeader = quic.webtransport_protocol.findHeader;
const config = @import("../config.zig");
const addr = @import("../net/addr.zig");
const socket = @import("../net/socket.zig");
const timers = @import("../timers.zig");
const pipe_mod = @import("pipe.zig");
const edge = @import("edge.zig");
const wire = @import("wire.zig");
const local_wt = @import("local_wt.zig");

const log = std.log.scoped(.tunnel);

pub const usage =
    \\usage: routez tunnel [-n name] [-u user:password] [--ca file] [-k] [--wt local] <edge-url> <local>
    \\  <edge-url>  https://host[:port]/path of the edge's tunnel_accept location
    \\  <local>     port, or host:port, of the server to share (host 127.0.0.1)
    \\  --wt local  where players' WebTransport sessions go, over UDP (default:
    \\              <local>); its certificate isn't checked
    \\  -n name     ask for this name (default: the edge picks one)
    \\  -u user:password  for a location with auth_basic
    \\  --ca file   trust this CA bundle (PEM) for the edge, not the system's
    \\  -k          accept any certificate from the edge (testing only)
    \\
;

/// QUIC PINGs after this much silence, and sooner if the edge's idle
/// timeout asks for it, so an idle tunnel stays open.
const keepalive_ms = 10_000;
/// Short: a playtest waits on the edge coming back.
const max_backoff_ms = 5_000;
/// A handshake that hasn't finished by then moves on to the edge's next
/// address.
const handshake_ms = 3_000;
/// Streams the edge may have open on the session at once: one per upstream
/// connection, one per player's WebTransport session and one per stream of
/// it.
const max_streams = 1000;

const Options = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
    local: std.Io.net.IpAddress,
    local_label: []const u8,
    /// Players' WebTransport sessions go here.
    wt: std.Io.net.IpAddress,
    wt_host: []const u8,
    name: ?[]const u8 = null,
    auth: ?[]const u8 = null,
    ca: ?[]const u8 = null,
    insecure: bool = false,
};

/// Set by SIGINT/SIGTERM; the tick closes the session so the edge frees the
/// name at once rather than at its idle timeout.
var quit_requested: std.atomic.Value(bool) = .init(false);

fn onQuit(_: std.posix.SIG) callconv(.c) void {
    quit_requested.store(true, .monotonic);
}

pub fn main(arena: std.mem.Allocator, args: []const []const u8) u8 {
    const opts = parseArgs(arena, args) catch |err| {
        if (err != error.Help) std.debug.print("routez tunnel: {s}\n", .{@errorName(err)});
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const ignore: std.posix.Sigaction = .{ .handler = .{ .handler = std.posix.SIG.IGN }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.PIPE, &ignore, null);
    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onQuit }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);

    const a = std.heap.smp_allocator;
    const agent = a.create(Agent) catch return 1;
    agent.* = .{ .alloc = a, .arena = arena, .opts = opts, .loop = xev.Loop.init(.{}) catch return 1, .timers = undefined };
    agent.timers = timers.Timers.init(&agent.loop) catch return 1;
    agent.timers.on_tick = Agent.onTick;
    agent.headers = agent.connectHeaders() catch return 1;
    agent.timers.start();
    agent.connect();
    agent.loop.run(.until_done) catch |err| {
        log.err("event loop: {s}", .{@errorName(err)});
        return 1;
    };
    return agent.exit_code;
}

fn parseArgs(arena: std.mem.Allocator, args: []const []const u8) !Options {
    var positional: [2][]const u8 = undefined;
    var n: usize = 0;
    var name: ?[]const u8 = null;
    var auth: ?[]const u8 = null;
    var ca: ?[]const u8 = null;
    var wt_text: ?[]const u8 = null;
    var insecure = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return error.Help;
        if (std.mem.eql(u8, arg, "-k")) {
            insecure = true;
        } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--ca") or std.mem.eql(u8, arg, "--wt")) {
            i += 1;
            if (i == args.len) return error.MissingValue;
            if (arg[1] == 'n') name = args[i] else if (arg[1] == 'u') auth = args[i] else if (arg[2] == 'c') ca = args[i] else wt_text = args[i];
        } else {
            if (n == positional.len) return error.TooManyArguments;
            positional[n] = arg;
            n += 1;
        }
    }
    if (n != 2) return error.MissingArguments;

    const url = positional[0];
    const rest = if (std.mem.startsWith(u8, url, "https://")) url["https://".len..] else return error.EdgeUrlNotHttps;
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const hp = config.parseHostPortOr(rest[0..slash], 443) catch return error.BadEdgeHost;
    const path = if (slash < rest.len) rest[slash..] else "/";

    const local = try parseLocal(positional[1]);
    const ip = addr.resolve(local.host, local.port) catch return error.CannotResolveLocal;
    const wt_local = if (wt_text) |t| try parseLocal(t) else local;
    const wt_ip = addr.resolve(wt_local.host, wt_local.port) catch return error.CannotResolveLocal;
    return .{
        .host = hp.host,
        .port = hp.port,
        .path = path,
        .local = ip,
        .local_label = try std.fmt.allocPrint(arena, "{s}:{d}", .{ local.host, local.port }),
        .wt = wt_ip,
        .wt_host = wt_local.host,
        .name = name,
        .auth = auth,
        .ca = ca,
        .insecure = insecure,
    };
}

/// A port, or host:port; the host is 127.0.0.1 unless named.
fn parseLocal(text: []const u8) !config.HostPort {
    const hp: config.HostPort = if (std.fmt.parseInt(u16, text, 10)) |port|
        .{ .host = "127.0.0.1", .port = port }
    else |_|
        config.parseHostPort(text) catch return error.LocalNeedsPort;
    if (hp.port == 0) return error.LocalNeedsPort;
    return hp;
}

const AgentPipe = pipe_mod.Pipe(Agent, true);
const Client = event_loop.Client(Handler);

/// An edge-opened stream until its head says what it carries.
const Fresh = struct { head: [wire.max_head]u8 = undefined, len: usize = 0 };

pub const Agent = struct {
    pub const Link = Conn;

    alloc: std.mem.Allocator,
    /// Lives as long as the agent.
    arena: std.mem.Allocator,
    opts: Options,
    loop: xev.Loop,
    timers: timers.Timers,
    headers: []const qpack.Header = &.{},
    exit_code: u8 = 0,

    conn: ?*Conn = null,
    /// The edge is draining this one; it serves on until `conn` is ready
    /// and its own streams are done, or the edge closes it.
    old: ?*Conn = null,
    /// Connections stopping, freed once off the loop.
    retired: std.ArrayListUnmanaged(*Conn) = .empty,
    next_serial: u64 = 1,
    /// By connection serial and stream.
    pipes: AgentPipe.Set = .{},
    /// Edge-opened streams whose head is still coming, likewise.
    fresh: std.AutoHashMapUnmanaged(local_wt.Key, Fresh) = .empty,
    /// Players' WebTransport sessions.
    wt: local_wt.Sessions = .{},
    /// A datagram for the edge, behind its session's token.
    datagram_buf: std.ArrayListUnmanaged(u8) = .empty,
    /// The URL last announced, to say so only when it changes.
    url: std.ArrayListUnmanaged(u8) = .empty,
    backoff_ms: u32 = 0,
    reconnect: timers.Deadline = .{ .callback = onReconnect },
    quitting: bool = false,
    /// The edge's addresses, tried in turn: a name like `localhost` gives
    /// ::1 first, where the edge may listen on 127.0.0.1 alone.
    addrs: [8]std.Io.net.IpAddress = undefined,
    addr_count: usize = 0,
    addr_index: usize = 0,

    /// The CONNECT's headers. Clients borrow them, so they are never freed.
    fn connectHeaders(self: *Agent) ![]const qpack.Header {
        var list: std.ArrayListUnmanaged(qpack.Header) = .empty;
        if (self.opts.name) |n| try list.append(self.arena, .{ .name = edge.name_header, .value = n });
        if (self.opts.auth) |cred| {
            const enc = std.base64.standard.Encoder;
            const buf = try self.arena.alloc(u8, "Basic ".len + enc.calcSize(cred.len));
            @memcpy(buf[0.."Basic ".len], "Basic ");
            _ = enc.encode(buf["Basic ".len..], cred);
            try list.append(self.arena, .{ .name = "authorization", .value = buf });
        }
        return list.items;
    }

    fn connect(self: *Agent) void {
        self.open() catch |err| {
            log.warn("cannot reach {s}:{d}: {s}", .{ self.opts.host, self.opts.port, @errorName(err) });
            self.retryLater(false);
        };
    }

    fn onReconnect(d: *timers.Deadline) void {
        const self: *Agent = @fieldParentPtr("reconnect", d);
        self.connect();
    }

    fn open(self: *Agent) !void {
        if (self.addr_count == 0) self.addr_count = try addr.resolveAll(self.opts.host, self.opts.port, &self.addrs);
        const ip = self.addrs[self.addr_index];
        var ip_buf: [64]u8 = undefined;
        const c = try self.alloc.create(Conn);
        errdefer self.alloc.destroy(c);
        c.* = .{ .agent = self, .serial = self.next_serial, .handler = .{ .conn = c }, .client = undefined };
        self.next_serial += 1;
        c.client = try Client.init(self.alloc, &c.handler, .{
            .address = socket.formatIp(ip, &ip_buf),
            .port = self.opts.port,
            .server_name = self.opts.host,
            .path = self.opts.path,
            .connect_headers = self.headers,
            .ipv6 = ip == .ip6,
            .ca = if (self.opts.ca) |f| .{ .file = f } else .system,
            .skip_cert_verify = self.opts.insecure,
            .loop = &self.loop,
            // Replaces quic-zig's defaults, so restate the datagram size.
            .conn_config = .{
                .max_datagram_frame_size = (event_loop.ClientConfig{}).max_datagram_frame_size,
                .keep_alive_period = keepalive_ms,
                .handshake_timeout = handshake_ms,
                .initial_max_streams_bidi = max_streams,
            },
            .wt_credits = credits: {
                var cr: quic.webtransport_flow_control.Credits = .default;
                cr.max_streams_bidi = max_streams;
                break :credits cr;
            },
        });
        c.client.start();
        self.conn = c;
    }

    /// `next_address`: this one never answered, so try the edge's next at
    /// once; past the last, wait and resolve again.
    fn retryLater(self: *Agent, next_address: bool) void {
        if (self.quitting) return self.finish();
        if (next_address) {
            self.addr_index += 1;
            if (self.addr_index < self.addr_count) return self.timers.set(&self.reconnect, 0);
            self.addr_index = 0;
            self.addr_count = 0;
        }
        self.backoff_ms = if (self.backoff_ms == 0) 500 else @min(self.backoff_ms * 2, max_backoff_ms);
        self.timers.set(&self.reconnect, self.backoff_ms);
    }

    /// Let `c` go: its pipes close, and it is freed once off the loop.
    fn retire(self: *Agent, c: *Conn) void {
        if (c.retired) return;
        c.retired = true;
        if (self.old == c) self.old = null;
        self.pipes.detach(c);
        self.wt.detach(c);
        var it = self.fresh.keyIterator();
        while (it.next()) |k| if (k.conn == c.serial) {
            self.fresh.removeByPtr(k);
            it = self.fresh.keyIterator();
        };
        c.client.stop();
        self.retired.append(self.alloc, c) catch {};
        if (self.conn == c) {
            self.conn = null;
            if (c.state == .ready) log.warn("session to the edge lost; reconnecting", .{});
            self.retryLater(c.state == .connecting);
        }
    }

    /// Done for good: stop once every connection is off the loop.
    fn finish(self: *Agent) void {
        self.quitting = true;
        self.timers.clear(&self.reconnect);
        if (self.old) |c| self.retire(c);
        if (self.conn) |c| self.retire(c);
    }

    /// The edge is stopping or reloading: a new session now, the old one
    /// kept until it takes over.
    fn draining(self: *Agent, c: *Conn) void {
        if (self.conn != c or self.quitting) return;
        log.info("the edge is draining this session; opening another", .{});
        if (self.old) |prev| self.retire(prev);
        self.old = c;
        self.conn = null;
        self.backoff_ms = 0;
        self.connect();
    }

    fn pipesOn(self: *Agent, c: *Conn) usize {
        var n: usize = self.wt.on(c);
        for (self.pipes.map.values()) |p| n += @intFromBool(p.link == c);
        return n;
    }

    fn onTick(t: *timers.Timers) void {
        const self: *Agent = @fieldParentPtr("timers", t);
        if (quit_requested.load(.monotonic) and !self.quitting) {
            log.info("closing the tunnel", .{});
            self.finish();
        }
        // So is one whose handshake ran past `handshake_ms`.
        if (self.conn) |c| if (c.client.conn.isClosed()) self.retire(c);
        if (self.old) |c| {
            const taken_over = if (self.conn) |n| n.state == .ready else false;
            if (c.client.conn.isClosed() or (taken_over and self.pipesOn(c) == 0)) self.retire(c);
        }
        self.pipes.checkPaused();
        self.wt.tick();
        var i: usize = 0;
        while (i < self.retired.items.len) {
            const c = self.retired.items[i];
            if (!c.client.isStopped()) {
                i += 1;
                continue;
            }
            _ = self.retired.swapRemove(i);
            c.client.deinit();
            self.alloc.destroy(c);
        }
        if (self.quitting and self.conn == null and self.retired.items.len == 0 and self.pipes.map.count() == 0 and self.wt.idle()) {
            self.timers.stop();
            self.loop.stop();
        }
    }

    fn sessionReady(self: *Agent, c: *Conn, sid: u64, headers: []const qpack.Header) void {
        c.sid = sid;
        c.state = .ready;
        self.backoff_ms = 0;
        // Reconnect to this address first.
        if (self.addr_index != 0) {
            std.mem.swap(std.Io.net.IpAddress, &self.addrs[0], &self.addrs[self.addr_index]);
            self.addr_index = 0;
        }
        // Ask for the edge's pick from now on, so a reconnect keeps the URL.
        if (self.opts.name == null) if (findHeader(headers, edge.name_header)) |n| keep: {
            self.opts.name = self.arena.dupe(u8, n) catch break :keep;
            self.headers = self.connectHeaders() catch self.headers;
        };
        const url = findHeader(headers, edge.url_header) orelse "";
        if (std.mem.eql(u8, url, self.url.items)) {
            log.info("session to the edge back", .{});
            return;
        }
        self.url.clearRetainingCapacity();
        self.url.appendSlice(self.alloc, url) catch {};
        // The one line a user waits for; stdout, so a script can take it.
        var buf: [512]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "{s} -> {s}\n", .{ url, self.opts.local_label }) catch return;
        _ = std.c.write(1, line.ptr, line.len);
    }

    fn sessionRejected(self: *Agent, c: *Conn, status: []const u8) void {
        c.state = .refused;
        const Refusal = struct { why: []const u8 = "", fatal: bool = false };
        const r: Refusal = switch (std.fmt.parseInt(u16, status, 10) catch 0) {
            400 => .{ .why = "the name must be letters, digits and inner hyphens, up to 63", .fatal = true },
            401 => .{ .why = "wrong or missing user and password (-u)", .fatal = true },
            403 => .{ .fatal = true },
            404 => .{ .why = "no tunnel_accept location at that URL", .fatal = true },
            409 => .{ .why = "the name is taken (maybe by our last session, not yet timed out)" },
            else => .{},
        };
        log.err("the edge refused the tunnel: {s} {s}", .{ status, r.why });
        if (r.fatal) {
            self.exit_code = 1;
            self.quitting = true;
        }
        self.retire(c);
    }

    /// The edge opened a stream: what it carries is in its first bytes.
    fn freshStream(self: *Agent, c: *Conn, stream: u64) void {
        self.fresh.put(self.alloc, .{ .conn = c.serial, .stream = stream }, .{}) catch {
            var s = c.session();
            refuseStream(&s, stream);
        };
    }

    /// More of a fresh stream; false when `stream` isn't one.
    fn freshData(self: *Agent, c: *Conn, stream: u64, data: []const u8, fin: bool) bool {
        const key: local_wt.Key = .{ .conn = c.serial, .stream = stream };
        const f = self.fresh.getPtr(key) orelse return false;
        var s = c.session();
        const take = @min(data.len, f.head.len - f.len);
        @memcpy(f.head[f.len..][0..take], data[0..take]);
        const before = f.len;
        f.len += take;
        const parsed = wire.parseHead(f.head[0..f.len]) catch {
            _ = self.fresh.remove(key);
            refuseStream(&s, stream);
            return true;
        };
        const h = parsed orelse {
            if (fin) {
                _ = self.fresh.remove(key);
                refuseStream(&s, stream);
            }
            return true;
        };
        _ = self.fresh.remove(key);
        const rest = data[h.len - before ..];
        switch (h.kind) {
            .http => if (self.openPipe(c, stream)) |p| if (rest.len > 0 or fin) p.onStreamData(rest, fin),
            .session => self.wt.openSession(c, stream, h.token, rest, fin),
            .stream => self.wt.openStream(c, stream, h.token, h.uni, rest, fin),
        }
        return true;
    }

    fn openPipe(self: *Agent, c: *Conn, stream: u64) ?*AgentPipe {
        const p = self.alloc.create(AgentPipe) catch {
            var s = c.session();
            s.resetStream(stream, pipe_mod.gone_error);
            return null;
        };
        p.* = .{ .owner = self, .link = c, .conn = c.serial, .stream = stream, .sock = undefined };
        p.sock.connect(p, &self.loop, &self.timers, self.alloc, self.opts.local) catch {
            self.alloc.destroy(p);
            var s = c.session();
            s.resetStream(stream, pipe_mod.gone_error);
            return null;
        };
        self.pipes.add(self.alloc, p) catch {
            p.sock.abort();
            return null;
        };
        return p;
    }

    /// The local server didn't answer: the edge's proxy gets a 502 saying so.
    pub fn pipeConnected(self: *Agent, p: *AgentPipe, err: ?anyerror) void {
        const e = err orelse return;
        log.warn("{s}: {s}", .{ self.opts.local_label, @errorName(e) });
        var body_buf: [256]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "routez tunnel: nothing answered at {s} ({s})\n", .{ self.opts.local_label, @errorName(e) }) catch "routez tunnel: the local server didn't answer\n";
        var buf: [512]u8 = undefined;
        const resp = std.fmt.bufPrint(&buf, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body.len, body }) catch return p.sock.abort();
        p.replyAndClose(resp);
    }
};

fn refuseStream(s: *event_loop.ClientSession, stream: u64) void {
    s.resetStream(stream, pipe_mod.gone_error);
    s.stopSending(stream, pipe_mod.gone_error);
}

/// One connection to the edge, and its session.
pub const Conn = struct {
    agent: *Agent,
    /// Tells this connection's pipes from an earlier one's: stream ids
    /// start over on each.
    serial: u64,
    handler: Handler,
    client: Client,
    sid: u64 = 0,
    /// Until the edge answers the session, its address isn't known to work.
    state: enum { connecting, ready, refused } = .connecting,
    retired: bool = false,

    pub fn session(self: *Conn) event_loop.ClientSession {
        return self.client.clientSession();
    }

    pub fn backlog(self: *Conn, stream: u64) u64 {
        return self.client.conn.streamBufferedBytes(stream) orelse 0;
    }
};

const Handler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;
    conn: *Conn,

    fn live(self: *Handler) ?*Conn {
        return if (self.conn.retired) null else self.conn;
    }

    fn pipe(self: *Handler, stream: ?u64) ?*AgentPipe {
        const c = self.live() orelse return null;
        return c.agent.pipes.get(c.serial, stream orelse return null);
    }

    pub fn onSessionReady(self: *Handler, _: *event_loop.ClientSession, session_id: u64, headers: []const qpack.Header) void {
        const c = self.live() orelse return;
        c.agent.sessionReady(c, session_id, headers);
    }

    pub fn onSessionRejected(self: *Handler, _: *event_loop.ClientSession, _: u64, status: []const u8) void {
        const c = self.live() orelse return;
        c.agent.sessionRejected(c, status);
    }

    pub fn onSessionClosed(self: *Handler, _: *event_loop.ClientSession, _: u64, _: u32, _: []const u8) void {
        const c = self.live() orelse return;
        c.agent.retire(c);
    }

    pub fn onSessionDraining(self: *Handler, _: *event_loop.ClientSession, _: u64) void {
        const c = self.live() orelse return;
        c.agent.draining(c);
    }

    pub fn onBidiStream(self: *Handler, _: *event_loop.ClientSession, _: u64, stream_id: u64) void {
        const c = self.live() orelse return;
        c.agent.freshStream(c, stream_id);
    }

    pub fn onUniStream(_: *Handler, session: *event_loop.ClientSession, _: u64, stream_id: u64) void {
        session.stopSending(stream_id, pipe_mod.gone_error);
    }

    pub fn onStreamData(self: *Handler, _: *event_loop.ClientSession, stream_id: u64, data: []const u8, fin: bool) void {
        if (self.pipe(stream_id)) |p| return p.onStreamData(data, fin);
        const c = self.live() orelse return;
        if (c.agent.wt.onTunnelData(c, stream_id, data, fin)) return;
        _ = c.agent.freshData(c, stream_id, data, fin);
    }

    pub fn onStreamReset(self: *Handler, _: *event_loop.ClientSession, _: u64, stream_id: u64, error_code: u32) void {
        self.onAbort(stream_id, true, error_code);
    }

    pub fn onStopSending(self: *Handler, _: *event_loop.ClientSession, _: u64, stream_id: u64, error_code: u32) void {
        self.onAbort(stream_id, false, error_code);
    }

    fn onAbort(self: *Handler, stream_id: u64, reset: bool, error_code: u32) void {
        if (self.pipe(stream_id)) |p| return p.onStreamAbort();
        const c = self.live() orelse return;
        if (c.agent.wt.onTunnelAbort(c, stream_id, reset, error_code)) return;
        _ = c.agent.fresh.remove(.{ .conn = c.serial, .stream = stream_id });
    }

    pub fn onWritable(self: *Handler, _: *event_loop.ClientSession, _: u64, stream_id: ?u64) void {
        if (self.pipe(stream_id)) |p| return p.onWritable();
        const c = self.live() orelse return;
        _ = c.agent.wt.onTunnelWritable(c, stream_id orelse return);
    }

    pub fn onDatagram(self: *Handler, _: *event_loop.ClientSession, _: u64, data: []const u8) void {
        const c = self.live() orelse return;
        c.agent.wt.onTunnelDatagram(c, data);
    }
};

test "the edge URL and the local server" {
    const a = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const o = try parseArgs(arena, &.{ "-n", "game", "https://edge.example:8443/.tunnel", "2567" });
    try std.testing.expectEqualStrings("edge.example", o.host);
    try std.testing.expectEqual(@as(u16, 8443), o.port);
    try std.testing.expectEqualStrings("/.tunnel", o.path);
    try std.testing.expectEqualStrings("127.0.0.1:2567", o.local_label);
    try std.testing.expectEqualStrings("game", o.name.?);
    const v6 = try parseArgs(arena, &.{ "https://[::1]", "[::1]:80" });
    try std.testing.expectEqualStrings("::1", v6.host);
    try std.testing.expectEqual(@as(u16, 443), v6.port);
    try std.testing.expectEqualStrings("/", v6.path);
    try std.testing.expectError(error.EdgeUrlNotHttps, parseArgs(arena, &.{ "http://edge", "80" }));
    try std.testing.expectError(error.LocalNeedsPort, parseArgs(arena, &.{ "https://edge", "localhost" }));
}

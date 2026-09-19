//! Layer-4 UDP forwarding, meant for QUIC we don't terminate (for example a
//! game server speaking raw QUIC behind this proxy).
//!
//! Each client address gets a flow with its own connected upstream socket,
//! so replies map back to the client without parsing. New flows go to a peer
//! chosen by the upstream's balancer, or, with `quic_lb`, to the peer whose
//! server ID is encoded in the packet's destination connection ID: a client
//! that migrates to a new address then still reaches the backend holding
//! its connection.
const std = @import("std");
const quic = @import("quic");
const xev = quic.event_loop.Xev;
const sys = quic.sys;
const quic_lb = quic.quic_lb;
const config = @import("config.zig");
const timers = @import("timers.zig");
const socket = @import("net/socket.zig");
const stats = @import("stats.zig");
const upstream = @import("upstream.zig");
const worker_mod = @import("worker.zig");
const Worker = worker_mod.Worker;

const log = std.log.scoped(.udp_proxy);
const posix = std.posix;

/// Datagrams handled per readiness event before yielding to the loop.
const batch = 256;

const AddrKey = [28]u8;

fn addrKey(sa: *const posix.sockaddr.storage) AddrKey {
    var k = std.mem.zeroes(AddrKey);
    const base: *const posix.sockaddr = @ptrCast(sa);
    switch (base.family) {
        posix.AF.INET => {
            const in: *const posix.sockaddr.in = @ptrCast(@alignCast(sa));
            k[0] = 4;
            @memcpy(k[1..3], std.mem.asBytes(&in.port));
            @memcpy(k[3..7], std.mem.asBytes(&in.addr));
        },
        posix.AF.INET6 => {
            const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(sa));
            k[0] = 6;
            @memcpy(k[1..3], std.mem.asBytes(&in6.port));
            @memcpy(k[3..19], &in6.addr);
            @memcpy(k[19..23], std.mem.asBytes(&in6.scope_id));
        },
        else => {},
    }
    return k;
}

fn sockaddrLen(sa: *const posix.sockaddr.storage) posix.socklen_t {
    const base: *const posix.sockaddr = @ptrCast(sa);
    return if (base.family == posix.AF.INET6) @sizeOf(posix.sockaddr.in6) else @sizeOf(posix.sockaddr.in);
}

fn ipToStorage(ip: std.Io.net.IpAddress) posix.sockaddr.storage {
    var s = std.mem.zeroes(posix.sockaddr.storage);
    switch (ip) {
        .ip4 => |a| {
            const in: *posix.sockaddr.in = @ptrCast(@alignCast(&s));
            in.* = .{ .port = std.mem.nativeToBig(u16, a.port), .addr = @bitCast(a.bytes) };
        },
        .ip6 => |a| {
            const in6: *posix.sockaddr.in6 = @ptrCast(@alignCast(&s));
            in6.* = .{ .port = std.mem.nativeToBig(u16, a.port), .flowinfo = a.flow, .addr = a.bytes, .scope_id = a.interface.index };
        },
    }
    return s;
}

pub const UdpProxy = struct {
    worker: *Worker,
    cfg: *const config.UdpProxy,
    group: *upstream.Group,
    fd: posix.socket_t,
    file: xev.File,
    poll_c: xev.Completion = .{},
    cancel_c: xev.Completion = .{},
    stopped: bool = false,
    flows: std.AutoHashMapUnmanaged(AddrKey, *Flow) = .empty,
    lb: ?quic_lb.Config = null,
    /// Server ID per peer, in the group's peer order.
    lb_ids: [][15]u8 = &.{},
    buf: [65536]u8 = undefined,

    /// `sock`, when given, is the bound socket of the proxy this one
    /// replaces; it is ours even if this fails.
    pub fn create(w: *Worker, cfg: *const config.UdpProxy, sock: ?posix.socket_t) !*UdpProxy {
        errdefer if (sock) |fd| sys.close(fd);
        const group = w.findGroup(cfg.proxy_pass) orelse return error.UnknownUpstream;
        const fd = sock orelse openSocket(cfg) catch |err| {
            worker_mod.bindFailed("udp_proxy", cfg.address, cfg.port, err);
            return err;
        };
        errdefer if (sock == null) sys.close(fd);

        const self = try w.alloc.create(UdpProxy);
        self.* = .{ .worker = w, .cfg = cfg, .group = group, .fd = fd, .file = xev.File.initFd(fd) };
        if (cfg.quic_lb) |lbc| {
            var lb: quic_lb.Config = .{ .config_id = lbc.config_id, .server_id_len = lbc.server_id_len, .nonce_len = lbc.nonce_len };
            if (lbc.key) |k| {
                var key: [16]u8 = undefined;
                _ = std.fmt.hexToBytes(&key, k) catch unreachable; // validated at load
                lb.key = key;
            }
            self.lb = lb;
            self.lb_ids = try w.alloc.alloc([15]u8, lbc.server_ids.len);
            for (lbc.server_ids, self.lb_ids) |hex, *out| {
                out.* = std.mem.zeroes([15]u8);
                _ = std.fmt.hexToBytes(out[0..lbc.server_id_len], hex) catch unreachable;
            }
        }
        if (w.id == 0) log.info("udp proxy on {s}:{d} -> {s}{s}", .{ cfg.address, cfg.port, cfg.proxy_pass, if (self.lb != null) " (quic-lb)" else "" });
        return self;
    }

    fn openSocket(cfg: *const config.UdpProxy) !posix.socket_t {
        const ip = try std.Io.net.IpAddress.parse(cfg.address, cfg.port);
        const storage = ipToStorage(ip);
        const family: u32 = if (ip == .ip6) posix.AF.INET6 else posix.AF.INET;
        const fd = try sys.socket(family, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
        errdefer sys.close(fd);
        const one: c_int = 1;
        _ = std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(c_int));
        // Same port in every worker; the kernel keeps a client's 4-tuple on one.
        _ = std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, std.mem.asBytes(&one), @sizeOf(c_int));
        const bufsz: c_int = 4 * 1024 * 1024;
        _ = std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&bufsz), @sizeOf(c_int));
        _ = std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&bufsz), @sizeOf(c_int));
        try sys.bind(fd, @ptrCast(&storage), sockaddrLen(&storage));
        return fd;
    }

    pub fn start(self: *UdpProxy) void {
        self.file.poll(&self.worker.loop, &self.poll_c, .read, UdpProxy, self, onReadable);
    }

    /// Close the listening socket and every flow.
    pub fn stop(self: *UdpProxy) void {
        if (self.stopped) return;
        self.stopped = true;
        self.closeAll();
        self.cancel_c = .{
            .op = .{ .cancel = .{ .c = &self.poll_c } },
            .userdata = self,
            .callback = onPollCancelled,
        };
        self.worker.loop.add(&self.cancel_c);
    }

    fn onPollCancelled(ud: ?*anyopaque, _: *xev.Loop, _: *xev.Completion, _: xev.Result) xev.CallbackAction {
        const self: *UdpProxy = @ptrCast(@alignCast(ud.?));
        sys.close(self.fd);
        return .disarm;
    }

    fn onReadable(ud: ?*UdpProxy, _: *xev.Loop, _: *xev.Completion, _: xev.File, r: xev.PollError!xev.PollEvent) xev.CallbackAction {
        const self = ud.?;
        if (self.stopped) return .disarm;
        _ = r catch return .rearm;
        var i: usize = 0;
        while (i < batch) : (i += 1) {
            var from: posix.sockaddr.storage = undefined;
            var from_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            const n = sys.recvfrom(self.fd, &self.buf, 0, @ptrCast(&from), &from_len) catch |err| switch (err) {
                error.WouldBlock => break,
                else => continue,
            };
            self.fromClient(self.buf[0..n], &from);
        }
        return .rearm;
    }

    fn fromClient(self: *UdpProxy, pkt: []const u8, from: *const posix.sockaddr.storage) void {
        const key = addrKey(from);
        if (self.flows.get(key)) |flow| return flow.toUpstream(pkt);
        if (self.flows.count() >= self.cfg.max_flows) return;

        const peer = self.routeByCid(pkt) orelse blk: {
            var text_buf: [64]u8 = undefined;
            const text = socket.formatSockaddr(from, &text_buf);
            break :blk self.group.pick(text, &.{}) orelse return;
        };
        stats.inc(&peer.stats.requests);
        const flow = Flow.create(self, key, from, peer) catch |err| {
            log.warn("new flow to {s}: {s}", .{ peer.label, @errorName(err) });
            return;
        };
        self.flows.put(self.worker.alloc, key, flow) catch {
            flow.close();
            return;
        };
        flow.toUpstream(pkt);
    }

    /// The peer named by a QUIC-LB server ID in the destination CID, if any.
    fn routeByCid(self: *UdpProxy, pkt: []const u8) ?*upstream.Peer {
        const lb = self.lb orelse return null;
        const i = peerIndexForPacket(&lb, self.lb_ids, pkt) orelse return null;
        const p = &self.group.peers[i];
        return if (p.health_ok) p else null;
    }

    fn removeFlow(self: *UdpProxy, flow: *Flow) void {
        if (self.flows.get(flow.key)) |f| {
            if (f == flow) _ = self.flows.remove(flow.key);
        }
    }

    pub fn closeAll(self: *UdpProxy) void {
        var it = self.flows.valueIterator();
        var list: std.ArrayListUnmanaged(*Flow) = .empty;
        defer list.deinit(self.worker.alloc);
        while (it.next()) |f| list.append(self.worker.alloc, f.*) catch break;
        for (list.items) |f| f.close();
    }
};

/// Index into `ids` of the server ID encoded in `pkt`'s destination CID.
/// Long headers carry the DCID length; short headers use the QUIC-LB length.
fn peerIndexForPacket(lb: *const quic_lb.Config, ids: []const [15]u8, pkt: []const u8) ?usize {
    if (pkt.len < 1) return null;
    const dcid: []const u8 = if (pkt[0] & 0x80 != 0) blk: {
        if (pkt.len < 6) return null;
        const len = pkt[5];
        if (len > 20 or pkt.len < 6 + @as(usize, len)) return null;
        break :blk pkt[6 .. 6 + len];
    } else blk: {
        const len = quic_lb.cidLength(lb);
        if (pkt.len < 1 + @as(usize, len)) return null;
        break :blk pkt[1 .. 1 + len];
    };
    if (dcid.len == 0) return null;
    if (quic_lb.extractConfigId(dcid[0]) != lb.config_id) return null;
    var sid: [15]u8 = undefined;
    if (!quic_lb.extractServerId(lb, dcid, &sid)) return null;
    const n: usize = lb.server_id_len;
    for (ids, 0..) |id, i| {
        if (std.mem.eql(u8, id[0..n], sid[0..n])) return i;
    }
    return null;
}

const Flow = struct {
    proxy: *UdpProxy,
    key: AddrKey,
    client: posix.sockaddr.storage,
    client_len: posix.socklen_t,
    peer: *upstream.Peer,
    fd: posix.socket_t,
    file: xev.File,
    poll_c: xev.Completion = .{},
    cancel_c: xev.Completion = .{},
    polling: bool = false,
    in_callback: bool = false,
    cancelling: bool = false,
    closing: bool = false,
    idle: timers.Deadline = .{ .callback = onIdle },
    free_cb: timers.Deferred = .{ .callback = onFree },

    fn create(proxy: *UdpProxy, key: AddrKey, client: *const posix.sockaddr.storage, peer: *upstream.Peer) !*Flow {
        const w = proxy.worker;
        const storage = ipToStorage(peer.addr);
        const family: u32 = if (peer.addr == .ip6) posix.AF.INET6 else posix.AF.INET;
        const fd = try sys.socket(family, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
        errdefer sys.close(fd);
        if (std.c.connect(fd, @ptrCast(&storage), sockaddrLen(&storage)) != 0) return error.ConnectFailed;

        const self = try w.alloc.create(Flow);
        self.* = .{
            .proxy = proxy,
            .key = key,
            .client = client.*,
            .client_len = sockaddrLen(client),
            .peer = peer,
            .fd = fd,
            .file = xev.File.initFd(fd),
        };
        peer.active += 1;
        self.polling = true;
        self.file.poll(&w.loop, &self.poll_c, .read, Flow, self, onReadable);
        w.timers.set(&self.idle, proxy.cfg.idle_timeout_ms);
        return self;
    }

    fn toUpstream(self: *Flow, pkt: []const u8) void {
        _ = sys.sendto(self.fd, pkt, 0, null, 0) catch |err| switch (err) {
            // UDP: a full buffer drops the datagram, as the network would.
            error.WouldBlock, error.SystemResources => return,
            else => {
                self.peer.recordFailure();
                return self.close();
            },
        };
        self.proxy.worker.timers.set(&self.idle, self.proxy.cfg.idle_timeout_ms);
    }

    fn onReadable(ud: ?*Flow, _: *xev.Loop, _: *xev.Completion, _: xev.File, r: xev.PollError!xev.PollEvent) xev.CallbackAction {
        const self = ud.?;
        _ = r catch {
            self.polling = false;
            self.maybeFree();
            return .disarm;
        };
        if (self.closing) {
            self.polling = false;
            self.maybeFree();
            return .disarm;
        }
        const proxy = self.proxy;
        self.in_callback = true;
        var i: usize = 0;
        while (i < batch) : (i += 1) {
            const n = sys.recvfrom(self.fd, &proxy.buf, 0, null, null) catch |err| switch (err) {
                error.WouldBlock => break,
                // ICMP port unreachable: the backend is gone.
                error.ConnectionRefused => {
                    self.peer.recordFailure();
                    self.close();
                    break;
                },
                else => continue,
            };
            _ = sys.sendto(proxy.fd, proxy.buf[0..n], 0, @ptrCast(&self.client), self.client_len) catch {};
        }
        self.in_callback = false;
        if (self.closing) {
            self.polling = false;
            self.maybeFree();
            return .disarm;
        }
        proxy.worker.timers.set(&self.idle, proxy.cfg.idle_timeout_ms);
        return .rearm;
    }

    fn onIdle(d: *timers.Deadline) void {
        const self: *Flow = @fieldParentPtr("idle", d);
        self.close();
    }

    fn close(self: *Flow) void {
        if (self.closing) return;
        self.closing = true;
        self.proxy.removeFlow(self);
        self.proxy.worker.timers.clear(&self.idle);
        self.peer.active -= 1;
        // Inside our own poll callback, disarming there is enough.
        if (self.polling and !self.in_callback) {
            self.cancelling = true;
            self.cancel_c = .{
                .op = .{ .cancel = .{ .c = &self.poll_c } },
                .userdata = self,
                .callback = onCancelled,
            };
            self.proxy.worker.loop.add(&self.cancel_c);
        } else {
            self.maybeFree();
        }
    }

    fn onCancelled(ud: ?*anyopaque, _: *xev.Loop, _: *xev.Completion, _: xev.Result) xev.CallbackAction {
        const self: *Flow = @ptrCast(@alignCast(ud.?));
        self.cancelling = false;
        // The poll completion reports Canceled separately, possibly later.
        self.maybeFree();
        return .disarm;
    }

    fn maybeFree(self: *Flow) void {
        if (!self.closing or self.polling or self.cancelling) return;
        // Deferred: this can run inside the poll callback, and epoll
        // deregisters the fd after that callback returns.
        self.proxy.worker.timers.defer_(&self.free_cb);
    }

    fn onFree(d: *timers.Deferred) void {
        const self: *Flow = @fieldParentPtr("free_cb", d);
        sys.close(self.fd);
        self.proxy.worker.alloc.destroy(self);
    }
};

test "route short and long headers by QUIC-LB server id" {
    inline for (.{ null, [_]u8{0x42} ** 16 }) |key| {
        var ids = [_][15]u8{ std.mem.zeroes([15]u8), std.mem.zeroes([15]u8) };
        ids[0][0..2].* = .{ 0x00, 0x01 };
        ids[1][0..2].* = .{ 0x00, 0x02 };
        var lb: quic_lb.Config = .{ .config_id = 0, .server_id_len = 2, .nonce_len = 6, .key = key };
        lb.server_id[0..2].* = .{ 0x00, 0x02 };
        var cid: [20]u8 = undefined;
        quic_lb.generateCid(&lb, &cid);
        const cid_len = quic_lb.cidLength(&lb);

        // Short header: flags, DCID, then protected payload.
        var short: [64]u8 = undefined;
        short[0] = 0x40;
        @memcpy(short[1 .. 1 + cid_len], cid[0..cid_len]);
        try std.testing.expectEqual(@as(?usize, 1), peerIndexForPacket(&lb, &ids, short[0 .. 1 + cid_len + 20]));

        // Long header: flags, version, DCID length, DCID.
        var long: [64]u8 = undefined;
        long[0] = 0xc0;
        long[1..5].* = .{ 0, 0, 0, 1 };
        long[5] = cid_len;
        @memcpy(long[6 .. 6 + cid_len], cid[0..cid_len]);
        try std.testing.expectEqual(@as(?usize, 1), peerIndexForPacket(&lb, &ids, long[0 .. 6 + cid_len + 10]));

        // A client-chosen Initial DCID names no server (almost surely).
        long[6..14].* = .{ 0xe0, 1, 2, 3, 4, 5, 6, 7 };
        long[5] = 8;
        try std.testing.expectEqual(@as(?usize, null), peerIndexForPacket(&lb, &ids, long[0..24]));
    }
}

test "addr key distinguishes ports" {
    var a = std.mem.zeroes(posix.sockaddr.storage);
    var b = std.mem.zeroes(posix.sockaddr.storage);
    const ina: *posix.sockaddr.in = @ptrCast(@alignCast(&a));
    const inb: *posix.sockaddr.in = @ptrCast(@alignCast(&b));
    ina.* = .{ .port = 1, .addr = 0x0100007f };
    inb.* = .{ .port = 2, .addr = 0x0100007f };
    try std.testing.expect(!std.mem.eql(u8, &addrKey(&a), &addrKey(&b)));
}

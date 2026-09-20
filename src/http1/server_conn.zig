//! One client connection speaking HTTP/1.x, optionally over TLS.
//!
//! Requests are handled one at a time; pipelined requests wait in the input
//! buffer until the current response finishes.
const std = @import("std");
const common = @import("../http/common.zig");
const parser = @import("parser.zig");
const socket = @import("../net/socket.zig");
const timers = @import("../timers.zig");
const exchange = @import("../exchange.zig");
const router = @import("../router.zig");
const tls_transport = @import("../net/tls.zig");
const proxy_protocol = @import("../net/proxy_protocol.zig");
const stats = @import("../stats.zig");
const build_options = @import("build_options");
const worker_mod = @import("../worker.zig");
const Worker = worker_mod.Worker;
const Listener = worker_mod.Listener;
const Exchange = exchange.Exchange;
const Header = common.Header;

const log = std.log.scoped(.http1);

/// Stop reading from a client whose unprocessed input exceeds this.
const max_buffered_input = 64 * 1024;
const linger_ms = 5_000;

pub const Conn = struct {
    worker: *Worker,
    listener: *Listener,
    sock: socket.Socket(Conn, false),
    tls: ?*tls_transport.Transport = null,

    /// Plaintext received and not yet consumed.
    in: std.ArrayListUnmanaged(u8) = .empty,
    /// Scratch for serializing response heads.
    out: std.ArrayListUnmanaged(u8) = .empty,
    phase: Phase = .head,
    ex: ?*Exchange = null,
    body: parser.BodyDecoder = parser.BodyDecoder.init(.none),
    body_paused: bool = false,
    /// The request ended while its body was paused; the exchange hears of
    /// it on resume, as it would of the body.
    end_pending: bool = false,
    body_received: u64 = 0,
    req_version: parser.Version = .http11,
    req_is_head: bool = false,
    keep_alive: bool = true,
    resp: Resp = .{},
    requests: u32 = 0,

    deadline: timers.Deadline = .{ .callback = onDeadline },
    process_cb: timers.Deferred = .{ .callback = onDeferredProcess },
    processing: bool = false,
    again: bool = false,

    /// The client: the TCP peer, or the one a PROXY protocol header names.
    addr_buf: [64]u8 = undefined,
    addr_len: usize = 0,
    client_ip: [16]u8 = @splat(0),
    /// The TCP peer, once a PROXY protocol header named another client.
    peer_buf: [64]u8 = undefined,
    peer_len: usize = 0,
    /// Waiting for the PROXY protocol header, ahead of anything else.
    proxy_pending: bool = false,

    /// `sock.queued_total` when the current request began.
    resp_start: u64 = 0,
    /// Finished exchanges whose responses are still queued, oldest first.
    flush_head: ?*Exchange = null,
    flush_tail: ?*Exchange = null,

    /// The worker's connection bookkeeping: list links and the per-IP count.
    client: worker_mod.Client = .{ .kind = .http },

    const Phase = enum {
        /// Waiting for (the rest of) a request head.
        head,
        /// Streaming the request body to the exchange.
        body,
        /// Request fully read; the response is in progress.
        wait,
        /// Raw bytes both ways after 101.
        tunnel,
        closing,
    };

    const Resp = struct {
        framing: enum { none, length, chunked, close, tunnel } = .none,
        remaining: u64 = 0,
        started: bool = false,
    };

    pub fn fromClient(c: *worker_mod.Client) *Conn {
        return @alignCast(@fieldParentPtr("client", c));
    }

    pub fn create(worker: *Worker, listener: *Listener, tcp: anytype) !*Conn {
        const self = try worker.alloc.create(Conn);
        self.* = .{ .worker = worker, .listener = listener, .sock = undefined, .proxy_pending = listener.proxy_protocol };
        self.sock.init(self, &worker.loop, &worker.timers, worker.alloc, tcp);
        var peer: std.posix.sockaddr.storage = undefined;
        var peer_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        const a = if (std.c.getpeername(self.sock.fd(), @ptrCast(&peer), &peer_len) == 0) blk: {
            self.client_ip = socket.ipKey(&peer) orelse self.client_ip;
            break :blk socket.formatSockaddr(&peer, &self.addr_buf);
        } else "-";
        self.addr_len = a.len;
        if (@intFromPtr(a.ptr) != @intFromPtr(&self.addr_buf)) @memcpy(self.addr_buf[0..a.len], a);
        if (listener.tls_config) |tc| {
            self.tls = tls_transport.Transport.create(worker.alloc, tc) catch |err| {
                worker.alloc.destroy(self);
                return err;
            };
        }
        worker.addClient(&self.client);
        worker.timers.set(&self.deadline, worker.cfg.limits.header_timeout_ms);
        self.sock.startReading();
        return self;
    }

    fn clientAddr(self: *const Conn) []const u8 {
        return self.addr_buf[0..self.addr_len];
    }

    fn peerAddr(self: *const Conn) []const u8 {
        return if (self.peer_len == 0) self.clientAddr() else self.peer_buf[0..self.peer_len];
    }

    fn limits(self: *const Conn) @TypeOf(self.worker.cfg.limits) {
        return self.worker.cfg.limits;
    }

    // ---- transport ----

    pub fn onSocketData(self: *Conn, data: []const u8) void {
        if (self.proxy_pending) return self.readProxyHeader(data);
        if (self.tls) |t| {
            t.feed(data) catch |err| {
                log.debug("tls from {s}: {s}", .{ self.clientAddr(), @errorName(err) });
                self.flushTls();
                return self.closeGracefully();
            };
            self.flushTls();
            while (true) {
                self.in.ensureUnusedCapacity(self.worker.alloc, 16 * 1024) catch return self.fatal();
                const n = t.read(self.in.unusedCapacitySlice());
                if (n == 0) break;
                self.in.items.len += n;
            }
            if (t.peerClosed()) {
                self.process();
                return self.onPeerFinished();
            }
        } else {
            self.in.appendSlice(self.worker.alloc, data) catch return self.fatal();
        }
        if (self.phase == .body or self.phase == .tunnel) self.worker.timers.set(&self.deadline, self.limits().io_timeout_ms);
        self.process();
    }

    /// Buffer the PROXY protocol header and take the client from it; the
    /// connection's own bytes (TLS or HTTP) follow.
    fn readProxyHeader(self: *Conn, data: []const u8) void {
        self.in.appendSlice(self.worker.alloc, data) catch return self.fatal();
        const h = proxy_protocol.parse(self.in.items) catch {
            log.debug("bad PROXY protocol header from {s}", .{self.clientAddr()});
            stats.inc(&stats.refused_proxy_protocol);
            return self.clientGone();
        } orelse return;
        self.proxy_pending = false;
        if (h.source) |src| {
            @memcpy(self.peer_buf[0..self.addr_len], self.clientAddr());
            self.peer_len = self.addr_len;
            self.client_ip = src.ip;
            self.addr_len = socket.formatIpKey(src.ip, &self.addr_buf).len;
        }
        switch (self.worker.admitIp(self.client_ip)) {
            .counted => self.client.ip_key = self.client_ip,
            .untracked => {},
            .refused => {
                stats.inc(&stats.refused_per_ip);
                return self.clientGone();
            },
        }
        var raw = self.in;
        self.in = .empty;
        defer raw.deinit(self.worker.alloc);
        if (raw.items.len > h.len) self.onSocketData(raw.items[h.len..]);
    }

    /// Send plaintext to the client.
    fn output(self: *Conn, bytes: []const u8) void {
        if (bytes.len == 0) return;
        if (self.tls) |t| {
            t.write(bytes) catch {
                // Not connected (handshake unfinished or already closed).
                return self.failDeferred();
            };
            self.flushTls();
        } else {
            self.sock.write(bytes);
        }
    }

    fn flushTls(self: *Conn) void {
        const t = self.tls orelse return;
        const pending = t.pendingOutput();
        if (pending.len == 0) return;
        self.sock.write(pending);
        t.consumeOutput(pending.len);
    }

    pub fn onSocketEof(self: *Conn) void {
        self.onPeerFinished();
    }

    fn onPeerFinished(self: *Conn) void {
        switch (self.phase) {
            .tunnel => if (self.ex) |ex| ex.onRequestEnd() else self.sock.abort(),
            .closing => self.sock.abort(),
            .head => if (self.in.items.len == 0) self.sock.abort() else self.clientGone(),
            .body, .wait => self.clientGone(),
        }
    }

    pub fn onSocketWritable(self: *Conn) void {
        if (self.phase == .wait) self.worker.timers.set(&self.deadline, self.limits().io_timeout_ms);
        if (self.ex) |ex| ex.onDownstreamWritable();
    }

    pub fn onSocketSent(self: *Conn) void {
        while (self.flush_head) |ex| {
            if (ex.flush_mark > self.sock.sent_total) break;
            self.popFlushed().onFlushed(0);
        }
        // Closing after a flush: a client still taking the output isn't idle.
        if (self.phase == .closing) self.armClosingDeadline();
    }

    fn popFlushed(self: *Conn) *Exchange {
        const ex = self.flush_head.?;
        self.flush_head = ex.flush_next;
        if (self.flush_head == null) self.flush_tail = null;
        ex.flush_next = null;
        return ex;
    }

    /// The connection is closing: whatever is still queued is lost.
    pub fn abandonFlushes(self: *Conn) void {
        while (self.flush_head != null) {
            const ex = self.popFlushed();
            ex.onFlushed(ex.flush_mark - @max(self.sock.sent_total, ex.flush_start));
        }
    }

    /// Bytes queued for the current request and not yet sent.
    fn unsent(self: *const Conn) u64 {
        const q = self.sock.queued_total;
        return q - @max(self.sock.sent_total, self.resp_start);
    }

    /// Hand the exchange its client's departure.
    fn detachGone(self: *Conn) void {
        const ex = self.ex orelse return;
        self.ex = null;
        ex.unsent = self.unsent();
        ex.onDownstreamGone();
    }

    pub fn onSocketConnect(_: *Conn, _: ?anyerror) void {}

    pub fn onSocketClosed(self: *Conn) void {
        // A queued process callback still points at us; free after it runs.
        if (self.process_cb.queued) return self.worker.timers.defer_(&self.sock.closed_cb);
        self.abandonFlushes();
        self.detachGone();
        const w = self.worker;
        w.timers.clear(&self.deadline);
        if (self.tls) |t| t.destroy();
        self.in.deinit(w.alloc);
        self.out.deinit(w.alloc);
        w.removeClient(&self.client);
        w.alloc.destroy(self);
    }

    /// The client vanished mid-request.
    fn clientGone(self: *Conn) void {
        self.phase = .closing;
        self.abandonFlushes();
        self.detachGone();
        self.sock.abort();
    }

    fn fatal(self: *Conn) void {
        self.clientGone();
    }

    /// Like `fatal`, but safe inside an exchange call (`output`, the
    /// Downstream vtable): the exchange hears about it from the deferred
    /// `onSocketClosed`, not while its own frame is still on the stack.
    fn failDeferred(self: *Conn) void {
        self.phase = .closing;
        self.sock.abort();
    }

    fn closeGracefully(self: *Conn) void {
        if (self.phase == .closing) return;
        self.phase = .closing;
        if (self.tls) |t| {
            t.close();
            self.flushTls();
        }
        self.sock.closeAfterFlush();
        self.armClosingDeadline();
    }

    /// While output is flushing, the I/O timeout since the last progress;
    /// after it, a short linger for the client's FIN.
    fn armClosingDeadline(self: *Conn) void {
        self.worker.timers.set(&self.deadline, if (self.sock.state == .flushing) self.limits().io_timeout_ms else linger_ms);
    }

    // ---- request processing ----

    fn scheduleProcess(self: *Conn) void {
        if (self.processing) {
            self.again = true;
            return;
        }
        // Deferred: this is reached from exchange callbacks, which must not
        // be re-entered from here.
        self.worker.timers.defer_(&self.process_cb);
    }

    fn onDeferredProcess(d: *timers.Deferred) void {
        const self: *Conn = @fieldParentPtr("process_cb", d);
        if (self.phase == .closing) return;
        self.process();
    }

    fn process(self: *Conn) void {
        if (self.processing) {
            self.again = true;
            return;
        }
        self.processing = true;
        // Responses produced in this pass leave in one send.
        self.sock.cork();
        defer self.sock.uncork();
        while (true) {
            self.again = false;
            const progressed = self.step();
            if (!progressed and !self.again) break;
        }
        self.processing = false;
        if (self.phase == .closing) return;
        if (self.in.items.len > max_buffered_input and (self.phase == .wait or self.body_paused)) {
            self.sock.pauseRead();
        } else if (!self.body_paused) {
            self.sock.resumeRead();
        }
    }

    /// One unit of work; false when waiting on input or on the response.
    fn step(self: *Conn) bool {
        switch (self.phase) {
            .head => return self.parseHead(),
            .body => return self.feedBody(),
            .tunnel => {
                if (self.in.items.len == 0 or self.body_paused) return false;
                const ex = self.ex orelse {
                    self.in.clearRetainingCapacity();
                    return false;
                };
                // The exchange copies what it needs; `in` is ours again after.
                ex.onRequestBody(self.in.items);
                self.in.clearRetainingCapacity();
                return false;
            },
            .wait => {
                if (!self.end_pending or self.body_paused) return false;
                self.end_pending = false;
                if (self.ex) |ex| ex.onRequestEnd();
                return true;
            },
            .closing => return false,
        }
    }

    fn parseHead(self: *Conn) bool {
        if (self.in.items.len == 0) return false;
        var hbuf: [256]Header = undefined;
        const lim: parser.Limits = .{ .max_head = self.limits().max_header_bytes, .max_headers = @min(self.limits().max_headers, hbuf.len) };
        const parsed = parser.parseRequest(self.in.items, &hbuf, lim) catch |err| {
            self.rejectRequest(switch (err) {
                error.HeadTooLarge, error.TooManyHeaders => 431,
                error.VersionNotSupported => 505,
                error.NotImplemented => 501,
                error.BadRequest => 400,
            });
            return false;
        } orelse return false;
        const head = parsed.head;

        self.requests += 1;
        self.resp_start = self.sock.queued_total;
        // Test hook: a small send buffer keeps output queued on our side.
        if (build_options.fault_injection and std.mem.indexOf(u8, head.target, "small-sndbuf") != null) {
            socket.setSendBuffer(self.sock.fd(), 16 * 1024);
        }
        self.req_version = head.version;
        self.req_is_head = std.mem.eql(u8, head.method, "HEAD");
        self.keep_alive = head.keep_alive and !self.worker.stopping;
        self.resp = .{};
        self.body_received = 0;
        self.body_paused = false;
        self.end_pending = false;
        self.body = parser.BodyDecoder.init(parser.requestBodyKind(&head));

        if (std.mem.eql(u8, head.method, "CONNECT")) {
            self.rejectRequest(405);
            return false;
        }

        // Host goes separately as the authority.
        var fwd: [256]Header = undefined;
        var n: usize = 0;
        for (head.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "host")) continue;
            fwd[n] = h;
            n += 1;
        }
        const body_mode: exchange.BodyMode = if (head.chunked) .streamed else if ((head.content_length orelse 0) > 0) .sized else .none;

        const ex = Exchange.create(self.worker, self.downstream(), .{
            .method = head.method,
            .target = head.target,
            .authority = head.host,
            .headers = fwd[0..n],
            .content_length = if (body_mode == .sized) head.content_length else null,
            .body = body_mode,
            .upgrade = head.upgrade,
            .protocol = if (head.version == .http10) .http10 else .http11,
            .scheme = if (self.tls != null) "https" else "http",
            .client_addr = self.clientAddr(),
            .client_ip = self.client_ip,
            .peer_addr = self.peerAddr(),
            .vhosts = &self.listener.vhosts,
            .client_cert = if (self.tls) |t| t.clientCert() else .{},
        }) catch {
            self.rejectRequest(500);
            return false;
        };
        const expect_continue = head.expect_continue and self.body.kind != .none and head.version == .http11;
        // Parsed slices point into `in`; drop the head only after copying.
        self.consumeIn(parsed.len);

        self.ex = ex;
        self.phase = if (self.body.done) .wait else .body;
        self.worker.timers.set(&self.deadline, self.limits().io_timeout_ms);
        if (expect_continue) self.output("HTTP/1.1 100 Continue\r\n\r\n");
        ex.start();
        if (self.phase == .wait) {
            if (self.body_paused) {
                self.end_pending = true;
            } else if (self.ex) |e| e.onRequestEnd();
        }
        return true;
    }

    fn feedBody(self: *Conn) bool {
        if (self.body_paused) return false;
        if (self.in.items.len == 0) return false;
        var consumed: usize = 0;
        defer self.consumeIn(consumed);
        while (consumed < self.in.items.len and !self.body.done) {
            const s = self.body.decode(self.in.items[consumed..]) catch {
                consumed = self.in.items.len;
                self.requestBodyFailed(400);
                return false;
            };
            consumed += s.consumed;
            if (s.data.len > 0) {
                self.body_received += s.data.len;
                const max = self.limits().max_body_bytes;
                if (max != 0 and self.body_received > max) {
                    consumed = self.in.items.len;
                    self.requestBodyFailed(413);
                    return false;
                }
                if (self.ex) |ex| ex.onRequestBody(s.data);
                if (self.phase != .body) return true;
                if (self.body_paused) break;
            }
            if (s.consumed == 0) break;
        }
        if (self.body.done) {
            self.phase = .wait;
            if (self.ex) |ex| ex.onRequestEnd();
            return true;
        }
        return false;
    }

    fn consumeIn(self: *Conn, n: usize) void {
        if (n == 0) return;
        const rest = self.in.items.len - n;
        std.mem.copyForwards(u8, self.in.items[0..rest], self.in.items[n..]);
        self.in.items.len = rest;
        // Give back memory from a burst (large pipelined input); keeps len.
        if (self.in.capacity > 256 * 1024 and rest < 4096) self.in.shrinkAndFree(self.worker.alloc, rest);
    }

    /// Bad or oversized request body: answer if we still can, then close.
    fn requestBodyFailed(self: *Conn, status: u16) void {
        self.keep_alive = false;
        if (self.ex) |ex| {
            if (!ex.head_sent) {
                ex.sendError(status);
                return;
            }
            self.detachGone();
        }
        self.sock.abort();
        self.phase = .closing;
    }

    /// Answer a request we won't hand to an exchange, and close.
    fn rejectRequest(self: *Conn, status: u16) void {
        self.keep_alive = false;
        var buf: [256]u8 = undefined;
        const body = std.fmt.bufPrint(&buf, "{d} {s}\n", .{ status, common.reason(status) }) catch unreachable;
        var head_buf: [512]u8 = undefined;
        const date = self.worker.dateHeader();
        const head = std.fmt.bufPrint(&head_buf, "HTTP/1.1 {d} {s}\r\nServer: routez\r\nDate: {s}\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ status, common.reason(status), date, body.len }) catch unreachable;
        self.output(head);
        self.output(body);
        self.closeGracefully();
    }

    /// The response is done; get ready for the next request or close.
    fn nextRequest(self: *Conn) void {
        if (!self.keep_alive or self.phase == .body) {
            self.closeGracefully();
            return;
        }
        self.phase = .head;
        self.worker.timers.set(&self.deadline, if (self.in.items.len == 0) self.limits().keepalive_timeout_ms else self.limits().header_timeout_ms);
        self.scheduleProcess();
    }

    fn onDeadline(d: *timers.Deadline) void {
        const self: *Conn = @fieldParentPtr("deadline", d);
        switch (self.phase) {
            .head => {
                if (self.proxy_pending) stats.inc(&stats.refused_proxy_protocol);
                self.sock.abort();
            },
            .closing => self.sock.abort(),
            .body => self.clientGone(),
            .wait => {
                // Waiting on the upstream is not the client's fault.
                if (self.sock.buffered() == 0) {
                    self.worker.timers.set(&self.deadline, self.limits().io_timeout_ms);
                } else {
                    self.clientGone();
                }
            },
            .tunnel => {},
        }
    }

    /// Close an idle keep-alive connection during shutdown. One that hasn't
    /// had a request yet is kept unless `fresh_too`: it may be mid-TLS-
    /// handshake, or its request still in the socket buffer. A finished
    /// response may still be queued (or a file range being sent): that is
    /// flushed first.
    pub fn closeIfIdle(self: *Conn, fresh_too: bool) void {
        self.keep_alive = false;
        if (self.phase != .head or self.in.items.len > 0 or (self.requests == 0 and !fresh_too)) return;
        // A request already in the receive queue makes an idle-looking
        // connection busy. It is read on the next turn of the loop and answered
        // with `Connection: close`, since keep_alive is off from here on; the
        // drain timeout is the backstop if the client sent a partial head and
        // stopped.
        if (self.sock.hasUnread()) return;
        if (self.tls) |t| {
            t.close();
            self.flushTls();
        }
        if (self.sock.buffered() == 0) return self.sock.abort();
        self.closeGracefully();
    }

    // ---- Downstream interface ----

    fn downstream(self: *Conn) exchange.Downstream {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: exchange.Downstream.VTable = .{
        .sendHead = dsSendHead,
        .sendBody = dsSendBody,
        .finish = dsFinish,
        .finishTracked = dsFinishTracked,
        .unsent = dsUnsent,
        .abort = dsAbort,
        .buffered = dsBuffered,
        .setRequestBodyPaused = dsSetPaused,
        .startTunnel = dsStartTunnel,
        .canSendFile = dsCanSendFile,
        .sendFile = dsSendFile,
        .cork = dsCork,
    };

    fn dsCork(ptr: *anyopaque, on: bool) void {
        const self = cast(ptr);
        if (on) self.sock.cork() else self.sock.uncork();
    }

    fn cast(ptr: *anyopaque) *Conn {
        return @ptrCast(@alignCast(ptr));
    }

    fn dsSendHead(ptr: *anyopaque, r: *const exchange.Response) void {
        const self = cast(ptr);
        const interim = r.status < 200 and r.status != 101;
        if (interim and self.req_version == .http10) return;

        if (!interim) {
            self.resp.started = true;
            if (r.status == 101) {
                self.resp.framing = .tunnel;
            } else if (self.req_is_head or common.statusHasNoBody(r.status)) {
                self.resp.framing = .none;
            } else if (r.content_length) |n| {
                self.resp.framing = .length;
                self.resp.remaining = n;
            } else if (self.req_version == .http11) {
                self.resp.framing = .chunked;
            } else {
                self.resp.framing = .close;
                self.keep_alive = false;
            }
            if (self.worker.stopping) self.keep_alive = false;
        }

        self.out.clearRetainingCapacity();
        self.writeHead(r, interim) catch {
            self.out.clearRetainingCapacity();
            return self.failDeferred();
        };
        self.output(self.out.items);
    }

    fn writeHead(self: *Conn, r: *const exchange.Response, interim: bool) !void {
        const a = self.worker.alloc;
        const o = &self.out;
        try o.print(a, "HTTP/1.1 {d} {s}\r\n", .{ r.status, common.reason(r.status) });
        if (!interim) try o.print(a, "Server: routez\r\nDate: {s}\r\n", .{self.worker.dateHeader()});
        for (r.headers) |h| try o.print(a, "{s}: {s}\r\n", .{ h.name, h.value });
        if (interim) {
            try o.appendSlice(a, "\r\n");
            return;
        }
        switch (self.resp.framing) {
            .length => try o.print(a, "Content-Length: {d}\r\n", .{self.resp.remaining}),
            .chunked => try o.appendSlice(a, "Transfer-Encoding: chunked\r\n"),
            .none => if (self.req_is_head) {
                if (r.content_length) |n| try o.print(a, "Content-Length: {d}\r\n", .{n});
            },
            .close, .tunnel => {},
        }
        if (self.listener.alt_svc) |v| try o.print(a, "Alt-Svc: {s}\r\n", .{v});
        if (self.resp.framing != .tunnel) {
            if (!self.keep_alive) {
                try o.appendSlice(a, "Connection: close\r\n");
            } else if (self.req_version == .http10) {
                try o.appendSlice(a, "Connection: keep-alive\r\n");
            }
        }
        try o.appendSlice(a, "\r\n");
    }

    fn dsSendBody(ptr: *anyopaque, data: []const u8) void {
        const self = cast(ptr);
        if (data.len == 0) return;
        switch (self.resp.framing) {
            .none => {},
            .length => {
                const n: usize = @intCast(@min(self.resp.remaining, data.len));
                self.resp.remaining -= n;
                self.output(data[0..n]);
            },
            .chunked => {
                var buf: [20]u8 = undefined;
                self.output(std.fmt.bufPrint(&buf, "{x}\r\n", .{data.len}) catch unreachable);
                self.output(data);
                self.output("\r\n");
            },
            .close, .tunnel => self.output(data),
        }
    }

    fn dsCanSendFile(ptr: *anyopaque) bool {
        const self = cast(ptr);
        return self.tls == null and self.resp.framing == .length;
    }

    fn dsSendFile(ptr: *anyopaque, f: socket.FileOut) exchange.FileSend {
        const self = cast(ptr);
        if (self.tls != null or self.resp.framing != .length or f.len > self.resp.remaining) {
            f.release(f.hold);
            return .unsupported;
        }
        if (!self.sock.sendFile(f)) return .busy;
        self.resp.remaining -= f.len;
        return .sent;
    }

    fn dsFinish(ptr: *anyopaque) void {
        const self = cast(ptr);
        self.ex = null;
        switch (self.resp.framing) {
            .chunked => self.output("0\r\n\r\n"),
            .length => if (self.resp.remaining > 0) {
                // Promised more than was produced; only closing tells the client.
                self.phase = .closing;
                return self.sock.abort();
            },
            .close, .tunnel => self.keep_alive = false,
            .none => {},
        }
        if (self.phase == .tunnel) self.keep_alive = false;
        if (self.phase == .body) {
            // Unread body left: we'd have to drain it to find the next request.
            self.keep_alive = false;
        }
        self.nextRequest();
    }

    fn dsFinishTracked(ptr: *anyopaque, ex: *Exchange) bool {
        const self = cast(ptr);
        dsFinish(ptr);
        const lost = self.sock.state == .closing or self.sock.state == .closed;
        if (lost or self.sock.sent_total >= self.sock.queued_total) {
            // A short body aborts the connection: not a complete response.
            if (lost) {
                ex.failed = true;
                ex.unsent = self.unsent();
            }
            return false;
        }
        ex.flush_start = self.resp_start;
        ex.flush_mark = self.sock.queued_total;
        if (self.flush_tail) |t| t.flush_next = ex else self.flush_head = ex;
        self.flush_tail = ex;
        return true;
    }

    fn dsUnsent(ptr: *anyopaque) u64 {
        return cast(ptr).unsent();
    }

    fn dsAbort(ptr: *anyopaque) void {
        const self = cast(ptr);
        self.ex = null;
        self.phase = .closing;
        self.sock.abort();
    }

    fn dsBuffered(ptr: *anyopaque) usize {
        const self = cast(ptr);
        return self.sock.buffered();
    }

    fn dsSetPaused(ptr: *anyopaque, paused: bool) void {
        const self = cast(ptr);
        if (self.body_paused == paused) return;
        self.body_paused = paused;
        // Stop reading at once: in a tunnel `in` is drained every pass, so
        // waiting for it to fill would never hold the client back.
        if (paused) self.sock.pauseRead() else self.scheduleProcess();
    }

    fn dsStartTunnel(ptr: *anyopaque) void {
        const self = cast(ptr);
        // The request is over; a tunnel only ever holds one frame at a time.
        self.in.clearAndFree(self.worker.alloc);
        self.out.clearAndFree(self.worker.alloc);
        self.phase = .tunnel;
        self.keep_alive = false;
        self.body_paused = false;
        self.worker.timers.clear(&self.deadline);
        self.scheduleProcess();
    }
};

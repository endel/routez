//! A blocking ACME client (RFC 8555) for HTTP-01 issuance, on std.http.Client.
//! Meant for a background thread: every call waits on the network.
const std = @import("std");
const jws = @import("jws.zig");
const x509 = @import("x509.zig");

const log = std.log.scoped(.acme);

/// Where HTTP-01 key authorizations are published while an order is pending.
pub const ChallengeSink = struct {
    ptr: *anyopaque,
    put: *const fn (*anyopaque, token: []const u8, key_authorization: []const u8) error{OutOfMemory}!void,
    remove: *const fn (*anyopaque, token: []const u8) void,
};

const Directory = struct {
    newNonce: []const u8,
    newAccount: []const u8,
    newOrder: []const u8,
};

const Problem = struct {
    type: []const u8 = "",
    detail: []const u8 = "",
};

const Identifier = struct { type: []const u8, value: []const u8 };

const Order = struct {
    status: []const u8,
    authorizations: []const []const u8 = &.{},
    finalize: []const u8,
    certificate: ?[]const u8 = null,
    @"error": ?Problem = null,
};

const Authorization = struct {
    status: []const u8,
    identifier: Identifier,
    challenges: []const Challenge = &.{},
};

const Challenge = struct {
    type: []const u8,
    url: []const u8,
    status: []const u8 = "",
    token: []const u8 = "",
    @"error": ?Problem = null,
};

const json_options: std.json.ParseOptions = .{ .ignore_unknown_fields = true, .allocate = .alloc_always };

pub const Response = struct {
    status: std.http.Status,
    body: []u8,
    location: ?[]u8,
    retry_after_s: ?u32,
};

/// Longest a CA's Retry-After is followed while polling.
const max_poll_pause_s = 60;

pub const Client = struct {
    /// Everything that outlives one request (directory, account URL, nonce).
    arena_state: std.heap.ArenaAllocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    http: std.http.Client,
    directory_url: []const u8,
    directory: ?Directory = null,
    account_key: x509.KeyPair,
    kid: ?[]const u8 = null,
    nonce: ?[]u8 = null,
    /// Upper bound on status polling, in seconds.
    poll_limit_s: u32 = 120,
    /// Set when the CA refused with a rate limit or Retry-After: how long
    /// to leave it alone, in seconds.
    retry_after_s: ?u32 = null,

    /// `ca_file` replaces the system roots for the directory's HTTPS.
    pub fn init(gpa: std.mem.Allocator, io: std.Io, directory_url: []const u8, ca_file: ?[]const u8, account_key: x509.KeyPair) !Client {
        var self: Client = .{
            .arena_state = .init(gpa),
            .gpa = gpa,
            .io = io,
            .http = .{ .allocator = gpa, .io = io },
            .directory_url = directory_url,
            .account_key = account_key,
        };
        errdefer self.deinit();
        if (ca_file) |path| {
            // Setting `now` stops the client from rescanning the system store.
            const now = std.Io.Clock.real.now(io);
            self.http.ca_bundle.addCertsFromFilePath(gpa, io, now, .cwd(), path) catch |err| {
                log.err("acme ca_file {s}: {s}", .{ path, @errorName(err) });
                return err;
            };
            self.http.now = now;
        }
        return self;
    }

    pub fn deinit(self: *Client) void {
        if (self.nonce) |n| self.gpa.free(n);
        self.http.deinit();
        self.arena_state.deinit();
    }

    fn fetchDirectory(self: *Client) !Directory {
        if (self.directory) |d| return d;
        const resp = try self.send(.GET, self.directory_url, null, null);
        defer self.freeResponse(resp);
        if (resp.status != .ok) {
            log.err("directory {s}: HTTP {d}", .{ self.directory_url, @intFromEnum(resp.status) });
            return error.AcmeDirectory;
        }
        const d = try std.json.parseFromSliceLeaky(Directory, self.arena_state.allocator(), resp.body, json_options);
        self.directory = d;
        return d;
    }

    fn freeResponse(self: *Client, resp: Response) void {
        self.gpa.free(resp.body);
        if (resp.location) |l| self.gpa.free(l);
    }

    /// One HTTP exchange. Keeps the Replay-Nonce the server hands out.
    fn send(self: *Client, method: std.http.Method, url: []const u8, body: ?[]const u8, accept: ?[]const u8) !Response {
        const uri = try std.Uri.parse(url);
        var extra: [1]std.http.Header = undefined;
        var n_extra: usize = 0;
        if (accept) |a| {
            extra[0] = .{ .name = "accept", .value = a };
            n_extra = 1;
        }
        var req = try self.http.request(method, uri, .{
            .redirect_behavior = .unhandled,
            .headers = .{
                .content_type = if (body != null) .{ .override = "application/jose+json" } else .default,
                .accept_encoding = .omit,
                .user_agent = .{ .override = "routez-acme" },
            },
            .extra_headers = extra[0..n_extra],
        });
        defer req.deinit();
        if (body) |b| {
            try req.sendBodyComplete(@constCast(b));
        } else {
            try req.sendBodiless();
        }
        var response = try req.receiveHead(&.{});

        // Header strings die once the body reader starts.
        var location: ?[]u8 = null;
        errdefer if (location) |l| self.gpa.free(l);
        var retry_after: ?u32 = null;
        var it = response.head.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "replay-nonce")) {
                const fresh = try self.gpa.dupe(u8, h.value);
                if (self.nonce) |old| self.gpa.free(old);
                self.nonce = fresh;
            } else if (std.ascii.eqlIgnoreCase(h.name, "location")) {
                if (location == null) location = try self.gpa.dupe(u8, h.value);
            } else if (std.ascii.eqlIgnoreCase(h.name, "retry-after")) {
                // Delay-seconds only; an HTTP-date falls back to our own backoff.
                retry_after = std.fmt.parseInt(u32, std.mem.trim(u8, h.value, " \t"), 10) catch null;
            }
        }
        const status = response.head.status;
        const reader = response.reader(&.{});
        const resp_body = reader.allocRemaining(self.gpa, .limited(1024 * 1024)) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => |e| return e,
        };
        return .{ .status = status, .body = resp_body, .location = location, .retry_after_s = retry_after };
    }

    fn takeNonce(self: *Client) ![]u8 {
        if (self.nonce) |n| {
            self.nonce = null;
            return n;
        }
        const d = try self.fetchDirectory();
        const resp = try self.send(.HEAD, d.newNonce, null, null);
        self.freeResponse(resp);
        const n = self.nonce orelse return error.AcmeNoNonce;
        self.nonce = null;
        return n;
    }

    /// A signed POST (`payload` "" is POST-as-GET), retried when the server
    /// rejects the nonce. Non-2xx answers are logged and turned into errors.
    pub fn post(self: *Client, url: []const u8, payload: []const u8, accept: ?[]const u8) !Response {
        var attempts: usize = 0;
        while (true) : (attempts += 1) {
            const nonce = try self.takeNonce();
            defer self.gpa.free(nonce);
            const signer: jws.Signer = if (self.kid) |k| .{ .kid = k } else .jwk;
            const body = try jws.sign(self.gpa, self.account_key, signer, nonce, url, payload);
            defer self.gpa.free(body);
            const resp = try self.send(.POST, url, body, accept);
            const code = @intFromEnum(resp.status);
            if (code >= 200 and code < 300) return resp;
            defer self.freeResponse(resp);
            const problem = std.json.parseFromSlice(Problem, self.gpa, resp.body, json_options) catch null;
            defer if (problem) |p| p.deinit();
            const ptype = if (problem) |p| p.value.type else "";
            if (std.mem.eql(u8, ptype, "urn:ietf:params:acme:error:badNonce") and attempts < 5) continue;
            log.err("{s}: HTTP {d} {s} {s}", .{ url, code, ptype, if (problem) |p| p.value.detail else resp.body });
            if (std.mem.eql(u8, ptype, "urn:ietf:params:acme:error:rateLimited") or resp.retry_after_s != null) {
                self.retry_after_s = resp.retry_after_s orelse 3600;
                return error.AcmeRateLimited;
            }
            return error.AcmeRequestFailed;
        }
    }

    /// Create the account, or look up the existing one for this key.
    pub fn register(self: *Client, email: ?[]const u8) !void {
        if (self.kid != null) return;
        const d = try self.fetchDirectory();
        const payload = if (email) |e|
            try std.fmt.allocPrint(self.gpa, "{{\"termsOfServiceAgreed\":true,\"contact\":[{f}]}}", .{std.json.fmt(try std.fmt.allocPrint(self.arena_state.allocator(), "mailto:{s}", .{e}), .{})})
        else
            try self.gpa.dupe(u8, "{\"termsOfServiceAgreed\":true}");
        defer self.gpa.free(payload);
        const resp = try self.post(d.newAccount, payload, null);
        defer self.freeResponse(resp);
        const loc = resp.location orelse return error.AcmeNoAccountUrl;
        self.kid = try self.arena_state.allocator().dupe(u8, loc);
    }

    /// Run one order for `names` to completion and return the PEM chain.
    /// HTTP-01 responses are published through `sink` while they're needed.
    /// Once the order is finalized its URL is put in `finalized` (allocated
    /// with the client's allocator): if anything fails after that, `resume`
    /// picks the certificate up without ordering again. Needs `register` first.
    pub fn issue(self: *Client, names: []const []const u8, cert_key: x509.KeyPair, sink: ChallengeSink, finalized: *?[]u8) ![]u8 {
        if (self.kid == null) return error.AcmeNotRegistered;
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const d = try self.fetchDirectory();

        var payload: std.ArrayListUnmanaged(u8) = .empty;
        try payload.appendSlice(a, "{\"identifiers\":[");
        for (names, 0..) |n, i| {
            if (i > 0) try payload.append(a, ',');
            try payload.print(a, "{{\"type\":\"dns\",\"value\":{f}}}", .{std.json.fmt(n, .{})});
        }
        try payload.appendSlice(a, "]}");
        const created = try self.post(d.newOrder, payload.items, null);
        defer self.freeResponse(created);
        const order_url = try a.dupe(u8, created.location orelse return error.AcmeNoOrderUrl);
        var order = try std.json.parseFromSliceLeaky(Order, a, created.body, json_options);

        for (order.authorizations) |authz_url| try self.authorize(a, authz_url, sink);

        if (std.mem.eql(u8, order.status, "pending") or std.mem.eql(u8, order.status, "ready")) {
            order = try self.pollOrder(a, order_url, "ready");
        }
        if (std.mem.eql(u8, order.status, "ready")) {
            const csr = try x509.csr(a, cert_key, names);
            const csr_b64 = try jws.base64UrlAlloc(a, csr);
            const fin_payload = try std.fmt.allocPrint(a, "{{\"csr\":\"{s}\"}}", .{csr_b64});
            const fin = try self.post(order.finalize, fin_payload, null);
            defer self.freeResponse(fin);
            finalized.* = try self.gpa.dupe(u8, order_url);
        }
        return self.download(a, order_url);
    }

    /// The certificate of an order already finalized, waiting for it if the
    /// CA is still processing.
    pub fn resumeOrder(self: *Client, order_url: []const u8) ![]u8 {
        if (self.kid == null) return error.AcmeNotRegistered;
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        return self.download(arena_state.allocator(), order_url);
    }

    fn download(self: *Client, a: std.mem.Allocator, order_url: []const u8) ![]u8 {
        const order = try self.pollOrder(a, order_url, "valid");
        const cert_url = order.certificate orelse return error.AcmeNoCertificateUrl;
        const cert = try self.post(cert_url, "", "application/pem-certificate-chain");
        defer if (cert.location) |l| self.gpa.free(l);
        return cert.body;
    }

    fn authorize(self: *Client, a: std.mem.Allocator, authz_url: []const u8, sink: ChallengeSink) !void {
        var authz = (try self.getJson(Authorization, a, authz_url)).value;
        if (std.mem.eql(u8, authz.status, "valid")) return;
        if (!std.mem.eql(u8, authz.status, "pending")) {
            log.err("authorization for {s} is {s}", .{ authz.identifier.value, authz.status });
            return error.AcmeAuthorizationFailed;
        }
        const ch = for (authz.challenges) |c| {
            if (std.mem.eql(u8, c.type, "http-01")) break c;
        } else {
            log.err("{s}: the CA offers no http-01 challenge", .{authz.identifier.value});
            return error.AcmeNoHttp01;
        };
        const key_auth = try jws.keyAuthorization(a, ch.token, self.account_key.public_key);
        try sink.put(sink.ptr, ch.token, key_auth);
        defer sink.remove(sink.ptr, ch.token);

        // An empty object tells the CA we're ready for it to connect.
        const ready = try self.post(ch.url, "{}", null);
        self.freeResponse(ready);

        const deadline = self.nowSeconds() + self.poll_limit_s;
        while (true) {
            const polled = try self.getJson(Authorization, a, authz_url);
            authz = polled.value;
            if (std.mem.eql(u8, authz.status, "valid")) return;
            if (!std.mem.eql(u8, authz.status, "pending")) {
                for (authz.challenges) |c| if (c.@"error") |p| {
                    log.err("{s}: {s} challenge failed: {s} {s}", .{ authz.identifier.value, c.type, p.type, p.detail });
                };
                return error.AcmeAuthorizationFailed;
            }
            if (self.nowSeconds() > deadline) return error.AcmeTimeout;
            try self.pause(polled.retry_after_s);
        }
    }

    fn pollOrder(self: *Client, a: std.mem.Allocator, url: []const u8, want: []const u8) !Order {
        const deadline = self.nowSeconds() + self.poll_limit_s;
        while (true) {
            const polled = try self.getJson(Order, a, url);
            const order = polled.value;
            if (std.mem.eql(u8, order.status, want) or std.mem.eql(u8, order.status, "valid")) return order;
            if (std.mem.eql(u8, order.status, "invalid")) {
                if (order.@"error") |p| log.err("order failed: {s} {s}", .{ p.type, p.detail });
                return error.AcmeOrderFailed;
            }
            if (self.nowSeconds() > deadline) return error.AcmeTimeout;
            try self.pause(polled.retry_after_s);
        }
    }

    /// POST-as-GET and parse; strings are copied into `a`.
    fn getJson(self: *Client, comptime T: type, a: std.mem.Allocator, url: []const u8) !struct { value: T, retry_after_s: ?u32 } {
        const resp = try self.post(url, "", null);
        defer self.freeResponse(resp);
        return .{ .value = try std.json.parseFromSliceLeaky(T, a, resp.body, json_options), .retry_after_s = resp.retry_after_s };
    }

    fn nowSeconds(self: *Client) i64 {
        return std.Io.Clock.awake.now(self.io).toSeconds();
    }

    /// Wait before polling again: the CA's Retry-After, else a second.
    fn pause(self: *Client, retry_after_s: ?u32) std.Io.Cancelable!void {
        const s: i64 = @min(retry_after_s orelse 1, max_poll_pause_s);
        try self.io.sleep(.fromSeconds(@max(s, 1)), .awake);
    }
};

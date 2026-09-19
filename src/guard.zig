//! Who may reach a location: IP rules, Basic auth users, client
//! certificates. Built once per config generation, read by every worker.
const std = @import("std");
const quic = @import("quic");
const config = @import("config.zig");
const access = @import("access.zig");
const htpasswd = @import("auth/htpasswd.zig");

const log = std.log.scoped(.config);

pub const Auth = struct {
    file: *const htpasswd.File,
    /// `WWW-Authenticate` value: `Basic realm="..."`.
    challenge: []const u8,
};

/// What a location demands of a request.
pub const Policy = struct {
    /// Effective rules: the location's, else its server's.
    rules: []const access.Rule = &.{},
    auth: ?Auth = null,
    require_client_cert: bool = false,
};

pub const Guards = struct {
    policies: std.AutoHashMapUnmanaged(*const config.Location, Policy) = .empty,
    /// Each TLS server's client-certificate policy. Servers naming the same
    /// CA file and mode share one, so a connection verified for one of them
    /// is good for the others (see `Exchange.create`).
    client_auths: std.AutoHashMapUnmanaged(*const config.Server, *const quic.tls13.ClientAuth) = .empty,
    /// Some location asks for a password: the verifier pool is needed.
    any_auth: bool = false,

    pub fn policy(self: *const Guards, loc: *const config.Location) Policy {
        return self.policies.get(loc) orelse .{};
    }

    pub fn clientAuth(self: *const Guards, srv: *const config.Server) ?*const quic.tls13.ClientAuth {
        return self.client_auths.get(srv);
    }
};

/// Compile the rules and load the htpasswd files and client CA bundles
/// `cfg` names. Everything lives in `arena`. Fails with the file named, so
/// `-t` catches a bad user file or CA bundle.
pub fn build(arena: std.mem.Allocator, cfg: *const config.Config) !Guards {
    var g: Guards = .{};
    var files: std.StringHashMapUnmanaged(*const htpasswd.File) = .empty;
    for (cfg.servers) |*srv| {
        const server_rules = try compile(arena, srv.access);
        for (srv.locations) |*loc| {
            var p: Policy = .{
                .rules = if (loc.access.len > 0) try compile(arena, loc.access) else server_rules,
                .require_client_cert = loc.require_client_cert,
            };
            if (loc.auth_basic) |ab| {
                const gop = try files.getOrPut(arena, ab.user_file);
                if (!gop.found_existing) gop.value_ptr.* = try loadUserFile(arena, ab.user_file);
                p.auth = .{
                    .file = gop.value_ptr.*,
                    .challenge = try std.fmt.allocPrint(arena, "Basic realm=\"{s}\", charset=\"UTF-8\"", .{ab.realm}),
                };
                g.any_auth = true;
            }
            try g.policies.put(arena, loc, p);
        }
    }

    const Key = struct { path: []const u8, mode: config.ClientVerify, auth: *const quic.tls13.ClientAuth };
    var loaded: std.ArrayList(Key) = .empty;
    for (cfg.servers) |*srv| {
        const t = srv.tls orelse continue;
        const path = t.client_ca orelse continue;
        const auth = for (loaded.items) |k| {
            if (k.mode == t.client_verify and std.mem.eql(u8, k.path, path)) break k.auth;
        } else blk: {
            const a = try loadClientAuth(arena, path, t.client_verify);
            try loaded.append(arena, .{ .path = path, .mode = t.client_verify, .auth = a });
            break :blk a;
        };
        try g.client_auths.put(arena, srv, auth);
    }
    return g;
}

fn compile(arena: std.mem.Allocator, rules: []const config.AccessRule) ![]const access.Rule {
    const out = try arena.alloc(access.Rule, rules.len);
    // Validated at parse; a failure here is a config that skipped it.
    for (rules, out) |r, *o| o.* = access.parse(r.action(), r.text()) catch return error.InvalidConfig;
    return out;
}

fn loadUserFile(arena: std.mem.Allocator, path: []const u8) !*const htpasswd.File {
    const text = quic.sys.readFileAlloc(arena, path, 16 * 1024 * 1024) catch |err| {
        log.err("auth_basic user_file {s}: {s}", .{ path, @errorName(err) });
        return err;
    };
    var diag: htpasswd.Diagnostic = .{};
    const f = try arena.create(htpasswd.File);
    f.* = htpasswd.parse(arena, text, &diag) catch |err| {
        if (err == error.InvalidFile) log.err("auth_basic user_file {s}:{d}: {s}", .{ path, diag.line, diag.reason });
        return err;
    };
    if (f.users.count() == 0) log.warn("auth_basic user_file {s} has no users: every login will fail", .{path});
    if (f.has_sha1) log.warn("auth_basic user_file {s}: {{SHA}} entries are unsalted SHA-1, fast to crack if the file leaks; prefer htpasswd -B", .{path});
    return f;
}

fn loadClientAuth(arena: std.mem.Allocator, path: []const u8, mode: config.ClientVerify) !*const quic.tls13.ClientAuth {
    const bundle = try arena.create(std.crypto.Certificate.Bundle);
    bundle.* = quic.ca_bundle.loadFile(arena, path) catch |err| {
        log.err("tls.client_ca {s}: {s}", .{ path, @errorName(err) });
        return err;
    };
    if (bundle.map.count() == 0) {
        log.err("tls.client_ca {s}: no certificates", .{path});
        return error.InvalidConfig;
    }
    const a = try arena.create(quic.tls13.ClientAuth);
    a.* = .{
        .ca_bundle = bundle,
        .mode = switch (mode) {
            .required => .required,
            .optional => .optional,
        },
        .authorities = try quic.tls13.certificateAuthorities(arena, bundle),
    };
    return a;
}

const testing = std.testing;

test "policies: location rules replace the server's, user files and CA bundles load once" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "users", .data = "alice:$2y$10$f/mtfnwsB2gGNc04FBRPnu07AK7xFpWb9z4jwcHSRI4vGLNN2IC82\n" });
    const ca_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIBlTCCATugAwIBAgIUJ0VVpBMXbR+m2qeJVtlLPwMGrS8wCgYIKoZIzj0EAwIw
        \\FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkxODAyMjc1MVoYDzIwNTYwOTEw
        \\MDIyNzUxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
        \\PQMBBwNCAARNKn/A+BTv6O4gtvRSCTsilRB39MBxN3r12JuLyBsBjbeS0BGQT0Ln
        \\dUgaVrtTNu7iCSi0Z5mDy584RtfhwLjjo2kwZzAdBgNVHQ4EFgQUgsQXmkDpwyyD
        \\DE+urWAkJzlvp4gwHwYDVR0jBBgwFoAUgsQXmkDpwyyDDE+urWAkJzlvp4gwDwYD
        \\VR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwID
        \\SAAwRQIhAL/ObOrd87Ioq197659prUHNDVOQ8y9LpqKlXroBCK0+AiBu5JczdLo0
        \\paz/2uMhZZ65w/QAplKh2+e0QSDAcZreyA==
        \\-----END CERTIFICATE-----
    ;
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "ca.pem", .data = ca_pem });
    const users = try tmp.dir.realPathFileAlloc(testing.io, "users", a);
    const ca = try tmp.dir.realPathFileAlloc(testing.io, "ca.pem", a);

    const locs = [_]config.Location{
        .{ .prefix = "/", .root = "x" },
        .{ .prefix = "/a/", .root = "x", .access = &.{.{ .allow = "all" }}, .auth_basic = .{ .user_file = users } },
        .{ .prefix = "/b/", .root = "x", .auth_basic = .{ .realm = "B", .user_file = users } },
    };
    const servers = [_]config.Server{
        .{ .listen = &.{}, .access = &.{.{ .deny = "all" }}, .tls = .{ .cert = "c", .key = "k", .client_ca = ca }, .locations = &locs },
        .{ .listen = &.{}, .tls = .{ .cert = "c", .key = "k", .client_ca = ca }, .locations = &.{} },
        .{ .listen = &.{}, .tls = .{ .cert = "c", .key = "k", .client_ca = ca, .client_verify = .optional }, .locations = &.{} },
    };
    const cfg: config.Config = .{ .servers = &servers };
    const g = try build(a, &cfg);
    try testing.expect(g.any_auth);
    const ip: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1 };
    try testing.expectEqual(access.Action.deny, access.check(g.policy(&servers[0].locations[0]).rules, ip));
    try testing.expectEqual(access.Action.allow, access.check(g.policy(&servers[0].locations[1]).rules, ip));
    const pa = g.policy(&servers[0].locations[1]).auth.?;
    const pb = g.policy(&servers[0].locations[2]).auth.?;
    try testing.expectEqual(pa.file, pb.file);
    try testing.expectEqualStrings("Basic realm=\"B\", charset=\"UTF-8\"", pb.challenge);
    try testing.expectEqual(g.clientAuth(&servers[0]).?, g.clientAuth(&servers[1]).?);
    try testing.expect(g.clientAuth(&servers[0]).? != g.clientAuth(&servers[2]).?);
    try testing.expectEqual(quic.tls13.ClientAuth.Mode.optional, g.clientAuth(&servers[2]).?.mode);
}

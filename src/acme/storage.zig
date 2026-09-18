//! On-disk layout for ACME state, and loading what's stored for serving.
//!
//! ```
//! <storage>/<ca>/account.key        ACME account key (EC PRIVATE KEY)
//! <storage>/<ca>/<name>.pem         certificate chain, then its key
//! ```
//! `<ca>` is the directory URL's host (and port), so staging and production
//! certificates never mix. `<name>` is the alphabetically first server name,
//! so reordering `server_names` keeps the file. Directories are 0700 and files 0600; files are
//! replaced by rename, so a reader sees the old or the new one whole. Chain and
//! key share a file so they can't be caught mismatched.
const std = @import("std");
const quic = @import("quic");
const config = @import("../config.zig");
const x509 = @import("x509.zig");

const log = std.log.scoped(.acme);

/// `<storage>/<ca>`.
pub fn caDir(a: std.mem.Allocator, acme: config.Acme) ![]u8 {
    const uri = std.Uri.parse(acme.directory) catch return error.InvalidDirectoryUrl;
    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = (uri.getHost(&host_buf) catch return error.InvalidDirectoryUrl).bytes;
    if (uri.port) |p| return std.fmt.allocPrint(a, "{s}/{s}_{d}", .{ acme.storage, host, p });
    return std.fmt.allocPrint(a, "{s}/{s}", .{ acme.storage, host });
}

pub fn accountKeyPath(a: std.mem.Allocator, acme: config.Acme) ![]u8 {
    return std.fmt.allocPrint(a, "{s}/account.key", .{try caDir(a, acme)});
}

/// Names are validated as DNS names, so any of them is a safe file name.
pub fn bundlePath(a: std.mem.Allocator, acme: config.Acme, names: []const []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{s}/{s}.pem", .{ try caDir(a, acme), config.acmeStorageName(names) });
}

pub const Bundle = struct {
    chain: []const []const u8,
    key: x509.KeyPair,
    not_before: u64,
    not_after: u64,
};

/// The stored certificate for `names`, if present, readable, matching its key
/// and covering every name. Expiry is the caller's call.
pub fn loadBundle(a: std.mem.Allocator, path: []const u8, names: []const []const u8) !Bundle {
    const b = try loadAnyBundle(a, path);
    if (x509.coveredUntil(b.chain[0], names) == null) return error.NamesNotCovered;
    return b;
}

/// A stored chain and its matching key, whatever names it covers.
pub fn loadAnyBundle(a: std.mem.Allocator, path: []const u8) !Bundle {
    const text = try quic.sys.readFileAlloc(a, path, 1024 * 1024);
    const chain = quic.tls13.parsePemCertChain(a, text) catch return error.CorruptBundle;
    const key = x509.parsePrivateKeyPem(text) catch return error.CorruptBundle;
    const parsed = (std.crypto.Certificate{ .buffer = chain[0], .index = 0 }).parse() catch return error.CorruptBundle;
    if (!std.mem.eql(u8, parsed.pubKey(), &key.public_key.toUncompressedSec1())) return error.CorruptBundle;
    return .{ .chain = chain, .key = key, .not_before = parsed.validity.not_before, .not_after = parsed.validity.not_after };
}

/// How many of `names` a certificate is valid for.
fn coverage(cert_der: []const u8, names: []const []const u8) usize {
    var n: usize = 0;
    for (names) |name| {
        if (x509.coveredUntil(cert_der, &.{name}) != null) n += 1;
    }
    return n;
}

pub const Stored = struct { path: []const u8, bundle: Bundle, covered: usize };

/// The unexpired stored certificate under this CA that covers the most of
/// `names`: the exact one if it exists, else one kept from before the names
/// changed, which still serves the names it has while the new one is ordered.
pub fn bestBundle(a: std.mem.Allocator, io: std.Io, acme: config.Acme, names: []const []const u8, now: i64) !?Stored {
    const exact = try bundlePath(a, acme, names);
    if (loadBundle(a, exact, names)) |b| {
        if (b.not_after > now) return .{ .path = exact, .bundle = b, .covered = names.len };
    } else |_| {}
    const dir_path = try caDir(a, acme);
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return null;
    defer dir.close(io);
    var best: ?Stored = null;
    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".pem")) continue;
        const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ dir_path, entry.name });
        const b = loadAnyBundle(a, path) catch continue;
        if (b.not_after <= now) continue;
        const covered = coverage(b.chain[0], names);
        if (covered == 0) continue;
        if (best) |cur| {
            if (covered < cur.covered or (covered == cur.covered and b.not_after <= cur.bundle.not_after)) continue;
        }
        best = .{ .path = path, .bundle = b, .covered = covered };
    }
    return best;
}

/// Renew once fewer than `renew_days` remain, or half the lifetime, whichever
/// comes later: a certificate shorter-lived than the window would otherwise be
/// renewed again as soon as it arrives.
pub fn renewalDue(b: Bundle, now: i64, renew_days: u16) bool {
    const lifetime: i64 = @as(i64, @intCast(b.not_after)) - @as(i64, @intCast(b.not_before));
    const window = @min(@as(i64, renew_days) * 86400, @divTrunc(lifetime, 2));
    return @as(i64, @intCast(b.not_after)) - now < window;
}

/// Write `bytes` to `path` with mode 0600, atomically replacing any old file.
pub fn writeAtomic(io: std.Io, path: []const u8, bytes: []const u8) !void {
    if (std.fs.path.dirname(path)) |dir| {
        _ = try std.Io.Dir.cwd().createDirPathStatus(io, dir, .fromMode(0o700));
    }
    var af = try std.Io.Dir.cwd().createFileAtomic(io, path, .{ .permissions = .fromMode(0o600), .replace = true });
    defer af.deinit(io);
    try af.file.writeStreamingAll(io, bytes);
    try af.file.sync(io);
    try af.replace(io);
}

/// The account key under `storage`, created on first use.
pub fn loadOrCreateAccountKey(gpa: std.mem.Allocator, io: std.Io, acme: config.Acme) !x509.KeyPair {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const path = try accountKeyPath(a, acme);
    if (quic.sys.readFileAlloc(a, path, 64 * 1024)) |text| {
        return x509.parsePrivateKeyPem(text) catch |err| {
            log.err("{s}: {s}", .{ path, @errorName(err) });
            return err;
        };
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    const kp = x509.KeyPair.generate(io);
    const pem = try x509.privateKeyPem(a, kp);
    defer std.crypto.secureZero(u8, pem);
    try writeAtomic(io, path, pem);
    log.info("created ACME account key {s}", .{path});
    return kp;
}

/// A self-signed stand-in, served until the CA's certificate arrives.
pub fn placeholder(a: std.mem.Allocator, io: std.Io, names: []const []const u8) !quic.tls_server.Certificate {
    const kp = x509.KeyPair.generate(io);
    var serial: [16]u8 = undefined;
    io.random(&serial);
    const now: u64 = @intCast(quic.sys.realtimeSeconds());
    const cert = try x509.selfSigned(a, kp, names, now - 3600, now + 7 * 86400, serial);
    const chain = try a.alloc([]const u8, 1);
    chain[0] = cert;
    return .{ .cert_chain_der = chain, .private_key_bytes = try a.dupe(u8, &kp.secret_key.toBytes()), .private_key_algorithm = .ecdsa_p256_sha256 };
}

/// What a TLS listener serves for an ACME server: the best stored
/// certificate still valid, else a placeholder (the ACME thread is fetching one).
pub fn servingCertificate(a: std.mem.Allocator, io: std.Io, acme: config.Acme, names: []const []const u8) !quic.tls_server.Certificate {
    if (try bestBundle(a, io, acme, names, quic.sys.realtimeSeconds())) |best| {
        if (best.covered < names.len) {
            log.warn("{s}: serving {s}, which covers {d} of {d} names, until ACME issues one for all of them", .{ names[0], best.path, best.covered, names.len });
        }
        const b = best.bundle;
        return .{ .cert_chain_der = b.chain, .private_key_bytes = try a.dupe(u8, &b.key.secret_key.toBytes()), .private_key_algorithm = .ecdsa_p256_sha256 };
    }
    log.warn("{s}: no usable certificate stored; serving a self-signed placeholder until ACME provides one", .{names[0]});
    return placeholder(a, io, names);
}

test "paths are per CA" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const names = [_][]const u8{"example.com"};
    try std.testing.expectEqualStrings("/s/acme-v02.api.letsencrypt.org/example.com.pem", try bundlePath(a, .{ .storage = "/s" }, &names));
    // Independent of order.
    try std.testing.expectEqualStrings("/s/acme-v02.api.letsencrypt.org/a.example.pem", try bundlePath(a, .{ .storage = "/s" }, &.{ "b.example", "a.example" }));
    try std.testing.expectEqualStrings("/s/localhost_14000/account.key", try accountKeyPath(a, .{ .storage = "/s", .directory = "https://localhost:14000/dir" }));
}

test "renewal window" {
    const day = 86400;
    const b: Bundle = .{ .chain = &.{}, .key = undefined, .not_before = 0, .not_after = 90 * day };
    try std.testing.expect(!renewalDue(b, 59 * day, 30));
    try std.testing.expect(renewalDue(b, 61 * day, 30));
    // A 6-day certificate renews at half-life, not straight away.
    const short: Bundle = .{ .chain = &.{}, .key = undefined, .not_before = 0, .not_after = 6 * day };
    try std.testing.expect(!renewalDue(short, 1 * day, 30));
    try std.testing.expect(renewalDue(short, 4 * day, 30));
}

test "bundle round trip through writeAtomic" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    const path = try std.fmt.allocPrint(a, "{s}/ca/example.com.pem", .{dir});
    const names = [_][]const u8{"example.com"};
    const kp = x509.KeyPair.generate(io);
    const cert = try x509.selfSigned(a, kp, &names, 1_700_000_000, 4_000_000_000, @splat(1));
    const text = try std.mem.concat(a, u8, &.{ try @import("der.zig").pem(a, "CERTIFICATE", cert), try x509.privateKeyPem(a, kp) });
    try writeAtomic(io, path, text);
    try writeAtomic(io, path, text); // replaces

    const st = try std.Io.Dir.cwd().statFile(io, path, .{});
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);
    const b = try loadBundle(a, path, &names);
    try std.testing.expectEqual(@as(u64, 4_000_000_000), b.not_after);
    try std.testing.expectError(error.NamesNotCovered, loadBundle(a, path, &.{"other.example"}));
}

test "a stored certificate for fewer names keeps serving them" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const acme: config.Acme = .{ .storage = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)] };

    const old_names = [_][]const u8{"b.example"};
    const kp = x509.KeyPair.generate(io);
    const now: i64 = 1_800_000_000;
    const cert = try x509.selfSigned(a, kp, &old_names, now - 86400, now + 86400, @splat(2));
    try writeAtomic(io, try bundlePath(a, acme, &old_names), try std.mem.concat(a, u8, &.{ try @import("der.zig").pem(a, "CERTIFICATE", cert), try x509.privateKeyPem(a, kp) }));

    // "a.example" sorts first, so the new set has its own file, not written yet.
    const best = (try bestBundle(a, io, acme, &.{ "b.example", "a.example" }, now)).?;
    try std.testing.expectEqual(@as(usize, 1), best.covered);
    try std.testing.expect(try bestBundle(a, io, acme, &.{"c.example"}, now) == null);
    // Expired: not served.
    try std.testing.expect(try bestBundle(a, io, acme, &old_names, now + 2 * 86400) == null);
}

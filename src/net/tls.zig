//! TLS 1.3 for TCP listeners, on quic-zig's sans-IO `tls_server`.
const std = @import("std");
const quic = @import("quic");
const config = @import("../config.zig");
const tls_server = quic.tls_server;
const tls13 = quic.tls13;

/// Certificates and TLS settings for one listener, shared read-only by all
/// workers. The certificate list is also what the QUIC listener serves.
pub const ServerConfig = struct {
    tls: tls_server.Config,
    certs: []const tls_server.CertEntry,
    ticket_key: [16]u8,

    /// Build from the servers sharing a listener; the first one with TLS
    /// provides the default certificate.
    pub fn load(arena: std.mem.Allocator, servers: []const *const config.Server, ticket_key: [16]u8, alpn: []const []const u8) !*const ServerConfig {
        var certs: std.ArrayListUnmanaged(tls_server.CertEntry) = .empty;
        for (servers) |srv| {
            const t = srv.tls orelse continue;
            try certs.append(arena, .{ .server_names = srv.server_names, .cert = try loadCertificate(arena, t) });
        }
        if (certs.items.len == 0) return error.NoCertificate;
        const self = try arena.create(ServerConfig);
        self.* = .{
            .tls = .{ .certs = certs.items, .alpn = alpn, .ticket_key = ticket_key },
            .certs = certs.items,
            .ticket_key = ticket_key,
        };
        return self;
    }
};

pub fn loadCertificate(arena: std.mem.Allocator, t: config.Tls) !tls_server.Certificate {
    const cert_pem = quic.sys.readFileAlloc(arena, t.cert, 1024 * 1024) catch |err| {
        std.log.err("reading {s}: {s}", .{ t.cert, @errorName(err) });
        return err;
    };
    const key_pem = quic.sys.readFileAlloc(arena, t.key, 64 * 1024) catch |err| {
        std.log.err("reading {s}: {s}", .{ t.key, @errorName(err) });
        return err;
    };
    const chain = try tls13.parsePemCertChain(arena, cert_pem);
    if (chain.len == 0) return error.NoCertificate;
    const der_buf = try arena.alloc(u8, key_pem.len);
    const key_der = try tls13.parsePemPrivateKey(key_pem, der_buf);
    if (tls13.extractEcPrivateKey(key_der)) |k| {
        return .{ .cert_chain_der = chain, .private_key_bytes = try arena.dupe(u8, k), .private_key_algorithm = .ecdsa_p256_sha256 };
    } else |_| {}
    if (tls13.extractPkcs8EcPrivateKey(key_der)) |k| {
        return .{ .cert_chain_der = chain, .private_key_bytes = try arena.dupe(u8, k), .private_key_algorithm = .ecdsa_p256_sha256 };
    } else |_| {}
    if (tls13.extractEd25519PrivateKey(key_der)) |k| {
        return .{ .cert_chain_der = chain, .private_key_bytes = try arena.dupe(u8, k), .private_key_algorithm = .ed25519 };
    } else |_| {}
    std.log.err("{s}: only EC P-256 and Ed25519 keys are supported", .{t.key});
    return error.UnsupportedKey;
}

/// One TLS connection's state, between the socket and the HTTP parser.
pub const Transport = struct {
    conn: tls_server.Conn,
    alloc: std.mem.Allocator,

    pub fn create(alloc: std.mem.Allocator, cfg: *const ServerConfig) !*Transport {
        const t = try alloc.create(Transport);
        t.* = .{ .conn = tls_server.Conn.init(alloc, &cfg.tls), .alloc = alloc };
        return t;
    }

    pub fn destroy(self: *Transport) void {
        self.conn.deinit();
        self.alloc.destroy(self);
    }

    /// Ciphertext from the socket. On error the alert is already queued.
    pub fn feed(self: *Transport, data: []const u8) !void {
        return self.conn.feed(data);
    }

    /// Decrypted application data; 0 when none is buffered.
    pub fn read(self: *Transport, buf: []u8) usize {
        return self.conn.read(buf);
    }

    pub fn write(self: *Transport, data: []const u8) !void {
        return self.conn.write(data);
    }

    pub fn pendingOutput(self: *Transport) []const u8 {
        return self.conn.pendingOutput();
    }

    pub fn consumeOutput(self: *Transport, n: usize) void {
        self.conn.consumeOutput(n);
    }

    pub fn close(self: *Transport) void {
        if (self.conn.handshakeComplete()) self.conn.close();
    }

    pub fn peerClosed(self: *Transport) bool {
        return self.conn.peerClosed();
    }

    pub fn handshakeComplete(self: *Transport) bool {
        return self.conn.handshakeComplete();
    }
};

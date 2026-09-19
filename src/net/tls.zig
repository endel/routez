//! TLS 1.3 over TCP, on quic-zig's sans-IO `tls_server` (listeners) and
//! `tls_client` (upstreams).
const std = @import("std");
const quic = @import("quic");
const config = @import("../config.zig");
const acme = @import("../acme.zig");
const tls_server = quic.tls_server;
const tls_client = quic.tls_client;
const socket = @import("socket.zig");
const tls13 = quic.tls13;
const guard = @import("../guard.zig");

/// Certificates and TLS settings for one listener, shared read-only by all
/// workers. The certificate list is also what the QUIC listener serves.
pub const ServerConfig = struct {
    tls: tls_server.Config,
    certs: []const tls_server.CertEntry,
    ticket_key: [16]u8,

    /// Build from the servers sharing a listener; the first one with TLS
    /// provides the default certificate. Each server's entry asks for client
    /// certificates when `guards` has a policy for it.
    pub fn load(arena: std.mem.Allocator, io: std.Io, servers: []const *const config.Server, ticket_key: [16]u8, alpn: []const []const u8, guards: *const guard.Guards) !*const ServerConfig {
        var certs: std.ArrayListUnmanaged(tls_server.CertEntry) = .empty;
        for (servers) |srv| {
            const t = srv.tls orelse continue;
            const cert = if (t.acme) |a|
                try acme.servingCertificate(arena, io, a, srv.server_names)
            else
                try loadCertificate(arena, t.cert.?, t.key.?);
            try certs.append(arena, .{ .server_names = srv.server_names, .cert = cert, .client_auth = guards.clientAuth(srv) });
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

pub fn loadCertificate(arena: std.mem.Allocator, cert_path: []const u8, key_path: []const u8) !tls_server.Certificate {
    const cert_pem = quic.sys.readFileAlloc(arena, cert_path, 1024 * 1024) catch |err| {
        std.log.err("reading {s}: {s}", .{ cert_path, @errorName(err) });
        return err;
    };
    const key_pem = quic.sys.readFileAlloc(arena, key_path, 64 * 1024) catch |err| {
        std.log.err("reading {s}: {s}", .{ key_path, @errorName(err) });
        return err;
    };
    const chain = try tls13.parsePemCertChain(arena, cert_pem);
    if (chain.len == 0) return error.NoCertificate;
    const der_buf = try arena.alloc(u8, key_pem.len);
    const key_der = try tls13.parsePemPrivateKey(key_pem, der_buf);
    const key = tls13.extractPrivateKey(key_der) catch |err| {
        switch (err) {
            error.InvalidKey => std.log.err("{s}: the RSA key's numbers do not fit together", .{key_path}),
            error.UnsupportedKey => std.log.err("{s}: only EC P-256, Ed25519 and 2048 to 4096-bit RSA keys are supported", .{key_path}),
        }
        return err;
    };
    const matches = tls13.keyMatchesCertificate(key, chain[0]) catch |err| {
        std.log.err("{s}: the first certificate does not parse", .{cert_path});
        return err;
    };
    if (!matches) {
        std.log.err("{s} is not the key of the first certificate in {s}", .{ key_path, cert_path });
        return error.KeyMismatch;
    }
    return .{ .cert_chain_der = chain, .private_key_bytes = try arena.dupe(u8, key.bytes), .private_key_algorithm = key.algorithm };
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

    /// The client's verified certificate and the policy that verified it.
    pub fn clientCert(self: *const Transport) ClientCert {
        return .{ .secure = true, .auth = self.conn.clientAuth(), .der = self.conn.peerCertificate() };
    }
};

/// A connection's client-certificate state, as a request sees it.
pub const ClientCert = struct {
    /// The request came over TLS or QUIC (whatever its scheme says).
    secure: bool = false,
    /// The policy the handshake ran under; null when none asked.
    auth: ?*const tls13.ClientAuth = null,
    /// The verified leaf (DER); null when none was presented.
    der: ?[]const u8 = null,
};

/// TLS to an upstream, between its socket and its owner (`UpConn`, `Probe`).
///
/// The owner hears `onTlsHandshake(?anyerror)` once, then plaintext through
/// `onTlsData`, and `onTlsEof` when the server closes the TLS session or a
/// record fails after the handshake.
pub const Client = struct {
    conn: tls_client.Conn,
    alloc: std.mem.Allocator,
    handshake_done: bool = false,
    ended: bool = false,

    /// The ClientHello is queued; `flush` it into the socket.
    pub fn create(alloc: std.mem.Allocator, cfg: *const tls_client.Config) !*Client {
        const c = try alloc.create(Client);
        errdefer alloc.destroy(c);
        c.* = .{ .conn = try tls_client.Conn.init(alloc, cfg), .alloc = alloc };
        return c;
    }

    pub fn destroy(self: *Client) void {
        self.conn.deinit();
        self.alloc.destroy(self);
    }

    /// Before the handshake completes, the bytes are held and sent after it.
    pub fn write(self: *Client, sock: anytype, bytes: []const u8) void {
        // Fails only after a TLS failure the owner has already heard about,
        // or out of memory.
        self.conn.write(bytes) catch return;
        self.flush(sock);
    }

    pub fn flush(self: *Client, sock: anytype) void {
        const pending = self.conn.pendingOutput();
        if (pending.len == 0) return;
        sock.write(pending);
        self.conn.consumeOutput(pending.len);
    }

    /// Ciphertext from the socket.
    pub fn onData(self: *Client, sock: anytype, owner: anytype, data: []const u8) void {
        if (self.ended) return;
        self.conn.feed(data) catch |err| {
            self.flush(sock); // the alert
            self.ended = true;
            if (!self.handshake_done) return owner.onTlsHandshake(err);
            return owner.onTlsEof();
        };
        self.flush(sock);
        if (!self.handshake_done and self.conn.handshakeComplete()) {
            self.handshake_done = true;
            owner.onTlsHandshake(null);
        }
        var buf: [socket.read_buffer_size]u8 = undefined;
        while (sock.isOpen()) {
            const n = self.conn.read(&buf);
            if (n == 0) break;
            owner.onTlsData(buf[0..n]);
        }
        if (sock.isOpen() and self.conn.peerClosed()) {
            self.ended = true;
            owner.onTlsEof();
        }
    }
};

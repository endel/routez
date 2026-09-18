//! Test helpers for tests/acme/run.sh, on routez's own encoders.
//!   acme-test-tool cert <out.pem> <days-ago> <days-left> <name>...
//!     self-signed certificate and key as one bundle, e.g. a stored
//!     certificate near expiry
//!   acme-test-tool csr <out.pem> <name>...
//!     a PKCS#10 request, for checking with openssl
const std = @import("std");
const x509 = @import("x509");

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    if (args.len < 4) return error.Usage;
    const kp = x509.KeyPair.generate(init.io);
    const text = if (std.mem.eql(u8, args[1], "csr")) blk: {
        break :blk try x509.der.pem(a, "CERTIFICATE REQUEST", try x509.csr(a, kp, args[3..]));
    } else if (std.mem.eql(u8, args[1], "cert") and args.len >= 6) blk: {
        const ago = try std.fmt.parseInt(u64, args[3], 10);
        const left = try std.fmt.parseInt(u64, args[4], 10);
        const now: u64 = @intCast(std.Io.Clock.real.now(init.io).toSeconds());
        var serial: [16]u8 = undefined;
        init.io.random(&serial);
        const cert = try x509.selfSigned(a, kp, args[5..], now - ago * 86400, now + left * 86400, serial);
        break :blk try std.mem.concat(a, u8, &.{ try x509.der.pem(a, "CERTIFICATE", cert), try x509.privateKeyPem(a, kp) });
    } else return error.Usage;
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = args[2], .data = text });
}

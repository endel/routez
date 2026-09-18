//! Automatic certificates over ACME (RFC 8555) with HTTP-01 validation.
pub const Manager = @import("acme/manager.zig").Manager;
pub const Challenges = @import("acme/manager.zig").Challenges;
pub const servingCertificate = @import("acme/storage.zig").servingCertificate;

test {
    _ = @import("acme/der.zig");
    _ = @import("acme/x509.zig");
    _ = @import("acme/jws.zig");
    _ = @import("acme/client.zig");
    _ = @import("acme/storage.zig");
    _ = @import("acme/manager.zig");
}

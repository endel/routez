//! Automatic certificates over ACME (RFC 8555) with HTTP-01 validation.

test {
    _ = @import("acme/der.zig");
    _ = @import("acme/x509.zig");
    _ = @import("acme/jws.zig");
}

//! JSON Web Signatures for ACME (RFC 7515, RFC 8555 section 6.2): ES256
//! over P-256, flattened JSON serialization.
const std = @import("std");
const x509 = @import("x509.zig");
const Ecdsa = x509.Ecdsa;

const b64 = std.base64.url_safe_no_pad.Encoder;

pub fn base64UrlAlloc(gpa: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, b64.calcSize(bytes.len));
    _ = b64.encode(out, bytes);
    return out;
}

/// The public JWK with members in lexicographic order and no whitespace,
/// which is also the RFC 7638 thumbprint input.
pub fn jwk(gpa: std.mem.Allocator, pk: Ecdsa.PublicKey) ![]u8 {
    var buf: [jwk_len]u8 = undefined;
    return gpa.dupe(u8, jwkBuf(&buf, pk));
}

const jwk_len = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\",\"y\":\"\"}".len + 2 * 43;

fn jwkBuf(buf: *[jwk_len]u8, pk: Ecdsa.PublicKey) []const u8 {
    const sec1 = pk.toUncompressedSec1();
    var x: [43]u8 = undefined;
    var y: [43]u8 = undefined;
    _ = b64.encode(&x, sec1[1..33]);
    _ = b64.encode(&y, sec1[33..65]);
    return std.fmt.bufPrint(buf, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ &x, &y }) catch unreachable;
}

/// RFC 7638 thumbprint, base64url.
pub fn thumbprint(pk: Ecdsa.PublicKey) [43]u8 {
    var buf: [jwk_len]u8 = undefined;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(jwkBuf(&buf, pk), &digest, .{});
    var out: [43]u8 = undefined;
    _ = b64.encode(&out, &digest);
    return out;
}

/// `token.thumbprint`, what an HTTP-01 challenge response must contain.
pub fn keyAuthorization(gpa: std.mem.Allocator, token: []const u8, pk: Ecdsa.PublicKey) ![]u8 {
    const tp = thumbprint(pk);
    return std.fmt.allocPrint(gpa, "{s}.{s}", .{ token, &tp });
}

/// Who signs: an account URL once registered, else the public key itself.
pub const Signer = union(enum) { kid: []const u8, jwk };

/// A flattened JWS over `payload`. An empty payload is a POST-as-GET.
pub fn sign(gpa: std.mem.Allocator, kp: x509.KeyPair, signer: Signer, nonce: []const u8, url: []const u8, payload: []const u8) ![]u8 {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const header = switch (signer) {
        .kid => |kid| try std.fmt.allocPrint(a, "{{\"alg\":\"ES256\",\"kid\":{f},\"nonce\":{f},\"url\":{f}}}", .{ std.json.fmt(kid, .{}), std.json.fmt(nonce, .{}), std.json.fmt(url, .{}) }),
        .jwk => try std.fmt.allocPrint(a, "{{\"alg\":\"ES256\",\"jwk\":{s},\"nonce\":{f},\"url\":{f}}}", .{ try jwk(a, kp.public_key), std.json.fmt(nonce, .{}), std.json.fmt(url, .{}) }),
    };
    const protected = try base64UrlAlloc(a, header);
    const body = try base64UrlAlloc(a, payload);
    const signing_input = try std.fmt.allocPrint(a, "{s}.{s}", .{ protected, body });
    // JWS ES256 wants the raw r || s, not DER.
    const sig = try kp.sign(signing_input, null);
    var sig_b64: [86]u8 = undefined;
    _ = b64.encode(&sig_b64, &sig.toBytes());
    return std.fmt.allocPrint(gpa, "{{\"protected\":\"{s}\",\"payload\":\"{s}\",\"signature\":\"{s}\"}}", .{ protected, body, &sig_b64 });
}

const testing = std.testing;

test "RFC 7638 thumbprint of a known key" {
    // RFC 7515 appendix A.3's P-256 key.
    const dec = std.base64.url_safe_no_pad.Decoder;
    var sec1: [65]u8 = undefined;
    sec1[0] = 4;
    try dec.decode(sec1[1..33], "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
    try dec.decode(sec1[33..65], "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
    const pk = try Ecdsa.PublicKey.fromSec1(&sec1);
    const j = try jwk(testing.allocator, pk);
    defer testing.allocator.free(j);
    try testing.expectEqualStrings(
        \\{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
    , j);
    // Independently computed: printf '%s' "$jwk" | openssl dgst -sha256 -binary | basenc --base64url
    const tp = thumbprint(pk);
    try testing.expectEqualStrings("oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U", &tp);
}

test "signed JWS verifies and carries the protected header" {
    const gpa = testing.allocator;
    const kp = x509.KeyPair.generate(testing.io);
    const out = try sign(gpa, kp, .{ .kid = "https://ca/acct/1" }, "n0nce", "https://ca/new-order", "{\"a\":1}");
    defer gpa.free(out);

    const Jws = struct { protected: []const u8, payload: []const u8, signature: []const u8 };
    const parsed = try std.json.parseFromSlice(Jws, gpa, out, .{});
    defer parsed.deinit();
    const dec = std.base64.url_safe_no_pad.Decoder;
    var header_buf: [256]u8 = undefined;
    const header = header_buf[0..try dec.calcSizeForSlice(parsed.value.protected)];
    try dec.decode(header, parsed.value.protected);
    try testing.expectEqualStrings(
        \\{"alg":"ES256","kid":"https://ca/acct/1","nonce":"n0nce","url":"https://ca/new-order"}
    , header);
    var payload: [7]u8 = undefined;
    try dec.decode(&payload, parsed.value.payload);
    try testing.expectEqualStrings("{\"a\":1}", &payload);

    var raw_sig: [64]u8 = undefined;
    try dec.decode(&raw_sig, parsed.value.signature);
    const input = try std.fmt.allocPrint(gpa, "{s}.{s}", .{ parsed.value.protected, parsed.value.payload });
    defer gpa.free(input);
    try Ecdsa.Signature.fromBytes(raw_sig).verify(input, kp.public_key);
}

test "POST-as-GET has an empty payload and a jwk header" {
    const gpa = testing.allocator;
    const kp = x509.KeyPair.generate(testing.io);
    const out = try sign(gpa, kp, .jwk, "n", "u", "");
    defer gpa.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "\"payload\":\"\"") != null);
}

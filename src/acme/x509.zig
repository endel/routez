//! P-256 keys, PKCS#10 certificate requests and self-signed certificates.
const std = @import("std");
const quic = @import("quic");
const der = @import("der.zig");
const Tag = der.Tag;
const Oid = der.Oid;

pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
pub const KeyPair = Ecdsa.KeyPair;

/// RFC 5915 ECPrivateKey, with the curve and public key, as OpenSSL writes it.
pub fn privateKeyDer(gpa: std.mem.Allocator, kp: KeyPair) ![]u8 {
    var w: der.Writer = .init(gpa);
    errdefer w.deinit();
    try w.begin(Tag.sequence);
    try w.small(1);
    try w.primitive(Tag.octet_string, &kp.secret_key.toBytes());
    try w.begin(Tag.context(0));
    try w.oid(&Oid.prime256v1);
    try w.end();
    try w.begin(Tag.context(1));
    try w.bitString(&kp.public_key.toUncompressedSec1());
    try w.end();
    try w.end();
    return w.toOwnedSlice();
}

pub fn privateKeyPem(gpa: std.mem.Allocator, kp: KeyPair) ![]u8 {
    const d = try privateKeyDer(gpa, kp);
    defer {
        std.crypto.secureZero(u8, d);
        gpa.free(d);
    }
    return der.pem(gpa, "EC PRIVATE KEY", d);
}

/// A P-256 key from PEM (SEC1 or PKCS#8).
pub fn parsePrivateKeyPem(pem_text: []const u8) !KeyPair {
    var buf: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const d = try quic.tls13.parsePemPrivateKey(pem_text, &buf);
    const raw = quic.tls13.extractEcPrivateKey(d) catch try quic.tls13.extractPkcs8EcPrivateKey(d);
    if (raw.len != 32) return error.UnsupportedKey;
    return KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(raw[0..32].*));
}

fn algorithmIdentifier(w: *der.Writer) !void {
    try w.begin(Tag.sequence);
    try w.oid(&Oid.ecdsa_with_sha256);
    try w.end();
}

fn subjectPublicKeyInfo(w: *der.Writer, kp: KeyPair) !void {
    try w.begin(Tag.sequence);
    try w.begin(Tag.sequence);
    try w.oid(&Oid.ec_public_key);
    try w.oid(&Oid.prime256v1);
    try w.end();
    try w.bitString(&kp.public_key.toUncompressedSec1());
    try w.end();
}

/// `CN=<name>`; an empty Name when the name doesn't fit CN's 64 characters.
fn name(w: *der.Writer, cn: []const u8) !void {
    try w.begin(Tag.sequence);
    if (cn.len <= 64) {
        try w.begin(Tag.set);
        try w.begin(Tag.sequence);
        try w.oid(&Oid.common_name);
        try w.primitive(Tag.utf8_string, cn);
        try w.end();
        try w.end();
    }
    try w.end();
}

/// Extensions ::= SEQUENCE { subjectAltName with one dNSName per name }.
fn sanExtensions(w: *der.Writer, names: []const []const u8) !void {
    try w.begin(Tag.sequence);
    try w.begin(Tag.sequence);
    try w.oid(&Oid.subject_alt_name);
    try w.begin(Tag.octet_string);
    try w.begin(Tag.sequence);
    for (names) |n| try w.primitive(Tag.contextPrimitive(2), n);
    try w.end();
    try w.end();
    try w.end();
    try w.end();
}

/// Sign `tbs` and wrap it as `SEQUENCE { tbs, ecdsa-with-SHA256, BIT STRING sig }`,
/// the shape shared by certificates and certification requests.
fn signed(gpa: std.mem.Allocator, kp: KeyPair, tbs: []const u8) ![]u8 {
    const sig = try kp.sign(tbs, null);
    var sig_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    var w: der.Writer = .init(gpa);
    errdefer w.deinit();
    try w.begin(Tag.sequence);
    try w.raw(tbs);
    try algorithmIdentifier(&w);
    try w.bitString(sig.toDer(&sig_buf));
    try w.end();
    return w.toOwnedSlice();
}

/// PKCS#10 (RFC 2986) request for `names`, signed by `kp`. The first name is
/// also the subject CN.
pub fn csr(gpa: std.mem.Allocator, kp: KeyPair, names: []const []const u8) ![]u8 {
    std.debug.assert(names.len > 0);
    var w: der.Writer = .init(gpa);
    defer w.deinit();
    try w.begin(Tag.sequence);
    try w.small(0);
    try name(&w, names[0]);
    try subjectPublicKeyInfo(&w, kp);
    try w.begin(Tag.context(0)); // attributes
    try w.begin(Tag.sequence);
    try w.oid(&Oid.extension_request);
    try w.begin(Tag.set);
    try sanExtensions(&w, names);
    try w.end();
    try w.end();
    try w.end();
    try w.end();
    return signed(gpa, kp, w.buf.items);
}

/// A self-signed X.509 v3 certificate for `names`.
pub fn selfSigned(gpa: std.mem.Allocator, kp: KeyPair, names: []const []const u8, not_before: u64, not_after: u64, serial: [16]u8) ![]u8 {
    std.debug.assert(names.len > 0);
    var s = serial;
    s[0] &= 0x7f; // positive
    var w: der.Writer = .init(gpa);
    defer w.deinit();
    try w.begin(Tag.sequence);
    try w.begin(Tag.context(0));
    try w.small(2); // v3
    try w.end();
    try w.unsigned(&s);
    try algorithmIdentifier(&w);
    try name(&w, names[0]);
    try w.begin(Tag.sequence);
    try w.time(not_before);
    try w.time(not_after);
    try w.end();
    try name(&w, names[0]);
    try subjectPublicKeyInfo(&w, kp);
    try w.begin(Tag.context(3));
    try sanExtensions(&w, names);
    try w.end();
    try w.end();
    return signed(gpa, kp, w.buf.items);
}

/// Validity end of a DER certificate, if it is valid for every one of `names`.
pub fn coveredUntil(cert_der: []const u8, names: []const []const u8) ?u64 {
    const parsed = (std.crypto.Certificate{ .buffer = cert_der, .index = 0 }).parse() catch return null;
    for (names) |n| parsed.verifyHostName(n) catch return null;
    return parsed.validity.not_after;
}

const testing = std.testing;

/// Walk `SEQUENCE { body, alg, BIT STRING sig }` and check the signature over body.
fn expectSignedBy(outer: []const u8, pk: Ecdsa.PublicKey) ![]const u8 {
    const seq = try der.Element.parse(outer);
    try testing.expectEqual(@as(u8, Tag.sequence), seq.tag);
    const body = try der.Element.parse(seq.contents);
    const body_tlv = seq.contents[0 .. seq.contents.len - body.rest.len];
    const alg = try der.Element.parse(body.rest);
    const alg_oid = try der.Element.parse(alg.contents);
    try testing.expectEqualSlices(u8, &Oid.ecdsa_with_sha256, alg_oid.contents);
    const bits = try der.Element.parse(alg.rest);
    try testing.expectEqual(@as(u8, Tag.bit_string), bits.tag);
    try testing.expectEqual(@as(u8, 0), bits.contents[0]);
    const sig = try Ecdsa.Signature.fromDer(bits.contents[1..]);
    try sig.verify(body_tlv, pk);
    return body.contents;
}

test "CSR parses back with the names and a valid signature" {
    const gpa = testing.allocator;
    const kp = KeyPair.generate(testing.io);
    const names = [_][]const u8{ "example.com", "www.example.com" };
    const req = try csr(gpa, kp, &names);
    defer gpa.free(req);

    const info = try expectSignedBy(req, kp.public_key);
    const version = try der.Element.parse(info);
    try testing.expectEqualSlices(u8, &.{0}, version.contents);
    const subject = try der.Element.parse(version.rest);
    try testing.expect(std.mem.indexOf(u8, subject.contents, "example.com") != null);
    const spki = try der.Element.parse(subject.rest);
    const alg = try der.Element.parse(spki.contents);
    const key_bits = try der.Element.parse(alg.rest);
    try testing.expectEqualSlices(u8, &kp.public_key.toUncompressedSec1(), key_bits.contents[1..]);
    const attrs = try der.Element.parse(spki.rest);
    try testing.expectEqual(Tag.context(0), attrs.tag);
    // attribute -> SET -> Extensions -> Extension -> OCTET STRING -> GeneralNames
    const attr = try der.Element.parse(attrs.contents);
    const attr_oid = try der.Element.parse(attr.contents);
    try testing.expectEqualSlices(u8, &Oid.extension_request, attr_oid.contents);
    const set = try der.Element.parse(attr_oid.rest);
    const exts = try der.Element.parse(set.contents);
    const ext = try der.Element.parse(exts.contents);
    const ext_oid = try der.Element.parse(ext.contents);
    try testing.expectEqualSlices(u8, &Oid.subject_alt_name, ext_oid.contents);
    const octets = try der.Element.parse(ext_oid.rest);
    const general_names = try der.Element.parse(octets.contents);
    var rest = general_names.contents;
    for (names) |n| {
        const gn = try der.Element.parse(rest);
        try testing.expectEqual(Tag.contextPrimitive(2), gn.tag);
        try testing.expectEqualStrings(n, gn.contents);
        rest = gn.rest;
    }
    try testing.expectEqual(@as(usize, 0), rest.len);
}

test "self-signed certificate parses with std.crypto.Certificate" {
    const gpa = testing.allocator;
    const kp = KeyPair.generate(testing.io);
    const names = [_][]const u8{ "a.example", "b.example" };
    const cert = try selfSigned(gpa, kp, &names, 1_700_000_000, 1_700_086_400, @splat(0xff));
    defer gpa.free(cert);
    _ = try expectSignedBy(cert, kp.public_key);

    const c: std.crypto.Certificate = .{ .buffer = cert, .index = 0 };
    const parsed = try c.parse();
    try parsed.verify(parsed, 1_700_000_100);
    try testing.expectEqual(@as(u64, 1_700_086_400), coveredUntil(cert, &names).?);
    try testing.expectEqual(@as(?u64, null), coveredUntil(cert, &.{"c.example"}));
}

test "private key PEM round trip" {
    const gpa = testing.allocator;
    const kp = KeyPair.generate(testing.io);
    const text = try privateKeyPem(gpa, kp);
    defer gpa.free(text);
    try testing.expect(std.mem.startsWith(u8, text, "-----BEGIN EC PRIVATE KEY-----\n"));
    const back = try parsePrivateKeyPem(text);
    try testing.expectEqualSlices(u8, &kp.secret_key.toBytes(), &back.secret_key.toBytes());
    try testing.expectEqualSlices(u8, &kp.public_key.toUncompressedSec1(), &back.public_key.toUncompressedSec1());
}

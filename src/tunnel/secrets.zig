//! Paths `tunnel_pass` never forwards, whatever the local server would answer:
//! secrets and repository internals, which a dev server can serve by accident
//! (an `express.static` of the project folder, a dev server's deny list
//! bypassed). The request gets 404, as if nothing were there.
//!
//! A path is refused when any of its segments starts with one of `prefixes`
//! or ends with one of `suffixes`, without case. Segments split on `\` as
//! well as `/` (Windows servers do), and the path is decoded again until it
//! settles, so a server that decodes twice finds nothing either. Not
//! configurable: a tunnel shares a developer's machine with the internet, and
//! none of these belong in a page.
const std = @import("std");

/// `.env` covers `.env.local`, `.envrc`; `.git` covers `.github`, `.git-credentials`;
/// `.colyseus` covers Cloud's deploy key (`.colyseus-cloud.json`) and the tunnel's own login.
const prefixes = [_][]const u8{
    ".env",    ".git",   ".hg",     ".svn",    ".colyseus", ".ssh",     ".aws",
    ".azure",  ".gnupg", ".docker", ".kube",   ".npmrc",    ".yarnrc",  ".pypirc",
    ".netrc",  ".pgpass", ".htpasswd", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
};
const suffixes = [_][]const u8{ ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore" };

/// Whether `path`, as routez decoded it once, names something a tunnel must not serve.
pub fn exposesSecret(path: []const u8) bool {
    var bufs: [2][4096]u8 = undefined;
    var cur = path;
    var round: usize = 0;
    while (std.mem.indexOfScalar(u8, cur, '%') != null) : (round += 1) {
        // still encoded after four more rounds: no honest path looks like that
        if (round == 4) return true;
        const next = decodeOnce(cur, &bufs[round % 2]) orelse return true;
        if (next.len == cur.len) break; // a `%` that escapes nothing: settled
        cur = next;
    }
    var it = std.mem.tokenizeAny(u8, cur, "/\\");
    while (it.next()) |seg| {
        for (prefixes) |p| if (std.ascii.startsWithIgnoreCase(seg, p)) return true;
        for (suffixes) |s| if (std.ascii.endsWithIgnoreCase(seg, s)) return true;
    }
    return false;
}

/// One round of percent-decoding into `out`; a malformed escape is kept as is.
/// Null when it doesn't fit.
fn decodeOnce(in: []const u8, out: *[4096]u8) ?[]const u8 {
    if (in.len > out.len) return null;
    var n: usize = 0;
    var i: usize = 0;
    while (i < in.len) : (i += 1) {
        var c = in[i];
        if (c == '%' and i + 2 < in.len) {
            const hi = std.fmt.charToDigit(in[i + 1], 16) catch null;
            const lo = std.fmt.charToDigit(in[i + 2], 16) catch null;
            if (hi != null and lo != null) {
                c = hi.? * 16 + lo.?;
                i += 2;
            }
        }
        out[n] = c;
        n += 1;
    }
    return out[0..n];
}

test "a tunnel never serves secrets or repository internals" {
    const refused = [_][]const u8{
        "/.env",                     "/.env.local",          "/app/.env.production", "/.envrc",
        "/.ENV",                     "/.git/config",         "/.git/HEAD",           "/x/.github/workflows/ci.yml",
        "/.colyseus-cloud.json",     "/home/.colyseus/tunnel.json", "/.ssh/id_rsa",  "/id_ed25519.pub",
        "/.aws/credentials",         "/.npmrc",              "/certs/server.key",    "/tls/fullchain.PEM",
        "/@fs/C:/game/.env",         "/@fs/Users/me/game/.env", "/src\\..\\.env",    "/a\\.git\\config",
        "/%2eenv",                   "/%252eenv",            "/%25252eenv",          "/.env#.svg",
        "/.env;x",                   "/%25%32%65env",
    };
    for (refused) |p| std.testing.expect(exposesSecret(p)) catch |e| {
        std.debug.print("not refused: {s}\n", .{p});
        return e;
    };
    const served = [_][]const u8{
        "/",                         "/index.html",          "/src/main.ts",         "/node_modules/.vite/deps/react.js",
        "/@vite/client",             "/@fs/Users/me/game/src/env.ts", "/assets/environment.glb", "/.well-known/security.txt",
        "/models/keyboard.glb",      "/matchmake/joinOrCreate/lobby", "/monkey.png",  "/100%25.png",
    };
    for (served) |p| std.testing.expect(!exposesSecret(p)) catch |e| {
        std.debug.print("refused: {s}\n", .{p});
        return e;
    };
}

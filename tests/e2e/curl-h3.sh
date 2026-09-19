#!/bin/bash
# Prints the path of a curl with HTTP/3: Homebrew's or the system's when
# they have it, else (Linux) a pinned static build from stunnel/static-curl,
# downloaded once into ~/.cache and checked against its SHA-256.
# Prints the plain curl, and fails, when none can be had.
set -u
for c in /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl "$(command -v curl)"; do
    [ -x "$c" ] && "$c" --version 2>/dev/null | grep -q HTTP3 && { echo "$c"; exit 0; }
done
PLAIN=$(command -v curl)

VERSION=8.22.0
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) ARCH=x86_64; SUM=dfb02460ba2abe513087538f12a3cf79b74b64a5ea3787ce8ac0cdb11251f884 ;;
    Linux-aarch64 | Linux-arm64) ARCH=aarch64; SUM=cf94cbeaae1b3c1944a4a761ef04478f8f0b23e93a324b5ed009b2082eda11f3 ;;
    *) echo "$PLAIN"; exit 1 ;;
esac
DIR="${XDG_CACHE_HOME:-$HOME/.cache}/routez-e2e/curl-$VERSION-$ARCH"
if [ ! -x "$DIR/curl" ]; then
    TAR="curl-linux-$ARCH-musl-$VERSION.tar.xz"
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    if ! "$PLAIN" -fsSL --retry 3 -o "$TMP/$TAR" "https://github.com/stunnel/static-curl/releases/download/$VERSION/$TAR" ||
        [ "$(sha256sum "$TMP/$TAR" | cut -d' ' -f1)" != "$SUM" ]; then
        echo "could not fetch a verified $TAR" >&2
        echo "$PLAIN"; exit 1
    fi
    tar -xJf "$TMP/$TAR" -C "$TMP" curl && mkdir -p "$DIR" && mv "$TMP/curl" "$DIR/curl" || { echo "$PLAIN"; exit 1; }
fi
echo "$DIR/curl"

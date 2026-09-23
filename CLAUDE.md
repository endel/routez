# routez

## libxev

routez gets libxev only through quic-zig (`../quic-zig`), which pins our fork,
[endel/libxev](https://github.com/endel/libxev), at a tag of its `quic-zig`
branch. The rules live in the "libxev" section of `../quic-zig/CLAUDE.md` and
in the fork's `FORK.md`. In short:

- A change libxev needs is made in the fork, on its own branch cut from
  upstream `main`, and opened as a PR on mitchellh/libxev. Never work around a
  libxev bug in routez without also doing that, and never patch libxev here.
- libxev's own tests must pass (`fork/check.sh <branch>` in the fork) on the
  change's branch and on `quic-zig` before the pin moves.
- A new pin is not pushed until routez's e2e suite passes on macOS and Linux.

When routez carries a workaround for a libxev bug, say so where the workaround
is, with the upstream PR, so it can be removed when the fix is pinned.

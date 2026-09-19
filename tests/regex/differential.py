#!/usr/bin/env python3
"""Differential test of src/regex.zig against Python's re, on random
patterns and inputs from a grammar both accept.

    zig build regex-diff && python3 tests/regex/differential.py [cases] [seed]

Every group's span must agree. Python's re isn't PCRE, though: around
repeats of groups that can match empty it sometimes records other
iterations (or a start past the end). A disagreement is settled by PCRE2,
what nginx uses, when pcre2test is installed; without it, only Python's
impossible spans are forgiven.
"""
import os, random, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER = os.path.join(HERE, "..", "..", "zig-out", "bin", "regex-diff")
ALPHABET = b"abcAB.-_/1 \n"


class Gen:
    def __init__(self, rnd):
        self.r = rnd
        self.groups = 0

    def atom(self, depth):
        r = self.r
        k = r.random()
        if k < 0.35:
            c = r.choice(b"abcAB/-_1")
            return (re.escape(bytes([c])), False)
        if k < 0.45:
            return (b".", False)
        if k < 0.6:
            return (r.choice([b"[ab]", b"[^a]", b"[a-c]", b"[^/]", b"[\\d_]", b"[A-Z]", b"[-a]"]), False)
        if k < 0.68:
            return (r.choice([b"\\d", b"\\w", b"\\s", b"\\W", b"\\.", b"\\/"]), False)
        if k < 0.74:
            return (r.choice([b"^", b"$", b"\\b", b"\\B"]), True)
        if depth < 3:
            capture = r.random() < 0.7
            if capture:
                self.groups += 1
            body, nullable = self.alt(depth + 1)
            return ((b"(" if capture else b"(?:") + body + b")", nullable)
        return (b"a", False)

    def quantified(self, depth):
        text, nullable = self.atom(depth)
        is_assert = text in (b"^", b"$", b"\\b", b"\\B")
        if is_assert or self.r.random() < 0.55:
            return text, nullable
        q, min0 = self.r.choice([
            (b"*", True), (b"+", False), (b"?", True), (b"{2}", False), (b"{1,3}", False), (b"{0,2}", True), (b"{2,}", False),
        ])
        if self.r.random() < 0.3:
            q += b"?"
        return text + q, nullable or min0

    def concat(self, depth):
        parts, nullable = [], True
        for _ in range(self.r.randint(0, 4)):
            t, n = self.quantified(depth)
            parts.append(t)
            nullable = nullable and n
        return b"".join(parts), nullable

    def alt(self, depth):
        branches = [self.concat(depth) for _ in range(1 if self.r.random() < 0.7 else self.r.randint(2, 3))]
        return b"|".join(b for b, _ in branches), any(n for _, n in branches)


def main():
    cases = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    rnd = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 1)
    rows = []
    for _ in range(cases):
        g = Gen(rnd)
        pattern, _ = g.alt(0)
        ci = rnd.random() < 0.25
        text = bytes(rnd.choice(ALPHABET) for _ in range(rnd.randint(0, 12)))
        # Python's \B never matches an empty input; PCRE's (and ours) does.
        if not text and b"\\B" in pattern:
            continue
        try:
            compiled = re.compile(pattern, re.I if ci else 0)
        except re.error:
            continue
        rows.append((pattern, ci, text, compiled))
    feed = "".join(f"{p.hex()} {int(ci)} {t.hex()}\n" for p, ci, t, _ in rows)
    out = subprocess.run([DRIVER], input=feed.encode(), capture_output=True, check=True).stdout.decode().splitlines()
    assert len(out) == len(rows), f"driver answered {len(out)} of {len(rows)} cases"
    fails = settled = 0
    for (pattern, ci, text, compiled), got in zip(rows, out):
        m = compiled.search(text)
        want = "nomatch" if m is None else spans([m.span(g) for g in range(min(m.re.groups, 9) + 1)])
        if want == got:
            continue
        if got not in ("nomatch", "error") and m is not None:
            ours = [None if x == "-" else text[int(x.split(",")[0]):int(x.split(",")[1])] for x in got.split(" ")]
            if PCRE2TEST:
                if pcre2(pattern, ci, text, len(ours)) == ours:
                    settled += 1
                    continue
            elif any(a > b for a, b in (m.span(g) for g in range(m.re.groups + 1))):
                settled += 1
                continue
        fails += 1
        if fails <= 20:
            print(f"MISMATCH pattern={pattern!r} ci={ci} input={text!r}: re={want} routez={got}")
    print(f"{len(rows)} cases, {settled} settled by {'PCRE2' if PCRE2TEST else 'impossible Python spans'}, {fails} mismatches")
    sys.exit(1 if fails else 0)


PCRE2TEST = shutil.which("pcre2test")


def spans(ss):
    return " ".join("-" if sp == (-1, -1) else f"{sp[0]},{sp[1]}" for sp in ss)


def pcre2(pattern, ci, text, groups):
    """The groups PCRE2 captures, as bytes (None: unset), or None."""
    assert b"!" not in pattern
    subject = "".join(f"\\x{{{c:02x}}}" for c in text)
    script = f"!{pattern.decode()}!{'i' if ci else ''}\n{subject}\n"
    out = subprocess.run([PCRE2TEST], input=script.encode(), capture_output=True, check=True).stdout.decode()
    if "No match" in out:
        return None
    found = [None] * groups
    for line in out.splitlines():
        g = re.match(r"^\s*(\d+): (.*)$", line)
        if g and int(g.group(1)) < groups and g.group(2) != "<unset>":
            found[int(g.group(1))] = re.sub(rb"\\x\{?([0-9a-f]{2})\}?", lambda h: bytes([int(h.group(1), 16)]), g.group(2).encode())
    return found


main()

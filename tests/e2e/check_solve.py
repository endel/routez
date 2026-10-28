"""Solve routez's browser check as the page does, and print the verify's
status and its Set-Cookie header.
Usage: check_solve.py BASE_URL CA_FILE [bad]
  bad  send a nonce that doesn't solve the puzzle"""
import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.request

base, ca = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context(cafile=ca)
# Python 3.13 checks X.509 strictly by default; the test CA has no AKI.
ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)


def get(path):
    try:
        return urllib.request.urlopen(base + path, context=ctx if base.startswith("https") else None, timeout=5)
    except urllib.error.HTTPError as e:
        return e


def base36(n):
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while True:
        n, r = divmod(n, 36)
        out = digits[r] + out
        if n == 0:
            return out


def zero_bits(digest):
    bits = 0
    for b in digest:
        if b == 0:
            bits += 8
            continue
        return bits + 8 - b.bit_length()
    return bits


puzzle = json.load(get("/.routez/check/challenge"))
n = 0
while zero_bits(hashlib.sha256((puzzle["challenge"] + base36(n)).encode()).digest()) < puzzle["difficulty"]:
    n += 1
if len(sys.argv) > 3:
    n += 1  # the next one, almost surely no solution
    while zero_bits(hashlib.sha256((puzzle["challenge"] + base36(n)).encode()).digest()) >= puzzle["difficulty"]:
        n += 1
res = get(f"/.routez/check/verify?expires={puzzle['expires']}&nonce={base36(n)}")
print(res.status, res.headers.get("Set-Cookie") or "-")

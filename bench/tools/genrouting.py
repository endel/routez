#!/usr/bin/env python3
"""Emits the routing row's locations for one server.

    genrouting.py nginx|haproxy|routez

200 prefixes that cannot match, then 20 regexes of which only the last does, so
a request walks the whole prefix set and every regex before it is answered. The
matching path is /r/deep/x42.z.

This goes in its own config profile: in nginx and routez a regex location is
tried for any path whose longest prefix does not opt out, so leaving these in
the main config would charge every other row for them.
"""
import sys

PREFIXES = 200
REGEXES = 20
MISS = r"^/r/miss{:02d}/([0-9]+)\.z$"
HIT = r"^/r/deep/x([0-9]+)\.z$"


def patterns():
    return [MISS.format(i) for i in range(REGEXES - 1)] + [HIT]


kind = sys.argv[1]
out = []
if kind == "nginx":
    for i in range(PREFIXES):
        out.append(f'location /p{i:03d}/ {{ return 200 "pong"; }}')
    for pat in patterns():
        out.append(f'location ~ {pat} {{ return 200 "pong"; }}')
elif kind == "routez":
    ret = '.@"return" = .{ .body = "pong", .content_type = "text/plain" }'
    for i in range(PREFIXES):
        out.append(f'.{{ .prefix = "/p{i:03d}/", {ret} }},')
    for pat in patterns():
        out.append(f'.{{ .regex = "{pat.replace(chr(92), chr(92) * 2)}", {ret} }},')
elif kind == "haproxy":
    ret = "http-request return status 200 content-type text/plain string pong if"
    for i in range(PREFIXES):
        out.append(f"{ret} {{ path_beg /p{i:03d}/ }}")
    for pat in patterns():
        out.append(f"{ret} {{ path_reg {pat} }}")
else:
    sys.exit(f"unknown kind {kind}")
print("\n".join(out))

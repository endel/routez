#!/usr/bin/env python3
"""Proves a server answers every request in a pipelined batch.

    pipecheck.py <url> <depth> <expected-body>

The pipelined row claims a large win over servers that answer one at a time, so
the gate checks the batch really is answered in full, not coalesced or dropped.
"""
import socket
import sys
import urllib.parse

url, depth, body = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
u = urllib.parse.urlparse(url)
req = f"GET {u.path} HTTP/1.1\r\nHost: {u.hostname}\r\nConnection: keep-alive\r\n\r\n".encode()
sock = socket.create_connection((u.hostname, u.port), 10)
sock.settimeout(10)
sock.sendall(req * depth)
buf = b""
while buf.count(b"HTTP/1.1 200") < depth:
    chunk = sock.recv(65536)
    if not chunk:
        sys.exit(f"closed after {buf.count(b'HTTP/1.1 200')} of {depth} responses")
    buf += chunk
got = buf.count(body)
if got != depth:
    sys.exit(f"{got} bodies for {depth} pipelined requests")

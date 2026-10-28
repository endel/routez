"""A TLS connection whose fingerprint is banned after it opened: closed at
once. It learns its own JA4 from the x-ja4 header, bans it, then lifts the
ban. Prints the status of its request and what became of the connection.
Usage: ban_fingerprint.py PORT CA ROUTEZ_BIN CONTROL_SOCKET"""
import socket
import ssl
import subprocess
import sys

port, ca, routez, sock = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
ctx = ssl.create_default_context(cafile=ca)
ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="127.0.0.1")
s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
got = b""
while b"\r\n\r\n" not in got:
    got += s.recv(4096)
head, body = got.split(b"\r\n\r\n", 1)
lines = head.split(b"\r\n")
field = lambda name: next(l.split(b":", 1)[1].strip().decode() for l in lines if l.lower().startswith(name + b":"))
while len(body) < int(field(b"content-length")):
    body += s.recv(4096)
ja4 = field(b"x-ja4")
ctl = lambda *args: subprocess.run([routez, "ctl", "-s", sock, *args], check=True, capture_output=True)
ctl("ban", ja4, "60")
s.settimeout(2)
try:
    seen = "closed" if s.recv(4096) == b"" else "data"
except (ConnectionResetError, ssl.SSLError):
    seen = "closed"
except socket.timeout:
    seen = "open"
ctl("unban", ja4)
print(lines[0].split(b" ")[1].decode(), seen)

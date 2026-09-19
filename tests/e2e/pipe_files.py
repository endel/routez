# Pipelined static requests on one connection: each response whole and in
# order, bodies byte-exact.
import socket, sys

big = open(sys.argv[1], "rb").read()
small = open(sys.argv[2], "rb").read()
reqs = [
    (b"GET /big.bin", b"", 200, big),
    (b"GET /big.bin", b"Range: bytes=1000-2000999\r\n", 206, big[1000:2001000]),
    (b"HEAD /big.bin", b"", 200, b""),
    (b"GET /sub/a.txt", b"", 200, small),
    (b"GET /big.bin", b"Range: bytes=-5\r\n", 206, big[-5:]),
    (b"GET /big.bin", b"Connection: close\r\n", 200, big),
]
s = socket.create_connection(("127.0.0.1", 18080))
s.sendall(b"".join(r + b" HTTP/1.1\r\nHost: a\r\n" + h + b"\r\n" for r, h, _, _ in reqs))
s.settimeout(10)
data = b""
while True:
    d = s.recv(1 << 20)
    if not d:
        break
    data += d
for i, (req, _, status, body) in enumerate(reqs):
    end = data.index(b"\r\n\r\n") + 4
    head = data[:end].decode()
    if not head.startswith("HTTP/1.1 %d" % status):
        sys.exit("response %d: %r" % (i, head.split("\r\n")[0]))
    n = len(body)
    if data[end:end + n] != body:
        sys.exit("response %d: body differs" % i)
    data = data[end + n:]
print("ok" if not data else "trailing bytes")

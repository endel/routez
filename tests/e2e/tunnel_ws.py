# WebSocket echo through a tunnel: connects to 127.0.0.1:PORT naming HOST,
# sends three messages (one 100 KB) and prints "ws-ok" if each comes back
# as "echo:<message>" (tests/e2e/ws_upstream.ts). Not ws_client.mjs: bun
# 1.2 on Linux sends a second Host header rather than replacing it.
import base64, os, socket, struct, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port), 5)
s.settimeout(5)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall(f"GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
          f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(4096)
    if not chunk: print("ws-closed-before-upgrade"); sys.exit(1)
    buf += chunk
head, buf = buf.split(b"\r\n\r\n", 1)
status = head.split(b"\r\n")[0].decode()
if " 101 " not in status: print("ws-no-upgrade", status); sys.exit(1)

def exact(n):
    global buf
    while len(buf) < n:
        chunk = s.recv(65536)
        if not chunk: raise EOFError
        buf += chunk
    out, buf = buf[:n], buf[n:]
    return out

def send(payload):
    mask, n = os.urandom(4), len(payload)
    if n < 126: hdr = bytes([0x81, 0x80 | n])
    elif n < 65536: hdr = bytes([0x81, 0x80 | 126]) + struct.pack(">H", n)
    else: hdr = bytes([0x81, 0x80 | 127]) + struct.pack(">Q", n)
    m = (mask * (n // 4 + 1))[:n]
    s.sendall(hdr + mask + bytes(a ^ b for a, b in zip(payload, m)))

def recv():
    b0, b1 = exact(2)
    n = b1 & 0x7f
    if n == 126: n = struct.unpack(">H", exact(2))[0]
    elif n == 127: n = struct.unpack(">Q", exact(8))[0]
    return exact(n)

msgs = [b"a", b"b", b"c" * 100000]
for m in msgs: send(m)
try:
    ok = all(recv() == b"echo:" + m for m in msgs)
except (EOFError, socket.timeout) as e:
    print("ws-cut", type(e).__name__); sys.exit(1)
print("ws-ok" if ok else "ws-mismatch")

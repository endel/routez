# Connect as a load balancer would: a PROXY protocol header, then an HTTP
# request. Prints the response body (the status with --status), or
# "closed" when the server closes without answering.
#
# usage: proxy_protocol.py HOST PORT KIND PATH [--tls] [--status] [--xff VALUE]
#   KIND: v1:ADDR, v2:ADDR, v2-local, none (no header), silent (send nothing)
import ipaddress, socket, ssl, struct, sys, time

host, port, kind, path = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
flags = sys.argv[5:]
xff = flags[flags.index("--xff") + 1] if "--xff" in flags else None

s = socket.create_connection((host, port), 5)
dst = s.getsockname()[0]
if kind.startswith("v1:"):
    src = kind[3:]
    fam = "TCP6" if ":" in src else "TCP4"
    d = dst if (":" in dst) == (fam == "TCP6") else ("::1" if fam == "TCP6" else "127.0.0.1")
    s.sendall(f"PROXY {fam} {src} {d} 40000 {port}\r\n".encode())
elif kind.startswith("v2:"):
    src = ipaddress.ip_address(kind[3:])
    if src.version == 4:
        body = src.packed + ipaddress.ip_address("127.0.0.1").packed + struct.pack("!HH", 40000, port)
        fam = 0x11
    else:
        body = src.packed + ipaddress.ip_address("::1").packed + struct.pack("!HH", 40000, port)
        fam = 0x21
    body += b"\x04\x00\x02zz"  # a NOOP TLV
    s.sendall(b"\r\n\r\n\x00\r\nQUIT\n" + bytes([0x21, fam]) + struct.pack("!H", len(body)) + body)
elif kind == "v2-local":
    s.sendall(b"\r\n\r\n\x00\r\nQUIT\n\x20\x00\x00\x00")
elif kind == "silent":
    s.settimeout(10)
    start = time.time()
    try:
        data = s.recv(1)
    except (socket.timeout, ConnectionResetError):
        data = None
    print("closed" if data == b"" or (data is None and time.time() - start < 9) else "open")
    sys.exit(0)

if "--tls" in flags:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = ctx.wrap_socket(s, server_hostname="localhost")
    except (ssl.SSLError, OSError):
        print("closed")
        sys.exit(0)

req = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
if xff:
    req += f"X-Forwarded-For: {xff}\r\n"
data = b""
try:
    s.sendall((req + "\r\n").encode())
    while True:
        d = s.recv(65536)
        if not d:
            break
        data += d
except (OSError, ssl.SSLError):
    pass
if not data:
    print("closed")
    sys.exit(0)
head, _, body = data.partition(b"\r\n\r\n")
status = head.split(b" ")[1].decode()
print(status if "--status" in flags else body.decode())

import socket, sys
s = socket.create_connection(("127.0.0.1", 18080))
reqs = sys.argv[1].encode().decode('unicode_escape').encode()
s.sendall(reqs)
s.settimeout(3)
data = b""
try:
    while True:
        d = s.recv(65536)
        if not d: break
        data += d
except socket.timeout:
    data += b"<TIMEOUT>"
print(repr(data))

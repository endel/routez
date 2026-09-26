# A pipelined request ahead of one whose file shrank: the first response
# arrives whole, the second as far as the file went. Prints each response's
# status and body bytes against its Content-Length.
import socket, sys

s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"GET /sub/a.txt HTTP/1.1\r\nHost: a\r\n\r\nGET /%s HTTP/1.1\r\nHost: a\r\n\r\n" % sys.argv[2].encode())
s.settimeout(10)
data = b""
while d := s.recv(1 << 16):
    data += d
out = []
while data:
    end = data.index(b"\r\n\r\n") + 4
    head = data[:end].decode().split("\r\n")
    n = next(int(h.split(":")[1]) for h in head if h.lower().startswith("content-length:"))
    out.append("%s %d/%d" % (head[0].split()[1], len(data[end:end + n]), n))
    data = data[end + n:]
print(", ".join(out))

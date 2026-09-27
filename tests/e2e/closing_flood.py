# Ask for a response with Connection: close and never read it, then send
# argv[3] MiB more. The server is flushing to close by then: what it reads
# is no longer parsed, so it must not be buffered either. Its RSS (pid
# argv[4]) is read with the connection still open.
import socket, subprocess, sys

def rss():
    return int(subprocess.check_output(["ps", "-o", "rss=", "-p", sys.argv[4]]))

base = rss()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
s.connect(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"GET /%s HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n" % sys.argv[2].encode())
s.settimeout(10)
junk = b"x" * (1 << 20)
for _ in range(int(sys.argv[3])):
    s.sendall(junk)
grew = rss() - base
print("bounded" if grew < 16384 else "grew %d KB" % grew)

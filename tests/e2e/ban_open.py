"""A connection opened before its client is banned: closed once the ban is
made, whether or not it sends another request. Prints what it saw.
Usage: ban_open.py PORT ROUTEZ_BIN CONTROL_SOCKET request|idle|tunnel|udp
  request  a keep-alive connection that sends a second request
  idle     one that just waits
  tunnel   a tcp_proxy tunnel to a keep-alive HTTP upstream
  udp      a udp_proxy flow to the echo server this starts on 19011"""
import http.client
import socket
import subprocess
import sys
import threading
import time

port, routez, sock, mode = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]


def ban():
    subprocess.run([routez, "ctl", "-s", sock, "ban", "127.0.0.1", "60"], check=True, capture_output=True)


def closed_within(s, seconds):
    s.settimeout(seconds)
    try:
        return "closed" if s.recv(1) == b"" else "data"
    except ConnectionResetError:
        return "closed"
    except socket.timeout:
        return "open"


if mode == "udp":
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(("127.0.0.1", 19011))

    def serve():
        while True:
            data, addr = echo.recvfrom(2048)
            echo.sendto(data, addr)

    threading.Thread(target=serve, daemon=True).start()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)

    def echoed():
        s.sendto(b"ping", ("127.0.0.1", port))
        try:
            return "echoed" if s.recv(16) == b"ping" else "garbled"
        except socket.timeout:
            return "dropped"

    first = echoed()
    ban()
    time.sleep(0.4)  # a worker tick: the flow goes, so this one is new
    print(first, echoed())
    sys.exit()

if mode == "tunnel":
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    # A response proves the tunnel is up before the ban, not refused at accept.
    s.sendall(b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n")
    got = b""
    while b"pong" not in got:
        got += s.recv(4096)
    ban()
    print(got[:12].decode(), closed_within(s, 2))
    sys.exit()

conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("GET", "/")
first = conn.getresponse()
first.read()
ban()
if mode == "idle":
    print(first.status, closed_within(conn.sock, 2))
    sys.exit()
try:
    conn.request("GET", "/")
    second = f"answered {conn.getresponse().status}"
except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError):
    second = "closed"
print(first.status, second)

"""A keep-alive connection whose client is banned between two requests: the
second gets no response, the connection closes. Prints the first status and
what happened to the second.
Usage: ban_keepalive.py PORT ROUTEZ_BIN CONTROL_SOCKET"""
import http.client
import subprocess
import sys

port, routez, sock = int(sys.argv[1]), sys.argv[2], sys.argv[3]
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("GET", "/")
first = conn.getresponse()
first.read()
subprocess.run([routez, "ctl", "-s", sock, "ban", "127.0.0.1", "60"], check=True, capture_output=True)
try:
    conn.request("GET", "/")
    second = f"answered {conn.getresponse().status}"
except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError):
    second = "closed"
print(first.status, second)

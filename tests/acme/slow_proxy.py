"""TCP proxy that holds each connection for a while before forwarding it.
usage: slow_proxy.py <listen-port> <upstream-port> <delay-s>
Upstream port 0: never forward; the peer just sees silence."""
import socket, sys, threading, time

listen, upstream, delay = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])

def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    for s in (a, b):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

def handle(c):
    if upstream == 0:
        time.sleep(3600)
        return
    time.sleep(delay)
    u = socket.create_connection(("127.0.0.1", upstream))
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    pipe(u, c)

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", listen))
srv.listen(16)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()

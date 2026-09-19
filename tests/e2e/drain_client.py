# Slow clients downloading while the server is told to stop or reload.
#
#   drain_client.py <server pid> <HUP|TERM> <sync port> <client>...
#   client = plain|tls : port : path : bytes per second : sync|nosync|reset
#
# A "sync" client pipelines a request for /drain-sync/ after its download.
# The server takes it (a proxy to us, on the sync port) only once the
# download's response is fully produced, while much of it may still be
# queued on its side; once every sync client's request has arrived and been
# answered, the signal is sent. Each client then reads the rest and expects
# every byte, then the server's close. A "reset" client drops its connection
# at the sync point instead. Prints one word per client: ok, reset, or what
# went wrong.
import os, signal, socket, ssl, sys, threading, time

pid, sig, sync_port = int(sys.argv[1]), getattr(signal, "SIG" + sys.argv[2]), int(sys.argv[3])
specs = [a.split(":") for a in sys.argv[4:]]
syncing = sum(1 for s in specs if s[4] != "nosync")
arrived = 0
lock = threading.Lock()
signalled = threading.Event()


def upstream():
    global arrived
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", sync_port))
    ls.listen(16)
    ls.settimeout(30)
    while not signalled.is_set():
        try:
            c, _ = ls.accept()
        except OSError:
            break
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = c.recv(4096)
            if not d:
                break
            buf += d
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        c.close()
        with lock:
            arrived += 1
            last = arrived == syncing
        if last:
            # Let the server finish these answers, so the connections are idle.
            time.sleep(0.2)
            os.kill(pid, sig)
            signalled.set()


def head_end(data, start):
    i = data.find(b"\r\n\r\n", start)
    return -1 if i < 0 else i + 4


def client(spec, results, i):
    proto, port, path, rate, mode = spec[0], int(spec[1]), spec[2], int(spec[3]), spec[4]
    want = open(os.path.join(os.environ["WWW"], path.lstrip("/")), "rb").read()
    s = socket.socket()
    # A small receive window, so the server can't hand everything to the kernel.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
    s.connect(("127.0.0.1", port))
    if proto == "tls":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s)
    req = b"GET %s HTTP/1.1\r\nHost: a\r\n\r\n" % path.encode()
    if mode != "nosync":
        req += b"GET /drain-sync/ HTTP/1.1\r\nHost: a\r\n\r\n"
    s.sendall(req)
    s.settimeout(15)
    data = b""
    t0 = time.time()
    while True:
        if mode == "reset" and signalled.is_set():
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
            s.close()
            results[i] = "reset"
            return
        try:
            d = s.recv(16384)
        except Exception as e:
            results[i] = "error:%s@%d" % (type(e).__name__, len(data))
            return
        if not d:
            break
        data += d
        lag = len(data) / rate - (time.time() - t0)
        if lag > 0:
            time.sleep(lag)
    end = head_end(data, 0)
    if end < 0 or not data.startswith(b"HTTP/1.1 200"):
        results[i] = "bad-head@%d" % len(data)
        return
    body = data[end:end + len(want)]
    if body != want:
        results[i] = "short:%d/%d" % (len(body), len(want))
        return
    rest = data[end + len(want):]
    if mode != "nosync" and not (rest.startswith(b"HTTP/1.1 200") and rest.endswith(b"\r\n\r\nok")):
        results[i] = "no-sync-answer"
        return
    results[i] = "ok"


threading.Thread(target=upstream, daemon=True).start()
results = [None] * len(specs)
threads = [threading.Thread(target=client, args=(s, results, i)) for i, s in enumerate(specs)]
for t in threads:
    t.start()
for t in threads:
    t.join()
print(" ".join(r or "none" for r in results))

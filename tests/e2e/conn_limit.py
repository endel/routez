import socket, sys, time
# Hold N idle connections; count how many the server closed right away.
n = int(sys.argv[1])
socks = [socket.create_connection(("127.0.0.1", 18080)) for _ in range(n)]
time.sleep(0.5)
closed = 0
for s in socks:
    s.setblocking(False)
    try:
        if s.recv(1) == b"":
            closed += 1
    except BlockingIOError:
        pass
    except ConnectionResetError:
        closed += 1
print(closed)

"""A UDP NAT that rebinds: client traffic reaches the server from one source
port, then after `switch_after` seconds from a new one, as when a NAT drops
a mapping. Usage: nat_relay.py LISTEN_PORT SERVER_PORT SWITCH_AFTER_PACKETS"""
import select, socket, sys, time

listen_port, server_port, switch_after = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
server = ("127.0.0.1", server_port)
front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
front.bind(("127.0.0.1", listen_port))
flows = {}  # client addr -> [upstream socket, client packets so far, switched]
by_sock = {}

def upstream_for(client):
    f = flows.get(client)
    if f is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0))
        f = flows[client] = [s, 0, False]; by_sock[s] = client
    f[1] += 1
    if not f[2] and f[1] > switch_after:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0))
        by_sock[s] = client  # the old socket keeps relaying late replies
        f[0], f[2] = s, True
    return f[0]

print("ready", flush=True)
while True:
    ready, _, _ = select.select([front] + list(by_sock), [], [], 1.0)
    for s in ready:
        data, addr = s.recvfrom(65535)
        if s is front:
            upstream_for(addr).sendto(data, server)
        else:
            front.sendto(data, by_sock[s])

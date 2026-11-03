# Requests through a tunnel from many clients at once, each on its own
# keep-alive connection naming HOST: prints "ok" when every one got a 200
# with the expected body, else the statuses seen.
import collections, http.client, json, sys, threading
host, port, clients, per_client = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
seen = collections.Counter()
lock = threading.Lock()
def run(i):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    for j in range(per_client):
        path = f"/load/{i}/{j}"
        try:
            c.request("GET", path, headers={"Host": host})
            r = c.getresponse()
            body = r.read()
            ok = r.status == 200 and json.loads(body)["path"] == path
            key = "200" if ok else str(r.status)
        except Exception as e:
            key = type(e).__name__
            c.close()
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        with lock: seen[key] += 1
threads = [threading.Thread(target=run, args=(i,)) for i in range(clients)]
for t in threads: t.start()
for t in threads: t.join()
print("ok" if seen == {"200": clients * per_client} else dict(seen))

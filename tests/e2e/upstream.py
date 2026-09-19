import http.server, sys, json, ssl, gzip, random
# Text that doesn't shrink much: gzipped, still past routez's 1 KiB minimum.
NOISE = "".join(random.Random(1).choice("0123456789abcdef") for _ in range(8000)).encode()
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _reply(self, code, body, ctype="application/json", chunked=False, headers=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("X-Upstream-Port", str(self.server.server_port))
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(body), 1000):
                part = body[i:i+1000]
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    def do_GET(self):
        if self.path.startswith("/chunked"):
            return self._reply(200, b"x" * 5000, "text/plain", chunked=True)
        if self.path.startswith("/bytes/"):
            n = int(self.path[len("/bytes/"):])
            return self._reply(200, bytes(i % 251 for i in range(n)), "application/octet-stream")
        if self.path == "/gzipped":
            return self._reply(200, gzip.compress(NOISE, mtime=0), "text/plain", headers=[("Content-Encoding", "gzip")])
        if self.path == "/no-transform":
            return self._reply(200, NOISE, "text/plain", headers=[("Cache-Control", "public, no-transform")])
        if self.path == "/noise":
            return self._reply(200, NOISE, "text/plain")
        if self.path == "/healthz":
            return self._reply(200, b"ok", "text/plain")
        reply = {"path": self.path, "headers": dict(self.headers), "port": self.server.server_port, "peer_port": self.client_address[1]}
        cert = self.connection.getpeercert() if hasattr(self.connection, "getpeercert") else None
        if cert:
            reply["client_cn"] = dict(x[0] for x in cert["subject"])["commonName"]
        body = json.dumps(reply).encode()
        self._reply(200, body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if self.headers.get("Transfer-Encoding") == "chunked":
            data = b""
            while True:
                size = int(self.rfile.readline().strip(), 16)
                if size == 0:
                    self.rfile.readline(); break
                data += self.rfile.read(size); self.rfile.readline()
        else:
            data = self.rfile.read(n)
        self._reply(200, json.dumps({"received": len(data), "port": self.server.server_port}).encode())
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H)
if len(sys.argv) > 3:  # HTTPS: upstream.py PORT CERT KEY [CLIENT_CA]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[2], sys.argv[3])
    if len(sys.argv) > 4:  # clients must present a certificate from CLIENT_CA
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(sys.argv[4])
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()

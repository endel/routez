import http.server, sys, json
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _reply(self, code, body, ctype="application/json", chunked=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
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
        if self.path == "/healthz":
            return self._reply(200, b"ok", "text/plain")
        body = json.dumps({"path": self.path, "headers": dict(self.headers), "port": self.server.server_port}).encode()
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
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()

import http.server, time, sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        if self.path.startswith("/big"):
            body = open(sys.argv[1] + "/big.bin","rb").read()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body); return
        time.sleep(3)
        self.send_response(200); self.send_header("Content-Length","4"); self.end_headers(); self.wfile.write(b"late")
    def do_POST(self):
        # Reads the body slowly, so the proxy has to hold the client back.
        left = int(self.headers.get("Content-Length") or 0)
        n = 0
        if self.headers.get("Transfer-Encoding") == "chunked":
            while True:
                size = int(self.rfile.readline().strip(), 16)
                if size == 0:
                    self.rfile.readline(); break
                while size:
                    part = self.rfile.read(min(size, 65536)); size -= len(part); n += len(part); time.sleep(0.005)
                self.rfile.readline()
        while left:
            part = self.rfile.read(min(left, 65536)); left -= len(part); n += len(part); time.sleep(0.005)
        body = str(n).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", 19004), H).serve_forever()

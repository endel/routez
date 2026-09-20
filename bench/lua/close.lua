-- A new connection per request: the server pays a handshake each time.
wrk.headers["Connection"] = "close"

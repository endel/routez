Bun.serve({
  port: 19003, hostname: "127.0.0.1",
  fetch(req, server) {
    if (server.upgrade(req, { data: { path: new URL(req.url).pathname } })) return;
    return new Response("not a websocket", { status: 400 });
  },
  websocket: { message(ws, msg) { ws.send(typeof msg === "string" ? "echo:" + msg : msg); } },
});

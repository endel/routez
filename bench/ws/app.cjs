// The WebSocket app behind every proxy: a `ws` echo server in one process.
// Usage: node app.cjs PORT...
// Several ports because each proxy→app address pair has only ~64k source ports.
const { WebSocketServer } = require("ws"); // CommonJS: ESM ignores NODE_PATH

for (const port of process.argv.slice(2).map(Number)) {
  const wss = new WebSocketServer({ host: "127.0.0.1", port, backlog: 65535, perMessageDeflate: false });
  wss.on("connection", (ws) => ws.on("message", (data, binary) => ws.send(data, { binary })));
}

const ws = new WebSocket(process.argv[2]);
const want = ["a", "b", "c".repeat(100000)];
const got = [];
ws.onopen = () => want.forEach((m) => ws.send(m));
ws.onmessage = (e) => { got.push(e.data); if (got.length === want.length) {
  const ok = want.every((m, i) => got[i] === "echo:" + m);
  console.log(ok ? "ws-ok" : "ws-mismatch"); ws.close(); } };
ws.onclose = () => process.exit(0);
ws.onerror = (e) => { console.log("ws-error", e.message); process.exit(1); };
setTimeout(() => { console.log("ws-timeout"); process.exit(1); }, 5000);

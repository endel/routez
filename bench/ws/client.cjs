// WebSocket load generator for ws.sh.
//
//   node client.cjs --check URL
//       One upgrade and echo round-trip; exits non-zero on failure.
//   node client.cjs URL[,URL...] N
//       Opens N connections (spread over the URLs) from CLIENTS worker
//       processes, holds them idle for HOLD s, then sends RATE echoes a second
//       in total for DURATION s, round-robin over the connections. Prints one
//       JSON line.
//
// HOOK names an executable run with the phase name ("held", "load0",
// "load1") at each boundary, so ws.sh can sample the server.
const { fork, execFileSync } = require("node:child_process");
const { performance } = require("node:perf_hooks");
const { WebSocket } = require("ws"); // CommonJS: ESM ignores NODE_PATH

const env = (k, d) => Number(process.env[k] ?? d);
const CLIENTS = env("CLIENTS", 4);
const RATE = env("RATE", 10000);
const HOLD = env("HOLD", 5);
const DURATION = env("DURATION", 10);
const IN_FLIGHT = 256; // handshakes per worker
const TICK_MS = 10;
const DRAIN_MS = 3000;
const MSG_BYTES = 32;
// Log2 histogram with 8 buckets per octave: ~9% resolution.
const SUB = 8;
const BUCKETS = 64 * SUB;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const noop = () => {};

if (process.argv[2] === "--check") check(process.argv[3]);
else if (process.argv[2] === "--worker") worker(Number(process.argv[3]));
else parent(process.argv[2].split(","), Number(process.argv[3]));

function check(url) {
  const ws = new WebSocket(url, { perMessageDeflate: false });
  const fail = (why) => { console.log(`ws check ${url}: ${why}`); process.exit(1); };
  setTimeout(() => fail("timeout"), 5000).unref();
  ws.on("open", () => ws.send("ping"));
  ws.on("message", (d) => { if (String(d) !== "ping") fail(`echoed '${d}'`); ws.close(); process.exit(0); });
  ws.on("error", (e) => fail(e.message));
}

async function parent(urls, n) {
  const kids = [...Array(CLIENTS)].map((_, i) => fork(__filename, ["--worker", String(i)]));
  const ask = (msg) => Promise.all(kids.map((k) => new Promise((r) => { k.once("message", r); k.send(msg); })));
  const hook = (phase) => process.env.HOOK && execFileSync(process.env.HOOK, [phase], { stdio: "inherit" });
  await Promise.all(kids.map((k) => new Promise((r) => k.once("message", r)))); // loaded, so startup isn't timed

  const t0 = performance.now();
  const opened = await ask({ cmd: "connect", urls, n });
  const connectMs = performance.now() - t0;
  await sleep(HOLD * 1000);
  hook("held");

  const loadDone = ask({ cmd: "load" });
  hook("load0");
  await sleep(DURATION * 1000);
  hook("load1");
  const loads = await loadDone;
  await ask({ cmd: "close" });

  const hist = new Array(BUCKETS).fill(0);
  for (const l of loads) l.hist.forEach((c, i) => (hist[i] += c));
  const sum = (xs, k) => xs.reduce((a, x) => a + x[k], 0);
  const received = sum(loads, "received");
  const pct = (p) => {
    let want = Math.ceil(received * p), seen = 0;
    for (let i = 0; i < BUCKETS; i++) if ((seen += hist[i]) >= want && want > 0) return Math.round(2 ** ((i + 0.5) / SUB));
    return 0;
  };
  console.log(JSON.stringify({
    n, in_flight: IN_FLIGHT, connected: sum(opened, "connected"), failed: sum(opened, "failed"), connect_ms: Math.round(connectMs),
    sent: sum(loads, "sent"), received, dropped: sum(loads, "dropped"),
    p50_us: pct(0.5), p99_us: pct(0.99), p999_us: pct(0.999),
  }));
  process.exit(0);
}

function worker(id) {
  // A source address per worker: each has its own ~64k ports to each target.
  const localAddress = `127.0.0.${2 + id}`;
  const conns = [];
  const hist = new Array(BUCKETS).fill(0);
  let received = 0, dropped = 0;

  const onMessage = (data) => {
    const us = (performance.now() - data.readDoubleLE(0)) * 1000;
    hist[Math.min(BUCKETS - 1, Math.max(0, Math.floor(Math.log2(Math.max(1, us)) * SUB)))]++;
    received++;
  };

  const connect = async ({ urls, n }) => {
    const mine = Math.floor(n / CLIENTS) + (id < n % CLIENTS ? 1 : 0);
    let next = 0, failed = 0;
    const one = () => new Promise((resolve) => {
      const i = next++;
      const ws = new WebSocket(urls[(i * CLIENTS + id) % urls.length], { localAddress, perMessageDeflate: false });
      ws.once("open", () => {
        ws.removeAllListeners("error");
        ws.on("error", noop);
        ws.on("message", onMessage);
        ws.on("close", () => { if (!ws.closing) dropped++; });
        conns.push(ws);
        resolve();
      });
      ws.once("error", () => { failed++; resolve(); });
    });
    const lane = async () => { while (next < mine) await one(); };
    await Promise.all([...Array(Math.min(IN_FLIGHT, mine))].map(lane));
    return { connected: conns.length, failed };
  };

  const load = async () => {
    const perMs = RATE / CLIENTS / 1000;
    const buf = Buffer.alloc(MSG_BYTES);
    const start = Date.now();
    let sent = 0;
    while (conns.length && Date.now() - start < DURATION * 1000) {
      const due = Math.floor((Date.now() - start) * perMs);
      for (; sent < due; sent++) {
        buf.writeDoubleLE(performance.now(), 0);
        conns[sent % conns.length].send(buf, { binary: true });
      }
      await sleep(TICK_MS);
    }
    const until = Date.now() + DRAIN_MS;
    while (received < sent && Date.now() < until) await sleep(10);
    return { sent, received, dropped, hist };
  };

  process.send({});
  process.on("message", async (msg) => {
    if (msg.cmd === "connect") process.send(await connect(msg));
    else if (msg.cmd === "load") process.send(await load());
    else if (msg.cmd === "close") {
      for (const ws of conns) { ws.closing = true; ws.terminate(); }
      process.send({});
      process.exit(0);
    }
  });
}

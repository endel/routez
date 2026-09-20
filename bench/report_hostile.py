#!/usr/bin/env python3
"""Turns hostile.sh's raw runs in OUT/raw into OUT/results.jsonl and OUT/table.md.

Every row is read against the same server's quiet baseline, so a figure says
what the abuse cost that server rather than how fast it is.
"""
import json
import re
import sys
from pathlib import Path

from rig import (METRICS, busy, cpu_list, cpu_ms_per_1k, load_env, med, proc_stat, rate,
                 read_int, row, write_jsonl)

SERVERS = [("nginx", "nginx"), ("haproxy", "HAProxy"), ("routez", "routez")]
LABEL = dict(SERVERS)
ROWS = {
    "idle": ("Parked keep-alive connections", "hold"),
    "slowhead": ("Request heads that never end", "hold"),
    "slowread": ("Clients reading a 1 MB body a trickle at a time", "hold"),
    "storm": ("A new connection per request", "storm"),
    "handshake-ecdsa": ("Full TLS handshakes, ECDSA P-256", "handshake"),
    "handshake-rsa": ("Full TLS handshakes, RSA 2048", "handshake"),
    "reload": ("A reload every 2 s under load", "reload"),
    "failover": ("An upstream killed mid-run", "failover"),
}
ERRORS = ("connect", "read", "write", "status", "timeout")


def wrk_json(path: Path):
    lines = [l for l in path.read_text().splitlines() if l.startswith('{"requests"')]
    return json.loads(lines[-1]) if lines else None


out = Path(sys.argv[1])
env = load_env(out)
server_cpus = cpu_list(env["server_cpus"])
load_cpus = cpu_list(env["wrk_cpus"])
back_cpus = cpu_list(env["upstream_cpus"])
held = int(env["held"])

# The quiet baseline per row and server.
base = {}
for f in (out / "raw").glob("*.base.txt"):
    workload, server = f.name.split(".")[:2]
    j = wrk_json(f)
    rss = f.with_suffix(".rss") if f.with_suffix(".rss").exists() else f.parent / f"{workload}.{server}.base.rss"
    base[workload, server] = {
        "rps": round(j["requests"] / (j["duration_us"] / 1e6)) if j else None,
        "p99_us": j["p99_us"] if j else None,
        "rss_kb": read_int(rss),
    }

runs = []
for txt in sorted((out / "raw").glob("*.txt")):
    parts = txt.name[: -len(".txt")].split(".")
    if len(parts) != 3 or parts[2] == "base":
        continue
    workload, server, rnd = parts
    kind = ROWS[workload][1]
    s0, s1 = proc_stat(txt.with_suffix(".stat0")), proc_stat(txt.with_suffix(".stat1"))
    cpu = {"server": busy(s0, s1, server_cpus), "load": busy(s0, s1, load_cpus),
           "upstream": busy(s0, s1, back_cpus)}
    b = base.get((workload, server), {})
    metrics, detail, flags = {}, {"cpu_pct": cpu["server"]}, []
    done = 0

    if kind == "handshake":
        text = txt.read_text()
        m = re.search(r"finished in ([\d.]+)(m?s), ([\d.]+) req/s", text)
        if not m:
            sys.exit(f"no h2load result in {txt}:\n{text}")
        secs = float(m.group(1)) / (1000 if m.group(2) == "ms" else 1)
        n = int(env["handshakes"])
        metrics["handshakes_per_s"] = round(n / secs) if secs else None
        done = n
        fail = re.search(r"(\d+) failed, (\d+) errored, (\d+) timeout", text)
        if fail and any(int(g) for g in fail.groups()):
            flags.append("errors: " + ", ".join(
                f"{g} {k}" for g, k in zip(fail.groups(), ("failed", "errored", "timeout")) if int(g)))
        if "Resumption: no" not in text:
            flags.append("the client resumed a session: not a full handshake")
    else:
        j = wrk_json(txt)
        if not j:
            sys.exit(f"no wrk result in {txt}:\n{txt.read_text()}")
        done = j["requests"]
        secs = j["duration_us"] / 1e6
        rps = round(j["requests"] / secs)
        detail["rps"] = rps
        detail["p99_us"] = j["p99_us"]
        detail["max_us"] = j["max_us"]
        errs = {k: j[k] for k in ERRORS if j[k]}
        if kind in ("reload", "failover"):
            # What leaked out to clients is the result, not the rate.
            metrics["errors"] = sum(errs.values())
            metrics["max_us"] = j["max_us"]
        if kind in ("hold", "storm"):
            metrics["rps_kept_pct"] = 100 * rps / b["rps"] if b.get("rps") else None
            if kind == "storm":
                metrics["rps"] = rps
        if errs and kind not in ("reload", "failover"):
            flags.append("errors: " + ", ".join(f"{n} {k}" for k, n in errs.items()))

    if kind == "hold":
        r0, r1 = (txt.with_suffix(f".rss{i}") for i in (0, 1))
        a, b2 = read_int(r0), read_int(r1)
        if a is not None and b2 is not None:
            metrics["kb_per_conn"] = (b2 - a) / held
        hold = txt.with_suffix(".hold")
        if hold.exists():
            lines = [l for l in hold.read_text().splitlines() if l.startswith("{")]
            if lines:
                h = json.loads(lines[-1])
                detail["held_opened"] = h["opened"]
                if h["failed"]:
                    flags.append(f"{h['failed']} of {held} connections could not be opened")
                if h["closed_by_server"]:
                    detail["closed_by_server"] = h["closed_by_server"]
    rss = txt.with_suffix(".rss")
    v = read_int(rss)
    if v is not None:
        detail["rss_kb"] = v
    metrics["cpu_ms_per_1k"] = cpu_ms_per_1k(s0, s1, server_cpus, done)
    r = row(env, "hostile", workload, server, rnd,
            {"workers": int(env["workers"]), "conns": int(env["conns"])}, metrics, detail, flags)
    r["cpu"] = cpu
    r["base"] = b
    runs.append(r)
write_jsonl(out, runs)

cells = {}
for r in runs:
    cells.setdefault((r["workload"], r["server"]), []).append(r)
order = [w for w in ROWS if any(k[0] == w for k in cells)]

notes = []
marks = {}
for (w, s), rs in cells.items():
    mark = ""
    for r in rs:
        for f in r["flags"]:
            notes.append(f"{LABEL[s]}, {ROWS[w][0].lower()}, round {r['round']}: {f}")
            mark = "†"
    marks[w, s] = mark


def table(head, rows_, cell):
    body = ["| Row | " + " | ".join(l for _, l in SERVERS) + " |", "|---" * (len(SERVERS) + 1) + "|"]
    for w in rows_:
        cols = []
        for s, _ in SERVERS:
            rs = cells.get((w, s))
            cols.append(f"{cell(rs)}{marks[w, s]}" if rs else "—")
        body.append(f"| {ROWS[w][0]} | " + " | ".join(cols) + " |")
    return [head, "", *body, ""]


def fmt(rs, key):
    v = med(rs, key)
    return METRICS[key].fmt(v) if v is not None else "—"


md = [
    f"nginx {env['nginx']}, HAProxy {env['haproxy']}, routez {env['routez']} (quic-zig {env['quic-zig']}), "
    f"{env['workers']} workers each. Median of {env['rounds']} × {env['duration']} s runs. "
    f"Linux {env['kernel']}, {env['cpus']} cpus; pinning: {env['pinning']}. "
    f"routez built with `-Dcpu={env['zig_cpu']}`. {env['date']}.", "",
]
holds = [w for w in order if ROWS[w][1] == "hold"]
if holds:
    md += table(f"**Memory per held connection** (lower is better), with {held:,} of them open: the "
                "server's RSS growth while they are held, divided by their number.", holds,
                lambda rs: fmt(rs, "kb_per_conn"))
    md += table("**Throughput a well-behaved client still gets** (higher is better), against the same "
                "server's quiet baseline.", holds, lambda rs: fmt(rs, "rps_kept_pct"))
storms = [w for w in order if ROWS[w][1] == "storm"]
if storms:
    md += table("**Connections opened and served per second** (higher is better).", storms,
                lambda rs: rate(med(rs, "rps")))
hs = [w for w in order if ROWS[w][1] == "handshake"]
if hs:
    md += table(f"**Full TLS handshakes per second** (higher is better), {int(env['handshakes']):,} "
                "connections, no session offered.", hs, lambda rs: fmt(rs, "handshakes_per_s"))
    md += table("**CPU per 1000 handshakes** (lower is better).", hs, lambda rs: fmt(rs, "cpu_ms_per_1k"))
disrupt = [w for w in order if ROWS[w][1] in ("reload", "failover")]
if disrupt:
    md += table("**Requests that failed** (lower is better): what reached a client as a socket error or "
                "a non-2xx while the server was disrupted.", disrupt, lambda rs: fmt(rs, "errors"))
    md += table("**Longest request** (lower is better) during the disruption.", disrupt,
                lambda rs: fmt(rs, "max_us"))
if notes:
    md.append("† " + "; ".join(sorted(set(notes))) + ".")

detail = ["| Row | Server | req/s | p99 | max | RSS | CPU ms/1k | CPU % server / load / upstream |",
          "|---" * 8 + "|"]
for w in order:
    for s, slabel in SERVERS:
        rs = cells.get((w, s))
        if not rs:
            continue
        cpu = rs[0]["cpu"]
        r0 = med(rs, "rps")
        detail.append(
            f"| {ROWS[w][0]} | {slabel} | {rate(r0) if r0 is not None else '—'} | {fmt(rs, 'p99_us')} "
            f"| {fmt(rs, 'max_us')} | {fmt(rs, 'rss_kb')} | {fmt(rs, 'cpu_ms_per_1k')} "
            f"| {cpu['server']} / {cpu['load']} / {cpu['upstream']} |")
md += ["", "— HAProxy isn't a file server, so it sits out the row that asks for one.",
       "", "All figures, per row.", "", *detail, ""]
(out / "table.md").write_text("\n".join(md))

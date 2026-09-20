#!/usr/bin/env python3
"""Turns ws.sh's raw runs in OUT/raw into OUT/results.jsonl and OUT/table.md.

Each figure is the median of its own across rounds: memory, latency and
connect rate don't move together, so no single round represents them all.
"""
import json
import statistics
import sys
from pathlib import Path

from rig import (METRICS, SATURATED, busy, cpu_list, load_env, med, ms,
                 proc_stat, row, write_jsonl)

SERVERS = [("direct", "No proxy"), ("nginx", "nginx"), ("haproxy", "HAProxy"), ("routez", "routez")]
PROXIES = SERVERS[1:]
LABEL = dict(SERVERS)


def rss(path):
    return {phase: (int(srv), int(app), int(est))
            for phase, srv, app, est in (line.split() for line in path.read_text().splitlines())}


out = Path(sys.argv[1])
env = load_env(out)
groups = {g: cpu_list(env[f"{g}_cpus"]) for g in ("server", "app", "client")}

runs, in_flight = [], None
for js in sorted((out / "raw").glob("*.json")):
    n, server, rnd = js.stem.split(".")
    n = int(n)
    lines = [l for l in js.read_text().splitlines() if l.startswith('{"n"')]
    err = js.with_suffix(".err")
    if not lines:
        sys.exit(f"no client result in {js}:\n{js.read_text()}{err.read_text() if err.exists() else ''}")
    j = json.loads(lines[-1])
    in_flight = j["in_flight"]
    m = rss(js.with_suffix(".rss"))
    s0, s1 = proc_stat(js.with_suffix(".stat0")), proc_stat(js.with_suffix(".stat1"))
    cpu = {g: busy(s0, s1, c) for g, c in groups.items()}
    problems = {k: v for k, v in {
        "failed to connect": j["failed"],
        "dropped": j["dropped"],
        "lost echoes": j["sent"] - j["received"],
    }.items() if v}
    if m["held"][2] != n:
        problems[f"of {n} connections at the app"] = m["held"][2]
    flags = ["problems: " + ", ".join(f"{v} {k}" for k, v in problems.items())] if problems else []
    if max(cpu["client"], cpu["app"]) >= SATURATED:
        flags.append(f"rig {max(cpu['client'], cpu['app'])}% busy")
    r = row(env, "ws", "tunnel", server, rnd, {"level": n, "workers": 1},
            {"kb_per_conn": (m["held"][0] - m["base"][0]) / n if server != "direct" else None,
             "connect_per_s": round(j["connected"] / max(1, j["connect_ms"]) * 1000),
             "echoes_per_s": round(j["received"] / float(env["duration"])),
             # The load is a fixed total echo rate, so latency and CPU do compare.
             "p50_us": j["p50_us"], "p99_us": j["p99_us"], "p999_us": j["p999_us"],
             "cpu_pct": cpu["server"] if server != "direct" else None},
            flags=flags)
    r["app_kb_per_conn"] = (m["held"][1] - m["base"][1]) / n
    r["cpu"] = cpu
    r["problems"] = problems
    runs.append(r)
write_jsonl(out, runs)

cells = {}
for r in runs:
    cells.setdefault((r["params"]["level"], r["server"]), []).append(r)
levels = sorted({r["params"]["level"] for r in runs})


def med_cpu(rs, g):
    return round(statistics.median(r["cpu"][g] for r in rs))


# Footnote marks per cell: † a round had problems, ‡ the rig was the limit.
pinned = not env["pinning"].startswith("none")
marks, notes = {}, []
for (n, s), rs in sorted(cells.items()):
    mark = ""
    for r in rs:
        if r["problems"]:
            notes.append(f"{LABEL[s]}, {n} connections, round {r['round']}: "
                         + ", ".join(f"{v} {k}" for k, v in r["problems"].items()))
            mark = "†"
    if pinned and max(med_cpu(rs, "client"), med_cpu(rs, "app")) >= SATURATED:
        mark += "‡"
    marks[n, s] = mark


def table(head, servers, cell):
    rows = ["| Open connections | " + " | ".join(l for _, l in servers) + " |",
            "|---" * (len(servers) + 1) + "|"]
    for n in levels:
        r = [f"{cell(cells[n, s])}{marks[n, s]}" if (n, s) in cells else "—" for s, _ in servers]
        rows.append(f"| {n:,} | " + " | ".join(r) + " |")
    return [head, "", *rows, ""]


md = [
    f"nginx {env['nginx']}, HAProxy {env['haproxy']}, routez {env['routez']} (quic-zig {env['quic-zig']}), "
    f"one worker each, proxying WebSocket over HTTP/1.1 to a Node.js {env['node']} `ws` {env['ws']} echo app. "
    f"Median of {env['rounds']} rounds. Linux {env['kernel']}, {env['cpus']} cpus; pinning: {env['pinning']}; "
    f"{env['clients']} client processes. routez built with `-Dcpu={env['zig_cpu']}`. {env['date']}.",
    "",
    *table("**Memory per open connection** (lower is better): the server's RSS growth over its idle "
           "baseline, divided by the number of connections.", PROXIES,
           lambda rs: METRICS["kb_per_conn"].fmt(med(rs, "kb_per_conn"))),
    *table(f"**Echo latency, p99** (lower is better): {int(env['rate']):,} messages per second in total, spread over "
           f"all open connections, for {env['duration']} s. The server's CPU use is in parentheses.", SERVERS,
           lambda rs: f"{ms(med(rs, 'p99_us'))} ({med_cpu(rs, 'server')}%)" if rs[0]["server"] != "direct"
           else ms(med(rs, "p99_us"))),
    *table(f"**Connections opened per second** (higher is better), with {in_flight} handshakes in flight per "
           "client process.", SERVERS,
           lambda rs: METRICS["connect_per_s"].fmt(med(rs, "connect_per_s"))),
]
if notes:
    md.append("† " + "; ".join(notes) + ".")
if any("‡" in m for m in marks.values()):
    md.append(f"‡ the client or the app was ≥{SATURATED}% busy: the rig may be the limit, not the server.")
md += ["", "All figures, per server:", "",
       "| Open connections | Server | server KB/conn | app KB/conn | connects/s | echoes/s | p50 | p99 | p99.9 "
       "| CPU % server / app / client |", "|---" * 10 + "|"]
for n in levels:
    for s, label in SERVERS:
        rs = cells.get((n, s))
        if not rs:
            continue
        kb = med(rs, "kb_per_conn")
        app_kb = statistics.median(r["app_kb_per_conn"] for r in rs)
        md.append(f"| {n:,} | {label} | {'—' if kb is None else f'{kb:.1f}'} | {app_kb:.1f} "
                  f"| {med(rs, 'connect_per_s'):,.0f} | {med(rs, 'echoes_per_s'):,.0f} | {ms(med(rs, 'p50_us'))} "
                  f"| {ms(med(rs, 'p99_us'))} | {ms(med(rs, 'p999_us'))} "
                  f"| {med_cpu(rs, 'server')} / {med_cpu(rs, 'app')} / {med_cpu(rs, 'client')} |")
md.append("")
(out / "table.md").write_text("\n".join(md))

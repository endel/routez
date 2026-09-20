#!/usr/bin/env python3
"""Turns l4.sh's raw runs in OUT/raw into OUT/results.jsonl and OUT/table.md.

Every row is read against `direct`, the same traffic with no proxy in the path,
so the interesting figure is what the proxy adds rather than the absolute rate.
"""
import json
import re
import sys
from pathlib import Path

from rig import (METRICS, SATURATED, busy, cpu_list, cpu_ms_per_1k, load_env, med, proc_stat,
                 rate, read_int, row, write_jsonl)

SERVERS = [("direct", "No proxy"), ("nginx", "nginx stream"), ("haproxy", "HAProxy tcp"),
           ("routez", "routez")]
LABEL = dict(SERVERS)
PROXIES = [s for s, _ in SERVERS if s != "direct"]
TCP_ROWS = {"tcp-small": "TCP: a small response, keep-alive",
            "tcp-conn": "TCP: a new connection per request",
            "tcp-bulk": "TCP: 1 MB responses"}
UDP_ROWS = {"udp-rtt": "UDP: round trip at a fixed rate",
            "udp-flood": "UDP: loss at a high rate",
            "udp-flows": "UDP: memory per client flow"}
LABELS = {**TCP_ROWS, **UDP_ROWS}

out = Path(sys.argv[1])
env = load_env(out)
server_cpus = cpu_list(env["server_cpus"])
load_cpus = cpu_list(env["wrk_cpus"])
back_cpus = cpu_list(env["upstream_cpus"])
duration = float(env["duration"])

runs = []
for txt in sorted((out / "raw").glob("*.txt")):
    workload, server, rnd = txt.stem.split(".")
    text = txt.read_text()
    s0, s1 = proc_stat(txt.with_suffix(".stat0")), proc_stat(txt.with_suffix(".stat1"))
    cpu = {"server": busy(s0, s1, server_cpus), "load": busy(s0, s1, load_cpus),
           "backend": busy(s0, s1, back_cpus)}
    base = txt.parent / f"{workload}.{server}.base"
    rss = txt.with_suffix(".rss")
    grew = None
    a, b2 = read_int(base), read_int(rss)
    if a is not None and b2 is not None:
        grew = b2 - a
    flags = []
    metrics, detail = {}, {"cpu_pct": cpu["server"]}
    if workload in UDP_ROWS:
        j = json.loads([l for l in text.splitlines() if l.startswith("{")][-1])
        done = j["sent"]
        secs = j["send_us"] / 1e6
        metrics["pps"] = round(j["received"] / secs)
        metrics["loss_pct"] = 100 * (j["sent"] - j["received"]) / max(1, j["sent"])
        metrics["p50_us"] = j["p50_us"]
        metrics["p99_us"] = j["p99_us"]
        detail["p999_us"] = j["p999_us"]
        if workload == "udp-flows" and grew is not None and server != "direct":
            metrics["kb_per_conn"] = grew / j["flows"]
        if metrics["loss_pct"] > 0.1:
            flags.append(f"{metrics['loss_pct']:.2f}% of datagrams lost")
    else:
        lines = [l for l in text.splitlines() if l.startswith('{"requests"')]
        if not lines:
            sys.exit(f"no wrk result in {txt}:\n{text}")
        j = json.loads(lines[-1])
        secs = j["duration_us"] / 1e6
        done = j["requests"]
        metrics["rps"] = round(j["requests"] / secs)
        metrics["p50_us"] = j["p50_us"]
        metrics["p99_us"] = j["p99_us"]
        detail["mbps"] = j["bytes"] / secs / 1e6
        detail["p999_us"] = j["p999_us"]
        errs = {k: j[k] for k in ("connect", "read", "write", "status", "timeout") if j[k]}
        if errs:
            flags.append("errors: " + ", ".join(f"{n} {k}" for k, n in errs.items()))
    if server != "direct":
        metrics["cpu_ms_per_1k"] = cpu_ms_per_1k(s0, s1, server_cpus, done)
        if grew is not None and workload != "udp-flows":
            detail["rss_kb"] = read_int(rss)
    limiter = max(cpu["load"], cpu["backend"])
    if limiter >= SATURATED:
        flags.append(f"rig {limiter}% busy")
    r = row(env, "l4", workload, server, rnd,
            {"workers": int(env["workers"]), "conns": int(env["conns"])},
            metrics, detail, flags)
    r["cpu"] = cpu
    runs.append(r)
write_jsonl(out, runs)

cells = {}
for r in runs:
    cells.setdefault((r["workload"], r["server"]), []).append(r)
order = [w for w in LABELS if any(k[0] == w for k in cells)]

notes, saturated = [], False
marks = {}
for (w, s), rs in cells.items():
    mark = ""
    for r in rs:
        for f in r["flags"]:
            if not f.startswith("rig "):
                notes.append(f"{LABEL[s]}, {w}, round {r['round']}: {f}")
                mark = "†"
    if any(f.startswith("rig ") for r in rs for f in r["flags"]):
        mark += "‡"
        saturated = True
    marks[w, s] = mark


def table(head, rows_, servers, cell):
    body = ["| Row | " + " | ".join(LABEL[s] for s in servers) + " |",
            "|---" * (len(servers) + 1) + "|"]
    for w in rows_:
        if not any(k[0] == w for k in cells):
            continue
        cols = [f"{cell(cells[w, s])}{marks[w, s]}" if (w, s) in cells else "—" for s in servers]
        body.append(f"| {LABELS[w]} | " + " | ".join(cols) + " |")
    return [head, "", *body, ""]


tcp = [w for w in order if w in TCP_ROWS]
udp = [w for w in order if w in UDP_ROWS]
md = [
    f"nginx {env['nginx']} (stream), HAProxy {env['haproxy']} (mode tcp, splice on), routez "
    f"{env['routez']} (quic-zig {env['quic-zig']}), {env['workers']} workers each, forwarding without "
    f"terminating anything. `wrk -c{env['conns']}` for TCP and bench/tools/udpload for UDP, median of "
    f"{env['rounds']} × {env['duration']} s runs. Linux {env['kernel']}, {env['cpus']} cpus; pinning: "
    f"{env['pinning']}; rmem_max {env['rmem_max']}. routez built with `-Dcpu={env['zig_cpu']}`. "
    f"{env['date']}.", "",
]
if tcp:
    md += table("**Requests per second** (higher is better). `No proxy` is the same traffic straight to "
                "the backend, so the gap to it is what forwarding costs.", tcp,
                [s for s, _ in SERVERS], lambda rs: rate(med(rs, "rps")))
    md += table("**Added latency at p99** (lower is better): the row's p99 less the unproxied p99.", tcp,
                PROXIES,
                lambda rs: METRICS["overhead_us"].fmt(
                    med(rs, "p99_us") - med(cells[rs[0]["workload"], "direct"], "p99_us")))
if udp:
    md += table("**Datagrams echoed per second** (higher is better).", udp,
                [s for s, _ in SERVERS if s != "haproxy"], lambda rs: rate(med(rs, "pps")))
    md += table("**Round trip at p99** (lower is better).", udp,
                [s for s, _ in SERVERS if s != "haproxy"], lambda rs: METRICS["p99_us"].fmt(med(rs, "p99_us")))
    if any(k[0] == "udp-flows" for k in cells):
        md += ["**Memory per client flow** (lower is better): the proxy's RSS growth over its idle "
               "baseline, divided by the flows held.", "",
               "| Flows | " + " | ".join(LABEL[s] for s in PROXIES if s != "haproxy") + " |",
               "|---" * (len([s for s in PROXIES if s != "haproxy"]) + 1) + "|",
               f"| {int(env['flows']):,} | " + " | ".join(
                   METRICS["kb_per_conn"].fmt(med(cells["udp-flows", s], "kb_per_conn"))
                   if ("udp-flows", s) in cells and med(cells["udp-flows", s], "kb_per_conn") is not None
                   else "—" for s in PROXIES if s != "haproxy") + " |", ""]
md.append("— HAProxy has no generic UDP proxy.")
if notes:
    md.append("† " + "; ".join(sorted(set(notes))) + ".")
if saturated:
    md.append(f"‡ the load generator or the backend was ≥{SATURATED}% busy: the rig may be the limit.")

detail = ["| Row | Server | rate | p50 | p99 | p99.9 | CPU ms/1k | CPU % proxy / load / backend |",
          "|---" * 8 + "|"]
for w in order:
    for s, slabel in SERVERS:
        rs = cells.get((w, s))
        if not rs:
            continue
        r0 = med(rs, "pps") if w in UDP_ROWS else med(rs, "rps")
        cost = med(rs, "cpu_ms_per_1k")
        cpu = rs[0]["cpu"]
        detail.append(
            f"| {LABELS[w]} | {slabel} | {rate(r0)} | {METRICS['p50_us'].fmt(med(rs, 'p50_us'))} "
            f"| {METRICS['p99_us'].fmt(med(rs, 'p99_us'))} "
            f"| {METRICS['p999_us'].fmt(med(rs, 'p999_us'))} "
            f"| {METRICS['cpu_ms_per_1k'].fmt(cost) if cost is not None else '—'} "
            f"| {cpu['server']} / {cpu['load']} / {cpu['backend']} |")
md += ["", "All figures, per row.", "", *detail, ""]
(out / "table.md").write_text("\n".join(md))

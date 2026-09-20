#!/usr/bin/env python3
"""Turns rate.sh's oha runs in OUT/raw into OUT/results.jsonl and OUT/table.md.

Latency is the result here, not a by-product: every server was offered the same
request rate, so the percentiles compare. A server that did not hold the offered
rate is flagged, because then its latency is the latency of a smaller load.
"""
import json
import sys
from pathlib import Path

from rig import (METRICS, busy, cpu_list, cpu_ms_per_1k, load_env, load_workloads, med,
                 proc_stat, rate as fmt_rate, read_int, row, write_jsonl)

HERE = Path(__file__).parent
SERVERS = [("nginx", "nginx"), ("haproxy", "HAProxy"), ("routez", "routez")]
LABEL = dict(SERVERS)
RANKED = ["p50_us", "p90_us", "p99_us", "p999_us"]
# Below this share of the offered rate the row measured a different load.
HELD = 0.97

out = Path(sys.argv[1])
env = load_env(out)
labels = {w["name"]: w["label"] for w in load_workloads(HERE)}
order = [w["name"] for w in load_workloads(HERE)]
server_cpus = cpu_list(env["server_cpus"])
fraction = float(env["fraction"])

runs, offered = [], {}
for js in sorted((out / "raw").glob("*.json")):
    workload, server, rnd = js.stem.split(".")
    d = json.loads(js.read_text())
    peak = read_int(out / "raw" / f"{workload}.peak") or 0
    want = max(100, int(peak * fraction))
    offered[workload] = want
    got = d["summary"]["requestsPerSec"]
    p = d["latencyPercentiles"]
    s0, s1 = proc_stat(js.with_suffix(".stat0")), proc_stat(js.with_suffix(".stat1"))
    flags = []
    if got < want * HELD:
        flags.append(f"held {got:.0f} of the {want} req/s offered, so this is a lighter load")
    if d["summary"]["successRate"] < 1:
        flags.append(f"success rate {d['summary']['successRate']:.3f}")
    n = int(got * float(env["duration"]))
    runs.append(row(env, "rate", workload, server, rnd,
                    {"workers": int(env["workers"]), "conns": int(env["conns"]),
                     "offered": want},
                    {k: p[j] * 1e6 for k, j in
                     (("p50_us", "p50"), ("p90_us", "p90"), ("p99_us", "p99"), ("p999_us", "p99.9"))},
                    {"rps": round(got), "cpu_pct": busy(s0, s1, server_cpus),
                     "cpu_ms_per_1k": cpu_ms_per_1k(s0, s1, server_cpus, n)},
                    flags))
write_jsonl(out, runs)

cells = {}
for r in runs:
    cells.setdefault((r["workload"], r["server"]), []).append(r)
rows_ = [w for w in order if any(k[0] == w for k in cells)]

notes, marks = [], {}
for (w, s), rs in cells.items():
    mark = ""
    for r in rs:
        for f in r["flags"]:
            notes.append(f"{LABEL[s]}, {labels.get(w, w).lower()}, round {r['round']}: {f}")
            mark = "†"
    marks[w, s] = mark

md = [
    f"nginx {env['nginx']}, HAProxy {env['haproxy']}, routez {env['routez']} (quic-zig {env['quic-zig']}), "
    f"{env['workers']} workers each. oha {env['oha']} holding a fixed rate, {int(fraction * 100)}% of the "
    f"slowest server's measured peak for that row, `-c{env['conns']}`, median of {env['rounds']} × "
    f"{env['duration']} s runs. Linux {env['kernel']}, {env['cpus']} cpus; pinning: {env['pinning']}. "
    f"{env['date']}.", "",
    "Every server sees the same offered rate, so unlike the wrk rows these "
    "percentiles are comparable: they are not the reciprocal of throughput.", "",
]
for metric in RANKED:
    spec = METRICS[metric]
    md += [f"**{spec.label}** (lower is better)", "",
           "| Row | offered | " + " | ".join(l for _, l in SERVERS) + " |",
           "|---" * (len(SERVERS) + 2) + "|"]
    for w in rows_:
        cols = [f"{spec.fmt(med(cells[w, s], metric))}{marks[w, s]}" if (w, s) in cells else "—"
                for s, _ in SERVERS]
        md.append(f"| {labels.get(w, w)} | {fmt_rate(offered[w])}/s | " + " | ".join(cols) + " |")
    md.append("")
md.append("— HAProxy isn't a file server.")
if notes:
    md.append("† " + "; ".join(sorted(set(notes))) + ".")
detail = ["| Row | Server | offered | achieved | p50 | p99 | p99.9 | CPU ms/1k | CPU % |",
          "|---" * 9 + "|"]
for w in rows_:
    for s, slabel in SERVERS:
        rs = cells.get((w, s))
        if not rs:
            continue
        detail.append(
            f"| {labels.get(w, w)} | {slabel} | {fmt_rate(offered[w])}/s "
            f"| {fmt_rate(med(rs, 'rps'))}/s | {METRICS['p50_us'].fmt(med(rs, 'p50_us'))} "
            f"| {METRICS['p99_us'].fmt(med(rs, 'p99_us'))} "
            f"| {METRICS['p999_us'].fmt(med(rs, 'p999_us'))} "
            f"| {METRICS['cpu_ms_per_1k'].fmt(med(rs, 'cpu_ms_per_1k'))} "
            f"| {med(rs, 'cpu_pct'):.0f}% |")
md += ["", "All figures, per row.", "", *detail, ""]
(out / "table.md").write_text("\n".join(md))

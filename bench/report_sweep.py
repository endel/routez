#!/usr/bin/env python3
"""Turns sweep.sh's per-value result directories into OUT/table.md.

One table per ranked metric: rows are (row, server), columns are the knob's
values. For a knob that adds resources, the last column also gives the scaling
factor from the first value, so a server that stops scaling is visible.
"""
import sys
from pathlib import Path

from rig import METRICS, load_workloads, med, read_jsonl

HERE = Path(__file__).parent
SERVERS = [("nginx", "nginx"), ("haproxy", "HAProxy"), ("routez", "routez")]
# Knobs where more of the thing should mean more throughput.
SCALES = {"WORKERS"}

out = Path(sys.argv[1])
meta = dict(l.split(": ", 1) for l in (out / "sweep.txt").read_text().splitlines())
knob, values = meta["knob"], meta["values"].split()
labels = {w["name"]: w["label"] for w in load_workloads(HERE)}
order = [w["name"] for w in load_workloads(HERE)]

# (value, workload, server) -> rounds
cells, metrics_seen, env = {}, [], {}
for v in values:
    f = out / v / "results.jsonl"
    if not f.exists():
        print(f"warning: no results for {knob}={v}", file=sys.stderr)
        continue
    for r in read_jsonl(f):
        cells.setdefault((v, r["workload"], r["server"]), []).append(r)
        env = r
        for m in r["metrics"]:
            if m not in metrics_seen:
                metrics_seen.append(m)
if not cells:
    sys.exit("no results to report")

have = [v for v in values if any(k[0] == v for k in cells)]
workloads = [w for w in order if any(k[1] == w for k in cells)]
workloads += sorted({k[1] for k in cells} - set(workloads))

md = [f"# Sweep over {knob}", "",
      f"{meta['suite']} suite, routez {env['routez']} (quic-zig {env['quic_zig']}), {env['date']}. "
      f"`{knob}` took the values {', '.join(have)}. Each figure is the median of its rounds.", ""]
for m in metrics_seen:
    spec = METRICS[m]
    scaling = knob in SCALES and spec.better > 0
    head = f"| Row | Server | " + " | ".join(f"{knob}={v}" for v in have) + \
           (f" | {have[0]}→{have[-1]} |" if scaling else " |")
    md += [f"**{spec.label}** ({'higher' if spec.better > 0 else 'lower'} is better)", "",
           head, "|---" * (len(have) + 2 + (1 if scaling else 0)) + "|"]
    for w in workloads:
        for s, slabel in SERVERS:
            vals = [med(cells[v, w, s], m) if (v, w, s) in cells else None for v in have]
            if all(v is None for v in vals):
                continue
            row = [spec.fmt(v) if v is not None else "—" for v in vals]
            if scaling:
                first, last = vals[0], vals[-1]
                row.append(f"{last / first:.2f}×" if first and last else "—")
            md.append(f"| {labels.get(w, w)} | {slabel} | " + " | ".join(row) + " |")
    md.append("")
(out / "table.md").write_text("\n".join(md))

#!/usr/bin/env python3
"""Turns soak.sh's samples in OUT/raw into OUT/results.jsonl and OUT/table.md.

The result is the trend, not the level: memory that climbs steadily over a long
mixed run, or descriptors that never come back, is what a soak is for. The slope
is a least-squares fit over the samples after the first minute, so the warm-up
doesn't set the trend.
"""
import sys
from pathlib import Path

from rig import METRICS, load_env, row, write_jsonl

SERVERS = [("nginx", "nginx"), ("haproxy", "HAProxy"), ("routez", "routez")]
WARMUP_S = 60


def slope_per_min(points):
    """Least squares on (seconds, value), in value per minute."""
    if len(points) < 3:
        return None
    n = len(points)
    mx = sum(p[0] for p in points) / n
    my = sum(p[1] for p in points) / n
    den = sum((p[0] - mx) ** 2 for p in points)
    if den == 0:
        return None
    return 60 * sum((p[0] - mx) * (p[1] - my) for p in points) / den


out = Path(sys.argv[1])
env = load_env(out)
runs = []
for f in sorted((out / "raw").glob("*.samples")):
    server = f.stem
    rows = []
    for line in f.read_text().splitlines():
        t, rss, fds = (int(x) for x in line.split())
        rows.append((t, rss, fds))
    if not rows:
        continue
    t0 = rows[0][0]
    after = [(t - t0, rss, fds) for t, rss, fds in rows if t - t0 >= WARMUP_S] or \
            [(t - t0, rss, fds) for t, rss, fds in rows]
    flags = []
    if len(after) < 3:
        flags.append("too few samples after the warm-up to fit a trend")
    runs.append(row(env, "soak", "mixed", server, 1,
                    {"workers": int(env["workers"]), "minutes": int(env["minutes"])},
                    {"rss_slope_kb_min": slope_per_min([(t, r) for t, r, _ in after]),
                     "fd_drift": after[-1][2] - after[0][2],
                     "rss_kb": max(r for _, r, _ in rows)},
                    {"cpu_pct": None}, flags))
    runs[-1]["samples"] = len(rows)
    runs[-1]["first"] = {"rss_kb": rows[0][1], "fds": rows[0][2]}
    runs[-1]["last"] = {"rss_kb": rows[-1][1], "fds": rows[-1][2]}
write_jsonl(out, runs)

by = {r["server"]: r for r in runs}
md = [
    f"nginx {env['nginx']}, HAProxy {env['haproxy']}, routez {env['routez']} (quic-zig {env['quic-zig']}), "
    f"{env['workers']} workers each, {env['minutes']} minutes per server of a repeating cycle: a fixed "
    f"response, a 10 KB file, a proxied response, a compressed one, and a stretch of connection churn. "
    f"`wrk -c{env['conns']}`. Sampled every {env['sample']} s; the trend is fitted after the first "
    f"minute. Linux {env['kernel']}, {env['cpus']} cpus. {env['date']}.", "",
    "| Server | RSS growth | descriptors gained | RSS at start | RSS at end | peak RSS | samples |",
    "|---|---|---|---|---|---|---|",
]
for s, label in SERVERS:
    r = by.get(s)
    if not r:
        continue
    m, d = r["metrics"], r["detail"]
    slope = m.get("rss_slope_kb_min")
    md.append(
        f"| {label} | {METRICS['rss_slope_kb_min'].fmt(slope) if slope is not None else '—'} "
        f"| {METRICS['fd_drift'].fmt(m['fd_drift'])} "
        f"| {r['first']['rss_kb'] / 1024:.1f} MB | {r['last']['rss_kb'] / 1024:.1f} MB "
        f"| {METRICS['rss_kb'].fmt(m['rss_kb'])} | {r['samples']} |")
md += ["", "A steady climb in RSS, or descriptors that never come back, is what this run is looking "
       "for; a small slope either way is noise from the phase the run happened to end in.", ""]
notes = [f"{dict(SERVERS)[r['server']]}: {f}" for r in runs for f in r["flags"]]
if notes:
    md += ["† " + "; ".join(notes) + ".", ""]
(out / "table.md").write_text("\n".join(md))

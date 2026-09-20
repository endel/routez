#!/usr/bin/env python3
"""Turns bench.sh's raw wrk runs in OUT/raw into OUT/results.jsonl and OUT/table.md."""
import json
import sys
from pathlib import Path

from rig import (METRICS, SATURATED, busy, cpu_list, cpu_ms_per_1k, load_env,
                 load_workloads, med, proc_stat, rate, row, spread, write_jsonl)

HERE = Path(__file__).parent
SERVERS = [("nginx", "nginx"), ("haproxy", "HAProxy"), ("routez", "routez")]
ERRORS = ("connect", "read", "write", "status", "timeout")
# Rows whose whole point is a non-2xx answer: wrk counts those as status errors.
EXPECTS_NON_2XX = {"404", "ims"}
# Columns of the per-row detail table.
DETAIL = ["rps", "mbps", "p50_us", "p99_us", "p999_us", "cpu_ms_per_1k", "rss_kb"]

out = Path(sys.argv[1])
env = load_env(out)
workloads = {w["name"]: w for w in load_workloads(HERE)}
order = [w["name"] for w in load_workloads(HERE)]

server_cpus = cpu_list(env["server_cpus"])
up_cpus = cpu_list(env["upstream_cpus"])
wrk_cpus = {"yes": cpu_list(env["wrk_cpus"]), "no": cpu_list(env["wide_wrk_cpus"])}

runs = []
for txt in sorted((out / "raw").glob("*.txt")):
    workload, server, rnd = txt.stem.split(".")
    lines = [l for l in txt.read_text().splitlines() if l.startswith('{"requests"')]
    if not lines:
        sys.exit(f"no wrk result in {txt}:\n{txt.read_text()}")
    j = json.loads(lines[-1])
    secs = j["duration_us"] / 1e6
    s0, s1 = proc_stat(txt.with_suffix(".stat0")), proc_stat(txt.with_suffix(".stat1"))
    rig_cpus = wrk_cpus[workloads[workload]["upstream"]]
    cpu = {"server": busy(s0, s1, server_cpus), "wrk": busy(s0, s1, rig_cpus),
           "upstream": busy(s0, s1, up_cpus)}
    rss = txt.with_suffix(".rss")
    flags = []
    expected = ERRORS if workloads[workload]["check"] not in EXPECTS_NON_2XX \
        else tuple(k for k in ERRORS if k != "status")
    errs = {k: j[k] for k in expected if j[k]}
    if errs:
        flags.append("errors: " + ", ".join(f"{n} {k}" for k, n in errs.items()))
    # The load generator (or, on a proxy row, the upstream) may be the limit.
    limiter = cpu["wrk"] if workloads[workload]["upstream"] == "no" else max(cpu["wrk"], cpu["upstream"])
    if limiter >= SATURATED:
        flags.append(f"rig {limiter}% busy")
    r = row(env, "http", workload, server, rnd,
            {"workers": int(env["workers"]), "conns": int(env["conns"]),
             "log": env.get("access_log", "off")},
            # Ranked: wrk keeps the connections full, so these are the row's real result.
            {"rps": round(j["requests"] / secs),
             "cpu_ms_per_1k": cpu_ms_per_1k(s0, s1, server_cpus, j["requests"]),
             "rss_kb": int(rss.read_text()) if rss.exists() else None},
            # Not ranked: closed-loop latency tracks 1/throughput, and every
            # server pins its cores. The fixed-rate rows are where latency counts.
            # Bandwidth restates req/s whenever the body is a fixed size, which
            # it is on every row here, so it is shown and not ranked.
            {**{k: j[k] for k in ("p50_us", "p90_us", "p99_us", "p999_us", "max_us")},
             "mbps": j["bytes"] / secs / 1e6,
             "cpu_pct": cpu["server"]},
            flags)
    r["cpu"] = cpu  # all three groups, for the detail table
    runs.append(r)
write_jsonl(out, runs)

cells = {}
for r in runs:
    cells.setdefault((r["workload"], r["server"]), []).append(r)

pinned = not env["pinning"].startswith("none")
notes, saturated = [], False
marks = {}
for (w, s), rs in cells.items():
    mark = ""
    for r in rs:
        for f in r["flags"]:
            if f.startswith("errors"):
                notes.append(f"{dict(SERVERS)[s]}, {workloads[w]['label'].lower()}, round {r['round']}: {f[8:]}")
                mark = "†"
    if pinned and any(f.startswith("rig ") for r in rs for f in r["flags"]):
        mark += "‡"
        saturated = True
    marks[w, s] = mark

table = ["| Workload | " + " | ".join(l for _, l in SERVERS) + " | routez vs best other |",
         "|---" * (len(SERVERS) + 2) + "|"]
detail = ["| Workload | Server | " + " | ".join(METRICS[m].label for m in DETAIL)
          + " | CPU % server / wrk / upstream |", "|---" * (len(DETAIL) + 3) + "|"]
for w in order:
    if not any(k[0] == w for k in cells):
        continue
    label = workloads[w]["label"]
    cols = []
    for s, slabel in SERVERS:
        rs = cells.get((w, s))
        if not rs:
            cols.append("—")
            continue
        cols.append(f"{rate(med(rs, 'rps'))}{marks[w, s]}")
        vals = []
        for m in DETAIL:
            v = med(rs, m)
            if v is None:
                vals.append("—")
                continue
            cell = METRICS[m].fmt(v)
            if m == "rps":
                lo, hi = spread(rs, m)
                cell += f" ({rate(lo)}–{rate(hi)})"
            vals.append(cell)
        cpu = rs[0]["cpu"]
        detail.append(f"| {label} | {slabel} | " + " | ".join(vals)
                      + f" | {cpu['server']} / {cpu['wrk']} / {cpu['upstream']} |")
    ours, others = cells.get((w, "routez")), [med(cells[w, s], "rps") for s, _ in SERVERS
                                              if s != "routez" and (w, s) in cells]
    best = max(others) if others else 0
    vs = f"{100 * (med(ours, 'rps') / best - 1):+.0f}%" if ours and best else ""
    table.append(f"| {label} | " + " | ".join(cols) + f" | {vs} |")

md = [
    f"nginx {env['nginx']}, HAProxy {env['haproxy']}, routez {env['routez']} (quic-zig {env['quic-zig']}), "
    f"{env['workers']} workers each. `wrk -c{env['conns']}`, keep-alive, median of {env['rounds']} × "
    f"{env['duration']} s runs, in requests per second. Linux {env['kernel']}, {env['cpus']} cpus; "
    f"pinning: {env['pinning']}. TLS 1.3 with TLS_AES_128_GCM_SHA256, X25519 and an ECDSA P-256 "
    f"certificate. routez built with `-Dcpu={env['zig_cpu']}`. {env['date']}.",
    "", *table, "", "— HAProxy isn't a file server.",
]
if notes:
    md.append("† socket errors or non-2xx responses in at least one round: " + "; ".join(notes) + ".")
if saturated:
    md.append(f"‡ wrk (or the upstream, for a proxy row) was ≥{SATURATED}% busy: the rig may be the "
              "limit, not the server.")
md += ["", "All figures, per row. Requests per second shows the min–max spread across rounds; "
       "CPU ms per 1000 requests still ranks the servers when the rig is the limit.", "", *detail, ""]
(out / "table.md").write_text("\n".join(md))

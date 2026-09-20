#!/usr/bin/env python3
"""Turns h3.sh's raw h2load runs in OUT/raw into OUT/results.jsonl and OUT/table.md."""
import re
import sys
from pathlib import Path

from rig import (METRICS, SATURATED, busy, cpu_list, cpu_ms_per_1k, load_env, med,
                 proc_stat, rate, read_jsonl, row, spread, write_jsonl)

SERVERS = [("nginx", "nginx"), ("haproxy", "HAProxy"), ("routez", "routez")]
LABEL = dict(SERVERS)
# Filled from the rows h3.sh actually ran; h1 rows pair with the h3 row of the
# same name so each server's cost of HTTP/3 comes from one client.
PAIRS = [("h3-return", "h1-return"), ("h3-static", "h1-static"), ("h3-proxy", "h1-proxy")]
DETAIL = ["rps", "mbps", "p50_us", "p99_us", "max_us", "connect_us", "rtt_us",
          "cpu_ms_per_1k", "rss_kb"]

SIZE = {"B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9}
TIME = {"us": 1, "ms": 1e3, "s": 1e6, "m": 60e6}


def parse_size(text):
    m = re.match(r"([\d.]+)\s*([KMG]?B)", text)
    return float(m.group(1)) * SIZE[m.group(2)] if m else None


def parse_time(text):
    m = re.match(r"([\d.]+)\s*(us|ms|s|m)$", text.strip())
    return float(m.group(1)) * TIME[m.group(2)] if m else None


def stat_row(text, name):
    """One row of h2load's trailing statistics table, by column name.

    A QUIC run gets min/max/median/p95/p99/mean; the older layout, and the
    HTTP/1.1 runs of some builds, print `time for <name>: min max mean sd`.
    """
    m = re.search(rf"^{name}\s*:\s*(.+)$", text, re.M)
    if m:
        cols = m.group(1).split()
        header = re.search(r"^\s+min\s+max\s+(\S+)", text, re.M)
        if header and header.group(1) == "median":
            keys = ["min", "max", "median", "p95", "p99", "mean"]
        else:
            keys = ["min", "max", "mean", "sd"]
        return dict(zip(keys, cols))
    m = re.search(rf"^time for {name}:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", text, re.M)
    if m:
        return dict(zip(["min", "max", "mean", "sd"], m.groups()))
    return {}


def parse(text):
    out = {"failed": 0, "errored": 0, "timeout": 0, "non2xx": 0}
    m = re.search(r"finished in [\d.]+\w+, ([\d.]+) req/s, ([\d.]+\s*[KMG]?B)/s", text)
    if not m:
        return None
    out["rps"] = float(m.group(1))
    out["mbps"] = parse_size(m.group(2)) / 1e6
    m = re.search(r"requests: (\d+) total, \d+ started, \d+ done, (\d+) succeeded, "
                  r"(\d+) failed, (\d+) errored, (\d+) timeout", text)
    if m:
        out["succeeded"] = int(m.group(2))
        out["failed"], out["errored"], out["timeout"] = (int(m.group(i)) for i in (3, 4, 5))
    m = re.search(r"status codes: (\d+) 2xx, (\d+) 3xx, (\d+) 4xx, (\d+) 5xx", text)
    if m:
        out["non2xx"] = sum(int(m.group(i)) for i in (2, 3, 4))
    req = stat_row(text, "request")
    for key, name in (("median", "p50_us"), ("p99", "p99_us"), ("max", "max_us")):
        if key in req:
            out[name] = parse_time(req[key])
    if "p50_us" not in out and "mean" in req:  # the older layout has no percentiles
        out["p50_us"] = parse_time(req["mean"])
    con = stat_row(text, "connect")
    if "mean" in con:
        out["connect_us"] = parse_time(con["mean"])
    rtt = stat_row(text, "smoothed RTT")
    if "mean" in rtt:
        out["rtt_us"] = parse_time(rtt["mean"])
    lost = stat_row(text, "packets lost")
    if lost.get("max") and float(lost["max"]) > 0:
        out["packets_lost"] = float(lost["max"])
    return out


out = Path(sys.argv[1])
env = load_env(out)
server_cpus = cpu_list(env["server_cpus"])
up_cpus = cpu_list(env["upstream_cpus"])

runs = []
for txt in sorted((out / "raw").glob("*.txt")):
    workload, server, rnd = txt.stem.split(".")
    j = parse(txt.read_text())
    if not j:
        sys.exit(f"no h2load result in {txt}:\n{txt.read_text()}")
    rig_cpus = cpu_list(env["wrk_cpus"] if "proxy" in workload else env["wide_wrk_cpus"])
    s0, s1 = proc_stat(txt.with_suffix(".stat0")), proc_stat(txt.with_suffix(".stat1"))
    cpu = {"server": busy(s0, s1, server_cpus), "load": busy(s0, s1, rig_cpus),
           "upstream": busy(s0, s1, up_cpus)}
    flags = []
    broken = {k: j[k] for k in ("failed", "errored", "timeout", "non2xx") if j.get(k)}
    if broken:
        flags.append("errors: " + ", ".join(f"{v} {k}" for k, v in broken.items()))
    u0, u1 = (txt.with_suffix(f".udp{i}") for i in (0, 1))
    if j.get("packets_lost"):
        flags.append(f"{j['packets_lost']:.0f} packets lost")
    if u0.exists() and u1.exists():
        dropped = int(u1.read_text()) - int(u0.read_text())
        if dropped:
            flags.append(f"{dropped} UDP datagrams the kernel dropped")
    limiter = max(cpu["load"], cpu["upstream"]) if "proxy" in workload else cpu["load"]
    if limiter >= SATURATED:
        flags.append(f"rig {limiter}% busy")
    rss = txt.with_suffix(".rss")
    r = row(env, "h3", workload, server, rnd,
            {"workers": int(env["workers"]), "conns": int(env["conns"])},
            {"rps": round(j["rps"]),
             "cpu_ms_per_1k": cpu_ms_per_1k(s0, s1, server_cpus, j.get("succeeded", 0)),
             "rss_kb": int(rss.read_text()) if rss.exists() else None},
            {"mbps": j["mbps"], "cpu_pct": cpu["server"],
             **{k: j.get(k) for k in ("p50_us", "p99_us", "max_us", "connect_us", "rtt_us")}},
            flags)
    r["cpu"] = cpu
    runs.append(r)
write_jsonl(out, runs)

cells = {}
for r in runs:
    cells.setdefault((r["workload"], r["server"]), []).append(r)
order = [w for w in ["h3-return", "h3-return-m10", "h3-static", "h3-static-1m", "h3-proxy",
                     "h1-return", "h1-static", "h1-proxy"] if any(k[0] == w for k in cells)]
labels = {r["workload"]: r["workload"] for r in runs}

notes, saturated = [], False
marks = {}
for (w, s), rs in cells.items():
    mark = ""
    for r in rs:
        for f in r["flags"]:
            if f.startswith("errors") or "dropped" in f:
                notes.append(f"{LABEL[s]}, {w}, round {r['round']}: {f}")
                mark = "†"
    if any(f.startswith("rig ") for r in rs for f in r["flags"]):
        mark += "‡"
        saturated = True
    marks[w, s] = mark

table = ["| Row | " + " | ".join(l for _, l in SERVERS) + " | routez vs best other |",
         "|---" * (len(SERVERS) + 2) + "|"]
detail = ["| Row | Server | " + " | ".join(METRICS[m].label for m in DETAIL)
          + " | CPU % server / h2load / upstream |", "|---" * (len(DETAIL) + 3) + "|"]
for w in order:
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
        detail.append(f"| {w} | {slabel} | " + " | ".join(vals)
                      + f" | {cpu['server']} / {cpu['load']} / {cpu['upstream']} |")
    others = [med(cells[w, s], "rps") for s, _ in SERVERS if s != "routez" and (w, s) in cells]
    ours = cells.get((w, "routez"))
    best = max(others) if others else 0
    vs = f"{100 * (med(ours, 'rps') / best - 1):+.0f}%" if ours and best else ""
    table.append(f"| {w} | " + " | ".join(cols) + f" | {vs} |")

ratio = ["| Row | " + " | ".join(l for _, l in SERVERS) + " |", "|---" * (len(SERVERS) + 1) + "|"]
for h3, h1 in PAIRS:
    if not any(k[0] == h3 for k in cells):
        continue
    cols = []
    for s, _ in SERVERS:
        a, b = cells.get((h3, s)), cells.get((h1, s))
        cols.append(f"{100 * med(a, 'rps') / med(b, 'rps'):.0f}%" if a and b else "—")
    ratio.append(f"| {h3.replace('h3-', '')} | " + " | ".join(cols) + " |")

md = [
    f"nginx {env['nginx']}, HAProxy {env['haproxy']}, routez {env['routez']} (quic-zig {env['quic-zig']}), "
    f"{env['workers']} workers each. h2load {env['h2load']}, {env['conns']} connections, median of "
    f"{env['rounds']} × {env['duration']} s runs, in requests per second. Linux {env['kernel']}, "
    f"{env['cpus']} cpus; pinning: {env['pinning']}. TLS 1.3 with TLS_AES_128_GCM_SHA256, X25519 and an "
    f"ECDSA P-256 certificate. routez built with `-Dcpu={env['zig_cpu']}`. {env['date']}.",
    "", *table, "", "— HAProxy isn't a file server.",
]
if notes:
    md.append("† " + "; ".join(notes) + ".")
if saturated:
    md.append(f"‡ h2load (or the upstream, for a proxy row) was ≥{SATURATED}% busy: the rig may be the "
              "limit, not the server.")
md += ["", "**HTTP/3 as a share of the same server's HTTP/1.1 rate** (higher is better): what QUIC costs "
       "each server, measured by one client.", "", *ratio, "",
       "All figures, per row. Latency and RTT are h2load's own, over a closed-loop load: on a row "
       "where the server answers slowly, the request latency is what caps the rate.", "", *detail, ""]
(out / "table.md").write_text("\n".join(md))

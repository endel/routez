#!/usr/bin/env python3
"""Turns bench.sh's raw wrk runs in OUT/raw into OUT/results.jsonl and OUT/table.md."""
import json
import sys
from pathlib import Path

WORKLOADS = [
    ("return", "Fixed response (`return`)"),
    ("static", "10 KB static file"),
    ("proxy", "Reverse proxy to a keep-alive upstream"),
    ("tls-return", "TLS: fixed response"),
    ("tls-static", "TLS: 10 KB static file"),
    # wrk resumes the session on each reconnect (checked with nginx's $ssl_session_reused).
    ("tls-handshake", "TLS: new connection per request (resumed)"),
]
SERVERS = [("nginx", "nginx"), ("haproxy", "HAProxy"), ("routez", "routez")]
ERRORS = ("connect", "read", "write", "status", "timeout")
# Busy % past which wrk or the upstream, not the server, may be the limit.
SATURATED = 95


def cpu_list(spec):
    a, _, b = spec.partition("-")
    return range(int(a), int(b or a) + 1)


def proc_stat(path):
    out = {}
    for line in path.read_text().splitlines():
        name, *v = line.split()
        v = [int(x) for x in v[:8]]  # user..steal; guest is already in user
        out[int(name[3:])] = (sum(v) - v[3] - v[4], sum(v))
    return out


def busy(s0, s1, cpus):
    pct = [100 * (s1[c][0] - s0[c][0]) / max(1, s1[c][1] - s0[c][1]) for c in cpus]
    return round(sum(pct) / len(pct))


def rate(rps):
    return f"{rps / 1000:.0f}k" if rps >= 10_000 else f"{rps / 1000:.1f}k"


def ms(us):
    return f"{us / 1000:.2f} ms"


out = Path(sys.argv[1])
env = dict(line.split(": ", 1) for line in (out / "env.txt").read_text().splitlines())
groups = {g: cpu_list(env[f"{g}_cpus"]) for g in ("server", "wrk", "upstream")}
hs_groups = {**groups, "wrk": cpu_list(env["handshake_wrk_cpus"])}

runs = []
for txt in sorted((out / "raw").glob("*.txt")):
    workload, server, rnd = txt.stem.split(".")
    lines = [l for l in txt.read_text().splitlines() if l.startswith('{"requests"')]
    if not lines:
        sys.exit(f"no wrk result in {txt}:\n{txt.read_text()}")
    j = json.loads(lines[-1])
    s0, s1 = proc_stat(txt.with_suffix(".stat0")), proc_stat(txt.with_suffix(".stat1"))
    runs.append({
        "date": env["date"], "routez": env["routez"], "quic_zig": env["quic-zig"],
        "workload": workload, "server": server, "round": int(rnd),
        "rps": round(j["requests"] / (j["duration_us"] / 1e6)),
        "p50_us": j["p50_us"], "p99_us": j["p99_us"],
        "errors": {k: j[k] for k in ERRORS if j[k]},
        "cpu": {g: busy(s0, s1, c) for g, c in (hs_groups if workload == "tls-handshake" else groups).items()},
    })
with open(out / "results.jsonl", "w") as f:
    for r in runs:
        f.write(json.dumps(r) + "\n")

cells = {}
for r in runs:
    cells.setdefault((r["workload"], r["server"]), []).append(r)
for rs in cells.values():
    rs.sort(key=lambda r: r["rps"])


def median(rs):
    return rs[(len(rs) - 1) // 2]


pinned = not env["pinning"].startswith("none")
errors, saturated = [], False
head = "| Workload | " + " | ".join(label for _, label in SERVERS) + " | routez vs best other |"
table = [head, "|---" * (len(SERVERS) + 2) + "|"]
details = ["| Workload | Server | req/s (min–max) | p50 | p99 | CPU % server / wrk / upstream |", "|---|---|---|---|---|---|"]
for w, wlabel in WORKLOADS:
    if not any(k[0] == w for k in cells):
        continue
    row = []
    for s, slabel in SERVERS:
        rs = cells.get((w, s))
        if not rs:
            row.append("—")
            continue
        m = median(rs)
        mark = ""
        for r in rs:
            if r["errors"]:
                errors.append(f"{slabel}, {wlabel.lower()}, round {r['round']}: "
                              + ", ".join(f"{n} {k}" for k, n in r["errors"].items()))
        if any(r["errors"] for r in rs):
            mark += "†"
        rig = m["cpu"]["wrk"] if w != "proxy" else max(m["cpu"]["wrk"], m["cpu"]["upstream"])
        if pinned and rig >= SATURATED:
            mark += "‡"
            saturated = True
        row.append(f"{rate(m['rps'])}{mark}")
        cpu = m["cpu"]
        details.append(f"| {wlabel} | {slabel} | {rate(m['rps'])} ({rate(rs[0]['rps'])}–{rate(rs[-1]['rps'])}) "
                       f"| {ms(m['p50_us'])} | {ms(m['p99_us'])} | {cpu['server']} / {cpu['wrk']} / {cpu['upstream']} |")
    ours = cells.get((w, "routez"))
    others = [median(cells[w, s])["rps"] for s, _ in SERVERS if s != "routez" and (w, s) in cells]
    vs = f"{100 * (median(ours)['rps'] / max(others) - 1):+.0f}%" if ours and others else ""
    table.append(f"| {wlabel} | " + " | ".join(row) + f" | {vs} |")

md = [
    f"nginx {env['nginx']}, HAProxy {env['haproxy']}, routez {env['routez']} (quic-zig {env['quic-zig']}), "
    f"{env['workers']} workers each. `wrk -t{env['wrk_threads']} -c{env['conns']}`, keep-alive, "
    f"median of {env['rounds']} × {env['duration']} s runs, in requests per second. "
    f"Linux {env['kernel']}, {env['cpus']} cpus; pinning: {env['pinning']}. "
    f"TLS 1.3 with TLS_AES_128_GCM_SHA256, X25519 and an ECDSA P-256 certificate. "
    f"routez built with `-Dcpu={env['zig_cpu']}`. {env['date']}.",
    "",
    *table,
    "",
    "— HAProxy isn't a file server.",
]
if errors:
    md.append("† socket errors or non-2xx responses in at least one round: " + "; ".join(errors) + ".")
if saturated:
    md.append(f"‡ wrk (or the upstream, for the proxy) was ≥{SATURATED}% busy: the rig may be the limit, not the server.")
md += ["", *details, ""]
(out / "table.md").write_text("\n".join(md))

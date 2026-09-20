"""Helpers shared by report.py and report_ws.py."""
import json
from pathlib import Path

# Busy % past which the load generator or the upstream, not the server, may be the limit.
SATURATED = 95


def load_env(out: Path):
    return dict(line.split(": ", 1) for line in (out / "env.txt").read_text().splitlines())


def write_jsonl(out: Path, runs):
    with open(out / "results.jsonl", "w") as f:
        for r in runs:
            f.write(json.dumps(r) + "\n")


def ms(us):
    return f"{us / 1000:.2f} ms"


def cpu_list(spec):
    a, _, b = spec.partition("-")
    return range(int(a), int(b or a) + 1)


def proc_stat(path: Path):
    out = {}
    for line in path.read_text().splitlines():
        name, *v = line.split()
        v = [int(x) for x in v[:8]]  # user..steal; guest is already in user
        out[int(name[3:])] = (sum(v) - v[3] - v[4], sum(v))
    return out


def busy(s0, s1, cpus):
    pct = [100 * (s1[c][0] - s0[c][0]) / max(1, s1[c][1] - s0[c][1]) for c in cpus]
    return round(sum(pct) / len(pct))

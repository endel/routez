"""Helpers shared by every suite's report script, and the result schema.

Each suite writes one JSON object per run to OUT/results.jsonl:

    {suite, workload, server, round, date, routez, quic_zig,
     params: {...}, metrics: {...}, flags: [...]}

`params` names what was varied (workers, conns, level); `metrics` uses the
names in METRICS, which fix each figure's unit, direction and formatting.
scorecard.py can then rank any suite's rows without knowing the suite.
"""
import json
import statistics
from pathlib import Path
from typing import Callable, NamedTuple

# Busy % past which the load generator or the upstream, not the server, may be the limit.
SATURATED = 95
USER_HZ = 100  # /proc/stat ticks per second


def ms(us):
    return f"{us / 1000:.2f} ms"


def rate(n):
    return f"{n / 1000:.0f}k" if n >= 10_000 else f"{n / 1000:.1f}k"


def _n(x, unit="", digits=1):
    return f"{x:,.{digits}f}{unit}"


class Metric(NamedTuple):
    label: str
    better: int  # +1 higher is better, -1 lower is better
    fmt: Callable[[float], str]
    # A figure that can be negative, so a ratio between two of them says
    # nothing: a trend of -352 KB/min is not "52 times better" than +6.7.
    # Those are compared by direction instead.
    signed: bool = False


METRICS = {
    # Throughput
    "rps": Metric("req/s", +1, rate),
    "mbps": Metric("MB/s", +1, lambda v: _n(v, " MB/s")),
    "gbps": Metric("Gbit/s", +1, lambda v: _n(v, " Gbit/s", 2)),
    "pps": Metric("packets/s", +1, rate),
    "echoes_per_s": Metric("echoes/s", +1, rate),
    "connect_per_s": Metric("connects/s", +1, lambda v: f"{v / 1000:.1f}k/s"),
    "handshakes_per_s": Metric("handshakes/s", +1, rate),
    # Latency
    "p50_us": Metric("p50", -1, ms),
    "p90_us": Metric("p90", -1, ms),
    "p99_us": Metric("p99", -1, ms),
    "p95_us": Metric("p95", -1, ms),
    "p999_us": Metric("p99.9", -1, ms),
    "connect_us": Metric("connect", -1, ms),
    "rtt_us": Metric("smoothed RTT", -1, lambda v: f"{v:,.0f} µs"),
    "max_us": Metric("max", -1, ms),
    "overhead_us": Metric("added latency", -1, lambda v: f"{v:,.0f} µs"),
    # Cost. CPU per request still ranks servers when the load generator is the limit.
    "cpu_ms_per_1k": Metric("CPU ms/1k req", -1, lambda v: _n(v, " ms", 2)),
    "cpu_pct": Metric("CPU %", -1, lambda v: f"{v:.0f}%"),
    "rss_kb": Metric("RSS", -1, lambda v: f"{v / 1024:.1f} MB"),
    "kb_per_conn": Metric("KB/conn", -1, lambda v: _n(v, " KB")),
    "rss_slope_kb_min": Metric("RSS growth", -1, lambda v: _n(v, " KB/min"), signed=True),
    "fd_drift": Metric("fd drift", -1, lambda v: _n(v, "", 0), signed=True),
    # Robustness. Degradation is the victim metric's loss against its own baseline.
    "rps_kept_pct": Metric("throughput kept", +1, lambda v: f"{v:.0f}%"),
    "errors": Metric("errors", -1, lambda v: _n(v, "", 0)),
    "recover_s": Metric("recovery", -1, lambda v: _n(v, " s", 1)),
    "loss_pct": Metric("loss", -1, lambda v: f"{v:.2f}%"),
}


WORKLOAD_FIELDS = ("name", "scheme", "path", "lua", "servers", "check", "upstream", "conns", "profile")


def load_workloads(here: Path):
    """bench/workloads.txt, in report order. `label` is the rest of the line."""
    out = []
    for line in (here / "workloads.txt").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split(None, len(WORKLOAD_FIELDS))
        w = dict(zip(WORKLOAD_FIELDS, parts))
        w["label"] = parts[len(WORKLOAD_FIELDS)] if len(parts) > len(WORKLOAD_FIELDS) else w["name"]
        out.append(w)
    return out


def read_int(path: Path):
    """A sample file a racing process left empty reads as missing, not as zero."""
    if not path.exists():
        return None
    text = path.read_text().strip()
    return int(text) if text else None


def load_env(out: Path):
    return dict(line.split(": ", 1) for line in (out / "env.txt").read_text().splitlines())


def write_jsonl(out: Path, runs, name="results.jsonl"):
    with open(out / name, "w") as f:
        for r in runs:
            f.write(json.dumps(r) + "\n")


def read_jsonl(path: Path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def row(env, suite, workload, server, rnd, params, metrics, detail=None, flags=()):
    """One results.jsonl record. Unmeasured figures are dropped.

    `metrics` is what scorecard.py ranks; `detail` is reported but not ranked.
    A figure belongs in `detail` when a comparison of it would be meaningless:
    under a closed-loop load that saturates the server, latency is just the
    reciprocal of throughput and every server sits at 100% CPU.
    """
    return {
        "suite": suite, "workload": workload, "server": server, "round": int(rnd),
        "date": env["date"], "routez": env["routez"], "quic_zig": env["quic-zig"],
        "params": params,
        "metrics": {k: v for k, v in metrics.items() if v is not None},
        "detail": {k: v for k, v in (detail or {}).items() if v is not None},
        "flags": list(flags),
    }


def cpu_list(spec):
    out = []
    for part in spec.split(","):
        a, _, b = part.partition("-")
        out += list(range(int(a), int(b or a) + 1))
    return out


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


def cpu_seconds(s0, s1, cpus):
    """Busy CPU time over the window, summed over the group's cores."""
    return sum(s1[c][0] - s0[c][0] for c in cpus) / USER_HZ


def cpu_ms_per_1k(s0, s1, cpus, requests):
    if not requests:
        return None
    return 1000 * cpu_seconds(s0, s1, cpus) / requests * 1000


def _vals(rs, key):
    out = []
    for r in rs:
        for where in ("metrics", "detail"):
            if key in r.get(where, {}):
                out.append(r[where][key])
                break
    return out


def med(rs, key, default=None):
    """Median of one figure across rounds. Each is the median of its own
    distribution: throughput, latency and memory don't move together."""
    vals = _vals(rs, key)
    return statistics.median(vals) if vals else default


def spread(rs, key):
    vals = _vals(rs, key)
    return (min(vals), max(vals)) if vals else (None, None)

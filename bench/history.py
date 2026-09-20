#!/usr/bin/env python3
"""Keeps a record of past runs, so a change can be shown to have helped.

    bench/history.py add <result-dir> [...]     append those runs
    bench/history.py compare <result-dir> [...] against the newest older revision
    bench/history.py list                       what is on record

The record is bench/history.jsonl, one line per (suite, row, server, params,
metric): small enough to commit, so the history travels with the code. Each line
carries the routez and quic-zig revisions the figure was measured at.

`compare` picks, per suite, the most recent recorded run whose routez revision
differs from the one being compared, and reports the metrics that moved by more
than `--threshold` (5% by default). It is a signal, not a verdict: several of
these figures swing by more than that between rounds of the same build.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from rig import METRICS, med, read_jsonl

HERE = Path(__file__).parent
RECORD = HERE / "history.jsonl"


def collect(run_dir: Path):
    """One entry per (suite, row, server, params, metric), the median of rounds."""
    rows = read_jsonl(run_dir / "results.jsonl")
    if not rows:
        return []
    cells = defaultdict(list)
    for r in rows:
        key = (r["suite"], r["workload"], r["server"],
               json.dumps(r["params"], sort_keys=True))
        cells[key].append(r)
    out = []
    for (suite, workload, server, params), rs in cells.items():
        for metric in {m for r in rs for m in r["metrics"]}:
            v = med(rs, metric)
            if v is None:
                continue
            out.append({
                "date": rs[0]["date"], "routez": rs[0]["routez"], "quic_zig": rs[0]["quic_zig"],
                "run": run_dir.name, "suite": suite, "workload": workload, "server": server,
                "params": params, "metric": metric, "value": v,
                "flags": sorted({f for r in rs for f in r["flags"]}),
            })
    return out


def load():
    return read_jsonl(RECORD) if RECORD.exists() else []


def add(dirs):
    have = {(e["run"], e["suite"], e["workload"], e["server"], e["params"], e["metric"])
            for e in load()}
    new = []
    for d in dirs:
        for e in collect(Path(d)):
            if (e["run"], e["suite"], e["workload"], e["server"], e["params"], e["metric"]) in have:
                continue
            new.append(e)
    with RECORD.open("a") as f:
        for e in new:
            f.write(json.dumps(e) + "\n")
    print(f"added {len(new)} figures from {len(dirs)} run(s) to {RECORD.name}")


def compare(dirs, threshold):
    past = load()
    for d in dirs:
        now = collect(Path(d))
        if not now:
            print(f"{d}: no results", file=sys.stderr)
            continue
        suite, rev = now[0]["suite"], now[0]["routez"]
        # The newest recorded run of this suite at a different revision.
        others = [e for e in past if e["suite"] == suite and e["routez"] != rev]
        if not others:
            print(f"{suite}: nothing on record at another revision to compare with")
            continue
        base_run = max(others, key=lambda e: e["date"])["run"]
        base = {(e["workload"], e["server"], e["params"], e["metric"]): e
                for e in past if e["run"] == base_run}
        print(f"{suite}: {rev} against {base[next(iter(base))]['routez']} "
              f"(`{base_run}`), moves over {threshold:.0%}")
        moved = []
        for e in now:
            b = base.get((e["workload"], e["server"], e["params"], e["metric"]))
            if not b or not b["value"]:
                continue
            spec = METRICS[e["metric"]]
            change = (e["value"] - b["value"]) / abs(b["value"])
            if abs(change) < threshold:
                continue
            better = (change > 0) == (spec.better > 0)
            moved.append((abs(change), better, e, b, change, spec))
        if not moved:
            print("  nothing moved by more than the threshold")
            continue
        moved.sort(key=lambda m: (m[1], -m[0]))
        for _, better, e, b, change, spec in moved:
            print(f"  {'better' if better else 'worse ':6} {e['server']:8} {e['workload']:18} "
                  f"{spec.label:16} {spec.fmt(b['value'])} -> {spec.fmt(e['value'])} "
                  f"({change:+.0%})")


def listing():
    by_run = defaultdict(list)
    for e in load():
        by_run[e["run"]].append(e)
    for run, es in sorted(by_run.items(), key=lambda kv: kv[1][0]["date"]):
        e = es[0]
        print(f"{e['date']}  {e['suite']:8} routez {e['routez']:16} quic-zig {e['quic_zig']:10} "
              f"{len(es):4} figures  {run}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", choices=["add", "compare", "list"])
    ap.add_argument("dirs", nargs="*")
    ap.add_argument("--threshold", type=float, default=0.05)
    a = ap.parse_args()
    if a.action == "list":
        listing()
    elif not a.dirs:
        ap.error(f"{a.action} needs at least one result directory")
    elif a.action == "add":
        add(a.dirs)
    else:
        compare(a.dirs, a.threshold)


if __name__ == "__main__":
    main()

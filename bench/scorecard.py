#!/usr/bin/env python3
"""Ranks routez against the best competitor on every metric of every row.

    bench/scorecard.py [result-dir ...]

With no arguments it takes the newest result directory of each suite under
bench/results/. Output is bench/results/scorecard.md (or ./scorecard.md when
directories are named): one line per (row, metric), worst first, so the LOSS
and TIE lines are the work list.

A metric is a TIE when the two servers' min–max ranges across rounds overlap:
several of these figures swing enough between rounds that a small difference
means nothing.
"""
import sys
from collections import defaultdict
from pathlib import Path

from rig import METRICS, read_jsonl

HERE = Path(__file__).parent
OURS = "routez"
LABEL = {"nginx": "nginx", "haproxy": "HAProxy", "direct": "no proxy", "routez": "routez"}
# A baseline, not a competitor: it has no proxy in the path at all.
NOT_A_COMPETITOR = {"direct"}


def newest_per_suite(results: Path):
    best = {}
    for jsonl in sorted(results.glob("*/results.jsonl")):
        rows = read_jsonl(jsonl)
        if not rows:
            continue
        suite = rows[0].get("suite", "?")
        if suite not in best or jsonl.stat().st_mtime > best[suite].stat().st_mtime:
            best[suite] = jsonl
    return list(best.values())


def params_key(p):
    return ", ".join(f"{k}={v}" for k, v in sorted(p.items()))


def main(argv):
    if argv:
        files = [Path(a) / "results.jsonl" if Path(a).is_dir() else Path(a) for a in argv]
        out = Path("scorecard.md")
    else:
        files = newest_per_suite(HERE / "results")
        out = HERE / "results" / "scorecard.md"
    if not files:
        sys.exit("no results.jsonl found; run a suite first")

    # (suite, workload, params, metric, server) -> values across rounds
    vals = defaultdict(list)
    flagged = defaultdict(list)
    sources = []
    for f in files:
        rows = read_jsonl(f)
        sources.append(f"{rows[0]['suite']}: `{f.parent.name}` (routez {rows[0]['routez']}, {rows[0]['date']})")
        for r in rows:
            key = (r["suite"], r["workload"], params_key(r["params"]))
            for m, v in r["metrics"].items():
                if m in METRICS:
                    vals[key + (m, r["server"])].append(v)
            for fl in r["flags"]:
                flagged[key + (r["server"],)].append(fl)

    def median(xs):
        xs = sorted(xs)
        return xs[(len(xs) - 1) // 2]

    lines = []
    for (suite, workload, params, metric, server) in list(vals):
        if server != OURS:
            continue
        key = (suite, workload, params, metric)
        rivals = {s: vals[key + (s,)] for (*k, s) in vals
                  if tuple(k) == key and s != OURS and s not in NOT_A_COMPETITOR}
        if not rivals:
            continue
        spec = METRICS[metric]
        ours = vals[key + (OURS,)]
        # The rival that does best on this metric is the one to beat.
        best = max(rivals, key=lambda s: spec.better * median(rivals[s]))
        theirs = rivals[best]
        mo, mt = median(ours), median(theirs)
        if mo == 0 and mt == 0:
            continue
        overlap = min(max(ours), max(theirs)) >= max(min(ours), min(theirs))
        if spec.signed or mo <= 0 or mt <= 0:
            # Compared by direction: a ratio between figures that can be
            # negative, or that straddle zero, means nothing.
            ratio = None
            ahead = spec.better * (mo - mt)
            cls = "TIE" if overlap or ahead == 0 else ("WIN" if ahead > 0 else "LOSS")
        else:
            ratio = mo / mt if spec.better > 0 else mt / mo
            cls = "TIE" if overlap else ("WIN" if ratio > 1 else "LOSS")
        notes = sorted(set(flagged[(suite, workload, params, OURS)]
                           + flagged[(suite, workload, params, best)]))
        lines.append({
            "suite": suite, "workload": workload, "params": params, "metric": metric,
            "ours": spec.fmt(mo), "theirs": spec.fmt(mt), "rival": LABEL.get(best, best),
            "ratio": ratio, "cls": cls, "notes": notes,
        })

    rank = {"LOSS": 0, "TIE": 1, "WIN": 2}
    # A row with no ratio sorts at the neutral point of its class.
    lines.sort(key=lambda l: (rank[l["cls"]], l["ratio"] if l["ratio"] is not None else 1.0))
    counts = {c: sum(1 for l in lines if l["cls"] == c) for c in ("LOSS", "TIE", "WIN")}

    md = ["# Scorecard", "",
          f"routez against the best of nginx and HAProxy on every metric measured, worst first. "
          f"{counts['LOSS']} losses, {counts['TIE']} ties, {counts['WIN']} wins.", "",
          "Runs read:", ""]
    md += [f"- {s}" for s in sorted(sources)]
    md += ["", "`ratio` is how many times better routez is, so below 1 is a loss; a figure that can be "
           "negative is compared by direction instead. A TIE is a metric whose min–max ranges "
           "across rounds overlap: the difference is inside the noise.", "",
           "| | Suite | Row | Params | Metric | routez | best other | | ratio |",
           "|---|---|---|---|---|---|---|---|---|"]
    for l in lines:
        mark = "†" if l["notes"] else ""
        ratio = f"{l['ratio']:.2f}×" if l["ratio"] is not None else "by direction"
        md.append(f"| {l['cls']} | {l['suite']} | {l['workload']} | {l['params']} "
                  f"| {METRICS[l['metric']].label} | {l['ours']} | {l['theirs']} | {l['rival']} "
                  f"| {ratio}{mark} |")
    notes = sorted({n for l in lines for n in l["notes"]})
    if notes:
        md += ["", "† a round of this row carried: " + "; ".join(notes)
               + ". Read those lines as untrusted."]
    md.append("")
    out.write_text("\n".join(md))
    print(f"{counts['LOSS']} losses, {counts['TIE']} ties, {counts['WIN']} wins -> {out}")
    for l in lines[:15]:
        if l["cls"] != "WIN":
            ratio = f"{l['ratio']:.2f}x" if l["ratio"] is not None else "(by direction)"
            print(f"  {l['cls']:4} {l['suite']}/{l['workload']} {METRICS[l['metric']].label}: "
                  f"{l['ours']} vs {l['theirs']} ({l['rival']}) {ratio}")


if __name__ == "__main__":
    main(sys.argv[1:])

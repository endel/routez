#!/usr/bin/env python3
"""Where a request's time goes, from routez's per-connection qlogs (QLOG=1).

    bench/qlog_gaps.py QLOG_DIR

For every bidi request stream: `hold` is from the first packet carrying the
request to the first packet sent back on that stream (the server's share);
`gap` is from the last response packet on the previous stream to the next
request's first packet (the client's share plus one network crossing). One
line per connection, sorted by requests served: an h2load round's
connections share its regime, so the rounds fall out as clusters.
"""
import json
import statistics
import sys
from pathlib import Path


def events(path):
    for line in path.read_text(errors="replace").splitlines():
        line = line.lstrip("\x1e").strip()
        if not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def stream_frames(ev):
    for f in (ev.get("data") or {}).get("frames") or []:
        if f.get("frame_type") == "stream" and f.get("stream_id", 1) % 4 == 0:
            yield f


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p / 100 * len(xs)))] if xs else float("nan")


rows = []
for path in sorted(Path(sys.argv[1]).rglob("*")):
    if not path.is_file():
        continue
    first_recv, first_sent, last_sent = {}, {}, {}
    end = 0.0
    for ev in events(path):
        name = ev.get("name", "")
        t = ev.get("time")
        if t is None:
            continue
        end = max(end, t)
        for f in stream_frames(ev):
            sid = f["stream_id"]
            if name.endswith("packet_received"):
                first_recv.setdefault(sid, t)
            elif name.endswith("packet_sent"):
                first_sent.setdefault(sid, t)
                last_sent[sid] = t
    sids = sorted(first_recv)
    if len(sids) < 10:
        continue
    hold = [first_sent[s] - first_recv[s] for s in sids if s in first_sent]
    gap = [first_recv[b] - last_sent[a] for a, b in zip(sids, sids[1:]) if a in last_sent]
    rows.append((len(sids), statistics.median(hold), pct(hold, 90), statistics.median(gap), pct(gap, 90), end))

# Every connection of an h2load round shares its regime: sort by requests
# served and the rounds fall out as clusters.
rows.sort()
print(f"{'reqs':>7} {'hold p50':>9} {'p90':>7} {'gap p50':>8} {'p90':>7} {'lived':>7}  (ms; one line per connection)")
step = max(1, len(rows) // 40)
for r in rows[::step]:
    print(f"{r[0]:>7} {r[1]:9.3f} {r[2]:7.3f} {r[3]:8.3f} {r[4]:7.3f} {r[5]:7.0f}")
print(f"{len(rows)} connections")

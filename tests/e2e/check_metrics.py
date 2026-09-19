# Validate Prometheus text exposition (0.0.4) on stdin, strictly, then
# print the value of each series named on the command line ("-" if absent).
import re, sys

NAME = r"[a-zA-Z_:][a-zA-Z0-9_:]*"
LABEL = r'[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\[\\"n])*"'
SAMPLE = re.compile(rf"^({NAME})(\{{(?:{LABEL}(?:,{LABEL})*)?\}})? (-?[0-9]+(?:\.[0-9]+)?(?:e[+-]?[0-9]+)?|NaN|[+-]Inf)$")
HELP = re.compile(rf"^# HELP ({NAME}) \S.*$")
TYPE = re.compile(rf"^# TYPE ({NAME}) (counter|gauge|histogram|summary|untyped)$")

def fail(msg):
    print("invalid:", msg)
    sys.exit(1)

text = sys.stdin.read()
if not text.endswith("\n"):
    fail("no trailing newline")
types, helps, series = {}, set(), {}
for n, line in enumerate(text.split("\n")[:-1], 1):
    if m := HELP.match(line):
        if m[1] in helps: fail(f"line {n}: second HELP for {m[1]}")
        helps.add(m[1])
    elif m := TYPE.match(line):
        if m[1] in types: fail(f"line {n}: second TYPE for {m[1]}")
        types[m[1]] = m[2]
    elif line.startswith("#"):
        fail(f"line {n}: stray comment {line!r}")
    elif m := SAMPLE.match(line):
        name, labels, value = m[1], m[2] or "", m[3]
        if name not in types: fail(f"line {n}: {name} has no TYPE before it")
        if types[name] == "counter" and (not name.endswith("_total") or float(value) < 0):
            fail(f"line {n}: bad counter {line!r}")
        key = name + labels
        if key in series: fail(f"line {n}: duplicate series {key}")
        series[key] = value
    else:
        fail(f"line {n}: {line!r}")
print(" ".join(series.get(k, "-") for k in sys.argv[1:]))

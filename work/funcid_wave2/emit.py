"""Append/replace rows in out/<shard>.tsv from stdin lines: 'addr | name | subsystem | evidence'.

Last row per address wins. Rejects malformed lines (printed to stderr) and keeps the rest.
"""
import re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import OUT, NAME_OK

SUBSYS = {"core", "core-math", "crt", "render", "battle", "campaign", "ui", "audio", "anim", "fs",
          "net", "net-curl", "script", "ai", "cine", "model", "physics", "naval", "replay", "input",
          "vfx", "os", "middleware-facefx", "middleware-jsoncpp", "middleware-lglcd", "terrain",
          "unknown"}
BAD = re.compile(r"^(fun_|fn_|decomp_fn|sub_|unknown|func_?\d|function$|helper$|wrapper$)", re.I)

def parse(line):
    p = [x.strip() for x in line.split("|", 3)]
    if len(p) != 4: return None, "need 4 fields"
    a, name, sub, ev = p
    m = re.fullmatch(r"(?:0x)?([0-9a-fA-F]{8})", a)
    if not m: return None, "bad addr"
    if not NAME_OK.match(name) or BAD.match(name): return None, f"bad name {name!r}"
    if sub not in SUBSYS: return None, f"bad subsystem {sub!r} (allowed: {' '.join(sorted(SUBSYS))})"
    ev = re.sub(r"\s+", " ", ev)
    if not re.match(r"^\[[HML]\] \S", ev): return None, "evidence must start with [H]/[M]/[L] + text"
    return (m.group(1).lower(), name, sub, ev[:300]), None

def main():
    sid = sys.argv[1]
    sys.stdin.reconfigure(encoding="utf-8")
    OUT.mkdir(exist_ok=True)
    f = OUT / f"{sid}.tsv"
    rows = {}
    if f.exists():
        for l in f.read_text(encoding="utf-8").splitlines():
            x = l.split("\t")
            if len(x) == 4: rows[x[0][2:]] = x
    ok = bad = 0
    for line in sys.stdin:
        if not line.strip(): continue
        r, err = parse(line.rstrip("\n"))
        if err:
            bad += 1; print(f"REJECT ({err}): {line.strip()[:160]}", file=sys.stderr); continue
        rows[r[0]] = [f"0x{r[0]}", r[1], r[2], r[3]]; ok += 1
    f.write_text("".join("\t".join(rows[k]) + "\n" for k in sorted(rows)), encoding="utf-8", newline="\n")
    print(f"accepted {ok} rejected {bad}; {sid} now has {len(rows)} rows")

if __name__ == "__main__":
    main()

"""Merge shard outputs into work/funcid_w2_agents.tsv, resolve thunks, print coverage.

usage: finalize.py [--stats-only]
"""
import collections, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, OUT, WORK, db, load_names

def merge():
    dst = WORK / "funcid_w2_agents.tsv"
    if dst.exists(): dst.unlink()
    base = load_names(include_wave=False)
    rows = {}
    for p in sorted(OUT.glob("*.tsv")):
        for l in p.read_text(encoding="utf-8").splitlines():
            x = l.split("\t")
            if len(x) == 4 and x[0][2:] not in base:
                rows[x[0][2:]] = l
    dst.write_text("".join(rows[k] + "\n" for k in sorted(rows)), encoding="utf-8", newline="\n")
    print("agent rows", len(rows))

def stats():
    idx = {a for (a,) in db().execute("select addr from fn")}
    named = load_names()
    n = len(set(named) & idx)
    print(f"named {n}/{len(idx)} ({100*n/len(idx):.1f}%)")
    conf = collections.Counter()
    for p in [WORK / "funcid_w2_agents.tsv"] if (WORK / "funcid_w2_agents.tsv").exists() else sorted(OUT.glob("*.tsv")):
        for l in p.read_text(encoding="utf-8").splitlines():
            x = l.split("\t")
            if len(x) == 4: conf[x[3][:3]] += 1
    print("wave-2 agent confidence", dict(conf))

if __name__ == "__main__":
    if "--stats-only" not in sys.argv:
        merge()
        subprocess.run([sys.executable, str(HERE / "mechanical.py"), "thunks"], check=True)
    stats()

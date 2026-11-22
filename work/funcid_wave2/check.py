"""Gate a shard's output: every shard address named exactly once, valid rows, names unique."""
import collections, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, OUT
from emit import parse

sid = sys.argv[1]
want = (HERE / "shards" / f"{sid}.txt").read_text().split()
f = OUT / f"{sid}.tsv"
rows = [l for l in f.read_text(encoding="utf-8").splitlines()] if f.exists() else []
got, errs = {}, []
for l in rows:
    x = l.split("\t")
    r, err = parse(" | ".join(x)) if len(x) == 4 else (None, "need 4 tab fields")
    if err: errs.append(f"{l[:100]}: {err}"); continue
    got[r[0]] = r
missing = [a for a in want if a not in got]
extra = [a for a in got if a not in set(want)]
dups = [n for n, k in collections.Counter(r[1] for r in got.values()).items() if k > 1]
conf = collections.Counter(r[3][1] for r in got.values())
if missing: errs.append(f"{len(missing)} missing: " + " ".join("0x" + a for a in missing[:40]))
if extra: errs.append(f"{len(extra)} addresses not in shard: " + " ".join(extra[:10]))
if dups: errs.append(f"{len(dups)} duplicate names (append _<addr> to make unique): " + " ".join(dups[:20]))
print(f"{sid}: {len(got)}/{len(want)} named; confidence H={conf['H']} M={conf['M']} L={conf['L']}")
print("OK" if not errs else "FAIL\n" + "\n".join(errs))

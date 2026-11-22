"""Partition unnamed, non-thunk functions into agent shards.

Tier = call-graph height within the unnamed set (0 = calls no unnamed fn), capped at 4,
so earlier shards name callees before later shards read them. Within a tier, shards are
address-contiguous (MSVC links object files contiguously -> shared subsystem context).
"""
import collections, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, db, load_names

MODE = sys.argv[1] if len(sys.argv) > 1 else "main"   # hubs | main
HUB_MIN = 10
BUDGET, MAXN, PFX = (90000, 60, "h") if MODE == "hubs" else (110000, 260, "t")
CAP = 4

named = load_names()
c = db()
cost, todo = {}, set()
for a, kind, thunk, size, blen in c.execute("select addr,kind,thunk,size,length(body) from fn"):
    if a in named or kind == "thunk" or thunk:
        continue
    todo.add(a)
    cost[a] = min(blen, 3000) + (900 if MODE == "hubs" else 350)
if MODE == "hubs":
    indeg = dict(c.execute("select dst,count(distinct src) from edge group by dst").fetchall())
    todo = {a for a in todo if indeg.get(a, 0) >= HUB_MIN}
callees = collections.defaultdict(set)
for s, d in c.execute("select src,dst from edge"):
    if s in todo and d in todo and s != d:
        callees[s].add(d)
h = {a: 0 for a in todo}
for _ in range(CAP):
    changed = False
    for a in todo:
        v = min(CAP, 1 + max((h[d] for d in callees[a]), default=-1))
        if v > h[a]:
            h[a] = v; changed = True
    if not changed: break
sd = HERE / "shards"; sd.mkdir(exist_ok=True)
for f in sd.glob(f"{PFX}*.txt"): f.unlink()
order, n = [], 0
for t in range(CAP + 1):
    cur, cc = [], 0
    for a in sorted(x for x in todo if h[x] == t):
        if cur and (cc + cost[a] > BUDGET or len(cur) >= MAXN):
            order.append((f"{PFX}{t}_{n:04d}", cur)); n += 1; cur, cc = [], 0
        cur.append(a); cc += cost[a]
    if cur:
        order.append((f"{PFX}{t}_{n:04d}", cur)); n += 1
for sid, lst in order:
    (sd / f"{sid}.txt").write_text("\n".join(lst) + "\n", encoding="utf-8", newline="\n")
(HERE / f"shard_order_{MODE}.txt").write_text("\n".join(s for s, _ in order) + "\n", newline="\n")
tc = collections.Counter(h.values())
print("todo", len(todo), "tiers", dict(sorted(tc.items())), "shards", len(order))
print("by tier", collections.Counter(s.split("_")[0] for s, _ in order))

import collections, re, sys
sys.path.insert(0, __file__.rsplit("\\",1)[0].rsplit("/",1)[0])
from common import db, load_names
named = load_names()
c = db()
tot = 0; capped = 0; n = 0
shape = collections.Counter()
for a, size, body in c.execute("select addr,size,body from fn"):
    if a in named: continue
    n += 1; tot += len(body); capped += min(len(body), 3500)
    i = body.find("{"); inner = body[i+1:body.rfind("}")]
    stm = [l.strip() for l in inner.splitlines() if l.strip()]
    if len(stm) <= 1: shape[" ".join(stm)[:60] if stm else "<empty>"] += 1
print(n, tot, capped)
print(sum(shape.values()))
for k, v in shape.most_common(40): print(v, k)

import sys, collections
sys.path.insert(0, "work/funcid_wave2")
from common import db, load_names
named = load_names(); c = db()
rs = [(a, o, q, st, k, t, s) for a, o, q, st, k, t, s in c.execute("select addr,orig,qual,src_type,kind,thunk,size from fn") if a not in named]
lib = [r for r in rs if not r[1].startswith(("FUN_", "thunk_FUN_"))]
print("lib", len(lib)); 
for r in lib[:: max(1, len(lib)//40)]: print(r)
th = [r for r in rs if r[4] == "thunk" or r[5]]
print("thunk", len(th), "to-named", sum(1 for r in th if r[5] in named))
for r in th[:10]: print(r)

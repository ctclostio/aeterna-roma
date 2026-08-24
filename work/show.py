import sys,io
sys.stdout=io.TextIOWrapper(sys.stdout.buffer,errors='replace')
import json, sys, pickle
recs={r['addr']:r for r in pickle.load(open('evidence.pkl','rb'))}
for a in sys.argv[1:]:
    r=recs.get(a)
    if not r: print(a,'NO REC'); continue
    print(f"== {a} size={r['size']} switch={r['switch']} thiscall={r['thiscall']} globals={r['globals']}")
    if r['sig']: print('   sig:',r['sig'][:110])
    if r['strings']: print('   str:', ' | '.join(s[:60] for s in r['strings'][:14]))
    api=[x for x in r['api'] if x not in ('CONCAT31','CONCAT44','CONCAT22','CONCAT13','CONCAT11','CONCAT12','SQRT','ROUND','ABS','fpatan','fsin','fcos','_atexit','block','SUB41','SUB42','LOCK','UNLET')]
    if api: print('   api:', ','.join(api[:18]))
    if r['meth']: print('   meth:', ','.join(r['meth'][:10]))
    if r['alloc']: print('   alloc:', ','.join(r['alloc']))
    if r['funs']: print('   funs:', ' '.join(f'{x}x{c}' for x,c in r['funs'][:8]))

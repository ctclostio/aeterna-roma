import sys
# usage: python pick.py <slice_file> <start> <count>  -> prints addrs + sizes, skipping done
from pathlib import Path
W=Path('X:/decompilation/work'); D=Path('X:/decompilation/src_out/empire.retail.dll/decomp')
done=set()
for line in open(W/'funcid_solo.tsv',encoding='utf-8',errors='ignore'):
    if line.strip(): done.add(line.split('\t')[0].strip())
addrs=[a.strip() for a in open(W/sys.argv[1]) if a.strip()]
s=int(sys.argv[2]); n=int(sys.argv[3])
for a in addrs[s:s+n]:
    if a in done: print(f'{a} DONE-SKIP'); continue
    f=D/f'{a[2:]}_FUN_{a[2:]}.c'
    print(a, f.stat().st_size if f.exists() else 'MISSING')

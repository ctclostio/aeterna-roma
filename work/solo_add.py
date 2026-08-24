#!/usr/bin/env python3
"""Append validated TSV rows to funcid_solo_out.tsv. Reads 'addr name subsys evidence' lines on stdin."""
import sys
from pathlib import Path
OUT = Path('X:/decompilation/work/funcid_solo_out.tsv')
have = set()
if OUT.exists():
    have = {l.split('\t')[0] for l in OUT.read_text(errors='replace').splitlines() if l.strip()}
SUBS = {'render','battle','campaign','ui','audio','anim','fs','net','script',
        'core(memory/string)','core','crt','middleware-facefx','unknown'}
added=0
for line in sys.stdin:
    p=line.rstrip('\n').split('\t')
    if len(p)!=4 or not p[0].startswith('0x'): 
        if line.strip(): print("SKIP:",line[:60],file=sys.stderr)
        continue
    if p[0].lower() in have: continue
    if p[2] not in SUBS: p[2]='unknown'
    OUT.open('a',encoding='utf8').write('\t'.join(p)+'\n')
    have.add(p[0].lower()); added+=1
print(f"appended {added}, total {len(have)}")

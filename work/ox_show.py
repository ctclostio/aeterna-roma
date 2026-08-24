#!/usr/bin/env python3
import json,sys,io
from pathlib import Path
sys.stdout=io.TextIOWrapper(sys.stdout.buffer,encoding='utf8',errors='replace')
start,count=int(sys.argv[1]),int(sys.argv[2])
pend=[x.strip() for x in Path('ox_pending.txt').read_text().split()]
D={}
for l in Path('solo_digest.jsonl').read_text(encoding='utf8').splitlines():
    d=json.loads(l); D[d['addr']]=d
for a in pend[start:start+count]:
    d=D.get(a)
    if not d: print(f'### {a} NO-DIGEST'); continue
    print(f"### {a} sz={d['size']}")
    if d['strings']: print('  STR:', ' | '.join(s[:60] for s in d['strings'][:7]))
    if d['apis']: print('  API:', ', '.join(f'{c}x{n}' for c,n in d['apis'][:8]))
    if d['types']: print('  TYP:', ', '.join(d['types'][:6]))
    cal=', '.join((f"{c['fa']}:{c['nm']}x{c['n']}" if c.get('nm') else f"{c['fa']}x{c['n']}") for c in d['calls'][:6])
    if cal: print('  CAL:', cal)

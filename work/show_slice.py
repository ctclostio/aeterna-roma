#!/usr/bin/env python3
"""Print solo_digest.jsonl slice [start,count). Usage: python show_slice.py <start> <count>"""
import json, sys, io
from pathlib import Path
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf8', errors='replace')
start, count = int(sys.argv[1]), int(sys.argv[2])
pend = [x.strip() for x in Path('solo_pending.txt').read_text().split() if x.strip()]
D = {}
for line in Path('solo_digest.jsonl').read_text(encoding='utf8').splitlines():
    d = json.loads(line); D[d['addr']] = d
for a in pend[start:start+count]:
    d = D.get(a)
    if not d or d.get('missing'):
        print(f'### {a} MISSING'); continue
    print(f"### {a} sz={d['size']} {d['sig']}")
    if d['strings']: print('  STR:', ' | '.join(s[:64] for s in d['strings'][:8]))
    if d['apis']: print('  API:', ', '.join(f'{c}x{n}' for c, n in d['apis'][:10]))
    if d['types']: print('  TYP:', ', '.join(d['types']))
    cal = ', '.join((f"{c['fa']}:{c['nm']}x{c['n']}" if c.get('nm') else f"{c['fa']}x{c['n']}") for c in d['calls'][:7])
    if cal: print('  CAL:', cal)

#!/usr/bin/env python3
"""Show pending-digest entries for solo_remaining queue. Usage: show_remaining.py <start> <count>"""
import json, sys
from pathlib import Path

start = int(sys.argv[1]); count = int(sys.argv[2])
addrs = [a.strip() for a in Path('work/solo_remaining.txt').read_text().split()]
digest = {}
for line in Path('work/solo_remaining_digest.jsonl').read_text().splitlines():
    d = json.loads(line); digest[d['addr'].removeprefix('0x')] = d

NAMED = {}
for line in open('src_out/empire.retail.dll/named_functions.txt', encoding='utf8', errors='replace'):
    p = line.split('\t')
    if len(p) >= 2:
        NAMED.setdefault(p[0].strip().lower().removeprefix('0x'), p[1].strip())

for a in addrs[start:start+count]:
    h = a.removeprefix('0x')
    d = digest.get(h)
    if not d:
        if d is None and digest.get(a): d = digest[a]
        else: print(f'### 0x{h} NO-DIGEST'); continue
    print(f"### {a} size={d['size']}")
    if d['strings']: print('  STR:', ' | '.join(s[:70] for s in d['strings'][:8]))
    if d['calls']: print('  API:', ', '.join(f'{c}x{n}' for c, n in list(d['calls'])[:12]))
    tops = []
    for fa, cnt in d['fun_top']:
        nm = NAMED.get(fa)
        tops.append(f'{fa}:{nm}x{cnt}' if nm else f'{fa}x{cnt}')
    if tops: print('  CAL:', ', '.join(tops))

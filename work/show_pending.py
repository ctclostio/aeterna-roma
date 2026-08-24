#!/usr/bin/env python3
"""Show pending-digest entries for a slice, with callee names resolved from
named_functions.txt + funcid_main.tsv proposals. Usage: show_digest.py <start> <count>"""
import json, sys
from pathlib import Path

start = int(sys.argv[1]); count = int(sys.argv[2])
addrs = [a.strip() for a in Path('solo_pending.txt').read_text().split()]
digest = {}
for line in Path('pending_digest.jsonl').read_text().splitlines():
    d = json.loads(line); digest[d['addr']] = d

NAMED = {}
for line in open('../src_out/empire.retail.dll/named_functions.txt', encoding='utf8', errors='replace'):
    p = line.split('\t')
    if len(p) >= 2:
        NAMED.setdefault('0x' + p[0].strip().lower().removeprefix('0x'), p[1].strip())
MINE = {}
for line in Path('funcid_main.tsv').read_text().splitlines():
    p = line.split('\t')
    if len(p) >= 2:
        MINE.setdefault(p[0].strip().lower().removeprefix('0x'), f"{p[1]}[{p[2]}]")

for a in addrs[start:start+count]:
    d = digest.get(a)
    if not d: print(f'### {a} NO-DIGEST'); continue
    h = a.removeprefix('0x')
    print(f"### {a} size={d['size']} sig={d['sig'][:70]}")
    if d['strings']: print('  STR:', ' | '.join(s[:60] for s in d['strings'][:8]))
    if d['calls']: print('  API:', ', '.join(f'{c}x{n}' for c, n in list(d['calls'])[:12]))
    if d['fun_resolved']: print('  RES:', ', '.join(f'{n}x{c}' for _, c, n in d['fun_resolved'][:8]))
    tops = []
    for fa, cnt in d['fun_top']:
        nm = MINE.get(fa) or NAMED.get(fa)
        tops.append(f'{fa}:{nm}x{cnt}' if nm else f'{fa}x{cnt}')
    if tops: print('  CAL:', ', '.join(tops))

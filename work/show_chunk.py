#!/usr/bin/env python3
"""Print a chunk of the remaining digest with callee names resolved.
Usage: show_chunk.py <start> <count> [filter_substring]"""
import json, sys
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

start = int(sys.argv[1]); count = int(sys.argv[2])
filt = sys.argv[3].lower() if len(sys.argv) > 3 else None

ds, missing = [], []
for l in Path('work/remaining_digest.jsonl').read_text(encoding='utf8').splitlines():
    if '\tMISSING' in l:
        missing.append(l.split('\t')[0]); continue
    ds.append(json.loads(l))

NAMED = {}
for line in open('src_out/empire.retail.dll/named_functions.txt', encoding='utf8', errors='replace'):
    p = line.split('\t')
    if len(p) >= 2:
        NAMED.setdefault(p[0].strip().lower(), p[1].strip())

MINE = {}
for f in ['funcid_main.tsv', 'funcid_solo.tsv', 'funcid_todo2_out.tsv', 'funcid_todo2_results.tsv']:
    p = Path('work') / f
    if not p.exists(): continue
    for line in p.read_text(encoding='utf8').splitlines():
        q = line.split('\t')
        if len(q) >= 3 and q[0].startswith('0x'):
            MINE.setdefault(q[0].strip().lower(), f"{q[1]}[{q[2]}]")

n = 0
for i, d in enumerate(ds):
    if i < start: continue
    if n >= count: break
    a = d['addr']
    blob = json.dumps(d).lower()
    if filt and filt not in blob and filt not in a: continue
    n += 1
    h = a[2:]
    print(f"### {a} size={d['size']} sig={d['sig'][:60]}")
    if d['strings']: print('  STR:', ' | '.join(s[:55] for s in d['strings'][:7]))
    if d['calls']: print('  API:', ', '.join(f'{c}x{k}' for c, k in d['calls'][:10]))
    if d['fun_resolved']: print('  NAMED:', ', '.join(f"{nm}x{k}" for _, k, nm in d['fun_resolved'][:8]))
    tops = []
    for fa, cnt in d['fun_top']:
        nm = MINE.get(fa) or NAMED.get(fa)
        tops.append(f'{fa}:{nm}x{cnt}' if nm else f'{fa}x{cnt}')
    if tops: print('  CAL:', ', '.join(tops))

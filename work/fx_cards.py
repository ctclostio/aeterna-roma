#!/usr/bin/env python3
"""Build compact context cards for manual funcid review."""
import json, re, sys
from pathlib import Path
ROOT = Path('X:/decompilation')
DEC = ROOT / 'src_out/empire.retail.dll/decomp'
recs = {r['addr']: r for r in (json.loads(l) for l in open(ROOT / 'work/batch1_evidence.jsonl', encoding='utf-8'))}
v3 = {}
for line in open(ROOT / 'work/funcid_batch1_v3.tsv', encoding='utf-8'):
    p = line.rstrip('\n').split('\t'); v3[p[0]] = p[2]

which = sys.argv[1] if len(sys.argv) > 1 else 'stronly'
N = int(sys.argv[2]) if len(sys.argv) > 2 else 40
if which == 'stronly':
    sel = [r for r in recs.values() if v3.get(r['addr']) == 'unknown' and r['strings'] and not r['imports']]
elif which == 'opaque':
    sel = [r for r in recs.values() if v3.get(r['addr']) == 'unknown' and not r['strings'] and not r['imports']]
else:
    sel = [recs[a] for a in which.split(',') if a in recs]
sel.sort(key=lambda r: -r['size'])

for r in sel[:N]:
    path = DEC / r['file']
    txt = open(path, encoding='utf-8', errors='replace').read()
    # strip WARNING comment blocks
    body = re.sub(r'/\* WARNING[^\n]*\*/\s*', '', txt)
    lines = [l for l in body.split('\n') if l.strip()]
    # skip decl header; find first '{'
    try:
        i = lines.index('{')
    except ValueError:
        i = 10
    snippet = '\n'.join(lines[i:i + 34])
    print('=' * 100)
    print(f"### {r['addr']}  size={r['size']} subsys={v3.get(r['addr'])}")
    if r['strings']: print(f"  STR: {[s[:70] for s in r['strings'][:8]]}")
    if r['named_calls']:
        nc = [(k, v) for k, v in r['named_calls'].items() if k not in
              ('CONCAT11','CONCAT22','CONCAT31','CONCAT33','CONCAT44','ROUND','SQRT','ABS','block','swi','guard_check_icall')]
        print(f"  CALLS: {nc[:8]}")
    print(snippet)

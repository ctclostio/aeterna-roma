#!/usr/bin/env python3
"""ox's evidence bundle for funcid solo run (uniquely named to avoid collisions).
Usage: python ox_ctx.py <addr> [addr...]
"""
import json, re, sys
from pathlib import Path

ROOT = Path('X:/decompilation')
DECOMP = ROOT / 'src_out/empire.retail.dll/decomp'

NAMES = {}
for line in open(ROOT/'src_out/empire.retail.dll/named_functions.txt', encoding='utf8', errors='replace'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 2:
        NAMES.setdefault(p[0].strip().lower().removeprefix('0x'), p[1].strip())
for f in ['funcid_main.tsv','funcid_solo.tsv','funcid_solo2.tsv'] + [f'funcid_{i:02d}.tsv' for i in range(25)]:
    p = ROOT/'work'/f
    if not p.exists(): continue
    for line in p.read_text(encoding='utf8', errors='replace').splitlines():
        c = line.split('\t')
        if len(c) >= 2 and c[0].strip():
            NAMES.setdefault(c[0].strip().lower().removeprefix('0x'), c[1].strip())

DIG = {}
for f in ['digest_00.jsonl','digest_01.jsonl','digest_02.jsonl','pending_digest.jsonl','solo_claim_digest.jsonl','funcid_digest2.jsonl']:
    p = ROOT/'work'/f
    if not p.exists(): continue
    for line in p.read_text(encoding='utf8', errors='replace').splitlines():
        try:
            d = json.loads(line)
            DIG.setdefault(d['addr'].lower().removeprefix('0x'), d)
        except Exception:
            pass

def ctx(a):
    a = a.strip().lower().removeprefix('0x')
    cf = DECOMP/f"{a}_FUN_{a}.c"
    print(f"===== {a} size={cf.stat().st_size if cf.exists() else '?'}")
    d = DIG.get(a)
    if d:
        if d.get('strings'): print('  STR:', ' | '.join(s.replace('\n','\\n')[:70] for s in d['strings'][:10]))
        if d.get('calls'): print('  API:', ', '.join(f'{n}x{c}' for n,c in d['calls'][:14]))
        tops=[(fa + (':'+NAMES[fa.lower()] if fa.lower() in NAMES else ''), cnt) for fa,cnt in d.get('fun_top',[])[:10]]
        if tops: print('  CAL:', ', '.join(f'{s}x{c}' for s,c in tops))
    else:
        print('  (no digest)')
    if not cf.exists():
        print('  MISSING FILE'); return
    txt = cf.read_text(encoding='utf8', errors='replace')
    lines = txt.splitlines()
    hits = []
    for i, l in enumerate(lines):
        for m in re.finditer(r'(?:L?)"([^"\n]{4,90})"', l):
            s = m.group(1)
            if re.fullmatch(r'[\x20-\x7e]+', s):
                hits.append(f'L{i+1}:"{s}"')
    seen=set(); dedup=[]
    for h in hits:
        k=h.split(':',1)[1]
        if k not in seen: seen.add(k); dedup.append(h)
    if dedup: print('  LIT:', ' ; '.join(dedup[:14]))
    print('  HEAD:')
    for l in lines[:10]: print('   |', l[:150])
    print('  TAIL:')
    for l in lines[-5:]: print('   |', l[:150])

for a in sys.argv[1:]:
    ctx(a)

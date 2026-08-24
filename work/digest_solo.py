#!/usr/bin/env python3
"""Rich per-function digest for the solo funcid queue.
Usage: python digest_solo.py <start> <count>
Writes work/solo_digest.jsonl (all pending) and prints a slice."""
import re, sys, json
from pathlib import Path
from collections import Counter

DECOMP = Path('../src_out/empire.retail.dll/decomp')
NAMED = {}
for line in open('../src_out/empire.retail.dll/named_functions.txt', encoding='utf8', errors='replace'):
    p = line.split('\t')
    if len(p) >= 2:
        NAMED.setdefault(p[0].strip().lower().removeprefix('0x'), p[1].strip())
MINE = {}
for f in ('funcid_main.tsv', 'funcid_solo.tsv', 'funcid_todo2_out.tsv'):
    p = Path(f)
    if not p.exists(): continue
    for line in p.read_text(errors='replace').splitlines():
        c = line.split('\t')
        if len(c) >= 3 and c[0].startswith('0x'):
            MINE.setdefault(c[0].strip().lower(), f"{c[1]}[{c[2]}]")

STR_RE = re.compile(r'"((?:[^"\\\n]|\\.){3,140})"')
CALL_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]{2,40})\s*\(')
FUN_RE = re.compile(r'\bFUN_([0-9a-f]{8})\b')
TYP_RE = re.compile(r'\b(((?:[A-Z][A-Za-z0-9]*::)+)?(Fx|CLua|C[A-Z])[A-Za-z0-9_]{2,30})\b')
SKIP_CALLS = {'if','for','while','switch','return','sizeof','CONCAT','LOCK','UNLOCK',
              'SQRT','ABS','assert','undefined'}
VTAB = re.compile(r'\b(PTR_[A-Za-z0-9_]+|[a-zA-Z_]\w*)_(\d{8})\b')

def digest(a):
    na = a[2:]
    txt = (DECOMP / f'{na}_FUN_{na}.c').read_text(encoding='utf8', errors='replace')
    size = len(txt)
    strs = []
    for s in STR_RE.findall(txt):
        s2 = s.strip()
        if len(s2) >= 4 and s2 not in strs: strs.append(s2)
    apis = Counter(c for c in CALL_RE.findall(txt)
                   if c not in SKIP_CALLS and not c.startswith(('DAT_','s_','LAB_','FUN_'))
                   and c not in ('int','char','uint','float','double','void','byte','word',
                                 'dword','bool','short','long','code','undefined4'))
    funs = Counter(FUN_RE.findall(txt))
    res = []
    for fa, cnt in funs.most_common(20):
        nm = MINE.get('0x'+fa) or NAMED.get(fa)
        res.append({'fa': '0x'+fa, 'n': cnt, 'nm': nm} if nm else {'fa': '0x'+fa, 'n': cnt})
    typs = []
    for m in TYP_RE.finditer(txt):
        t = m.group(1).split('::')[-1]
        if t not in typs and not re.match(r'^(CONCAT|CARRY|SUB|BVar|DVar|FVar|uVar|iVar|pcVar|puVar|local_|in_|extraout|DAT|LAB|PTR|uRam)', t):
            typs.append(t)
    vtabs = sorted(set(VTAB.findall(txt)))[:6]
    m = re.search(r'Signature type\s+(.*)', txt)
    sig = m.group(1)[:70] if m else ''
    return {'addr': a, 'size': size, 'sig': sig, 'strings': strs[:10],
            'apis': apis.most_common(14), 'types': typs[:8],
            'vtab': [f'{n}_{o}' for n, o in vtabs], 'calls': res}

if __name__ == '__main__':
    pend = [x.strip() for x in Path('solo_pending.txt').read_text().split() if x.strip()]
    start, count = int(sys.argv[1]), int(sys.argv[2])
    out = Path('solo_digest.jsonl')
    done_map = {}
    if out.exists():
        for line in out.read_text().splitlines():
            d = json.loads(line); done_map[d['addr']] = d
    todo = pend[start:start+count]
    with out.open('a', encoding='utf8') as fh:
        for a in todo:
            if a in done_map: continue
            try:
                d = digest(a)
            except FileNotFoundError:
                d = {'addr': a, 'size': 0, 'missing': True}
            fh.write(json.dumps(d) + '\n'); fh.flush()
    # print slice with callee-name resolution
    allmap = dict(done_map)
    for line in out.read_text().splitlines():
        d = json.loads(line); allmap[d['addr']] = d
    for a in todo:
        d = allmap.get(a)
        if d is None or d.get('missing'):
            print(f'### {a} MISSING'); continue
        print(f"### {a} sz={d['size']} {d['sig']}")
        if d['strings']: print('  STR:', ' | '.join(s[:64] for s in d['strings'][:8]))
        if d['apis']: print('  API:', ', '.join(f'{c}x{n}' for c, n in d['apis'][:10]))
        if d['types']: print('  TYP:', ', '.join(d['types']))
        cal = ', '.join((f"{c['fa']}:{c['nm']}x{c['n']}" if c.get('nm') else f"{c['fa']}x{c['n']}")
                        for c in d['calls'][:7])
        if cal: print('  CAL:', cal)

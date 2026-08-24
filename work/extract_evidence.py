#!/usr/bin/env python3
"""Digest decompiled functions into compact evidence lines for classification."""
import re, sys, json
from pathlib import Path
from collections import Counter

DECOMP = Path('src_out/empire.retail.dll/decomp')
NAMED = {}
for line in open('src_out/empire.retail.dll/named_functions.txt', encoding='utf8', errors='replace'):
    p = line.split('\t')
    if len(p) >= 2:
        NAMED[p[0].strip().lower()] = p[1].strip()

addrs = [a.strip() for a in Path(sys.argv[1]).read_text().split() if a.strip()]

STR_RE = re.compile(r'"([^"\\\n]{3,120})"')
CALL_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]{2,40})\s*\(')
FUN_RE = re.compile(r'\bFUN_([0-9a-f]{8})\b')
SKIP_CALLS = {'if','for','while','switch','return','sizeof','CONCAT','LOCK','UNLOCK',
              'SQRT','ABS','assert'}

out = open(sys.argv[2], 'w', encoding='utf8')
for a in addrs:
    na = a[2:] if a.startswith('0x') else a
    f = DECOMP / f'{na}_FUN_{na}.c'
    try:
        txt = f.read_text(encoding='utf8', errors='replace')
    except FileNotFoundError:
        out.write(f'{a}\tMISSING\n'); continue
    size = len(txt)
    strs = [s for s in STR_RE.findall(txt)]
    # dedupe preserving freq order, skip noise like ".meta"
    freq = Counter(s.strip() for s in strs if len(s.strip()) >= 4)
    top_strs = [s for s, c in freq.most_common(10) if not s.startswith('@')]
    calls = Counter(c for c in CALL_RE.findall(txt) if c not in SKIP_CALLS
                    and not c.startswith(('DAT_', 's_', 'LAB_', 'SUB$', '_'))
                    and c not in ('undefined','int','char','uint','float','double','void',
                                  'byte','word','dword','bool','short','long','code'))
    named_calls = {c: n for c, n in calls.items() if not c.startswith('FUN_')}
    fun_calls = {f'FUN_{k}': v for k, v in
                 ((k, calls.get(f'FUN_{k}', 0)) for k in [])}
    funs = Counter(FUN_RE.findall(txt))
    # resolve FUN_ callees against named_functions (exact addr match)
    resolved = []
    for fa, cnt in funs.most_common(15):
        nm = NAMED.get('0x' + fa.lower()) or NAMED.get(fa)
        resolved.append((fa, cnt, nm))
    sig = ''
    m = re.search(r'Signature: (.*)', txt)
    if m: sig = m.group(1)[:60]
    out.write(json.dumps({
        'addr': a, 'size': size, 'sig': sig,
        'strings': top_strs[:8],
        'calls': [(c, n) for c, n in named_calls.items()],
        'fun_resolved': [(fa, cnt, nm) for fa, cnt, nm in resolved if nm],
        'fun_top': [(fa, cnt) for fa, cnt, nm in resolved[:6]],
    }) + '\n')
out.close()
print(f'digested {len(addrs)}')

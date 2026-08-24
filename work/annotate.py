#!/usr/bin/env python3
"""Annotate decompiled C: resolve DAT_/s_/unaff ref addresses to strings, flag known callee names.
Usage: python annotate.py <addr> [addr...]   (addr with or without 0x)
"""
import sys, re
from pathlib import Path
ROOT = Path('X:/decompilation')
DEC = ROOT / 'src_out/empire.retail.dll/decomp'
# load va->string map (first occurrence wins)
vmap = {}
for line in open(ROOT / 'work/va_strings.txt', encoding='utf-8', errors='replace'):
    a, _, s = line.rstrip('\n').partition('\t')
    if a not in vmap: vmap[a] = s[:90]
named = {}
for line in open(ROOT / 'src_out/empire.retail.dll/named_functions.txt', encoding='utf-8', errors='replace'):
    p = line.split('\t')
    if len(p) >= 2: named[p[0].lower()] = p[1]
strre = re.compile(r'(?:DAT_|s_|UNK_)([0-9a-fA-F]{8})')
callre = re.compile(r'(FUN_|THUNK_)?([0-9a-fA-F]{8})_(FUN_\2|[A-Za-z_~][\w:<>~]*)')

for arg in sys.argv[1:]:
    addr = arg.lower().removeprefix('0x')
    f = DEC / f'{addr}_FUN_{addr}.c'
    if not f.exists():
        cands = list(DEC.glob(f'{addr}_*.c'))
        if not cands: print(f'### {addr}: FILE NOT FOUND'); continue
        f = cands[0]
    print(f'\n===== {f.stem} =====')
    for i, line in enumerate(open(f, encoding='utf-8', errors='replace')):
        ann = []
        for m in strre.finditer(line):
            va = m.group(1).lower()
            if va in vmap: ann.append(vmap[va])
        seen = set()
        for m in re.finditer(r'\b(FUN_[0-9a-f]{8}|[0-9a-f]{8}_[A-Za-z][\w]*)\b', line):
            t = m.group(0)
            base = t.split('_', 1)[-1] if t.startswith('FUN_') else None
            key = None
            if t.startswith('FUN_'): key = t[4:].lower()
            else:
                parts = t.split('_', 1)
                if len(parts) == 2 and len(parts[0]) == 8: key = parts[0].lower()
            if key and key in named and named[key] not in seen:
                seen.add(named[key]); ann.append(f'->{named[key]}')
        print(line.rstrip())
        if ann:
            print('      ; ' + ' | '.join(dict.fromkeys(ann)))

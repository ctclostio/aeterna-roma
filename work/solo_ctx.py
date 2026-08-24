#!/usr/bin/env python3
"""Context for solo analyst: digest + live callee-name resolution.
Usage: solo_ctx.py <addr> [<addr>...]"""
import json, sys, re
from pathlib import Path
W = Path('X:/decompilation/work')
NAMED = {}
for src in ['X:/decompilation/src_out/empire.retail.dll/named_functions.txt', W/'funcid_main.tsv', W/'funcid_solo_out.tsv']:
    try:
        for line in open(src, encoding='utf8', errors='replace'):
            p=line.split('\t')
            if len(p)>=2:
                k=p[0].strip().lower()
                if not k.startswith('0x'): k='0x'+k.lstrip('0x')
                NAMED.setdefault(k, p[1].strip())
    except FileNotFoundError: pass
dig={}
for l in (W/'pending_digest.jsonl').read_text(errors='replace').splitlines():
    d=json.loads(l); dig[d['addr'].lower()]=d
for a in sys.argv[1:]:
    na=None; a=a.strip().lower(); na=a.removeprefix('0x')
    print(f"=== {a} ({dig.get(a,{}).get('size','?')} bytes)")
    d=dig.get(a)
    if not d: continue
    if d['strings']: print(' STR:', ' | '.join(s[:70] for s in d['strings'][:6]))
    api=[f'{c}x{n}' for c,n in d['calls'][:10]]
    if api: print(' API:', ', '.join(api))
    tops=[]
    for fa,cnt in d['fun_top']:
        nm=NAMED.get('0x'+fa)
        tops.append(f'{nm}({fa})x{cnt}' if nm else f'{fa}x{cnt}')
    print(' CAL:', ', '.join(tops))

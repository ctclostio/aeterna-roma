#!/usr/bin/env python3
"""Compact structural summary of decompiled funcs for no-string triage."""
import sys, re
from pathlib import Path
DECOMP = Path('X:/decompilation/src_out/empire.retail.dll/decomp')
NAMED = {}
for src in ['X:/decompilation/src_out/empire.retail.dll/named_functions.txt','X:/decompilation/work/funcid_main.tsv','X:/decompilation/work/funcid_solo_out.tsv']:
    try:
        for line in open(src, encoding='utf8', errors='replace'):
            p=line.split('\t')
            if len(p)>=2:
                k=p[0].strip().lower()
                if not k.startswith('0x'): k='0x'+k.lstrip('0x')
                NAMED.setdefault(k,p[1].strip())
    except FileNotFoundError: pass
VT = {}
try:
    for line in open('X:/decompilation/src_out/empire.retail.dll/vftables.txt',encoding='utf8',errors='replace'):
        p=line.rstrip('\n').split('\t')
        if len(p)>=3: VT[p[0].strip().lower()]=p[2]
except FileNotFoundError: pass
FUN_RE=re.compile(r'\bFUN_([0-9a-f]{8})\b')
API_RE=re.compile(r'\b([A-Z][A-Za-z0-9]{3,28})\s*\(')
for a in sys.argv[1:]:
    na=a.removeprefix('0x').lower()
    f=DECOMP/f'{na}_FUN_{na}.c'
    try: txt=f.read_text(encoding='utf8',errors='replace')
    except FileNotFoundError:
        print(f"### {a} MISSING"); continue
    sig=re.search(r'Signature: (.*)',txt)
    apis=sorted({m for m in API_RE.findall(txt) if m not in ('CONCAT','SQRT','ABS','ROUND','SUB','FUN') and not m.startswith('FUN')} )[:8]
    funs={}
    for m in FUN_RE.findall(txt):
        k='0x'+m; funs[k]=funs.get(k,0)+1
    cn=[f"{NAMED.get(k,k)}x{c}" for k,c in sorted(funs.items(),key=lambda x:-x[1])[:7]]
    vt=[f"+{o}" for o in re.findall(r'\*\*\(code \*\)\(\*[^\)]+\+(0x[0-9a-f]+)\)',txt)][:6]
    allocs=re.findall(r'FUN_(?:100d12b0|100fcc80|101206f0|10120560)\w*\((0x[0-9a-f]+)',txt)[:5]
    consts=sorted({c for c in re.findall(r'\b(0x[0-9a-f]{4,})\b',txt) if int(c,16)>0xff and int(c,16)!=0x3f800000})[:8]
    print(f"### {a} sz={len(txt)//1024}K sig={sig.group(1)[:52] if sig else '?'}")
    if apis: print(' api:',','.join(apis))
    if cn: print(' cal:',', '.join(cn))
    if vt: print(' vtbl:',','.join(vt))
    if allocs: print(' alloc:',','.join(allocs))
    if consts: print(' const:',','.join(consts))

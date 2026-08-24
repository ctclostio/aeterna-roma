#!/usr/bin/env python3
"""Annotate addrs with nearest preceding/following named symbol (exports + named_functions + classified TSVs).
Usage: python anchor.py <start> <count>"""
import sys, io, bisect
from pathlib import Path
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf8', errors='replace')
pend=[x.strip() for x in Path('solo_pending.txt').read_text().split() if x.strip()]
syms={}
import re
for line in open('../pe_meta/empire.retail_exports.txt',encoding='utf8',errors='replace'):
    p=line.rstrip('\n').split('\t')
    if len(p)>=2:
        a=p[0].strip()
        if a.startswith('0x'): syms[int(a,16)]=p[1]
for line in open('../src_out/empire.retail.dll/named_functions.txt',encoding='utf8',errors='replace'):
    p=line.split('\t')
    if len(p)>=2 and p[0].strip().startswith('0x'):
        syms.setdefault(int(p[0].strip(),16),p[1].strip())
for f in ('funcid_solo.tsv','funcid_main.tsv','funcid_todo2_out.tsv'):
    p=Path(f)
    if not p.exists(): continue
    for line in p.read_text(errors='replace').splitlines():
        c=line.split('\t')
        if len(c)>=2 and c[0].startswith('0x'):
            try: syms.setdefault(int(c[0],16),c[1])
            except ValueError: pass
addrs=sorted(syms)
def near(a):
    i=bisect.bisect_left(addrs,int(a,16))
    lo=addrs[i-1] if i>0 else None
    hi=addrs[i] if i<len(addrs) else None
    out=[]
    if lo: out.append(f'after {hex(lo)}={syms[lo][:60]}(+{int(a,16)-lo})')
    if hi==int(a,16): hi=None
    if hi: out.append(f'before {hex(hi)}={syms[hi][:60]}(-{hi-int(a,16)})')
    return ' | '.join(out)
start,count=int(sys.argv[1]),int(sys.argv[2])
for a in pend[start:start+count]:
    print(f'{a}  {near(a)}')

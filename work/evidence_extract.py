#!/usr/bin/env python3
"""Solo funcid accelerator: extract per-function evidence from decompiled C.
Usage: python evidence_extract.py <addr_list> <out_jsonl>
For each addr: strings (ascii+wide), external/API calls, FUN_ callees w/ counts,
DAT/PTR globals, vtable assigns, alloc sizes, switch counts, param count.
"""
import re, sys, json, os
from pathlib import Path

ROOT = Path('X:/decompilation')
DECOMP = ROOT / 'src_out/empire.retail.dll/decomp'

addrs = [a.strip() for a in Path(sys.argv[1]).read_text().split() if a.strip()]
out = open(sys.argv[2], 'w', encoding='utf-8')

re_str_a = re.compile(r'"((?:[^"\\]|\\.){3,120})"')
re_str_w = re.compile(r'L"((?:[^"\\]|\\.){3,120})"')
re_call = re.compile(r'\b(FUN_[0-9a-f]+|[A-Za-z_][A-Za-z0-9_:]*)\s*\(')
re_known = re.compile(r'\b(?:FUN_[0-9a-f]+)\b')
ext_exclude = {'if','for','while','switch','return','sizeof','CONCAT','in','offset',
               'undefined','undefined1','undefined2','undefined4','undefined8',
               'char','short','int','long','uint','ulong','uchar','ushort','float','double',
               'bool','byte','word','dword','qword','code','void','local','param','DAT','PTR',
               'sVar','iVar','uVar','bVar','fVar','dVar','puVar','piVar','pfVar','ppuVar',
               'pcVar','psVar','extraout','in_x0','UNRECOVERED_JUMPTAB'}

_dir_index = None
def _index():
    global _dir_index
    if _dir_index is None:
        _dir_index = {}
        for name in os.listdir(DECOMP):
            base = name.split('_', 1)[0]
            _dir_index.setdefault(base.lower(), name)
    return _dir_index

def find_file(a):
    bare = a[2:] if a.lower().startswith('0x') else a
    p = DECOMP / f'{bare}_FUN_{bare}.c'
    if p.exists(): return p
    return DECOMP / _index().get(bare.lower(), '__nope__')

n = 0
for a in addrs:
    f = find_file(a)
    rec = {'addr': a}
    if not f:
        rec['missing'] = True
        out.write(json.dumps(rec) + '\n'); n += 1; continue
    txt = f.read_text(errors='replace')
    # signature line
    m = re.search(r'Signature:\s*(.+)', txt)
    rec['sig'] = m.group(1).strip() if m else ''
    m = re.search(r'Size:\s*(\d+)', txt)
    rec['size'] = int(m.group(1)) if m else 0
    body = txt
    strs = re_str_w.findall(body) + [s for s in re_str_a.findall(body)]
    seen=set(); slist=[]
    for s in strs:
        if s not in seen:
            seen.add(s); slist.append(s)
    rec['strings'] = slist[:40]
    calls = {}
    for mm in re_call.finditer(body):
        name = mm.group(1)
        if name.startswith('FUN_') or name in ext_exclude or name.startswith(('local','param','uVar','iVar','sVar','bVar')): continue
        calls[name] = calls.get(name, 0) + 1
    ext = {k:v for k,v in calls.items() if not k.startswith('FUN_') and '::' not in k}
    meth = {k:v for k,v in calls.items() if '::' in k}
    funs = {k[4:]:v for k,v in calls.items() if k.startswith('FUN_')}
    rec['api'] = sorted(ext, key=ext.get, reverse=True)[:30]
    rec['meth'] = sorted(meth)[:15]
    rec['funs'] = sorted(funs.items(), key=lambda kv:-kv[1])[:12]
    dats = set(re.findall(r'\b(?:DAT|PTR|s_|u_)_?([0-9a-f]{8})', body))
    rec['globals'] = len(dats)
    vt = set(re.findall(r'PTR__vftable_\w+|vftable', body))
    rec['vftable'] = bool(vt)
    al = set(int(x,16) for x in re.findall(r'\(int\)\s*0x([0-9a-f]{3,7})|\bnalloc[^;]*?,\s*0x([0-9a-f]+)', body) if x)
    rec['alloc'] = [hex(x) for x in sorted(al)[:8]]
    rec['switch'] = body.count('switch (')
    rec['thiscall'] = 'this' in txt[:2000] or '__thiscall' in txt
    out.write(json.dumps(rec) + '\n')
    n += 1
    if n % 500 == 0: print(n, flush=True)
print('DONE', n)

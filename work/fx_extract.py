#!/usr/bin/env python3
"""Solo funcid pass step 1: extract evidence from every batch1 decompiled .c file.
Output: work/batch1_evidence.jsonl  (one record per function)
"""
import json, re, glob, os
from pathlib import Path
from collections import Counter

ROOT = Path('X:/decompilation')
DEC = ROOT / 'src_out/empire.retail.dll/decomp'
OUT = ROOT / 'work/batch1_evidence.jsonl'

# ---- reference maps ----
# exports: addr -> short demangled name (crude)
exp = {}
for line in open(ROOT / 'pe_meta/empire.retail_exports.txt', encoding='utf-8', errors='replace'):
    parts = line.split('\t')
    if len(parts) >= 2 and parts[0].startswith('0x'):
        a = parts[0][2:].lower()
        m = parts[1].strip()
        # crude MSVC demangle: ?Name@Class@Face@OC3Ent@@...
        mm = re.match(r'^\?([A-Za-z_][\w]*)@(?:([\w]+)@)?(?:([\w]+)@)?', m)
        if mm:
            segs = [mm.group(1)]
            for g in (mm.group(2), mm.group(3)):
                if g and g not in ('Face', 'OC3Ent'):
                    segs.insert(0, g)
            exp[a] = '::'.join(segs)
        else:
            exp[a] = m

# named functions: addr -> name
named = {}
for line in open(ROOT / 'src_out/empire.retail.dll/named_functions.txt', encoding='utf-8', errors='replace'):
    p = line.split('\t')
    if len(p) >= 2:
        named.setdefault(p[0].strip().lower(), p[1].strip())

resolve = {}
for a, n in exp.items():
    resolve.setdefault(a, ('facefx', n))
for a, n in named.items():
    resolve.setdefault(a, ('named', n))

# Ghidra already renamed export callees to short names (e.g. `Serialize(`).
# Map short name -> kind so named_calls can be resolved too.
short_kind = {}
for a, (kind, nm) in list(resolve.items()):
    leaf = nm.split('::')[-1]
    if leaf and not leaf.startswith('~'):
        short_kind.setdefault(leaf, (kind, nm))

# vftables: addr -> class name
vft = {}
for line in open(ROOT / 'src_out/empire.retail.dll/vftables.txt', encoding='utf-8', errors='replace'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 3:
        vft.setdefault(p[0].strip().lower(), p[2].strip())

# imports: set of import function names (base names, no dll)
import_names = set()
imps = json.load(open(ROOT / 'pe_meta/empire.retail_imports.json'))
def walk(node):
    if isinstance(node, dict):
        for k, v in node.items():
            walk(v)
    elif isinstance(node, list):
        for v in node:
            walk(v)
    elif isinstance(node, str):
        import_names.add(node)
if isinstance(imps, dict):
    for dll, funcs in imps.items():
        if isinstance(funcs, dict):
            import_names.update(funcs.keys())
        elif isinstance(funcs, list):
            for f in funcs:
                if isinstance(f, str): import_names.add(f)
                elif isinstance(f, dict) and 'name' in f: import_names.add(f['name'])
        elif isinstance(funcs, list):
            walk(funcs)

addrs = [a.strip() for a in open(ROOT / 'work/batch1_addrs.txt') if a.strip()]

STR_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
CALL_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')

def classify_string(s):
    return s

out = open(OUT, 'w', encoding='utf-8')
missing = []
for i, addr in enumerate(addrs):
    a = addr.lower().removeprefix('0x')
    files = glob.glob(str(DEC / f'{a}_*.c'))
    if not files:
        missing.append(addr); continue
    path = files[0]
    try:
        txt = open(path, encoding='utf-8', errors='replace').read()
    except Exception:
        missing.append(addr); continue
    hdr_size = 0
    m = re.search(r'Size:\s*(\d+)', txt)
    if m: hdr_size = int(m.group(1))

    strs = []
    seen_s = set()
    for s in STR_RE.findall(txt):
        if len(s) < 4 or len(s) > 120: continue
        if re.fullmatch(r'[\s\d\.\-_]*', s): continue
        if s in seen_s: continue
        seen_s.add(s)
        strs.append(s)
    strs = strs[:40]

    calls = Counter(c for c in CALL_RE.findall(txt) if c not in ('if','for','while','switch','sizeof','return','CONCAT','in'))
    imports = sorted({c for c in calls if c in import_names})
    named_calls = {c: n for c, n in calls.items() if not c.startswith('FUN_') and c not in import_names}

    fun_counts = Counter()
    resolved = Counter()
    for c, n in calls.items():
        if c.startswith('FUN_'):
            fun_counts[c] += n
            ca = c[4:].lower()
            if ca in resolve:
                kind, nm = resolve[ca]
                resolved[f'{kind}:{nm}'] += n
        elif c not in import_names and c in short_kind:
            kind, nm = short_kind[c]
            resolved[f'{kind}:{nm}'] += n

    vfound = set()
    for va, cls in vft.items():
        if va in txt:
            vfound.add(cls)

    rec = {
        'addr': addr, 'file': os.path.basename(path), 'size': hdr_size,
        'lines': txt.count('\n'),
        'strings': strs,
        'imports': imports,
        'named_calls': dict(sorted(named_calls.items(), key=lambda x: -x[1])[:25]),
        'fun_resolved': dict(resolved.most_common(12)),
        'vftables': sorted(vfound),
        'fun_addrs': sorted({c[4:].lower() for c in fun_counts}),
    }
    out.write(json.dumps(rec, ensure_ascii=False) + '\n')
    if (i + 1) % 500 == 0: print(f'{i+1}/{len(addrs)}', flush=True)
out.close()
print(f'done. missing={len(missing)}')
if missing: print('\n'.join(missing[:20]))

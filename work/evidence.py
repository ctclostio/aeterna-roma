import sys, re
from pathlib import Path
D=Path('X:/decompilation/src_out/empire.retail.dll/decomp')
named={}
for line in open('X:/decompilation/work/named_map.tsv'):
    p=line.rstrip('\n').split('\t');  named.setdefault(p[0],p[1])
known={}
for line in open('X:/decompilation/work/known_names.tsv'):
    p=line.rstrip('\n').split('\t')
    if len(p)>=2: known[p[0]]=p[1]
def name(a):
    k='0x'+a
    return known.get(k) or named.get(k) or ''
addr=sys.argv[1].lower()
f=D/f'{addr.lstrip("0x")}_FUN_{addr[2:]}.c'
if not f.exists(): print('MISSING',f); sys.exit(1)
txt=f.read_text(errors='ignore')
m=re.search(r'// Entry: (0x[0-9a-f]+)\s+Size: (\d+)',txt)
sig=re.search(r'// Signature: (.+)',txt)
print('FILE:',f.name, 'size:',len(txt))
print('SIG:', sig.group(1) if sig else '?')
# string literals inline
inl=set(re.findall(r'"([^"\n]{4,90})"',txt))
if inl:
    print('STR:')
    for s in sorted(inl)[:25]: print('   "%s"'%s)
# s_ variable declarations (ghidra strings)
sdecls=dict(re.findall(r'(s_\S{3,60}?)\s*=\s*"([^"\n]{1,90})"',txt))
srefs=re.findall(r'\bs_[A-Za-z0-9_.%+\-]{3,60}',txt)
from collections import Counter
c=Counter(srefs)
if c:
    print('STRVARS:')
    shown=0
    for v,n in c.most_common(30):
        cont=sdecls.get(v,'')
        print('   %s x%d %s'%(v,n,('"%s"'%cont[:80]) if cont else ''))
# calls
calls=Counter(re.findall(r'\b(FUN)_[0-9a-f]{8}',txt))
calls=Counter(re.findall(r'\bFUN_([0-9a-f]{8})\b',txt))
print('CALLS:')
for a,n in calls.most_common(18):
    lbl=name(a)
    print('   FUN_%s x%d %s'%(a,n,('<- '+lbl) if lbl else ''))
# apis / other identifiers
apis=Counter(re.findall(r'\b([A-Z][A-Za-z0-9_]{3,28})\s*\(',txt))
apis={k:v for k,v in apis.items() if k not in ('FUN','CONCAT','SUB','DAT','PTR','uVar','iVar')}
if apis:
    print('APIS:', ', '.join('%s x%d'%(k,v) for k,v in Counter(apis).most_common(1)))
api2=Counter(re.findall(r'\b((?:[A-Z][a-z0-9]+){2,})\s*\(',txt))
if api2:
    print('API2:', ', '.join('%s x%d'%(k,v) for k,v in api2.most_common(14)))
# vtables / DATs of interest
vt=Counter(re.findall(r'PTR_FUN_[0-9a-f]{8}|`vftable\'',txt))
dats=Counter(re.findall(r'\bDAT_([0-9a-f]{8})\b',txt))
big=[(a,n) for a,n in dats.most_common(8)]
print('TOPDAT:', ', '.join('DAT_%s x%d'%(a,n) for a,n in big))

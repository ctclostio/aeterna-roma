import re,sys
from pathlib import Path
from collections import Counter
D=Path('X:/decompilation/src_out/empire.retail.dll/decomp')
named={}
for line in open('X:/decompilation/work/named_map.tsv'):
    p=line.rstrip('\n').split('\t'); named[p[0][2:]]=p[1]
known={}
for line in open('X:/decompilation/work/known_names.tsv'):
    p=line.rstrip('\n').split('\t')
    if len(p)>=2: known.setdefault(p[0][2:],p[1])
def nm(a): return known.get(a) or named.get(a) or ''
# index: which files call target addrs
targets={a.lower().lstrip('0x') for a in open(sys.argv[1]).read().split()}
rev=Counter(); callees={}
files=sorted(D.glob('*.c'))
for f in files:
    # quick prefilter by size to skip self
    m=re.match(r'([0-9a-f]{8})_FUN_',f.name)
    if not m: continue
    self_a=m.group(1)
    txt=f.read_text(errors='ignore')
    cs=set(re.findall(r'\bFUN_([0-9a-f]{8})\b',txt))
    for t in targets:
        if t in cs and t!=self_a:
            lbl=nm(self_a)
            rev[t]+=1
            callees.setdefault(t,[]).append((self_a,lbl))
out=open('revcalls.txt','w',newline='\n')
for t in sorted(targets):
    lst=callees.get(t,[])
    named_c=[(a,l) for a,l in lst if l]
    out.write(f'0x{t}: {len(lst)} callers; NAMED: '+ '; '.join(f'{l}({a})' for a,l in named_c[:8])+'\n')
out.close()
print('done', len(rev))

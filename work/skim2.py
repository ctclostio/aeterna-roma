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
addrs=[a.strip().lower().lstrip('0x') for a in open(sys.argv[1]).read().split()]
sel=set(addrs[int(sys.argv[2]):int(sys.argv[3])])
for addr in addrs:
    if addr not in sel: continue
    f=D/f'{addr}_FUN_{addr}.c'
    txt=f.read_text(errors='ignore')
    lines=txt.splitlines()
    print(f'######## {addr} ({len(lines)}L)')
    cs=Counter(re.findall(r'\bFUN_([0-9a-f]{8})\b',txt))
    cl=[f'{a}:{nm(a) or ""}x{n}' for a,n in cs.most_common(50)]
    print('  CALLEES:', ' '.join(cl[:22]))
    thiscall=len(re.findall(r'in_ECX',txt))
    print('  in_ECX refs:',thiscall)
    # code windows: find first assignment line beyond decls (line containing '(' and '=' or 'if')
    starts=[i for i,l in enumerate(lines) if i>10 and re.match(r'\s{2,6}(if|for|while|do |[a-zA-Z_].*=)',l)]
    s0=starts[0] if starts else 12
    for tag,rng in (('HEAD',(s0,s0+16)),('MID',(len(lines)//2,len(lines)//2+10))):
        print(f'  --{tag}')
        for j in range(*rng): print('    '+lines[j][:148])

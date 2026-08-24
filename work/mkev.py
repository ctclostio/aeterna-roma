import re,sys
from collections import Counter
from pathlib import Path
D=Path('X:/decompilation/src_out/empire.retail.dll/decomp')
named={}
for line in open('X:/decompilation/work/named_map.tsv'):
    p=line.rstrip('\n').split('\t'); named[p[0][2:]]=p[1]
known={}
for line in open('X:/decompilation/work/known_names.tsv'):
    p=line.rstrip('\n').split('\t')
    if len(p)>=2: known[p[0][2:]]=p[1]
def nm(a): return known.get(a) or named.get(a) or ''
out=open('my_slice_digest.txt','w',encoding='utf-8',newline='\n')
addrs=[a.strip() for a in open(sys.argv[1]) if a.strip()]
start=int(sys.argv[2]); n=int(sys.argv[3])
for a0 in addrs[start:start+n]:
    addr=a0.lower().lstrip('0x') if a0.lower().startswith('0x') else a0.lower()
    f=D/f'{addr}_FUN_{addr}.c'
    if not f.exists():
        out.write(f'== 0x{addr} MISSING\n'); continue
    txt=f.read_text(errors='ignore')
    sig=re.search(r'// Signature: (.+)',txt)
    sz=len(txt)
    parts=[f'== 0x{addr} ({sz}b) SIG: {sig.group(1).strip() if sig else "?"}']
    inl=sorted(set(re.findall(r'"([^"\n]{4,90})"',txt)))
    if inl:
        parts.append('STR: '+' | '.join('"%s"'%s[:70] for s in inl[:8]))
    sdecls=dict(re.findall(r'(s_\S{3,60}?)\s*=\s*"([^"\n]{1,90})"',txt))
    c=Counter(re.findall(r'\bs_[A-Za-z0-9_.%+\-]{3,60}',txt))
    sv=[]
    for v,n2 in c.most_common(10):
        cont=sdecls.get(v,'')
        sv.append('%s"%s"'%(v[:24],cont[:52]) if cont else v[:30])
    if sv: parts.append('SVARS: '+' | '.join(sv))
    calls=Counter(re.findall(r'\bFUN_([0-9a-f]{8})\b',txt))
    nc=[f'FUN_{a}={nm(a)} x{n2}' for a,n2 in calls.most_common(60) if nm(a)]
    parts.append('NCALL: '+('; '.join(nc[:10]) if nc else '-'))
    parts.append('NDIST: %d'%len(calls))
    api2=Counter(re.findall(r'\b((?:[A-Z][a-z0-9]+){2,})\s*\(',txt))
    ap=', '.join('%s x%d'%(k,v) for k,v in api2.most_common(12))
    if ap: parts.append('API: '+ap)
    dats=len(set(re.findall(r'\bDAT_[0-9a-f]{8}\b',txt)))
    ptrs=re.findall(r'PTR_(?:FUN|DAT)_?([0-9a-f]{0,8})',txt)
    parts.append(f'DATu:{dats} PTRs:{len(ptrs)}')
    vt=sorted(set(re.findall(r'PTR_FUN_([0-9a-f]{8})',txt)))[:4]
    if vt: parts.append('VTBL:'+' '.join(vt))
    out.write('\n   '.join(parts)+'\n')
out.close()
print('done')

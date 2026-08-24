import re,sys,json
from pathlib import Path
DEC=Path('../src_out/empire.retail.dll/decomp')
NAMED={}
for line in open('../src_out/empire.retail.dll/named_functions.txt',encoding='utf8',errors='replace'):
    p=line.split('\t')
    if len(p)>=2: NAMED.setdefault(p[0].strip().lower().removeprefix('0x'),p[1].strip())
MINE={}
for tsv in ['funcid_solo.tsv','funcid_main.tsv']:
    for line in open(tsv,encoding='utf8',errors='replace'):
        p=line.split('\t')
        if len(p)>=2 and p[0].startswith('0x'): MINE.setdefault(p[0][2:],p[1])
addrs=[a.strip() for a in Path(sys.argv[1]).read_text().split()][int(sys.argv[2]):int(sys.argv[2])+int(sys.argv[3])]
for a in addrs:
    h=a[2:]
    f=DEC/f'{h}_FUN_{h}.c'
    try: txt=f.read_text(errors='ignore')
    except FileNotFoundError:
        print(f'### {a} MISSING'); continue
    strs=[]
    for s in re.findall(r'"((?:[^"\\n]|\.){2,90})"',txt):
        if s not in strs: strs.append(s)
    consts=sorted(set(re.findall(r'(?<![\w.])(?:[0-9]{4,10}\.(?:[0-9]+)?e?[+-]?[0-9]*|[0-9]\.[0-9]+e[+-][0-9]+|0\.00[0-9]+)(?![\w])',txt)))[:10]
    ints=sorted(set(int(x,16) for x in re.findall(r'0x[0-9a-f]{4,}',txt) if int(x,16)>0xff and int(x,16)<0x1000000))[:12]
    vt=re.findall(r'\*(?:int \*)?(?:in_ECX|param_\d+|\w+)\s*=\s*&(PTR_FUN_[0-9a-f]+)',txt)[:4]
    fc={}
    for mm in re.finditer(r'(FUN_[0-9a-f]{8})\s*\(',txt): fc[mm.group(1)]=fc.get(mm.group(1),0)+1
    callees=[]
    for c,n in sorted(fc.items(),key=lambda kv:-kv[1])[:9]:
        if c==f'FUN_{h}': continue
        nm=MINE.get(c[4:]) or NAMED.get(c[4:])
        callees.append(f'{c[4:]}={nm}x{n}' if nm else f'{c[4:]}x{n}')
    print(f"### {a} len={len(txt)}")
    if strs: print("  STR:", ' | '.join(s[:55] for s in strs[:10]))
    if consts: print("  F:", ', '.join(consts))
    if ints: print("  HEX:", ', '.join(hex(i) for i in ints))
    if vt: print("  VT:", ', '.join(vt))
    if callees: print("  CAL:", ', '.join(callees))

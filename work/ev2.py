import re,sys
from pathlib import Path
D=Path('X:/decompilation/src_out/empire.retail.dll/decomp')
addrs=[a.strip() for a in open(sys.argv[1]) if a.strip()]
sel={a.lower().lstrip('0x') for a in addrs[int(sys.argv[2]):int(sys.argv[3])]}
for a0 in addrs:
    addr=a0.lower().lstrip('0x') if a0.lower().startswith('0x') else a0.lower()
    if addr not in sel: continue
    f=D/f'{addr}_FUN_{addr}.c'
    if not f.exists(): print(f'== {addr} MISSING'); continue
    txt=f.read_text(errors='ignore')
    strs=sorted(set(re.findall(r'"([^"\n]{3,110})"',txt)) | set(re.findall(r's_\S{3,60}?\s*=\s*"([^"\n]{1,110})"',txt)))
    print(f'== {addr}')
    if strs:
        for s in strs[:28]: print('   "%s"'%s[:100])
        if len(strs)>28: print('   ...+%d more'%(len(strs)-28))
    else:
        # no strings: profile constants & structure
        flt=re.findall(r'=\s*(-?[0-9]+\.[0-9]+[eE]?[-+0-9]*)',txt)
        hexc=re.findall(r'= (0x[0-9a-f]{2,8})',txt)
        from collections import Counter
        print('   FLT:', ', '.join('%s x%d'%(k,v) for k,v in Counter(flt).most_common(8)))
        print('   HEX:', ', '.join('%s x%d'%(k,v) for k,v in Counter(hexc).most_common(12)))
        off=re.findall(r'\+\s*(0x[0-9a-f]{1,4})\)',txt)
        print('   OFF:', ', '.join('%s x%d'%(k,v) for k,v in Counter(off).most_common(14)))

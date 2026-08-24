import re,sys
from pathlib import Path
D=Path('X:/decompilation/src_out/empire.retail.dll/decomp')
addrs=[a.strip().lower().lstrip('0x') for a in open(sys.argv[1]).read().split()]
sel=set(addrs[int(sys.argv[2]):int(sys.argv[3])])
for addr in addrs:
    if addr not in sel: continue
    f=D/f'{addr}_FUN_{addr}.c'
    txt=f.read_text(errors='ignore')
    lines=txt.splitlines()
    print(f'######## {addr} ({len(lines)} lines)')
    # first 3 call sites with context
    shown=0
    for i,l in enumerate(lines):
        if re.search(r'\bFUN_[0-9a-f]{8}\b|\bDAT_[0-9a-f]{8}\b',l):
            print('--- ctx @%d'%i)
            for j in range(max(0,i-3),min(len(lines),i+5)):
                print('   '+lines[j][:150])
            shown+=1
            if shown>=2: break
    # mid window
    mid=len(lines)//2
    print('--- mid @%d'%mid)
    for j in range(mid,min(len(lines),mid+12)): print('   '+lines[j][:150])
    print('--- tail')
    for j in range(max(0,len(lines)-8),len(lines)): print('   '+lines[j][:150])

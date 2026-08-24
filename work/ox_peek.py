#!/usr/bin/env python3
import sys, io
from pathlib import Path
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf8', errors='replace')
start, count = int(sys.argv[1]), int(sys.argv[2])
maxl = int(sys.argv[3]) if len(sys.argv) > 3 else 14
pend=[x.strip() for x in Path('ox_pending.txt').read_text().split()]
DEC=Path('../src_out/empire.retail.dll/decomp')
for a in pend[start:start+count]:
    na=a[2:]
    txt=(DEC/f'{na}_FUN_{na}.c').read_text(errors='ignore')
    i=txt.find('{')
    sig=txt[:txt.find('\n',txt.find('Signature'))].strip()
    body=txt[i:i+3000]
    lines=[l.rstrip() for l in body.splitlines() if l.strip()][:maxl]
    print(f'===== {a} {sig[sig.find("Signature"):]}')
    print('\n'.join(lines))

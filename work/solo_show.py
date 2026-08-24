#!/usr/bin/env python3
"""Show decompiled C for one address, compactly. Usage: solo_show.py <addr> [maxlines] [startline]"""
import sys
from pathlib import Path
addr = sys.argv[1].replace('0x','').lower()
maxl = int(sys.argv[2]) if len(sys.argv) > 2 else 120
start = int(sys.argv[3]) if len(sys.argv) > 3 else 0
f = Path(f'../src_out/empire.retail.dll/decomp/{addr}_FUN_{addr}.c')
lines = f.read_text(encoding='utf8', errors='replace').splitlines()
out = [(i,l.rstrip()) for i,l in enumerate(lines) if l.strip()]
print(f'== {f.name} ({len(out)} nonblank lines)')
for i,s in out[start:start+maxl]: print(s)
if len(out) > start+maxl: print(f'... [{len(out)-start-maxl} more]')

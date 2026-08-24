#!/usr/bin/env python3
"""Peek at N decompiled functions: signature + first LINES of real code each.
Usage: peek.py <start_idx> <count> [lines_per_func]"""
import sys, re
from pathlib import Path

start = int(sys.argv[1]); count = int(sys.argv[2])
lines_per = int(sys.argv[3]) if len(sys.argv) > 3 else 40
DECOMP = Path('src_out/empire.retail.dll/decomp')
addrs = [a.strip() for a in Path('work/solo_remaining.txt').read_text().split()]
for a in addrs[start:start+count]:
    h = a.removeprefix('0x')
    f = DECOMP / f'{h}_FUN_{h}.c'
    if not f.exists():
        print(f'##### {a} MISSING'); continue
    txt = f.read_text(encoding='utf8', errors='replace').splitlines()
    # find end of declarations: first line that isn't a decl/comment after signature
    out, started, blanks, depth = [], False, 0, 0
    for ln in txt:
        s = ln.strip()
        if not started:
            if s.startswith('//') or not s:
                continue
            out.append(ln)
            if re.match(r'^(undefined\d|int|void|float\d*|char|bool|double|long|byte|word|dword|\*)', s) and '{' not in s and '(' in s and not s.endswith(';'):
                started = True
            elif s.endswith('{'):
                started = True
        else:
            if not s:
                blanks += 1
                if blanks > 2: continue
            else:
                blanks = 0
            out.append(ln)
        if len([o for o in out]) > lines_per + 8:
            break
    print(f'##### {a} ({len(txt)} lines)')
    print('\n'.join(out[:lines_per+8]))
    print()

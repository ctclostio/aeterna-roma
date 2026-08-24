#!/usr/bin/env python3
"""Print next K un-named addrs from ox_pending.txt (skips ones named in any tsv).
Usage: ox_next.py [K]   (default 6)"""
import sys, glob
from pathlib import Path
k = int(sys.argv[1]) if len(sys.argv) > 1 else 6
named=set()
for f in glob.glob('*.tsv'):
    for l in Path(f).read_text(encoding='utf8',errors='replace').splitlines():
        c=l.split('\t')
        if c and c[0].strip(): named.add(c[0].strip().lower().removeprefix('0x'))
out=[]
for l in Path('ox_pending.txt').read_text().splitlines():
    a=l.strip().lower().removeprefix('0x')
    if not a: continue
    if a in named:
        continue
    out.append(a)
    if len(out)>=k: break
# rewrite pending without named ones up to this point
keep=[l for l in Path('ox_pending.txt').read_text().splitlines()
      if l.strip() and l.strip().lower().removeprefix('0x') not in named]
Path('ox_pending.txt').write_text('\n'.join(keep)+('\n' if keep else ''))
print('\n'.join(out))
print(f"[{len(keep)} left]", file=sys.stderr)

#!/usr/bin/env python3
"""Append classification rows to funcid_solo.tsv. Reads TSV lines from stdin or arg file."""
import sys
from pathlib import Path
src = Path(sys.argv[1]) if len(sys.argv) > 1 else None
rows = (src.read_text(encoding='utf8') if src else sys.stdin.read()).splitlines()
out = Path('funcid_solo.tsv')
have = set()
if out.exists():
    for line in out.read_text(errors='replace').splitlines():
        p = line.split('\t')
        if p and p[0].startswith('0x'): have.add(p[0].strip())
added = skipped = 0
with out.open('a', encoding='utf8') as fh:
    for r in rows:
        if not r.strip(): continue
        a = r.split('\t')[0].strip()
        if a in have: skipped += 1; continue
        have.add(a); fh.write(r.strip() + '\n'); added += 1
print(f'added {added}, skipped {skipped}; total now {len(have)}')

#!/usr/bin/env python
"""Append funcid rows to a TSV. Usage: append_tsv.py <out.tsv> <addr> <name> <subsystem> <evidence> [<addr> <name> <subsystem> <evidence> ...]"""
import sys
from pathlib import Path
out = Path(sys.argv[1])
args = sys.argv[2:]
assert len(args) % 4 == 0, "need addr/name/subsystem/evidence quadruples"
rows = []
for i in range(0, len(args), 4):
    addr, name, subsys, ev = args[i:i+4]
    assert '\t' not in name and '\t' not in subsys and '\t' not in ev
    rows.append(f"{addr}\t{name}\t{subsys}\t{ev}")
with out.open('a', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(rows) + '\n')
print(f"+{len(rows)} -> {out}")

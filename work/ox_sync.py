#!/usr/bin/env python3
"""OX-private pending list: my queue minus live-classified."""
from pathlib import Path
norm=lambda a:a.strip().lower().removeprefix('0x')
queue=[]
seen=set()
for a in Path('funcid_solo_queue.txt').read_text(errors='replace').split():
    n=norm(a)
    if n not in seen: seen.add(n); queue.append(n)
done=set()
for line in Path('funcid_solo.tsv').read_text(errors='replace').splitlines():
    c=line.split('\t')
    if c and c[0].strip().startswith('0x'): done.add(norm(c[0]))
pend=['0x'+a for a in queue if a not in done]
Path('ox_pending.txt').write_text('\n'.join(pend)+'\n')
print(f'pending {len(pend)}')

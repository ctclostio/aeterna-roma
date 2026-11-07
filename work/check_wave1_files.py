import csv
from pathlib import Path

D = Path(r'X:\decompilation\src_canonical_out\empire.retail.dll\canonical_decomp')
rows = [r for r in csv.DictReader(
    open(r'X:\decompilation\work\gap_apply.tsv', encoding='utf-8'),
    delimiter='\t') if r['status'] == 'created']
bad = []
for r in rows:
    addr = int(r['address'], 16)
    p = D / f'decomp_fn_{addr:08x}.c'
    if not p.exists() or '// Export result: success' not in p.read_text(
            encoding='utf-8', errors='replace'):
        bad.append(r['address'])
print('wave1 checked', len(rows), 'bad', len(bad), bad[:10])

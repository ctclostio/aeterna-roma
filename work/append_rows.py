import sys
rows = [l for l in sys.stdin.read().splitlines() if l.strip()]
with open('funcid_solo_results.tsv','a',encoding='utf8') as f:
    for r in rows: f.write(r+'\n')
print(f'appended {len(rows)}')

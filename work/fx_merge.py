#!/usr/bin/env python3
"""Solo funcid pass step 4: merge priors + v4 auto-classification -> final TSV."""
from pathlib import Path
from collections import Counter
ROOT = Path('X:/decompilation')

MANUAL_FIXES = {
    '0x10f95930': ('net_steam_metrics_auth_url_build', 'net', 'str:"&steamid=" "&ticket=" "&metric=" steam web/metrics URL build'),
}

prior = {}
for f in ['funcid_main.tsv', 'funcid_solo.tsv', 'funcid_todo2_out.tsv', 'funcid_todo2_results.tsv']:
    try:
        for line in open(ROOT / 'work' / f, encoding='utf-8'):
            p = line.rstrip('\n').split('\t')
            if len(p) >= 4 and p[0].strip():
                prior.setdefault(p[0].strip().lower(), (p[1].strip(), p[2].strip(), p[3].strip() + f' [prior:{f}]'))
    except FileNotFoundError:
        pass

auto = {}
for line in open(ROOT / 'work/funcid_batch1_v4.tsv', encoding='utf-8'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 4:
        auto.setdefault(p[0].lower(), (p[1], p[2], p[3]))

final = {}
src_stats = Counter()
for a in set(prior) | set(auto):
    if a in MANUAL_FIXES:
        final[a] = MANUAL_FIXES[a]; src_stats['manual'] += 1
    elif a in prior:
        final[a] = prior[a]; src_stats['prior'] += 1
    else:
        final[a] = auto[a]; src_stats['auto-v4'] += 1

out = open(ROOT / 'work/funcid_batch1_final.tsv', 'w', encoding='utf-8')
rows = [f'{a}\t{n}\t{s}\t{e}' for a, (n, s, e) in sorted(final.items())]
out.write('\n'.join(rows) + '\n')
out.close()
print(f'final entries: {len(final)}  sources: {dict(src_stats)}')
subc = Counter(v[1] for v in final.values())
print('subsystem distribution:')
for k, v in subc.most_common(): print(f'{v:6d} {k}')

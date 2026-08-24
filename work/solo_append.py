import sys
out = r"X:/decompilation/work/funcid_solo.tsv"
lines = [l.strip() for l in sys.stdin.read().strip().splitlines() if l.strip()]
for line in lines:
    parts = line.split('\t')
    assert len(parts) == 4, f"bad line: {line!r}"
    with open(out, 'a', encoding='utf-8') as f:
        f.write(line + '\n')
print(f"appended {len(lines)}")

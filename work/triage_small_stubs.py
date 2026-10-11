from pathlib import Path
from collections import Counter
import re

canonical_dir = Path("src_canonical_out/empire.retail.dll/canonical_decomp")

named = set()
with open("src_out/empire.retail.dll/named_functions.txt", "r", encoding="utf-8") as f:
    for line in f:
        p = line.strip().split("\t")
        if len(p) >= 2:
            named.add(p[0].lower().replace("0x", ""))

thunks = []
with open("src_out/empire.retail.dll/function_index.txt", "r", encoding="utf-8") as f:
    for line in f:
        p = line.strip().split("\t")
        if len(p) >= 3:
            addr = p[0].lower().replace("0x", "")
            size = int(p[2])
            if addr not in named and size <= 15:
                thunks.append(addr)

patterns = {
    "stub_return_0": re.compile(r"\{\s*return\s+0;\s*\}"),
    "stub_return_1": re.compile(r"\{\s*return\s+1;\s*\}"),
    "stub_noop": re.compile(r"\{\s*(?:return;)?\s*\}"),
    "stl_throw_length_error": re.compile(r'decomp_fn_11686192\("string too long"\)'),
    "stl_throw_out_of_range": re.compile(r'decomp_fn_11686192\("invalid string position"\)'),
}

counts = Counter()
matches = {}

for addr in thunks:
    c_file = canonical_dir / f"decomp_fn_{addr}.c"
    if not c_file.exists():
        continue
    text = c_file.read_text(encoding="utf-8")
    for pat_name, pat in patterns.items():
        if pat.search(text):
            counts[pat_name] += 1
            matches[addr] = pat_name
            break

print(f"Total candidates <= 15 bytes: {len(thunks)}")
for k, v in counts.items():
    print(f"  {k}: {v}")
print(f"Total classified in this pass: {len(matches)}")

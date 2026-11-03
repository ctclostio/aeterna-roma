from pathlib import Path
import re
from collections import Counter

canonical_dir = Path("src_canonical_out/empire.retail.dll/canonical_decomp")

# Load existing known names
named = set()
with open("src_out/empire.retail.dll/named_functions.txt", "r", encoding="utf-8") as f:
    for line in f:
        p = line.strip().split("\t")
        if len(p) >= 2:
            named.add(p[0].lower().replace("0x", ""))

# Candidates <= 32 bytes
candidates = []
with open("src_out/empire.retail.dll/function_index.txt", "r", encoding="utf-8") as f:
    for line in f:
        p = line.strip().split("\t")
        if len(p) >= 3:
            addr = p[0].lower().replace("0x", "")
            size = int(p[2])
            if addr not in named and size <= 32:
                candidates.append((addr, size))

def extract_outer_body(code: str) -> str:
    start = code.find("{")
    if start < 0:
        return ""
    depth = 0
    end = -1
    for i in range(start, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end < 0:
        return ""
    raw = code[start:end]
    no_block = re.sub(r"/\*.*?\*/", "", raw, flags=re.DOTALL)
    no_line = re.sub(r"//[^\n]*", "", no_block)
    return " ".join(no_line.split())

# Generalized normalizer: replace variables and literals with tokens
def normalize_shape(body: str) -> str:
    s = body
    s = re.sub(r'(?:_DAT_|DAT_|PTR_|_PTR_)[0-9a-fA-F_.]+', 'GLOBAL', s)
    s = re.sub(r'decomp_fn_[0-9a-fA-F]+', 'CALLEE', s)
    s = re.sub(r'0x[0-9a-fA-F]+', 'HEX', s)
    s = re.sub(r'\b[0-9]+\b', 'NUM', s)
    s = re.sub(r'param_\d+', 'PARAM', s)
    s = re.sub(r'"[^"]*"', 'STR', s)
    return s

shapes = Counter()
shape_samples = {}

for addr, sz in candidates:
    c_file = canonical_dir / f"decomp_fn_{addr}.c"
    if not c_file.exists():
        continue
    b = extract_outer_body(c_file.read_text(encoding="utf-8"))
    if not b:
        continue
    sh = normalize_shape(b)
    shapes[sh] += 1
    if sh not in shape_samples:
        shape_samples[sh] = (addr, b)

print(f"Top 35 normalized shapes across {len(candidates)} small candidates:")
for sh, cnt in shapes.most_common(35):
    addr, raw = shape_samples[sh]
    print(f"[{cnt:4d}] {sh}")
    print(f"       eg (0x{addr}): {raw[:80]}")

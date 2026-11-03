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

# Candidates <= 20 bytes
candidates = []
with open("src_out/empire.retail.dll/function_index.txt", "r", encoding="utf-8") as f:
    for line in f:
        p = line.strip().split("\t")
        if len(p) >= 3:
            addr = p[0].lower().replace("0x", "")
            size = int(p[2])
            if addr not in named and size <= 20:
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

# Inspect the first 50 bodies
bodies = []
for addr, size in candidates[:50]:
    c_file = canonical_dir / f"decomp_fn_{addr}.c"
    if c_file.exists():
        b = extract_outer_body(c_file.read_text(encoding="utf-8"))
        bodies.append((addr, size, b))

print(f"Sample bodies (total {len(candidates)} candidates):")
for addr, sz, b in bodies[:25]:
    print(f"  0x{addr} ({sz}b): {b}")

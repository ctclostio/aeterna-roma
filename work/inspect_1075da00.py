import re
from pathlib import Path

ROOT = Path("X:/decompilation")

path = ROOT / "src_out" / "empire.retail.dll" / "decomp" / "1075da00_FUN_1075da00.c"
text = path.read_text(encoding="utf-8", errors="replace")

print(f"Total lines: {len(text.splitlines())}")

# Extract strings
str_literals = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)
print(f"String Literals ({len(str_literals)}):")
for s in str_literals:
    print(f"  \"{s}\"")

# Check callees
funs = sorted(list(set(re.findall(r'FUN_([0-9a-fA-F]+)', text))))
print(f"\nCallees ({len(funs)}):")
print(", ".join(f"0x{f}" for f in funs[:35]))

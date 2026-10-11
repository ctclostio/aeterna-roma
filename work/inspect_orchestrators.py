import re
from pathlib import Path

ROOT = Path("X:/decompilation")

# Load va_strings if available
va_strings = {}
va_file = ROOT / "work" / "va_strings.txt"
if va_file.exists():
    with open(va_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split("\t", 1)
            if len(parts) == 2:
                va_strings[parts[0].lower()] = parts[1]

def analyze_file(addr, filename):
    print(f"==================================================")
    print(f"FUNCTION: 0x{addr} -> {filename}")
    print(f"==================================================")
    path = ROOT / filename
    if not path.exists():
        print(f"File not found: {path}")
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    
    # Extract string literals in source
    str_literals = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)
    print(f"String Literals ({len(str_literals)}):")
    for s in str_literals[:25]:
        print(f"  \"{s}\"")
        
    # Extract DAT_ references
    dats = sorted(list(set(re.findall(r'DAT_([0-9a-fA-F]+)', text))))
    print(f"\nReferenced DAT_ symbols ({len(dats)}):")
    resolved_dats = 0
    for d in dats:
        addr_hex = f"0x{d.lower()}"
        if addr_hex in va_strings:
            print(f"  DAT_{d} -> \"{va_strings[addr_hex]}\"")
            resolved_dats += 1
        elif d.lower() in va_strings:
            print(f"  DAT_{d} -> \"{va_strings[d.lower()]}\"")
            resolved_dats += 1
    print(f"  (Resolved {resolved_dats} / {len(dats)} from va_strings)")

    # Extract FUN_ references
    funs = sorted(list(set(re.findall(r'FUN_([0-9a-fA-F]+)', text))))
    print(f"\nCalled FUN_ functions ({len(funs)}):")
    print(", ".join(f"0x{fn}" for fn in funs[:30]))

analyze_file("106ba2e0", "src_out/empire.retail.dll/decomp/106ba2e0_FUN_106ba2e0.c")
analyze_file("100e39c0", "src_out/empire.retail.dll/decomp/100e39c0_FUN_100e39c0.c")

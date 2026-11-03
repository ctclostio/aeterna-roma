from pathlib import Path
import re
from collections import Counter

canonical_dir = Path("src_canonical_out/empire.retail.dll/canonical_decomp")

# Load existing known names
named = {}
with open("src_out/empire.retail.dll/named_functions.txt", "r", encoding="utf-8") as f:
    for line in f:
        p = line.strip().split("\t")
        if len(p) >= 2:
            named[p[0].lower().replace("0x", "")] = p[1]

# Load candidates <= 32 bytes
candidates = []
with open("src_out/empire.retail.dll/function_index.txt", "r", encoding="utf-8") as f:
    for line in f:
        p = line.strip().split("\t")
        if len(p) >= 3:
            addr = p[0].lower().replace("0x", "")
            size = int(p[2])
            if addr not in named and size <= 32:
                candidates.append((addr, size))

print(f"Total unnamed candidates <= 32 bytes: {len(candidates)}")

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

patterns = [
    ("noop", re.compile(r"^\{\s*(?:return;)?\s*\}$")),
    ("return_0", re.compile(r"^\{\s*return\s+0;\s*\}$")),
    ("return_1", re.compile(r"^\{\s*return\s+1;\s*\}$")),
    ("return_const", re.compile(r"^\{\s*return\s+(-?(?:0x[0-9a-fA-F]+|[0-9]+));\s*\}$")),
    ("return_this", re.compile(r"^\{\s*return\s+param_1;\s*\}$")),
    ("return_global_ptr", re.compile(r"^\{\s*return\s+&(?:DAT_|PTR_)([0-9a-zA-Z_]+);\s*\}$")),
    ("return_global_val", re.compile(r"^\{\s*return\s+(?:DAT_|PTR_|_DAT_|_PTR_)([0-9a-zA-Z_]+);\s*\}$")),
    ("getter_deref", re.compile(r"^\{\s*return\s+(?:\([a-zA-Z0-9_ *]+\))?\s*\*\((\w+)\s*\*\)param_1;\s*\}$")),
    ("getter_off", re.compile(r"^\{\s*return\s+(?:\([a-zA-Z0-9_ *]+\))?\s*\*\((\w+)\s*\*\)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\);\s*\}$")),
    ("setter_deref", re.compile(r"^\{\s*\*\((\w+)\s*\*\)param_1\s*=\s*(?:(?:\([a-zA-Z0-9_ *]+\))?\s*)param_2;\s*(?:return;)?\s*\}$")),
    ("setter_off", re.compile(r"^\{\s*\*\((\w+)\s*\*\)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\)\s*=\s*(?:(?:\([a-zA-Z0-9_ *]+\))?\s*)param_2;\s*(?:return;)?\s*\}$")),
    ("setter_const_deref", re.compile(r"^\{\s*\*\((\w+)\s*\*\)param_1\s*=\s*(-?(?:0x[0-9a-fA-F]+|[0-9]+));\s*(?:return;)?\s*\}$")),
    ("setter_const_off", re.compile(r"^\{\s*\*\((\w+)\s*\*\)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\)\s*=\s*(-?(?:0x[0-9a-fA-F]+|[0-9]+));\s*(?:return;)?\s*\}$")),
    ("vtable_bind", re.compile(r"^\{\s*\*param_1\s*=\s*&(?:PTR_|DAT_)([0-9a-zA-Z_]+);\s*(?:return;)?\s*\}$")),
    ("vtable_bind_ret", re.compile(r"^\{\s*\*param_1\s*=\s*&(?:PTR_|DAT_)([0-9a-zA-Z_]+);\s*return\s+param_1;\s*\}$")),
    ("post_quit_msg", re.compile(r"^\{\s*PostQuitMessage\(([0-9]+)\);\s*(?:return;)?\s*\}$")),
    ("terminate_process", re.compile(r".*TerminateProcess.*")),
    ("thunk_1", re.compile(r"^\{\s*(?:return\s+)?(decomp_fn_[0-9a-fA-F]+)\(param_1\);\s*(?:return;)?\s*\}$")),
    ("thunk_2", re.compile(r"^\{\s*(?:return\s+)?(decomp_fn_[0-9a-fA-F]+)\(param_1,\s*param_2\);\s*(?:return;)?\s*\}$")),
    ("thunk_const2", re.compile(r"^\{\s*(?:return\s+)?(decomp_fn_[0-9a-fA-F]+)\(param_1,\s*(-?(?:0x[0-9a-fA-F]+|[0-9]+))\);\s*(?:return;)?\s*\}$")),
    ("win32_api_wrapper", re.compile(r"^\{\s*(?:BOOL\s+BVar1;\s+BVar1\s*=\s*)?([A-Za-z0-9_]+)\((?:(?:\([a-zA-Z0-9_* ]+\))?param_1)?(?:\s*,\s*param_2)?\);\s*(?:return\s+[^;]+;)?\s*\}$")),
]

matched = []
cat_counts = Counter()

for addr, sz in candidates:
    c_file = canonical_dir / f"decomp_fn_{addr}.c"
    if not c_file.exists():
        continue
    body = extract_outer_body(c_file.read_text(encoding="utf-8"))
    if not body:
        continue

    for pat_name, pat in patterns:
        m = pat.match(body)
        if m:
            matched.append((addr, sz, pat_name, body))
            cat_counts[pat_name] += 1
            break

print(f"Total matched: {len(matched)} / {len(candidates)}")
for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
    print(f"  {cat}: {cnt}")

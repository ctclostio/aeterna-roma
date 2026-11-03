from pathlib import Path
import re
from collections import Counter

ROOT = Path("X:/decompilation")
canonical_dir = ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_decomp"

# Load existing known names across existing funcid TSVs
named = set()
for p in (ROOT / "work").glob("funcid_*.tsv"):
    if p.name == "funcid_small_stubs.tsv":
        continue
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.strip().split("\t")
        if parts and parts[0]:
            addr_clean = parts[0].lower().replace("0x", "")
            named.add(addr_clean)

# Load candidates <= 32 bytes from function_index.txt
candidates = []
with open(ROOT / "src_out" / "empire.retail.dll" / "function_index.txt", "r", encoding="utf-8") as f:
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

re_scalar_del_dtor = re.compile(r"^\{\s*(decomp_fn_[0-9a-fA-F]+)\(\);\s*if\s*\(\(param_2\s*&\s*1\)\s*!=\s*0\)\s*\{\s*(?:decomp_fn_[0-9a-fA-F]+)\(param_1,\s*(0x[0-9a-fA-F]+|[0-9]+)\);\s*\}\s*return\s+param_1;\s*\}$")
re_fwd0 = re.compile(r"^\{\s*(decomp_fn_[0-9a-fA-F]+)\(\);\s*return;\s*\}$")
re_global_setter_const = re.compile(r"^\{\s*(?:_DAT_|DAT_|PTR_|_PTR_)([0-9a-zA-Z_.]+)\s*=\s*(-?(?:0x[0-9a-fA-F]+|[0-9]+));\s*(?:return;)?\s*\}$")
re_vtable_ptr_store = re.compile(r"^\{\s*\*param_1\s*=\s*(?:_DAT_|DAT_|PTR_|_PTR_)([0-9a-zA-Z_.]+);\s*(?:return;)?\s*\}$")
re_global_cleanup = re.compile(r"^\{\s*if\s*\((?:_DAT_|DAT_)([0-9a-zA-Z_.]+)\s*!=\s*0\)\s*\{\s*(decomp_fn_[0-9a-fA-F]+)\((?:_DAT_|DAT_)\1\);\s*\}\s*(?:return;)?\s*\}$")
re_member_off = re.compile(r"^\{\s*return\s+param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+);\s*\}$")
re_subobj_dtor = re.compile(r"^\{\s*(decomp_fn_[0-9a-fA-F]+)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\);\s*return\s+param_1;\s*\}$")
re_nested_getter = re.compile(r"^\{\s*return\s+\*(?:undefined4\s*\*|\w+\s*\*)\(\*(?:int\s*\*|\w+\s*\*)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\)\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\);\s*\}$")
re_dual_thunk = re.compile(r"^\{\s*(decomp_fn_[0-9a-fA-F]+)\(\);\s*(decomp_fn_[0-9a-fA-F]+)\(\);\s*return;\s*\}$")
re_field_eq = re.compile(r"^\{\s*return\s+\*(?:int\s*\*|\w+\s*\*)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\)\s*==\s*(-?(?:0x[0-9a-fA-F]+|[0-9]+));\s*\}$")
re_field_neq = re.compile(r"^\{\s*return\s+\*(?:int\s*\*|\w+\s*\*)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\)\s*!=\s*(-?(?:0x[0-9a-fA-F]+|[0-9]+));\s*\}$")
re_win32_cs_del = re.compile(r"^\{\s*DeleteCriticalSection\(\(LPCRITICAL_SECTION\)&(?:DAT_|PTR_)([0-9a-zA-Z_]+)\);\s*(?:return;)?\s*\}$")
re_return_this = re.compile(r"^\{\s*return\s+param_1;\s*\}$")
re_vtable_bind_ret = re.compile(r"^\{\s*\*param_1\s*=\s*&(?:PTR_|DAT_)([0-9a-zA-Z_]+);\s*return\s+param_1;\s*\}$")
re_fwd1 = re.compile(r"^\{\s*(?:return\s+)?(decomp_fn_[0-9a-fA-F]+)\(param_1\);\s*(?:return;)?\s*\}$")
re_fwd2 = re.compile(r"^\{\s*(?:return\s+)?(decomp_fn_[0-9a-fA-F]+)\(param_1,\s*param_2\);\s*(?:return;)?\s*\}$")
re_win32_wrap = re.compile(r"^\{\s*(?:BOOL\s+BVar1;\s+BVar1\s*=\s*)?([A-Za-z0-9_]+)\((?:(?:\([a-zA-Z0-9_* ]+\))?param_1)?(?:\s*,\s*param_2)?\);\s*(?:return\s+[^;]+;)?\s*\}$")

classified = []
counts = Counter()

for addr, sz in candidates:
    c_file = canonical_dir / f"decomp_fn_{addr}.c"
    if not c_file.exists():
        continue
    body = extract_outer_body(c_file.read_text(encoding="utf-8"))
    if not body:
        continue

    m = re_scalar_del_dtor.match(body)
    if m:
        dtor = m.group(1).replace("decomp_fn_", "")
        sz_val = m.group(2)
        classified.append((addr, f"scalar_deleting_dtor_{dtor}_{addr}", "core(destructor)", f"scalar deleting destructor calling {dtor} size {sz_val}"))
        counts["scalar_del_dtor"] += 1
        continue

    m = re_fwd0.match(body)
    if m:
        target = m.group(1).replace("decomp_fn_", "")
        classified.append((addr, f"thunk_{target}_{addr}", "core(thunk)", f"zero-argument forwarding thunk to {target}"))
        counts["fwd_thunk_0"] += 1
        continue

    m = re_global_setter_const.match(body)
    if m:
        glob = m.group(1).replace(".", "_")
        val = m.group(2).replace("-", "neg_").replace("0x", "")
        classified.append((addr, f"init_global_{glob}_val_{val}_{addr}", "core(init)", f"set global {glob} to {m.group(2)}"))
        counts["global_setter_const"] += 1
        continue

    m = re_vtable_ptr_store.match(body)
    if m:
        glob = m.group(1).replace(".", "_")
        classified.append((addr, f"store_vptr_{glob}_{addr}", "core(vtable)", f"store pointer {glob} into *this"))
        counts["vtable_ptr_store"] += 1
        continue

    m = re_global_cleanup.match(body)
    if m:
        glob = m.group(1).replace(".", "_")
        fn = m.group(2).replace("decomp_fn_", "")
        classified.append((addr, f"cleanup_global_{glob}_{addr}", "core(cleanup)", f"clean global {glob} via {fn}"))
        counts["global_cleanup"] += 1
        continue

    m = re_member_off.match(body)
    if m:
        off = m.group(1)
        classified.append((addr, f"offset_ptr_off_{off}_{addr}", "core(accessor)", f"calculate interior pointer this + {off}"))
        counts["member_offset"] += 1
        continue

    m = re_subobj_dtor.match(body)
    if m:
        fn = m.group(1).replace("decomp_fn_", "")
        off = m.group(2)
        classified.append((addr, f"subobject_dtor_off_{off}_{addr}", "core(destructor)", f"destroy subobject at this + {off} via {fn}"))
        counts["subobject_dtor"] += 1
        continue

    m = re_nested_getter.match(body)
    if m:
        off1 = m.group(1)
        off2 = m.group(2)
        classified.append((addr, f"nested_getter_{off1}_{off2}_{addr}", "core(accessor)", f"read field *(this + {off1}) + {off2}"))
        counts["nested_getter"] += 1
        continue

    m = re_dual_thunk.match(body)
    if m:
        f1 = m.group(1).replace("decomp_fn_", "")
        f2 = m.group(2).replace("decomp_fn_", "")
        classified.append((addr, f"dual_thunk_{f1}_{f2}_{addr}", "core(thunk)", f"sequence calls to {f1} and {f2}"))
        counts["dual_thunk"] += 1
        continue

    m = re_field_eq.match(body)
    if m:
        off = m.group(1)
        val = m.group(2).replace("-", "neg_").replace("0x", "")
        classified.append((addr, f"predicate_eq_off_{off}_val_{val}_{addr}", "core(accessor)", f"check if field at this + {off} == {m.group(2)}"))
        counts["field_eq"] += 1
        continue

    m = re_field_neq.match(body)
    if m:
        off = m.group(1)
        val = m.group(2).replace("-", "neg_").replace("0x", "")
        classified.append((addr, f"predicate_neq_off_{off}_val_{val}_{addr}", "core(accessor)", f"check if field at this + {off} != {m.group(2)}"))
        counts["field_neq"] += 1
        continue

    m = re_win32_cs_del.match(body)
    if m:
        cs = m.group(1)
        classified.append((addr, f"cs_delete_{cs}_{addr}", "os(sync)", f"DeleteCriticalSection on &DAT_{cs}"))
        counts["win32_cs_del"] += 1
        continue

    if re_return_this.match(body):
        classified.append((addr, f"identity_return_this_{addr}", "core(method)", "return this / identity method"))
        counts["return_this"] += 1
        continue

    m = re_vtable_bind_ret.match(body)
    if m:
        vt = m.group(1)
        classified.append((addr, f"vtable_bind_ret_{vt}_{addr}", "core(vtable)", f"bind vtable &PTR_{vt} and return this"))
        counts["vtable_bind_ret"] += 1
        continue

    m = re_fwd1.match(body)
    if m:
        t = m.group(1).replace("decomp_fn_", "")
        classified.append((addr, f"thunk_{t}_{addr}", "core(thunk)", f"forwarding thunk to {t}"))
        counts["fwd_thunk_1"] += 1
        continue

    m = re_fwd2.match(body)
    if m:
        t = m.group(1).replace("decomp_fn_", "")
        classified.append((addr, f"thunk2_{t}_{addr}", "core(thunk)", f"two-arg forwarding thunk to {t}"))
        counts["fwd_thunk_2"] += 1
        continue

    m = re_win32_wrap.match(body)
    if m:
        api = m.group(1)
        if not api.startswith("decomp_fn_"):
            classified.append((addr, f"win32_{api}_{addr}", "os(win32)", f"Win32 API call {api}"))
            counts["win32_wrap"] += 1
            continue

print(f"Total classified: {len(classified)} / {len(candidates)}")
for cat, cnt in sorted(counts.items(), key=lambda x: -x[1]):
    print(f"  {cat}: {cnt}")

out_tsv = ROOT / "work" / "funcid_small_stubs.tsv"
with open(out_tsv, "w", encoding="utf-8") as f:
    for addr, name, subsystem, desc in classified:
        f.write(f"0x{addr}\t{name}\t{subsystem}\t{desc}\n")

print(f"Wrote {len(classified)} classified rows to {out_tsv}")

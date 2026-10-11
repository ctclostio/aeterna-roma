from pathlib import Path
from collections import Counter
import re

canonical_dir = Path("src_canonical_out/empire.retail.dll/canonical_decomp")

# Load existing known names
named = {}
with open("src_out/empire.retail.dll/named_functions.txt", "r", encoding="utf-8") as f:
    for line in f:
        p = line.strip().split("\t")
        if len(p) >= 2:
            named[p[0].lower().replace("0x", "")] = p[1]

# Load candidates <= 15 bytes
candidates = []
with open("src_out/empire.retail.dll/function_index.txt", "r", encoding="utf-8") as f:
    for line in f:
        p = line.strip().split("\t")
        if len(p) >= 3:
            addr = p[0].lower().replace("0x", "")
            size = int(p[2])
            if addr not in named and size <= 25:
                candidates.append((addr, size))

print(f"Total unnamed candidates <= 15 bytes: {len(candidates)}")

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
    no_block_comments = re.sub(r"/\*.*?\*/", "", raw, flags=re.DOTALL)
    no_line_comments = re.sub(r"//[^\n]*", "", no_block_comments)
    return " ".join(no_line_comments.split())

# Patterns
re_noop = re.compile(r"^\{\s*(?:return;)?\s*\}$")
re_ret0 = re.compile(r"^\{\s*return\s+0;\s*\}$")
re_ret1 = re.compile(r"^\{\s*return\s+1;\s*\}$")
re_ret_const = re.compile(r"^\{\s*return\s+(-?(?:0x[0-9a-fA-F]+|[0-9]+));\s*\}$")
re_ret_global_ptr = re.compile(r"^\{\s*return\s+&(?:DAT_|PTR_)([0-9a-zA-Z_]+);\s*\}$")
re_ret_global_val = re.compile(r"^\{\s*return\s+(?:DAT_|PTR_)([0-9a-zA-Z_]+);\s*\}$")
re_getter = re.compile(r"^\{\s*return\s+(?:\([a-zA-Z0-9_ ]+\))?\s*\*\((\w+)\s*\*\)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\);\s*\}$")
re_getter_deref = re.compile(r"^\{\s*return\s+(?:\([a-zA-Z0-9_ ]+\))?\s*\*\((\w+)\s*\*\)param_1;\s*\}$")
re_setter = re.compile(r"^\{\s*\*\((\w+)\s*\*\)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\)\s*=\s*(?:(?:\([a-zA-Z0-9_ ]+\))?\s*)param_2;\s*(?:return;)?\s*\}$")
re_setter_deref = re.compile(r"^\{\s*\*\((\w+)\s*\*\)param_1\s*=\s*(?:(?:\([a-zA-Z0-9_ ]+\))?\s*)param_2;\s*(?:return;)?\s*\}$")
re_setter_const = re.compile(r"^\{\s*\*\((\w+)\s*\*\)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\)\s*=\s*(-?(?:0x[0-9a-fA-F]+|[0-9]+));\s*(?:return;)?\s*\}$")
re_setter_const_deref = re.compile(r"^\{\s*\*\((\w+)\s*\*\)param_1\s*=\s*(-?(?:0x[0-9a-fA-F]+|[0-9]+));\s*(?:return;)?\s*\}$")
re_bitflag_set = re.compile(r"^\{\s*\*\((\w+)\s*\*\)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\)\s*=\s*\*\((\w+)\s*\*\)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\)\s*\|\s*(0x[0-9a-fA-F]+|[0-9]+);\s*(?:return;)?\s*\}$")
re_vtable_bind = re.compile(r"^\{\s*\*param_1\s*=\s*&(?:PTR_|DAT_)([0-9a-zA-Z_]+);\s*(?:return;)?\s*\}$")
re_fwd1 = re.compile(r"^\{\s*(?:return\s+)?(decomp_fn_[0-9a-fA-F]+)\(param_1\);\s*(?:return;)?\s*\}$")
re_fwd2 = re.compile(r"^\{\s*(?:return\s+)?(decomp_fn_[0-9a-fA-F]+)\(param_1,\s*param_2\);\s*(?:return;)?\s*\}$")
re_fwd1_const2 = re.compile(r"^\{\s*(?:return\s+)?(decomp_fn_[0-9a-fA-F]+)\(param_1,\s*(-?(?:0x[0-9a-fA-F]+|[0-9]+))\);\s*(?:return;)?\s*\}$")
re_stl_len_err = re.compile(r".*decomp_fn_11686192\(\"string too long\"\).*")
re_stl_range_err = re.compile(r".*decomp_fn_11686192\(\"invalid string position\"\).*")
re_scalar_del_dtor = re.compile(r"^\{\s*if\s*\(param_1\s*!=\s*\([a-zA-Z0-9_* ]+\)0x0\)\s*\{\s*\(\*\*\([a-zA-Z0-9_* ]+\)\*param_1\)\(1\);\s*\}\s*(?:return;)?\s*\}$")
re_array_index = re.compile(r"^\{\s*return\s+\*\(int\s*\*\)\(param_1\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\)\s*\+\s*param_2(?:\s*\*\s*([0-9]+))?;\s*\}$")
re_win32_call1 = re.compile(r"^\{\s*([A-Za-z0-9_]+)\(param_1\);\s*(?:return;)?\s*\}$")
re_win32_call2 = re.compile(r"^\{\s*([A-Za-z0-9_]+)\(\([a-zA-Z0-9_* ]+\)0x0,\s*param_1\);\s*(?:return;)?\s*\}$")
re_raii_close_handle = re.compile(r"^\{\s*if\s*\(\(HANDLE\)\*param_1\s*!=\s*\(HANDLE\)0x0\)\s*\{\s*CloseHandle\(\(HANDLE\)\*param_1\);\s*\}\s*(?:return;)?\s*\}$")
re_zero_4dwords = re.compile(r"^\{\s*\*param_1\s*=\s*0;\s*param_1\[1\]\s*=\s*0;\s*param_1\[2\]\s*=\s*0;\s*param_1\[3\]\s*=\s*0;\s*return\s+param_1;\s*\}$")

results = []
category_counts = Counter()

for addr, size in candidates:
    c_file = canonical_dir / f"decomp_fn_{addr}.c"
    if not c_file.exists():
        continue
    body_clean = extract_outer_body(c_file.read_text(encoding="utf-8"))
    if not body_clean:
        continue

    if re_noop.match(body_clean):
        name = f"stub_noop_{addr}"
        subsystem = "core(stub)"
        desc = "empty no-op stub"
        results.append((addr, name, subsystem, desc))
        category_counts["noop"] += 1
        continue

    if re_ret0.match(body_clean):
        name = f"stub_return_0_{addr}"
        subsystem = "core(stub)"
        desc = "stub returning 0 / false"
        results.append((addr, name, subsystem, desc))
        category_counts["return_0"] += 1
        continue

    if re_ret1.match(body_clean):
        name = f"stub_return_1_{addr}"
        subsystem = "core(stub)"
        desc = "stub returning 1 / true"
        results.append((addr, name, subsystem, desc))
        category_counts["return_1"] += 1
        continue

    m = re_ret_const.match(body_clean)
    if m:
        val = m.group(1).replace("-", "neg_").replace("0x", "")
        name = f"stub_return_const_{val}_{addr}"
        subsystem = "core(stub)"
        desc = f"stub returning constant {m.group(1)}"
        results.append((addr, name, subsystem, desc))
        category_counts["return_const"] += 1
        continue

    m = re_ret_global_ptr.match(body_clean)
    if m:
        target = m.group(1)
        name = f"singleton_get_ptr_{target}_{addr}"
        subsystem = "core(singleton)"
        desc = f"returns pointer to global singleton &DAT_{target}"
        results.append((addr, name, subsystem, desc))
        category_counts["return_global_ptr"] += 1
        continue

    m = re_ret_global_val.match(body_clean)
    if m:
        target = m.group(1)
        name = f"global_get_val_{target}_{addr}"
        subsystem = "core(singleton)"
        desc = f"returns value of global variable DAT_{target}"
        results.append((addr, name, subsystem, desc))
        category_counts["return_global_val"] += 1
        continue

    m = re_getter.match(body_clean)
    if m:
        vtype = m.group(1)
        offset = m.group(2)
        name = f"getter_off_{offset}_{addr}"
        subsystem = "core(accessor)"
        desc = f"read {vtype} field at this + {offset}"
        results.append((addr, name, subsystem, desc))
        category_counts["getter"] += 1
        continue

    m = re_getter_deref.match(body_clean)
    if m:
        vtype = m.group(1)
        name = f"getter_deref_{addr}"
        subsystem = "core(accessor)"
        desc = f"dereference {vtype} field at this"
        results.append((addr, name, subsystem, desc))
        category_counts["getter_deref"] += 1
        continue

    m = re_setter.match(body_clean)
    if m:
        vtype = m.group(1)
        offset = m.group(2)
        name = f"setter_off_{offset}_{addr}"
        subsystem = "core(accessor)"
        desc = f"write {vtype} field at this + {offset}"
        results.append((addr, name, subsystem, desc))
        category_counts["setter"] += 1
        continue

    m = re_setter_deref.match(body_clean)
    if m:
        vtype = m.group(1)
        name = f"setter_deref_{addr}"
        subsystem = "core(accessor)"
        desc = f"write {vtype} field at this"
        results.append((addr, name, subsystem, desc))
        category_counts["setter_deref"] += 1
        continue

    m = re_setter_const.match(body_clean)
    if m:
        vtype = m.group(1)
        offset = m.group(2)
        val = m.group(3).replace("-", "neg_").replace("0x", "")
        name = f"setter_off_{offset}_const_{val}_{addr}"
        subsystem = "core(accessor)"
        desc = f"set {vtype} field at this + {offset} to constant {m.group(3)}"
        results.append((addr, name, subsystem, desc))
        category_counts["setter_const"] += 1
        continue

    m = re_setter_const_deref.match(body_clean)
    if m:
        vtype = m.group(1)
        val = m.group(2).replace("-", "neg_").replace("0x", "")
        name = f"setter_deref_const_{val}_{addr}"
        subsystem = "core(accessor)"
        desc = f"set {vtype} field at this to constant {m.group(2)}"
        results.append((addr, name, subsystem, desc))
        category_counts["setter_const_deref"] += 1
        continue

    m = re_bitflag_set.match(body_clean)
    if m:
        offset = m.group(2)
        mask = m.group(5)
        name = f"bitflag_set_off_{offset}_mask_{mask}_{addr}"
        subsystem = "core(accessor)"
        desc = f"bitwise-OR field at this + {offset} with {mask}"
        results.append((addr, name, subsystem, desc))
        category_counts["bitflag_set"] += 1
        continue

    m = re_vtable_bind.match(body_clean)
    if m:
        vt = m.group(1)
        name = f"vtable_bind_{vt}_{addr}"
        subsystem = "core(vtable)"
        desc = f"initialize vtable pointer to &PTR_{vt}"
        results.append((addr, name, subsystem, desc))
        category_counts["vtable_bind"] += 1
        continue

    m = re_array_index.match(body_clean)
    if m:
        offset = m.group(1)
        scale = m.group(2) or "1"
        name = f"array_index_off_{offset}_scale_{scale}_{addr}"
        subsystem = "core(accessor)"
        desc = f"compute element address at this + {offset} + index * {scale}"
        results.append((addr, name, subsystem, desc))
        category_counts["array_index"] += 1
        continue

    if re_raii_close_handle.match(body_clean):
        name = f"raii_close_handle_if_nonzero_{addr}"
        subsystem = "core(resource)"
        desc = "CloseHandle on non-null HANDLE pointer"
        results.append((addr, name, subsystem, desc))
        category_counts["raii_close_handle"] += 1
        continue

    if re_zero_4dwords.match(body_clean):
        name = f"struct16_zero_init_{addr}"
        subsystem = "core(memory)"
        desc = "zero initialize 16-byte structure (4 dwords)"
        results.append((addr, name, subsystem, desc))
        category_counts["zero_4dwords"] += 1
        continue

    if re_scalar_del_dtor.match(body_clean):
        name = f"scalar_deleting_destructor_thunk_{addr}"
        subsystem = "core(destructor)"
        desc = "MSVC virtual scalar deleting destructor thunk: if (this) this->vtable[0](1)"
        results.append((addr, name, subsystem, desc))
        category_counts["scalar_del_dtor"] += 1
        continue

    m = re_win32_call1.match(body_clean)
    if m:
        api = m.group(1)
        if not api.startswith("decomp_fn_"):
            name = f"win32_thunk_{api}_{addr}"
            subsystem = "os(win32)"
            desc = f"thunk calling Win32 API {api}(param_1)"
            results.append((addr, name, subsystem, desc))
            category_counts["win32_call"] += 1
            continue

    m = re_win32_call2.match(body_clean)
    if m:
        api = m.group(1)
        if not api.startswith("decomp_fn_"):
            name = f"win32_thunk_{api}_{addr}"
            subsystem = "os(win32)"
            desc = f"thunk calling Win32 API {api}(NULL, param_1)"
            results.append((addr, name, subsystem, desc))
            category_counts["win32_call"] += 1
            continue

    m = re_fwd1.match(body_clean)
    if m:
        callee = m.group(1)
        callee_addr = callee.replace("decomp_fn_", "").lower()
        callee_name = named.get(callee_addr, callee)
        name = f"thunk_{callee_name}_{addr}"
        subsystem = "core(thunk)"
        desc = f"forwarding thunk to {callee_name}"
        results.append((addr, name, subsystem, desc))
        category_counts["thunk_1"] += 1
        continue

    m = re_fwd2.match(body_clean)
    if m:
        callee = m.group(1)
        callee_addr = callee.replace("decomp_fn_", "").lower()
        callee_name = named.get(callee_addr, callee)
        name = f"thunk_{callee_name}_{addr}"
        subsystem = "core(thunk)"
        desc = f"two-argument forwarding thunk to {callee_name}"
        results.append((addr, name, subsystem, desc))
        category_counts["thunk_2"] += 1
        continue

    m = re_fwd1_const2.match(body_clean)
    if m:
        callee = m.group(1)
        c2 = m.group(2).replace("-", "neg_").replace("0x", "")
        callee_addr = callee.replace("decomp_fn_", "").lower()
        callee_name = named.get(callee_addr, callee)
        name = f"thunk_{callee_name}_arg2_{c2}_{addr}"
        subsystem = "core(thunk)"
        desc = f"forwarding thunk to {callee_name} with arg2={m.group(2)}"
        results.append((addr, name, subsystem, desc))
        category_counts["thunk_const2"] += 1
        continue

    if re_stl_len_err.match(body_clean):
        name = f"stl_throw_length_error_{addr}"
        subsystem = "stl(exception)"
        desc = "std::_Xlength_error(\"string too long\") thunk"
        results.append((addr, name, subsystem, desc))
        category_counts["stl_len_err"] += 1
        continue

    if re_stl_range_err.match(body_clean):
        name = f"stl_throw_out_of_range_{addr}"
        subsystem = "stl(exception)"
        desc = "std::_Xout_of_range(\"invalid string position\") thunk"
        results.append((addr, name, subsystem, desc))
        category_counts["stl_range_err"] += 1
        continue

print(f"Successfully classified {len(results)} functions out of {len(candidates)}:")
for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
    print(f"  {cat}: {count}")

# Save classified results
out_tsv = Path("work/funcid_small_stubs.tsv")
with open(out_tsv, "w", encoding="utf-8") as f:
    for addr, name, subsystem, desc in results:
        f.write(f"0x{addr}\t{name}\t{subsystem}\t{desc}\n")

print(f"Saved {len(results)} records to {out_tsv}")

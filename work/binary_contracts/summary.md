# Whole-binary static ABI & type-layout contracts - empire.retail.dll

Complete PE-verified static contract pinning across all **81,280 / 81,280 (100.0%)** canonical functions, all **9,639 / 9,639 (100.0%)** inventoried vtables, all **181** MSVC RTTI `TypeDescriptor`s (**15** `.rdata` `CompleteObjectLocator`s), static member/constructor class field layouts (**95,747** entries across **6,281** vtables), and **11,189** PE-verified static global records (`port/recovered_types/contracts.json` curated C17 Layer 83 kept independent and untouched).

## 1. Contract coverage

| contract artifact | entries | file size | verification scope |
|---|---:|---:|---|
| `function_contracts_part1.tsv` + `part2.tsv` | 81,280 | 18.00 MB | PE `body_ranges` SHA-256, Capstone exit opcode, CC/stack purge, export & vtable flags |
| `non_proc_curated_slots.tsv` | 31 | 4.5 KB | Curated Layer 1-83 vtable-slot entries absent from canonical function index |
| `vtable_class_contracts.tsv` | 9,639 | 2.68 MB | PE `.rdata` slot-table SHA-256, hierarchy, RTTI link, observed field extent & alloc hints |
| `class_field_layouts.tsv` | 95,747 | 6.44 MB | `+0x0` vptr (`9,639`), MI subobjects, member/ctor `this+off` widths & read/write access |
| `rtti_contracts.tsv` | 181 (15 COLs) | 34.1 KB | PE `.data` `TypeDescriptor` SHA-256 + `.rdata` `CompleteObjectLocator` / `CHD` / bases |
| `global_contracts.tsv` | 11,189 | 0.95 MB | Curated globals (`1,130`), IAT (`615`), data exports (`29`), RTTI, `.data` reloc ptrs |

## 2. Function exit & calling-convention breakdown (`81,280` functions)

| exit_kind | count | share |
|---|---:|---:|
| `ret` | 74,884 | 92.13% |
| `tail_jmp_rel32` | 5,746 | 7.07% |
| `tail_jmp_indirect` | 375 | 0.46% |
| `tail_jmp_iat` | 208 | 0.26% |
| `noreturn_call_rel32` | 33 | 0.04% |
| `tail_jmp_rel8` | 12 | 0.01% |
| `fallthrough_stub` | 9 | 0.01% |
| `bnd_ret` | 7 | 0.01% |
| `noreturn_call_iat` | 3 | 0.00% |
| `trap_int3` | 3 | 0.00% |

| calling_convention | count | share |
|---|---:|---:|
| `thiscall` | 41,025 | 50.47% |
| `unknown` | 23,894 | 29.40% |
| `fastcall` | 15,722 | 19.34% |
| `cdecl` | 592 | 0.73% |
| `stdcall` | 47 | 0.06% |

## 3. Class field layouts, RTTI & curated Layer 83 reconciliation

* Vtables with member/ctor fields recovered beyond `+0x0` vptr: **6,281 / 9,639** (65.16%), totaling **95,747** `(vtable, offset)` entries.
* Vtables with direct constructor `alloc(size)` hint (`decomp_fn_100d12b0`): **278**.
* Curated Layer 83 reconciliation (`port/recovered_types/contracts.json`): **2,029 / 2,029** functions (`1,980` exact SHA match, `18` merged tail-jump expanded in Layer 47-56 vs canonical boundaries, `31` non-proc slots), **1130 / 1130** globals, and **85 / 85** vtables matched.

## 4. Boundary & honesty note

* Whole-binary contracts capture PE-verified byte identities, x86 return/tail-jump mechanics, calling-convention/stack-purge bounds, RTTI descriptors, static globals, and observed `this+off` field accesses — NOT handwritten C17 native behavioral implementations (`port/recovered_types/contracts.json` remains separate and authoritative for tested C17 native semantics).

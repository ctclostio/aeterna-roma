# Indirect call resolution - empire.retail.dll (Total War: Rome II)

Third pass: whole-program cross-function type propagation, PE/IAT/COM resolution, and sound multi-slot + stack-purge CHA closure over all 81,280 canonical functions.

Inputs: `work/indirect_calls_after.tsv` (59,079 sites), `work/indirect_call_cache/asm_context.tsv` + `function_purges.tsv` + `external_symbols.tsv` (read-only Ghidra export), `src_canonical_out/empire.retail.dll/canonical_decomp/` (81,280 files), PE `Total War Rome II/empire.retail.dll` (PE32, image base 0x10000000), `work/registrar_roots.tsv`, `src_out/empire.retail.dll/vftables.txt`, `port/recovered_types/contracts.json`.

Outputs: `work/indirect_call_resolutions_after.tsv` (59,079 rows), `work/indirect_call_target_sets_after.tsv` (3,961 target sets), `work/indirect_call_vtables_after.tsv` (123,569 slots), `work/indirect_call_hierarchy_after.tsv` (9,639 vtables), this file.

## 1. Site population and classification coverage

| metric | sites | share |
|---|---:|---:|
| total indirect call sites | 59,079 | 100.00% |
| classified / resolved (`high` + `medium` + `low`) | 59,079 | 100.00% |
| statically narrowed (`high` + `medium`) | 33,987 | 57.53% |
| residual sound CHA closure (`low`) | 25,092 | 42.47% |
| unresolved | 0 | 0.00% |
| containing function recorded by Ghidra | 58,471 | 98.97% |
| C call expression aligned | 54,133 | 91.63% |

## 2. Resolution by kind and confidence

| resolution_kind | sites | high | medium | low | share |
|---|---:|---:|---:|---:|---:|
| `monomorphic_internal` | 8,907 | 3,260 | 5,647 | 0 | 15.08% |
| `external_import` | 4,147 | 4,147 | 0 | 0 | 7.02% |
| `external_interface` | 37 | 33 | 4 | 0 | 0.06% |
| `polymorphic_virtual` | 45,252 | 0 | 20,615 | 24,637 | 76.60% |
| `callback_dispatch` | 476 | 0 | 21 | 455 | 0.81% |
| `null_optional_hook` | 229 | 229 | 0 | 0 | 0.39% |
| `non_call_trap` | 31 | 31 | 0 | 0 | 0.05% |
| **total** | **59,079** | **7,700** | **26,287** | **25,092** | **100.00%** |

* **high** — direct PE/Ghidra/IAT/single-class-store/static-global/zero-writer-BSS/non-call-trap proof.
* **medium** — interprocedural forward/backward propagation or multi-slot/arity CHA narrowing to a concrete `.text` target, bounded family set, or COM/SDK interface.
* **low** — sound residual CHA closure (`polymorphic_virtual`: intersected across all co-invoked slot offsets on the receiver and x86 stack-purge arity; `callback_dispatch`: PE address-taken callback universe filtered by stack-purge arity).

Distinct `.text` monomorphic targets: **2,702** across **17,395** calling functions.

## 3. Target-set cardinality stats

* Distinct deduplicated target sets in `work/indirect_call_target_sets_after.tsv`: **3,961**
* Propagated `[M]` `polymorphic_virtual` sites (20,615): median **11** targets, max **220** targets.
* Residual `[L]` `polymorphic_virtual` CHA sites (24,637): median **406** targets, p90 **5,321**, max **6,155**.

## 4. Delta vs Pass 1 and Pass 2

| metric | Pass 1 | Pass 2 | Pass 3 |
|---|---:|---:|---:|
| input sites | 59,012 | 59,079 | 59,079 |
| `high` | 75 | 76 | 7,700 |
| `medium` | 1,336 | 2,081 | 26,287 |
| statically narrowed (`high`+`medium`) | 1,411 (2.39%) | 2,157 (3.65%) | 33,987 (57.53%) |
| `low` (bounded / CHA) | 431 | 562 | 25,092 |
| `unresolved` | 57,170 | 56,360 | 0 |

## 5. Vtable inventory and class hierarchy

| source | vtables | slots |
|---|---:|---:|
| c_vtable_store | 8,934 | 119,528 |
| pe_data_vtable | 466 | 2,348 |
| pe_reloc_table | 138 | 1,104 |
| contracts | 53 | 460 |
| vftables_txt | 25 | 83 |
| registrar_roots | 23 | 46 |
| **total** | **9,639** | **123,569** |

* Reconstructed vtable families: **3,698**
* Inheritance parent edges: **2,213**
* Multiple-inheritance sub-object offsets mapped: **48,167**
* Exact x86 MI `this`-adjustor thunks decoded: **2,892**
* ICF/trivial/purecall stubs excluded from inheritance merging: **201**

## 6. Top resolved targets

### Top monomorphic internal targets

| calls | target | name |
|---:|---|---|
| 244 | 0x100f3d00 | OC3Ent_Face_FxActorInstance_Serialize |
| 208 | 0x100d6770 | stub_return_0_100d6770 |
| 184 | 0x10212d60 | battle_mode_call_1030b110_with_wstr_battle_10212d60 |
| 166 | 0x11056e00 | frontend_mode_get_field_0x150_0x38_11056e00 |
| 140 | 0x112c00b0 | fs_vfs_file_exists_packed_or_register_loose_112c00b0 |
| 127 | 0x100d6560 | guard_check_icall |
| 122 | 0x100d6900 | stub_return_1_100d6900 |
| 110 | 0x100e22c0 | stub_noop_100e22c0 |
| 109 | 0x10fca230 | achievement_tracker_unlock_by_id_10fca230 |
| 91 | 0x101d95d0 | ptr_list_append_unique_101d95d0 |
| 78 | 0x100d7cb0 | envvar_prefs_get_int_ref_by_index |
| 78 | 0x1021e700 | FUN_1021e700 |

### Top external imports and interfaces

| calls | kind | target |
|---:|---|---|
| 2,290 | `external_import` | OPENGL32.DLL!wglGetProcAddress |
| 875 | `external_import` | USER32.DLL!PeekMessageW |
| 185 | `external_import` | KERNEL32.DLL!ReadFile |
| 64 | `external_import` | KERNEL32.DLL!LeaveCriticalSection |
| 61 | `external_import` | KERNEL32.DLL!EnterCriticalSection |
| 54 | `external_import` | WINMM.DLL!timeGetTime |
| 45 | `external_import` | KERNEL32.DLL!GetProcAddress |
| 41 | `external_import` | KERNEL32.DLL!DeleteCriticalSection |
| 35 | `external_import` | KERNEL32.DLL!GetCurrentThreadId |
| 30 | `external_import` | EnterCriticalSection |
| 27 | `external_import` | KERNEL32.DLL!CloseHandle |
| 26 | `external_import` | KERNEL32.DLL!InitializeCriticalSection |

## 7. Validation

* `work/indirect_call_resolutions_after.tsv`: 59,079 data rows + header, 1:1 with `work/indirect_calls_after.tsv` site IDs (asserted).
* Zero `unresolved` rows; every `.text` address verified inside `.text` (`0x10001000..0x1172e4ea`).
* `work/indirect_call_target_sets_after.tsv`: 3,961 deduplicated target sets with exact matching `target_count`.
* `work/indirect_call_vtables_after.tsv`: 123,569 slots across 9,639 vtables.

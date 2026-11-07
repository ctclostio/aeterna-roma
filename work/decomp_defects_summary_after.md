# Decompiler Defect Inventory (post-recovery) - empire.retail.dll canonical corpus

Scanned **81,280** C files in `src_canonical_out/empire.retail.dll/canonical_decomp` (read-only). Every file carries fingerprint `f0caa97fbcb663124542c80eaebc440031e3d65708ec0630678beb77d85a884a` and reports `Export result: success`; no `DECOMPILATION FAILED`, no final timeouts (`canonical_export_status.tsv`: 2 first-pass timeouts, 0 final), no `halt_baddata()` calls and no blank function bodies were found.

- Warning rows: **9,856**
- Affected functions: **6,765** of 81,280 (8.32%)
- Functions with at least one high-severity defect: **1,048**
- High-severity rows: **2,220**
- Medium-severity rows: **413**
- Low-severity rows: **7,223**

## Delta vs the pre-wave inventory

| Metric | Before (63,326 files) | After (81,280 files) | Delta |
|---|---|---|---|
| Warning rows | 6,796 | 9,856 | +3,060 |
| Affected functions | 4,156 | 6,765 | +2,609 |
| High rows | 1,427 | 2,220 | +793 |
| High functions | 687 | 1,048 | +361 |
| Medium rows | 398 | 413 | +15 |
| Low rows | 4,971 | 7,223 | +2,252 |

Delta decomposition:

- **Pre-existing functions: 0 change.** All 4,156 pre-wave affected functions are still present and carry exactly 6,796 rows before and 6,796 after (zero regressions, zero fixes in already-inventoried functions).
- **Recovered functions: +3,044 rows** in 2,595 of the 17,935 recovered bodies (the other 15,340 are warning-free).
- **Newly materialised non-recovered files: +16 rows** in 14 files (12 global-overlap-only, 2 with jumptable/indirect pairs).
- **Removed functions: 0.**

## Counts by category (after / before)

| Category | Severity | After occ. | After funcs | Before occ. | Delta |
|---|---|---|---|---|---|
| `global_overlap` | low | 4,348 | 4,348 | 2,142 | +2,206 |
| `unreachable_block` | low | 1,959 | 393 | 1,935 | +24 |
| `jumptable_failure` | high | 1,110 | 1,043 | 713 | +397 |
| `indirect_jump_as_call` | high | 1,102 | 1,037 | 706 | +396 |
| `noreturn_call` | low | 584 | 455 | 569 | +15 |
| `type_propagation` | medium | 331 | 331 | 318 | +13 |
| `injection` | low | 276 | 274 | 273 | +3 |
| `spacebase` | medium | 73 | 73 | 72 | +1 |
| `restart_deadcode` | low | 41 | 41 | 38 | +3 |
| `inlined` | low | 8 | 8 | 8 | +0 |
| `jumptable_degraded` | medium | 7 | 5 | 6 | +1 |
| `readonly_write` | high | 6 | 3 | 6 | +0 |
| `heritage_dead_removal` | low | 4 | 4 | 4 | +0 |
| `switch_degraded` | low | 2 | 2 | 2 | +0 |
| `restart_limit` | high | 2 | 2 | 2 | +0 |
| `switch_case_unlabeled` | medium | 2 | 1 | 2 | +0 |
| `infinite_loop_block` | low | 1 | 1 | 0 | +1 |
| **TOTAL** |  | **9,856** | **6,765** | **6,796** | **+3,060** |

`infinite_loop_block` is the only category added to the schema: the post-wave export emits `/* WARNING: Do nothing block with infinite loop */` once (function `112bae20`). The exporter also changed the tagged form from `WARNING: (jumptable): ...` to `WARNING (jumptable): ...`; the scanner normalises it back to the old `(jumptable): ...` detail so categories and detail text stay comparable.

## Recovered functions (17,935 unique bodies in `work/recovery_all.tsv`)

- Recovered functions with defects: **2,595** / 17,935 (14.47%); 15,340 are clean.
- Rows: **3,044** (low 2,240, medium 15, high 789).
- High-severity rows: **789** in **359** functions, all of them `jumptable_failure` (395) + `indirect_jump_as_call` (394).
- By wave: wave2_table: 695 high rows / 329 funcs, wave3_table: 90 high rows / 28 funcs, wave4_undisassembled: 4 high rows / 2 funcs.

### Are those new high-severity rows real?

Of the 395 `jumptable_failure` warnings in recovered functions, 394 carry an address. Instruction-shape classification of those addresses (`work/_jumptable_dump_after.tsv`, which covers every addressed warning):

| Shape | Recovered addressed warnings | Share |
|---|---|---|
| `virtual_vtable` | 320 | 81.2% |
| `register_indirect` | 72 | 18.3% |
| `iat_dispatch` | 2 | 0.5% |

- **Zero** recovered addressed jumptable warnings point at a true code switch table (`JMP dword ptr [reg*4+disp32]`).
- 320 are vtable slot dispatch, 72 are register-indirect tail calls and 2 are IAT thunks; their paired `indirect_jump_as_call` rows describe the same sites.
- **One** recovered function has a genuine switch-table failure without an address: `114b7d80` (`Could not find normalized switch variable to match jumptable` + `Sanity check requires truncation of jumptable`). Its body contains 8 real `JMP dword ptr [EAX*4+disp32]` jump sites (0x114b7ef1 ... 0x114b82b4, tables at 0x114b8380 ... 0x114b8678); the decompiler emitted `switch((&DAT_114b85d4)[iVar4])`, i.e. it read a jump table as data.

**Conclusion:** 788 of the 789 new high-severity rows in recovered functions are virtual/IAT/register-dispatch artefacts (benign), and exactly **1** is a true switch-table failure (`114b7d80`). No new `readonly_write`, `restart_limit`, `halt_baddata` or export failures appeared in the recovered set.

Recovered medium/low defects: `global_overlap` 2194, `unreachable_block` 24, `noreturn_call` 15, `type_propagation` 13, `injection` 3, `restart_deadcode` 3, `spacebase` 1, `infinite_loop_block` 1, `jumptable_degraded` 1.

## True switch tables vs virtual/IAT dispatch

The post-wave corpus has **1,110** `jumptable_failure` warnings: 1,102 addressed (1,086 unique addresses; 16 addresses are reported by two overlapping bodies) and 8 without an address. All 1,102 addressed warnings have a paired `Treating indirect jump as call`; the 8 no-address warnings are the only unpaired ones, which is exactly the signature of a selector-normalization failure rather than dispatch.

Addressed warnings by instruction shape:

| Shape | Warnings | Functions |
|---|---|---|
| `virtual_vtable` | 691 | 640 |
| `iat_dispatch` | 227 | 227 |
| `register_indirect` | 163 | 161 |
| `true_switch_table` | 21 | 10 |

- **21 addressed warnings are true switch tables** (`JMP dword ptr [reg*4+disp32]`) in **10 functions**. I re-derived this from `_jumptable_dump_after.tsv` and byte-verified every site in the DLL. The addresses are identical to the pre-wave `_jumptable_dump.tsv` set, so the "same 21 in 10" part of the claim is **confirmed**.
- The 10 functions: `103e76a0`, `103e7c70`, `103e96c0`, `10445310`, `104c1fb0`, `1068cea0`, `107ca950`, `10fbb5e0`, `10fe9050`, `11299e70`.
- The other 1,081 addressed warnings are **not** switch tables: 691 vtable-slot dispatch (`JMP [reg+off]`), 163 register-indirect (`JMP reg`) and 227 IAT thunks (`JMP [abs]`).

**Correction to the 21/10 claim:** the dump-based count silently drops the 8 no-address `Could not find normalized switch variable` warnings. All 6 functions that carry them contain real code jump tables (26 table sites):

| Function | No-addr warnings | True table sites |
|---|---|---|
| `10a054b0` | 1 | 2 |
| `10f1f890` | 1 | 4 |
| `1130aa70` | 1 | 2 |
| `114b7d80` | 1 | 8 |
| `116b8ebc` | 2 | 5 |
| `116ba4ba` | 2 | 5 |

Those 8 warnings are genuine switch-table failures too (they are not virtual/IAT), so the correct total is **29 of 1,110 warnings (2.6%) in 16 functions** are switch-table failures; the remaining 1,081 (97.4%) are dispatch. The "21/10" figure is correct only for warnings that carry an address.

Two newly materialised non-recovered files add high warnings, and both are dispatch, not tables: `1036bd50` (`JMP [EAX+0x1dc]`, vtable) and `11683541` (`JMP [0x1172f8c0]`, IAT `D3DPERF_EndEvent`).

## Top 30 functions by total defect count

| # | Entry | Defects | High | Categories | File |
|---|---|---|---|---|---|
| 1 | `1056d720` | 224 | 0 | global_overlap, unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1056d720.c` |
| 2 | `10cd8240` | 55 | 0 | global_overlap, unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10cd8240.c` |
| 3 | `114e9820` | 46 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114e9820.c` |
| 4 | `10cde540` | 39 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10cde540.c` |
| 5 | `10cdea50` | 39 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10cdea50.c` |
| 6 | `112f6e00` | 37 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_112f6e00.c` |
| 7 | `10c0ce70` | 35 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10c0ce70.c` |
| 8 | `109e1710` | 30 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_109e1710.c` |
| 9 | `112cd780` | 30 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_112cd780.c` |
| 10 | `106b5d70` | 28 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_106b5d70.c` |
| 11 | `11185b40` | 28 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11185b40.c` |
| 12 | `113cb530` | 25 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_113cb530.c` |
| 13 | `100d3bb0` | 24 | 0 | noreturn_call, unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100d3bb0.c` |
| 14 | `10946e00` | 24 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10946e00.c` |
| 15 | `10e3b3c0` | 23 | 0 | global_overlap, unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10e3b3c0.c` |
| 16 | `10c85c20` | 21 | 0 | global_overlap, unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10c85c20.c` |
| 17 | `10c86780` | 21 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10c86780.c` |
| 18 | `11620500` | 19 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11620500.c` |
| 19 | `107fcd00` | 18 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_107fcd00.c` |
| 20 | `1145a7c0` | 18 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1145a7c0.c` |
| 21 | `10b51150` | 17 | 0 | global_overlap, unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10b51150.c` |
| 22 | `114f70e0` | 16 | 16 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f70e0.c` |
| 23 | `114f7230` | 16 | 16 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f7230.c` |
| 24 | `10cd92d0` | 14 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10cd92d0.c` |
| 25 | `10fc0a00` | 14 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10fc0a00.c` |
| 26 | `10343770` | 13 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10343770.c` |
| 27 | `10489090` | 13 | 0 | global_overlap, unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10489090.c` |
| 28 | `11208810` | 13 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11208810.c` |
| 29 | `103e76a0` | 12 | 12 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e76a0.c` |
| 30 | `103e96c0` | 12 | 12 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e96c0.c` |

## Top 20 functions by high-severity defect count

| # | Entry | High | Categories | File |
|---|---|---|---|---|
| 1 | `114f70e0` | 16 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f70e0.c` |
| 2 | `114f7230` | 16 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f7230.c` |
| 3 | `103e76a0` | 12 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e76a0.c` |
| 4 | `103e96c0` | 12 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e96c0.c` |
| 5 | `114f6df0` | 8 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f6df0.c` |
| 6 | `114f6e60` | 8 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f6e60.c` |
| 7 | `114f7070` | 8 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f7070.c` |
| 8 | `114f71c0` | 8 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f71c0.c` |
| 9 | `110e26b0` | 6 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_110e26b0.c` |
| 10 | `114f6920` | 6 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f6920.c` |
| 11 | `10193ba0` | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10193ba0.c` |
| 12 | `1030fe80` | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1030fe80.c` |
| 13 | `103bce60` | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103bce60.c` |
| 14 | `103e7c70` | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e7c70.c` |
| 15 | `103ed2a0` | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103ed2a0.c` |
| 16 | `107249d0` | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_107249d0.c` |
| 17 | `10795f80` | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10795f80.c` |
| 18 | `10fc0e70` | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10fc0e70.c` |
| 19 | `10ff8e80` | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10ff8e80.c` |
| 20 | `11000380` | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11000380.c` |

## Validation

- `decomp_defects_after.tsv`: 9,857 lines including header; 7 columns; sum of category rows = 9,856.
- `decomp_defects_by_function_after.tsv`: 6,766 lines including header; 3 columns; sum of `defect_count` = 9,856.
- Every `function_entry` matches `decomp_fn_<entry>.c`, the file exists, and the entry exists in `canonical_function_index.tsv`.
- Every non-empty `warning_address` matches `^0x[0-9a-f]+$`; 6,507 warnings have no address in their text (expected for type/global/noreturn/selector notes).
- No unclassified warnings; no tabs/newlines in `detail`.
- Cross-check against `work/recovered_defects.tsv`: that quick scan has 3,042 rows; this scan has 3,044. The 2-row difference is exactly the two post-wave `/* WARNING (jumptable): ... */` rows (`114b7d80` jumptable_degraded, `103ed020` spacebase) that the quick scan's `/* WARNING: ... */` regex cannot see.

## Output files

- `work/decomp_defects_after.tsv` - one row per warning occurrence.
- `work/decomp_defects_by_function_after.tsv` - per-function counts and category sets.
- `work/decomp_defects_summary_after.md` - this report.

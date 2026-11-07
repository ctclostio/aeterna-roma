# Decompiler Defect Inventory - empire.retail.dll canonical corpus

Scanned **63,326** C files in `src_canonical_out/empire.retail.dll/canonical_decomp` (read-only). Every file reports `Export result: success`; no `DECOMPILATION FAILED`, no timeouts, no `halt_baddata()` calls, and no blank function bodies were found.

- Warning rows: **6,796**
- Affected functions: **4,156** of 63,326 (6.56%)
- Functions with at least one high-severity defect: **687**
- High-severity rows: **1,427**
- Medium-severity rows: **398**
- Low-severity rows: **4,971**

## How to read this report

- One TSV row = one `/* WARNING ... */` occurrence. `detail` is the exact warning text (wrapper and trailing `*/` removed). `warning_address` is the first standalone hex address in that text; register-space forms such as `r0x...`/`s0x...` are skipped.
- For `Function: decomp_fn_<hex> replaced with injection: ...` the warning text has no address, so `warning_address` is the referenced callee entry (`0x<hex>`).
- **high** = control flow is truncated/wrong, or a write/flow is mis-modelled; **medium** = output is degraded (types, stack, partial switch); **low** = informational or usually benign.
- `unreachable_block`, `global_overlap`, `noreturn_call` and `injection` inflate raw counts but rarely need repair; the high-severity tables are the actionable set. The total-count table below is therefore dominated by low-severity unreachable-block removals.
- String literals that merely contain the word `WARNING` (log messages, e.g. in `decomp_fn_10ea1240.c`) were excluded; only decompiler comments were counted.

## Counts by category

| Category | Severity | Occurrences | Functions |
|---|---|---:|---:|
| `global_overlap` | low | 2,142 | 2,142 |
| `unreachable_block` | low | 1,935 | 383 |
| `jumptable_failure` | high | 713 | 682 |
| `indirect_jump_as_call` | high | 706 | 677 |
| `noreturn_call` | low | 569 | 440 |
| `type_propagation` | medium | 318 | 318 |
| `injection` | low | 273 | 271 |
| `spacebase` | medium | 72 | 72 |
| `restart_deadcode` | low | 38 | 38 |
| `inlined` | low | 8 | 8 |
| `jumptable_degraded` | medium | 6 | 4 |
| `readonly_write` | high | 6 | 3 |
| `heritage_dead_removal` | low | 4 | 4 |
| `switch_degraded` | low | 2 | 2 |
| `restart_limit` | high | 2 | 2 |
| `switch_case_unlabeled` | medium | 2 | 1 |
| `halt_baddata` | high | 0 | 0 |
| `decompile_failed` | high | 0 | 0 |
| `blank_body` | high | 0 | 0 |
| **TOTAL** | | **6,796** | **4,156** |

## Top 30 functions by total defect count

| # | Entry | Defects | High | Categories | File |
|---:|---|---:|---:|---|---|
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
| 22 | `10cd92d0` | 14 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10cd92d0.c` |
| 23 | `10fc0a00` | 14 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10fc0a00.c` |
| 24 | `10343770` | 13 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10343770.c` |
| 25 | `10489090` | 13 | 0 | global_overlap, unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10489090.c` |
| 26 | `11208810` | 13 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11208810.c` |
| 27 | `103e76a0` | 12 | 12 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e76a0.c` |
| 28 | `103e96c0` | 12 | 12 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e96c0.c` |
| 29 | `11405fc0` | 12 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11405fc0.c` |
| 30 | `100e7960` | 11 | 0 | unreachable_block | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100e7960.c` |

## Top 30 functions by high-severity defect count

| # | Entry | High | Total | Categories | File |
|---:|---|---:|---:|---|---|
| 1 | `103e76a0` | 12 | 12 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e76a0.c` |
| 2 | `103e96c0` | 12 | 12 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e96c0.c` |
| 3 | `110e26b0` | 6 | 6 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_110e26b0.c` |
| 4 | `11317860` | 4 | 6 | global_overlap, noreturn_call, readonly_write | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11317860.c` |
| 5 | `10193ba0` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10193ba0.c` |
| 6 | `103bce60` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103bce60.c` |
| 7 | `103e7c70` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e7c70.c` |
| 8 | `103ed2a0` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103ed2a0.c` |
| 9 | `107249d0` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_107249d0.c` |
| 10 | `10795f80` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10795f80.c` |
| 11 | `10fc0e70` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10fc0e70.c` |
| 12 | `10ff8e80` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10ff8e80.c` |
| 13 | `110981c0` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_110981c0.c` |
| 14 | `11104fc0` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11104fc0.c` |
| 15 | `114f67c0` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f67c0.c` |
| 16 | `114f6890` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f6890.c` |
| 17 | `114f8d20` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f8d20.c` |
| 18 | `11585530` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11585530.c` |
| 19 | `115b0e90` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_115b0e90.c` |
| 20 | `1161c6a0` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1161c6a0.c` |
| 21 | `1161c780` | 4 | 4 | indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1161c780.c` |
| 22 | `116b8ebc` | 2 | 4 | jumptable_degraded, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_116b8ebc.c` |
| 23 | `116ba4ba` | 2 | 4 | jumptable_degraded, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_116ba4ba.c` |
| 24 | `10453550` | 2 | 3 | global_overlap, indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10453550.c` |
| 25 | `1048d650` | 2 | 3 | global_overlap, indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1048d650.c` |
| 26 | `1048ec20` | 2 | 3 | global_overlap, indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1048ec20.c` |
| 27 | `104d8b60` | 2 | 3 | global_overlap, indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_104d8b60.c` |
| 28 | `1068cea0` | 2 | 3 | global_overlap, indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1068cea0.c` |
| 29 | `109af630` | 2 | 3 | global_overlap, indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_109af630.c` |
| 30 | `10fad940` | 2 | 3 | global_overlap, indirect_jump_as_call, jumptable_failure | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10fad940.c` |

## Prioritized repair list

### P0 - Ghidra switch analysis / manual jump tables

`jumptable_failure`: **713** warnings in **682** functions (706 `Could not recover jumptable ... Too many branches` + 7 `Could not find normalized switch variable`). These are the functions whose bodies are most likely incomplete: the switch table was not recovered, so Ghidra falls through to an indirect call. Repair with Ghidra switch analysis at the reported address; if the table is computed/obfuscated, define it manually and re-decompile.

| # | Entry | Warnings | Warning addresses | File |
|---:|---|---:|---|---|
| 1 | `103e76a0` | 6 | 0x103e7914, 0x103e7967, 0x103e79ba, 0x103e7a0d, 0x103e7a60, 0x103e7aa7 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e76a0.c` |
| 2 | `103e96c0` | 6 | 0x103e99a1, 0x103e99fc, 0x103e9a57, 0x103e9ab2, 0x103e9b0e, 0x103e9b5a | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e96c0.c` |
| 3 | `110e26b0` | 3 | 0x110e26d5, 0x110e26e3, 0x110e26ef | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_110e26b0.c` |
| 4 | `10193ba0` | 2 | 0x10193c17, 0x10193c3c | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10193ba0.c` |
| 5 | `103bce60` | 2 | 0x103bcf15, 0x103bcf43 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103bce60.c` |
| 6 | `103e7c70` | 2 | 0x103e7f87, 0x103e7faa | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e7c70.c` |
| 7 | `103ed2a0` | 2 | 0x103ed2cc, 0x103ed3b9 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103ed2a0.c` |
| 8 | `107249d0` | 2 | 0x10724abc, 0x10724b19 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_107249d0.c` |
| 9 | `10795f80` | 2 | 0x10795fa6, 0x10795faf | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10795f80.c` |
| 10 | `10fc0e70` | 2 | 0x10fc1313, 0x10fc1350 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10fc0e70.c` |
| 11 | `10ff8e80` | 2 | 0x10ff8ec8, 0x10ff8f5f | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10ff8e80.c` |
| 12 | `110981c0` | 2 | 0x110981d4, 0x110981d7 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_110981c0.c` |
| 13 | `11104fc0` | 2 | 0x1110517a, 0x11105186 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11104fc0.c` |
| 14 | `114f67c0` | 2 | 0x114f6807, 0x114f681e | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f67c0.c` |
| 15 | `114f6890` | 2 | 0x114f68d7, 0x114f68ee | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f6890.c` |
| 16 | `114f8d20` | 2 | 0x114f8d61, 0x114f8d71 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f8d20.c` |
| 17 | `11585530` | 2 | 0x11585548, 0x11585567 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11585530.c` |
| 18 | `115b0e90` | 2 | 0x115b0ebb, 0x115b0ecf | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_115b0e90.c` |
| 19 | `1161c6a0` | 2 | 0x1161c6b7, 0x1161c6c7 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1161c6a0.c` |
| 20 | `1161c780` | 2 | 0x1161c797, 0x1161c7a7 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1161c780.c` |
| 21 | `116b8ebc` | 2 | (none) | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_116b8ebc.c` |
| 22 | `116ba4ba` | 2 | (none) | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_116ba4ba.c` |
| 23 | `10453550` | 1 | 0x10453656 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10453550.c` |
| 24 | `1048d650` | 1 | 0x1048d6e7 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1048d650.c` |
| 25 | `1048ec20` | 1 | 0x1048ec8c | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1048ec20.c` |
| 26 | `104d8b60` | 1 | 0x104d8c41 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_104d8b60.c` |
| 27 | `1068cea0` | 1 | 0x1068cfad | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1068cea0.c` |
| 28 | `109af630` | 1 | 0x109af7be | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_109af630.c` |
| 29 | `10a054b0` | 1 | (none) | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10a054b0.c` |
| 30 | `10fad940` | 1 | 0x10fadf94 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10fad940.c` |
| 31 | `1130bd40` | 1 | 0x1130bd4f | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1130bd40.c` |
| 32 | `1130bda0` | 1 | 0x1130bdaf | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1130bda0.c` |
| 33 | `114d9a50` | 1 | 0x114d9a9a | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114d9a50.c` |
| 34 | `1159e240` | 1 | 0x1159e3e1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1159e240.c` |
| 35 | `115aa300` | 1 | 0x115aa32a | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_115aa300.c` |
| 36 | `116c1eb0` | 1 | 0x116c1f5a | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_116c1eb0.c` |
| 37 | `1000218b` | 1 | 0x100021a1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1000218b.c` |
| 38 | `100f3880` | 1 | 0x100f3880 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100f3880.c` |
| 39 | `100f3890` | 1 | 0x100f3890 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100f3890.c` |
| 40 | `10171e70` | 1 | 0x10171e92 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10171e70.c` |
| ... | 642 more functions | | | filter `work/decomp_defects.tsv` |

The remaining 642 functions are in `work/decomp_defects_by_function.tsv` (filter category `jumptable_failure`) and as individual rows in `work/decomp_defects.tsv`.

`Could not find normalized switch variable` (5 functions, no address in the warning) - these need the selector identified manually before the table can be applied:

- `10a054b0` - `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10a054b0.c`
- `10f1f890` - `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10f1f890.c`
- `1130aa70` - `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1130aa70.c`
- `116b8ebc` - `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_116b8ebc.c`
- `116ba4ba` - `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_116ba4ba.c`

### P0b - Degraded switch labeling (table truncated/collapsed, case block unlabeled)

**10** warnings in **7** functions. Verify table bounds and case ranges; these usually accompany a P0 failure.

| Entry | Warnings | Address | Detail | File |
|---|---:|---|---|---|
| `116b8ebc` | 2 | (none) | (jumptable): Sanity check requires truncation of jumptable | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_116b8ebc.c` |
| `116ba4ba` | 2 | (none) | (jumptable): Sanity check requires truncation of jumptable | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_116ba4ba.c` |
| `10a054b0` | 1 | (none) | (jumptable): Sanity check requires truncation of jumptable | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10a054b0.c` |
| `10f1f890` | 1 | (none) | (jumptable): Sanity check requires truncation of jumptable | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10f1f890.c` |
| `10f50c70` | 2 | (none) | This code block may not be properly labeled as switch case | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10f50c70.c` |
| `108071c0` | 1 | 0x10807dda | Switch with 1 destination removed at 0x10807dda | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_108071c0.c` |
| `10a21fb0` | 1 | 0x10a21fcf | Switch with 1 destination removed at 0x10a21fcf : 31 cases all go to same destination | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10a21fb0.c` |

### P1 - Indirect jump treated as call

`indirect_jump_as_call`: **706** warnings in **677** functions. The call truncates the body; recover the jump target and re-decompile. All 677 of these functions also have `jumptable_failure` (706 paired warnings); the 5 remaining jumptable functions have no indirect-call warning (7 warnings, listed under P0).

| # | Entry | Warnings | Paired jumptable addresses | File |
|---:|---|---:|---|---|
| 1 | `103e76a0` | 6 | 0x103e7914, 0x103e7967, 0x103e79ba, 0x103e7a0d, 0x103e7a60, 0x103e7aa7 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e76a0.c` |
| 2 | `103e96c0` | 6 | 0x103e99a1, 0x103e99fc, 0x103e9a57, 0x103e9ab2, 0x103e9b0e, 0x103e9b5a | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e96c0.c` |
| 3 | `110e26b0` | 3 | 0x110e26d5, 0x110e26e3, 0x110e26ef | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_110e26b0.c` |
| 4 | `10193ba0` | 2 | 0x10193c17, 0x10193c3c | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10193ba0.c` |
| 5 | `103bce60` | 2 | 0x103bcf15, 0x103bcf43 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103bce60.c` |
| 6 | `103e7c70` | 2 | 0x103e7f87, 0x103e7faa | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103e7c70.c` |
| 7 | `103ed2a0` | 2 | 0x103ed2cc, 0x103ed3b9 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103ed2a0.c` |
| 8 | `107249d0` | 2 | 0x10724abc, 0x10724b19 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_107249d0.c` |
| 9 | `10795f80` | 2 | 0x10795fa6, 0x10795faf | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10795f80.c` |
| 10 | `10fc0e70` | 2 | 0x10fc1313, 0x10fc1350 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10fc0e70.c` |
| 11 | `10ff8e80` | 2 | 0x10ff8ec8, 0x10ff8f5f | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10ff8e80.c` |
| 12 | `110981c0` | 2 | 0x110981d4, 0x110981d7 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_110981c0.c` |
| 13 | `11104fc0` | 2 | 0x1110517a, 0x11105186 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11104fc0.c` |
| 14 | `114f67c0` | 2 | 0x114f6807, 0x114f681e | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f67c0.c` |
| 15 | `114f6890` | 2 | 0x114f68d7, 0x114f68ee | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f6890.c` |
| 16 | `114f8d20` | 2 | 0x114f8d61, 0x114f8d71 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114f8d20.c` |
| 17 | `11585530` | 2 | 0x11585548, 0x11585567 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11585530.c` |
| 18 | `115b0e90` | 2 | 0x115b0ebb, 0x115b0ecf | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_115b0e90.c` |
| 19 | `1161c6a0` | 2 | 0x1161c6b7, 0x1161c6c7 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1161c6a0.c` |
| 20 | `1161c780` | 2 | 0x1161c797, 0x1161c7a7 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1161c780.c` |
| 21 | `10453550` | 1 | 0x10453656 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10453550.c` |
| 22 | `1048d650` | 1 | 0x1048d6e7 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1048d650.c` |
| 23 | `1048ec20` | 1 | 0x1048ec8c | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1048ec20.c` |
| 24 | `104d8b60` | 1 | 0x104d8c41 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_104d8b60.c` |
| 25 | `1068cea0` | 1 | 0x1068cfad | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1068cea0.c` |
| 26 | `109af630` | 1 | 0x109af7be | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_109af630.c` |
| 27 | `10fad940` | 1 | 0x10fadf94 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10fad940.c` |
| 28 | `1130bd40` | 1 | 0x1130bd4f | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1130bd40.c` |
| 29 | `1130bda0` | 1 | 0x1130bdaf | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1130bda0.c` |
| 30 | `114d9a50` | 1 | 0x114d9a9a | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114d9a50.c` |
| 31 | `1159e240` | 1 | 0x1159e3e1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1159e240.c` |
| 32 | `115aa300` | 1 | 0x115aa32a | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_115aa300.c` |
| 33 | `116c1eb0` | 1 | 0x116c1f5a | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_116c1eb0.c` |
| 34 | `1000218b` | 1 | 0x100021a1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1000218b.c` |
| 35 | `100f3880` | 1 | 0x100f3880 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100f3880.c` |
| 36 | `100f3890` | 1 | 0x100f3890 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100f3890.c` |
| 37 | `10171e70` | 1 | 0x10171e92 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10171e70.c` |
| 38 | `10171ea0` | 1 | 0x10171ebf | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10171ea0.c` |
| 39 | `1017d140` | 1 | 0x1017d166 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1017d140.c` |
| 40 | `1017ec90` | 1 | 0x1017ecab | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1017ec90.c` |
| ... | 637 more functions | | | filter `work/decomp_defects.tsv` |

The remaining 637 functions are in `work/decomp_defects.tsv` (filter category `indirect_jump_as_call`).

### P1 - Restart limit and read-only writes

`restart_limit`: **2** warnings in **2** functions. Raise the restart limit and/or fix types/flow, then re-decompile.

| Entry | Detail | Address | File |
|---|---|---|---|
| `11472bd0` | Exceeded maximum restarts with more pending | - | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11472bd0.c` |
| `10c6afa0` | Exceeded maximum restarts with more pending | - | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10c6afa0.c` |

`readonly_write`: **6** warnings in **3** functions. The same address written repeatedly is a single bad global/pointer type.

| Entry | Detail | Address | File |
|---|---|---|---|
| `11317860` | Read-only address (ram,0x118a0210) is written | 0x118a0210 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11317860.c` |
| `114270b0` | Read-only address (ram,0x118c0860) is written | 0x118c0860 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_114270b0.c` |
| `116a0b30` | Read-only address (ram,0x119135f0) is written | 0x119135f0 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_116a0b30.c` |

### P2 - Type propagation and stack/spacebase fixes

`type_propagation`: **318** warnings in **318** functions. Set concrete pointer/struct types on the conflicting varnodes and re-decompile.

| # | Entry | Warnings | File |
|---:|---|---:|---|
| 1 | `100dbf80` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100dbf80.c` |
| 2 | `10125ba0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10125ba0.c` |
| 3 | `10145fb0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10145fb0.c` |
| 4 | `10165e60` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10165e60.c` |
| 5 | `101661f0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_101661f0.c` |
| 6 | `10166350` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10166350.c` |
| 7 | `1016f0f0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1016f0f0.c` |
| 8 | `10224850` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10224850.c` |
| 9 | `1023c7a0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1023c7a0.c` |
| 10 | `1023cc30` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1023cc30.c` |
| 11 | `10250790` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10250790.c` |
| 12 | `10268750` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10268750.c` |
| 13 | `102765b0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_102765b0.c` |
| 14 | `1028af50` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1028af50.c` |
| 15 | `1028c0c0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1028c0c0.c` |
| 16 | `102b89b0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_102b89b0.c` |
| 17 | `102d3dd0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_102d3dd0.c` |
| 18 | `1030cbf0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1030cbf0.c` |
| 19 | `1030edb0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1030edb0.c` |
| 20 | `10356230` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10356230.c` |
| 21 | `1037dd50` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1037dd50.c` |
| 22 | `10387310` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10387310.c` |
| 23 | `10421750` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10421750.c` |
| 24 | `10423d00` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10423d00.c` |
| 25 | `1044bc90` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1044bc90.c` |
| 26 | `104548c0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_104548c0.c` |
| 27 | `1045adb0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1045adb0.c` |
| 28 | `1045ae40` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1045ae40.c` |
| 29 | `104615f0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_104615f0.c` |
| 30 | `1047ac10` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_1047ac10.c` |

`spacebase`: **72** warnings in **72** functions. Stack frame/spacebase not fully tracked; fix the stack delta or frame pointer.

| # | Entry | Warnings | File |
|---:|---|---:|---|
| 1 | `100fc9a0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100fc9a0.c` |
| 2 | `100fe770` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100fe770.c` |
| 3 | `100fec00` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100fec00.c` |
| 4 | `100ffc50` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ffc50.c` |
| 5 | `100ffd80` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ffd80.c` |
| 6 | `100ffeb0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100ffeb0.c` |
| 7 | `100fffe0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100fffe0.c` |
| 8 | `10101ad0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10101ad0.c` |
| 9 | `10101e30` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10101e30.c` |
| 10 | `101048f0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_101048f0.c` |
| 11 | `101136e0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_101136e0.c` |
| 12 | `101153f0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_101153f0.c` |
| 13 | `10125870` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10125870.c` |
| 14 | `10125ba0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10125ba0.c` |
| 15 | `103a17d0` | 1 | `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_103a17d0.c` |

### P3 - Informational / usually benign (no action unless output looks wrong)

- `unreachable_block`: 1,935 occurrences in 383 functions - dead blocks removed after noreturn/thunk flow; verify only if control flow looks wrong.
- `global_overlap`: 2,142 occurrences in 2,142 functions - data-symbol size overlap; cosmetic unless it causes a bad access.
- `noreturn_call`: 569 occurrences in 440 functions - Ghidra marked a call as noreturn; confirm the annotation.
- `injection`: 273 occurrences in 271 functions - compiler idiom (alloca/SEH/EH) substituted; expected. `warning_address` is the referenced callee entry.
- `restart_deadcode`: 38 occurrences in 38 functions - extra decompiler pass; expected.
- `inlined`: 8 occurrences in 8 functions - Ghidra detected an inlined body; expected.
- `heritage_dead_removal`: 4 occurrences in 4 functions - internal IR heritage note; low impact.

## Suggested repair batches

| Batch | Categories | Warnings | Functions | Action |
|---|---|---:|---:|---|
| A | jumptable_failure, indirect_jump_as_call, jumptable_degraded, switch_case_unlabeled, switch_degraded | 1,429 | 685 | Ghidra switch analysis + manual tables; highest value per fix |
| B | type_propagation, spacebase | 390 | 384 | concrete types and stack deltas |
| C | restart_limit | 2 | 2 | raise restart limit / simplify |
| D | readonly_write | 6 | 3 | fix the global/pointer type at the written address |
| E | informational (P3) | 4,969 | 3,186 | none by default |

## Validation

- `decomp_defects.tsv`: 6,797 lines including header; 7 columns; no malformed rows.
- `decomp_defects_by_function.tsv`: 4,157 lines including header; 3 columns; sum of `defect_count` = 6,796 = defect rows.
- Every `function_entry` matches its `decomp_fn_<entry>.c` filename, the file exists, and the entry exists in `canonical_function_index.tsv`.
- Every non-empty `warning_address` matches `0x[0-9a-f]+`; 3,870 warnings have no address in their text (expected for type/global/noreturn notes).

## Output files

- `work/decomp_defects.tsv` - one row per warning occurrence.
- `work/decomp_defects_by_function.tsv` - per-function counts and category sets.
- `work/decomp_defects_summary.md` - this report.

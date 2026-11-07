# Tier-2 candidate validation

Validated **14,524** candidates from `work/gap_addresses_tier2.tsv` without Ghidra, using only the recorded run metadata, the pre-existing function index, and the raw PE image.

**Key finding:** no candidate is a jump-table case block. Every referencing table is either a wide function-pointer array / vtable (14,067 candidates), a small 1-12 entry array of functions (412), or a lone pointer. The only hard problems are 4 entries that overlap ranges already present in `function_index.txt`.

## Risk

| risk | count | share | meaning |
| --- | ---: | ---: | --- |
| high | 4 | 0.03% | conflicts with a function already in the index |
| medium | 108 | 0.74% | entry boundary unconfirmed, or sits in a narrow ordered table |
| low | 14,412 | 99.23% | entry confirmed by int3 padding or a preceding RET |

## Entry evidence

| signal | count | share |
| --- | ---: | ---: |
| int3 padding before entry | 13,335 | 91.8% |
| no padding | 1,189 | 8.2% |
| preceded by RET (no padding) | 1,083 | 7.5% |
| starts right after a JMP, no padding | 106 | 0.7% |
| run ends in RET | 13,312 | 91.7% |
| run ends in JMP | 1,212 | 8.3% |

### Prologue shape (decoded from `first_bytes`)

| shape | bucket | count |
| --- | --- | ---: |
| `push_reg` | register_save | 2,234 |
| `push_imm32` | arg_push | 2,192 |
| `mov_reg_esp` | thiscall_leaf | 1,904 |
| `mov_reg_mem` | thiscall_leaf | 1,449 |
| `mov_reg_imm32` | imm_return | 1,409 |
| `sub_esp_imm8` | stack_alloc | 840 |
| `mov_eax_mem` | global_load | 692 |
| `mov_mem_imm` | store_first | 492 |
| `cmp_mem` | compare_first | 478 |
| `sub_esp_imm32` | stack_alloc | 444 |
| `push_imm8` | arg_push | 411 |
| `fs_tls_load` | global_load | 392 |
| `sse_load` | sse_load | 241 |
| `test_mem` | compare_first | 236 |
| `push_mem` | arg_push | 173 |
| `sub_reg_imm` | thunk | 166 |
| `lea` | address_first | 131 |
| `mov_reg_global` | global_load | 109 |
| `fpu_load` | fpu_load | 93 |
| `mov_reg8_mem` | thiscall_leaf | 86 |
| `mov_reg_reg` | thiscall_leaf | 83 |
| `call_rel32` | call_first | 83 |
| `sub_mem` | arith_first | 61 |
| `arith_reg_imm` | arith_first | 48 |
| `xor_reg` | zero_first | 31 |
| `imul` | arith_first | 29 |
| `add_mem` | arith_first | 12 |
| `incdec_mem` | arith_first | 2 |
| `jmp_rel32` | tail_jump | 1 |
| `hotpatch_mov_edi_edi` | hotpatch | 1 |
| `call_iat` | call_first | 1 |

| bucket | count |
| --- | ---: |
| thiscall_leaf | 3,522 |
| arg_push | 2,776 |
| register_save | 2,234 |
| imm_return | 1,409 |
| stack_alloc | 1,284 |
| global_load | 1,193 |
| compare_first | 714 |
| store_first | 492 |
| sse_load | 241 |
| thunk | 166 |
| arith_first | 152 |
| address_first | 131 |
| fpu_load | 93 |
| call_first | 84 |
| zero_first | 31 |
| tail_jump | 1 |
| hotpatch | 1 |

## Pointer tables

`work/tier2_tables.tsv` records **114,517** contiguous pointer runs (source dwords 4 bytes apart, same section). 7,379 have more than one entry.

- 109,712 runs have `target_span < 0x1000` (the literal `likely_switch` flag), but 107,138 of those are single-entry runs where the flag is vacuous. Only 2,574 are multi-entry narrow tables.
- 472 runs are narrow, ordered and have >= 4 entries (`switch_candidate`), i.e. plausible jump tables rather than single pointers.

| span of the table a candidate sits in | candidates |
| --- | ---: |
| < 0x1000 (narrow) | 412 |
| 0x1000-0xffff | 45 |
| >= 0x10000 (wide) | 14,067 |

No candidate sits in a table that satisfies the full switch-table shape (>= 8 entries, span < 0x1000, targets ordered by address). The wide tables are function-pointer arrays / vtables, and the narrow ones are 1-12 entry arrays of small functions.

## Highest-risk candidates

All high-risk entries, then medium-risk entries, worst first.

| address | size | first mnemonic | last | prologue | pad | prev | table | entries | span | reason |
| --- | ---: | --- | --- | --- | ---: | --- | --- | ---: | ---: | --- |
| 0x1119f100 | 45 | PUSH | RET | `push_reg` | 4 | RET | 0x1187f3ac | 11 | 0x10c8ba0 | start inside pre-existing FUN_1119f0a0 (0x1119f0a0+159); but 4B int3 pad + preceding RET suggest the index size is over-extended |
| 0x1119f130 | 31 | MOV | RET | `mov_eax_mem` | 3 | RET | 0x1187f17c | 11 | 0x10c8bd0 | start inside pre-existing FUN_1119f0a0 (0x1119f0a0+159); but 3B int3 pad + preceding RET suggest the index size is over-extended |
| 0x11199540 | 19 | MOV | RET | `mov_reg_mem` | 1 | RET | 0x11880254 | 78 | 0x10d2f40 | start inside pre-existing FUN_11199530 (0x11199530+118); but 1B int3 pad + preceding RET suggest the index size is over-extended |
| 0x11199560 | 24 | MOV | RET | `mov_reg_mem` | 13 | RET | 0x11880254 | 78 | 0x10d2f40 | start inside pre-existing FUN_11199530 (0x11199530+118); but 13B int3 pad + preceding RET suggest the index size is over-extended |
| 0x10f38ce0 | 349 | SUB | RET | `sub_esp_imm8` | 0 | RET | 0x11845254 | 5 | 0x5a0 | small ordered pointer table (table 0x11845254 5e span 0x5a0 .rdata) - confirm it is a function-pointer array and not a switch; prologue sub_esp_imm8 |
| 0x10f38e50 | 32 | CMP | RET | `cmp_mem` | 11 | JMP | 0x11845254 | 5 | 0x5a0 | small ordered pointer table (table 0x11845254 5e span 0x5a0 .rdata) - confirm it is a function-pointer array and not a switch; prologue cmp_mem |
| 0x1169c5f0 | 14 | FXCH | RET | `fpu_load` | 0 | JMP | 0x11911d50 | 16 | 0x14d80 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue fpu_load, ends RET; table 0x11911d50 16e span 0x14d80 .rdata |
| 0x116b1280 | 17 | FSTP | RET | `fpu_load` | 0 | JMP | 0x11911d50 | 16 | 0x14d80 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue fpu_load, ends RET; table 0x11911d50 16e span 0x14d80 .rdata |
| 0x116afb15 | 43 | MOV | RET | `mov_mem_imm` | 0 | JMP | 0x11739434 | 7 | 0x39bc5 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue mov_mem_imm, ends RET; table 0x11739434 7e span 0x39bc5 .rdata |
| 0x11676e7d | 12 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x118f958c | 310 | 0x4828f | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x118f958c 310e span 0x4828f .rdata |
| 0x11661aeb | 7 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x118f86d8 | 110 | 0x88a4f | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x118f86d8 110e span 0x88a4f .rdata |
| 0x101d8120 | 72 | SUB | RET | `sub_esp_imm8` | 0 | JMP | 0x117575a4 | 7 | 0x1395d0 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_esp_imm8, ends RET; table 0x117575a4 7e span 0x1395d0 .rdata |
| 0x101d254f | 7 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x11755498 | 68 | 0x151e00 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x11755498 68e span 0x151e00 .rdata |
| 0x102633f2 | 7 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1175e9a4 | 46 | 0x1ea0d0 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1175e9a4 46e span 0x1ea0d0 .rdata |
| 0x10263408 | 7 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1175e878 | 46 | 0x1ea100 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1175e878 46e span 0x1ea100 .rdata |
| 0x1026345a | 7 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1175b458 | 50 | 0x1ea210 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1175b458 50e span 0x1ea210 .rdata |
| 0x10263475 | 7 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1175b250 | 102 | 0x1ea210 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1175b250 102e span 0x1ea210 .rdata |
| 0x1026348b | 18 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1175b250 | 102 | 0x1ea210 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1175b250 102e span 0x1ea210 .rdata |
| 0x102633cf | 20 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1175af54 | 42 | 0x27c8f0 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1175af54 42e span 0x27c8f0 .rdata |
| 0x10265ab0 | 7 | LEA | RET | `lea` | 0 | JMP | 0x1175af54 | 42 | 0x27c8f0 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue lea, ends RET; table 0x1175af54 42e span 0x27c8f0 .rdata |
| 0x1038f3b0 | 6 | MOV | RET | `mov_eax_mem` | 0 | JMP | 0x1176dafc | 35 | 0x29ba90 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue mov_eax_mem, ends RET; table 0x1176dafc 35e span 0x29ba90 .rdata |
| 0x103f1420 | 6188 | SUB | JMP | `sub_esp_imm8` | 0 | JMP | 0x1176f5bc | 340 | 0x31e700 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_esp_imm8, ends JMP; table 0x1176f5bc 340e span 0x31e700 .rdata |
| 0x103f2d50 | 135 | PUSH | RET | `push_reg` | 0 | JMP | 0x1176f5bc | 340 | 0x31e700 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue push_reg, ends RET; table 0x1176f5bc 340e span 0x31e700 .rdata |
| 0x10521aab | 7 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1177fe78 | 47 | 0x474ff0 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1177fe78 47e span 0x474ff0 .rdata |
| 0x10521af5 | 7 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1177fbfc | 46 | 0x498790 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1177fbfc 46e span 0x498790 .rdata |
| 0x102634ac | 18 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1175ef4c | 189 | 0x51ac30 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1175ef4c 189e span 0x51ac30 .rdata |
| 0x105d0e60 | 8 | CMP | RET | `cmp_mem` | 0 | JMP | 0x11786430 | 33 | 0x523960 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue cmp_mem, ends RET; table 0x11786430 33e span 0x523960 .rdata |
| 0x105d0810 | 14 | MOV | RET | `mov_reg_mem` | 0 | JMP | 0x11786a64 | 364 | 0x52c370 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue mov_reg_mem, ends RET; table 0x11786a64 364e span 0x52c370 .rdata |
| 0x102634da | 61 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1175b830 | 483 | 0x52d490 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1175b830 483e span 0x52d490 .rdata |
| 0x10263533 | 58 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1175b830 | 483 | 0x52d490 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1175b830 483e span 0x52d490 .rdata |
| 0x1062db30 | 40 | MOV | JMP | `mov_reg_mem` | 0 | JMP | 0x1178ae8c | 127 | 0x55b760 | matches case-block shape (no padding, follows JMP, no frame prologue, 40B, ends JMP) but the referencing table is wide, which argues for a real function; table 0x1178ae8c 127e span 0x55b760 .rdata |
| 0x1062d9b0 | 7 | MOV | RET | `mov_reg8_mem` | 0 | JMP | 0x1178b74c | 143 | 0x56a8b0 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue mov_reg8_mem, ends RET; table 0x1178b74c 143e span 0x56a8b0 .rdata |
| 0x106620a8 | 74 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x11791d70 | 35 | 0x5af430 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x11791d70 35e span 0x5af430 .rdata |
| 0x106c0d10 | 334 | SUB | RET | `sub_esp_imm8` | 0 | JMP | 0x117931a4 | 72 | 0x639700 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_esp_imm8, ends RET; table 0x117931a4 72e span 0x639700 .rdata |
| 0x106c3f50 | 24 | CMP | RET | `cmp_mem` | 0 | JMP | 0x117931a4 | 72 | 0x639700 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue cmp_mem, ends RET; table 0x117931a4 72e span 0x639700 .rdata |
| 0x107aa9bc | 15 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1179fb28 | 58 | 0x6e4760 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1179fb28 58e span 0x6e4760 .rdata |
| 0x107aa9ef | 26 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1179fb28 | 58 | 0x6e4760 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1179fb28 58e span 0x6e4760 .rdata |
| 0x107aaa18 | 40 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x1179fb28 | 58 | 0x6e4760 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x1179fb28 58e span 0x6e4760 .rdata |
| 0x108d06b0 | 533 | SUB | RET | `sub_esp_imm8` | 0 | JMP | 0x117b7e10 | 11 | 0x7fa150 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_esp_imm8, ends RET; table 0x117b7e10 11e span 0x7fa150 .rdata |
| 0x10970328 | 391 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x117bcaa8 | 16 | 0x89a240 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x117bcaa8 16e span 0x89a240 .rdata |
| 0x10971180 | 6 | MOV | RET | `mov_reg_imm32` | 0 | JMP | 0x117bcc4c | 48 | 0x89a880 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue mov_reg_imm32, ends RET; table 0x117bcc4c 48e span 0x89a880 .rdata |
| 0x1098f940 | 450 | SUB | RET | `sub_esp_imm32` | 0 | JMP | 0x117be13c | 21 | 0x8b9040 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_esp_imm32, ends RET; table 0x117be13c 21e span 0x8b9040 .rdata |
| 0x1099e9f4 | 299 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x117be760 | 24 | 0x8cf370 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x117be760 24e span 0x8cf370 .rdata |
| 0x10a3e66b | 12 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x117c6b60 | 90 | 0x9684c0 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x117c6b60 90e span 0x9684c0 .rdata |
| 0x10a7ec73 | 7 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x117c8690 | 21 | 0x9a8800 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x117c8690 21e span 0x9a8800 .rdata |
| 0x10a7f6b3 | 12 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x117c86f8 | 74 | 0x9a93a2 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x117c86f8 74e span 0x9a93a2 .rdata |
| 0x10a81d93 | 7 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x117c89c0 | 39 | 0x9abed0 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x117c89c0 39e span 0x9abed0 .rdata |
| 0x10a82fa0 | 11 | MOV | JMP | `mov_reg_mem` | 0 | JMP | 0x117c8ad4 | 23 | 0x9acb95 | matches case-block shape (no padding, follows JMP, no frame prologue, 11B, ends JMP) but the referencing table is wide, which argues for a real function; table 0x117c8ad4 23e span 0x9acb95 .rdata |
| 0x10ac066e | 18 | SUB | JMP | `sub_reg_imm` | 0 | JMP | 0x117cad70 | 46 | 0x9ea7c6 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue sub_reg_imm, ends JMP; table 0x117cad70 46e span 0x9ea7c6 .rdata |
| 0x10b2bb40 | 15 | PUSH | RET | `push_mem` | 0 | JMP | 0x117ced6c | 14 | 0xa55600 | no int3 padding and previous instruction is JMP, so the entry boundary is unconfirmed; prologue push_mem, ends RET; table 0x117ced6c 14e span 0xa55600 .rdata |

## Recommendation

Recover in three passes, largest-confidence first:

1. **Core set - 11,254 candidates.** Low risk, at least 2 bytes of `int3` padding before the entry, the run ends in RET, and the referencing table is wide (>= 0x1000 span, i.e. a function pointer array rather than a switch). This is the subset with the strongest independent evidence on every axis; recover it first.
2. **Remaining low risk - 3,158 candidates.** Same evidence but weaker on one axis (1 byte of padding, ends in JMP, or a narrow table). Recover after pass 1 once a sample decompiles cleanly.
3. **Review before recovering - 108 medium.** Most start immediately after a JMP with no padding (many are adjustor thunks, `sub ecx, imm; jmp`), 2 sit in a small ordered 5-entry table, and 2 match a case-block shape but are referenced from wide tables. The entry boundary is not independently confirmed, so check a sample by hand before batching them.

Do **not** bulk-recover the 4 high-risk entries: they overlap functions already present in `function_index.txt`. All four are preceded by `int3` padding and by a RET, which suggests the existing index entry is over-extended rather than the candidate being wrong; resolve that conflict explicitly first.

## Method and limitations

- No disassembler is used. Each candidate is checked against the run metadata, `function_index.txt`, the 1,993 accepted gap ranges, and raw bytes read straight from `empire.retail.dll`.
- Entry evidence: `int3`/`nop` padding immediately before the address (detected in the PE image), the terminal instruction of the run, the shape of the first instruction bytes, and the size, order and span of the pointer table that references the address.
- `function_index.txt` sizes are assumed exact. Where padding contradicts an index range the conflict is reported rather than silently resolved.
- Prologue shapes come from byte patterns, not a full x86 decoder; the operand-size (`0x66`) prefix is stripped before classification.
- Risk is a review priority, not a proof of correctness. A `low` rating means no counter-evidence was found, not that the entry is certainly a function.

## Outputs

- `work/tier2_validation.tsv` - per-candidate verdict, sorted by risk then address
- `work/tier2_tables.tsv` - contiguous pointer tables
- `work/tier2_summary.md` - this file

# Recovered function audit (first wave)

Inputs: `work/gap_addresses.tsv` (1993 rows), `work/gap_apply.tsv` (1993 rows), `work/funcid_environment_variables.tsv` (1973 rows), `function_index.txt` (63326 funcs).

Binary: `Total War Rome II/empire.retail.dll`, image base 0x10000000, `.text` 0x10001000-0x1172e4ea.

Method: a pure-stdlib x86-32 length decoder walks each reported body from its start; every body was additionally traversed recursively from its entry so that only reachable instructions count as code. Immediate operands are resolved against the PE sections: `.rdata`/`.data` immediates are read back as NUL-terminated C strings, `.text` immediates are matched against `function_index.txt` and the gap tables, and direct `call` targets are resolved to exports, imports or indexed function names.

## Validation

| check | result |
|---|---|
| recovered functions audited | 1993 |
| body starts exactly at address | 1993 / 1993 |
| body size matches report | 1993 / 1993 |
| body ends with RET/JMP/noreturn | 1993 / 1993 |
| no overlap with indexed body | 1993 / 1993 |
| no duplicate/overlapping recovered ranges | 1993 / 1993 |
| fully decoded (no decode failure) | 1993 / 1993 |
| **all checks passed (status=ok)** | **1993 / 1993** |

End-mnemonic distribution: RET=1993

Most common direct call targets (structural evidence: every registrar body ends by calling the shared registration helper, then `_atexit` with a per-variable cleanup callback):

| target | bodies |
|---|---|
| _atexit | 1973 |
| FUN_100d1c90 | 1104 |
| FUN_100d1d60 | 585 |
| FUN_100df0d0 | 182 |
| FUN_100d1960 | 58 |
| FUN_100d1bc0 | 24 |
| FUN_107005a0 | 14 |
| FUN_100e8240 | 14 |
| FUN_100d12b0 | 11 |
| FUN_10411ae0 | 6 |

## Name verdicts

- name_supported: 1972
- name_unverified: 20
- name_conflict: 1

Proposed-name variable string found verbatim in body literals: 1972 / 1993

Conflicts (proposed name contradicts the literals in its own body):

- 0x10012730 `env_mbard_register` -- strings=CONTEXT_CAMERA_FAR_PLANE|s:\branches\rome2\curator\common\EmpireBattle\Source\cameras\BattleCameras.cpp; calls=FUN_100d1c90|_atexit; globals=0x11bcf690; coderefs=0x116e45b0; other_identifier:CONTEXT_CAMERA_FAR_PLANE

Unverified rows (no name was proposed for these; they are the 20 `registrar_handler` rows and have no entry in `funcid_environment_variables.tsv`, so there is nothing to verify against):

- 0x100d38b0 size=33 -- calls=FUN_116835d7; no_name_proposed
- 0x100e1470 size=90 -- calls=?FxSDKShutdown@Face@OC3Ent@@YAXXZ|?RemoveListener@FxLog@Logging@Face@OC3Ent@@QAEXPAVFxLogListener@234@@Z|FUN_11683
- 0x100e16f0 size=33 -- calls=FUN_116835d7; no_name_proposed
- 0x100e8410 size=108 -- calls=FUN_100d12b0|FUN_10c95460; globals=0x119f3140; no_name_proposed
- 0x100e8550 size=47 -- calls=FUN_100de850|FUN_100dea70|FUN_100dec90; no_name_proposed
- 0x100e85e0 size=126 -- calls=?Startup@FxEventManager@Face@OC3Ent@@SAXXZ|FUN_100d12b0|FUN_101150a0; globals=0x119f3140; no_name_proposed
- 0x100e8660 size=97 -- calls=?Startup@FxEventManager@Face@OC3Ent@@SAXXZ|FUN_100d12b0|FUN_100d1e30; globals=0x119f3140; no_name_proposed
- 0x100e8760 size=62 -- calls=FUN_100d12b0|FUN_100e877c|FUN_10d48440; globals=0x119f3140; no_name_proposed
- 0x100e8810 size=119 -- calls=?FxAllocate@Face@OC3Ent@@YAPAXI@Z|?SetAudioCallback@FxEventManager@Face@OC3Ent@@SAXABV?$FxFunctor@XUFxEventCallbac
- 0x100e8bb0 size=41 -- strings=Steam and legals; calls=FUN_100f3ba0|FUN_112dcaf0; globals=0x119f3140; no_name_proposed
- 0x100e8be0 size=28 -- calls=FUN_100e8240; no_name_proposed
- 0x100e8c00 size=115 -- calls=FUN_100d12b0|FUN_100e8240|FUN_10f5f5f0; globals=0x119f3140; no_name_proposed
- 0x100e8d40 size=174 -- strings=Finished sound init part 2; calls=??0FxMountUnmountResult@Face@OC3Ent@@QAE@XZ|FUN_100d12b0|FUN_100e8240; globals
- 0x100e8df0 size=32 -- calls=FUN_10caa100; globals=0x119f3140; no_name_proposed
- 0x100e8e10 size=63 -- calls=FUN_10f8c5e0; globals=0x119f3140; no_name_proposed
- 0x100e8e50 size=43 -- strings=Finished VFS load_release; calls=FUN_112dcaf0|FUN_112e3d20; no_name_proposed
- 0x100e9230 size=57 -- strings=VFS started; calls=FUN_112dcaf0|FUN_112e3d20; no_name_proposed
- 0x100e9270 size=68 -- calls=FUN_100d12b0|FUN_10cc3590; globals=0x119f3140; no_name_proposed
- 0x100e9490 size=2985 -- strings=Finished ws_create|UI/FrontEnd UI/LoadingScreen/legal.dds|Finished run_window; api=GDI32.dll!GetStockObject|USER
- 0x100ea040 size=21 -- calls=FUN_100e8240; no_name_proposed

## Failures

None. All 1993 bodies start at the reported address, have the reported size, decode to exactly that size, end in a single-byte `RET` at the last byte, overlap no pre-existing indexed function and overlap no other recovered body.

## Body-start boundaries

padding=1610, after_ret=382, adjacent=1

(`padding` = preceded by 0xCC fill, `after_ret` = preceded by a `RET` byte, `adjacent` = preceded by the last byte of an indexed or recovered function, `unknown` = none of these.)

## SEH / code-pointer handler candidates

`push <imm32>` in a recovered body whose value lands in `.text` and is neither an indexed function nor part of a gap body: **0 push sites, 0 distinct addresses**.

For context, the recovered bodies contain 1975 `push imm32` sites whose immediate lands in `.text`; every one of those immediates is the exact entry address of a function already present in `function_index.txt` (1974 distinct targets), so none survives the `in_index` filter.

All `imm32` operands that land in `.text` (any mnemonic), by classification:

| mnemonic | in_index | in_gap | count |
|---|---|---|---|
| MOV | no | no | 1 |
| MOV | yes | no | 1 |
| PUSH | yes | no | 1975 |

Non-`push` code pointers into `.text` that are not indexed and not in a gap body (missed-function candidates, not SEH push candidates):

- 0x100ed550 via `MOV` at 0x100e9e17 (in 0x100e9490), first bytes `83 ec 6c 53 55 56 57 e8`

No unindexed `.text` push targets were found: every `push imm32` code pointer in the recovered bodies resolves to the exact start of an already-indexed function (typically a per-registrar `atexit`/cleanup callback pushed before a call to a runtime helper). `work/gap_handler_candidates.tsv` therefore contains only its header. The 20 unnamed `registrar_handler` rows are separate recovered functions, not handler pointers discovered inside the registrar bodies.


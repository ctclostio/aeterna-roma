# Code-recovery wave — closing the non-indexed `.text` gaps

Date: 2026-11-03
Scope: `empire.retail.dll`, Ghidra project `workspace/TW2`
Related: `docs/funcid_track3_report.md`, `docs/canonical_export.md`

## Result in one line

The canonical corpus grew from **63,326** to **81,280** internal functions
(**+17,954**), every one of the 11,887 named corpus addresses now resolves to a
canonical function, and all **20** previously missing startup vtable handlers
have decompilations.

The work was split across four DeepSeek V4.1 Flash subagents (decompiler-defect
inventory, indirect-call resolution, wave-1 independent audit, tier-2 candidate
validation) while the Ghidra writer ran the recovery waves serially.  Ghidra
writes were never parallelised: `workspace/TW2` is an exclusive-writer project.

## Why the old 100% was not 100%

`docs/funcid_track3_report.md` documented two separate gaps:

1. **1,973 named `.text` addresses** in `work/funcid_environment_variables.tsv`
   that appeared in neither `function_index.txt` nor the canonical export.  They
   are environment-variable registration wrappers, not SEH prologues as the
   first report guessed; every one begins `push ecx; push 0; push <imm32>` and
   ends in a single-byte `RET`.
2. **20 startup vtable handlers** installed by the `app_init` registrar hub at
   `0x100ea060`, with no function and no decompilation.

The 63,326 / 63,326 figure was 100% of *what Ghidra had chosen to define*, not
100% of executable code.  A second inventory found the gap was much larger:
18,643 contiguous undefined instruction runs covering ~2.1 MB of `.text`, plus
77,344 un-disassembled gaps (mostly `0xCC` padding, but 1,158,757 bytes total).

## What was recovered

| wave | selector | created | evidence |
|---|---|---:|---|
| 1 | 1,973 named environment registrars + 20 registrar handlers | 1,993 | name corpus + `app_init` vtable slots |
| 2 | undefined runs whose start is a `.rdata`/`.data` function-pointer target | 14,524 | 14,412 low-risk, 108 medium, 4 boundary conflicts |
| 3 | residual table-pointer runs missed by the first length filter | 1,384 | `.rdata`/`.data` pointer target, `RET`/`JMP`, real length >= 5 |
| 4 | executable bytes never disassembled | 34 | MSVC prologue, flow-decoded body stays inside gap, ends in `RET`/`JMP` |
| | **total** | **17,935** | |

The canonical export reports 81,280 functions.  The 19-function difference from
`63,326 + 17,935` is the set of project functions the old exporter did not
include (external/thunk entries); they were already present before this wave.

Recovered-function size profile:

| size | count |
|---|---:|
| <= 16 bytes (thunks/leaves) | 5,076 |
| 17–64 bytes | 6,720 |
| 65–256 bytes | 5,152 |
| 257–1,024 bytes | 746 |
| 1,025–8,192 bytes | 234 |
| > 8,192 bytes | 7 |

Address distribution (1 MB bands):

| band | recovered |
|---|---:|
| 0x10000000 | 6,305 |
| 0x10100000 | 686 |
| 0x10200000 | 687 |
| 0x10300000 | 614 |
| 0x10400000 | 236 |
| 0x10500000 | 691 |
| 0x10600000 | 984 |
| 0x10700000 | 183 |
| 0x10800000 | 268 |
| 0x10900000 | 164 |
| 0x10a00000 | 252 |
| 0x10b00000 | 452 |
| 0x10c00000 | 305 |
| 0x10d00000 | 76 |
| 0x10e00000 | 139 |
| 0x10f00000 | 566 |
| 0x11000000 | 633 |
| 0x11100000 | 596 |
| 0x11200000 | 992 |
| 0x11300000 | 261 |
| 0x11400000 | 1,744 |
| 0x11500000 | 849 |
| 0x11600000 | 252 |

The largest recovered functions are `0x10094ec0` (49,538 bytes), `0x10091890`
(13,392), `0x10beefc0` (13,232), `0x10bf4a70` (10,042) and `0x10bf24e0`
(9,598).  `0x10094ec0` required the exporter's 600-second retry path (90 s first
attempt); its 284 KB decompilation is a successful `Export result: success`.
2,165 recovered functions carry a non-default name (the 1,973 environment
registrars plus names that were already in the project).

### Wave 1 — the documented gaps

All 1,993 bodies were independently re-decoded from the PE with a stdlib x86-32
decoder and checked against the Ghidra report:

- body starts exactly at the reported address: 1,993 / 1,993
- body size matches: 1,993 / 1,993
- ends in `RET`: 1,993 / 1,993
- no overlap with an indexed body or another recovered body: 1,993 / 1,993
- 1,972 names supported by the exact variable string in the body
- 1 name conflict: `0x10012730` is labelled `env_mbard_register` but its body
  only references `CONTEXT_CAMERA_FAR_PLANE` (BattleCameras.cpp).  Treat the
  corpus name as wrong; the address is recovered, the name is not.
- 20 registrar-handler rows have no proposed semantic name; they are recovered
  as `FUN_<address>` and decompiled.

The 20 handlers now resolve:

```
0x100d38b0 0x100e1470 0x100e16f0 0x100e8410 0x100e8550 0x100e85e0
0x100e8660 0x100e8760 0x100e8810 0x100e8bb0 0x100e8be0 0x100e8c00
0x100e8d40 0x100e8df0 0x100e8e10 0x100e8e50 0x100e9230 0x100e9270
0x100e9490 0x100ea040
```

### Waves 2–3 — the function-pointer tables

The engine keeps thousands of function pointers in `.rdata` arrays (vtables and
dispatch tables), not only in the 23 `app_init` vtables.  A scan of every
4-byte-aligned data dword found 263,724 values pointing into `.text`; 22,959
unique targets were absent from the old index.  After filtering to undefined
runs that are not inside a function, begin at a standalone run, and end in
`RET`/`JMP`, 14,524 candidates remained.  Independent validation classified
14,412 as low risk (13,335 preceded by `0xCC` padding), 108 medium and 4 high;
the 4 high entries overlap ranges that `function_index.txt` had over-extended,
and Ghidra accepted them as separate bodies without overlap.

A residual 1,384 candidates were recovered after fixing the run-length
calculation: the first pass used the start address of the last instruction
instead of its end address, so 5-byte `JMP rel32` thunks looked like 1-byte runs
and were filtered out.

### Wave 4 — never-disassembled code

`AnalyzeUndisassembled.java` found 77,344 executable gaps.  57,875 are `0xCC`
padding and 17,613 are shorter than 5 bytes.  Of the rest, 34 passed all of:
recognized MSVC prologue, flow-decoded body stays inside the gap, body ends in
`RET`/`JMP`, at least two instructions.  One example is `0x100ed550`
(`83 EC 6C 53 55 56 57 E8 ...`), a real function that Ghidra had never even
disassembled.

## Verification

- `work/recovery_all.tsv` — every recovered body range.
- Zero overlaps among the 17,946 recovered ranges.
- Zero overlaps between recovered ranges and the pre-recovery canonical index.
- `scripts/test_funcid_corpus_integrity.py` now asserts:
  - all 11,887 named addresses resolve to the canonical index (baseline 0);
  - all 20 registrar handlers resolve;
  - the 549-row clobber and address-format guards still hold.

The canonical snapshot is now:

```
format  canonical-address-v2
executable_sha256  d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528
mapping_fingerprint f0caa97fbcb663124542c80eaebc440031e3d65708ec0630678beb77d85a884a
functions  81280
data_symbols 2750
```

Export status: `export_ok`, **81,280 succeeded / 0 failed / 0 skipped**; two
first-pass 90-second timeouts (`0x10094ec0`, `0x114f9210`) both recovered at the
600-second retry, final timeouts 0.  The fresh-process rollback verifier
reports `ok` with 0 function/data/snapshot mismatches and 0 symbol leaks.

`data_symbols` fell from 4,143 to 2,750 because 1,393 labels that were previously
outside any function now sit inside recovered function bodies and are no longer
addressable data symbols.  They are control-flow/jump-table labels, not lost
globals.  Stage the new snapshot with:

```
python scripts/gen_canonical_skeleton.py src_canonical_out/empire.retail.dll \
    --output-root generated/canonical \
    --executable "Total War Rome II/empire.retail.dll"
```

The old `generated/canonical/0a728199...` stage remains immutable for the
pre-recovery x64 bootstrap; the new stage is `f0caa97f...`.

### Downstream re-baseline

The x64 bootstrap configures and builds against the new stage (140/140 build
targets, `empire.retail64.dll` and the test probes link successfully).  Its
provenance CTests still pin the pre-recovery canonical index hash
(`d6f066...`), snapshot hash (`07962b...`), fingerprint (`0a7281...`) and the
resulting built DLL hashes, so they fail until re-baselined.  That is a
deliberate hash lock, not a build failure: the canonical identity changed
legitimately.  Re-baseline those constants together with the new built-DLL
hashes before treating the x64 provenance suite as green.  The code-recovery
acceptance gates (`work/verify_recovery.py`,
`work/check_index_integrity.py`, `scripts/test_funcid_corpus_integrity.py`) are
independent of those pins and pass on the new corpus.

## Indirect calls

`work/indirect_calls_after.tsv` enumerates **59,079** indirect call sites in the
post-recovery project (Ghidra `CALL` instructions that are not direct
addresses).  Only **608** sites now lack a containing function, down from 5,898
before the recovery wave; 5,303 of the previously function-less sites gained a
canonical C body.

| kind | sites |
|---|---:|
| `register_offset` (`call [reg+off]`, virtual dispatch) | 35,370 |
| `register` (`call reg`) | 23,678 |
| `other` | 31 |

Static resolution recovered **2,157 sites (3.65%)** across 1,337 functions and
926 distinct targets, a **+746 (+52.9%)** improvement over the pre-recovery
1,411.  Of the newly contained sites, 747 resolved (all medium confidence).
The vtable map in `work/indirect_call_vtables_after.tsv` covers **9,051
vtables / 121,692 slots** (23 from the registrar hub, 28 from `vftables.txt`,
9,000 recovered from `*obj = &PTR_...` stores in the corpus).

The remaining 56,360 (95.4%) are structurally hard.  The dominant shapes
(first-pass counts, essentially unchanged) are:

- 23,942 (50.8%) virtual calls through a local object pointer whose dynamic
  type is assigned in several branches;
- 9,209 (19.5%) calls through an embedded sub-object (`**(param_N + off)`);
- 4,217 (8.9%) function pointers held in locals/parameters;
- 3,152 + 2,366 plain `this` virtual calls in functions that are not registered
  in any known vtable;
- 1,232 through runtime-initialised BSS pointers.

Resolving these needs cross-function type propagation (class inference from
constructor/vtable stores and parameter flow), not another local scan.  The
resolved subset and the full vtable inventory are checked in so the next pass
starts from evidence rather than re-deriving it.  Full details:
`work/indirect_call_summary_after.md`.

## Decompiler-output defects

A scan of all 63,326 pre-wave C files found **6,796 warning comments in 4,156
functions**; zero export failures, zero timeouts, zero `halt_baddata()` calls
and zero blank bodies.  After the recovery export, the full 81,280-file corpus
has **zero failed decompilations**, zero `halt_baddata()` calls and zero blank
bodies; the warning census rises because the recovered functions add real
virtual-dispatch code:

| category | pre-wave rows | post-wave rows |
|---|---:|---:|
| `global_overlap` | 2,142 | (not recounted) |
| `unreachable_block` | 1,935 | (not recounted) |
| `jumptable_failure` | 713 | **1,110** |
| `indirect_jump_as_call` | 706 | **1,102** |
| `noreturn_call` | 569 | (not recounted) |
| `type_propagation` | 318 | **331** |
| `injection` | 273 | (not recounted) |
| `spacebase` | 72 | (not recounted) |
| `readonly_write` | 6 | **6** |
| `restart_limit` | 2 | **2** |
| `switch_case_unlabeled` | 2 | **2** |
| `halt_baddata` / `decompile_failed` / `blank_body` | 0 | **0** |

The 1,110 post-wave `jumptable_failure` warnings are **not** 1,110 switch
tables.  Inspecting the instruction at each reported address gives:

| instruction shape | post-wave count | reading |
|---|---:|---|
| `JMP dword ptr [reg + off]` | 661 | virtual tail dispatch; resolve the vtable slot |
| `JMP dword ptr [abs]` | 224 | IAT/import thunk; benign |
| `JMP reg` | 159 | computed tail call; dynamic target |
| `JMP dword ptr [reg*4 + table]` | 21 | **true switch table** |
| `JMP dword ptr [reg]` | 21 | virtual slot 0 |

The true switch-table failures are **29 warnings in 16 functions**: the 21
addressed `JMP [reg*4 + table]` warnings in 10 functions (`103e76a0`,
`103e7c70`, `103e96c0`, `10445310`, `104c1fb0`, `1068cea0`, `107ca950`,
`10fbb5e0`, `10fe9050`, `11299e70`) plus 8 no-address
`Could not find normalized switch variable` warnings in 6 more functions
(`10a054b0`, `10f1f890`, `1130aa70`, `114b7d80`, `116b8ebc`, `116ba4ba`).
The no-address cases still contain real code jump tables (26 table sites); the
decompiler emitted a `switch` over a data table instead of recovering the
selector.  The extra 397 warnings are virtual dispatch in the newly recovered
functions, not new switch tables.  The addressed tables are absolute address
arrays in `.text`/`.rdata` (8-24 entries per table).  Extending the function
body with the case blocks and adding `COMPUTED_JUMP` references did not clear
the decompiler's `Too many branches` warning on `0x103e76a0`; the decompiler
still refuses to normalize the switch variable.  These 16 functions are a known
manual-repair worklist, not a bulk-export failure.  The exact jump address,
table address, entry count and case targets for the addressed cases are in
`work/switch_table_repairs.tsv`; the combined worklist, including the six
selector-normalization functions, is `work/switch_table_repairs_after.tsv`
(27 rows, 16 functions).  The other 1,081 warnings are virtual/IAT dispatch and
are addressed by the indirect-call work, not by switch analysis.

## Artifacts

New scripts:

| script | purpose |
|---|---|
| `scripts/RecoverGapFunctions.java` | create functions from an address list; inspect/apply/apply-partial |
| `scripts/RecoverUndisassembledGaps.java` | conservative recovery of never-disassembled prologues |
| `scripts/AnalyzeIndirectCalls.java` | enumerate indirect call sites |
| `scripts/AnalyzeUndefinedCode.java` | inventory undefined instruction runs |
| `scripts/ClassifyUndefinedRuns.java` | classify runs by refs, prev function and terminal |
| `scripts/AnalyzeUndisassembled.java` | inventory never-disassembled executable gaps |
| `scripts/DumpCode.java` | instruction/byte context dump |
| `scripts/CountFunctions.java` | function inventory |
| `scripts/RepairOneSwitch.java` | one-function switch-table repair probe |
| `scripts/ResolveIndirectCalls.java` | symbolic-propagation probe (not productive; see doc) |
| `work/gap_recon.py` | named-address vs index/export reconnaissance |
| `work/build_gap_addresses.py` | build the 1,993-address wave-1 list |
| `work/scan_code_pointers.py` | scan PE data sections for `.text` pointers |
| `work/build_tier2.py` | build the 14,524-address wave-2 list |
| `work/build_tier3.py` | build the 1,384-address wave-3 list |
| `work/consolidate_recovery.py` | consolidate waves and check body overlaps |
| `work/check_index_integrity.py` | canonical index uniqueness/overlap checks |
| `work/recovery_stats.py` | recovered-function size/address-band statistics |
| `work/build_switch_repairs.py` | build the 21-table switch repair worklist |
| `work/build_switch_repairs_after.py` | build the combined 27-row / 16-function worklist |
| `work/scan_recovered_defects.py` | scan only the recovered functions' C files |
| `work/scan_new_corpus_defects.py` | post-export warning census |
| `work/verify_recovery.py` | post-export acceptance gate |

New work artifacts:

| file | contents |
|---|---|
| `work/gap_addresses.tsv` | 1,993 wave-1 addresses |
| `work/gap_apply.tsv` | wave-1 Ghidra report |
| `work/gap_addresses_tier2.tsv` | 14,524 wave-2 candidates |
| `work/gap_tier2_apply.tsv` | wave-2 report |
| `work/gap_addresses_tier3.tsv` | 1,384 wave-3 candidates |
| `work/gap_tier3_apply.tsv` | wave-3 report |
| `work/gap_undisassembled_apply.tsv` | wave-4 report |
| `work/recovery_all.tsv` | consolidated body ranges |
| `work/indirect_calls.tsv` | 59,012 indirect sites (pre-wave) |
| `work/indirect_calls_after.tsv` | 59,079 indirect sites (post-wave) |
| `work/indirect_call_resolutions.tsv` | pre-wave per-site resolution/confidence |
| `work/indirect_call_resolutions_after.tsv` | post-wave per-site resolution/confidence |
| `work/indirect_call_vtables.tsv` | pre-wave 8,851 vtables / 120,941 slots |
| `work/indirect_call_vtables_after.tsv` | post-wave 9,051 vtables / 121,692 slots |
| `work/decomp_defects.tsv` | 6,796 pre-wave warning rows |
| `work/decomp_defects_after.tsv` | 9,856 post-wave warning rows |
| `work/decomp_defects_by_function.tsv` | pre-wave per-function defect counts |
| `work/decomp_defects_by_function_after.tsv` | post-wave per-function defect counts |
| `work/decomp_defects_summary.md` | pre-wave triage and repair batches |
| `work/decomp_defects_summary_after.md` | post-wave triage and switch-table correction |
| `work/switch_table_repairs.tsv` | 21 addressed switch tables |
| `work/switch_table_repairs_after.tsv` | 27 rows / 16 functions, including selector-normalization cases |
| `work/gap_recovered_audit.tsv` | wave-1 independent validation |
| `work/tier2_validation.tsv` | wave-2 risk classification |
| `work/tier2_tables.tsv` | 114,517 pointer-table runs |

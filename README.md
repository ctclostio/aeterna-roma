# Total War: ROME II — 32→64-bit Decompilation Project

[![Tests](https://github.com/ctclostio/aeterna-roma/actions/workflows/ci.yml/badge.svg)](https://github.com/ctclostio/aeterna-roma/actions/workflows/ci.yml)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](LICENSE)

Long-horizon effort to decompile Total War: Rome II (2013) so the game can be
recompiled as a native 64-bit executable.

Public checkout testing and SonarQube Cloud setup are documented in
[continuous integration](docs/continuous_integration.md). The public workflows
build and test reconstructed native components and source tools without the
original game or private analysis exports. This remains a work in progress.

The current recovery checklist is [progress.md](progress.md). Its latest milestone
adds [unit-card resource and XML-node setup](docs/unitcard_resource_recovery.md),
including clear-before-load order, direct-node decoding, allocation-failure
checks and installed-asset comparisons.

## License

Project-authored software is released under the [Unlicense](LICENSE): anyone
may use, modify, redistribute, or sell it for any purpose, without an
attribution requirement. Contributions are accepted under the same terms.
This dedication applies to rights held by the contributors; it grants no
rights to Creative Assembly/SEGA's original game, assets, trademarks, or
third-party components. Game-based analysis still requires your own copy.

## Target binaries (in `Total War Rome II/`)

| File | Role | Arch | Size |
|---|---|---|---|
| `empire.retail.dll` | **The entire game engine** (loaded by the exe) | x86 PE32, base 0x10000000 | 28 MB |
| `Rome2.exe` | Thin launcher: WOW64 check, registry, spawns game process | x86 PE32 | 0.8 MB |
| `data/*.pack` | Game assets (proprietary pack format, not code) | — | many GB |

**Everything that matters is in `empire.retail.dll`.** The launcher is trivial.

## Binary facts

- Built with MSVC (`.msvcjmc` section present → debug-ish retail build with
  JMC metadata; RTTI is ON → class names recoverable from vftables).
- Image base 0x10000000. Sections: `.text` (24 MB), `.rdata`, `.data`, `.msvcjmc`, `_RDATA`, `.rsrc`, `.reloc`.
- **522 named exports** = 463 FaceFX (`OC3Ent::*`), 56 libcurl, `entry_point`,
  and two mod-option exports. See the lossless contract in
  `docs/x64_export_contract.md`; the older PE text dump drops alias names.
- Imports (`pe_meta/empire.retail_imports.json`): D3D9 + D3D11 + OpenGL,
  Steam API, Bink video, OpenSSL (LIBEAY32/SSLEAY32), Twitch SDK, WinMM/DInput8.
- PE/DLL initialization entry RVA 0x16841D0; the launcher-facing `entry_point`
  is ordinal 520 at original VA 0x100EDD70 (RVA 0x0EDD70).

## Toolchain requirements (all local, verified)

These are the **minimum supported versions**. Anything older is not
reproducible against the pinned artifacts in `port/` and `generated/canonical/`.
Versions below are what is currently installed and verified on this machine.

| Component | Required | Verified in use | Notes |
|---|---|---|---|
| Ghidra | **12.1.3** | 12.1.3 | Vendored in-tree at `ghidra_12.1.3_PUBLIC/`. Do not mix with a system Ghidra; the export scripts depend on this layout. |
| JDK | **Eclipse Adoptium OpenJDK 25 LTS** | 25.0.4.1+101 | `C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot`. Ghidra 12.1.3 requires a JDK ≥ 21. |
| Python | **3.15** | 3.15.0 (`C:\Python315`) | Automation, static gates, provenance tests. See the PATH caveat below. |
| MSVC | **Visual Studio Build Tools 2026** | 18.10.12224.181 | x64-only. MSVC toolset 14.51.36231. `/Brepro` + `/WX` builds are hash-locked, so the exact toolset version affects committed hashes. |
| Windows SDK | **10.0.26100.0** | 10.0.26100.0 | Provides the Win32 headers the port targets use. |
| CMake | **4.3.1** | 4.3.1-msvc1 (VS-bundled) | The build scripts resolve CMake from the VS install, *not* from `PATH`. |
| Ninja | **1.13.2** | 1.13.2 | Also resolved from the VS install. |
| Git | **2.50+** | 2.55.0 | Version control and evidence provenance. |
| REA CLI | **6.4.0** | 6.4.0 | `rea` is globally installed via npm and drives the Ghidra provider. |

Project dir: `X:/decompilation`; Ghidra project: `workspace/TW2`.

### Python packaging

**There are no third-party Python dependencies.** Every module under
`scripts/` imports only the standard library (`struct`, `hashlib`, `json`,
`subprocess`, `unittest`, …) plus sibling scripts in the same directory. PE
parsing in `scripts/pe_info.py` is hand-rolled on `struct` rather than
`pefile`, which is deliberate: the export contract depends on exact byte
offsets, and a third-party parser would obscure that.

Consequently there is no `requirements.txt` and none is needed. A
`requirements.txt` pinning the stdlib would be misleading. Adding one is only
correct if and when a real third-party import is introduced — at which point
it must pin exact versions, because several static gates assert on generated
output byte-for-byte.

### Resolving the `python` interpreter

The **persistent** machine `PATH` already lists `C:\Python315\` before
`C:\Python314\`, so in a correctly composed environment `python` resolves to
3.15.0 and `py` agrees:

```bat
python --version   :: Python 3.15.0
py --version       :: Python 3.15.0
```

Two build scripts invoke bare `python` rather than an explicit version:

- `scripts/build_compile_island.bat`
- `scripts/test_compile.bat`

These therefore follow whichever interpreter the launching shell happens to
carry. **A shell started before Python 3.15 was installed can still report
3.14**, because long-lived processes (notably `explorer.exe`, which passes its
own cached environment block to everything it launches) retain a stale `PATH`.
This is an environment-staleness artifact, not a `PATH` misconfiguration — no
`PATH` edit is required. Confirm with:

```bat
where python
```

If the first hit is `C:\Python314\`, restart `explorer.exe` (or sign out and
back in) and start a new terminal rather than editing `PATH`.

The public source/fixture suite runs under both interpreters in CI:

```
py -3.15 scripts/run_public_tests.py
```

The full original-byte suite additionally requires the local game image,
canonical exports, and frozen analysis reports. Its corpus identity pins must
be reviewed after a new export; public CI does not claim those local proofs.
See [continuous integration](docs/continuous_integration.md) for both commands.

### Node.js

Node **24.19.0** / npm **12.0.2** is installed on this machine, but this
project has **no Node dependency**: there is no `package.json`, no lockfile, and
no `.js`/`.ts`/`.mjs`/`.cjs` source anywhere outside the vendored Ghidra
distribution. Node is present only as the runtime that hosts the globally
installed `rea` npm shim (`%APPDATA%\npm\rea.ps1`).

It is therefore *not* a project toolchain requirement, and no `package.json`
should be added just to pin it. Revisit only if a Node-based Ghidra
postScript or a web-based UI is introduced.

### Verified command lines

```bat
:: x64 bootstrap build + CTest (resolves CMake/Ninja from the VS install)
scripts\build_x64_bootstrap.bat

:: full Python gate suite (target interpreter)
py -3.15 -m unittest discover -s scripts -p "test_*.py" -t scripts

:: Ghidra headless analysis
scripts\analyze_dll.bat
scripts\run_headless.bat workspace TW2 -process empire.retail.dll ^
  -postScript ExportAllDecompiled.java X:\decompilation\src_out 0 1000
```

## Pipeline

1. `scripts/validate_rome2.bat` — ✅ DONE: import+analyze+export Rome2.exe
   (584 functions → `src_out/Rome2.exe/decomp/*.c`)
2. `scripts/analyze_dll.bat` — ✅ DONE: full auto-analysis of empire.retail.dll.
   The older batch-export audit still records 35 missing decompilations in
   `work/missing_decomp.txt`; the canonical export is complete.
3. Batch decompile export: `run_headless.bat workspace TW2 -process empire.retail.dll
   -postScript ExportAllDecompiled.java X:\decompilation\src_out <start> <end>`
   (1000 functions per batch; resumable; index at `src_out/empire.retail.dll/function_index.txt`)
4. Type recovery pass: RTTI/vtable-derived class headers into `include/`
5. Symbolic renaming: exports, steam_api thunks, D3D vtables, string-xref-named funcs
6. 64-bit port: pointer-width fixes, calling-convention normalization (__thiscall→x64 RCX),
   re-link against 64-bit deps (steam_api64, d3d9/d3d11, openssl x64)

## Layout

```
X:/decompilation/
├── scripts/        # automation (Ghidra postScripts, batch files, python tools)
├── src_out/        # raw decompiled C per binary (generated)
├── pe_meta/        # PE exports/imports/sections dumps (generated)
├── logs/           # run logs
├── include/        # reconstructed headers (types/classes) [planned]
├── src/            # cleaned, compilable sources [planned]
├── port/           # checked-in x64 bootstrap and hash-locked ABI/evidence data
├── docs/           # architecture notes [planned]
└── workspace/      # Ghidra project (gitignored, large)
```

## Progress tracker

These are separate completion axes and must not be blended into one percentage:

| Axis | Current state | What it means |
| --- | ---: | --- |
| Canonical decompiler export | 81,280 / 81,280 (100%) | Every indexed function has canonical output, and the former non-indexed gaps are closed: all 1,973 named `.text` addresses and all 20 startup registrar handlers now have functions and decompilations. The corpus grew from 63,326 to 81,280 functions (+17,954). See `docs/code_recovery_wave.md`. |
| Function identification | 9,036 / 81,280 (11.1%) | Unique addresses named across all `work/funcid_*.tsv`. |
| Indirect-call resolution | 2,157 / 59,079 (3.65%) | Statically resolved sites across 1,337 functions; 9,051 vtables / 121,692 slots inventoried. The remaining 56,360 sites need cross-function type propagation. See `work/indirect_call_summary_after.md`. |
| Decompiler-warning triage | 9,856 warnings / 6,765 functions | 1,110 jumptable warnings reduce to 29 true switch-table failures in 16 functions (21 addressed + 8 selector-normalization); the rest are virtual/IAT dispatch. Repair worklist: `work/switch_table_repairs_after.tsv`. |
| Current exact x64 milestone | 150 / 150 decision-and-caller bytes (100%) | The frozen selector, conditional registration-data interval, and two caller/continuation windows compose the admitted 400-byte nonempty ordinary-domain parent in a standalone test-only route. |
| Playable/game-equivalent reconstruction | <1% (planning estimate) | No recovered launcher-facing startup, main loop, renderer, campaign, battle, UI, audio, networking, or save system is integrated. |

- [x] Ghidra headless pipeline validated on Rome2.exe
- [x] PE metadata extracted (exports/imports)
- [x] Lossless 522-export ABI lock → `docs/x64_export_contract.md`
- [x] empire.retail.dll auto-analysis and code-gap recovery — all 81,280
  canonical functions exported; see `docs/code_recovery_wave.md`
- [x] Full decompilation export — 81,280 canonical functions
- Historical FuncID snapshot (superseded by the next item): intermediate
  classifications in `work/funcid_solo.tsv` (+ main/todo2). Method + anchor
  table: `work/SOLO_SESSION_SUMMARY.md`; the contemporaneous remaining queue is
  `work/remaining_after_solo1.txt`.
- [~] FuncID pass: **9,036 unique addresses named (14.3%)**. Corpus integrity
  note: `funcid_batch1.tsv`, `v2/v3/v4` and `funcid_solo_batch1.tsv` are
  successive versions of the same 5,398 rows, so naive row sums over-report;
  `funcid_batch1_final.tsv` also mixes `0x`-prefixed and bare-hex addresses
  (13 rows), so count the union of both forms.
  Track 3 registrar wave: 23 vtables → 49 handlers, 4,105 functions reached to
  depth 6, 3,572 still unnamed; callee-cluster propagation is structurally
  starved (only 11.5% of call edges reach a named address, +74 subsystems);
  **~1,993 `.text` addresses have no decompilation at all**
  → `docs/funcid_track3_report.md`, `work/registrar_roots.tsv`,
  `work/registrar_reach.tsv`, `work/registrar_proposed.tsv`
  Output `work/funcid_batch1_final.tsv` (5,452; restored byte-identically from
  `2891a19` after a 549-row duplicate overwrote it)
- [ ] RTTI class recovery → headers
- [ ] Named-symbol propagation (exports, imports thunks)
- [ ] Module identification (engine subsystems: render, AI, battle, campaign, UI…)
  - [x] funcid solo pass #1 (2024-08): 250/250 `work/solo_claim_addrs.txt` classified →
    `work/funcid_solo.tsv` (raw, all parallel runs) + `work/funcid_solo_merged.tsv`
    (1,066 unique addrs deduped last-wins; subsystem mix: core 421, battle 207,
    render 103, anim 73, facefx 54, ui 50). Known anchors: MSVC LCG rand
    (0x343fd+0x269ec3), rad→16-bit angle ×10430.378, anim-id remap switch
    (8→0x5d9 … default 0x7f3), soldier class letters @obj+0x1dd, unit state
    byte @obj+0x1dc / idle short 0x11 @+0x1e2, slot array session+0x68→+0xc0.
- [x] 64-bit build scaffolding (CMake/MSVC x64) → `docs/x64_bootstrap.md`
- [x] Strict canonical compile island (16/16 x64 syntax gate) → `docs/compile_island.md`
- [x] Evidence-only x86 startup initializer inventory (9,874 slots, exact PE
  validation, rollback-safe publication) → `docs/startup_audit_spec.md`
- [x] First isolated pointer-width behavior slice (`0x1093c450` →
  `0x100e81a0`) with a checked guest32 address API and pinned original-byte
  provenance → `docs/guest32_slice.md`
- [x] Static x64 entry-policy selector for original `0x100edd70`, including
  bounded UTF-16LE guest reads, original-byte provenance, adversarial tests,
  and bootstrap-link containment → `docs/x64_entry_policy_selector_spec.md`
- [x] Test-only x64 DLL-boundary probe for that selector (guest addresses stay
  32-bit; no recovered startup execution) →
  `docs/x64_entry_policy_probe.md`
- [x] First bounded post-policy startup leaf (`0x100f1c10`), isolated as a
  `BUILD_TESTING`-only guest32 writer with pinned bytes, static/mutant gates,
  boundary tests, and unchanged bootstrap artifacts →
  `docs/x64_startup_100f1c10_spec.md`
- [x] First native x64 lifecycle composition (`rome2_headless64.exe`), still
  `BUILD_TESTING`-only: entry-policy selection, bounded UTF-16 measurement,
  empty-startup construction, nonowning cleanup, and the bounded initializer
  branches listed below, with gameplay explicitly unlinked
- [x] Deterministic middle slice of platform-heavy `0x100df270`: exact
  post-platform field projection for empty descriptors, with Win32 effects,
  global publication, initializers, and virtual dispatch explicitly excluded
  → `docs/x64_startup_100df270_headless.md`
- [x] Short nonallocating branch of descriptor copy `0x100f2750`: exact
  2-to-30-byte forward copies, external 15-unit ceiling, guest32 alias/range
  containment, and allocation/release/overlap routes explicitly excluded
  → `docs/x64_startup_100f2750_nonalloc.md`
- [x] Bounded no-crash fast path of crash-record `0x100e8240`: read-only
  branch returning the `0x119f3a38` identity, crash-handler/crash-file window
  excluded. The adjacent `0x100ea4d0` body remains separately pinned as the
  original evidence authority; its later executable boundary uses only
  injected allocation and the bounded router
  → `docs/x64_startup_100e8240_fastpath.md`,
  `docs/x64_startup_100ea4d0_evidence.md`
- [x] First state-mutating step past that boundary: allocation-free append
  prefix of `0x100e2460`, with exact two-cell commit ordering, full
  allocator/dispatch/`PeekMessageW` exclusion evidence, and a runnable
  headless guest32 composition. This historical prefix milestone is now
  composed by the completed preallocated branch below
  → `docs/x64_startup_100e2460_append_prefix.md`
- [x] One genuine return path through `0x100e2460`: the complete allocation-free
  unsigned `count < capacity` branch, using total injected dispatch and
  `PeekMessageW`-shaped effects with a finite drain bound. Native USER32 and
  other platform calls and the then-unported allocation routes remain excluded
  from this historical branch milestone
  → `docs/x64_startup_100e2460_preallocated_branch.md`
- [x] Second genuine return path through `0x100e2460`: the complete intended
  `capacity == count == backing == 0` branch. It preserves capacity-before-
  allocation ordering with a total injected `(4, 0)` guest allocator,
  validates the returned guest32 cell, and reuses the bounded dispatch/Peek
  tail. This historical branch is now joined by the growth route below
  → `docs/x64_startup_100e2460_capacity_zero_branch.md`
- [x] Normal full-vector growth path through `0x100e2460`: checked capacity
  doubling, injected guest allocation, ascending copy and append, injected
  release of the old backing, and the bounded dispatch/Peek tail.
  Wrapped/signed resize states and the native stack-slot self-alias subroute
  remain excluded
  → `docs/x64_startup_100e2460_growth_branch.md`
- [x] Unified bounded router over all three admitted `0x100e2460` storage
  paths. A persistent six-insertion composition now follows the original
  zero/growth/growth/preallocated/growth/preallocated route sequence, requests
  pre-provisioned 4/8/16/32-byte guest spans, releases all three superseded
  backings, and retains the six handler identities in order. Native allocation,
  release, and platform effects remain excluded
  → `docs/x64_startup_100e2460_router.md`
- [x] First registered slot-4 handler `0x100e8d00`: authenticated six-call
  sequence represented as a typed injected transcript, with exact argument
  identities/order and AL publication only after the sixth effect
  → `docs/x64_startup_100e8d00_handler_transcript.md`
- [x] Second registered handler `0x100e85d0`: effect-free adapter for the
  authenticated no-op-helper call and `AL=1`, preserving both ignored guest
  identities and excluding native linkage
  → `docs/x64_startup_100e85d0_normal_adapter.md`
- [x] Third registered handler `0x100e8580`: nine-step injected transcript with
  an explicit snapshotted `0x100e8240` result, checked guest32 `+0x68`, and
  exactly-seven-step prefix semantics on null/overflow
  → `docs/x64_startup_100e8580_handler_transcript.md`
- [x] Bounded injected outer composition of `0x100ea4d0`: six total `(4, 0)`
  handler allocations, authenticated vtable stores, unified-router calls,
  accumulated handler-graph audits, and explicit fail-closed statuses in place
  of native allocation and the original null-write trap; finalized checkpoint
  verification is extended through the complete six-handler composition
  → `docs/x64_startup_100ea4d0_injected.md`
- [x] Fourth registered handler `0x100e9340`: four-step injected transcript
  covering two virtual lookup results, receiver-low-byte replacement, and the
  native-singleton/helper suffix without exposing a host pointer
  → `docs/x64_startup_100e9340_handler_transcript.md`
- [x] Fifth registered handler `0x100e92c0`: exact 3/4/6-step predicate routes,
  dependent two-word getter results, and final four-word startup call with all
  Steam and global behavior injected
  → `docs/x64_startup_100e92c0_handler_transcript.md`
- [x] Sixth registered handler `0x100e87a0`: injected listener allocation,
  checked guest32 vtable store, publication, and FaceFX startup with explicit
  prefix-commit failures and a typed memory policy
  → `docs/x64_startup_100e87a0_handler_transcript.md`
- [x] Complete deterministic suffix of `0x100df270`: authenticated receiver
  publication, adjacent direct-call identities, two selector-2 queries,
  mismatch-only four-call route, final marker store, and receiver return as a
  bounded injected transcript
  → `docs/x64_startup_100df270_suffix_transcript.md`
- [x] Complete platform-bound prefix interval of `0x100df270` as a typed
  injected call-shape transcript: exact 7/10-step normal and duplicate routes,
  three ordered guest writes, resource/callee provenance, and fail-closed
  guest32 containment. Native resource, mutex, UI, system-setting, global, and
  termination effects remain deliberately unexecuted
  → `docs/x64_startup_100df270_platform_prefix_transcript.md`
- [x] Empty-input straight-line prefix of launcher-facing parent `0x100ed3c0`:
  exact `0x90c` frame construction, the contiguous bounded `0x100df270`
  prefix/middle/suffix composition, nonowning cleanup, and a hard stop before
  the first parent loop instruction. The completion token is
  `startup-100ed3c0-empty-preloop=injected-composition-complete`
  → `docs/x64_startup_100ed3c0_empty_preloop.md`
- [x] Ordinary-domain lifecycle tail `[0x100ed471,0x100ed550)`: prevalidated
  finite `0* -> 2` poll transcript, checked first slot-`0x54` dispatch,
  injected timestamp and teardown, four ordered nonowning cleanups, exact
  result-last commit, and hard exclusion of the ordinary-unreachable
  result-one list/second indirect route. The completion token is
  `startup-100ed471-ordinary-lifecycle=injected-bounded-complete`
  → `docs/x64_startup_100ed471_ordinary_lifecycle.md`
- [x] Bounded nonempty UTF-16 descriptor lifecycle through
  `0x100f1bb0 -> 0x100ef330` and owning cleanup `0x100f1cc0`: exact
  `2*N+10` allocation grant, all four raw-address alignment residues, hidden
  raw-base metadata, opaque UTF-16 copy, literal-zero terminator, and
  one-shot LIVE/CONSUMED ownership with compensating release for unusable
  grants. This leaf remains a standalone `BUILD_TESTING` target
  → `docs/x64_startup_100f1bb0_owned_utf16.md`
- [x] First-use sentinel-to-owned persistent crash descriptor route in
  `0x100f2750` plus registered one-shot teardown: authenticated temporary
  source ownership, injected allocation/release authority, exact commit order,
  compensating release, and SENTINEL/LIVE/CONSUMED lifecycle. This leaf remains
  a standalone `BUILD_TESTING` target
  → `docs/x64_startup_100f2750_sentinel_owned.md`
- [x] Typed mid-suffix substitution seam at the observed `0x100f2750` call in
  `0x100df270`: snapshotted status-returning delegate, exact
  emit/execute/resume order, three-step committed failure prefix, unchanged
  observation-only API, and expanded 76-case oracle
  → `docs/x64_startup_100df270_suffix_transcript.md`,
  `docs/x64_startup_100ed3c0_nonempty_preloop_spec.md`
- [x] Compose the distinct temporary `0x100f1bb0` owner and persistent
  `0x100f2750` owner into a bounded nonempty `0x100ed3c0` preloop adapter:
  exact parent/child/cleanup order, independent 48-case total-order oracle,
  reciprocal admission gate, and strict `BUILD_TESTING` containment
  → `docs/x64_startup_100ed3c0_nonempty_preloop.md`,
  `docs/x64_startup_100ed3c0_nonempty_preloop_spec.md`
- [x] Whole nonempty ordinary-domain parent `[0x100ed3c0,0x100ed550)`:
  standalone composition of the admitted nonempty preloop and finite ordinary
  lifecycle, private successor preview before external effects, 36-case
  total-order oracle, reciprocal/provenance admission gates, and unchanged
  production binaries under strict `BUILD_TESTING` containment
  → `docs/x64_startup_100ed3c0_nonempty_lifecycle.md`
- [x] Bind that whole parent to the two exact `entry_point` call/continuation
  windows `[0x100edf20,0x100edf41)` and `[0x100edf73,0x100edf94)`, preserving
  all four caller positions, calling the whole parent exactly once, and
  modeling the two post-parent keeper stores plus grouped cleanup as injected
  success-only effects with hard stops before both epilogues. The 54-case
  oracle, reciprocal mutation gate, strict analyzer/ASan runs, two independent
  186/186 graphs, and testing-disabled containment are admitted
  → `docs/x64_startup_100edd70_caller_closure.md`
- [x] Compose the exact selector `[0x100edecc,0x100edf05)`, conditional
  registration-data interval `[0x100edf05,0x100edf20)`, and both admitted
  caller routes into one structural entry decision. The 44-case outer oracle
  re-runs the unchanged 54-case child oracle, pins four inert registration
  records on the install route, embeds the child result, commits result-last,
  and stops before the installed tail, exception gap, and common epilogue.
  Strict analyzer/ASan runs, primary and fresh 192/192 graphs,
  testing-disabled token containment, and unchanged reproducible production
  hashes are admitted
  → `docs/x64_startup_100edd70_entry_decision.md`
- [x] Corrected test-only battle entity field projection (`0x10cbe350`):
  independent origin/vector inputs, authenticated nineteen-word argument map,
  widened vector storage, atomic construction failure, and paired host cleanup
  → `docs/x64_battle_entity_10cbe350.md`. Strings remain borrowed; this does not
  integrate gameplay or reproduce native string ownership.
- [ ] Finish the provisional unit-card external helper and ownership boundary
  → `docs/x64_battle_unitcard_10145c70.md`.
- [ ] Pointer-width port of additional hot code paths

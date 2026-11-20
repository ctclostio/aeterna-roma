# Total War: ROME II — 32→64-bit Decompilation Project

[![Tests](https://github.com/ctclostio/aeterna-roma/actions/workflows/ci.yml/badge.svg)](https://github.com/ctclostio/aeterna-roma/actions/workflows/ci.yml)
[![Status page](https://github.com/ctclostio/aeterna-roma/actions/workflows/status-page.yml/badge.svg)](https://ctclostio.github.io/aeterna-roma/)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](LICENSE)

Long-horizon effort to decompile Total War: Rome II (2013) so the game can be
recompiled as a native 64-bit executable. This remains a work in progress: the
whole engine is decompiled and exported, but only small, test-only slices are
reconstructed and nothing is playable yet.

<a href="https://ctclostio.github.io/aeterna-roma/">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://ctclostio.github.io/aeterna-roma/status-dark.svg">
    <img alt="Decompilation status: completion axes, pinned functions and test gates" src="https://ctclostio.github.io/aeterna-roma/status-light.svg">
  </picture>
</a>

## Status

The [status page](https://ctclostio.github.io/aeterna-roma/) and the card above
are rebuilt from this repository on every push to `main`
(`scripts/gen_status_site.py`). They read the table and open-work list below,
the latest verification counts in [progress.md](progress.md), the pinned counts
in `port/recovered_types/contracts.json` and its Git history, and the next
milestone in `docs/x64_next_milestone_candidates.md`. Update those sources and
the page follows.

These are separate completion axes and must not be blended into one percentage:

| Axis | Current state | What it means |
| --- | ---: | --- |
| Canonical decompiler export | 81,280 / 81,280 (100%) | Every indexed function has canonical output, and the former non-indexed gaps are closed: all 1,973 named `.text` addresses and all 20 startup registrar handlers now have functions and decompilations. The corpus grew from 63,326 to 81,280 functions (+17,954). See `docs/code_recovery_wave.md`. |
| Function identification | 9,036 / 81,280 (11.1%) | Unique addresses named across all `work/funcid_*.tsv`. |
| Indirect-call resolution | 2,157 / 59,079 (3.65%) | Statically resolved sites across 1,337 functions; 9,051 vtables / 121,692 slots inventoried. The remaining 56,360 sites need cross-function type propagation. See `work/indirect_call_summary_after.md`. |
| Decompiler-warning triage | 9,856 warnings / 6,765 functions | 1,110 jumptable warnings reduce to 29 true switch-table failures in 16 functions (21 addressed + 8 selector-normalization); the rest are virtual/IAT dispatch. Repair worklist: `work/switch_table_repairs_after.tsv`. |
| Latest admitted x64 milestone | 150 / 150 decision-and-caller bytes (100%) | The `entry_point` entry decision: the frozen selector, conditional registration-data interval, and two caller/continuation windows compose the admitted 400-byte nonempty ordinary-domain parent in a standalone test-only route. |
| Playable/game-equivalent reconstruction | <1% (planning estimate) | No recovered launcher-facing startup, main loop, renderer, campaign, battle, UI, audio, networking, or save system is integrated. |

Completed work is recorded in [progress.md](progress.md): analysis milestones,
x64 port milestones, and the type-recovery layers.

## Open work

- **Post-validation rewrite:** After decompilation and validation are complete, the
  engine will be rewritten in Rust for memory safety, modern tooling, and long-term
  maintainability. See `docs/rust_rewrite_decision.md`.
- **Next x64 milestone:** not yet frozen. The `entry_point` (`0x100edd70`)
  entry decision is admitted up to the hard stops `0x100edf41` and
  `0x100edf94`. Past them lie the installed tail, exception gap, common
  epilogue, `CoUninitialize`, and SEH restoration. See
  `docs/x64_next_milestone_candidates.md`.
- **Startup type recovery:** close the remaining Partition 6 startup and
  handler roots after Layer 60, then the further engine and export roots.
- **Live execution:** recovered routines run only as bounded, test-only
  transcripts with injected effects. Native Win32 file mapping (`CreateFileA`,
  `MapViewOfFile`), threading, and CRT effects are modelled, not executed.
- **Resource loading:** the rest of the original XML object ABI, exact
  partial-parser and exception outcomes, and full resource-backed constructor
  equivalence.
- **Unit cards:** finish the provisional external helper and ownership boundary
  (`0x10145c70`, `docs/x64_battle_unitcard_10145c70.md`), the remaining
  methods, and the meaning of opaque 32-bit words before widening any of them
  into native pointers or ownership links.
- **Engine classes:** RTTI class recovery into headers, engine and FaceFX
  layouts, complete vtable bounds and callable method signatures, and general
  allocator and threading behaviour.
- **Identification:** name the remaining functions, identify engine modules
  (render, AI, battle, campaign, UI), propagate symbols from exports and import
  thunks, and resolve indirect calls through cross-function type propagation.
- **Startup audit re-admission:** `scripts/gen_startup_audit.py` still pins the
  63,326-function canonical index. Against the current 81,280-function local
  export its local-only tests fail (`initterm_e_int` finds 7 exact joins where
  1 is pinned). Re-pinning needs a reviewed admission, not a hash update.
- **Game integration:** port additional hot code paths to native pointer width
  and integrate the main loop, renderer (D3D9/D3D11), campaign, battle, UI,
  audio, networking, and save system.

## Target binary

| File (in `Total War Rome II/`) | Role | Arch | Size |
|---|---|---|---|
| `empire.retail.dll` | **The entire game engine** (loaded by the exe) | x86 PE32, base 0x10000000 | 28 MB |
| `Rome2.exe` | Thin launcher: WOW64 check, registry, spawns game process | x86 PE32 | 0.8 MB |
| `data/*.pack` | Game assets (proprietary pack format, not code) | — | many GB |

Everything that matters is in `empire.retail.dll`:

- Built with MSVC. The `.msvcjmc` section marks a debug-ish retail build with
  JMC metadata; RTTI is on, so class names are recoverable from vftables.
- Sections: `.text` (24 MB), `.rdata`, `.data`, `.msvcjmc`, `_RDATA`, `.rsrc`, `.reloc`.
- **522 named exports** = 463 FaceFX (`OC3Ent::*`), 56 libcurl, `entry_point`,
  and two mod-option exports. See the lossless contract in
  `docs/x64_export_contract.md`; the older PE text dump drops alias names.
- Imports (`pe_meta/empire.retail_imports.json`): D3D9 + D3D11 + OpenGL,
  Steam API, Bink video, OpenSSL (LIBEAY32/SSLEAY32), Twitch SDK, WinMM/DInput8.
- PE/DLL initialization entry RVA 0x16841D0; the launcher-facing `entry_point`
  is ordinal 520 at original VA 0x100EDD70 (RVA 0x0EDD70).

## Getting started

### Toolchain

These are the **minimum supported versions**. Anything older is not
reproducible against the pinned artifacts in `port/` and `generated/canonical/`.

| Component | Required | Verified in use | Notes |
|---|---|---|---|
| Ghidra | **12.1.3** | 12.1.3 | Vendored in-tree at `ghidra_12.1.3_PUBLIC/`. Do not mix with a system Ghidra; the export scripts depend on this layout. |
| JDK | **Eclipse Adoptium OpenJDK 25 LTS** | 25.0.4.1+101 | `C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot`. Ghidra 12.1.3 requires a JDK ≥ 21. |
| Python | **3.15** | 3.15.0 (`C:\Python315`) | Automation, static gates, provenance tests. CI also runs 3.14. |
| MSVC | **Visual Studio Build Tools 2026** | 18.10.12224.181 | x64-only. MSVC toolset 14.51.36231. `/Brepro` + `/WX` builds are hash-locked, so the exact toolset version affects committed hashes. |
| Windows SDK | **10.0.26100.0** | 10.0.26100.0 | Provides the Win32 headers the port targets use. |
| CMake | **4.3.1** | 4.3.1-msvc1 (VS-bundled) | The build scripts resolve CMake from the VS install, *not* from `PATH`. |
| Ninja | **1.13.2** | 1.13.2 | Also resolved from the VS install. |
| Git | **2.50+** | 2.55.0 | Version control and evidence provenance. |
| REA CLI | **6.4.0** | 6.4.0 | `rea` is globally installed via npm and drives the Ghidra provider. |

Project dir: `X:/decompilation`; Ghidra project: `workspace/TW2`.

There are **no third-party Python or Node dependencies**, so there is no
`requirements.txt` or `package.json`. Every module under `scripts/` uses only
the standard library plus sibling scripts. PE parsing in `scripts/pe_info.py`
is hand-rolled on `struct` on purpose: the export contract depends on exact
byte offsets. If a third-party import is ever added, pin its exact version,
because several static gates assert on generated output byte-for-byte. Node
24 is installed only to host the global `rea` npm shim.

`scripts/build_compile_island.bat` and `scripts/test_compile.bat` call bare
`python`. If `where python` lists `C:\Python314\` first, the shell inherited a
stale `PATH` from a long-lived process such as `explorer.exe`. Restart it (or
sign out and back in) and open a new terminal; do not edit `PATH`.

### Build and test

```bat
:: x64 bootstrap build + CTest (resolves CMake/Ninja from the VS install)
scripts\build_x64_bootstrap.bat

:: public source/fixture suite, as run in CI
py -3.15 scripts/run_public_tests.py

:: full Python gate suite, including local-only original-byte provenance
py -3.15 -m unittest discover -s scripts -p "test_*.py" -t scripts

:: status page, written to out/status-site
py -3.15 scripts/gen_status_site.py

:: Ghidra headless analysis
scripts\analyze_dll.bat
scripts\run_headless.bat workspace TW2 -process empire.retail.dll ^
  -postScript ExportAllDecompiled.java X:\decompilation\src_out 0 1000
```

The full original-byte suite needs the local game image, canonical exports, and
frozen analysis reports, and its corpus identity pins must be reviewed after a
new export. Public CI does not claim those local proofs. See
[continuous integration](docs/continuous_integration.md) for the public
workflows and SonarQube Cloud setup.

## Pipeline

1. `scripts/validate_rome2.bat`: import, analyze and export `Rome2.exe`
   (584 functions → `src_out/Rome2.exe/decomp/*.c`). Done.
2. `scripts/analyze_dll.bat`: full auto-analysis of `empire.retail.dll`. Done;
   the older batch-export audit still lists 35 missing decompilations in
   `work/missing_decomp.txt`, but the canonical export is complete.
3. Batch decompile export with `run_headless.bat … ExportAllDecompiled.java`
   (1,000 functions per batch, resumable, index at
   `src_out/empire.retail.dll/function_index.txt`). Done: 81,280 canonical
   functions.
4. Type recovery: guest32 layouts, contracts and bounded C17 reconstructions in
   `port/recovered_types/`. In progress; see the type-recovery layers in
   [progress.md](progress.md).
5. Symbolic renaming: exports, `steam_api` thunks, D3D vtables, string-xref
   names. In progress (FuncID).
6. 64-bit port: pointer-width fixes, calling-convention normalization
   (`__thiscall` → x64 `RCX`), and relinking against 64-bit dependencies
   (`steam_api64`, D3D9/D3D11, OpenSSL x64). Started with test-only startup
   slices in `port/x64_*`.

## Repository layout

```
X:/decompilation/
├── scripts/        # automation: Ghidra postScripts, batch files, Python tools and gates
├── port/
│   ├── recovered_types/   # guest32 layouts, contracts.json, C17 reconstructions + tests
│   ├── x64_*/             # x64 bootstrap, exports, probe, headless, ported slices, runtime
│   └── startup_audit*/    # startup initializer audit outputs and locks
├── src/            # generated compile-island headers and decompiled-source manifest
├── tests/          # public native CTest and terminal runtime tests
├── docs/           # design notes, specs, and recovery records (see below)
├── site/           # status page template
├── work/           # FuncID tables, analysis reports, worklists
├── pe_meta/        # PE exports/imports/strings dumps
├── src_out/        # raw decompiled C per binary (generated, gitignored)
├── generated/      # canonical export (generated, gitignored)
└── workspace/      # Ghidra project (gitignored, large)
```

## Documentation

- **Progress:** [progress.md](progress.md) (milestones and type-recovery
  layers), [status page](https://ctclostio.github.io/aeterna-roma/).
- **Analysis:** `docs/canonical_export.md`, `docs/code_recovery_wave.md`,
  `docs/engine_architecture.md`, `docs/funcid_report.md`,
  `docs/funcid_track3_report.md`, `docs/process_audit.md`.
- **Type recovery:** `docs/type_recovery.md`, `docs/vfs_recovery.md`,
  `docs/xml_loader_recovery.md`, `docs/unitcard_*_recovery.md`.
- **x64 port:** `docs/x64_bootstrap.md`, `docs/compile_island.md`,
  `docs/guest32_slice.md`, `docs/x64_export_contract.md`,
  `docs/x64_reproducible_build_v2.md`, `docs/startup_audit_spec.md`, the
  `docs/x64_startup_*.md` and `docs/x64_battle_*.md` milestone records, and
  `docs/x64_next_milestone_candidates.md`.
- **Process:** `docs/continuous_integration.md`, `docs/pi_swarm_evaluation.md`.

## License

Project-authored software is released under the [Unlicense](LICENSE): anyone
may use, modify, redistribute, or sell it for any purpose, without an
attribution requirement. Contributions are accepted under the same terms.
This dedication applies to rights held by the contributors; it grants no
rights to Creative Assembly/SEGA's original game, assets, trademarks, or
third-party components. Game-based analysis still requires your own copy.

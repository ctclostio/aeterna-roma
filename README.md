# Total War: ROME II — 32→64-bit Decompilation Project

Long-horizon effort to decompile Total War: Rome II (2013) so the game can be
recompiled as a native 64-bit executable.

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
- **522 named exports** = statically-linked FaceFX middleware (`OC3Ent::Face::*`,
  facial animation SDK by OC3 Entertainment). See `pe_meta/empire.retail_exports.txt`.
- Imports (`pe_meta/empire.retail_imports.json`): D3D9 + D3D11 + OpenGL,
  Steam API, Bink video, OpenSSL (LIBEAY32/SSLEAY32), Twitch SDK, WinMM/DInput8.
- Engine entry point RVA 0x16841D0 (DllEntryPoint).

## Toolchain (all local)

- Ghidra 12.1.3 headless (`ghidra_12.1.3_PUBLIC/`) + JDK 25 (Eclipse Adoptium)
- Python 3.14 for automation; Git for versioning
- MSVC Build Tools 2026 (`cl.exe` Hostx64/x64) — final 64-bit compiler target
- Project dir: `X:/decompilation`; Ghidra project: `workspace/TW2`

## Pipeline

1. `scripts/validate_rome2.bat` — ✅ DONE: import+analyze+export Rome2.exe
   (584 functions → `src_out/Rome2.exe/decomp/*.c`)
2. `scripts/analyze_dll.bat` — 🔄 IN PROGRESS: full auto-analysis of empire.retail.dll
   (detached, log at `logs/dll_run.log`)
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
├── docs/           # architecture notes [planned]
└── workspace/      # Ghidra project (gitignored, large)
```

## Progress tracker

- [x] Ghidra headless pipeline validated on Rome2.exe
- [x] PE metadata extracted (exports/imports)
- [ ] empire.retail.dll auto-analysis (RUNNING — check `logs/dll_run.log`)
- [ ] Full decompilation export (~100k+ funcs expected, batched)
- [ ] RTTI class recovery → headers
- [ ] Named-symbol propagation (exports, imports thunks)
- [ ] Module identification (engine subsystems: render, AI, battle, campaign, UI…)
- [ ] 64-bit build scaffolding (CMake/MSVC x64)
- [ ] Pointer-width port of hot code paths

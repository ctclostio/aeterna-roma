# Empire Engine (Rome II) — Architecture Notes

Derived from: PE metadata, RTTI inventory, 61,329 extracted strings,
and decompiled-code sampling. Binary: `empire.retail.dll` (x86, base 0x10000000).

## Confirmed middleware (statically linked)

| Component | Evidence |
|---|---|
| **FaceFX 2010-era** (OC3 Entertainment) | 522 exports `OC3Ent::Face::Fx*` — facial animation/lip-sync |
| **MSVC CRT + STL** | `_fprintf`, `parse_floating_point<>`, operator news; VS2012/2013-era type archive applied cleanly |
| **Bink Video** (`binkw32.dll` imports) | cutscene playback |
| **OpenSSL** (LIBEAY32/SSLEAY32 imports) | network crypto |
| **Twitch SDK** (`twitchsdk_32_release.dll`) | streaming integration (2013-era feature) |
| **Steamworks** (`steam_api.dll`, 16 imports) | platform layer |
| **Scaleform/Awesomium UI** | `Awesomium.dll` present; `awesomium_process.exe`; "browser_use_local" string |

## Subsystem map (string evidence)

- **Campaign** (4,311 strings): campaign pathfinder cache threads, faction/character/
  settlement/province logic, diplomacy, traits/ancillaries, turn system.
- **Battle** (3,427): unit tooltips, formations, siege, artillery, morale, VO quotes.
- **Render** (~2,711+): D3D9+D3D11+OpenGL backends, shaders/textures/meshes, gfx settings.
- **UI** (983+): porthole/card/radar panels, layout components, Awesomium browser UI.
- **Animation** (861+): FaceFX hooks, skeleton/rig, motion matching era-tech.
- **Audio** (299+): music tracks unlock logic, advisor audio, wavebanks.
- **VFS/Filesystem** (494+): `.pack` archives ("vfs_log_level"), movie/sound packs.
- **Scripting**: Lua (`CLua` strings), event triggers, campaign script hooks.
- **Net**: Steam lobby/matchmaking, VOIP.

## Console-command registry (high-value anchor)

Hundreds of `<command_name> <args>` help strings (e.g.
`number_of_threads_for_campaign_pathfinder_cache <int>`,
`gfx_brightness_setting <float>`). These are registered at startup by their
handler functions → grep decompiled code for a registration loop referencing
these strings to name hundreds of functions across all modules. TODO.

## Key addresses

- DllEntryPoint: `0x116841D0`
- FaceFX export block: `0x100D6560`–… (see pe_meta/empire.retail_exports.txt)
- String data mostly in file-offset range 0x1738000+ (.rdata)

## Recompile-relevant observations

- x86 __thiscall everywhere (ECX this); x64 port normalizes to MS x64 ABI.
- Heavy use of global singletons via .data section (0x1933000+ VA).
- Guard/icall thunk pattern (`guard_check_icall`) = CFG-era toolset? No — that is
  /guard:cf check icall; present even in 2013 builds of some CRTs. Verify per-function.
- Pointer-heavy serialization code (FxArchive::Serialize) will need pointer-width
  abstraction when porting.

## Open questions

- Which parts use SEH vs C++ exceptions (/EHsc)? Check func start flags.
- Are there embedded JIT/bytecode VMs beyond Lua?
- Identify main loop & module init order from entry point call graph.

## RTTI survey (funcid pass, 2026-08-23)

`work/rtti_scan.py` parses the PE directly: 181 MSVC type descriptors exist but
only **15 complete object locators / 14 usable vftables** — all CRT/std
(`std::exception`, `std::locale`, `stdext::bad_alloc`...). The engine itself was
linked essentially `/GR-`; only ~30 CA-namespace types appear as throw/catch
type_info (e.g. `.?AUString@CA@@`). **Vtable→class recovery is NOT a viable
naming strategy for this binary** — classification must rely on strings, API
calls, and callee-cluster propagation.

## Texture conversion family (identified by funcid pass)

`0x10106920–0x1010df10` (~29 funcs): D3DFORMAT-style pixel repacking over an
`__thiscall` image descriptor `{ptr,width,height,stride}` with X/Y-flip flags;
reads go through memmove helper `FUN_116bd8d0`. Conversions include
A8R8G8B8↔A1R5G5B5/A4R4G4B4/R5G6B5, R3G3B2→RGBA8888, L8→565/5551 (gray
replication), RGB→L8 luma (weights 0x96/0x4c/0x1c ≈ ITU-R 601), plus forced-
opaque variants. Named `texconv_*` in `work/funcid_solo.tsv`.

## funcid queue status

`work/funcid_solo_queue.txt` (970 addrs): **970/970 classified** in
`work/funcid_solo.tsv` (multi-proposal; final name reconciliation is a later
pass). Tooling: `work/digest_solo.py` (evidence digests → `solo_digest.jsonl`),
`work/add_rows.py` (dedup append), `work/ox_show.py`/`ox_peek.py` (slice views).

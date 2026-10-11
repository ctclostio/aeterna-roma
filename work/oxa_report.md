# funcid solo run — oxa (2026-08-23 ~20:31–21:00)

**Scope:** 300 functions classified solo, all Ghidra-unnamed (`FUN_*`), none owned by
the 25 shard workers on `batch1_addrs.txt`.

## Outputs

| File | Rows | Contents |
|---|---|---|
| `work/funcid_solo2.tsv` | 150 mine (+ concurrent rows from another analyst — union is dedupe-safe) | slice 1: `0x10002070`–`0x1000ab40` |
| `work/funcid_oxa.tsv` | 300 | slice 2 `0x1000ac20`–`0x1002fa30` + slice 3 `0x1002fd80`–`0x1003f310` |

Claim/resume files: `ox_claim_all.txt` (all remaining unnamed, regenerated), `ox_slice*.txt`.
Format: `<addr>\t<proposed_name>\t<subsystem>\t<evidence>`.

## Key identifications

1. **Logitech G-series LCD SDK (lgLcd)** statically linked at .text start.
   Pinned via registry probe `CLSID {FE750200-B72E-11d9-829B-0050DA1A72D3}\ServerBinary`
   → `GetProcAddress("GetInterface")` — exact match to `lgLcd.lib` (verified against mpc-hc sources).
   Includes a full **delay-load discovery suite**: setupapi device-interface enum,
   service-config search (`OpenSCManagerW/OpenServiceW/QueryServiceConfigW`),
   driver-store INF resolution (`SetupGetInfDriverStoreLocationW`), secure LoadLibraryExW
   path guard (rejects paths outside Windows/Program Files; `%ProgramW6432%` aware).
2. **NVAPI thunk family**: `nvapi.dll/nvpowerapi.dll` loader + refcounted
   `QueryInterface(<32-bit magic>)` dispatch thunks with profiler begin/end hooks;
   special safe-load path for names starting `nv` when OS build ≥ 14308 (0x37e4).
3. **Engine static-initializer region mapped:**
   - `EnvironmentVariable.cpp` ctors (~85): `envvar_<name>_init` (gfx_/sound_/ui_/camera_/twitch_...)
   - console command registrars (~40): `cmd_<name>_register` with category evidence
   - battle config floats/colours: `ALLIANCE_COLOUR_*`, `ENRAGED_THRESHOLD`, `ENTITY_FIREARC_COLOUR`
   - mount/fauna anim param tables: camel, elephant_adult/baby, peasant, seagull, vulture, whale…
   - vegetation proxy singletons (SHRUB/SMALL_VEG/TREE_PROXY ×~8 instances each)
   - campaign script metadata: ~55 event-arg type ctors + 51 `CCQ_*` command constants
     (`ccq_building_construct_register`, …) — the EmpireCampaign scripting surface
4. **MSVC CRT string helpers**: `wcscpy_s/wcsncpy_s/wcsnlen_s/wcscat_s` HRESULT variants,
   wide strdups, path join/ext/slash helpers (fs subsystem).

## Subsystem distribution (funcid_oxa.tsv)
campaign 129 · unknown 59 · battle 44 · render 35 · anim 18 · core 8 · net 3 · audio 3 · ui 1

## Notes for pipeline
- `funcid_solo2.tsv` is shared with another live analyst (rows interleaved) — merge step must dedupe by addr.
- Remaining unnamed pool after this run: ~55k addresses in `ox_claim_all.txt`; next contiguous
  slice starts at `0x1003f310+`.
- Suggest renaming the lgLcd block (0x10002000–0x10004c00) and nvapi suite as a unit in Ghidra.

# funcid solo run — report (ox)

**Mission:** solo funcid analyst pass over the decompiled `empire.retail.dll` batch queue.
**Queue source:** `work/solo_todo_now.txt` (966 addrs, derived from batch1 `all_shard_addrs.txt` minus already-named).
**Output:** TSV rows appended to `work/funcid_solo2.tsv` (`<addr>\t<name>\t<subsystem>\t<evidence>`), incremental via `work/append_tsv.py`.

## Result

- **55 functions analyzed first-hand this run** (read + classified with code-level evidence).
- Queue fully drained: `ox_pending.txt` = 0; batch1 (1000 addrs) shows **0 unnamed** across the union
  of all worker TSVs; `todo_solo.txt` (5364) also fully covered fleet-wide (parallel workers were
  draining concurrently — my per-batch skip-list re-checked names before each function).
- My rows: 55 unique addrs; shared file contains 348 rows / 316 unique addrs (concurrent workers).

## Tooling added (this run)

- `work/ox_ctx.py` — per-addr evidence bundle: merged digest index + name resolution +
  string-literal line numbers + head/tail preview. (Uniquely named to avoid clobbering
  `solo_ctx.py`, which another process overwrote mid-run.)
- `work/ox_next.py` — next-K unnamed addresses from a pending list, atomically skipping
  anything named in any `*.tsv` (handles concurrent fleet writes).

## Subsystem mix of my 55

battle 26 · core/math 9 · render 6 · middleware-facefx 4 · ui 3 · anim 2 · script 0 · unknown 5

## Notable identifications

| addr | name | evidence hook |
|---|---|---|
| 10138c30 | battle_result_unit_ctor | registers type string `"BATTLE_RESULT_UNIT"` |
| 1015b610 | serialize_army_units_ships | named arrays REINFORCEMENTS/UNITS/SHIPS, recursive stride 0x140 |
| 104a5ad0 / 104467d0 family | anim pose snapshot slerp/interp | quat dot ≤0.993 → fsin slerp; double-buffered 200-stride poses, frac=(tick&0xfff)/4096 |
| 10272df0 / 103ac6e0 etc. | brad angle convention | ×10430.378 (=65536/2π) ROUND→ushort; sincos table @DAT_120351f0 |
| 102de7e0 | spatial_grid_hier_init_insert_all | levels=1<<n, u16 grids, critsec(10000), inserts via tags 0x1000/0x80000 |
| 103529c0 / 10375840 / 1035e8f0 | soldier melee pairing pipeline | dxz²≤2e-4 contact test; 0x70 pair objs; mgr lists +2fc/+300 |
| 103a3280 + 103ac6e0 | threat direction histogram | f32[32] bins, idx=atan2×32/2π |
| 10319670 | explosive charge fuse | OBB collect, detonate thresholds 19-out/0.3/0.8, HUD `"Explosion in : %u"` |

## Caveats

- Ghidra-propagated FaceFX export names (GetNumBones, GetAudioAssetPath…) sometimes land on
  non-FaceFX call sites (bad thunk matching) — treat those names as untrusted in decomp output.
- 4 rows in the shared file reference addrs without decomp files (116a… thunks) — from another worker.
- Concurrent workers were active during this run; dedupe on merge is required (first-writer-wins suggested).

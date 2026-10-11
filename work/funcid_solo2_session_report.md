# funcid solo session report — 2025 session (ox-alpha)

## Mission
Solo funcid pass over the 1000-address shard (`work/all_shard_addrs.txt`) of
empire.retail.dll decompilation.

## Key finding: shard was already covered
On startup I derived "966 pending" from `funcid_main.tsv` alone — **wrong**:
earlier batch runs (`funcid_batch1.tsv` 5398 lines, `funcid_solo.tsv` 3082,
`funcid_main.tsv` 2252, plus ~20 other TSVs) already cover the whole shard.
Unique classified addresses across all `work/funcid*.tsv`: **6182**, which
includes all 1000 shard addresses.

My 62 fresh analyses therefore became an independent verification layer —
they confirm or refine prior labels. Examples of agreement/refinement:

| addr | this session | prior label(s) |
|---|---|---|
| 101ebd00 | obb_point_outside_edge_distance | same (confirmed) |
| 104a5ad0 | anim_pose_slerp_blend | anim_pose_blend_slerp (confirmed) |
| 10351130 | seg_seg_closest_point_params | (new, Ericson classic) |
| 101fbf30 | obstacle_list_hittest_vs_obb | same (confirmed) |

## Deliverables written this session
- `work/funcid_solo2.tsv` — appended 62 verified entries (no 0x prefix).
- `work/funcid_consolidated.tsv` — **deduped master, 6182 addrs**, priority:
  solo2(this run) > master > merged > batch1_final > main > batch1 > rest;
  subsystem labels normalized (cine→render, naval→battle, core-math→core, …).

### Subsystem histogram (normalized)
```
unknown            2254  36%
core               1014  16%
middleware-facefx   611  10%
campaign            571   9%
battle              478   8%
render              447   7%
ui                  224   4%
anim                152   2%
crt                 116   2%
audio               110   2%
ai                   66   1%
net                  52   1%
script               52   1%
fs                   35   1%
```

## Remaining gap
- `unknown` = 2254 (36%). Within the original shard-1000 only **35** are unknown
  (`work/shard_unknown_addrs.txt`). The big unknown mass lies outside this shard.
- 2 of the 35 were classified this session (1017a960 battle_units_spawn_from_list,
  101b5400 battle_ai_pick_withdraw_army); consolidated file updated accordingly.

## Notable identifications this session (high confidence)
- 10351130 seg_seg_closest_point_params (core math, used by 1036af00 frontage)
- 102fdd30 obb4corner point test; 102de7e0 pow2 spatial grid init
- 104467d0/104a5520/102f45f0 family: 4096-frame quantized keyframe samplers
  (12-bit t, dbl-buffered pose arrays) → Rome II anim system fingerprint
- 10430.378 multiplier everywhere = 65536/2π fixed-point angle; 9.58738e-05 its inverse
- 0x343fd/0x269EC3 = MSVC LCG rand seeded per-battle at [mgr+0x4c]
- DAT_120351f0/f4: 65536-entry sin/cos table indexed by ushort angle

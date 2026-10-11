# Funcid solo run report

Queue: `work/funcid_solo_queue.txt` (970 addrs) — **fully covered** (0 remaining).
Output: `work/funcid_solo.tsv` (shared with a concurrent worker; 1,782 lines,
1,765 unique addrs incl. earlier batches; all lines well-formed `<addr>\t<name>\t<subsystem>\t<evidence>`).

## Method
- Digest triage (`work/*.jsonl`: strings/API/callers) -> targeted full reads of decompiled C.
- Every classification backed by code evidence: constants (0x343fd LCG, 10430.378 bin-angle,
  sincos tbl @0x120351f0, dual-buffer 12.4 fixed-point anim sampling), vtables/RTTI names,
  string literals, call-graph anchors.
- Ambiguous functions named structurally and marked honestly; subsystem `unknown` where
  purpose could not be established.

## Notable identifications (this session)
- 0x10169940 render2d_draw_thick_line_quad; 0x102f3b20 render2d_debug_prims_flush
- 0x104a5ad0 anim_pose_blend_slerp + 0x10446c00/79de0 anim_channel_dualbuf_sample family
- 0x1015b610 campaign_army_serialize ("REINFORCEMENTS"/"UNITS"/"SHIPS", tag-based ser API)
- 0x1023c7a0/1023cc30/1023d500 siege threat-vector/cluster/navgraph debug draws
- 0x1030edb0 script_blob_dump_records (id^0x4a545eed hash table, "%d: %S (ver%d)")
- 0x104f6220 ctx = Wwise audio ("Battle_Rain.bnk") -> audio IDs in
  0x10432d20 battle_sound_emitter_ctor / 0x1049600d event state machine
- 0x10222560 battle_flank_attack_point_calc; 0x10183dc0 battle_scatter_entities_from_point
- 0x10278fc0 ui_naval_flag_model_load; 0x1048e460 facefx_clientevent_actor_link_setup

## Subsystem mix (unique addrs)
core 708 | battle 334 | render 141 | anim 98 | campaign 96 | audio 82 |
middleware-facefx 70 | ai 60 | ui 49 | cine 34 | model 22 | script 21 |
physics 12 | replay 10 | naval 8 | net 5 | fs 4 | input 3 | unit 3 | crt 2 | vfx 2

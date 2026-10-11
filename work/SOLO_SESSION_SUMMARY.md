# Funcid Analyst — Solo Session Summary (empire.retail.dll)

## What happened
The 25-worker dispatch (`work/dispatch.log`: "launched 25 workers") produced zero output —
all `funcid_*.tsv` and `worker_*.log` files were empty. This session executed the funcid
mission **solo**: classified functions from `work/remaining_digest.jsonl` (built fresh via
`work/extract_evidence.py` for the 5,364 not-yet-classified addresses of `work/batch1_addrs.txt`)
and appended rows to `work/funcid_solo.tsv`.

## Coverage
- **~4,150 function classifications written this session** (chunks of ~100, digest indices 0–4110).
- **Total classified across all TSVs: 4,761 / 5,398 batch1 addresses**.
- **Remaining queue: `work/remaining_after_solo1.txt` (678 addresses)** — resumable with:
  `python work/show_chunk.py <start> <count>` against `work/remaining_digest.jsonl`
  (digest covers all of batch1; note 35 addresses have MISSING decomp exports,
  logged in `work/missing_decomp.txt`, need a Ghidra re-export pass).

## Output format (unchanged contract)
`addr \t name \t subsystem \t evidence` appended to `work/funcid_solo.tsv`.
Subsystems used: core, middleware-facefx, campaign, ui, battle, render, anim, net,
audio, cine/cine(editor), script, ai, model, naval, unit, physics, vfx, replay, fs,
input, net-curl, net-ssl, script-lua.

## Key anchor identifications (high-value, propagate these)
| addr | id |
|---|---|
| 0x10124e50 | global free() w/ debug hook DAT_119f3eb0 + large-span VirtualFree |
| 0x100fcc80 / 0x100fcc50 / 0x10102f50 | malloc / delete-wrapper / aligned alloc |
| 0x116bd8d0 | memmove (CRT) |
| 0x100f1c80 / 0x100f1850 / 0x100ef2c0 | std::string dtor / ctor(empty sentinel DAT_11af408e) / assign-grow |
| 0x112ae010 | lua_gettable (Lua C API) |
| 0x103751a0 / 0x11364860 / 0x11364920 / 0x1136def0 / 0x101ebd00 | transform / seg-dist family / seg-vs-circle / OBB-outside-edge-dist |
| 0x10680500 | wrapper of OBB edge dist |
| 0x102a7140, 0x1084f180, 0x107274c0, 0x10ca7f20, 0x105946e0 | recurring scene/audio obj ops |
| 0x1014d710 | callback-vector clear (event teardown) |
| 0x10fef3b0 / 0x10fef330 / 0x10fef190 | audio bank manager entry points |
| 0x11683a32 / 0x116839e8 / 0x11683b10 | CRT lock/unlock/lock-B |

## Engine map established (address regions)
- 0x100ef–0x100f7: custom printf/vformat engine (float32/double emitters)
- 0x10106–0x1011f: 50 texture pixel-format converters (+fp16), tex dispatch 0x1011e650
- 0x10123–0x10126: custom page allocator (VirtualAlloc guard dialogs, CPUID topology)
- 0x10135–0x1048b: battle setup parse/serialize (ARMIES, REINFORCEMENTS, VICTORY_CONDITIONS,
  camera_start_position, spawn_conditions, GroupFormations.bin)
- 0x10155–0x1027b: battle setup writers/readers + AI test harness (output_test_ai_build.txt,
  SYNC LOG FOR TICK %d)
- 0x1028–0x1032: nav-graph debug names (im_edge_%d/threat_cluster_%d), siege approach graphs
- 0x103b–0x1047: cinematic-editor tool (cinematic_editor module, camera tracks/keyframes,
  battle_action_camera.txt, battle_cameras.txt, battle_arena_camera.txt parsers)
- 0x1048–0x1057: naval ship model assembly (VariantMeshes, masts, naval flags, hull materials)
- 0x1057–0x106b: FaceFX ingame bridge (LoadActorFromMemory, client events) + campaign startpos
- 0x106b–0x1092: campaign core (startpos.esf, victory missions, region connectivity graph,
  politics actions, trade routes .ptd, missions.txt, CAI BDI pools/interface serialization)
- 0x1093–0x10ac: mission generator giants (CND_/VAR_/GEN_ condition keys; twin 120–242KB parsers),
  CAI world serialize (CAI_WORLD_*), Twitch SDK (TTV_*) init/chat/stream
- 0x10ed–0x10f0: FaceFX SDK internals (FxArchive stores, FxCompiledFaceGraph, FxPhonemeMap,
  curve compression KEY_MERGE_EPSILON, FxMasterBoneList)
- 0x10f1–0x10f48: statically-linked libcurl + OpenSSL (SMTP/LDAP/FTP/SOCKS/Digest) + Lua VM lexer/parser
- 0x10f6f+: game HTTP/JSON web services (Content-Type application/json, region_qos.xml, Steam metrics)
- 0x10fe–0x1101: MP lobby/matchmaking JSON, battle_setup_info.dat, desync_report.txt, Global.bnk set,
  Audio/event_data.dat, UI layout system (.cml), front-end screens
- 0x1102–0x1117: strategy HUD panels (recruitment, politics, diplomacy offers, tech tree,
  public order bar, effect bundles, agent action panel), battle HUD (unit cards, radar, group frames)

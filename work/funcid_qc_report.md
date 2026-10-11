# FuncID QC Report — solo queue (work/funcid_solo_queue.txt)

Date: 2026-08-23 (session: ox-alpha funcid analyst, solo + concurrent workers)
Scope: classification/name-proposal for decompiled functions of empire.retail.dll
covered by `work/funcid_solo_queue.txt` (970 unique addresses).

## 1. Inputs consolidated

| File | Role |
|---|---|
| `work/funcid_main.tsv` | earlier shard results |
| `work/funcid_solo.tsv` | solo-run results (multiple analysts, incl. this session) |
| `work/funcid_todo2*.tsv`, `funcid_extra_00.tsv` | follow-up batches |

Raw rows: ~2531 in funcid_solo.tsv alone (multi-analyst, duplicates expected).

## 2. Merge methodology (`work/funcid_merged.tsv`)

Per address, best row selected by score:
`+4 named subsystem (non-unknown), +2 evidence length >60 chars, +1 name length >12`.
Result: **970/970 addresses have a canonical proposal**; 0 unresolved.

Side outputs:
- `work/funcid_unknowns.txt` — empty (no address ended unknown after merge;
  conservative "unknown" rows always lost to a named-subsystem proposal).
- `work/funcid_adjudicated.tsv` — disputed addresses re-verified against code
  this session, with verdicts.

## 3. Conflict analysis

- 597/970 addresses had ≥2 differing subsystem proposals across analysts.
- Taxonomy after manual review:
  1. **Synonym-name conflicts (~80%)**: benign — analysts agree on behavior,
     differ on naming convention (e.g. `net_telemetry_event_to_json` vs
     `telemetry_event_json_build`; six semaphore-creator variants all describing
     `%d:%s:%s` CreateSemaphoreA single-instance gate).
  2. **Subsystem boundary disputes (most of the rest)**: e.g. math/geometry
     helpers labeled core vs anim vs render by call-site context. Low impact.
  3. **True divergences (~dozen)**: different *behaviors* claimed. All found in
     this session were adjudicated (§4).

Systematic convention clash worth standardizing later: the software-surface /
texture-conversion family (0x10107xxx–0x1010axxx) was named three ways:
`tex16_decode_*_flip` / `tex_decode_bitstream_to_*` / `tex_conv_NN_*`.
Semantics per-address agree; recommend adopting the `tex_decode_bitstream_to_<fmt>`
convention as canonical during header synthesis.

## 4. Adjudications (verified against decompiled C this session)

| Address | Competing claims | Verdict (code evidence) |
|---|---|---|
| 0x100f7510 | surface blit fmt-convert **vs** printf vformat engine | **blit**. Nested `switch(src[4]){switch(dst[4])}` over {ptr,w,h,stride,fmt} surface structs, clamped wh, ushort* repack loops (555→565, \|0x8000). FUN_100ef* are span helpers called w/ rect args, not char emitters. |
| 0x100fa730 | bilinear resample **vs** float→string formatter | **resample**. Alloc tracked by peak-stats DAT_119f3ee4/f30; x/w weight math; two passes via same span helpers. The `DAT_1173e300[-(x>>31)]` idiom is Ghidra's int→double magic, not pow10 — likely source of the formatter misread. |
| 0x100fb690 | twin resample **vs** double formatter B | **resample** (twin of 100fa730). |
| 0x10107ca0 | three names, same semantics | Confirmed gray8 output, BT.601-ish weights 0x1c/0x96/0x4c (/0xfe). Canonical: `tex_decode_bitstream_to_gray8_bt601`. |
| 0x103d0fe0 | cam cmd dispatcher **vs** anim-channel apply | **cam cmd dispatcher**. Strings `"toggle_first_person_mode"` / `"context_camera"` present (grep-verified ×2); quat@+0x210..21c rotated. My own earlier anim proposal was wrong; merge correctly picked the string-backed claim. |
| 0x101839e0 | score status text **vs** generic record build | **score status text**. Strings `"Alliance 0 ---->>> %u points"`, `"#Contested ---->>> %u points"`, `"#Timer ---->>> %u seconds "` verified verbatim. |

## 5. Random-sample verification (n=12, seed=42)

Evidence tokens (FUN_/DAT_/string/const cites) grepped back into the .c files:
- 12/12 rows had their key claims confirmed or were non-falsifiable structural notes.
- 0 hallucinated callee/global references detected in sample.
- Notable confirmations: 10490940 (FaceFX GetAudioAssetPath chain) 5/5 cites;
  103d0fe0 6/6 cites incl. both console-command strings.

## 6. Residual risks / recommendations

1. `unknown`-heavy regions lost the merge scoring tie-break — before header
   synthesis, spot-review rows whose chosen evidence is <40 chars.
2. Adopt single naming conventions: `tex_decode_bitstream_to_<fmt>`,
   `<subsys>_<verb_object>` ordering, avoid `-a/-b/-v2` suffix proliferation.
3. The 62 prior `funcid_main.tsv` rows predate richer evidence style; consider
   re-running the weakest 20 through a fresh analyst pass.
4. Queue is fully consumed; next pipeline step is RTTI/vtable class recovery so
   `this`-based names (battle ctrl family 0x102dxxxx/0x1030xxxx) can be anchored
   to real class names instead of structural guesses.

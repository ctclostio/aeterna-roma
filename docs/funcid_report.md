# Function Identification Report — empire.retail.dll (batch1)

Date: 2025-08-23 (solo funcid analyst pass)
Scope: `work/batch1_addrs.txt` — 5,398 large functions (~9.8 MB decompiled C)
Output: `work/funcid_batch1_final.tsv` — **5,452 entries** (addr \t name \t subsystem \t evidence)

## Results

| Source | Count | Notes |
|---|---|---|
| prior rounds (funcid_main/solo/todo2) | 1,998 | deep-read quality, kept verbatim |
| auto-classification v4 (this pass) | 3,453 | rule engine + token families, spot-validated |
| manual fixes | 1 | |

### Subsystem distribution

    unknown             2135  (mostly opaque: no strings/imports, leaf helpers)
    core                 820
    middleware-facefx    592
    campaign             440
    battle               390
    render               304
    ui                   156
    anim                 109
    crt                   97
    audio                 93
    core-math             68
    ai                    62
    cine                  40
    net                   32
    fs                    27
    script                25
    model                 23
    physics               12
    replay/rest           ~30

## Methodology

1. **Evidence extraction** (`work/fx_extract.py`): parsed every .c file for string
   literals, imports (Ghidra renames import thunks to plain API names), named calls,
   FUN_ callee address lists, vftable references, sizes. FaceFX export callees were
   resolved via crude MSVC demangle (`FxClass::Method`) — Ghidra had already renamed
   them to short names (`Serialize`, `GetNameEntry`, …).
2. **FaceFX SDK bands**: clustered the 375 OC3Ent/Fx export addresses into 5 dense
   address bands; any function whose callee set is ≥70% inside bands∪exports is
   SDK-internal (`facefx_sdk_internal`). 1,764 of all 63k functions live in-band.
3. **Rule engine** (`work/fx_classify.py`): ordered predicates — distinctive-string
   rules FIRST (telemetry JSON, sockets/proxy, zlib literals, FxArchive type errors,
   lua, pack/esf, steam/twitch, audio, render keywords, anim, campaign/battle domain,
   UI, registry/sysinfo, VirtualAlloc allocator, threads, debug), THEN strong
   FaceFX resolved-callee ratio, THEN weak band heuristic (no-strings only).
   Structural fallbacks: <64B thunks, math-intrinsic cluster (`SQRT/fpatan/fsin/
   fcos/ROUND/ABS` ≥3 distinct → `math_*_heavy_compute`), `_atexit` chains → static
   init/dtors.
4. **Token-family layer** (`work/fx_families.py`): remaining unknown-with-strings got
   names from their most distinctive literal; ALLCAPS ID families map to subsystems:
   `CAI_*`→campaign-AI tables, `CND_*`→mission conditions, `CDIR_*`→directives,
   `VAR_OBJECTIVE_*`→objectives, SPRAWL/SLOT→settlement growth, etc.
5. **Validation**: sampled per-category against actual code (battle replay block,
   sun shader w/ `sun_VS`+`g_sun_scale`, steam metrics URL builder, vector-math,
   facefx band membership) — 7/7 confirmed; two names refined manually.
6. **Merge** (`work/fx_merge.py`): prior identifications always override auto ones.

## Notable identifications (this pass)

- `0x10accfe0 / 0x10ac1e10 / 0x10ac7700` — mission **condition table builders**
  (`CND_CAMPAIGN/CND_FACTION/CND_MISSION_*`), ~22.8 KB each, near-identical triplets
- `0x10a71cb0` — **CAI world serialization** (`CAI_WORLD_THEATRES/FACTIONS/REGIONS/
  SETTLEMENTS/TRADE_NODES`…), 13.7 KB
- `0x107e15f0` — battle-script trigger table (`VISIBILITY_TRIGGER/TIME_TRIGGER/
  ATTACK_OF_OPPORTUNITY`…)
- `0x10928400` — political event payload resolution (`political_event_adoption/
  marriage/blackmail`)
- `0x101207a0` + family — zlib inflate (`invalid hash bucket count` literals)
- `0x100feef0` — socket layer error wrapper (winsock)
- `0x113c7310` — sun shader setup (`sun_VS`, `g_sun_scale`, `t_diffuse`)
- `0x10f95930` — steam web/metrics URL builder (`&steamid=`,`&ticket=`,`appid=`)

## Known limitations / next steps

- 2,135 `unknown_opaque`: no strings/imports; need xref-direction data (callers) and
  manual reads. Tool: `python work/fx_cards.py opaque 40` renders review cards.
- Rule-derived names are intentionally conservative; treat `unknown_str_*`,
  `*_via_*`, `*_heavy_compute` as lower confidence than prior deep-read entries.
- Next leverage: apply RTTI class names (`vftables.txt`, 305 classes) once vtable
  assignment xrefs are exported from Ghidra → converts whole classes at once.

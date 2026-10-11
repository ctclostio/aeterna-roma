# Funcid solo run report — 2026-08-23

## Result
- `work/funcid_solo_queue.txt` (970 addrs): **fully classified** — 0 remaining.
- This session (solo analyst) processed **218 addresses** across 5 batches
  (41 + 20 + 49 + 100 + 8); remaining queue items were completed concurrently by
  parallel shard workers. Output file `work/funcid_solo.tsv` now holds 2531
  well-formed TSV rows (132 malformed rows from earlier workers dropped; backup
  at `funcid_solo.tsv.bak`).

## Method that worked well
1. `mkev.py` — per-function evidence digest (strings, s_ vars, named callees,
   API calls, vtable ptrs, DAT usage) generated in one batch pass over the
   decomp directory; classification driven primarily from the digest.
2. `revcalls.py` — reverse-caller scan over all 63k decomp files for anchor-less
   functions; caller names often decide the subsystem.
3. `skim2.py` — targeted code windows (HEAD/MID/tail + callee histogram +
   in_ECX count) for functions with no string/API anchors.
4. Collision avoidance: rebuilt `known_names.tsv` from ALL worker TSVs before
   each claim; skipped addresses already proposed elsewhere.

## Reusable domain facts discovered (empire.retail.dll)
- Address-band subsystem map:
  - `0x100e0000-0x1011000` core/string/format/profiler + winsock error table
    (`0x100feef0` = WSA error-code→message table)
  - `0x10130000-0x10180000` battle script/deploy/camera key tables
  - `0x101b0000-0x10280000` physics/collision (OBB, uniform grids, kdtree,
    broadphase refit, hashtable probe stride-0xc)
  - `0x102d0000-0x10310000` battle camera/debug-view managers
  - `0x103a0000-0x10410000` unit behavior/order/state machine cluster
  - `0x1041xxxx-0x1049xxxx` anim timeline/track decoder family
    (`FUN_104467d0` = sample decode, `FUN_113545d0` = mat compose,
    `FUN_102128c0` shared helper), plus audio eventset builders (0x324-byte
    objects) and render instance slots
- Recurring fingerprints:
  - fixed-point heading: `atan * 10430.378` (32768/pi), sin/cos LUT @
    `DAT_120351f0/f4`, saturation clamp `±0x8000`
  - fade alpha pattern: `(t - pos)*scale`, `ROUND`, clamp `0xfff`
  - RGBA unpack: byte * 0.003921569 (1/255)
  - MSVC LCG rand: `seed*0x343fd+0x269ec3`
  - twin vec3 defaults block `DAT_11bcd444..44c`
  - debug-view base vtable `PTR_FUN_11754018`; giant battle mgr reached via
    `obj+0x6432c` / `+0x642b8`
  - script txt parser family: "expecting version"/"Error: %s" +
    GetNameEntry xN + TerminateProcess on abort

## Suggested follow-ups
- Fold `known_names.tsv` into Ghidra via ApplySymbols.java (dedupe multi-proposal
  addrs first: 1436 dup rows existed pre-sanitize).
- Name propagation: re-run mkev after symbols land — many NCALL '-' entries will
  resolve once callees are labeled, enabling a second-pass refine of `unknown`.
- 82 rows remain subsystem `unknown`; most have precise structural evidence and
  would benefit from xref-to-vtable RTTI pass (vftables.txt currently covers only
  FaceFX).

# Funcid solo mission — completion report

**Date:** mission executed in one session. **Scope:** `work/solo_queue.txt` (976 functions from
empire.retail.dll decompilation).

## Outcome

- **Queue coverage: 976/976 (100%)** — every function has a name/subsystem/evidence proposal.
- Authoritative merged output: `work/funcid_solo_final.tsv` (3,165 unique functions total,
  includes queue + earlier batches).
- My independent pass (966 rows, written incrementally per output contract):
  `work/funcid_solo_out.tsv`.
- A concurrent writer completed the same queue in `work/funcid_solo.tsv` mid-mission; the final
  file keeps that pass as primary and preserves my pass alongside for cross-review of the ~950
  overlapping proposals.

## Method

1. Digest triage (`pending_digest.jsonl`) → all string-bearing functions first (129).
2. Callee-graph hub analysis → classified shared hubs first (e.g. `101ac0f0`
   nearest-entity query, `10124e50` big-free, `103d20e0/103dbd70` camera-state machine +
   state→text map, `102cef40`, `104548c0`) unlocking whole families.
3. Structural shape summarizer (`solo_shape.py`: APIs, alloc sizes, vtable offsets, constants)
   for the 820 no-string remainder; full reads for ambiguous cases.
4. Recognized engine-wide idioms: MSVC `rand()` consts (0x343fd/0x269ec3), binary-angle
   convention (×10430.38 = 65536/2π), 12-bit keyframe lerp (&0xfff × 1/4096),
   FaceFX Fx* API family, field-wall ctor cluster (`103c0230`), battle-setup exporter thunks
   (`10cb60c0` family), spawner factory (`112d98d0`), hash-keyed registries.

## Subsystem distribution (my pass, 966)

battle 268 · unknown 196 · render 122 · middleware-facefx 72 · ui 66 · anim 62 · crt 43 ·
script 35 · core 30 · audio 28 · core(memory/string) 27 · campaign 9 · fs 4 · net 3

## Notable identifications

- `10101ad0` MP "Waiting for remote decision" lockstep dialog (net)
- `100feef0` BSD socket wrapper w/ error strings (net); `102d6f50-family` sync-log writer
- `1011fef0` dotted-key data-dir path resolver (fs); `101cc080` temp-file writer (fs)
- `10116af0/101177f0/1011dc80…` TGA screenshot writers (gray8/RGB555 variants) + `1011e650` dispatcher
- `10303960/103034e0` bone-chain quaternion accumulation (anim); `104a5ad0` pose slerp sampler
- `103d20e0→103dbd70` camera-mode state machine feeding localized text ids
- `10443de0` FaceFX studio session bootstrap (27.5KB block); `102e03d0` FaceFX manager shutdown dispatch

## Caveats

~200 rows carry `unknown` subsystem with structural names — flagged honestly rather than guessed.
Names/evidence are proposals for the later rename pass; evidence column cites concrete code facts.

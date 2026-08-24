# FuncID Solo Run Report — 2025-08-23 (batch1)

## Result
- **2190 functions identified** this run (solo, after the 25-worker dispatch produced zero output — all worker logs empty).
- `work/funcid_main.tsv` now holds **2252** classified functions.
- Remaining from batch1: **3174** (queue: `work/todo_solo_remaining.txt`).

## Coverage by subsystem (this run)
| subsystem | count |
|---|---|
| middleware-facefx | 1057 |
| ui | ~300 |
| campaign | ~290 |
| render | ~250 |
| battle | ~120 |
| net | ~100 |
| script | ~60 |
| anim | ~33 |
| crt/core/audio/fs/phys | ~75 |
| unknown | 1 (+decomp failures) |

## Major discoveries
1. **FaceFX statically linked & typed**: 1043 functions carry Ghidra-recovered `OC3Ent::Face::*` calls → bulk-classified. Code region ≈ 0x10145000–0x101f0000 and 0x10eb0000–0x10f20000.
2. **Lua VM embedded**: `0x10f4c0f0` = luaV_execute (`'for' limit must be a number`); lexer/parser errors at 0x10f4e1e0/0x10f4eec0/0x10f51340. Scripting glue at 0x10f74–0x10f8d.
3. **libcurl + OpenSSL static**: ~35 funcs (cookie parser, FTP/HTTP/SMTP/SOCKS/Digest, TLS handshake, X509 dump) around 0x10f10–0x10f45.
4. **GL renderer**: complete family of `wglGetProcAddress` extension loaders (GL1.3→4.x, ARB/NV/ATI/SUN/EXT), plus per-shader registration functions with full HLSL names (rigidterrain.hlsl, weightedcommon.hlsl, MLAA, FFT ocean, HDR pipeline).
5. **CAI world**: property-set builder clones (byte-identical COMDAT pairs) at 0x10ad2940+; BDI pools, TMS task generators, director intentions all mapped via save-block names.
6. **Config parser idiom**: engine uses keyword-compare helper FUN_100f28e0 + expecting-parser family (FUN_102a2xxx-0x102a5xxx); "expecting {"/"Error: %s" strings mark every schema parser.

## Method / tooling (reusable)
- `work/evidence_extract.py <addr_list> <out.jsonl>` — strings/API/callees/allocs per function (~2 min for 5400).
- `work/scan.py|scan2.py|scan3.py|scan4.py <lo> <hi>` — paginated evidence viewer over remaining set (string-rich first).
- `work/peek2.py <lo> <hi>` — big-function view: features + top callees resolved to proposed names.
- `work/append_tsv.py` / `app.sh` — incremental TSV append (write every batch!).
- Output: `work/funcid_solo_batch1.tsv`, merged into canonical `work/funcid_main.tsv`.

## Gotchas for next runs
- Python text-mode writes emit CRLF on Windows → strip `\r` before using addr files as args.
- Filtered lists mutate between scans → always recompute the remaining set inside the scan script (done in scan3/scan4).
- Some .c exports failed ("DECOMPILATION FAILED: timeout") e.g. `0x114f9210`; re-export these individually.
- A few evidence fields contain embedded newlines from mojibake string literals — harmless but keep the 4-column assert.

## Resume plan
1. Process `work/todo_solo_remaining.txt` (3174, sorted by address; ~1485 are >1.2KB).
2. Start with `python work/peek2.py 44 N` chunks; dark functions have no shared callees — read individually.
3. Address-region priors: 0x1013-106b battle · 0x106b-109c campaign · 0x109c-10a2 settlement · 0x10a2-10c6 CAI · 0x10cd-10e3 vfx/scene · 0x110a-1139 UI · 0x1139-1160 render/shaders · 0x116a+ CRT.

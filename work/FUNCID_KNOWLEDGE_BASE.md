# FuncID Knowledge Base — empire.retail.dll (session 2024-08-23)

Analyst session results + reusable reverse-engineering dictionary for future
funcid passes. Canonical merged output: `work/funcid_merged.tsv` (5,879 unique
addresses, deduped across 30+ worker TSVs; conflict policy: analyzed names
beat mechanical fallbacks, longer beats shorter).

## Confirmed hub functions (call-graph anchors)

| Addr | Identity |
|---|---|
| 0x100fcc80 | custom heap **alloc** |
| 0x100fcc50 / 0x10124e50 | custom heap **free** (10124e50 has VirtualFree decommit path) |
| 0x100d12b0 | new-wrapper (alloc + zero) |
| 0x100f1c80 / 0x100f1cc0 | std::string / std::wstring **dtor** |
| 0x100ef2c0 / 0x100ef330 | string assign (char / wchar) into SSO obj |
| 0x100f1800 / 0x100f1bb0 | string assign from cstr / wcstr |
| 0x100f1700 | string copy ctor |
| 0x100f1850 | string assign (wide, variant) |
| 0x100eaf40 | dword vector push_back |
| 0x11683a32 / 116839e8 | TLS magic-static init guard pair |
| 0x116835d7 / 11686175 / 1169c43b | TLS/vtable thunk helpers |
| 0x103c0230 | timeline/curve sampler (time→value) — anim/effect tracks |
| 0x10404b30 | companion sampler (min/max bound of track?) |
| 0x10312d50 | generic evaluator used by track banks |
| 0x102198e0 | sampler tick (render/anim banks) |
| 0x112d98d0 / 0x10103ec0 | audio-ish samplers (bank ticks) |
| 0x10d99350(id) | toggle/option query by small id (cheats/modes) |
| 0x1136e120 | 2D segment intersection |
| 0x1136def0 | segment vs circle |
| 0x101ebd00 | OBB point-vs-outside-edge distance |
| 0x1029fe40 | bounds finalize (AABB accumulate) |
| 0x1135d6f0 / 0x11364920 | vec2 helpers / point-to-segment distance |
| 0x10cb9040 | streambuf read (grows in 0x100000 chunks) — fs pipeline |
| 0x10340480 | keyed setter over stride-0x1c record array (switch on key) |

## Constant cheat-sheet

| Const | Meaning |
|---|---|
| `10430.378` | 65536/(2π) — radians → BAM16 (binary angle) |
| `5215.189` | half of above (rad → signed quarter-BAM) |
| `9.58738e-05`, `4.79369e-05` | BAM16 → float (2π/65536 and half) |
| `0x343fd, 0x269ec3` | MSVC rand() LCG state update |
| `1.5259022e-05` | 1/65535 u16 normalize |
| `9.58738e-05` | BAM→rad |
| `0.003921569` | 1/255 byte→float color |
| `0.00024414062` | 1/4096 quantization |
| `0.007874016` | 1/127 |
| `3276.8 / 6553.6` | 32768/10, /5 — gain scaling |
| `22500.0 / 40000.0 / 160000.0` | squared range thresholds 150², 200², 400² |
| `5000.0 / 1035.0 / 6471.681` | audio distance/gain curve constants |
| denorms `1.4e-45 / 2.8e-45` | float sentinel tags (kind markers), not values |

## Region map discovered

- `0x100ef000–0x10120000`: core utility lib — strings, format (%f/%d),
  profiler dump (`core_profiler_report_dump` @0x100fd1d0), sockets, fs walk,
  tex decode family (bit-reader `FUN_116bd8d0` → 16bpp blitters, flip flag),
  surface blit matrix @0x100f7510.
- `0x10120000–0x1048000`: gameplay/sim mixed block (units, formations,
  steering, AI goals, spline paths, spatial hash).
- `0x10480000+`: battle render/audio banks, variant mesh defs, soldier visuals.

## Process notes

- Queue `work/solo_queue.txt` (976) fully claimed this session by parallel agents.
- Corruption mode seen in shared TSVs: multi-line evidence strings break TSV
  rows → always sanitize `\t`/`\n` before appending.
- Merge tool semantics preserved in this file's git history; rerun via the
  python block in the session log if new partial TSVs appear.

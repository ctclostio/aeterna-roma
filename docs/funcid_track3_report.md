# Track 3 — Function Classification & Symbol Recovery (registrar wave)

Date: 2026-10-11
Scope: call graph outward from the app_init registrar hub `0x100ea060`
Tooling: `work/registrar_walk.py`, `work/registrar_evidence.py`

## Why this wave, and not the vtable route

The plan originally proposed recovering C++ class hierarchies from
`src_out/empire.retail.dll/vftables.txt`. **That route is closed.** It was
already surveyed (`work/rtti_scan.py`, commit `c3d0bcb`,
`docs/engine_architecture.md`):

- 181 MSVC type descriptors exist, but only **15 complete object locators and
  14 usable vftables** — all CRT/std (`std::exception`, `std::locale`,
  `stdext::bad_alloc`, `?$ctype@D@std`).
- The engine itself is linked essentially **`/GR-`**. Only ~30 `CA`-namespace
  types survive, and only as throw/catch `type_info`.
- `vftables.txt` is therefore **entirely FaceFX SDK** — `FxAnim`, `FxActor`,
  `FxSingleton<OC3Ent::Face::FxResourceManager>`, … Those are third-party
  library classes that already have authoritative public names; there is
  nothing to recover from them.

What *does* survive is the vtable **slot data**: the concrete function
pointers the engine actually installs. That is what this wave uses.

## Hub resolution: 23 vtables → 49 handlers

`0x100ea060` is `FUN_100ea060` (1123 bytes, unnamed). It performs **23**
`FUN_100e2460` appends of `&PTR_*` vtable bases into `this + 0x824`, plus one
separate 0xE4-byte allocation published at global `+8`. The task brief said
25; the recovered count is **24 registrations** (23 in-loop + 1 separate).

Resolving those 23 vtable bases against `.rdata` yields **780 slots over 49
distinct handler functions** — the handlers are shared between vtables.

Implementation note: Ghidra renders the vtable symbol itself as `PTR_<name>`,
and the hub writes `*obj = &PTR_<name>`, so the symbol address *is* the vtable
base. Dereferencing it (the intuitive reading) walks into `.text` and yields
garbage.

The 49 handlers cluster tightly — 47 of them between `0x100d38b0` and
`0x100ea040` — the classic MSVC one-functor-per-class layout:

```
0x100e1180..0x100e1af0   19 handlers   (contiguous)
0x100e8410..0x100e9490   22 handlers   (contiguous)
0x116bd8af                1 outlier
```

## Reach

BFS over direct `FUN_*` calls, reading each function's canonical
decompilation:

| Depth | Functions |
|---:|---:|
| 0 (handlers) | 49 |
| 1 | 61 |
| 2 | 166 |
| 3 | 367 |
| **total** | **643** |

Of the 643, **538 are unnamed** by the existing corpus (85 already carry
names). Per-subsystem proposals for all 538 are in
`work/registrar_proposed.tsv`.

## Two findings that block the other tracks

### 1. 20 of 49 startup handlers were never decompiled

The canonical export is self-consistent — 63,326 index entries, 63,326 `.c`
files, zero mismatch. But **20 of the 49 registrar handler addresses appear in
neither**. They are genuine gaps, not mid-function pointers: each sits in the
gap *between* two defined functions (e.g. `0x100e8e50` precedes the next
defined function at `0x100e8e80`, and is not inside any function body).

Missing: `0x100d38b0 0x100e1470 0x100e16f0 0x100e8410 0x100e8550 0x100e85e0
0x100e8660 0x100e8760 0x100e8810 0x100e8bb0 0x100e8be0 0x100e8c00 0x100e8d40
0x100e8df0 0x100e8e10 0x100e8e50 0x100e9230 0x100e9270 0x100e9490 0x100ea040`

So "63,326 / 63,326 (100%)" means 100% of *what Ghidra chose to define*, not
100% of the code reachable from startup. **Track 1 cannot fully model the
registrar chain until these are re-exported with forced disassembly.**
Note `0x100e9230` sits between two handlers Track 1 has already ported
(`0x100e92c0`, `0x100e87a0`), so the gap lands inside already-modelled code.

### 2. `work/funcid_batch1_final.tsv` was overwritten by a 549-row duplicate

The documented artifact holds 5,452 entries. On disk it had **549 rows**, all
disjoint from the 5,452 and all already present in `work/funcid_batch1.tsv`,
`funcid_batch1_v4.tsv` and `funcid_solo.tsv`. No data was lost; a partial
rule-engine run wrote its FaceFX-band subset to the canonical path.

Restored byte-identically from `2891a19` (`git checkout`, not a text rewrite —
`Out-File` silently converted LF to CRLF and broke the blob hash).

## Naming outcome is inherently thin here

444 of the 538 proposals are `unknown_opaque`. The handlers are **thin vtable
dispatch shims** (241–867 bytes) with no string literals and no API calls; the
substance lives in their callees, which is why depth-1/2/3 is where the signal
is. Only four handlers carry direct evidence:

| Address | Evidence | Reading |
|---|---|---|
| `0x100e2740` | `Total War: Rome 2 (%d.%d.%d)(%s; Build(%d%s)(%s); %s) Change` | version/build reporting |
| `0x100e8890` | `v%d.%d.%d  Build %d.%d%S` | version display |
| `0x100e86d0` | `Finished WarScape init` | WarScape (battle) init completion |
| `0x100e9390` | `bink_use_thread` | Bink **video** (not audio — rule fixed) |

Only `0x100e8e80` (`audio_init_part1`) was already named. **48 of 49 startup
handlers remain unnamed** — consistent with the brief's premise that Track 3
is the widest remaining gap.

## Corpus integrity

Strict union across all `work/funcid_*.tsv`: **9,036 unique named addresses**
of 63,326 (**14.3%**). Three figures in circulation are wrong: the README's
old "5,452" predates the solo passes, a naive row sum over-reports to ~10.4k
because intermediate files (`funcid_batch1.tsv`, `v2/v3/v4`,
`funcid_solo_batch1.tsv`) are successive versions of the same 5,398 rows, and a
strict `0x`-only match under-reports to 8,993 because
`funcid_batch1_final.tsv` mixes in 13 bare-hex addresses. The union must accept
both forms.

## Deeper traversal, and why propagation cannot rescue it

BFS to **depth 6** reaches **4,105 functions**, of which **3,572 are unnamed**:

| Depth | 0 | 1 | 2 | 3 | 4 | 5 | 6 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| Functions | 49 | 61 | 166 | 367 | 679 | 1,113 | 1,670 |

`work/registrar_propagate.py` implements the callee-cluster propagation the
RTTI survey recommends: seed a subsystem table from the 9,036-name corpus and
inherit it backwards along call edges. It converges in 5 rounds and adds only
**+74** subsystems (57 + 11 + 4 + 2 + 0).

The reason is measurable, and it is structural:

| Depth | call edges out | edges landing on a named address | hit rate |
|---:|---:|---:|---:|
| 0 | 105 | 33 | 31.4% |
| 1 | 284 | 54 | 19.0% |
| 2 | 874 | 119 | 13.6% |
| 3 | 1,872 | 219 | 11.7% |
| 4 | 3,732 | 420 | 11.3% |
| 5 | 6,298 | 708 | 11.2% |
| 6 | 8,327 | 918 | 11.0% |
| **total** | **21,492** | **2,471** | **11.5%** |

**Only 11.5% of edges leaving the startup subgraph land on anything the corpus
has ever named.** The existing names cluster in FaceFX SDK, setupapi/render and
telemetry bands, which the startup path barely touches. There is nothing to
propagate, so propagation is not a viable lever here — the registrar wave needs
direct evidence or a much broader seed corpus, not inference.

## The export gap is far wider than the registrars

Checking every named address against `function_index.txt` surfaced something
larger than the 20 missing handlers.

**1,973 named addresses lie in `.text` but appear in neither
`function_index.txt` nor the canonical export.** All of them come from
`work/funcid_environment_variables.tsv`. They are real code: every address
sampled begins

```
51 6a 00 68 <imm32> ...     push ecx ; push 0 ; push <handler>
```

the classic **MSVC SEH prologue** that Ghidra's analyzer splits off without
ever defining a function. Combined with the 20 registrar handlers, **~1,993
real code addresses carry names or vtable references but have no decompilation
at all.**

So "63,326 / 63,326 (100%)" should be read as *100% of the functions Ghidra
chose to define* — not 100% of the code reachable from startup, and not 100%
of code that the classification corpus references. Fixing this needs a targeted
re-export that forces function creation at known `.text` addresses that begin
an SEH prologue.

The Ghidra project was idle at the time of writing (no lock files, no running
`java`), but `workspace/TW2` is shared with the other tracks — any re-export
must be coordinated so it does not collide with an agent holding the lock.

## Guard rails added

`scripts/test_funcid_corpus_integrity.py` (6 tests) locks the defects found
here so they cannot recur silently:

1. `funcid_batch1_final.tsv` must keep ≥5,000 rows and every row must carry a
   name — this catches the 549-row clobber.
2. Address-format mix is asserted visible; bare-hex rows must stay a small
   minority of `0x`-prefixed ones.
3. `v2`/`v3`/`v4` must refine, not replace, the base `funcid_batch1.tsv`.
4. Undefined-code addresses are pinned to a baseline of 1,973 — it may shrink,
   never grow, so an export regression cannot hide behind the known gap.
5. `registrar_reach.tsv` must keep its header and stay duplicate-free.

## Recommended next

1. Re-export the 20 missing handlers with forced disassembly and decode, then
   re-run `registrar_walk.py`. This unblocks Track 1's registrar coverage.
2. Push BFS to depth 5–6 — signal density rises sharply past depth 3.
3. Treat `work/registrar_proposed.tsv` as advisory; it is deliberately not
   merged into the corpus.

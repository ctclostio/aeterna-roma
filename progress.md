# Progress ledger

Detailed record of admitted work, oldest first within each section. The
[live status page](https://ctclostio.github.io/aeterna-roma/) summarizes it,
and open work is listed in the [README](README.md#open-work). Completed entries
describe bounded evidence and executable behavior; they do not imply
whole-engine or gameplay equivalence.

Rules for new entries:

- Keep original image identities separate from native pointers. Prefix extents
  are not proofs of complete class sizes.
- Preserve step 1's files and active export. Do not relax provenance locks to
  hide metadata changes from concurrent recovery work.
- Link files with repository-relative paths, not `file:///` URLs.

## Analysis milestones

- [x] Ghidra headless pipeline validated on Rome2.exe
- [x] PE metadata extracted (exports/imports)
- [x] Lossless 522-export ABI lock → `docs/x64_export_contract.md`
- [x] empire.retail.dll auto-analysis and code-gap recovery — all 81,280
  canonical functions exported; see `docs/code_recovery_wave.md`
- [x] funcid solo pass #1 (2024-08): 250/250 `work/solo_claim_addrs.txt` classified →
  `work/funcid_solo.tsv` (raw, all parallel runs) + `work/funcid_solo_merged.tsv`
  (1,066 unique addrs deduped last-wins; subsystem mix: core 421, battle 207,
  render 103, anim 73, facefx 54, ui 50). Known anchors: MSVC LCG rand
  (0x343fd+0x269ec3), rad→16-bit angle ×10430.378, anim-id remap switch
  (8→0x5d9 … default 0x7f3), soldier class letters @obj+0x1dd, unit state
  byte @obj+0x1dc / idle short 0x11 @+0x1e2, slot array session+0x68→+0xc0.
- Historical FuncID snapshot (superseded by the next item): intermediate
  classifications in `work/funcid_solo.tsv` (+ main/todo2). Method + anchor
  table: `work/SOLO_SESSION_SUMMARY.md`; the contemporaneous remaining queue is
  `work/remaining_after_solo1.txt`.
- [~] FuncID pass: **9,036 unique addresses named (11.1% of 81,280; 14.3% of the earlier
  63,326-function corpus)**. Corpus integrity
  note: `funcid_batch1.tsv`, `v2/v3/v4` and `funcid_solo_batch1.tsv` are
  successive versions of the same 5,398 rows, so naive row sums over-report;
  `funcid_batch1_final.tsv` also mixes `0x`-prefixed and bare-hex addresses
  (13 rows), so count the union of both forms.
  Track 3 registrar wave: 23 vtables → 49 handlers, 4,105 functions reached to
  depth 6, 3,572 still unnamed; callee-cluster propagation is structurally
  starved (only 11.5% of call edges reach a named address, +74 subsystems);
  ~1,993 `.text` addresses then had no decompilation (since closed by
  the code-recovery wave, `docs/code_recovery_wave.md`)
  → `docs/funcid_track3_report.md`, `work/registrar_roots.tsv`,
  `work/registrar_reach.tsv`, `work/registrar_proposed.tsv`
  Output `work/funcid_batch1_final.tsv` (5,452; restored byte-identically from
  `2891a19` after a 549-row duplicate overwrote it)
- [x] FuncID Wave 2 complete (2026-11-23): **81,280 / 81,280 (100.0%)** unique
  canonical functions named across `work/funcid_*.tsv` (Wave 1 baseline plus
  Wave 2 `work/funcid_w2_library.tsv` `1,837` library/import symbols,
  `work/funcid_w2_agents.tsv` `67,303` tiered classifications [`[H]` `24,607`,
  `[M]` `28,240`, `[L]` `14,456`], and `work/funcid_w2_thunks.tsv` `253`
  internal thunks; shards complete: hubs `49/49`, `t0` `382/382`, `t1` `173/173`,
  `t2` `80/80`, `t3` `42/42`, `t4` `64/64`; `pro` audits across `8` sampled `t1`
  shards: `81/96` ok [`84.4%`], `2` wrong auto-fixed; `0` dangling canonical
  addresses).
- [x] Indirect-call resolution Pass 3 complete (2026-11-23): **59,079 / 59,079
  (100.0%)** indirect call sites classified with `0` unresolved across all
  `81,280` canonical functions (`33,987` [`57.53%`] statically narrowed:
  `7,700` `high`, `26,287` `medium`; `25,092` [`42.47%`] `low` sound
  multi-slot + stack-purge CHA closure; `45,252` `polymorphic_virtual`,
  `8,907` `monomorphic_internal` [`2,702` distinct `.text` targets across
  `17,395` callers], `4,147` `external_import`, `476` `callback_dispatch`,
  `229` `null_optional_hook`, `37` `external_interface`, `31`
  `non_call_trap`; `9,639` vtables / `123,569` slots / `3,698` families /
  `2,213` inheritance edges / `48,167` MI sub-object mappings / `2,892` MI
  thunks / `201` ICF stubs; `3,961` deduplicated target sets) →
  `work/indirect_call_resolutions_after.tsv`,
  `work/indirect_call_target_sets_after.tsv`,
  `work/indirect_call_vtables_after.tsv`,
  `work/indirect_call_hierarchy_after.tsv`,
  `work/indirect_call_summary_after.md`.
- [x] Decompiler-warning triage complete (2026-11-23): **9,856 / 9,856 (100.0%)**
  decompiler warning rows across all `6,765` affected canonical functions
  classified at `high` confidence with `0` untriaged (`9,724` benign:
  `4,348` `global_overlap`, `1,959` `unreachable_block`, `1,698` virtual + `450`
  IAT + `10` register + `4` `.data` callback tail calls, `584` `noreturn_call`,
  `331` `type_propagation`, `276` `injection`, `41` `restart_deadcode`, `8`
  `inlined`, `6` `readonly_write` PE-verified read-only SSE `.rdata` loads, `4`
  `heritage_dead_removal`, `2` `switch_case_unlabeled`, `2` `switch_degraded`,
  `1` `infinite_loop_block`; `73` `spacebase` stack-frame + `2` clean-exported
  `restart_limit` flagged for port verification; `57` switch-table warnings
  resolved via all **47** PE `.reloc`-verified code jump tables recovered
  across all **16** switch functions [`21` addressed + `26` selector-norm])
  → `work/decomp_defects_triaged_after.tsv`,
  `work/switch_tables_recovered_after.tsv`,
  `work/decomp_defects_triage_summary_after.md`.

## x64 port milestones

All x64 work below is `BUILD_TESTING`-only unless stated otherwise.

- [x] 64-bit build scaffolding (CMake/MSVC x64) → `docs/x64_bootstrap.md`
- [x] Strict canonical compile island (16/16 x64 syntax gate) → `docs/compile_island.md`
- [x] Evidence-only x86 startup initializer inventory (9,874 slots, exact PE
  validation, rollback-safe publication) → `docs/startup_audit_spec.md`
- [x] First isolated pointer-width behavior slice (`0x1093c450` →
  `0x100e81a0`) with a checked guest32 address API and pinned original-byte
  provenance → `docs/guest32_slice.md`
- [x] Static x64 entry-policy selector for original `0x100edd70`, including
  bounded UTF-16LE guest reads, original-byte provenance, adversarial tests,
  and bootstrap-link containment → `docs/x64_entry_policy_selector_spec.md`
- [x] Test-only x64 DLL-boundary probe for that selector (guest addresses stay
  32-bit; no recovered startup execution) →
  `docs/x64_entry_policy_probe.md`
- [x] First bounded post-policy startup leaf (`0x100f1c10`), isolated as a
  `BUILD_TESTING`-only guest32 writer with pinned bytes, static/mutant gates,
  boundary tests, and unchanged bootstrap artifacts →
  `docs/x64_startup_100f1c10_spec.md`
- [x] First native x64 lifecycle composition (`rome2_headless64.exe`), still
  `BUILD_TESTING`-only: entry-policy selection, bounded UTF-16 measurement,
  empty-startup construction, nonowning cleanup, and the bounded initializer
  branches listed below, with gameplay explicitly unlinked
- [x] Deterministic middle slice of platform-heavy `0x100df270`: exact
  post-platform field projection for empty descriptors, with Win32 effects,
  global publication, initializers, and virtual dispatch explicitly excluded
  → `docs/x64_startup_100df270_headless.md`
- [x] Short nonallocating branch of descriptor copy `0x100f2750`: exact
  2-to-30-byte forward copies, external 15-unit ceiling, guest32 alias/range
  containment, and allocation/release/overlap routes explicitly excluded
  → `docs/x64_startup_100f2750_nonalloc.md`
- [x] Bounded no-crash fast path of crash-record `0x100e8240`: read-only
  branch returning the `0x119f3a38` identity, crash-handler/crash-file window
  excluded. The adjacent `0x100ea4d0` body remains separately pinned as the
  original evidence authority; its later executable boundary uses only
  injected allocation and the bounded router
  → `docs/x64_startup_100e8240_fastpath.md`,
  `docs/x64_startup_100ea4d0_evidence.md`
- [x] First state-mutating step past that boundary: allocation-free append
  prefix of `0x100e2460`, with exact two-cell commit ordering, full
  allocator/dispatch/`PeekMessageW` exclusion evidence, and a runnable
  headless guest32 composition. This historical prefix milestone is now
  composed by the completed preallocated branch below
  → `docs/x64_startup_100e2460_append_prefix.md`
- [x] One genuine return path through `0x100e2460`: the complete allocation-free
  unsigned `count < capacity` branch, using total injected dispatch and
  `PeekMessageW`-shaped effects with a finite drain bound. Native USER32 and
  other platform calls and the then-unported allocation routes remain excluded
  from this historical branch milestone
  → `docs/x64_startup_100e2460_preallocated_branch.md`
- [x] Second genuine return path through `0x100e2460`: the complete intended
  `capacity == count == backing == 0` branch. It preserves capacity-before-
  allocation ordering with a total injected `(4, 0)` guest allocator,
  validates the returned guest32 cell, and reuses the bounded dispatch/Peek
  tail. This historical branch is now joined by the growth route below
  → `docs/x64_startup_100e2460_capacity_zero_branch.md`
- [x] Normal full-vector growth path through `0x100e2460`: checked capacity
  doubling, injected guest allocation, ascending copy and append, injected
  release of the old backing, and the bounded dispatch/Peek tail.
  Wrapped/signed resize states and the native stack-slot self-alias subroute
  remain excluded
  → `docs/x64_startup_100e2460_growth_branch.md`
- [x] Unified bounded router over all three admitted `0x100e2460` storage
  paths. A persistent six-insertion composition now follows the original
  zero/growth/growth/preallocated/growth/preallocated route sequence, requests
  pre-provisioned 4/8/16/32-byte guest spans, releases all three superseded
  backings, and retains the six handler identities in order. Native allocation,
  release, and platform effects remain excluded
  → `docs/x64_startup_100e2460_router.md`
- [x] First registered slot-4 handler `0x100e8d00`: authenticated six-call
  sequence represented as a typed injected transcript, with exact argument
  identities/order and AL publication only after the sixth effect
  → `docs/x64_startup_100e8d00_handler_transcript.md`
- [x] Second registered handler `0x100e85d0`: effect-free adapter for the
  authenticated no-op-helper call and `AL=1`, preserving both ignored guest
  identities and excluding native linkage
  → `docs/x64_startup_100e85d0_normal_adapter.md`
- [x] Third registered handler `0x100e8580`: nine-step injected transcript with
  an explicit snapshotted `0x100e8240` result, checked guest32 `+0x68`, and
  exactly-seven-step prefix semantics on null/overflow
  → `docs/x64_startup_100e8580_handler_transcript.md`
- [x] Bounded injected outer composition of `0x100ea4d0`: six total `(4, 0)`
  handler allocations, authenticated vtable stores, unified-router calls,
  accumulated handler-graph audits, and explicit fail-closed statuses in place
  of native allocation and the original null-write trap; finalized checkpoint
  verification is extended through the complete six-handler composition
  → `docs/x64_startup_100ea4d0_injected.md`
- [x] Fourth registered handler `0x100e9340`: four-step injected transcript
  covering two virtual lookup results, receiver-low-byte replacement, and the
  native-singleton/helper suffix without exposing a host pointer
  → `docs/x64_startup_100e9340_handler_transcript.md`
- [x] Fifth registered handler `0x100e92c0`: exact 3/4/6-step predicate routes,
  dependent two-word getter results, and final four-word startup call with all
  Steam and global behavior injected
  → `docs/x64_startup_100e92c0_handler_transcript.md`
- [x] Sixth registered handler `0x100e87a0`: injected listener allocation,
  checked guest32 vtable store, publication, and FaceFX startup with explicit
  prefix-commit failures and a typed memory policy
  → `docs/x64_startup_100e87a0_handler_transcript.md`
- [x] Complete deterministic suffix of `0x100df270`: authenticated receiver
  publication, adjacent direct-call identities, two selector-2 queries,
  mismatch-only four-call route, final marker store, and receiver return as a
  bounded injected transcript
  → `docs/x64_startup_100df270_suffix_transcript.md`
- [x] Complete platform-bound prefix interval of `0x100df270` as a typed
  injected call-shape transcript: exact 7/10-step normal and duplicate routes,
  three ordered guest writes, resource/callee provenance, and fail-closed
  guest32 containment. Native resource, mutex, UI, system-setting, global, and
  termination effects remain deliberately unexecuted
  → `docs/x64_startup_100df270_platform_prefix_transcript.md`
- [x] Empty-input straight-line prefix of launcher-facing parent `0x100ed3c0`:
  exact `0x90c` frame construction, the contiguous bounded `0x100df270`
  prefix/middle/suffix composition, nonowning cleanup, and a hard stop before
  the first parent loop instruction. The completion token is
  `startup-100ed3c0-empty-preloop=injected-composition-complete`
  → `docs/x64_startup_100ed3c0_empty_preloop.md`
- [x] Ordinary-domain lifecycle tail `[0x100ed471,0x100ed550)`: prevalidated
  finite `0* -> 2` poll transcript, checked first slot-`0x54` dispatch,
  injected timestamp and teardown, four ordered nonowning cleanups, exact
  result-last commit, and hard exclusion of the ordinary-unreachable
  result-one list/second indirect route. The completion token is
  `startup-100ed471-ordinary-lifecycle=injected-bounded-complete`
  → `docs/x64_startup_100ed471_ordinary_lifecycle.md`
- [x] Bounded nonempty UTF-16 descriptor lifecycle through
  `0x100f1bb0 -> 0x100ef330` and owning cleanup `0x100f1cc0`: exact
  `2*N+10` allocation grant, all four raw-address alignment residues, hidden
  raw-base metadata, opaque UTF-16 copy, literal-zero terminator, and
  one-shot LIVE/CONSUMED ownership with compensating release for unusable
  grants. This leaf remains a standalone `BUILD_TESTING` target
  → `docs/x64_startup_100f1bb0_owned_utf16.md`
- [x] First-use sentinel-to-owned persistent crash descriptor route in
  `0x100f2750` plus registered one-shot teardown: authenticated temporary
  source ownership, injected allocation/release authority, exact commit order,
  compensating release, and SENTINEL/LIVE/CONSUMED lifecycle. This leaf remains
  a standalone `BUILD_TESTING` target
  → `docs/x64_startup_100f2750_sentinel_owned.md`
- [x] Typed mid-suffix substitution seam at the observed `0x100f2750` call in
  `0x100df270`: snapshotted status-returning delegate, exact
  emit/execute/resume order, three-step committed failure prefix, unchanged
  observation-only API, and expanded 76-case oracle
  → `docs/x64_startup_100df270_suffix_transcript.md`,
  `docs/x64_startup_100ed3c0_nonempty_preloop_spec.md`
- [x] Compose the distinct temporary `0x100f1bb0` owner and persistent
  `0x100f2750` owner into a bounded nonempty `0x100ed3c0` preloop adapter:
  exact parent/child/cleanup order, independent 48-case total-order oracle,
  reciprocal admission gate, and strict `BUILD_TESTING` containment
  → `docs/x64_startup_100ed3c0_nonempty_preloop.md`,
  `docs/x64_startup_100ed3c0_nonempty_preloop_spec.md`
- [x] Whole nonempty ordinary-domain parent `[0x100ed3c0,0x100ed550)`:
  standalone composition of the admitted nonempty preloop and finite ordinary
  lifecycle, private successor preview before external effects, 36-case
  total-order oracle, reciprocal/provenance admission gates, and unchanged
  production binaries under strict `BUILD_TESTING` containment
  → `docs/x64_startup_100ed3c0_nonempty_lifecycle.md`
- [x] Bind that whole parent to the two exact `entry_point` call/continuation
  windows `[0x100edf20,0x100edf41)` and `[0x100edf73,0x100edf94)`, preserving
  all four caller positions, calling the whole parent exactly once, and
  modeling the two post-parent keeper stores plus grouped cleanup as injected
  success-only effects with hard stops before both epilogues. The 54-case
  oracle, reciprocal mutation gate, strict analyzer/ASan runs, two independent
  186/186 graphs, and testing-disabled containment are admitted
  → `docs/x64_startup_100edd70_caller_closure.md`
- [x] Compose the exact selector `[0x100edecc,0x100edf05)`, conditional
  registration-data interval `[0x100edf05,0x100edf20)`, and both admitted
  caller routes into one structural entry decision. The 44-case outer oracle
  re-runs the unchanged 54-case child oracle, pins four inert registration
  records on the install route, embeds the child result, commits result-last,
  and stops before the installed tail, exception gap, and common epilogue.
  Strict analyzer/ASan runs, primary and fresh 192/192 graphs,
  testing-disabled token containment, and unchanged reproducible production
  hashes are admitted
  → `docs/x64_startup_100edd70_entry_decision.md`
- [x] Corrected test-only battle entity field projection (`0x10cbe350`):
  independent origin/vector inputs, authenticated nineteen-word argument map,
  widened vector storage, atomic construction failure, and paired host cleanup
  → `docs/x64_battle_entity_10cbe350.md`. Strings remain borrowed; this does not
  integrate gameplay or reproduce native string ownership.

## Type-recovery layers

Step 2 of the project: types, layouts, and ownership. The code-recovery agent
owns step 1, the shared `workspace/TW2` Ghidra database, and canonical export
publication. Each heading reads `Layer N — scope (date closed)`.

### Layer 1 — Guest layouts, incomplete types and owned strings (2026-11-03)

- Replaced 158 fabricated 64-byte types with incomplete declarations and
  preserved exact 3/5/6/7-byte and ten-byte x87 storage.
- Added fixed-width guest layouts, checked descriptor bridging, typed initial
  global snapshots, and original-byte contracts for 15 functions, 11 globals,
  nine vtable first slots, and ten instruction windows.
- Implemented native owned narrow/UTF-16 strings, deep-owned string vectors,
  an owning entity adapter, and typed linked-slot pool constructors.
- Added a warning-clean compile profile with real object generation. The
  historical 16 raw canonical roots still produce 228 syntax-profile warnings
  and are rejected by the strict profile with 232 front-end warnings.
- Verification: 74 focused Python tests passed; six native suites passed in
  both `/analyze` and AddressSanitizer builds.
- Details: [type recovery](docs/type_recovery.md),
  [verification record](port/recovered_types/verification.json).

### Layer 2 — Unit-card tag/helper boundary and nested containers (2026-11-03)

Target: the provisional unit-card tag/helper boundary and nested container
ownership.

- [x] Authenticate the helper call receivers, argument offsets, and cleanup
  boundaries against original bytes and retained analysis.
- [x] Recover the tag vector and nested element layouts without guessing
  unknown field meanings or widening guest address cells.
- [x] Implement deep-owned native copies and matching cleanup for the admitted
  tag/container domain, including failure rollback.
- [x] Correct or replace the provisional unit-card helper boundary where the
  evidence supports a concrete native implementation.
- [x] Extend provenance checks, compile with warnings as errors, and run
  analyzer/ASan and regression checks.
- [x] Record final results, supported domains, and remaining gaps here.

Implemented: exact 12/16/76/136-byte guest tag/vector records and
16/24/80/152-byte native projections; an opaque native tag owner that deep-copies
both string widths and both array levels. Verification passed 76 focused Python
tests and all seven native suites in both `/W4 /WX /analyze` and ASan profiles.
The new suite covers eleven allocation failure
positions at every raw alignment 0–7, captured allocators, independent copies,
embedded zeros, UTF-16 surrogate units, rejection before effects, and private
release authority despite corrupted published descriptor copies. Metadata uses
native extents; string payloads retain the verified allocation formulas.

Original-byte windows and a private REA/Ghidra analysis confirm `arg01+4` as the tag
source, `block+4` as the guest destination receiver, and the allocated attachment
block in ECX for `FUN_101350c0`. The corrected native callback uses typed vector
members at native offset 8, accepts the allocated attachment receiver, and
requests 24/288-byte native projection blocks rather than 16/232-byte guest
blocks. Missing callbacks suppress allocation. The original requests remain
separately recorded.

The registry now checks 18 original function bodies/stack returns, 11 initial
globals, nine vtable first slots, and twelve instruction windows. The UTF-16
copy helper's complete 15-instruction REA view confirms the outer string width.
The private session was saved and closed; the shared Ghidra project and step 1
exports were not modified by this layer. No callable virtual methods or
original destructor ordering are inferred from a vtable identity. Native
cleanup is explicit allocation pairing with full rollback.

Details: [tag copy map, evidence, and limits](docs/unitcard_tag_type_recovery.md),
[native owning API](port/recovered_types/owned_tag.h),
[verification record](port/recovered_types/verification.json).

### Layer 3 — Native ownership (2026-11-03)

- [x] Implement the attachment copy, including the observed `+0x50` word and
  accurate capacity/count order.
- [x] Recover and implement the word/pair append effects, shared index,
  normalization, fauna record layout, nested cleanup and capacity retention.
- [x] Authenticate the setup receiver and XML dependency; provide an explicit
  decoded-configuration boundary with a required configuration input.
- [x] Add the typed UTF-16 writer and compose recovered subobjects into a
  native owner with complete rollback and cleanup for this admitted domain.
- [x] Complete integration tests, independent review, original-byte checks,
  strict analyzer builds and ASan verification.

Implementation:

- Corrected the entity vector to capacity at guest `+0xb4`, count at `+0xb8`,
  and items at `+0xbc`. Added the observed `+0x50` scalar without increasing
  the 288-byte native projection; its previous alignment gap absorbed it.
- Added `rome2_owned_battle_entity_copy`, deep-copying the attachment's seven
  source strings, two reconstructed literal names, and nested string vector.
  Its suite covers all fifteen allocation failure positions at all alignments.
- Added word/pair vectors with observed doubling growth, captured allocation
  authority, alias-safe append, and the verified finite-domain SSE arithmetic
  order for pair normalization. The scalar suite covers sixteen allocation
  failure positions at all alignments.
- Added stable owners for 44-byte guest / 48-byte native fauna records,
  deep nested string copies, alias-safe append, and clear with retained
  capacity. Its suite covers twenty-two allocation failure positions at all
  alignments, source revocation, and private release authority.
- Added a distinct 472-byte native unit-card prefix with correctly typed
  vectors and UTF-16 text, plus an owning composition API. The integrated
  suite performs 1,228,292 checks, including factory failure injection at
  36 full-fixture positions, ten empty-parts positions and seven minimal
  positions; config replacement covers twelve positions and alias replacement
  eight, each across raw alignments 0–7. All 23 deliberately broken copies
  failed that suite; the unmodified control passed.

Verification: **82 focused Python tests passed; all twelve native suites passed
both `/W4 /WX /analyze` and ASan.** The original-byte registry now verifies
26 bodies/stack returns, twelve original data values, nine vtable first slots
and twenty instruction windows. Whole-repository regression status below is
historical and is not replaced by these focused results.

Independent review found two issues that were corrected and regression-tested:
publish new/empty unit-card views before release callbacks, and keep entity
liveness/release checks independent of published items/counts. A follow-up
review confirmed both fixes for supported inputs. The observer suite directly
reads cached views during text replacement, config replacement and fauna clear;
destruction invalidates cached views when it consumes the handle.

The eight additional helper bodies have been checked through REA/Ghidra. The
private session was saved and closed. The setup callback's receiver is a
pointer to a holder containing the unit-card pointer; it is not the unit-card
itself. XML resource parsing remains an explicit boundary: the new native
factory requires decoded configuration and rejects an omitted configuration.

The native factory accepts explicit decoded configuration, including an
explicit empty view. It returns `CONFIG_REQUIRED` without allocations when
configuration is omitted. It does not fabricate successful XML/resource I/O.
The legacy projection remains bounded and is separate from the new native owner.

Details: [ownership and evidence](docs/unitcard_ownership_recovery.md),
[native owning unit-card API](port/recovered_types/owned_unit_card.h),
[verification record](port/recovered_types/verification.json).

Claude Code workers used exact `claude-opus-5-5` with `xhigh` effort. After the
earlier quota reset, layer 3 used a test worker and a read-only reviewer, followed
by a review of the fixes. Root supplied binary interpretations, integrated the
work and independently ran the final builds. No alternate model was substituted.

### Layer 4 — Resource-backed setup for the admitted domain (2026-11-07)

- [x] Verify the existing PFH4 resource reader, owned XML frontend and
  `FUN_10141630` fauna decoder against retained original-image evidence.
- [x] Connect the default `Script/fauna_config.xml` path to the native owning
  unit-card factory using explicitly ordered archives.
- [x] Add setup with the observed clear-before-load state order from
  `FUN_101a97f0`; preserve the existing transactional reload API.
- [x] Test missing resources/root, malformed XML, retained capacity, captured
  allocators and every allocation-failure position at raw alignments 0–7.
- [x] Compare both factory and setup output against both installed fauna
  resources, including both explicit archive-priority orders.
- [x] Pass original-byte checks, optimized native tests and ASan; record the
  admitted scope and unresolved original-loader behavior.

The previous XML/resource item was partly implemented but not recorded here.
This pass verified that code and added the missing setup operation: the original
clears fauna count at `0x101a9860` before its default resource call at
`0x101a989b`. Native setup now clears before loading, leaves fauna empty on
ordinary load/allocation failure, retains outer capacity, and preserves other
card fields. The earlier reload continues to preserve old configuration on
failure. Resource failures remain explicit; full original quiet-failure and
exception behavior is not claimed.

Verification: all **60 local native tests** pass in both optimized and ASan
profiles; all **22 original-image contract tests** pass. The resource suite runs
**3,065,966 checks**, covering 52 factory / 46 reload / 46 setup allocation
failure positions at eight alignments. The independent asset oracle checks
every semantic word and climate byte of both shipped 13-record configurations
for factory and setup. The static registry verifies 46 function bodies, 57
globals, nine first vtable slots and 33 instruction windows.

The retained REA dossiers were hash-checked. This pass used local review;
the attempted DeepSeek review did not execute because authentication failed.
Shared Ghidra state and canonical exports were unchanged. Details and limits:
[resource-backed setup](docs/unitcard_resource_recovery.md),
[verification record](port/recovered_types/verification.json), and
[installed-asset identities](port/recovered_types/fauna_assets.json).

### Layer 5 — Explicit XML-node setup for the native domain (2026-11-07)

- [x] Verify the nonzero XML-node branch of `0x101a97f0` against retained REA
  evidence and an additional original-byte instruction window.
- [x] Decode every direct child of a selected native XML node without a
  filename or `fauna_config` parent-name lookup.
- [x] Validate document membership before mutation, deep-own decoded records,
  capture transient/card allocator policies independently, and retain the exact
  old backing on empty setup or later allocation failure.
- [x] Exercise every decoder/loading/card allocation-failure position at raw
  alignments 0–7, source-document destruction, fabricated/foreign nodes and
  callbacks that mutate the caller's allocator policy.
- [x] Strengthen resource setup tests for missing-entry fallback, stop-on-error
  archives, malformed/missing-root shadowing and allocation-free empty commit.

Both optimized and ASan profiles pass **61 local native tests**. The new XML-node
suite runs **311,049 checks**, with nine decoder/loading and eight card-owner
allocation-failure positions at eight alignments. The resource suite runs
**3,153,797 checks**, with the existing 52 factory / 46 reload / 46 setup failure
positions and nested strings in the old setup seed. All **23 original-image
contract tests** pass; the registry now verifies 34 instruction windows while
retaining the same 46 function bodies, 57 globals and nine first vtable slots.
Both installed-resource factory/setup comparisons continue to pass.
The clean public worktree passes **851 Python tests** on both 3.14 and 3.15,
with 252 expected private-evidence skips in each run.

Google Argon provided a read-only second review and identified useful test
gaps addressed here. The installed CLI rejected Max effort for Argon; its
highest available variant, `gemini-4-argon-high` with High effort, was used.
Review findings were checked against the source and retained binary evidence.
The focused filename-loader callback query returned no procedure at
`0x112b5110`; original loader failure behavior remains unresolved. Shared
Ghidra state and canonical exports were unchanged. The XML-node API accepts
native document views; it does not claim the original XML object ABI or exact
nonempty backing-allocation behavior. Details:
[setup recovery](docs/unitcard_resource_recovery.md) and
[verification record](port/recovered_types/verification.json).

### Layer 6 — XML loader policy and failure distinctions (2026-11-07)

- [x] Follow the 20-byte callback adapter into the original filename loader
  and recover nine focused function dossiers in one private REA session.
- [x] Distinguish normalized drive-rooted routing from file-existence or
  archive precedence; retain complete normalization/VFS policy as open work.
- [x] Establish direct-file open-failure return, continued buffer processing
  after failed/short reads, and import despite a false parser result.
- [x] Recover the legacy BOM byte filter without treating it as Unicode
  conversion; add a bounded in-place native helper.
- [x] Record the fixed-width XML state prefix and add a checked root-state
  reader with an explicit work budget and preserved output on failure.
- [x] Verify native path routing, byte preparation and linked readiness with
  original-byte contracts, optimized/ASan tests and independent Argon review.

The new policy suite runs **200,779 checks**, including every two-byte prefix
for the legacy filter, every raw readiness byte, a non-monotone unaligned chain,
all mapped-view truncations, cycles, work limits and address-space boundaries.
Both native profiles pass **62 local suites**, including installed-resource
comparisons. The clean public suite passes **856 tests** on Python 3.14 and
3.15, with 257 expected private-evidence skips. All **28 original-image tests**
pass; the registry verifies **55 function bodies, 57 globals, nine first vtable
slots and 45 instruction windows**.

The complete filename-loader assembly shows why blanket quiet-empty fallback
would be wrong: failed/short reads still reach byte preparation, and parser
failure does not suppress import of temporary nodes. Existing native resource
APIs retain explicit diagnostics. Direct-file open failure is a narrower
statically established quiet-empty case for a fresh destination. Missing VFS
entry behavior and exact partial-tree/exception outcomes remain open.

Argon reviewed the new helpers read-only using the highest installed Argon
High/High variant. Review suggestions were checked against assembly; an early
existence-based routing hypothesis was rejected. The private REA session was
closed, its 55-record bundle validated, and 12 new retained records hash-pinned.
Shared Ghidra state, canonical exports and frozen admission locks were unchanged.
See [XML loader recovery](docs/xml_loader_recovery.md) and the
[verification record](port/recovered_types/verification.json).

### Layer 7 — VFS dispatch, filename hash and table probing (2026-11-07)

- [x] Resolve the XML loader's secondary-interface slot to active/static
  targets and trace original hit branches omitted by pseudocode.
- [x] Establish ordinary active-miss empty-wrapper representation while
  preserving allocator, release and unwind limits.
- [x] Add a bounded dispatch observer that keeps guest code identities separate
  from native pointers and performs no original-code execution.
- [x] Port the alternating signed-byte/16-bit filename hash and circular
  name-table probing with checked views and an explicit probe budget.
- [x] Preserve match-before-empty semantics, full 32-bit key equality and the
  distinction between a matched NULL value and a missing key.
- [x] Extend function provenance to database-reported disjoint body ranges;
  retain actual code bytes and reject returns in gaps.

Both native profiles pass **64 local suites**, including installed-resource
comparisons. New dispatch/name suites run **2,459 / 134,705 checks**. All **37
focused contract tests** pass, and the clean public suite passes **865 tests**
on both Python versions with 264 expected private-evidence skips. The registry
verifies **72 function bodies, 63 globals, 12 first vtable slots and 62
instruction windows**. Two noncontiguous bodies exclude nine/three gap bytes.

Seventeen new function dossiers and a validated 28-record bundle support this
pass. The oversized constant-zero dossier was consumed through retained views
and complete export. A fresh private session was used after prior snapshot
reuse ended unexpectedly; prior records stayed intact. The session was closed.
Argon's read-only native review found no confirmed defect; hypotheses were
checked against assembly, including the always-successful memory-reader setup
and the real active hit branches. The release entry still lacks a decoded
procedure, so its raw bytes do not admit a release ABI or lifetime equivalence.

Native resource APIs retain explicit diagnostics. The new helpers observe
dispatch/name-table state; they do not construct managers, populate mounts,
open files, intern names or reproduce original locking/unwinding. Full mount
priority and normalization remain separate obligations. See
[VFS recovery](docs/vfs_recovery.md) and the
[verification record](port/recovered_types/verification.json).

### Layer 8 — VFS name-table assignment, duplicate suppression and archive-candidate comparison (2026-11-12)

- [x] Recover generic hash-table assignment `0x112ddee0` and adapt its
  fixed-capacity probing/write loop as `rome2_vfs_assign_name32`.
- [x] Preserve equal-key priority over the empty marker, write preflight before
  mutation, `TABLE_FULL` vs. `PROBE_LIMIT` distinction, and sentinel-query
  `matched_key` semantics.
- [x] Distinguish generic overwrite (`0x112ddee0`), loose-file cache
  old-entry slot-0 teardown and `NULL`-fallback assignment (`0x112b8830`), and
  archive-local first-equal-key duplicate suppression (`0x112a9560`).
- [x] Separate the global archive-name tree (`0x112c01f0` -> `0x12032a34`,
  `0x112c0250`) and archive-candidate resolver (`0x112ce0c0`) from the
  loose-file hash table (`0x112bbd10` -> `0x120329b4`).
- [x] Recover archive registration comparator installation (`0x112cfc10` ->
  `0x112e1500`) and directional relationship predicate checks (`0x112d59f0`)
  without overclaiming full dependency-graph or mount-order semantics.
- [x] Verify with an exhaustive small-table circular-distance oracle, strict
  `/W4 /WX /analyze` and ASan native builds, original-byte contracts, and
  independent Argon High code/assembly reviews.

Both native profiles pass **65 local suites**, including installed-resource
comparisons. The new assignment suite runs **346,378 checks**, covering all
three-key states of 1-to-5-slot tables across all start indices, probe budgets,
sentinel/zero queries and zero/nonzero values, plus alignment residues 0–7,
truncations, key-only collisions, minimally mapped selected slots, full-table
replacement and 32-bit endpoints. All **41 focused contract tests** pass, and
the clean public suite passes **869 tests** on Python 3.14 and 3.15 with 269
expected private-evidence skips each. The registry verifies **81 function
bodies, 68 globals, 14 first vtable slots and 90 instruction windows**.

Fourteen new REA records (nine function dossiers and five data reads) were
added in a resumed private session on top of the 28-record Layer 7 snapshot,
producing a validated 42-record bundle and closed session snapshot. Argon High's
read-only native code review and original-assembly review both found no
confirmed defect or overclaim. Shared Ghidra state, canonical exports and
frozen admission locks were unchanged. See [VFS recovery](docs/vfs_recovery.md)
and the [verification record](port/recovered_types/verification.json).

### Layer 9 — Archive-name tree search, string-key ordering, winning-archive resolution and dependency-graph walk (2026-11-12)

Target: trace the two-level archive lookup in `0x112ce0c0` (`0x112c0250` ->
`0x112ce0f2` -> `0x112c1130`), the name-entry less-than comparator chain
(`0x101206f0` -> `0x100f2fe0` -> `0x100f7040`), tree/candidate-set sentinel
initialization (`0x112a7550`, `0x112a7690`), and the dependency-graph lookup
and reachability routines (`0x112d4fa0`, `0x112a77b0`, `0x112afff0`,
`0x112b5090`).

Completed deliverables:
- [x] Opened a private REA session from the Layer 8 snapshot (`out/vfs-layer9-20261112/`)
  and recovered 12 new records (9 function dossiers for `0x101206f0`,
  `0x100f2fe0`, `0x100f7040`, `0x112a7550`, `0x112a7690`, `0x112d4fa0`,
  `0x112a77b0`, `0x112afff0` and `0x112b5090`, plus 3 global reads for
  `0x12032950`, `0x12032a40` and `0x12032a58`), producing a validated 54-record
  evidence bundle and closed session snapshot.
- [x] Added fixed-width guest layouts in `port/recovered_types/guest32_layouts.h`
  for `rome2_vfs_tree_header_layout32` (`8` bytes), `rome2_vfs_tree_node_prefix32`
  (`24` bytes), `rome2_vfs_candidate_set_layout32` (`12` bytes), and
  `rome2_vfs_candidate_node_prefix32` (`20` bytes).
- [x] Implemented bounded native helpers `rome2_vfs_compare_name_less32` and
  `rome2_vfs_search_archive_tree32` in `port/recovered_types/vfs_archive_tree.h`
  and `vfs_archive_tree.c`, preserving `lhs == 0` asymmetry (`(0, 0) -> true`),
  signed-byte lexicographic order, lower-bound traversal with explicit step/byte
  budgets, and optional winning-archive table descriptor resolution
  (`[winner + 0x10] + 4`).
- [x] Verified **66 native test suites** across both `/W4 /WX /analyze` and ASan
  profiles, with `rome2_vfs_archive_tree_tests` executing **134,286 checks**.
- [x] Extended `port/recovered_types/contracts.json` to **90 functions, 71
  globals, 14 vtables and 110 instruction witnesses**, verified by **44 focused
  contract tests** in `scripts/test_type_recovery_contracts.py` and **872 clean
  public tests** (with 272 expected private-evidence skips) on Python 3.14 and
  Python 3.15.

### Layer 10 — Archive dependency-graph reachability, candidate priority comparator, and tree/registration callees (2026-11-12)

Target: close the exact semantics and native helper coverage of the archive
dependency graph and candidate priority comparator (`0x112e1500` -> `0x112d59f0`
-> `0x112b5090` -> `0x112afff0`), including narrow-string data resolution
(`0x10101a40`) and RB-tree iterator traversal (`0x112ac2d0`), while recovering
the archive-registration tree/candidate insertion and pack-resolution callees
from `0x112cfc10` (`0x112a4c00`, `0x112bb620`, `0x112a4320`, `0x112a30b0`,
`0x112d4cc0`, `0x112d4de0`, `0x112c13f0`, `0x112dd6b0`).

Completed and verified:
- [x] Opened a private REA session reusing the closed Layer 9 snapshot
  (`out/vfs-layer10-20261112/session.rea.json`) and recovered all 10 target
  function dossiers (`0x10101a40` via `inspect_analysis_view` and validated
  bundle record after `resource_constraint`) and 3 global reads (`0x12032944`,
  `0x12032960`, `0x1173dfac`), validating the 70-record evidence bundle
  (`54` reused Layer 9 + `13` new primary + `3` extra views).
- [x] Verified and locked fixed-width 32-bit layouts in `port/recovered_types/guest32_layouts.h`:
  `rome2_vfs_dep_bucket_pair32` (8 bytes), `rome2_vfs_dep_hashmap_layout32`
  (32 bytes), `rome2_vfs_dep_graph_node_prefix32` (36 bytes),
  `rome2_vfs_dep_edge_node_prefix32` (28 bytes), and
  `rome2_vfs_archive_candidate_prefix32` (32 bytes).
- [x] Implemented bounded C17 helpers `rome2_vfs_string8_equals32` (`0x100f28a0`),
  `rome2_vfs_dep_hashmap_find32` (`0x112afff0`), `rome2_vfs_dep_edge_next32`
  (`0x112ac2d0`), `rome2_vfs_dep_reachable32` (`0x112d59f0` -> `0x112b5090`), and
  `rome2_vfs_compare_archive_candidates32` (`0x112e1500`) in
  `port/recovered_types/vfs_dependency_graph.h/.c` with explicit hash-chain,
  RB-tree step, DFS depth (`<= 64`), total visit, and string-byte budgets
  (failing closed with `ROME2_VFS_DEP_STEP_LIMIT` on cycles).
- [x] Verified `test_vfs_dependency_graph.c` (`127 checks passed` covering signed/high-byte
  `string8` equality, hash collision chains stopping after `last`, unbalanced 7-node
  RB-tree in-order traversal and bounded step limits, DAGs/diamonds/cycles, lazy
  `pack_props` `0x1c & 0xf` tie-breaking, alignment residues 0–7, and truncations),
  passing **67/67** native suites under `/W4 /WX /analyze` and ASan (`ROME2_TYPES_ASAN=ON`).
- [x] Extended `port/recovered_types/contracts.json` (`100` functions, `74` globals,
  `14` vtables, `127` instruction witnesses, verified under original binary) and
  `scripts/test_type_recovery_contracts.py` (`45` tests OK), ran clean public-checkout
  suites on Python 3.14 & Python 3.15 (`873` tests run, `273` skipped, `OK`), and
  updated `docs/vfs_recovery.md`, `progress.md`, `README.md`, and `verification.json`.

### Layer 11 — Archive registration (`0x112cfc10`) orchestration, precondition gates, and candidate-set insertion policy (2026-11-12)

Target: recover the remaining callees of `0x112cfc10` and `0x112bb620`/`0x112a4320`
(`0x112a37b0`, `0x112a3c90`, `0x112a4230`, `0x112a27c0`, `0x112c0b20`,
`0x112a20b0`, `0x112a4470`, `0x112a5840`, `0x112c0bb0`, `0x101028f0`,
`0x10121690`, `0x112c9ad0` containing `0x112ca9d0`), lock the exact `0x112cfc10`
registration precondition and error-code semantics (`0` eligible/registered, `1`
already mounted in `0x12032a1c`, `2` blacklisted in `0x12032a40+0x10`, `3`
absent from open-pack hash table `0x120329e0`, `8` new-key insert rejected when
`param_2 != 0`), and build a bounded native C17 adaptation of the registration
precondition and candidate-set insertion/winner selection policy.

Completed and verified:
- [x] Opened a private REA session reusing the closed Layer 10 snapshot
  (`out/vfs-layer11-20261112/session.rea.json`) and recovered all 12 target
  procedures (`0x101028f0` and internal anchor `0x112ca9d0` -> `0x112c9ad0`
  via `inspect_analysis_view` and validated bundle records after direct MCP
  `resource_constraint`) plus 3 global reads (`0x120329e0`, `0x12032a1c`,
  `0x12032a8c`), validating the **91-record** evidence bundle (`70` reused Layer 10
  + `15` new primary + `6` extra views).
- [x] Inspected exact assembly and call sites confirming RB-tree allocation,
  hint-insert, unique-insert, and post-order deletion (`0x112a37b0`, `0x112a3c90`,
  `0x112a4230`, `0x112a4470`, `0x112a27c0`), open-pack & name-table slice
  iterators (`0x112c0b20`, `0x112c0bb0`), `FxName` accessors (`0x101028f0`,
  `0x10121690`), archive-name tree constructor (`0x112a20b0`), keyed lookup
  dispatcher (`0x112a5840`), `FUN_112c9ad0` (`0x112ca9d0`), and `0x112cfc10`'s
  `1 -> 2 -> 3 -> 0` precondition gates + `cStack_48`/`param_2` (`8`) + leftmost
  winner displacement checks.
- [x] Locked `rome2_vfs_open_pack_slot_layout32` (`0x14` bytes) and
  `rome2_vfs_open_pack_table_layout32` (`0x14` bytes) in
  `port/recovered_types/guest32_layouts.h` and implemented bounded C17 helpers
  `rome2_vfs_open_pack_find32` (`0x112c13f0`), `rome2_vfs_blacklist_contains32`
  (`0x112a4c00`), `rome2_vfs_check_registration_preconditions32` (`1/2/3/0`), and
  `rome2_vfs_probe_candidate_insert32` (`0x112cfc10` + `0x112a30b0` + `0x112e1500`
  + code `8` + `head->left` winner displacement) in
  `port/recovered_types/vfs_archive_register.h/.c`.
- [x] Verified `test_vfs_archive_register.c` (`119 checks` passed covering
  single-wrap open-pack collision probing, `STEP_LIMIT`, `INVALID_STATE` /
  `RANGE_ERROR` output preservation, strict `1 -> 2 -> 3 -> 0` precondition
  precedence, alignment residues 0–7, empty/winner-displacing/middle/tied
  candidate probing, and `only_update_existing` code `8`), passing **68/68**
  native suites under `/W4 /WX /analyze` and ASan (`ROME2_TYPES_ASAN=ON`).
- [x] Extended `port/recovered_types/contracts.json` (`112` functions, `77` globals,
  `14` vtables, `143` instruction witnesses, verified under original binary) and
  `scripts/test_type_recovery_contracts.py` (`46` tests OK), ran clean
  public-checkout suites on Python 3.14 & Python 3.15, and updated
  `docs/vfs_recovery.md`, `progress.md`, `README.md`, and `verification.json`.

### Layer 12 — `0x112cfc10` archive carrier (`0x112a9560`), path normalization & remaining RB-tree callees (2026-11-12)

Target: recover the next batch of `0x112cfc10` callees (`0x112a9560`,
`0x101206e0`, `0x1011fdd0`, `0x1011fe40`, `0x101141f0`, `0x10113c10`,
`0x100f2610`, `0x10cb8f10`, `0x112a24f0`, `0x112a2e80`, `0x112a3570`,
`0x112a3a50`) and globals (`0x12032a34`, `0x12032a7c`, `0x117df544`), lock
`0x112cfc10`'s `0x20`-byte archive-carrier layout, name-table iteration, path
normalization (`"\\"`), and recursive dependency-closure `0/1` gate, and
validate bounded C17 helpers.

- [x] **REA Evidence Extraction (`out/vfs-layer12-20261112/`)**: Reused closed
  Layer 11 snapshot (`out/vfs-layer11-20261112/session.rea.json`) and closed
  `out/vfs-layer12-20261112/session.rea.json` with **105** validated evidence
  records (`91` reused + `14` new across all 12 procedures and 4 data reads
  including UTF-16LE `L"vfs_log_level"` at `0x117df544`).
- [x] **Layouts & Native C17 Helpers**: Refined
  `rome2_vfs_archive_candidate_prefix32` (`+0x00 pack_props`, `+0x04 name_table`,
  `+0x14 archive_name`) and added `rome2_vfs_pending_entry_vec_layout32` (`12`
  bytes at `0x12032a7c..0x12032a84`) in `port/recovered_types/guest32_layouts.h`,
  and implemented `rome2_vfs_archive_leaf_name`, `rome2_vfs_entry_dir_prefix`,
  `rome2_vfs_carrier_pack_props_gate32`, `rome2_vfs_carrier_next_nonempty_slot32`,
  `rome2_vfs_collect_pending_deps32`, and `rome2_vfs_dep_status_acceptable` in
  `port/recovered_types/vfs_archive_mount_step.h/.c`.
- [x] Verified `test_vfs_archive_mount_step.c` (`63 checks` passed with
  output-preservation invariants on overflow/limit errors), passing **69/69**
  native suites on `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] Extended `port/recovered_types/contracts.json` (**122** functions, **78**
  globals, **14** vtables, **157** instruction witnesses) and
  `scripts/test_type_recovery_contracts.py` (**47** contract tests OK),
  clean-public Python 3.14 & Python 3.15 suites, and updated
  `docs/vfs_recovery.md`, `progress.md`, and `verification.json`.

### Layer 13 — Pack Entry Vtable `0x118976c0`, Winner Notification `+0x34` & `0x112a9560` Stream/Pool Callees (2026-11-12)

- [x] **REA Evidence Extraction (`out/vfs-layer13-20261112/`)**: Inspected
  `0x118976c0` (64B pack-entry vtable including non-procedure slots `+0x04`
  `0x112d3270` and `+0x34` `0x112d2900` confirmed via `resolve_containing_procedure`
  + `read_bytes`) and `0x1189a434` (32B archive-name entry vtable), and recovered
  `0x100d12b0`, `0x100f16b0`, `0x100f1bb0`, `0x101155a0`, `0x10115530`,
  `0x101146c0`, `0x101157c0`, `0x101048f0`, `0x10106120`, `0x103282b0`, and
  `0x112e1560` (**131** validated records in closed `out/vfs-layer13-20261112/session.rea.json`).
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_pack_props_prefix32`
  (`0x44` bytes) and `rome2_vfs_pack_entry_layout32` (`0x28` bytes) in
  `port/recovered_types/guest32_layouts.h`, implemented `rome2_vfs_decode_pack_index_record`,
  `rome2_vfs_pack_props_read_prefix32`, `rome2_vfs_entry_read32`, and
  `rome2_vfs_entry_notify_winner32` in `port/recovered_types/vfs_pack_entry.h/.c`,
  and verified `test_vfs_pack_entry.c` (**61 checks** passed) across **70/70**
  native suites under `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Extended `port/recovered_types/contracts.json`
  (**133** functions, **79** globals, **15** vtables, **168** instruction witnesses),
  `scripts/test_type_recovery_contracts.py` (**48** contract tests OK on Python 3.14 & 3.15),
  clean-public Python suites, `docs/vfs_recovery.md`, `progress.md`, and `verification.json`.

### Layer 14 — Remaining `0x112a9560` Non-CRT Callees & Full `0x118976c0` Pack-Entry Vtable Slots (2026-11-12)

- [x] **REA Evidence Extraction (`out/vfs-layer14-20261112/`)**: Recovered the remaining
  non-CRT `0x112a9560` callees (`0x100f3880` IAT `GetLastError` thunk, `0x10102f50`
  aligned heap buffer wrapper) and all remaining 13 virtual dispatch slots of `0x118976c0`
  (`+0x00`, `+0x08..+0x0c`, `+0x14..+0x30`, `+0x38..+0x3c`) on top of
  `out/vfs-layer13-20261112/session.rea.json` (**152** validated records in closed
  `out/vfs-layer14-20261112/session.rea.json`; high-fanout CRT heap/SEH thunks
  `0x100fcc50`/`0x100fcc80`/`0x11683*` deferred from cumulative bundle export).
- [x] **Layouts & Native C17 Helpers**: Promoted `+0x20` (`stream_state`) in
  `rome2_vfs_pack_entry_layout32` (`guest32_layouts.h` & `vfs_pack_entry.h/.c`),
  implemented `rome2_vfs_plan_aligned_alloc`, `rome2_vfs_entry_clamp_slice32`,
  `rome2_vfs_entry_has_per_entry_meta32`, and `rome2_vfs_entry_read_stream_info32` in
  `port/recovered_types/vfs_pack_stream.h/.c`, and verified `test_vfs_pack_stream.c`
  (**155 checks** passed; `test_vfs_pack_entry.c` **61 checks** passed) across **71/71**
  native suites under `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Extended `port/recovered_types/contracts.json`
  (**141** functions, **79** globals, **15** vtables, **180** instruction witnesses),
  `scripts/test_type_recovery_contracts.py` (**49** contract tests OK on Python 3.14 & 3.15),
  clean-public Python suites, `docs/vfs_recovery.md`, `progress.md`, and `verification.json`.

### Layer 15 — Archive-Name Disposer Vtable `0x1189a434`, Base Vtable `0x11849278`, VFS Mutex/Global Map `0x112bff80`/`0x112e32b0`, & Pool Slabs (2026-11-13)

- [x] **REA Evidence Extraction (`out/vfs-layer15-20261113/`)**: Read base pack-entry
  vtable `0x11849278` (60B/15 slots + 12 xrefs) alongside `0x118976c0` (`0x112a9963`),
  recovered the `0x1189a434`/`0x1189a444` handlers (`0x112afd00`, `0x112afbf0`,
  `0x112acd70`, `0x10128c50`, `0x112afcd0`, `0x1090bb10`, `0x112acd30`, `0x112afd30`),
  VFS mutex singleton (`0x112bff80` -> `0x12032b10`), global UTF-16LE registry table
  (`0x112c02e0` / `0x112e32b0` -> `0x12032bf4`), virtual-base setting resolver
  (`0x11346530`), freelist pool singletons (`0x10106000` / `0x10106060` / `0x101060c0`),
  and `0x1c`-stride slab initializer `0x10328250` on top of
  `out/vfs-layer14-20261112/session.rea.json` (**174** validated records in closed
  `out/vfs-layer15-20261113/session.rea.json`: `152` reused Layer 14 + `22` new).
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_freelist_pool_header32`,
  `rome2_vfs_slab_descriptor32`, `rome2_vfs_archive_name_disposer32`,
  `rome2_vfs_mutex_box32`, and `rome2_vfs_global_map32` in `guest32_layouts.h`,
  implemented bounded C17 helpers in `port/recovered_types/vfs_pool_slab.h/.c`, and
  verified `test_vfs_pool_slab.c` (**45 checks** passed) across **72/72** native suites
  under `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Extended `port/recovered_types/contracts.json`
  (**154** functions, **87** globals, **16** vtables, **187** instruction witnesses),
  `scripts/test_type_recovery_contracts.py` (**50** contract tests OK on Python 3.14 & 3.15),
  clean-public Python suites, `docs/vfs_recovery.md`, `progress.md`, and `verification.json`.

### Layer 16 — Pack-Entry Site `0x112a9963`, Base Concrete Slots `0x11849278`, Quota Tracker, RB Sentinel/Recycler & Global Map Probe (2026-11-13)

- [x] **REA Evidence Extraction (`out/vfs-layer16-20261113/`)**: Resolved
  `0x112a9963` inside `0x112a9560`, recovered base vtable `0x11849278` concrete
  slot `+0x30` (`0x10f9f6e0`) + non-procedure slots (`0x10fa1340`, `0x10f9faa0`,
  `0x10f9fae0`) and vtable `0x1189a454` slot `+0x00` (`0x112afca0`), iostream
  wchar_t helpers (`0x113492c0`, `0x11347360`), per-thread VFS quota tracker
  (`0x112a45c0`), stream slice/open wrappers (`0x112aa5d0`, `0x112ba6c0`),
  `pack_props` 28B header reader (`0x112a9bc0`), root scan/mount initializer
  (`0x112b5730`), RB sentinel singleton (`0x112e3eb0`), recursive RB recycler
  (`0x10cf4d20`), and fresh `0x100d79c0` probe on top of
  `out/vfs-layer15-20261113/session.rea.json` (**195** validated records in closed
  `out/vfs-layer16-20261113/session.rea.json`: `174` reused Layer 15 + `21` new).
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_pack_header_wire32`,
  `rome2_vfs_rb_sentinel_node32`, `rome2_vfs_quota_frame32`, and
  `rome2_vfs_stream_slice_view32` in `guest32_layouts.h`, implemented checked
  C17 helpers in `port/recovered_types/vfs_quota_map.h/.c`, and verified
  `test_vfs_quota_map.c` (**25 checks** passed) across **73/73** native suites
  under `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Extended `port/recovered_types/contracts.json`
  (**164** functions, **93** globals, **17** vtables, **197** instruction witnesses),
  `scripts/test_type_recovery_contracts.py` (**51** contract tests OK on Python 3.14 & 3.15),
  clean-public Python suites, `docs/vfs_recovery.md`, `progress.md`, and `verification.json`.

### Layer 17 — Unpinned Direct VFS Callees of Root Scan, Per-Thread Quota, Stream Openers & `pack_props` (2026-11-13)

- [x] **REA Evidence Extraction (`out/vfs-layer17-20261113/`)**: Recovered all 11
  remaining unpinned direct VFS callees of Layers 12–16 (`0x112d4160`, `0x112d4c50`,
  `0x112baf90`, `0x112b5450`, `0x112a4e10`, `0x112e3db0`, `0x101f4f90`, `0x112cbe10`,
  `0x112a7ae0`, `0x112a94d0`, `0x112bb790`) plus static descriptors `0x1173f1f0` and
  `0x1173dad0` on top of `out/vfs-layer16-20261113/session.rea.json` (**208**
  validated records in closed `out/vfs-layer17-20261113/session.rea.json`: `195`
  reused Layer 16 + `13` new).
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_ref_pack_block_header32`,
  `rome2_vfs_open_bucket_map32`, `rome2_vfs_open_bucket_slot32`,
  `rome2_vfs_thread_node32`, `rome2_vfs_post_scan_table32`,
  `rome2_vfs_stream_wrap_a32`, and `rome2_vfs_stream_wrap_b32` in
  `guest32_layouts.h`, implemented checked C17 helpers in
  `port/recovered_types/vfs_scan_mount.h/.c`, and verified `test_vfs_scan_mount.c`
  (**32 checks** passed) across **74/74** native suites under `/W4 /WX /sdl /GS
  /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Extended `port/recovered_types/contracts.json`
  (**175** functions, **101** globals, **20** vtables, **204** instruction witnesses),
  `scripts/test_type_recovery_contracts.py` (**52** contract tests OK on Python 3.14 & 3.15),
  clean-public Python suites, `docs/vfs_recovery.md`, `progress.md`, and `verification.json`.

### Layer 18 — `0x1189a424` / Stream Wrapper Vtable Slots, Bucket Rehash `0x112d9e20` & `0x112bb790` Dependency Sub-Callees (2026-11-13)

- [x] **REA Evidence Extraction (`out/vfs-layer18-20261113/`)**: Recovered
  `0x1189a424` slots (`0x112afce0` tail-jump, `0x112acd50` `0x50`B scalar dtor),
  `0x118977ec`/`0x11897790` leading slots (`0x112acde0`, `0x112d8d30`,
  `0x112ad0f0`, `0x112d8e20`), bucket-map rehash helper (`0x112d9e20`), and all
  10 remaining Layer 17 non-CRT callees (`0x112a2760`, `0x112a4090`, `0x112a4b60`,
  `0x112a59c0`, `0x112a7700`, `0x112af270`, `0x112be300`, `0x112d57f0`,
  `0x112ddb30`, `0x112e3ae0`) plus vtable reads (`0x1189a424`, `0x118977ec`,
  `0x11897790`) on top of `out/vfs-layer17-20261113/session.rea.json` (**231**
  validated records in closed `out/vfs-layer18-20261113/session.rea.json`: `208`
  reused Layer 17 + `23` new).
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_dep_rb_node32` (`40`B),
  `rome2_vfs_cycle_rb_sentinel32` (`28`B), `rome2_vfs_ref_block_vtable32` (`16`B),
  and `rome2_vfs_stream_wrap_vtable_prefix32` (`32`B) in `guest32_layouts.h`,
  implemented checked C17 helpers in `port/recovered_types/vfs_dep_rehash.h/.c`,
  and verified `test_vfs_dep_rehash.c` (**23 checks** passed) across **75/75**
  native suites under `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Extended `port/recovered_types/contracts.json`
  (**188** functions, **106** globals, **20** vtables, **216** instruction witnesses),
  `scripts/test_type_recovery_contracts.py` (**53** contract tests OK on Python 3.14 & 3.15),
  clean-public Python suites, `docs/vfs_recovery.md`, `progress.md`, and `verification.json`.

### Layer 19 — Deep VFS Leaf/Mutation Sub-Callees of Layer 18 (2026-11-13)

- [x] **REA Evidence Extraction (`out/vfs-layer19-20261113/`)**: Recovered all 15
  remaining unpinned `0x112...` sub-callees of Layer 18 (`0x112a21f0`, `0x112a25b0`,
  `0x112a2810`, `0x112a3320`, `0x112a5ce0`, `0x112ab310`, `0x112ab420`,
  `0x112ac430`, `0x112afc10`, `0x112afd50`, `0x112b0070`, `0x112b41a0`,
  `0x112cd780`, `0x112d8550`, `0x112dbe10`) plus globals `0x11745c98`, `0x1177ddbc`,
  `0x1172f1f0`, `0x1172f1f4` on top of `out/vfs-layer18-20261113/session.rea.json`
  (**246** validated records in closed `out/vfs-layer19-20261113/session.rea.json`:
  `231` reused Layer 18 + `15` new).
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_stream_handle_box32` (`20`B)
  and `rome2_vfs_bucket_vec_header32` (`12`B) in `guest32_layouts.h`, implemented
  checked C17 helpers in `port/recovered_types/vfs_rb_bucket_ops.h/.c`, and verified
  `test_vfs_rb_bucket_ops.c` (**21 checks** passed) across **76/76** native suites
  under `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Extended `port/recovered_types/contracts.json`
  (**203** functions, **110** globals, **20** vtables, **224** instruction witnesses),
  `scripts/test_type_recovery_contracts.py` (**54** contract tests OK on Python 3.14 & 3.15),
  clean-public Python suites, `docs/vfs_recovery.md`, `progress.md`, and `verification.json`.

### Layer 20 — Stream-Wrapper Vtable Slots `+0x08..+0x1c` & RB Rotate/Iterator Leaves (2026-11-13)

- [x] **REA Evidence Extraction (`out/vfs-layer20-20261113/`)**: Recovered all 10
  remaining slots `+0x08..+0x1c` of stream-wrapper vtables `0x118977ec` &
  `0x11897790` (`0x10190580`, `0x100e22c0`, `0x112da9f0`, `0x112c8b80`,
  `0x112d9860`, `0x112badf0`, `0x112dab00`, `0x112c8bc0`, `0x10369160`,
  `0x112baef0`) plus the 5 RB rotate/iterator leaf helpers from Layer 19
  (`0x112a2470`, `0x112b0710`, `0x112b0760`, `0x112b0780`, `0x112b07a0`) on top of
  `out/vfs-layer19-20261113/session.rea.json` (**267** validated records in closed
  `out/vfs-layer20-20261113/session.rea.json`: `246` reused Layer 19 + `21` new =
  `9` `analyze_function` + `6` paired `resolve_containing_procedure`/`read_bytes`).
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_stream_view_box32` (`8`B),
  `rome2_vfs_stream_state_prefix32` (`16`B), and `rome2_vfs_rb_tree_head32` (`8`B)
  in `guest32_layouts.h`, implemented checked C17 helpers in
  `port/recovered_types/vfs_stream_wrap_ops.h/.c`, and verified
  `test_vfs_stream_wrap_ops.c` (**18 checks** passed) across **77/77** native
  suites under `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Extended `port/recovered_types/contracts.json`
  (**218** functions, **110** globals, **20** vtables, **233** instruction witnesses),
  `scripts/test_type_recovery_contracts.py` (**55** contract tests OK on Python 3.14 & 3.15),
  clean-public Python suites, `docs/vfs_recovery.md`, `progress.md`, and `verification.json`.

### Layer 21 — Deferred VFS Sub-Callees, Stream-Wrapper Open Slots & Ref-Block Destructors (2026-11-14)

- [x] **REA Evidence Extraction (`out/vfs-layer21-20261114/`)**: Recovered all 13 Layer 21 VFS procedures and virtual slots (`0x112a2660`, `0x112a2910`, `0x112a3ee0`, `0x112ac1a0`, `0x112accd0`, `0x112acd50`, `0x112acd70`, `0x112be350`, `0x112c0c60`, `0x112cd4c0`, `0x112d8c50`, `0x112d8d30`, `0x112d8e20`) on top of `out/vfs-layer20-20261113/session.rea.json`, closing `out/vfs-layer21-20261114/session.rea.json` (`281` validated evidence records = `267` Layer 20 + `14` net new unique evidence IDs across `18` retained envelopes: `8` `analyze_function` + `5` `resolve_containing_procedure` + `5` `read_bytes` length=320). Verified `0x112a2910` has a `1`B `0x90` NOP gap at `0x112a2a1f`.
- [x] **Layouts & Native C17 Helpers**: Locked 4 fixed-width guest32 structs (`rome2_vfs_adj_hash_node32` 36B, `rome2_vfs_recursive_mutex_prefix32` 8B, `rome2_vfs_u32_ptr_vec32` 12B, `rome2_vfs_flag_chain_node32` 8B) in `port/recovered_types/guest32_layouts.h`, implemented 7 checked helpers (`rome2_vfs_adj_hash_can_allocate32`, `rome2_vfs_decode_adj_hash_node32`, `rome2_vfs_u32_vec_plan_push32`, `rome2_vfs_state_wait_plan32`, `rome2_vfs_stream_wrap_check_open_reentry32`, `rome2_vfs_clear_flag_chain_bounded`, `rome2_vfs_ref_block_delete_size32`) in `port/recovered_types/vfs_adj_open_ops.h/.c`, and verified **20 checks** in `test_vfs_adj_open_ops.c` plus **78/78** native suites on `/W4 /WX /sdl /GS /guard:cf /analyze` (`5.84s`) and ASan (`5.61s`) with zero warnings.
- [x] **Contracts, Docs & Public-Clean Parity**: Pinned **231 functions, 113 globals, 20 vtables, and 241 instruction witnesses** in `port/recovered_types/contracts.json`, added `test_adj_hash_stream_open_and_ref_dtor_contracts` and `"112a2910": [1]` gap verification to `scripts/test_type_recovery_contracts.py` (**56** contract tests passing on Python 3.14 & 3.15), verified **884** public tests (`284` skipped) in clean checkout on Python 3.14 & 3.15, updated `docs/vfs_recovery.md` and `port/recovered_types/verification.json` (`layer21`, `82` source identities), and committed cleanly.

### Layer 22 — Stream Handle-Box & View-Map Callees, Pack-Entry Vtable `0x118976c0` Completion & Ref-Block Destructors (2026-11-14)

- [x] **REA Evidence Extraction (`out/vfs-layer22-20261114/`)**: Recovered all 16 Layer 22 targets (`0x112afb90`, `0x101d9910`, `0x116835d7`, `0x112a7860`, `0x10102f90`, `0x112e1830`, `0x10e13a60`, `0x10115900`, `0x112ad1b0`, `0x112d3270`, `0x112e0d80`, `0x112c9540`, `0x112afd00`, `0x112accf0`, `0x112acd10`, `0x112acd30`) over `out/vfs-layer21-20261114/session.rea.json` (`302` closed/validated records = `281` reused Layer 21 + `18` primary new IDs [`7` direct `analyze_function`, `1` `fn-116835d7-bundle-record.json`, `8` `read_bytes(768)`, `2` new `resolve_containing_procedure`] + `3` `inspect_analysis_view` extras for `0x116835d7`, with `6` resolve IDs reused from Layer 18).
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_state_ref_block32` (`44`B), `rome2_vfs_pack_telemetry_mgr32` (`108`B), and `rome2_vfs_pack_vtable_76c0_prefix32` (`40`B) with `_Static_assert` checks in [guest32_layouts.h](port/recovered_types/guest32_layouts.h); implemented bounded helpers in [vfs_view_map_ops.h](port/recovered_types/vfs_view_map_ops.h) / [vfs_view_map_ops.c](port/recovered_types/vfs_view_map_ops.c) with **21 checks** passing in [test_vfs_view_map_ops.c](port/recovered_types/test_vfs_view_map_ops.c) and **79/79** CTest suites passing on `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Pinned **247 functions, 119 globals, 24 vtables, and 253 instruction witnesses** in [contracts.json](port/recovered_types/contracts.json) (`rea_layer22_evidence`), verified **57** contract tests on Python 3.14 and 3.15, updated [vfs_recovery.md](docs/vfs_recovery.md), verified **885** clean-public Python tests (`285` skipped) on Python 3.14 and 3.15, and locked **85** normalized source hashes in [verification.json](port/recovered_types/verification.json).

### Layer 23 — Stream-State Inner Vtables `0x118977bc`–`0x118977e0`, Async View-Map / Page-Prefetch / Heap-Free Callees & Pack Telemetry Vtable `0x118976a4` Completion (2026-11-14)

- [x] **REA Evidence Extraction (`out/vfs-layer23-20261114/`)**: Recovered all 21 VFS procedures and virtual slots (`0x112acd90`, `0x112ad140`, `0x112acfe0`, `0x112bade0`, `0x112baf00`, `0x112d9640`, `0x112d97f0`, `0x112c0300`, `0x112d91c0`, `0x10115730`, `0x10115940`, `0x100fcc50`, `0x112d36f0`, `0x100e80b0`, `0x112badd0`, `0x10299640`, `0x10497c50`, `0x112e1780`, `0x112e17e0`, `0x112e1960`, `0x112e19b0`) on top of `out/vfs-layer22-20261114/session.rea.json`, closing `out/vfs-layer23-20261114/session.rea.json` (`336` validated records: `302` reused from Layer 22 + `31` new primary + `3` view records).
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_state_ref_block28_32`, `rome2_vfs_state_inner_listener28_32`, `rome2_vfs_sys_info32`, and `rome2_vfs_pack_vtable_76a4_32` in `guest32_layouts.h`, implemented 9 checked C17 helpers in `port/recovered_types/vfs_state_telemetry_ops.h/.c`, and verified **21 checks** (`test_vfs_state_telemetry_ops.c`) plus **80/80** suites on `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Pinned **268 functions, 131 globals, 28 vtables, and 270 instruction witnesses** in `contracts.json`, expanded `scripts/test_type_recovery_contracts.py` to **58** passing contract tests on Python 3.14 and 3.15, updated `docs/vfs_recovery.md` and `verification.json` (`88` source identities), and verified **886** public Python tests (`286` skipped) on clean checkouts of Python 3.14 and 3.15.

### Layer 24 — Stream Cipher/Cache/Worker/Tagged-Alloc/CRT-64 Callees & Pack/Stream/Ref-Block Vtable Tail Completion (2026-11-14)

- [x] **REA Evidence Extraction (`out/vfs-layer24-20261114/`)**: Recovered all 22 VFS procedures and virtual slots (`0x100fa6d0`, `0x100fcfd0`, `0x100f19f0`, `0x100ff8c0`, `0x112b3270`, `0x112b2f40`, `0x100fcc80`, `0x11684200`, `0x11684270`, `0x112d9890`, `0x112d2900`, `0x112d0bd0`, `0x112dd2f0`, `0x112c0090`, `0x112c0c40`, `0x1018ad20`, `0x108b2600`, `0x112b3190`, `0x101a0430`, `0x105cd140`, `0x112b30b0`, `0x1090b600`) on top of `out/vfs-layer23-20261114/session.rea.json`, closing `out/vfs-layer24-20261114/session.rea.json` (`367` validated records: `336` reused from Layer 23 + `31` new IDs across `28` primary + `3` view records; `3` reused resolve IDs from Layers 13/14).
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_open_cache_entry16_32`, `rome2_vfs_async_worker_ref_block56_32`, `rome2_vfs_stream_vtable_11slot32`, and `rome2_vfs_pack_vtable_76c0_full32` in `guest32_layouts.h`, implemented 13 checked C17 helpers in `port/recovered_types/vfs_stream_completion_ops.h/.c`, and verified **21 checks** (`test_vfs_stream_completion_ops.c`) plus **81/81** suites on `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Pinned **290 functions, 145 globals, 29 vtables, and 286 instruction witnesses** in `contracts.json`, expanded `scripts/test_type_recovery_contracts.py` to **59** passing contract tests on Python 3.14 and 3.15, updated `docs/vfs_recovery.md` and `verification.json` (`91` source identities), and verified **887** public Python tests (`287` skipped) on clean checkouts of Python 3.14 and 3.15.

### Layer 25 — Win32 Handle/Semaphore Lifecycle, `std::bad_alloc`, Intrusive Queue Teardown & Pack Sub-Vtables `0x11897be0` / `0x11897c24` / `0x11897c44` (2026-11-14)

- [x] **REA Evidence Extraction (`out/vfs-layer25-20261114/`)**: Opened a clean **48-record** REA partition snapshot (`session.rea.json`, `13` primitive entries; `validated-evidence-bundle.json` `49,807,427` bytes) to avoid V8's `536,870,888`-byte JS string ceiling hit past Layer 24 (`532,429,932` bytes), while retaining `cumulative-validated-evidence-bundle.json` (`415` records). Recovered all **24 functions** (`13` direct `analyze_function`, `3` `resource_constraint` bundle records + `9` `inspect_analysis_view` calls, `8` `invalid_request` -> `8` `resolve_containing_procedure` + `8` `read_bytes`), **7** extra `read_bytes` records (`39` unique evidence items in `contracts.json["rea_layer25_evidence"]`), **10 globals**, **2 vtables** (`0x11741d78`, `0x11897c44`), and **16 instruction witnesses**.
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_win32_handle_box8_32` (`8`B), `rome2_vfs_open_file_mapping16_32` (`16`B), `rome2_vfs_bad_alloc_exc8_32` (`8`B), `rome2_vfs_pack_vtable_7be0_17slot32` (`68`B), and `rome2_vfs_pack_vtable_7c44_8slot32` (`32`B) in `port/recovered_types/guest32_layouts.h`, implemented **15** checked C17 helpers plus the mockable `rome2_vfs_win32_handle_ops` interface in `port/recovered_types/vfs_handle_lifecycle_ops.h/.c`, and verified **21 checks** in `test_vfs_handle_lifecycle_ops.c` across **82/82** native CTest suites on `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Pinned **314 functions, 155 globals, 31 vtables, and 302 instruction witnesses** in `contracts.json`, expanded `scripts/test_type_recovery_contracts.py` to **60** passing contract tests on Python 3.14 and 3.15, updated `docs/vfs_recovery.md` and `verification.json` (`94` source identities), and verified **888** public Python tests (`288` skipped) on clean checkouts of Python 3.14 and 3.15.

### Layer 26 — VFS Loose-Entry (`0x11897710`), Pack Wrapper (`0x11897760`), Buffered Substream (`0x11897c24`), and `std::exception` (`0x11741d58` / `0x11741d78`) Completion (2026-11-14)

- [x] **REA Evidence Extraction & Cumulative Validation**: Extended the clean 48-record Layer 25 REA snapshot (`out/vfs-layer25-20261114/session.rea.json`) to close `out/vfs-layer26-20261114/session.rea.json` (`95` evidence records = `48` reused + `47` new: `20` direct `analyze_function`, `10` `invalid_request` targets paired with `10` `resolve_containing_procedure` + `10` `read_bytes(length=320)`, and `7` extra `read_bytes` calls) and merged canonically via `import_evidence_bundle` + `rea evidence-export` into `out/vfs-layer26-20261114/cumulative-validated-evidence-bundle.json` (`462` validated records) outside Git, recovering **30 functions**, **8 globals**, **3 vtables** (`0x11897760` -> `0x112ace20`, `0x11897c24` -> `0x112ad6a0`, `0x11741d58` -> `0x100f3820`), and **16 instruction witnesses**.
- [x] **Bounded Guest32 Layouts & C17 Implementation**: Added 6 `_Static_assert`-checked guest32 structs (`rome2_vfs_loose_file_entry32` `32`B, `rome2_vfs_buffered_substream40_32` `40`B, `rome2_vfs_file_stat20_32` `20`B, `rome2_vfs_loose_vtable_7710_20slot32` `80`B, `rome2_vfs_pack_wrap_vtable_7760_12slot32` `48`B, and `rome2_vfs_substream_vtable_7c24_8slot32` `32`B) to `port/recovered_types/guest32_layouts.h` and implemented **15** checked C17 helpers (`rome2_vfs_close_handle_bool_6fd0`, `rome2_vfs_create_file_flags_4cc0`, `rome2_vfs_file_stat20_zero_fda0`, `rome2_vfs_aligned16_or_memcpy_43d0`, `rome2_vfs_std_exception_what_5df0`, `rome2_vfs_loose_entry_clamp_window_0d20`, `rome2_vfs_loose_entry_teardown_handles_aa40`, `rome2_vfs_loose_vtable_7710_matches`, `rome2_vfs_pack_wrap_vtable_7760_matches`, `rome2_vfs_pack_wrap_flag_bit6_9520`, `rome2_vfs_substream_vtable_7c24_matches`, `rome2_vfs_substream_can_read_8c40`, `rome2_vfs_substream_refresh_eof_57d0`, `rome2_vfs_substream_advance_0cf0`, and `rome2_vfs_substream_rewind_c1a0`) in `port/recovered_types/vfs_substream_loose_ops.h` and `port/recovered_types/vfs_substream_loose_ops.c`.
- [x] **Native CTest Gate (`/analyze` & ASan)**: Added `port/recovered_types/test_vfs_substream_loose_ops.c` (`22 checks passed (0 failures)`) to `port/recovered_types/CMakeLists.txt` and passed **83/83** CTest suites on both `/W4 /WX /analyze` and AddressSanitizer builds.
- [x] **Contracts, Docs & Public-Clean Parity**: Pinned **344 functions, 163 globals, 34 vtables, and 318 instruction witnesses** in `contracts.json`, expanded `scripts/test_type_recovery_contracts.py` to **61** passing contract tests on Python 3.14 and 3.15, updated `docs/vfs_recovery.md` and `verification.json` (`97` source identities), and verified **889** public Python tests (`289` skipped) on clean checkouts of Python 3.14 and 3.15.

### Layer 27 — VFS Dual-Slot View (`0x11897818`), Cipher-Memory View (`0x11897844`), Delegating Stream Adapter (`0x11897c90`), and Loose-File Stat/Path/String Helpers (2026-11-15)

- [x] **REA Evidence Extraction & Cumulative Validation**: Extended the Layer 26 95-record REA snapshot (`out/vfs-layer26-20261114/session.rea.json`) to close `out/vfs-layer27-20261115/session.rea.json` (`156` evidence records = `95` reused + `61` new: `18` direct `analyze_function`, `2` `resource_constraint` bundle records `0x100f1720` / `0x100f3090` + `6` `inspect_analysis_view` view records, `10` `invalid_request` targets paired with `10` `resolve_containing_procedure` + `10` `read_bytes(length=320)`, and `15` extra `read_bytes` calls) and merged canonically via `import_evidence_bundle` + `rea evidence-export` into `out/vfs-layer27-20261115/cumulative-validated-evidence-bundle.json` (`523` validated records) outside Git, recovering **30 functions**, **6 globals**, **3 vtables** (`0x11897818` -> `0x112ad210`, `0x11897844` -> `0x112ace20`, `0x11897c90` -> `0x112ad1e0`), and **20 instruction witnesses**.
- [x] **Bounded Guest32 Layouts & C17 Implementation**: Added 5 `_Static_assert`-checked guest32 structs (`rome2_vfs_dual_slot_entry32` `16`B, `rome2_vfs_dual_slot_view32` `84`B, `rome2_vfs_cipher_mem_view32` `32`B, `rome2_vfs_stream_delegate_adapter32` `20`B, and `rome2_vfs_file_stat32` `16`B) to `port/recovered_types/guest32_layouts.h` and implemented **24** bounded C17 helpers (`rome2_vfs_dual_slot_entry_zero_init`, `rome2_vfs_dual_slot_view_init`, `_destroy`, `_has_active_task`, `_is_active_task_ready`, `_active_remaining_bytes`, `_has_active_refs`, `_release_ref`, `_is_window_cache_miss`, `_map_and_prefetch`, `rome2_vfs_cipher_mem_view_init`, `_inc_ref`, `_dec_ref`, `_is_valid`, `_is_ready`, `_install_buffer`, `_get_buffer`, `rome2_vfs_stream_delegate_adapter_init_base`, `_init`, `_destroy`, `_query_interface`, `_resolve_thunk_target`, `rome2_vfs_file_stat32_from_mode_and_meta`, and `rome2_vfs_widen_ascii_to_utf16`) in `port/recovered_types/vfs_stream_mux_async_ops.h` and `port/recovered_types/vfs_stream_mux_async_ops.c`.
- [x] **Native CTest Gate (`/analyze` & ASan)**: Added `port/recovered_types/test_vfs_stream_mux_async_ops.c` (`vfs_stream_mux_async_ops_tests: 3 suites passed (0 failures)`, `129` `CHECK` evaluations) to `port/recovered_types/CMakeLists.txt` and passed **84/84** CTest suites on both `/W4 /WX /analyze` and AddressSanitizer builds.
- [x] **Contracts, Docs & Public-Clean Parity**: Pinned **374 functions, 169 globals, 37 vtables, and 338 instruction witnesses** in `contracts.json`, expanded `scripts/test_type_recovery_contracts.py` to **62** passing contract tests on Python 3.14 and 3.15, updated `docs/vfs_recovery.md` and `verification.json` (`100` source identities), and verified **890** public Python tests (`290` skipped) on clean checkouts of Python 3.14 and 3.15.


### Layer 28 — Base VFS FileSystem, `_Ref_count_base` & Active Secondary Interface (`0x1189791c`, `0x11897994`, `0x1189a520`, `0x118978e8`) (2026-11-15)
- Extended the closed Layer 27 REA session (`156` reused records) to `216`
  validated records (`60` net new across `15` direct `analyze_function`
  calls, `1` `resource_constraint` procedure `0x1018bd90` + `3`
  `inspect_analysis_view` records, `14` `invalid_request` fallback pairs,
  and `13` `read_bytes(length=128)` global/helper anchors) and merged via
  `import_evidence_bundle` + `rea evidence-export` into the `583`-record
  canonical cumulative bundle outside Git (`out/vfs-layer28-20261115/`).
- Recorded **30** Layer 28 procedures, **17** globals, **2** vtables
  (`0x1189791c` -> `0x100f3d00`, `0x1189a520` -> `0x112afc90`), and **22**
  instruction witnesses in `port/recovered_types/contracts.json`, bringing
  totals to **404 functions, 186 globals, 39 vtables, and 360 instruction
  witnesses** (`rea_layer28_evidence`).
- Locked 10 `_Static_assert`-verified guest32 layouts (`8B`–`120B`) in
  `port/recovered_types/guest32_layouts.h` and implemented 15 checked C17
  models in `port/recovered_types/vfs_fs_secondary_ops.h/.c` (including
  `< pack_count` vs `0x80000001..[0x119e1000]` handle classification,
  `_Ref_count_base` strong/weak release, encrypted whole-file XOR decipher,
  quota telemetry accounting, platform gate, and `0x112e3480` doubly-linked
  node unlink) tested by 78 `CHECK`s across 3 suites in
  `port/recovered_types/test_vfs_fs_secondary_ops.c`.
- Verified **85/85** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **63** contract tests on Python 3.14 and 3.15, and **891** clean-public Python
  tests (**291** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; active primary FileSystem interface
  `0x11897870` (`28` slots) and live runtime threading remain open.

### Layer 29 — Active VFS FileSystem primary interface and TLS vector helpers (2026-11-15)

Target: active VFS FileSystem primary interface (`0x11897870`, all `30/30` slots)
and directly coupled TLS singleton / vector helpers.

- Extended the closed Layer 28 REA session (`216` reused records) to `279`
  validated session records (`63` new: `12` direct `analyze_function`
  procedures, `20` `invalid_request` targets backed by `20`
  `resolve_containing_procedure` + `20` `read_bytes(length=320)`, and `11`
  extra `read_bytes` records) and merged canonically via `import_evidence_bundle`
  and `rea evidence-export` into the **646-record** cumulative validated bundle
  retained outside Git.
- Pinned **32** functions, **17** globals, **1** vtable (`0x11897870` ->
  `0x112beac0`), and **23** instruction witnesses in
  [contracts.json](port/recovered_types/contracts.json) under
  `rea_layer29_evidence`, raising totals to **436** functions, **203** globals,
  **40** vtables, and **383** instruction witnesses; closed all `30/30` slots
  of `0x11897870` (`26` new RET-bearing slots, `2` prior contracts
  `0x100f3d00`/`0x112c9550`, and `2` tail-jump thunks `0x112beac0`/`0x112b0870`)
  plus `6` TLS singleton / vector helpers (`0x112beb10`, `0x100eb330`,
  `0x112d30c0`, `0x112bcf00`, `0x112bbca0`, `0x112e3c60`).
- Locked `5` fixed-width `guest32` structs in
  [guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_active_fs_obj32` `40`B, `rome2_vfs_mount_vec_header12_32` `12`B,
  `rome2_vfs_root_archive_header20_32` `20`B, `rome2_vfs_loose_table12_32` `12`B,
  `rome2_vfs_large_hash16_32` `16`B) and added checked C17 helpers and `65`
  checks in [vfs_fs_primary_ops.h](port/recovered_types/vfs_fs_primary_ops.h),
  [vfs_fs_primary_ops.c](port/recovered_types/vfs_fs_primary_ops.c), and
  [test_vfs_fs_primary_ops.c](port/recovered_types/test_vfs_fs_primary_ops.c).
- Verified **86/86** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **64** contract tests on Python 3.14 and 3.15, and **892** clean-public Python
  tests (**292** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining sweep/cleanup helpers
  (`0x112d5cc0`, `0x112e1a00`, `0x112d4de0`, `0x112cfc10`, `0x112da500`) and
  live runtime threading remain open.

### Layer 30 — VFS mount rebuild, teardown, hash-container and probe callees (2026-11-15)

Target: active VFS FileSystem mount-rebuild, flush, teardown (`WaitForSingleObject`),
open-address hash container, vector push/copy, and command-line/capability probe
callees.

- Extended the closed Layer 29 REA session (`279` reused records) to `324`
  validated session records (`45` new: `29` direct `analyze_function`
  procedures, `1` `invalid_request` target `0x112e3f20` paired with
  `resolve_containing_procedure` + `read_bytes(length=320)`, and `14` extra
  `read_bytes(length=64)` records) and merged canonically via
  `import_evidence_bundle` and `rea evidence-export` into the **691-record**
  cumulative validated bundle retained outside Git.
- Pinned **30** functions, **22** globals, and **24** instruction witnesses in
  [contracts.json](port/recovered_types/contracts.json) under
  `rea_layer30_evidence`, raising totals to **466** functions, **225** globals,
  **40** vtables, and **407** instruction witnesses.
- Locked `6` fixed-width `guest32` structs in
  [guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_hash_entry8_32` `8`B, `rome2_vfs_open_hash16_32` `16`B,
  `rome2_vfs_hash_iter20_32` `20`B, `rome2_vfs_unordered_map32_32` `32`B,
  `rome2_vfs_rbtree_header12_32` `12`B, `rome2_vfs_mount_entry48_32` `48`B) and
  added checked C17 helpers and `79` checks in
  [vfs_fs_mount_ops.h](port/recovered_types/vfs_fs_mount_ops.h),
  [vfs_fs_mount_ops.c](port/recovered_types/vfs_fs_mount_ops.c), and
  [test_vfs_fs_mount_ops.c](port/recovered_types/test_vfs_fs_mount_ops.c).
- Verified **87/87** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **65** contract tests on Python 3.14 and 3.15, and **893** clean-public Python
  tests (**293** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; VFS pack-index singleton (`0x10122cb0`),
  `0x100fec00` directory traversal, atexit destructors, and live runtime
  threading remain open.

### Layer 31 — VFS pack-entry index, Win32 traversal, container/rehash ops, diagnostics & 10 atexit destructors (2026-11-15)
- Closed **31 additional VFS functions, 15 globals, and 27 instruction
  witnesses** (`rea_layer31_evidence` -> **497 functions, 240 globals,
  40 vtables, 434 instruction witnesses**; **376** closed Layer 31 session
  records / **743** canonical cumulative validated bundle records) covering:
  - Pack-entry index singletons & prefix resolution (`0x10122cb0`, `0x10122640`,
    `0x101217e0`, `0x10121c40`, `0x10122260`, `0x10122380`, `0x10122d70`,
    `0x10121d80` wildcard matcher, `0x10121250`).
  - Win32 recursive `FindFirstFileA`/`FindNextFileA`/`FindClose` traversal
    (`0x100fec00`) with exact `FILETIME` `+0x49ef7d10` (`3600`s offset) conversion
    and writable/dir/hidden attribute decoding.
  - Container destructors, `unordered_map::_Rehash` (`0x112b03b0`, `0x3fffffff`
    ceiling), self-aliased vector `push_back` (`0x112d7b40`, `0x100eaf40`),
    interface/bitmask diagnostics (`0x112c2370`, `0x112a5530`, `0x112a56d0`,
    `0x112f0b90`), and all 10 RET-bearing VFS singleton atexit destructors
    (`0x11724a10`..`0x11724e50`).
- Locked **5** fixed-width `guest32` structs in
  [guest32_layouts.h](port/recovered_types/guest32_layouts.h) and added checked
  C17 helpers and **50** tests in
  [vfs_fs_index_atexit_ops.h](port/recovered_types/vfs_fs_index_atexit_ops.h),
  [vfs_fs_index_atexit_ops.c](port/recovered_types/vfs_fs_index_atexit_ops.c),
  and [test_vfs_fs_index_atexit_ops.c](port/recovered_types/test_vfs_fs_index_atexit_ops.c).
- Verified **88/88** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **66** contract tests on Python 3.14 and 3.15, and **894** clean-public Python
  tests (**294** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; Layer 32 (`0x1011fef0` pack-index ctor,
  `0x10120b30`/`0x10120c10` locked entry builders, remaining `0x112a..0x1130`
  VFS callees) and live runtime threading remain open.

### Layer 32 — VFS bootstrap initialization, path interning, XML save dispatch & string/handle primitives (2026-11-15)
- Closed **32 additional VFS functions, 22 globals, and 24 instruction
  witnesses** (`rea_layer32_evidence` -> **529 functions, 262 globals,
  40 vtables, 458 instruction witnesses**; **423** closed Layer 32 session
  records / **790** canonical cumulative validated bundle records) covering:
  - Pack-entry bootstrap (`0x1011fef0`) choosing retail `\data\` (`data\boot.pack`)
    or 6 working-data paths, plus `CRITICAL_SECTION`-locked (`0x10122dc0`, spin
    `0x2710`) 32B path-interning (`0x10121930`, `0x101225a0` `<empty_file_name>`,
    `0x10120b30`, `0x10120c10`).
  - All 14 remaining RET-bearing `0x112a..0x1130` VFS callees (`0x112a4690`
    thread budget, `0x112a85e0`..`0x112aa710` observers, `0x112acec0`,
    `0x112b0880`, `0x112c2190`/`c21f0`, `0x112c5460` 5491B XML save switch,
    `0x112cc200`, `0x112ce950`, `0x112d3640`, `0x11300140` mod banner).
  - Win32 file/handle and `CA_ASCIIString` primitives (`0x100ff880`,
    `0x100ff8e0`, `0x100ff8f0`, `0x100f1a50`, `0x100f2530`, `0x100f2ad0`,
    `0x100f2c40`, `0x100f2de0`, `0x100f6ea0`, `0x100f6ee0`, `0x100f70f0`,
    `0x1017fc90`).
- Locked **5** fixed-width `guest32` structs in
  [guest32_layouts.h](port/recovered_types/guest32_layouts.h) and added checked
  C17 helpers and **46** tests in
  [vfs_fs_init_xml_pack_ops.h](port/recovered_types/vfs_fs_init_xml_pack_ops.h),
  [vfs_fs_init_xml_pack_ops.c](port/recovered_types/vfs_fs_init_xml_pack_ops.c),
  and [test_vfs_fs_init_xml_pack_ops.c](port/recovered_types/test_vfs_fs_init_xml_pack_ops.c).
- Verified **89/89** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **67** contract tests on Python 3.14 and 3.15, and **895** clean-public Python
  tests (**295** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; Layer 33 (`0x10126e50..0x10127c00` 60B
  folder-entry tree & `0x112aa800..0x112e4050` VFS helpers) and live runtime
  execution remain open.

### Layer 33 — VFS folder-tree, path-normalization & unit-switch reconstruction (2026-11-16)
- Added 4 fixed-width guest32 folder-tree/path/slab layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_folder_tree_ops.h](port/recovered_types/vfs_fs_folder_tree_ops.h),
  [port/recovered_types/vfs_fs_folder_tree_ops.c](port/recovered_types/vfs_fs_folder_tree_ops.c),
  and [port/recovered_types/test_vfs_fs_folder_tree_ops.c](port/recovered_types/test_vfs_fs_folder_tree_ops.c)
  (**33** checks) closing 6 remaining `0x112a..0x112e` VFS helpers (`0x112aa800`,
  `0x112cbff0`, `0x112d6a10`, `0x112da2d0`, `0x112dc5e0`, `0x112e4050` unit tag
  switch `1..0xd` via `0x112e4188`), `0x10126e50..0x10127c00` recursive 60B
  folder tree & tab/newline KV parser, `0x10120e10`/`0x10122760`/`0x10122830`
  path normalizers, `0x1011f7c0`/`0x1011fd40`/`0x1011fea0`/`0x1011f6e0` slab &
  unordered_map limit helpers, `0x10103ec0`/`0x100f26b0`/`0x100f2750` UTF-8/UTF-16
  codecs, `0x100fce00` (`GetCurrentDirectoryA`), and `0x100f0a80` (split_path48).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  to **557 functions**, **281 globals**, **40 vtables**, and **482 instruction
  witnesses**, backed by **32** retained Layer 33 REA operation records (**455**
  closed Layer 33 records, **822** cumulative validated bundle records, zero
  non-proc or resource-constrained slots).
- Verified **90/90** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **68** contract tests on Python 3.14 and 3.15, and **896** clean-public Python
  tests (**296** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; the remaining **20** RET-bearing
  `0x100f..0x1012` leaves and live runtime execution remain open.

### Layer 34 — Final `0x100f..0x1012` leaves, error switches & `dlmalloc` reconstruction (2026-11-16)
- Added 3 fixed-width guest32 handle/dlmalloc layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_leaf_codec_ops.h](port/recovered_types/vfs_fs_leaf_codec_ops.h),
  [port/recovered_types/vfs_fs_leaf_codec_ops.c](port/recovered_types/vfs_fs_leaf_codec_ops.c),
  and [port/recovered_types/test_vfs_fs_leaf_codec_ops.c](port/recovered_types/test_vfs_fs_leaf_codec_ops.c)
  (**31** checks) closing 100% of the remaining **20** RET-bearing
  `0x100f..0x1012` leaves (`0x10124e50` `dlfree` & `0x101254a0` `dlmalloc` on
  `0x11afa700`, `0x101021b0` & `0x101030d0` Win32 error LUT switches,
  `0x101145e0` slash/case canonicalizer, `0x10115050` `SetFilePointerEx`,
  `0x101153c0` `GetFileSize`, `0x100f11b0`/`0x100f21c0` stream handle36
  lifecycle, `0x10114420` wait/event guard, `0x10102310` 64-bit budget check,
  `0x10103450` UTF-8 bridge, and UTF-16/ASCII string helpers).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  to **577 functions**, **295 globals**, **40 vtables**, and **504 instruction
  witnesses**, backed by **26** retained Layer 34 REA operation records (**481**
  closed Layer 34 records, **848** cumulative validated bundle records, zero
  non-proc or resource-constrained slots).
- Verified **91/91** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **69** contract tests on Python 3.14 and 3.15, and **897** clean-public Python
  tests (**297** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining unrecovered `0x100d..0x1018` /
  `0x112a..0x112e` internal callees (Layer 35) and live runtime execution
  remain open.

### Layer 35 — UTF-16/ASCII formatters, math `vector`/`euler` codecs, telemetry & tuple/hash vector ops (2026-11-16)
- Added 3 fixed-width guest32 memory/vector layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_codec_vec_ops.h](port/recovered_types/vfs_fs_codec_vec_ops.h),
  [port/recovered_types/vfs_fs_codec_vec_ops.c](port/recovered_types/vfs_fs_codec_vec_ops.c),
  and [port/recovered_types/test_vfs_fs_codec_vec_ops.c](port/recovered_types/test_vfs_fs_codec_vec_ops.c)
  (**30** checks) closing **24** remaining RET-bearing `0x100ef..0x1017ff`
  internal callees plus **12** clean `0x112a..0x112e` math/vector/hash/tuple
  helpers (`0x112bed30..0x112e49b0` `euler`/`vector` formatters, `0x112d8ae0`
  36B 3-string tuple vector & `0x1017ff40` 44B descriptor cleanup, `0x100fcb80`
  worker thread launcher/LUT `0x1174108c`, `0x10103220`/`0x101015c0`/`0x101034b0`
  `GlobalMemoryStatusEx`/`GetModuleFileNameW`/`OutputDebugStringW` telemetry,
  `0x10100620`/`0x101007b0` u32 & `_ecvt_s` decimal formatters, `0x101207a0`/
  `0x112da050` hash rehash, `0x10122b50` two-pass dot normalizer, and UTF-16/ASCII
  format scanner/fill helpers).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  to **613 functions**, **311 globals**, **40 vtables**, and **540 instruction
  witnesses**, backed by **46** retained Layer 35 REA operation records (**527**
  closed Layer 35 records, **894** cumulative validated bundle records, zero
  non-proc or resource-constrained slots).
- Verified **92/92** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **70** contract tests on Python 3.14 and 3.15, and **898** clean-public Python
  tests (**298** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining unrecovered `0x100d..0x1013` /
  `0x112b..0x1136` internal callees (Layer 36+) and live runtime execution
  remain open.

### Layer 36 — `dlmalloc` internals, `12B` bucket vectors, `wstringstream`/`num_get`, and stream/hash leaves (2026-11-16)
- Added 3 fixed-width guest32 allocator/bucket/iterator layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_dlmalloc_stream_ops.h](port/recovered_types/vfs_fs_dlmalloc_stream_ops.h),
  [port/recovered_types/vfs_fs_dlmalloc_stream_ops.c](port/recovered_types/vfs_fs_dlmalloc_stream_ops.c),
  and [port/recovered_types/test_vfs_fs_dlmalloc_stream_ops.c](port/recovered_types/test_vfs_fs_dlmalloc_stream_ops.c)
  (**36** checks) closing all **24** remaining clean `0x100d..0x1012` &
  `dlmalloc` internal helpers plus **10** `0x112b..0x1136` hash-bucket/wostream/
  `num_get`/handle-table helpers (`0x10123640..0x101246f0` `mparams28`,
  `sys_trim`, `tmalloc_large`/`tmalloc_small`, `release_unused_segments`, and
  `SleepEx` spin backoff; `0x100d2740`/`0x100d3790`/`0x11346070..0x11349f00`
  `wstringstream`/`wostream` & wchar `_Getifld` parser; `0x100e3950..0x100ec450`
  & `0x112d87a0..0x112dbf20` `12B` bucket vector ops; `0x100db960`/`0x100e10c0`/
  `0x113682d0` hashes; `0x100f6f30` `VFileStream::close`; and `0x100d1790`/
  `0x100f3150`/`0x100ffbb0`/`0x10105fa0`).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  to **647 functions**, **324 globals**, **40 vtables**, and **574 instruction
  witnesses**, backed by **39** retained Layer 36 REA operation records + **3**
  view facets for `0x100e10c0` (**569** closed Layer 36 records, **936**
  cumulative validated bundle records, `non_proc_slots=[]`,
  `resource_constrained_slots=["100e10c0"]`).
- Verified **93/93** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **71** contract tests on Python 3.14 and 3.15, and **899** clean-public Python
  tests (**299** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining **22** clean `0x1023..0x1103`
  engine callees (Layer 37) and live runtime execution remain open.

### Layer 37 — Engine container, allocator, UTF-16 stream & channel bit-stream ops (2026-11-16)
- Added 3 fixed-width guest32 refcount/bit-cursor/channel layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_channel_ops.h](port/recovered_types/vfs_fs_engine_channel_ops.h),
  [port/recovered_types/vfs_fs_engine_channel_ops.c](port/recovered_types/vfs_fs_engine_channel_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_channel_ops.c](port/recovered_types/test_vfs_fs_engine_channel_ops.c)
  (**31** checks) closing all **22** remaining clean single-part RET-bearing
  direct callees across `0x1023..0x1103` (`0x10238c90` UTF-16 `%l` scanner,
  `0x1036a710`/`0x10ca9010`/`0x10d82640` hash-table `emplace`, `0x1039db80`
  `_Ref_count_base::_Decref`, `0x10524c30` STL `>=0x1000` aligned unalign,
  `0x1075c5a0` `24B` slab links, `0x107c9080` RB-tree inorder successor,
  `0x107e0650` string range find, `0x108bfc70`/`0x108c0510`/`0x1103d530`
  `12B` bucket vector ops, `0x10cb03c0` `u16`-prefixed UTF-16LE reader, and
  `0x10f78370..0x10fd9660` 20-slot channel & bit-stream encoder).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  to **669 functions**, **325 globals**, **40 vtables**, and **596 instruction
  witnesses**, backed by **23** retained Layer 37 REA operation records (**592**
  closed Layer 37 records, **959** cumulative validated bundle records, zero
  non-proc or resource-constrained slots).
- Verified **94/94** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **72** contract tests on Python 3.14 and 3.15, and **900** clean-public Python
  tests (**300** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; **25** newly uncovered Layer 38 clean
  callees plus non-clean/multi-part callees and live runtime execution remain
  open.

### Layer 38 — `std::basic_stringbuf<wchar_t>`, `%l`/`float32` formatters, socket/Steam helpers, `dlmalloc` top/segments & SWAR bit-range codec (2026-11-16)
- Added 3 fixed-width guest32 wstringbuf/queue/endpoint layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_codec_ops.h](port/recovered_types/vfs_fs_engine_codec_ops.h),
  [port/recovered_types/vfs_fs_engine_codec_ops.c](port/recovered_types/vfs_fs_engine_codec_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_codec_ops.c](port/recovered_types/test_vfs_fs_engine_codec_ops.c)
  (**55** checks) closing all **25** newly uncovered clean single-part RET-bearing
  direct callees across the 669-function graph (`0x100d26e0`/`0x113490a0`/
  `0x11349180`/`0x1134a060` `basic_stringbuf<wchar_t>`, `0x100de0d0` sentinel VA,
  `0x100f2af0`/`0x100f2b00` UTF-16 indexers, `0x100de340`/`0x101056d0`/
  `0x10105850`/`0x100f5860` `%l` & `float32` formatting, `0x10114f00`/
  `0x10114f60`/`0x10fd7df0`/`0x10fe4780` endpoint/`FIONBIO`/`MSG_PEEK`/Steam P2P
  close, `0x1011fcf0`/`0x101236f0`/`0x10123dd0`/`0x101e3c50`/`0x10f5f5c0`/
  `0x10fd6850` freelist4/`dlmalloc` `init_top`/`segment_holding`/list/queue/
  adapter, `0x1055bff0` SSE stream reader, `0x10f71eb0` SWAR ranged bit encoder,
  and `0x10f78290`/`0x10f80f40` channel slot reset/search).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  to **694 functions**, **335 globals**, **40 vtables**, and **621 instruction
  witnesses**, backed by **32** retained Layer 38 REA operation records (**624**
  closed Layer 38 records, **991** cumulative validated bundle records, zero
  non-proc or resource-constrained slots).
- Verified **95/95** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **73** contract tests on Python 3.14 and 3.15, and **901** clean-public Python
  tests (**301** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; **24** Layer 39 engine/channel/allocator/
  format callees (`16` single-part + `8` multi-part), CRT runtime helpers, and
  live runtime execution remain open.

### Layer 39 — TLS singletons, thread-name SEH, formatters, Winsock messages, `dlmalloc` `sys_alloc`, MSB bitcopy, ack ring & channel transport (2026-11-16)
- Added 3 fixed-width guest32 thread-name, ack-ring, and channel slot layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_net_sys_ops.h](port/recovered_types/vfs_fs_engine_net_sys_ops.h),
  [port/recovered_types/vfs_fs_engine_net_sys_ops.c](port/recovered_types/vfs_fs_engine_net_sys_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_net_sys_ops.c](port/recovered_types/test_vfs_fs_engine_net_sys_ops.c)
  (**46** checks) closing all **24** Layer 39 engine/channel/allocator/format
  callees (`16` single-part + `8` multi-part/switch across `0x100e..0x10fd`:
  `0x100e7ff0`/`0x10fddba0` TLS singletons, `0x100f38b0` `MS_VC_EXCEPTION`
  thread-naming SEH helper, `0x100efa10`/`0x100f2f60`/`0x100f3f70`/`0x100f4240`/
  `0x10104e10`/`0x10115640`/`0x10c93ed0` UTF-16 format/pad/slice & int32/card32
  switch dispatchers, `0x100feef0` Winsock `WSAGetLastError` strings,
  `0x10123e40` `dlmalloc` `sys_alloc`, `0x10f74830`/`0x10f79f60` MSB bit-width
  & transfer, `0x10fa5d10` sequence ack ring pop, `0x10fdf080`/`0x10fe45f0`/
  `0x10fe47b0` SteamID/Networking probes, and `0x10fb2fb0`/`0x10fd6d80`/
  `0x10fd6ed0`/`0x10fd7410`/`0x10fd7500`/`0x10fd9500` TCP/Steam channel setup,
  slot metadata move, and length-prefixed transport).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**718** functions, **353** globals, **40** vtables, **645** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **655** closed session REA evidence records (**31** new operations,
  **624** reused Layer 38 records; **1022** cumulative validated bundle records;
  `non_proc_slots=[]`, `resource_constrained_slots=[]`).
- Verified **96/96** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **74** contract tests on Python 3.14 and 3.15, and **902** clean-public Python
  tests (**302** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; **26** Layer 40 callees (`11` clean
  engine + `15` CRT helpers) and live runtime execution remain open.

### Layer 40 — UTF-16 scanners, `WS2_32!send`, `dlmalloc` `add_segment`/`prepend_alloc`, `564B` channel manager, SteamID/P2P & 15 CRT runtime helpers (2026-11-16)
- Added 3 fixed-width guest32 CRT/SEH/channel layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_filex56_32`, `rome2_vfs_cxx_throw_template32_32`,
  `rome2_vfs_channel_mgr564_32`) and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_ops.h](port/recovered_types/vfs_fs_engine_crt_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_ops.c](port/recovered_types/vfs_fs_engine_crt_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_ops.c](port/recovered_types/test_vfs_fs_engine_crt_ops.c)
  (**49** checks) closing all **26** Layer 40 targets (`11` clean engine
  helpers `0x100ee990`..`0x10fe4980` plus `15` CRT helpers `0x116838ea`,
  `0x11683a32`, `0x11683b10`, `0x11687aa6`, `0x1168c02e`, `0x1168e713`,
  `0x1169764e`, `0x11699f33`, `0x1169b63d`, `0x1169b820`, `0x116b856e`,
  `0x116be510`, `0x116be975`, `0x116bebf1`, `0x116bec60`).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**744** functions, **372** globals, **40** vtables, **671** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **695** closed session REA evidence records (**40** new records across
  **34** retained operation envelopes + **6** view envelopes, **655** reused
  Layer 39 records; **1062** cumulative validated bundle records;
  `non_proc_slots=[]`, `resource_constrained_slots=["116838ea", "11683a32"]`).
- Verified **97/97** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **75** contract tests on Python 3.14 and 3.15, and **903** clean-public Python
  tests (**303** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; **26** Layer 41 clean non-overlapping
  callees (`7` engine + `13` CRT + `6` multi-part) plus remaining IAT/noret
  thunks and live runtime execution remain open.

### Layer 41 — ASCII/UTF-8 formatters, sliding timestamp trim, `EP2PSend` switch, `$I10_OUTPUT`, `_stat32i64`, `memcpy` & `memmove` (2026-11-16)
- Added 3 fixed-width guest32 queue/thread-param layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_ts_node16_32`, `rome2_vfs_ts_queue24_32`,
  `rome2_vfs_crt_thread_param20_32`) and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_fmt_ops.h](port/recovered_types/vfs_fs_engine_crt_fmt_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_fmt_ops.c](port/recovered_types/vfs_fs_engine_crt_fmt_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_fmt_ops.c](port/recovered_types/test_vfs_fs_engine_crt_fmt_ops.c)
  (**39** checks) closing all **26** Layer 41 targets (`7` clean engine
  format/queue helpers `0x100ee800`..`0x10fba190`, `13` single-part CRT
  helpers `0x116838bd`..`0x116b85db`, plus `6` multi-part `0x10fdec30`,
  `0x116839e8`, `0x11699af7`, `0x11699b02`, `0x116bd8d0`, `0x116bde50`).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**770** functions, **402** globals, **40** vtables, **697** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **743** Partition 2 validated REA records (**48** new records across
  **42** retained operation envelopes + **6** view envelopes, **695** reused
  Layer 40 records; combined with Partition 1's **367** records for **1110**
  disjoint validated records total after monolithic merge reached V8's `536.8M`
  string ceiling; `non_proc_slots=[]`,
  `resource_constrained_slots=["116839e8", "116bd8d0"]`).
- Verified **98/98** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **76** contract tests on Python 3.14 and 3.15, and **904** clean-public Python
  tests (**304** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; **25** Layer 42 clean single-part callees
  (`1` remaining engine callee `0x100f17a0` + `24` CRT helpers, opened as clean
  Partition 3 because Layer 41's closed snapshot reached `517.8 MB`) plus
  remaining Layer 43+ CRT/thunk callees and live runtime execution remain open.

### Layer 42 — Partition 3 opening (`0x100f17a0` engine repeat-fill & 24 CRT SEH/`_LocaleUpdate`/`_stat64`/PTD/error helpers) (2026-11-16)
- Added 4 fixed-width guest32 CRT/locale/stat/PTD layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_locale_update16_32`, `rome2_vfs_crt_errentry8_32`,
  `rome2_vfs_crt_stat56_32`, `rome2_vfs_crt_tiddata868_32`) and bounded C17
  helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_io_ops.h](port/recovered_types/vfs_fs_engine_crt_io_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_io_ops.c](port/recovered_types/vfs_fs_engine_crt_io_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_io_ops.c](port/recovered_types/test_vfs_fs_engine_crt_io_ops.c)
  (**46** checks) closing all **25** Layer 42 targets (`0x100f17a0` final clean
  uncovered engine callee + `24` single-part CRT helpers `0x11684800`..`0x116a5967`).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**795** functions, **417** globals, **40** vtables, **722** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **36** clean Partition 3 validated REA records (`fresh_partition_p3`,
  **0** reused Layer 41 records, combined with Partition 1's **367** and
  Partition 2's **743** records for **1146** disjoint validated records total;
  `non_proc_slots=[]`, `resource_constrained_slots=[]`).
- Verified **99/99** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **77** contract tests on Python 3.14 and 3.15, and **905** clean-public Python
  tests (**305** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; **44** clean single-part CRT callees
  (queued across Layers 43–44) plus remaining multi-part/thunk callees and live
  runtime execution remain open.

### Layer 43 — CRT security cookies, `__alloca_probe`, stdio input/output adapters, `stat64`, matherr/FP dispatch & `construct_ptd` (2026-11-18)
- Added 4 fixed-width guest32 exception/parser/matherr layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_win32_exception_pointers8_32`,
  `rome2_vfs_win32_exception_record80_32`, `rome2_vfs_crt_fmt_parser76_32`,
  `rome2_vfs_crt_math_exception32_32`) and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_sec_ops.h](port/recovered_types/vfs_fs_engine_crt_sec_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_sec_ops.c](port/recovered_types/vfs_fs_engine_crt_sec_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_sec_ops.c](port/recovered_types/test_vfs_fs_engine_crt_sec_ops.c)
  (**36** checks) closing **25** single-part CRT runtime helpers
  (`0x11683dd0`..`0x116a4434`).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**820** functions, **435** globals, **40** vtables, **747** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **71** Partition 3 validated REA records (**35** new records across
  `25` `analyze_function` + `10` `read_bytes`, **36** reused Layer 42 records;
  combined with Partition 1's **367** and Partition 2's **743** records for
  **1181** disjoint validated records total; `non_proc_slots=[]`,
  `resource_constrained_slots=[]`).
- Verified **100/100** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **78** contract tests on Python 3.14 and 3.15, and **906** clean-public Python
  tests (**306** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 44+ CRT/multi-part/thunk
  callees and live runtime execution remain open.

### Layer 44 — CRT `win32_buffer`, stdio tmpbuf, `___acrt_getptd`, Win32/FLS APIs & IEEE-754/`fenv` helpers (2026-11-18)
- Added 3 fixed-width guest32 buffer/float/fenv layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_win32_buffer24_32`, `rome2_vfs_crt_strflt12_32`,
  `rome2_vfs_crt_fp_env8_32`) and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_flt_ops.h](port/recovered_types/vfs_fs_engine_crt_flt_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_flt_ops.c](port/recovered_types/vfs_fs_engine_crt_flt_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_flt_ops.c](port/recovered_types/test_vfs_fs_engine_crt_flt_ops.c)
  (**57** checks) closing **26** single-part CRT runtime helpers
  (`0x1168499d`..`0x116bcc58`).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**846** functions, **449** globals, **40** vtables, **773** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **102** Partition 3 validated REA records (**31** new records across
  `26` `analyze_function` + `5` `read_bytes`, **71** reused Layer 43 records;
  combined with Partition 1's **367** and Partition 2's **743** records for
  **1212** disjoint validated records total; `non_proc_slots=[]`,
  `resource_constrained_slots=[]`).
- Verified **101/101** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **79** contract tests on Python 3.14 and 3.15, and **907** clean-public Python
  tests (**307** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 45+ CRT/multi-part/thunk
  callees and live runtime execution remain open.

### Layer 45 — CRT stdio flush, parser scans, UNC/drive pathing, locks/onexit & `try_get_function` (2026-11-18)
- Added 2 fixed-width guest32 onexit/lock layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_onexit_table12_32`, `rome2_vfs_win32_critsec24_32`, plus
  `ptmbcinfo_48` on `rome2_vfs_crt_tiddata868_32`) and bounded C17 helpers/tests
  in [port/recovered_types/vfs_fs_engine_crt_env_ops.h](port/recovered_types/vfs_fs_engine_crt_env_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_env_ops.c](port/recovered_types/vfs_fs_engine_crt_env_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_env_ops.c](port/recovered_types/test_vfs_fs_engine_crt_env_ops.c)
  (**40** checks) closing **25** single-part CRT runtime helpers
  (`0x11687d0f`..`0x116adc01`).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**871** functions, **460** globals, **40** vtables, **798** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **134** Partition 3 validated REA records (**32** new records across
  `25` `analyze_function` + `7` `read_bytes`, **102** reused Layer 44 records;
  combined with Partition 1's **367** and Partition 2's **743** records for
  **1244** disjoint validated records total; `non_proc_slots=[]`,
  `resource_constrained_slots=[]`).
- Verified **102/102** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **80** contract tests on Python 3.14 and 3.15, and **908** clean-public Python
  tests (**308** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 46+ CRT/multi-part/thunk
  callees and live runtime execution remain open.

### Layer 46 — CRT locale/module cache, recalloc/isatty, log10 & fenv helpers (2026-11-18)
- Added 2 fixed-width guest32 ioinfo/x87-env layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_ioinfo56_32`, `rome2_vfs_x87_env28_32`, plus `ptlocinfo_4c` on
  `rome2_vfs_crt_tiddata868_32`) and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_fenv_ops.h](port/recovered_types/vfs_fs_engine_crt_fenv_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_fenv_ops.c](port/recovered_types/vfs_fs_engine_crt_fenv_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_fenv_ops.c](port/recovered_types/test_vfs_fs_engine_crt_fenv_ops.c)
  (**39** checks) closing all **28** remaining clean single-part CRT runtime
  callees across the 871-function graph (`0x1168781e`..`0x116be8d3`).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**899** functions, **473** globals, **40** vtables, **826** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **169** Partition 3 validated REA records (**35** new records across
  `28` `analyze_function` + `7` `read_bytes`, **134** reused Layer 45 records;
  combined with Partition 1's **367** and Partition 2's **743** records for
  **1279** disjoint validated records total; `non_proc_slots=[]`,
  `resource_constrained_slots=[]`).
- Verified **103/103** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **81** contract tests on Python 3.14 and 3.15, and **909** clean-public Python
  tests (**309** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 47+ CRT leaf/multi-part/thunk
  callees and live runtime execution remain open.

### Layer 47 — CRT strtox/bigint division, parser FSM, locale refcounts & fenv mappers (2026-11-18)
- Added 3 fixed-width guest32 strtox/locale layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_cstr_source8_32`, `rome2_vfs_crt_locale_cat16_32`,
  `rome2_vfs_crt_threadlocinfo184_32`) and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_strtox_ops.h](port/recovered_types/vfs_fs_engine_crt_strtox_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_strtox_ops.c](port/recovered_types/vfs_fs_engine_crt_strtox_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_strtox_ops.c](port/recovered_types/test_vfs_fs_engine_crt_strtox_ops.c)
  (**51** checks) closing **27** clean non-overlapping CRT runtime helpers
  (**17** single-part + **10** multi-part/switch/tail-jump across
  `0x11683e00`..`0x116b88e6`).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**926** functions, **484** globals, **40** vtables, **853** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **206** Partition 3 validated REA records (**37** new records across
  `27` `analyze_function` + `10` `read_bytes`, **169** reused Layer 46 records;
  combined with Partition 1's **367** and Partition 2's **743** records for
  **1316** disjoint validated records total; `non_proc_slots=[]`,
  `resource_constrained_slots=[]`).
- Verified **104/104** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **82** contract tests on Python 3.14 and 3.15, and **910** clean-public Python
  tests (**310** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 48+ leaf CRT/overlapping/thunk
  callees and live runtime execution remain open.

### Layer 48 — CRT printf/scanf FSM, leap/calendar, fullpath resize & timezone helpers (2026-11-18)
- Added 2 fixed-width guest32 wprintf/scanf state layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_wprintf_state64_32`, `rome2_vfs_crt_scanf_input116_32`) and
  bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_printf_ops.h](port/recovered_types/vfs_fs_engine_crt_printf_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_printf_ops.c](port/recovered_types/vfs_fs_engine_crt_printf_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_printf_ops.c](port/recovered_types/test_vfs_fs_engine_crt_printf_ops.c)
  (**44** checks) closing **26** clean single-part CRT runtime helpers
  (`0x116842e0`..`0x116afbb0`).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**952** functions, **489** globals, **40** vtables, **879** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **234** Partition 3 validated REA records (**28** new records across
  `26` `analyze_function` + `2` `read_bytes`, **206** reused Layer 47 records;
  combined with Partition 1's **367** and Partition 2's **743** records for
  **1344** disjoint validated records total; `non_proc_slots=[]`,
  `resource_constrained_slots=[]`).
- Verified **105/105** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **83** contract tests on Python 3.14 and 3.15, and **911** clean-public Python
  tests (**311** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 49+ CRT leaf/multi-part/overlapping/thunk
  callees and live runtime execution remain open.

### Layer 49 — CRT lconv/lc_time lifecycle, _write_nolock, wprintf type & __87except helpers (2026-11-18)
- Added 2 new fixed-width guest32 lconv/lc_time layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_lconv80_32`, `rome2_vfs_crt_lc_time_data180_32`, alongside
  reused `rome2_vfs_crt_math_exception32_32`) and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_lconv_ops.h](port/recovered_types/vfs_fs_engine_crt_lconv_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_lconv_ops.c](port/recovered_types/vfs_fs_engine_crt_lconv_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_lconv_ops.c](port/recovered_types/test_vfs_fs_engine_crt_lconv_ops.c)
  (**52** checks) closing **22** clean single-part CRT runtime helpers
  (`0x1168949f`..`0x116bcfc0`).
- Advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**974** functions, **513** globals, **40** vtables, **901** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **264** Partition 3 validated REA records (**30** new records across
  `22` `analyze_function` + `8` `read_bytes`, **234** reused Layer 48 records;
  combined with Partition 1's **367** and Partition 2's **743** records for
  **1374** disjoint validated records total; `non_proc_slots=[]`,
  `resource_constrained_slots=[]`).
- Verified **106/106** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **84** contract tests on Python 3.14 and 3.15, and **912** clean-public Python
  tests (**312** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 50+ CRT leaf/multi-part/overlapping/thunk
  callees and live runtime execution remain open.

### Layer 50 — CRT wprintf type handlers, lowio text/console writers, DST/TZ & locale helpers (2026-11-18)
- Added 3 fixed-width guest32 lowio/timezone/string layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_lowio_write_result12_32`,
  `rome2_vfs_crt_tz_transition_date12_32`, `rome2_vfs_crt_unicode_string8_32`)
  and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_wio_ops.h](port/recovered_types/vfs_fs_engine_crt_wio_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_wio_ops.c](port/recovered_types/vfs_fs_engine_crt_wio_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_wio_ops.c](port/recovered_types/test_vfs_fs_engine_crt_wio_ops.c)
  (**50** checks) closing all **30** remaining clean single-part CRT runtime
  callees across the 974-function graph (`0x1168750e`..`0x116bc636`) to pass **1,004**
  recovered functions.
- Sealed Partition 3 (**264** validated records) and advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**1004** functions, **524** globals, **40** vtables, **931** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  with **38** clean Partition 4 validated REA records (`fresh_partition_p4`,
  `30` `analyze_function` + `8` `read_bytes`; combined with Partitions 1–3
  `367 + 743 + 264 = 1374` for **1412** disjoint validated records total;
  `non_proc_slots=[]`, `resource_constrained_slots=[]`, **11,304,983B** snapshot).
- Verified **107/107** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **85** contract tests on Python 3.14 and 3.15, and **913** clean-public Python
  tests (**313** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 51+ CRT leaf/multi-part/overlapping/thunk
  callees and live runtime execution remain open.

### Layer 51 — CRT formatting_buffer, FP formatters, UTF-8/MBCS, lseek64, TZ/DST & drive/locale helpers (2026-11-18)
- Added 3 fixed-width guest32 buffer/timezone layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_formatting_buffer1032_32`,
  `rome2_vfs_crt_time_zone_info172_32`, `rome2_vfs_crt_tzname_pair8_32`)
  and bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_fpfmt_ops.h](port/recovered_types/vfs_fs_engine_crt_fpfmt_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_fpfmt_ops.c](port/recovered_types/vfs_fs_engine_crt_fpfmt_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_fpfmt_ops.c](port/recovered_types/test_vfs_fs_engine_crt_fpfmt_ops.c)
  (**67** checks) closing all **27** remaining clean single-part CRT runtime
  callees across the 1,004-function graph (`0x11688991`..`0x116bd871`) to reach
  **1,031** recovered functions.
- Extended Partition 4 (**69** validated records) and advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**1031** functions, **537** globals, **40** vtables, **958** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  (`extending_layer50`: `31` new records across `27` `analyze_function` + `4`
  `read_bytes`, `38` reused Layer 50 records; combined with Partitions 1–3
  `367 + 743 + 264 = 1374` for **1443** disjoint validated records total;
  `non_proc_slots=[]`, `resource_constrained_slots=[]`, **23,139,080B** snapshot).
- Verified **108/108** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **86** contract tests on Python 3.14 and 3.15, and **914** clean-public Python
  tests (**314** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 52+ CRT leaf/multi-part/overlapping/thunk
  callees and live runtime execution remain open.

### Layer 52 — CRT UTF-8, FP formatters (`%a/%e/%f/%g`/INF/NAN), lowio `_get_osfhandle`/console & `strncpy_s` helpers (2026-11-18)
- Added 3 fixed-width guest32 mbstate/FP-table/heap-ptr layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_mbstate8_32`,
  `rome2_vfs_crt_fp_nan_inf_table64_32`, `rome2_vfs_crt_unique_heap_ptr4_32`),
  exposed `lc_codepage_08` on `rome2_vfs_crt_threadlocinfo184_32`, and added
  bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_utf8_ops.h](port/recovered_types/vfs_fs_engine_crt_utf8_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_utf8_ops.c](port/recovered_types/vfs_fs_engine_crt_utf8_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_utf8_ops.c](port/recovered_types/test_vfs_fs_engine_crt_utf8_ops.c)
  (**54** checks) closing all **28** remaining clean single-part CRT runtime
  callees across the 1,031-function graph (`0x116889a9`..`0x116bd528`) to reach
  **1,059** recovered functions.
- Extended Partition 4 (**102** validated records) and advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**1059** functions, **544** globals, **40** vtables, **986** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  (`extending_layer51`: `33` new records across `28` `analyze_function` + `5`
  `read_bytes`, `69` reused Layer 51 records; combined with Partitions 1–3
  `367 + 743 + 264 = 1374` for **1476** disjoint validated records total;
  `non_proc_slots=[]`, `resource_constrained_slots=[]`, **28,904,212B** snapshot).
- Verified **109/109** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **87** contract tests on Python 3.14 and 3.15, and **915** clean-public Python
  tests (**315** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 53+ CRT leaf/multi-part/overlapping/thunk
  callees and live runtime execution remain open.

### Layer 53 — CRT `_flsbuf`/`_flswbuf`, switch tables, `parse_integer`, `__wctomb_s_l` & `__alldvrm` helpers (2026-11-18)
- Added 3 fixed-width guest32 stream/API-descriptor/SEH4 layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_stdio_stream56_32`,
  `rome2_vfs_crt_api_mod_desc8_32`, `rome2_vfs_crt_seh4_scope16_32`), and added
  bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_fls_ops.h](port/recovered_types/vfs_fs_engine_crt_fls_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_fls_ops.c](port/recovered_types/vfs_fs_engine_crt_fls_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_fls_ops.c](port/recovered_types/test_vfs_fs_engine_crt_fls_ops.c)
  (**75** checks) closing all **19** remaining clean non-overlapping CRT runtime
  callees (`13` single-part + `6` switch-table/two-part tail-jump helpers) across
  the 1,059-function graph (`0x116847e0`..`0x116d7120`) to reach **1,078**
  recovered functions.
- Extended Partition 4 (**127** validated records) and advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**1078** functions, **550** globals, **40** vtables, **1005** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  (`extending_layer52`: `25` new records across `19` `analyze_function` + `6`
  `read_bytes`, `102` reused Layer 52 records; combined with Partitions 1–3
  `367 + 743 + 264 = 1374` for **1501** disjoint validated records total;
  `non_proc_slots=[]`, `resource_constrained_slots=[]`, **35,667,118B** snapshot).
- Verified **110/110** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **88** contract tests on Python 3.14 and 3.15, and **916** clean-public Python
  tests (**316** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 54+ CRT leaf/overlapping/thunk
  callees and live runtime execution remain open.

### Layer 54 — CRT scanf adapters, stdio buffer/EOF checks, `__c32rtomb_utf8` & downlevel locale lookup helpers (2026-11-18)
- Corrected `charbuf_14`/`bufsiz_18` field ordering on
  `rome2_vfs_crt_stdio_stream56_32` and added 3 fixed-width guest32 scanf/locale
  layouts in [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_input_char_source32_32`,
  `rome2_vfs_crt_lcid_name_entry8_32`, `rome2_vfs_crt_locale_index_entry8_32`),
  and added bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_scanf_ops.h](port/recovered_types/vfs_fs_engine_crt_scanf_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_scanf_ops.c](port/recovered_types/vfs_fs_engine_crt_scanf_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_scanf_ops.c](port/recovered_types/test_vfs_fs_engine_crt_scanf_ops.c)
  (**73** checks) closing **21** Wave 1+2 clean single-part CRT runtime callees
  across the 1,078-function graph (`0x1168f338`..`0x116b81e9`) to reach
  **1,099** recovered functions.
- Extended Partition 4 (**153** validated records) and advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**1099** functions, **555** globals, **40** vtables, **1026** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  (`extending_layer53`: `26` new records across `21` `analyze_function` + `5`
  `read_bytes`, `127` reused Layer 53 records; combined with Partitions 1–3
  `367 + 743 + 264 = 1374` for **1527** disjoint validated records total;
  `non_proc_slots=[]`, `resource_constrained_slots=[]`, **42,447,253B** snapshot).
- Verified **111/111** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **89** contract tests on Python 3.14 and 3.15, and **917** clean-public Python
  tests (**317** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining Layer 55+ CRT leaf/overlapping/thunk
  callees and live runtime execution remain open.

### Layer 55 — CRT env init, multibyte, `_strnicoll`, `common_lseek<int64>` & scanf adapter helpers (2026-11-18)
- Refined `rome2_vfs_crt_input_char_source32_32` (`+0x08` `width_lo_08`/`+0x0c`
  `width_hi_0c`, `+0x18` `succeeded_ptr_18`) and added 4 fixed-width guest32
  mbctype/mbcasemap/SEH4 layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_mbctype_table257_32`, `rome2_vfs_crt_mbcasemap_table256_32`,
  `rome2_vfs_crt_seh4_scope_entry16_32`, `rome2_vfs_crt_seh4_scope_table32_32`),
  and added bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_envinit_ops.h](port/recovered_types/vfs_fs_engine_crt_envinit_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_envinit_ops.c](port/recovered_types/vfs_fs_engine_crt_envinit_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_envinit_ops.c](port/recovered_types/test_vfs_fs_engine_crt_envinit_ops.c)
  (**77** checks; **74** checks in
  [port/recovered_types/test_vfs_fs_engine_crt_scanf_ops.c](port/recovered_types/test_vfs_fs_engine_crt_scanf_ops.c))
  closing **23** clean non-overlapping CRT runtime callees (`20` single-part +
  `1` switch-table `0x1169712a` + `2` two-part `0x1169e653`/`0x116a1729`)
  across the 1,099-function graph (`0x11692d4c`..`0x116b8400`) to reach
  **1,122** recovered functions.
- Extended Partition 4 (**181** validated records) and advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**1122** functions, **566** globals, **40** vtables, **1049** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  (`extending_layer54`: `28` new records across `23` `analyze_function` + `5`
  `read_bytes`, `153` reused Layer 54 records; combined with Partitions 1–3
  `367 + 743 + 264 = 1374` for **1555** disjoint validated records total;
  `non_proc_slots=[]`, `resource_constrained_slots=[]`, **46,501,290B** snapshot).
- Verified **112/112** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **90** contract tests on Python 3.14 and 3.15, and **918** clean-public Python
  tests (**318** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; remaining 23 Layer 56 clean CRT callees
  plus NORET/overlapping/thunk entries and live runtime execution remain open.

### Layer 56 — Final CRT Clean Closure: `setmbcp`, `CompareStringEx`, `LCMapStringA`, `getptd`, `setenv` & `strchr` (2026-11-18)
- Added 4 fixed-width guest32 multibyte/codepage/cpinfo layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_crt_multibyte_data544_32`, `rome2_vfs_crt_codepage_info48_32`,
  `rome2_vfs_crt_mbcs_locale_ptrs16_32`, `rome2_vfs_crt_cpinfo20_32`),
  and added bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_crt_mbcp_ops.h](port/recovered_types/vfs_fs_engine_crt_mbcp_ops.h),
  [port/recovered_types/vfs_fs_engine_crt_mbcp_ops.c](port/recovered_types/vfs_fs_engine_crt_mbcp_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_crt_mbcp_ops.c](port/recovered_types/test_vfs_fs_engine_crt_mbcp_ops.c)
  (**70** checks) closing the **final 23 clean non-overlapping CRT runtime callees**
  (`22` single-part + `1` two-part `0x116b56b1`) across the 1,122-function graph
  (`0x116a2c97`..`0x116bf200`) to reach **1,145** recovered functions (**100%
  transitive clean closure**: zero remaining `clean_eng`, `clean_crt`, or
  non-overlapping multi-part callees).
- Sealed Partition 4 (`181` records) and opened fresh Partition 5 (**36**
  validated records) in [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**1145** functions, **580** globals, **40** vtables, **1072** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  (`fresh_partition_p5`: `23` `analyze_function` + `13` `read_bytes`; combined
  with Partitions 1–4 `367 + 743 + 264 + 181 = 1555` for **1591** disjoint
  validated records total; `non_proc_slots=[]`, `resource_constrained_slots=[]`,
  **8,316,221B** snapshot).
- Verified **113/113** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **91** contract tests on Python 3.14 and 3.15, and **919** clean-public Python
  tests (**319** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; NORET/IAT thunks (`19`), overlapping
  shared-tail entries (`7`), further engine/export roots, and live runtime
  execution remain open.

### Layer 57 — Engine/VFS/CRT Tail-Jump Closures & Win32/Winsock IAT Thunks (2026-11-19)
- Added fail-closed `tail_exit` (`direct_jmp` and `iat_jmp`) validation to
  [scripts/type_recovery_contracts.py](scripts/type_recovery_contracts.py),
  locked 4 fixed-width guest32 vector/peer/hash/folder layouts in
  [port/recovered_types/guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  (`rome2_vfs_elem12_vec12_32`, `rome2_vfs_peer_node12_32`,
  `rome2_vfs_folder_hashtable32_32`, `rome2_vfs_folder_node128_32`), and added
  bounded C17 helpers/tests in
  [port/recovered_types/vfs_fs_engine_tail_thunk_ops.h](port/recovered_types/vfs_fs_engine_tail_thunk_ops.h),
  [port/recovered_types/vfs_fs_engine_tail_thunk_ops.c](port/recovered_types/vfs_fs_engine_tail_thunk_ops.c),
  and [port/recovered_types/test_vfs_fs_engine_tail_thunk_ops.c](port/recovered_types/test_vfs_fs_engine_tail_thunk_ops.c)
  (**80** checks) closing all **22** remaining non-overlapping engine/VFS/CRT
  tail-jumpers and Win32/Winsock IAT thunks across the 1,145-function frontier
  (`0x100d12c0`..`0x116c8125`: 10 engine/VFS helpers, 3 CRT tail-jumpers, and
  9 Win32/`WS2_32` IAT thunks) to reach **1,167** recovered functions.
- Extended Partition 5 (**65** validated records) and advanced PE32 contracts in
  [port/recovered_types/contracts.json](port/recovered_types/contracts.json)
  (**1167** functions, **587** globals, **40** vtables, **1094** instruction
  witnesses) and [port/recovered_types/verification.json](port/recovered_types/verification.json)
  (`extending_layer56`: `29` new records across `22` `analyze_function` + `7`
  `read_bytes`, `36` reused Layer 56 records; combined with Partitions 1–4
  `367 + 743 + 264 + 181 = 1555` for **1620** disjoint validated records total;
  `non_proc_slots=[]`, `resource_constrained_slots=[]`, **22,444,408B** snapshot).
- Verified **114/114** native CTest suites on both `/W4 /WX /analyze` and ASan,
  **94** contract tests on Python 3.14 and 3.15, and **922** clean-public Python
  tests (**322** skipped) on Python 3.14 and 3.15 without touching the shared
  Ghidra project or canonical exports; 4 Layer 58 CRT noreturn roots
  (`10120b20`, `11686192`, `116879f9`, `1169b93d`), 3 embedded sub-entries
  (`11696481`, `1169933e`, `116ae512`), further engine/export roots, and live
  runtime execution remain open.

### Layer 58 — Final CRT exception, signal, abort & exit closure (2026-11-19)
- Extended [type_recovery_contracts.py](scripts/type_recovery_contracts.py) and
  [test_type_recovery_contracts.py](scripts/test_type_recovery_contracts.py)
  with fail-closed `noreturn_call` (`0xE8` terminal call) and
  `noreturn_iat_call` (`FF 15` terminal IAT call) verification and mutation tests.
- Extended Partition 5 (`extending_layer57`) across all **30** final CRT
  exception, signal, abort, and exit functions from the 4 `NORET` frontier
  roots (`0x10120b20`, `0x11686192`, `0x116879f9`, `0x1169b93d`, plus
  `0x1168601c`, `0x1168606c`, `0x116bf74d`, `0x1168d0ce`–`0x1168d362`,
  `0x116a176f`–`0x116a23ed`, `0x116a8555`, `0x116a8c48`, and
  `0x116b03fb`–`0x116b06aa` including two-range `raise` `0x116b0517`),
  growing [contracts.json](port/recovered_types/contracts.json)
  to **1,197 functions, 618 globals, 40 vtables, and 1,124 instruction witnesses**
  over **118** Partition 5 validated REA records (**1,673** cumulative across
  Partitions 1–5; `28,032,212B` snapshot; `0` Ghidra mismatches).
- Reused `rome2_vfs_crt_onexit_table12_32`, locked 3 fixed-width
  [guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  layouts (`rome2_vfs_crt_std_exception12_32`, `rome2_vfs_crt_throw_info16_32`,
  `rome2_vfs_crt_xcpt_action12_32`), and added bounded C17 reconstruction and
  **109 checks** in [vfs_fs_engine_crt_exit_ops.h](port/recovered_types/vfs_fs_engine_crt_exit_ops.h),
  [vfs_fs_engine_crt_exit_ops.c](port/recovered_types/vfs_fs_engine_crt_exit_ops.c), and
  [test_vfs_fs_engine_crt_exit_ops.c](port/recovered_types/test_vfs_fs_engine_crt_exit_ops.c).
- Verified **115/115** native CTest suites on both `/W4 /WX /sdl /GS /guard:cf /analyze`
  and ASan, **97** contract tests on Python 3.14 and 3.15, and **925** clean-public
  Python tests (**325** skipped) on Python 3.14 and 3.15 without touching the
  shared Ghidra project or canonical exports, achieving **100% transitive VFS+CRT
  closure** (`clean_eng=0`, `clean_crt=0`, `noret_or_thunk=0`; only 3
  already-embedded sub-entry labels `11696481`, `1169933e`, `116ae512`,
  further engine/export roots, and live runtime execution remain open).

### Layer 59 — Partition 6 mod-options exports & startup bootstrap foundation (2026-11-19)
- Sealed Partition 5 (**118** records; **1,673** cumulative across Partitions 1–5)
  and opened fresh Partition 6 (`fresh_partition_p6`) closing all **25** self-contained
  `RET`-bearing functions across both non-`entry_point` Rome II DLL exports
  (ordinals 521–522 `0x113048b0` / `0x11304980` + HKCU registry helpers
  `0x11302cc0` / `0x11303db0`), crash-reporter singleton `0x100e8240`, AppData and
  user-folder resolvers (`0x101016c0`, `0x10120d90`, `0x10122e30`, `0x100e1050`),
  recursive directory scanner & 48B RB-tree (`0x100e3360`, `0x100ea5e0`,
  `0x10102c10`, `0x100f71b0`, `0x100f3000`), `entry_point` continuation keepers
  (`0x101136d0`, `0x101150f0`), startup handler queue registrations (`0x100ea060`,
  `0x100ea4d0`) spanning all 29 vtables (`0x1173f20c..0x1173f2ec`), 228B perf config
  `0x100d24c0`, allocator selector `0x100fcc30`, section timings `0x112dc9f0`,
  formatters (`0x101c89e0`, `0x100de500`, `0x100f4920`), and CRT `strstr`
  (`0x116be670`), growing [contracts.json](port/recovered_types/contracts.json)
  to **1,222 functions, 677 globals, 69 vtables, and 1,149 instruction witnesses**
  over **99** fresh Partition 6 validated REA records (**1,772** cumulative across
  Partitions 1–6; `21,616,716B` snapshot; `0` Ghidra mismatches).
- Locked 5 fixed-width [guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  layouts (`rome2_startup_perf_config228_32`, `rome2_startup_user_folder_entry12_32`,
  `rome2_startup_dir_rb_node48_32`, `rome2_startup_timing_slot16_32`,
  `rome2_startup_mod_options2_32`) and added bounded C17 reconstruction and
  **184 checks** in [startup_export_bootstrap_ops.h](port/recovered_types/startup_export_bootstrap_ops.h),
  [startup_export_bootstrap_ops.c](port/recovered_types/startup_export_bootstrap_ops.c), and
  [test_startup_export_bootstrap_ops.c](port/recovered_types/test_startup_export_bootstrap_ops.c).
- Verified **116/116** native CTest suites on both `/W4 /WX /sdl /GS /guard:cf /analyze`
  and ASan, **98** contract tests on Python 3.14 and 3.15, and **926** clean-public
  Python tests (**326** skipped) on Python 3.14 and 3.15 without touching the
  shared Ghidra project or canonical exports (`clean_eng=0`, `clean_crt=0`,
  `noret_or_thunk=0` across **1,222** functions; further startup/engine roots and
  live runtime execution remain open).

### Layer 60 — Partition 6 `entry_point` & `0x100ed3c0` startup spine foundation (2026-11-19)
- Extended Partition 6 (`extending_layer59`) closing **29** single-part `RET`-bearing
  functions across `EMPIRE_APP::EMPIRE_APP` (`0x100df270`, observer/pair/terminate/temp-cleanup
  helpers `0x100f0eb0`, `0x1014d170`, `0x10102850`, `0x101046d0`, `0x100fe770`, `0x10122e40`),
  the 11-function UCRT `wchar_t` `string_output_adapter` `vswprintf` cluster
  (`0x11688718..0x1168c120` + wrapper `0x100edfe0`), `entry_point` fatal diagnostic/pointer hex
  formatter/abort prompt (`0x100de6d0`, `0x100f4a10`, `0x101032a0`), cookie-encoded
  `_set_invalid_parameter_handler` (`0x11687a4a`), and section timings completion + WinMM timer
  (`0x112dcaf0`, `0x112b2d40`, `0x106b91a0`, `0x112e2bb0`, `0x10115800`, `0x10115810`),
  growing [contracts.json](port/recovered_types/contracts.json)
  to **1,251 functions, 703 globals, 73 vtables, and 1,178 instruction witnesses**
  over **152** Partition 6 validated REA records (`53` new + `99` reused Layer 59; **1,825**
  cumulative across Partitions 1–6; `45,485,318B` snapshot; `0` Ghidra mismatches).
- Locked 4 fixed-width [guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  layouts (`rome2_startup_observer_node12_32`, `rome2_startup_pair8_32`,
  `rome2_startup_wprintf_string_adapter16_32`, `rome2_startup_timing_vec12_32`) and added
  bounded C17 reconstruction and **79 checks** in
  [startup_app_ctor_timing_ops.h](port/recovered_types/startup_app_ctor_timing_ops.h),
  [startup_app_ctor_timing_ops.c](port/recovered_types/startup_app_ctor_timing_ops.c), and
  [test_startup_app_ctor_timing_ops.c](port/recovered_types/test_startup_app_ctor_timing_ops.c).
- Verified **117/117** native CTest suites on both `/W4 /WX /sdl /GS /guard:cf /analyze`
  and ASan, **99** contract tests on Python 3.14 and 3.15, and **927** clean-public
  Python tests (**327** skipped) on Python 3.14 and 3.15 without touching the
  shared Ghidra project or canonical exports (`clean_eng=0`, `clean_crt=0`,
  `noret_or_thunk=0` across **1,251** functions; remaining startup/handler roots and
  live runtime execution remain open).

### Layer 61 — Partition 6 startup handlers, teardown & CRT stdio close cluster (2026-11-19)
- Extended Partition 6 (`extending_layer60`) closing **31** single-part `RET`-bearing
  functions across startup log closer `"End Logging\r\n"` (`0x100e32e0`), the complete
  17-function UCRT stdio close/fwrite stack (`0x11687a7a..0x116bc6d8`: `_feof`, `_fwrite`,
  `__fwrite_nolock`, `_fclose`, `__fclose_nolock`, `__acrt_stdio_free_stream`, `__close`,
  `__close_nolock`, `___acrt_stdio_free_buffer_nolock`, `__free_osfhnd` with `SetStdHandle`
  & SEH4 lock/unlock helpers), 3 `EMPIRE_APP` teardown callees (`0x100d3620`, `0x100e7690`,
  `0x10121170`), and 10 startup handler vtable `slot0`/`slot1` methods (`0x100d38b0`,
  `0x100e14d0`, `0x100e16a0`, `0x100e1820`, `0x100e1a70`, `0x100e85d0`, `0x100e8be0`,
  `0x100e8e50`, `0x100e9230`, `0x100ea040`, including `0x100e8e50`/`0x100e9230` logging
  to `0x112dcaf0`), growing [contracts.json](port/recovered_types/contracts.json) to
  **1,282 functions, 712 globals, 73 vtables, and 1,209 instruction witnesses** over
  **196** Partition 6 validated REA records (`44` new = `25` `analyze_function` + `6`
  `resolve_containing_procedure` + `13` `read_bytes` including 6 CFG-verified vtable-slot
  `non_proc_slots`; `152` reused Layer 60; **1,869** cumulative across Partitions 1–6;
  `55,880,972B` snapshot; `0` Ghidra mismatches).
- Locked 4 fixed-width [guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  layouts (`rome2_startup_log_file_box8_32`, `rome2_startup_fwrite_capture16_32`,
  `rome2_startup_handler_slot4_32`, `rome2_startup_crt_ioinfo56_32`) and added bounded C17
  reconstruction and **95 checks** in
  [startup_handler_stdio_close_ops.h](port/recovered_types/startup_handler_stdio_close_ops.h),
  [startup_handler_stdio_close_ops.c](port/recovered_types/startup_handler_stdio_close_ops.c),
  and [test_startup_handler_stdio_close_ops.c](port/recovered_types/test_startup_handler_stdio_close_ops.c).
- Verified **118/118** native CTest suites on both `/W4 /WX /sdl /GS /guard:cf /analyze`
  and ASan, **100** contract tests on Python 3.14 and 3.15, and **933** clean-public
  Python tests (**328** skipped) on Python 3.14 and 3.15 without touching the
  shared Ghidra project or canonical exports (`clean_eng=0`, `clean_crt=0`,
  `noret_or_thunk=0` across **1,282** functions; remaining startup/handler roots and
  live runtime execution remain open).

### Layer 62 — Partition 6 startup input, message pump, console registry & helper cluster (2026-11-19)
- Extended Partition 6 (`extending_layer61`) closing **33** single-part `RET`-bearing
  functions across all 8 clean `0x100ec5c0` callees (`0x101061b0` `PeekMessageW` /
  `TranslateMessage` / `DispatchMessageW` message pump, `0x1010eda0` DirectInput
  keyboard/mouse poller, `0x10101980` `GetSystemPowerStatus` mapper, `0x112ac3f0` 64-bit
  delta, `0x112bff20` flag read, `0x112e2b00` / `0x112e2c20` `/1000` ms timers with
  `__ultod3` `0x11683d60`, and `0x100f2d60` NUL-prefixed UTF-16 concat), 15 functions
  closing 8 of 12 `0x100e2980` callees (48B RB-tree iterator/min/max/rotations/destroy/erase
  `0x100e0ff0`..`0x100ec560`, UTF-16 compare/rfind/%s formatters `0x100f5f20`..`0x1011fb70`,
  AppData subpath builders `0x100ddfc0`/`0x10121350`, and `wfstream` filebuf open/close
  `0x11347290`/`0x11349100`), plus the full 9-function `0x1173f2ac` Warscape console
  registry closure (`0x100d1e30`..`0x100fd130`, including CFG-verified 97B `non_proc_slot`
  `0x100e8660`), growing [contracts.json](port/recovered_types/contracts.json) to
  **1,315 functions, 739 globals, 76 vtables, and 1,242 instruction witnesses** over
  **252** Partition 6 validated REA records (`56` new = `32` `analyze_function` + `1`
  `resolve_containing_procedure` + `23` `read_bytes`; `196` reused Layer 61; **1,925**
  cumulative across Partitions 1–6; `70,481,281B` snapshot; `0` Ghidra mismatches).
- Locked 4 fixed-width [guest32_layouts.h](port/recovered_types/guest32_layouts.h)
  layouts (`rome2_startup_dinput_mouse16_32`, `rome2_startup_mouse_pub16_32`,
  `rome2_startup_sys_power_status12_32`, `rome2_startup_console_node_prefix64_32`) and
  added bounded C17 reconstruction and **83 checks** in
  [startup_input_msg_console_ops.h](port/recovered_types/startup_input_msg_console_ops.h),
  [startup_input_msg_console_ops.c](port/recovered_types/startup_input_msg_console_ops.c),
  and [test_startup_input_msg_console_ops.c](port/recovered_types/test_startup_input_msg_console_ops.c).
- Verified **119/119** native CTest suites on both `/W4 /WX /sdl /GS /guard:cf /analyze`
  and ASan, **101** contract tests on Python 3.14 and 3.15, and **934** clean-public
  Python tests (**329** skipped) on Python 3.14 and 3.15 without touching the
  shared Ghidra project or canonical exports (`clean_eng=0`, `clean_crt=0`,
  `noret_or_thunk=0` across **1,315** functions; remaining startup/handler roots and
  live runtime execution remain open).

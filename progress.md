# Decompilation progress

## Step 2 — types, layouts, and ownership

This ledger tracks the type-recovery work. The code-recovery agent owns step 1,
the shared `workspace/TW2` Ghidra database, and canonical export publication.
Completed entries describe bounded evidence and executable behavior; they do
not imply whole-engine or gameplay equivalence.

### Layer 1 — completed, 2026-11-03

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

### Layer 2 — completed, 2026-11-03

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

### Layer 3 — native ownership milestone completed, 2026-11-03

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

### Layer 4 — resource-backed setup completed for the admitted domain, 2026-11-07

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

### Layer 5 — explicit XML-node setup completed for the native domain, 2026-11-07

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

### Remaining work

1. Extend the verified resource-backed domain toward the original resource
   manager: recover mount/dependency/mod precedence, quiet-failure/exception
   ordering, and the original XML object ABI. Historic CRT/locale
   behavior and full resource-backed constructor equivalence remain open.
2. Recover the remaining unit-card methods and meanings of opaque 32-bit
   words before widening any of them into native pointers or ownership links.
3. Continue engine/FaceFX class recovery, complete vtable bounds and callable
   method signatures, and general allocator/threading behavior. Step 2 and
   whole-game playability are not declared complete by this milestone.

### Integration constraints and open work

- Keep original image identities separate from native pointers. Prefix extents
  are not proofs of complete class sizes.
- Preserve step 1's files and active export. Do not relax provenance locks to
  hide metadata changes from its concurrent recovery work.
- The broader Python run during the export recorded 71 failures and six
  errors; the 44-test oracle-context module subsequently passed on rerun.
  Downstream canonical-index locks and an older entry-tail oracle pin still
  need a coordinated admission update.
- The layer-5 public runner invoked in the full local corpus tree recorded
  nine failures and 502 errors, including canonical-index/acceptance mismatches
  and static-gate exceptions. The focused failing static-gate module passed
  separately on both interpreters. The clean public-worktree suite passed on
  both; full local-suite health is not claimed and no frozen pins were relaxed.
- Complete engine/FaceFX layouts, callable vtable method signatures, general
  allocator/threading behavior, and full unit-card constructor equivalence
  remain open.

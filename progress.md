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

### Layer 6 — XML loader policy and failure distinctions, 2026-11-07

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

### Layer 7 — VFS dispatch, filename hash and table probing, 2026-11-07

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

### Layer 8 — VFS name-table assignment, duplicate suppression and archive-candidate comparison, 2026-11-12

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

### Layer 9 — archive-name tree search, string-key ordering, winning-archive resolution and dependency-graph walk (complete, 2026-11-12)

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

### Layer 10 — archive dependency-graph reachability, candidate priority comparator, and tree/registration callees (completed, 2026-11-12)

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

### Layer 11 — archive registration (`0x112cfc10`) orchestration, precondition gates, and candidate-set insertion policy (2026-11-12)

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

### Layer 13 — completed, 2026-11-12 (Pack Entry Vtable `0x118976c0`, Winner Notification `+0x34` & `0x112a9560` Stream/Pool Callees)

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

### Layer 14 — completed, 2026-11-12 (Remaining `0x112a9560` Non-CRT Callees & Full `0x118976c0` Pack-Entry Vtable Slots)

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

### Current target: Layer 15 (Completed — Archive-Name Disposer Vtable `0x1189a434`, Base Vtable `0x11849278`, VFS Mutex/Global Map `0x112bff80`/`0x112e32b0`, & Pool Slabs)

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

### Current target: Layer 16 (Completed — Pack-Entry Site `0x112a9963`, Base Concrete Slots `0x11849278`, Quota Tracker, RB Sentinel/Recycler & Global Map Probe)

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

### Current target: Layer 17 (Completed — Unpinned Direct VFS Callees of Root Scan, Per-Thread Quota, Stream Openers & `pack_props`)

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

### Completed: Layer 18 (`0x1189a424` / Stream Wrapper Vtable Slots, Bucket Rehash `0x112d9e20` & `0x112bb790` Dependency Sub-Callees)

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

### Completed: Layer 19 (Deep VFS Leaf/Mutation Sub-Callees of Layer 18)

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

### Completed: Layer 20 (Stream-Wrapper Vtable Slots `+0x08..+0x1c` & RB Rotate/Iterator Leaves)

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

### Completed: Layer 21 (Deferred VFS Sub-Callees, Stream-Wrapper Open Slots & Ref-Block Destructors)

- [x] **REA Evidence Extraction (`out/vfs-layer21-20261114/`)**: Recovered all 13 Layer 21 VFS procedures and virtual slots (`0x112a2660`, `0x112a2910`, `0x112a3ee0`, `0x112ac1a0`, `0x112accd0`, `0x112acd50`, `0x112acd70`, `0x112be350`, `0x112c0c60`, `0x112cd4c0`, `0x112d8c50`, `0x112d8d30`, `0x112d8e20`) on top of `out/vfs-layer20-20261113/session.rea.json`, closing `out/vfs-layer21-20261114/session.rea.json` (`281` validated evidence records = `267` Layer 20 + `14` net new unique evidence IDs across `18` retained envelopes: `8` `analyze_function` + `5` `resolve_containing_procedure` + `5` `read_bytes` length=320). Verified `0x112a2910` has a `1`B `0x90` NOP gap at `0x112a2a1f`.
- [x] **Layouts & Native C17 Helpers**: Locked 4 fixed-width guest32 structs (`rome2_vfs_adj_hash_node32` 36B, `rome2_vfs_recursive_mutex_prefix32` 8B, `rome2_vfs_u32_ptr_vec32` 12B, `rome2_vfs_flag_chain_node32` 8B) in `port/recovered_types/guest32_layouts.h`, implemented 7 checked helpers (`rome2_vfs_adj_hash_can_allocate32`, `rome2_vfs_decode_adj_hash_node32`, `rome2_vfs_u32_vec_plan_push32`, `rome2_vfs_state_wait_plan32`, `rome2_vfs_stream_wrap_check_open_reentry32`, `rome2_vfs_clear_flag_chain_bounded`, `rome2_vfs_ref_block_delete_size32`) in `port/recovered_types/vfs_adj_open_ops.h/.c`, and verified **20 checks** in `test_vfs_adj_open_ops.c` plus **78/78** native suites on `/W4 /WX /sdl /GS /guard:cf /analyze` (`5.84s`) and ASan (`5.61s`) with zero warnings.
- [x] **Contracts, Docs & Public-Clean Parity**: Pinned **231 functions, 113 globals, 20 vtables, and 241 instruction witnesses** in `port/recovered_types/contracts.json`, added `test_adj_hash_stream_open_and_ref_dtor_contracts` and `"112a2910": [1]` gap verification to `scripts/test_type_recovery_contracts.py` (**56** contract tests passing on Python 3.14 & 3.15), verified **884** public tests (`284` skipped) in clean checkout on Python 3.14 & 3.15, updated `docs/vfs_recovery.md` and `port/recovered_types/verification.json` (`layer21`, `82` source identities), and committed cleanly.

### Layer 22 (Completed — Stream Handle-Box & View-Map Callees, Pack-Entry Vtable `0x118976c0` Completion & Ref-Block Destructors)

- [x] **REA Evidence Extraction (`out/vfs-layer22-20261114/`)**: Recovered all 16 Layer 22 targets (`0x112afb90`, `0x101d9910`, `0x116835d7`, `0x112a7860`, `0x10102f90`, `0x112e1830`, `0x10e13a60`, `0x10115900`, `0x112ad1b0`, `0x112d3270`, `0x112e0d80`, `0x112c9540`, `0x112afd00`, `0x112accf0`, `0x112acd10`, `0x112acd30`) over `out/vfs-layer21-20261114/session.rea.json` (`302` closed/validated records = `281` reused Layer 21 + `18` primary new IDs [`7` direct `analyze_function`, `1` `fn-116835d7-bundle-record.json`, `8` `read_bytes(768)`, `2` new `resolve_containing_procedure`] + `3` `inspect_analysis_view` extras for `0x116835d7`, with `6` resolve IDs reused from Layer 18).
- [x] **Layouts & Native C17 Helpers**: Locked `rome2_vfs_state_ref_block32` (`44`B), `rome2_vfs_pack_telemetry_mgr32` (`108`B), and `rome2_vfs_pack_vtable_76c0_prefix32` (`40`B) with `_Static_assert` checks in [guest32_layouts.h](port/recovered_types/guest32_layouts.h); implemented bounded helpers in [vfs_view_map_ops.h](port/recovered_types/vfs_view_map_ops.h) / [vfs_view_map_ops.c](port/recovered_types/vfs_view_map_ops.c) with **21 checks** passing in [test_vfs_view_map_ops.c](port/recovered_types/test_vfs_view_map_ops.c) and **79/79** CTest suites passing on `/W4 /WX /sdl /GS /guard:cf /analyze` and ASan.
- [x] **Contracts, Docs & Public-Clean Parity**: Pinned **247 functions, 119 globals, 24 vtables, and 253 instruction witnesses** in [contracts.json](port/recovered_types/contracts.json) (`rea_layer22_evidence`), verified **57** contract tests on Python 3.14 and 3.15, updated [vfs_recovery.md](docs/vfs_recovery.md), verified **885** clean-public Python tests (`285` skipped) on Python 3.14 and 3.15, and locked **85** normalized source hashes in [verification.json](port/recovered_types/verification.json).

### Remaining work

1. Extend the verified resource-backed domain toward full archive registration
   (`0x112cfc10`) mutation/orchestration (red-black rebalancing writes,
   recursive dependency registration loop `0/1` tolerance, open-pack/archive-tree
   mutation, virtual winner notification `+0x34`), live Win32 `CreateFileA` /
   `CreateFileMappingA` / `MapViewOfFile` execution (`0x116835d7` CRT free
   wrapper, `0x10102f90`/`0x112a7860` mapping/handle-box planning, and
   `0x118976c0` non-proc slots are now recovered/modeled read-only), full
   normalization rules, exact partial parser/exception outcomes, and the rest
   of the original XML object ABI. Historic CRT/locale behavior and full
   resource-backed constructor equivalence remain open.
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

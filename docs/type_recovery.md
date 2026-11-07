# Recovered types and native ownership

This work implements curated type and lifetime layers. It does
not recover every engine class or make the game playable. The implementation
lives in `port/recovered_types/`, independently of the inert production DLL.
The code-recovery agent retains ownership of the shared Ghidra database,
missing-function work, and canonical export publication.

## Layouts and evidence

`guest32_layouts.h` describes original four-byte data/code identities, 12-byte
narrow/UTF-16 descriptors, the 16-byte handler-vector prefix, entity source
descriptors, climate/entity/unit-card constructor prefixes, original stack
argument records, and the two linked-slot pool layouts. Every published extent
and important offset is checked by the native compiler. Constructor prefix
extents are not proofs of whole-class sizes. Unknown gaps have explicit ranges
and no invented field meaning. Guest code identities are never C function
pointers.

`contracts.json` authenticates 26 original function bodies and stack-pop
boundaries, 12 original data values, nine vtable identities (first slot only),
and twenty instruction windows against the pinned original DLL. It distinguishes
file bytes from PE virtual-tail zero fill. Initial globals are not observations
of live process state; `image_defaults.h` supplies typed snapshots used by the
existing entity and unit-card global helpers.

The 0x100ef2c0 string-allocation analysis was independently checked with REA's
Ghidra provider. Retained Evidence:
`ev_e221a4f06bb4df691902dfef8a7b4f6835c07a5ca27cfb629bedfbcdae0a75cc`.
The complete local record, its digest, and a reproduction command are recorded
in the contract registry. The retained result is static analysis, not runtime
observation; its decompiler signatures are observations rather than original
source declarations. Stack argument bytes and return boundaries are separately
checked against the original bytes. Semantic field names remain interpretations.

Validate the pinned image without touching the shared Ghidra project:

```bat
py -3.15 scripts\type_recovery_contracts.py
```

## Real native ownership

`owned_string.h` defines distinct native 16-byte narrow and UTF-16 descriptors
and separate, address-bound owner records. It supports bounded deep copy, move,
idempotent destruction, and deep-owned narrow-string vectors. Empty strings
point at readable native zero objects. Allocation and release use a captured
allocator/context pair, including when the caller later changes its allocator
object. Partial vector construction rolls back every acquired resource.

The admitted string primitives preserve capacity equal to length, exact copies
of opaque units, literal terminators, class-zero allocation, original `n+9` and
`2*n+10` requests, and the original four-byte payload alignment. Native release
authority is kept outside guest memory: an eight-byte native pointer is never
put into the original four-byte hidden cell. Status codes, owner bookkeeping,
the host hidden-cell offset, observer signature, descriptor reset on destruction,
and safe failure behavior are explicit host adaptations. Owners must be moved
through the API rather than copied. Arbitrary corruption, stale owner bytes,
dangling handle copies, concurrent mutation, and general callback reentrancy are
not made safe by these C APIs.

`owned_entity.h` provides an opaque heap-owned consumer of the existing bounded
entity projection. All nine string members and every vector element are
independent owned copies. It publishes the handle only after complete success,
uses readable native empty strings, and releases through captured allocation
authority. It does not consume borrowed source arguments. Original constructor
write order, original failure routes, callable vtables, and the incoming
by-value arg06..arg08 destructor remain outside this adapter.

`free_list_pool.h` ports the linked-slot constructor behavior at 0x10328370 and
0x1064d4e0 using real native next pointers. The original strides remain 80/76
bytes; widened host slots are 88/80 bytes, with the original payload extents
left uninterpreted and untouched. Native slot/index relationships and tag bits
are preserved. Counts are checked before effects, allocator pairing is captured,
and failure rolls back all grants. Empty native pools use NULL heads; the
original allocator(0) route and wrapped/failing original allocations are not
reproduced. Later pool methods have not been reconstructed.

`layout_bridge.h` decodes unaligned, little-endian guest descriptors using
checked guest reads. It validates lengths/capacity and payload ranges and
preserves outputs on failure. It returns borrowed native views; UTF-16 remains
LE bytes until explicitly decoded into aligned native units. It does not turn
an original address into a pointer or take ownership of borrowed memory.

Step 2 layer 2 adds `tag_types.h` and `owned_tag.h`: exact guest tag/vector
layouts and distinct native records, with deep ownership of both array levels,
narrow names, and UTF-16 text. It also corrects the unit-card source/receiver
boundary and separates guest allocation requests from actual native extents.
See [unitcard_tag_type_recovery.md](unitcard_tag_type_recovery.md) for the
copy map, REA evidence, tests, and remaining constructor gaps. Root
[progress.md](../progress.md) tracks these milestones.

Layer 3 adds the accurate attachment copy, corrects its omitted `+0x50` word
and capacity/count order, and adds scalar-vector growth, owned fauna records
and a 472-byte native unit-card owner. That factory requires explicit decoded
configuration; the game's XML/resource parser remains outside its admitted
domain. See [unit-card ownership](unitcard_ownership_recovery.md) for the new
types, helper evidence, ownership rules and implementation limits.

## Legacy headers and compile admission

All 158 arbitrary 64-byte opaque bodies have been replaced by incomplete types.
`filter_opaque.py` preserves their names, validates identifiers, and supports
deterministic rerendering. Private struct tags prevent accidental substitution
of same-named Windows host structures. `prune_opaque.py` uses the same renderer
and preserves conflicting function prototypes instead of deleting them to
enable implicit calls.

The compatibility header and its generator now retain exact 3/5/6/7-byte guest
storage and ten-byte x87 storage. These are storage records, not native scalar
arithmetic types. Numeric operations and by-value native ABI use require an
explicitly recovered port. No compiler operation is silently substituted for
x87 extended arithmetic.

MSVC C accepts some operations on incomplete types and can emit no copy at all
for an assignment such as `*a = *b`. Therefore forward declarations alone are
not an ABI admission gate. The strict canonical generator continues to exclude
the wholesale legacy headers and quarantine unresolved declarations/types.

`gen_compile_island.py --warning-clean` adds a separate profile: `/c /W4 /WX
/we4013`, cleared `CL`/`_CL_`, no warning-control pragmas, and a required object
file. It rejects non-echo compiler output, even with exit code zero, and issues
`WARNING_CLEAN_VERIFIED` only after complete success. Actual code generation is
required because `/Zs` misses back-end diagnostics. The historical syntax
profile and `COMPILE_VERIFIED` remain available, with different policy identities.
Neither profile proves ABI or behavior equivalence.

The unchanged 16 canonical roots still pass the historical syntax gate with
228 warnings and fail strict admission with 232 front-end warnings. Those
warnings have not been hidden or declared fixed. The new native implementations
are compiled separately with warnings as errors.

## Build and verification

These standalone targets do not change root CMake's 194-test graph or its
production binary hashes. They require the existing Windows x64 MSVC toolchain.

```bat
scripts\build_recovered_types.bat
scripts\build_recovered_types.bat --asan
```

Both profiles run twelve native suites: checked layouts/bridging, owned strings
and vectors, owned entities, linked-slot pools, nested tags, attachment copies,
scalar vectors, fauna vectors, callback publication, the composed unit-card
owner, and the two legacy battle projection regressions. The ordinary profile also
uses `/analyze`; the second instruments the complete native library with ASan.
Release tests use explicit checks rather than elided `assert` calls. Tests cover
source mutation/freeing, readable sentinels, opaque UTF-16 units, allocation
formulas/alignment, move, captured allocator identity, every allocation-failure
position, rollback, malformed input, original normalized pool chains, and
preservation of unknown payload bytes. Maximum-sized successful allocations
are not exercised.

Focused Python checks are `test_filter_opaque.py`,
`test_gen_compile_island.py`, `test_legacy_type_storage.py`, and
`test_type_recovery_contracts.py`, plus the four original entity-provenance
checks in `test_x64_battle_entity_10cbe350_provenance.py`. The final layer 3
focused run passes all 82 tests. Original-image provenance checks skip when
the game image is absent; native ownership tests require no game assets.

The resource-backed continuation and clear-before-load setup are now recorded in
[unitcard_resource_recovery.md](unitcard_resource_recovery.md). It verifies the
native PFH4/XML/fauna path for its explicit archive and XML domain. The layer 3
counts and resource boundary above are historical; the layer 4 record contains
the current resource verification and limits.

Remaining recovery includes the incomplete engine/FaceFX class definitions,
complete vtable bounds and method signatures, general allocator/threading
behavior and the original resource manager's complete precedence/error paths. The legacy
unit-card projection remains bounded; the new owner supplies typed UTF-16
lifetime and the recovered subobjects for explicit decoded configuration. No broad header
should be promoted into the engine solely because MSVC accepts it.

## Shared-export integration status, 2026-11-03

Layer 1 focused validation passed 74 Python tests and all six native suites in
both analyzer and ASan profiles. Existing production DLL/host artifacts still
match their recorded hashes. Root CMake and its production sources were not
changed by this milestone.

A broader run exercised 1,133 Python tests during the parallel recovery export
and recorded 71 failures and six errors. The old canonical function-index lock
expects 8,344,450 bytes and SHA-256 `d6f06617...`, while the newly published index
had 10,851,680 bytes and SHA-256 `bf2229bc...`. Cached oracle-context pins also
changed mid-run; their complete 44-test module passed on a targeted rerun after
that publication. A pre-existing terminal-transcript lock additionally expects
an older entry-tail oracle file than the one already in HEAD.

These are not a green whole-repository result. Reconcile the new canonical
snapshot with its downstream frozen admission locks as part of the export
milestone. The type work does not loosen those locks or roll back the other
agent's export. The native suites and byte contracts above remain independent
of that changing function-index metadata.

## Claude Code work

The implementation workers ran through Claude Code with exact model
`claude-opus-5-5` and `--effort xhigh`. Their scopes were disjoint: opaque
header tooling, native string ownership, compile admission, and entity ownership.
Root Codex supplied binary interpretations, reviewed/integrated changes, and
ran independent validation. Claude's five-hour account limit interrupted the
pool follow-up after its header; root Codex completed and tested that module.
No alternate subagent model was substituted.

Layer 3 resumed the requested model after the quota reset for integrated
unit-card tests and independent read-only review. The test worker added
1,228,292 active checks and caught all 23 injected implementation faults in
scratch copies. Root corrected callback publication and a published-pointer
liveness dependency found by review; the follow-up confirmed both fixes.
Root independently compiled and passed all twelve native suites in both
analyzer and ASan profiles on the final sources.

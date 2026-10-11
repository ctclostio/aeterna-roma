# Complete bounded growth branch for original `0x100e2460`

Status: implemented and verified as a `BUILD_TESTING`-only guest32 execution
slice.

This milestone completes the intended `capacity > 0`, `count == capacity`
growth route through original `0x100e2460`. It injects total allocation and
release effects, preserves the original resize/copy/append/effect order, and
continues through the already-authenticated dispatch and bounded Peek-shaped
tail.

"Complete" is branch-scoped. The port rejects corrupted vector states,
wrapped or signed-negative resize arithmetic, and the native x86 stack-slot
self-alias subroute. The later unified router now composes this implementation
with the other two admitted branches; the six concrete handler methods, the
six outer allocations in `0x100ea4d0`, native platform integration, and
gameplay remain outside this historical executable slice.

## Original-byte authority

The provenance test reads the original DLL only as inert data. The pinned
image is 28,278,272 bytes with SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
Original `0x100e2460` is 252 bytes at raw offset `0x000e1860`, SHA-256
`33066e9680f5ed234e0f9fcc114d0542a33b4280cda936ed55e7e6b9b7c82123`.

The growth route is authenticated from these exact windows:

| Role | Original VA range | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Entry predicate | `0x100e2460-0x100e246d` | 14 | `78860a504081ae472b75dd5a30aed09a70613b93d4579739303b997c26430551` |
| Nonzero-capacity discriminator | `0x100e247d-0x100e2480` | 4 | `3ca7f0113f08d0e3b578001a9aa08008678880f4c657d2e1355fea67a05a0a0d` |
| Resize and allocation | `0x100e24a5-0x100e24c7` | 35 | `770139608101bd65e63c6a3f285369175377f000ca9de3a89b9403d3dd9fd721` |
| Ascending copy loop | `0x100e24c8-0x100e24e4` | 29 | `889b1531d96e444b57a8d3a299cbd37340d197b55f0d2482da79bc31b27485cc` |
| Source stack-slot adjustment and append | `0x100e24e5-0x100e251e` | 58 | `2d30707bfc46a8940ee0c408c44b90890e8c6dd718ad8ddc60ba7796aa5dac2d` |
| Old-backing release | `0x100e251f-0x100e252c` | 14 | `3806e3a4d3d56813bbfc3d2f35dafc83a1608d7da50d4670648f8b532be6a5d1` |
| Mandatory common tail | `0x100e252d-0x100e255b` | 47 | `fb4f572129c1d66b60be22c9f9ca6d9698be8a95281df72c232787f279c354c0` |

The contiguous 136-byte growth body has SHA-256
`9b618022f138033d8b71b5d256bf66d70c15a11de0829515fb8e59aec8e77b22`.
The entry/discriminator/growth control concatenation has SHA-256
`14c1178ddabeb5c9d2724e7edeb1235672ab64c10c2a3e827ddf67b94a795983`,
and the 201-byte executed-route concatenation including the common tail has
SHA-256
`8e337476fa1159b17fa6faa04d98da4eddd0f4e0f917f278a13d561cc0c10caf`.

The verifier also pins original allocator `0x100fcc80` at 380 bytes, SHA-256
`da50f0daf59ed3194f95fcb7c9df0198debdd7c8244497c026acb485100d44d8`,
and release wrapper `0x100fcc50` at 37 bytes, SHA-256
`3c9eb430ade389d3f31098476cad63aa88c0ce9f130e7b4781897129d65c1cb4`.
Their low-level allocation/free callees, allocator failure helper, throw
boundary, canonical files, and canonical index rows are independently pinned.

## Recovered order and admitted arithmetic

For the normal full-vector invariant, the original observable order is:

1. save the nonzero old backing identity;
2. double capacity with 32-bit arithmetic and publish it immediately;
3. allocate `new_capacity * 4` bytes in class zero;
4. publish the new backing identity;
5. copy `count` four-byte cells from old to new in ascending order;
6. append the handler identity at `new_backing[count]`;
7. release the old backing when nonzero;
8. increment count;
9. dispatch through the handler's vtable slot `+4`;
10. call the Peek-shaped adapter at least once and continue while nonzero;
11. publish the dispatch result's low byte after the terminating false Peek.

The original signed/wrapping behavior is authenticated but not admitted. A
doubled value with its sign bit set is converted to an allocation size of zero;
other values can wrap when shifted left by two. The port therefore requires
old capacity at most `0x1fffffff` (`UINT32_MAX / 8`). Doubling and the complete
`new_capacity * 4` allocation request are then exact 32-bit values. It also
requires `count == capacity`, a nonzero old backing, and a fully mapped old
`count * 4` span.

## Guest32 effect contract

`rome2_port_100e2460_run_growth_branch` receives writable state and read-only
vtable views, opaque vector/handler/argument guest identities, a finite drain
budget, an output byte, and this extended effects table:

```c
typedef struct rome2_100e2460_growth_effects {
    rome2_100e2460_effects tail_effects;
    rome2_100e2460_allocate_effect_fn allocate;
    rome2_100e2460_release_effect_fn release;
} rome2_100e2460_growth_effects;
```

Allocation and release identities remain opaque guest32 values. The port does
not cast them to host pointers and does not call native allocation, free,
USER32, or guest code. All callback identities and their shared context are
snapshotted before the first write. Allocation and release are total,
non-reentrant adapters that may mutate only their disjoint context. Dispatch
and Peek inherit the earlier modeled-effect contract.

Before commit, the implementation validates the descriptors, host and guest
intervals, control objects, callbacks, budget, complete vector, arithmetic,
old buffer, handler cell, vtable slot, and nonzero method identity. The vector,
old buffer, handler, and method cell must be pairwise disjoint in both guest
and host space.

After the allocator effect returns, the entire new-capacity span must be
nonzero, non-overflowing, fully mapped, and logically and physically disjoint
from every prevalidated vector/old-buffer/handler/method span. Unaligned but
fully byte-addressable spans are accepted.

## Commit and failure semantics

Precommit failures preserve guest bytes and the output and call no adapter.
The allocation result cannot be checked until after capacity publication and
the total allocation effect. A null, overflowing, unmapped, truncated, or
aliasing result therefore returns
`ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID` with exactly the doubled
capacity and allocation effect committed. Backing, old and new cells, count,
release, dispatch, Peek, and the output byte remain untouched.

A successful allocation commits the remaining operations in the recovered
order. If the final permitted Peek result is still nonzero, the function
returns `ROME2_100E2460_BRANCH_DRAIN_LIMIT`: growth, release, count, dispatch,
and preceding Peek effects remain committed, while the output byte remains
unchanged.

The original compares the address of its x86 `param_1` stack slot with the old
buffer and, on overlap, reloads the copied value from the new buffer. This API
accepts only the handler's four by-value guest bits; it has no guest identity
for a native stack slot. That self-alias subroute is deliberately
unrepresentable rather than guessed.

## Runtime composition and containment

The independent runtime oracle covers capacity-one and larger growth,
unaligned and exact-boundary new spans, exact copy/append/spare-cell state,
zero and nonzero low `AL`, an opaque zero argument, one-call drain exhaustion,
allocation-result failures, the safe arithmetic boundary, malformed mappings,
callbacks and budget, pairwise logical/physical aliases, and descriptor/host/
output aliases. Strict MSVC C17 `/W4 /WX /sdl /GS /guard:cf /analyze` and a
separate AddressSanitizer build/run pass.

`rome2_headless64` runs this branch in a third synthetic guest arena. It grows
capacity two to four, copies two sentinels, appends the handler, records release
of the old backing, increments count to three, dispatches, and performs a
nonzero then zero Peek sequence. The lifecycle suffix now includes:

```text
initializer-growth=injected-complete;
growth-allocator=injected-16-byte;
growth-release=injected-old-backing;native-release=not-run
```

CMake adds exactly six checks for this slice: provenance, reciprocal static-
gate unit, static gate, runtime, post-PE gate, and bootstrap reload. The
configured testing graph contains 87 CTests. The growth library, test, and
headless composition exist only inside `if(BUILD_TESTING)`; the static gate
rejects production/probe linkage, export escape, native allocation/release or
platform identifiers, guest-address casts, and unexpected consumers.

Both the primary and fresh `BUILD_TESTING=ON` graphs pass 87/87 CTests. A
fresh `BUILD_TESTING=OFF` tree contains neither the growth library nor its
tests, and all three configured Ninja graphs are clean.

The shipped production artifacts remain byte-identical:

- `empire.retail64.dll`: 107,520 bytes, SHA-256
  `d5f432084f4638a69fc3ef1b155c973c281f7704af1be6eca7f5aa63c7ca12a5`;
- `rome2_host64.exe`: 144,384 bytes, SHA-256
  `be4048881e43c09b5b9a9c22381aa8f02f74a9ed0a47221bb1022cb727bd4e73`.

## Subsequent closure

The bounded selector and six-insertion storage composition are now implemented
in `docs/x64_startup_100e2460_router.md`. Executing the parent initializer's
real startup meaning still requires evidence and ports or semantic adapters
for the six concrete vtable-slot methods, followed by its outer allocations
and vtable publications.

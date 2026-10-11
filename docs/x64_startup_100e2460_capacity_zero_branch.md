# Complete bounded capacity-zero branch for original `0x100e2460`

Status: implemented and verified as a `BUILD_TESTING`-only guest32 execution
slice.

This milestone completes the intended `capacity == 0`, `count == 0`,
`backing == 0` return path through original `0x100e2460`. It injects a total
four-byte allocation effect, publishes and validates the returned guest32
identity, then reuses the already-admitted preallocated branch for the append,
indirect-dispatch model, bounded Peek-shaped drain, and returned low `AL`.

"Complete" remains branch-scoped. The nonzero-capacity growth/copy/free route
is now implemented by a separate bounded successor. Native allocation, native
USER32, real guest indirect calls, the six concrete handler methods,
`0x100ea4d0` itself, and gameplay remain outside this historical executable
port.

## Original-byte authority

The provenance test reads the original DLL only as inert data. The pinned image
is 28,278,272 bytes with SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
Original `0x100e2460` is 252 bytes at raw offset `0x000e1860`, SHA-256
`33066e9680f5ed234e0f9fcc114d0542a33b4280cda936ed55e7e6b9b7c82123`.

The executed capacity-zero route is authenticated from four exact windows:

| Role | Original VA range | Raw offset | Bytes | SHA-256 |
| --- | --- | ---: | ---: | --- |
| Entry predicate | `0x100e2460-0x100e246d` | `0x000e1860` | 14 | `78860a504081ae472b75dd5a30aed09a70613b93d4579739303b997c26430551` |
| Zero-capacity discriminator | `0x100e247d-0x100e2480` | `0x000e187d` | 4 | `3ca7f0113f08d0e3b578001a9aa08008678880f4c657d2e1355fea67a05a0a0d` |
| Zero-capacity body | `0x100e2481-0x100e24a4` | `0x000e1881` | 36 | `8a5172516788b3886df02503207f131d8ca25958df0e25ef73cae3be99a331a7` |
| Mandatory common tail | `0x100e252d-0x100e255b` | `0x000e192d` | 47 | `fb4f572129c1d66b60be22c9f9ca6d9698be8a95281df72c232787f279c354c0` |

The contiguous 40-byte discriminator/body window has SHA-256
`030e64a45d9c01c867c01a24400d6c89a465c0bd2daf52baaf9665c365135189`.
The 101-byte discontiguous executed-route concatenation—entry predicate,
zero-capacity window, and common tail—has SHA-256
`11e40cca7cff6bed447043fcb10b29ddbc52b4a0951c6e880819edf91a088dc2`.
The omitted `0x100e246e-0x100e247c` bytes are the already-preallocated branch;
the omitted `0x100e24a5-0x100e252c` bytes are the 136-byte growth/copy/free
route now authenticated and admitted by the separate growth successor.

The provenance script pins the append-prefix authority itself at SHA-256
`b3d9dd5ca5e354e94fc06072e4e98c3d3312bde47a9399cd660f946fb6c2ef4c`
and executes its exact source bytes to reuse its PE parser and common-tail
authority. The canonical index independently identifies `decomp_fn_100e2460`
as size `252`, body `100e2460-100e255b`; canonical C remains a semantic
cross-check rather than the machine-code oracle.

## Original allocation boundary and order

The exact zero-capacity body proves this observable order:

1. reject the no-growth branch and take the `capacity == 0` discriminator;
2. push allocation class `0`, then byte count `4`;
3. publish `capacity = 1` before the allocator call;
4. call original allocator `0x100fcc80(4, 0)`;
5. reload `count`, perform the eight-byte cdecl cleanup, and load the handler;
6. publish the allocator result as `backing`;
7. publish the handler identity in `backing[count]`;
8. jump to the common tail, which increments `count`, dispatches through
   handler vtable slot `+4`, drains while the Peek result is nonzero, and
   returns the dispatch result's low byte.

The allocator boundary is authenticated separately. Original `0x100fcc80` is
380 bytes at raw offset `0x000fc080`, SHA-256
`da50f0daf59ed3194f95fcb7c9df0198debdd7c8244497c026acb485100d44d8`.
Its canonical source is pinned at SHA-256
`9dbd299240f648438f3e5a9e0a1d55707790af16b4d95c58f190c0475a034e6f`.

| Allocator evidence | Original VA range | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Argument/low-level-call window | `0x100fcca2-0x100fccb6` | 21 | `78778436a8a3cb26d687fb5194410f235024857743a62ceca0ba28eb7f57289b` |
| Result test | `0x100fccb7-0x100fccbf` | 9 | `604b86e14ff4f8e4337467abdbda6d3f42fd1cadcb80856ea47f3e87e8b9c3f5` |
| Normal nonzero-result epilogue | `0x100fccf6-0x100fccfe` | 9 | `5905b49658f32cf791dfe9cc07a9bd30ee1b41a0864b6558e07cd5931a2fcc54` |
| Null-result failure path | `0x100fccff-0x100fcd16` | 24 | `45100b02408c5367aee59bddde0c482df4f5ba0fcbcea2675ee2c30aaac3929b` |

The original normal path returns a nonzero allocator identity in `EAX`. Its
null path calls failure helper `0x100f1c50` and then
`__CxxThrowException@8` at `0x116bebf1`. The native slice does not call this
allocator or reproduce its throwing machinery; that boundary is modeled by a
total injected adapter.

## Guest32 contract

`rome2_port_100e2460_run_capacity_zero_branch` accepts the same writable state
view, read-only vtable view, vector/handler/argument guest identities, finite
Peek budget, and output byte as the preallocated branch. Its extended effects
table adds:

```c
rome2_guest_addr32 allocate(void *context,
    uint32_t byte_count, uint32_t allocation_class);
```

The implementation always requests exactly `(4, 0)`. The result remains an
opaque 32-bit guest identity; it is never converted to a native pointer. The
caller grants an exclusive non-reentrant borrow. The allocation adapter may
mutate only disjoint context storage; it cannot mutate guest bytes, either
view, the effects table, or the output object. After allocation returns,
dispatch and Peek inherit the preallocated-tail contract: they may mutate
their modeled context/state, but cannot retain or modify either view
descriptor, the effects table, or the output object.

Before mutation, the port validates:

- all descriptors, host/guest intervals, control objects, callbacks, and the
  nonzero drain budget;
- a complete 16-byte vector and the exact admitted initial state
  `capacity == count == backing == 0`;
- a mapped handler cell, nonzero vtable identity, mapped vtable-slot-`+4`
  method cell, and nonzero opaque method identity;
- logical and physical disjointness between handler/method reads and the
  pending capacity, count, and backing writes; and
- disjoint view/control/output storage.

Requiring the old backing identity to be zero is an ownership-safety
divergence. The original capacity-zero route overwrites that cell without
examining or freeing an unexpected old identity; admitting such state natively
would silently lose ownership. Likewise, zero capacity with nonzero count is
rejected before mutation because the original allocates only four bytes and
then indexes that allocation by the nonzero count.

## Commit and failure semantics

After prevalidation, the port writes `capacity = 1` and calls the allocation
adapter exactly once. Because its result does not exist before the effect, the
four-byte result cell is necessarily validated post-effect. It must be nonzero,
fully mapped in the writable guest view, free of guest/host overflow, and
disjoint from the vector, handler, and resolved method cell. Unaligned but
fully byte-addressable cells are accepted.

A null, unmapped, truncated, overflowing, or aliasing result returns
`ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID`. This is an explicit partial
commit: `capacity == 1` and the allocator effect remain committed, while
backing, count, the return byte, dispatch, and Peek remain unchanged.

For a valid result, the port publishes the backing identity and calls
`rome2_port_100e2460_run_preallocated_branch`. That existing gate then performs
the exact element/count commit, injected dispatch, at-least-once bounded
Peek-shaped drain, and low-`AL` publication. Its `DRAIN_LIMIT` semantics are
unchanged: storage, dispatch, and prior Peek effects remain committed while the
output byte remains unchanged when the final permitted Peek result is nonzero.

## Runtime, headless composition, and containment

The independent runtime oracle covers successful empty and multi-probe drains,
low bytes `0`, `0xff`, and an opaque zero dispatch argument; unaligned and exact
boundary allocation cells; one-call drain exhaustion; every represented
invalid allocation result; callback/budget failures; malformed vector state;
the old-backing ownership invariant; handler/method write aliases; and
control/view/output aliases. Precommit failures prove byte-for-byte state
preservation and zero effects. Invalid allocation-result cases prove the exact
capacity-only partial commit and suppression of dispatch/Peek.

`rome2_headless64` executes the route once in separate synthetic guest state at
base `0x5000`. Its vector is at `0x5020`, handler at `0x5060`, and
pre-provisioned allocation cell at `0x5080`. The injected allocator observes
`capacity == 1`, `count == 0`, and `backing == 0`; dispatch observes final
capacity/backing/slot/count state. The effect oracle fixes allocation at order
1, dispatch at order 2, first Peek at order 3, and the terminating second Peek
at order 4. Dispatch returns `0x89abcde7`, so successful publication produces
`AL == 0xe7`.

The lifecycle reports the boundary truthfully:

```text
initializer-append=preallocated-prefix;
initializer-branch=preallocated-complete;
initializer-capacity-zero=injected-complete;
initializer-growth=injected-complete;
platform-effects=not-run;
post-platform-state=bounded-empty-projection;
allocator=injected-4-byte;native-allocator=not-run;
growth-allocator=injected-16-byte;
growth-release=injected-old-backing;native-release=not-run;
initializer-dispatch=injected-complete;
queue-drain=injected-bounded-complete;gameplay=not-linked
```

The CMake integration adds exactly six tests: provenance, reciprocal static-gate
unit, static gate, runtime, post-PE gate, and bootstrap reload. The runtime
requires the preceding preallocated-branch reload plus its own provenance and
static gates. At this historical milestone the final lifecycle required the
capacity-zero reload and contained 81 CTests. The growth successor adds six,
so the current lifecycle terminates at its reload and passes 87/87 in both
testing-enabled graphs.

The library is static and exists only inside `if(BUILD_TESTING)`. It depends
only on the preallocated-branch library and is consumed only by its dedicated
test and `rome2_headless64`. The static gate rejects native allocator/USER32
identifiers, guest-to-native casts, unexpected calls or consumers, production
or probe linkage, and any escape into the export manifest, legacy DEF, or probe
DEF. Neither shipped PE exports nor links this branch.

## Successor and remaining route

`x64_startup_100e2460_growth_branch.md` documents the completed normal
nonzero-capacity growth/copy/free route, including checked doubled-capacity
arithmetic, allocation-result partial commits, ascending copy, append, and old-
backing release. The next storage step is a bounded router over all three
admitted branches. Separately, the six real vtable-slot-`+4` handler methods and
the six outer object allocations are still required before composing all of
`0x100ea4d0`.

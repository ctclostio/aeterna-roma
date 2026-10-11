# Unified bounded router for original `0x100e2460`

Status: implemented as a `BUILD_TESTING`-only guest32 execution slice.

This milestone joins all three admitted normal storage routes of original
`0x100e2460` behind one selector:

| Unsigned vector state | Selected implementation |
| --- | --- |
| `count < capacity` | preallocated append |
| `count >= capacity && capacity == 0` | capacity-zero allocation |
| `count >= capacity && capacity != 0` | nonzero-capacity growth |

The selected branch remains authoritative for its complete validation,
effects, commits, failure status, bounded Peek-shaped drain, and low-`AL`
publication. The router does not reinterpret malformed states: for example,
`count > capacity` reaches the growth implementation and fails there, while
zero capacity with nonzero count reaches the capacity-zero implementation and
fails there.

This is a complete bounded router for the three admitted storage paths, not a
complete port of the parent `0x100ea4d0` initializer. Outer handler allocation,
vtable publication, real handler behavior, global publication, native platform
effects, and gameplay remain separate milestones.

## Original-byte authority

The provenance suite pins the original 252-byte function at
`0x100e2460-0x100e255c`, raw offset `0x000e1860`, with SHA-256
`33066e9680f5ed234e0f9fcc114d0542a33b4280cda936ed55e7e6b9b7c82123`.
It partitions that body without gaps or overlaps:

| Role | Original VA | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Unsigned entry comparison | `0x100e2460` | 14 | `78860a504081ae472b75dd5a30aed09a70613b93d4579739303b997c26430551` |
| Preallocated body/jump | `0x100e246e` | 15 | `2e1493212a3d722ff90d9f73cd12052ac438e484bb6f3eea59764203ed95d45c` |
| Capacity discriminator | `0x100e247d` | 4 | `3ca7f0113f08d0e3b578001a9aa08008678880f4c657d2e1355fea67a05a0a0d` |
| Capacity-zero body/jump | `0x100e2481` | 36 | `8a5172516788b3886df02503207f131d8ca25958df0e25ef73cae3be99a331a7` |
| Growth body | `0x100e24a5` | 136 | `9b618022f138033d8b71b5d256bf66d70c15a11de0829515fb8e59aec8e77b22` |
| Common dispatch/drain tail | `0x100e252d` | 47 | `fb4f572129c1d66b60be22c9f9ca6d9698be8a95281df72c232787f279c354c0` |

The first comparison is the x86 unsigned `CMP`/`JAE` pair. The provenance
truth table explicitly includes high-bit values so the selector cannot drift
into a signed comparison. It also authenticates each direct edge and proves
that all three bodies converge on the same mandatory tail.

The router provenance source-loads and hash-pins the four earlier authorities
(append, preallocated, capacity-zero, and growth), preventing this join from
silently diverging from a branch contract.

## Portable API and containment

`rome2_port_100e2460_run_router` accepts the same writable state view,
read-only vtable view, opaque vector/handler/argument identities, finite Peek
budget, and one-byte output as the branch APIs. Its effects parameter is always
the complete growth superset:

```c
typedef struct rome2_100e2460_growth_effects {
    rome2_100e2460_effects tail_effects;
    rome2_100e2460_allocate_effect_fn allocate;
    rome2_100e2460_release_effect_fn release;
} rome2_100e2460_growth_effects;
```

The router validates the descriptors, complete effects object, output object,
host intervals, and control/host aliases before reading the selector. It then
snapshots the whole effects value before adapting it for a narrower delegate.
Every field must therefore contain an initialized valid C representation.
Callbacks inactive on the selected path may be null: preallocated uses neither
allocation nor release, and capacity-zero does not use release.

No guest identity is cast to a host pointer. The router and delegates call no
native allocator, release routine, USER32 function, or original guest target.
Allocation, release, handler dispatch, and queue probing remain total injected
effects with the existing exclusive, non-reentrant borrow contract.

## Six-registration composition

The independent integration oracle and `rome2_headless64` both retain one
vector across six ordered handler insertions. Starting from zero capacity,
count, and backing, the router produces:

| Append | Route | Capacity | Count |
| ---: | --- | ---: | ---: |
| 1 | capacity-zero | 1 | 1 |
| 2 | growth | 2 | 2 |
| 3 | growth | 4 | 3 |
| 4 | preallocated | 4 | 4 |
| 5 | growth | 8 | 5 |
| 6 | preallocated | 8 | 6 |

The allocator returns pre-provisioned guest spans of 4, 8, 16, and 32 bytes.
The release adapter observes exactly the superseded 4-, 8-, and 16-byte
backing identities. Each handler identity remains ordered in the final
eight-cell span, each insertion dispatches once through its authenticated
slot-`+4` method identity, and each bounded Peek adapter returns false once.
No host allocation or original method executes.

The headless sequence uses the six concrete identities in original
`0x100ea4d0` order:

| Vtable identity | Slot `+4` method |
| --- | --- |
| `0x1173f20c` | `0x100e8d00` |
| `0x1173f214` | `0x100e85d0` |
| `0x1173f21c` | `0x100e8580` |
| `0x1173f224` | `0x100e9340` |
| `0x1173f2ec` | `0x100e92c0` |
| `0x1173f2dc` | `0x100e87a0` |

The router itself treats those values only as guest32 data. The headless
dispatch callback now selects the independently authenticated bounded adapter
for each of all six method identities in both composed router contexts; no
original x86 method or guest-derived function pointer executes. The status
suffix adds `initializer-router=injected-complete`; the existing
`platform-effects=not-run`, `native-allocator=not-run`,
`native-release=not-run`, and `gameplay=not-linked` boundaries remain true.

## Verification boundary

The branch-level runtime suite covers all three successes, high-bit unsigned
selection, inactive callbacks, drain-limit commits, allocation partial
commits, malformed vector states, descriptor failures, and logical/physical
alias failures. The six-append oracle additionally pins the full capacity,
count, allocation, release, handler-order, dispatch, Peek, and final-`AL`
trace. Both pass strict MSVC C17 analysis and separate AddressSanitizer runs.

CMake contains the router and both runtime executables only inside
`if(BUILD_TESTING)`. The static gate rejects production/probe/export escape,
unexpected consumers, native or platform edges, guest-to-host casts, selector
drift, incomplete effects validation, and changes to the terminal fixture
chain. The production DLL and host remain outside this test-only graph.

The primary and fresh `BUILD_TESTING=ON` graphs pass 94/94 CTests. A fresh
`BUILD_TESTING=OFF` graph contains neither router runtime executable. All three
Ninja graphs are clean, fresh ON/OFF smoke loads pass, and the reproducibility
verifier accepts 14 PE-gate routes. The production artifacts are byte-identical
across all three trees:

- `empire.retail64.dll`: 107,520 bytes, SHA-256
  `d5f432084f4638a69fc3ef1b155c973c281f7704af1be6eca7f5aa63c7ca12a5`;
- `rome2_host64.exe`: 144,384 bytes, SHA-256
  `be4048881e43c09b5b9a9c22381aa8f02f74a9ed0a47221bb1022cb727bd4e73`.

## Next closure

The storage mechanics required by all six `0x100ea4d0` registrations are now
joined. The next behavior boundary is the first handler in original order,
`0x100e8d00`, represented initially as a bounded injected-effect transcript.
The second handler, `0x100e85d0`, is effect-free after its authenticated no-op
callee and can be ported directly. After all six handler contracts are
available, the outer initializer can add its six allocations and vtable stores
around this router without guessing native x86 pointer behavior.

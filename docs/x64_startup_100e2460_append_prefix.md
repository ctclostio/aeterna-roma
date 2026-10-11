# Bounded x64 append prefix for original `0x100e2460`

Status: implemented historical milestone, now reused by the `BUILD_TESTING`-
only complete preallocated and capacity-zero branches and preserved by the
separate growth branch documented in
`x64_startup_100e2460_preallocated_branch.md` and
`x64_startup_100e2460_capacity_zero_branch.md`, and
`x64_startup_100e2460_growth_branch.md`.

This milestone is the first state mutation admitted immediately beyond the
evidence-only `0x100ea4d0` boundary. It implements only the no-growth prefix of
original `0x100e2460`: when unsigned `count < capacity`, store one opaque
32-bit handler identity in `backing[count]`, then increment `count`.

At this milestone it was deliberately not described as a completed call or a
return path. The original always continues into virtual initializer dispatch
and a Windows message-queue drain before returning. Those effects and the
original return byte were excluded here. The successor now composes this exact
prefix with total injected dispatch and `PeekMessageW`-shaped effects, while
the later capacity-zero successor first publishes an injected four-byte guest
allocation and then reuses the same prefix. The later nonzero-capacity
growth/copy/free successor independently preserves the same append/count tail.

## Machine-code boundary

The provenance test reads the original DLL as inert data. The pinned image is
28,278,272 bytes with SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
Original `0x100e2460` is 252 bytes at raw offset `0x000e1860`, SHA-256
`33066e9680f5ed234e0f9fcc114d0542a33b4280cda936ed55e7e6b9b7c82123`.
The verifier partitions every byte exactly:

- `0x100e2460-0x100e247c`: 29-byte control/append window, SHA-256
  `129c7a2963c963a6f498c65ab6c392269eeaf592017904e7d495eaf05dcb188f`;
- `0x100e247d-0x100e252c`: 176-byte capacity-zero and growth window,
  SHA-256
  `a57de6025b31b5dcc04dae6e2063beb9ad1b7c4c960a8740cfaaf557c6c4f37b`;
- `0x100e252d-0x100e255b`: 47-byte mandatory common tail, SHA-256
  `fb4f572129c1d66b60be22c9f9ca6d9698be8a95281df72c232787f279c354c0`.

The admitted control bytes load count from `this+8`, capacity from `this+4`,
compare them with unsigned `jae`, load the backing identity from `this+0xc`,
store the first stack argument with the x86 scale-four addressing form, and
jump to the common tail. The excluded middle contains two direct calls to
allocator `0x100fcc80` and one direct call to free path `0x100fcc50`.

The common tail proves why this is a prefix. It increments `this+8`, invokes
the appended object's vtable slot at byte offset four, saves returned `AL`, and
drains `PeekMessageW(NULL, NULL, 0, 0, PM_REMOVE)` until false before `ret 8`.
The binary import directory independently resolves IAT cell `0x1172f670` to
`USER32.dll!PeekMessageW`.

The canonical source is pinned at SHA-256
`38aa07ab66bd4e551a830131c500a76a9a37a3c67c7f97fbf8fdc6c20bc67451`,
and its index row is exactly size `252`, body `100e2460-100e255b`. Canonical C
is a semantic cross-check, not the machine-code oracle.

## ABI and direct callers

Original `0x100e2460` is x86 `__thiscall`:

- `ECX`: container identity;
- first stack argument: opaque handler/object identity;
- second stack argument: virtual-dispatch argument;
- return: the virtual method's low byte in `AL`; and
- callee cleanup: `ret 8`.

The raw `0x100ea4d0` caller sets the container receiver to owner `+0x854` and
passes owner `+0x824` as the second explicit argument. Its six stored values
`0x1173f20c`, `0x1173f214`, `0x1173f21c`, `0x1173f224`, `0x1173f2ec`, and
`0x1173f2dc` are vtable identities, not direct method pointers. Provenance pins
the method identity in each vtable's `+4` cell and all six direct calls.
It also scans sibling `0x100ea060` and pins its 23 direct calls to the same
utility.

Starting from an empty container and assuming all earlier effects complete,
the fourth and sixth `0x100ea4d0` appends take the no-growth branch. The first,
second, third, and fifth need the allocation/growth routes now covered by
separate adapters. This historical prefix still cannot execute `0x100ea4d0` as
a whole because no unified router or outer allocator composition exists here.

## Guest32 contract

`rome2_port_100e2460_append_preallocated_prefix` accepts one borrowed writable
guest32 view, a vector identity, and the opaque 32-bit element bits. It reads a
16-byte vector object whose relevant little-endian cells are:

| Offset | Meaning |
|---:|---|
| `+0x04` | capacity |
| `+0x08` | count |
| `+0x0c` | backing-array identity |

The function admits only `count < capacity`. It validates the guest and host
numeric ranges, the complete vector span, non-null backing, checked
`count * 4`, checked backing addition, the complete four-byte append cell, and
disjointness between that cell and the entire vector object before mutation.
The write-view descriptor itself may not alias the borrowed guest bytes.

A zero element is accepted because the prefix stores opaque bits and does not
dereference them. Success writes exactly two little-endian cells in original
order: append slot, then `count + 1`. Capacity, backing identity, the view
descriptor, and every other guest byte remain unchanged. All validation
failures are byte-for-byte atomic.

## Verification and containment

The runtime suite covers ordinary and final-capacity appends, a zero count and
zero element, cells ending exactly at both the view and 32-bit address-space
ends, maximum capacity, both excluded branch decisions, status precedence,
all guest/host overflow cases, truncated spans, every vector-cell overlap, an
unaligned overlap, view-descriptor aliasing, and exact failure preservation.

The reciprocal static gate pins the header, source, runtime test, and headless
harness; enforces the unsigned branch and scale-four arithmetic; requires
validation before the two ordered writes; bans allocation, message APIs,
function-pointer dispatch, guest-to-native casts, exports, and production/probe
consumers; and mutates each load-bearing rule.

The library and test exist only inside `if(BUILD_TESTING)`. The fixture chain is
the corrected `0x100e8240` reload, this slice's provenance/static/runtime
checks, a fresh post-PE gate, another bootstrap reload, and finally
`headless_bounded_lifecycle`. At the time of this milestone, the headless
harness seeded a synthetic
already-preallocated registry beside the earlier deterministic object
projection, appended the second handler object's guest address, re-read the
slot and count, and reported:

```text
initializer-append=preallocated-prefix;platform-effects=not-run;
allocator=not-run;initializer-dispatch=not-linked;queue-drain=not-run
```

Fresh `BUILD_TESTING=ON` and `OFF` builds are recorded under
`out/repro-100e2460-verified-on` and
`out/repro-100e2460-verified-off`. Both reproduce the pinned production DLL
and host exactly:

- DLL: `d5f432084f4638a69fc3ef1b155c973c281f7704af1be6eca7f5aa63c7ca12a5`;
- host: `be4048881e43c09b5b9a9c22381aa8f02f74a9ed0a47221bb1022cb727bd4e73`.

For this historical milestone, the primary and fresh-ON headless executables
were also byte-identical at
150,528 bytes, SHA-256
`0c79a4b0e2ac325e932512135b64ae157ab5f5808beaaaac632078a477065a76`.
The then-complete configured lifecycle reported 69/69 passing CTests.

The current headless composition still reports
`initializer-append=preallocated-prefix`, then additionally reports
`initializer-branch=preallocated-complete`,
`initializer-capacity-zero=injected-complete`,
`initializer-growth=injected-complete`,
`allocator=injected-4-byte`, `native-allocator=not-run`,
`growth-allocator=injected-16-byte`,
`growth-release=injected-old-backing`, `native-release=not-run`,
`initializer-dispatch=injected-complete`, and
`queue-drain=injected-bounded-complete`. `platform-effects=not-run`,
and `gameplay=not-linked` remain explicit. The preallocated successor added six
tests to this historical 69-test lifecycle; the capacity-zero successor adds
six more and the growth successor another six, producing the current configured
87-test lifecycle. The pinned
production DLL and host hashes above remain the shipped-artifact contract;
all successors are `BUILD_TESTING`-only.

## Superseding boundary

The bounded injected-effects decision is implemented by
`x64_startup_100e2460_preallocated_branch.md`, which completes the
allocation-free `count < capacity` return path. The injected four-byte guest
allocation and its post-effect result validation are implemented by
`x64_startup_100e2460_capacity_zero_branch.md`, completing the intended first
append from an empty vector. The normal nonzero-capacity growth/copy/free route
is implemented by `x64_startup_100e2460_growth_branch.md`. The remaining
storage step is a bounded router over all three branches. A full `0x100ea4d0`
composition also
requires six outer handler allocations and ports or adapters for all six
vtable-slot methods. None of those effects is implied by this historical
prefix itself.

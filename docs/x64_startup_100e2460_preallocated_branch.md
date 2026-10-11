# Complete bounded preallocated branch for original `0x100e2460`

Status: implemented and verified as a `BUILD_TESTING`-only guest32 execution
slice, and now reused as the common append/dispatch/Peek tail of the completed
capacity-zero branch. The later growth branch independently preserves the same
authenticated tail.

This milestone completes one genuine return path through original
`0x100e2460`: the unsigned `count < capacity` branch. It composes the admitted
append prefix with the mandatory common tail: vtable-slot-4 dispatch, a
`PeekMessageW`-shaped drain that probes at least once and continues while the
result is nonzero, and publication of the dispatch result's low `AL` byte.

"Complete" is branch-scoped. This library remains allocation-free. The
capacity-zero successor now composes an injected four-byte guest allocation
with this tail, and the nonzero-capacity growth/copy/free successor is now
implemented separately. No unified router yet executes all six `0x100ea4d0`
registrations.

## Machine-code authority

The provenance test authenticates the original 28,278,272-byte DLL at SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
Original `0x100e2460` is 252 bytes at raw offset `0x000e1860`, SHA-256
`33066e9680f5ed234e0f9fcc114d0542a33b4280cda936ed55e7e6b9b7c82123`.
It retains the exact three-way partition established by the append-prefix
milestone: 29-byte no-growth control, 176-byte excluded allocator/growth
middle, and 47-byte mandatory tail.

The new test additionally partitions every tail byte into:

- count increment and dispatch, `0x100e252d-0x100e253c`, 16 bytes, SHA-256
  `0c39615f1998cfdd8b5f272d6c1ec24c45c1dce68bdbb536d59546bee88b2839`;
- IAT load, saved `AL`, and queue loop, `0x100e253d-0x100e2554`, 24 bytes,
  SHA-256
  `2a1304ba7973a578f0eee4d838043b456950a6a424f0d4258e06331bcd894d7a`;
- restored `AL` and `ret 8`, `0x100e2555-0x100e255b`, 7 bytes, SHA-256
  `cdcceb30543e9b5c00f4fcc7fc5ecf5ce7dece61c1fc34d3bfa6c9321ddbb9e9`.

The machine sequence increments `this+8`, sets `ECX` to the appended handler,
loads its vtable, pushes the original second explicit argument, loads the
method identity from vtable byte offset four, and calls it. It saves returned
`AL`, then repeatedly pushes machine arguments `1,0,0,0,0` for the source API
order `PeekMessageW(NULL,NULL,0,0,PM_REMOVE)`. `test eax,eax; jne` returns to
the first push while the full 32-bit result is nonzero. The PE import table
independently resolves IAT cell `0x1172f670` to
`USER32.dll!PeekMessageW`.

All 29 direct calls from `0x100ea060` and `0x100ea4d0`, plus the six original
vtable `{slot0, slot+4}` pairs, remain pinned. The no-growth control and tail
concatenation is 76 bytes with SHA-256
`b95416d4dec58abb68351be21cab561948dd4090e8304fc39bd0222a0a6738bd`.

## Bounded injected-effects contract

`rome2_port_100e2460_run_preallocated_branch` accepts:

- a writable state view containing the vector, backing array, and handler;
- a separate read-only view containing the handler vtable's `+4` cell;
- guest32 identities for vector, handler, and the opaque dispatch argument;
- total dispatch and Peek-shaped adapters plus their modeled context;
- a nonzero maximum number of queue probes; and
- a borrowed output byte for the original low-`AL` result.

The port reads `[handler]` from state and checked `[vtable+4]` from the
read-only view. The resulting method remains an opaque `rome2_guest_addr32`;
it is never cast to or invoked as a native pointer. The dispatch adapter
returns modeled `EAX` directly. The Peek adapter receives the exact logical
five-argument tuple and returns modeled `BOOL` directly. These adapters are
total semantic seams, not fallible platform wrappers.

All view, host-range, vector, backing, scaled-index, handler, method, budget,
control-object, output, and pending-write alias checks finish before mutation.
The implementation then calls the already-gated append prefix, invokes
dispatch exactly once, saves only its low byte, and invokes Peek at least once.
A zero on the last allowed call succeeds; a nonzero result on that call returns
`ROME2_100E2460_BRANCH_DRAIN_LIMIT`.

Precommit failures run no adapter and preserve all guest bytes and the output.
Drain-limit is necessarily postcommit: the append, increment, dispatch effect,
and prior queue effects remain committed, while the output byte stays
unchanged. The port never rolls back externally visible effects.

The caller grants an exclusive, non-reentrant borrow. Adapters may mutate their
modeled context or state, as the original method and platform call may, but
must not retain or alter the API's view descriptors, effects table, or output
object.

The headless harness exercises this composition with a distinct synthetic
state/vtable pair, verifies that append and count publication precede dispatch,
checks the opaque receiver/method/argument identities, and drains through the
bounded injected Peek-shaped adapter. It now also runs the capacity-zero and
growth successors in separate synthetic state. Its current status suffix is:

```text
initializer-append=preallocated-prefix;
initializer-branch=preallocated-complete;
initializer-capacity-zero=injected-complete;
initializer-growth=injected-complete;platform-effects=not-run;
post-platform-state=bounded-empty-projection;
allocator=injected-4-byte;native-allocator=not-run;
growth-allocator=injected-16-byte;
growth-release=injected-old-backing;native-release=not-run;
initializer-dispatch=injected-complete;
queue-drain=injected-bounded-complete;gameplay=not-linked
```

## Explicit divergences and containment

The original would append first and then fault on malformed handler/vtable
data. This port rejects such data before the append. The original queue loop
can run without a bound; this port requires a finite caller-supplied bound.
Native USER32 calls, dynamic symbol lookup, native indirect dispatch,
allocation, release, and gameplay code are absent from this library. It remains
inside `if(BUILD_TESTING)` and is not exported or linked into either shipped
PE. Its capacity-zero consumer also remains test-only and injects a guest
identity rather than calling a native allocator.

The runtime oracle covers exact two-cell state, postcommit dispatch ordering,
receiver/method/argument identity, distinct vtable `+0/+4/+8` sentinels, low
bytes `0`, `0xa5`, and `0xff`, mandatory empty-queue probing, arbitrary
nonzero BOOL values, final-call termination, drain-limit preservation, the
exercised guest/host range and truncation failures, malformed
handler/vtable/method data, logical and physical pending-write aliases, and
control-object/output aliases. Every exercised precommit failure proves zero
callbacks and byte-for-byte preservation.

At this milestone the branch added six checks to the historical 69-test
append-prefix lifecycle, and both then-current `BUILD_TESTING=ON` trees passed
all 75 CTests. The capacity-zero successor adds six more and the growth
successor adds another six, yielding the current configured 87-test lifecycle.
Because every target remains under
`BUILD_TESTING`, the production artifacts retain their established pins:

- DLL: `d5f432084f4638a69fc3ef1b155c973c281f7704af1be6eca7f5aa63c7ca12a5`;
- host: `be4048881e43c09b5b9a9c22381aa8f02f74a9ed0a47221bb1022cb727bd4e73`.

## Successor and remaining route

`x64_startup_100e2460_capacity_zero_branch.md` documents the completed intended
`capacity == count == backing == 0` route, including capacity-before-allocation
ordering, post-effect guest result validation, and reuse of this exact tail.
`x64_startup_100e2460_growth_branch.md` documents the completed normal
nonzero-capacity route. The next storage milestone is a bounded router over all
three admitted branches. The next behavior milestone is porting or safely
adapting the six vtable-slot-4 handler methods. Once both exist, the six-call
`0x100ea4d0` registration
routine can be composed rather than sampled through only the first, fourth,
and sixth storage cases.

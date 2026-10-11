# Injected handler transcript for `0x100e87a0`

`0x100e87a0` is the sixth and final slot-4 method registered by original
`0x100ea4d0`. Its bounded x64 model preserves the listener-allocation,
publication, and FaceFX startup transcript without calling the recovered
allocator, FaceFX implementation, policy callbacks, platform APIs, or
process-global state.

## Authenticated body and vtable identities

The pinned original is `empire.retail.dll`, exactly 28,278,272 bytes with
SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
The complete handler is the 109-byte interval
`[0x100e87a0, 0x100e880d)`, at `.text` raw offset `0x000e7ba0`, with
SHA-256
`0917917b3f65047b219059555acfb913b8cd9f91ccf6908e8295619d0dea710d`.
Two `0xcc` bytes precede the body and three follow it.

The registered two-cell record at `0x1173f2dc`, raw offset `0x0173dcdc`, is
`(0x100e1470, 0x100e87a0)`. Its eight bytes have SHA-256
`2053789917661c2352a1b94f0a09d6e24e534772a0f7cab361ce09de5e0962d2`.
The listener vtable installed by the handler is the three-cell record at
`0x1173ff28`, raw offset `0x0173e928`, containing
`(0x100e1440, 0x100e22c0, 0x100e1410)`. Its 12 bytes have SHA-256
`a918b100bb37ca2ff326b725e71e93402a7830b887c24f1652196b081754f89d`.

The original body has four direct calls in exact order:

| Step | Target | Authenticated role |
|---:|---:|---|
| 1 | `0x10ed3d90` | initialize the 20-byte stack-local allocation policy |
| 2 | `0x100d12b0` | allocate a four-byte listener through allocation class zero |
| 3 | `0x10ed67a0` | start FaceFX with `(policy, listener, 6)` |
| 4 | `0x100d6560` | no-op policy cleanup |

The receiver is overwritten with the local policy address before its first
use, and the incoming stack argument is only discarded by `ret 4`; both are
otherwise ignored. After cleanup the body executes `mov al, 1`. It defines
only AL, not the upper bits of EAX.

## Typed policy boundary

The original policy constructor first zeroes five four-byte fields. The
handler then installs this exact final policy:

| Field | Injected value |
|---|---:|
| allocation type | `2` |
| track allocations | `1` |
| allocation callback identity | `0x100d12b0` |
| debug-allocation callback identity | `0x100e2190` |
| free callback identity | `0x100e21a0` |

`rome2_100e87a0_memory_policy` preserves those five 32-bit values without
native pointers. The original Boolean at offset four is widened to an exact
zero-or-one field. The callback addresses remain authenticated guest
identities and are never called or cast. Constructing this final typed value
directly and eliding the authenticated `ret`-only destructor preserve the
admitted observable behavior without inventing native policy lifetime.

Every receiver and argument bit pattern is accepted as an opaque
`rome2_guest_addr32`, including zero and unaligned values, because neither is
dereferenced.

## Allocate, store, publish, and FaceFX order

After pre-effect validation and snapshotting,
`rome2_port_100e87a0_run_handler_transcript` performs this exact sequence:

1. Call the injected allocator as `allocate_listener(context, 4, 0)`.
2. If its result is nonnull, validate a complete four-byte guest span and
   store little-endian vtable identity `0x1173ff28` into that span.
3. Call `publish_listener(context, listener)`.
4. Call `startup_facefx(context, policy, listener, 6)`.
5. Publish `return_al_out = 1`.

Publication therefore observes a completed vtable store for every nonnull
listener. FaceFX startup follows publication and receives the same listener
identity plus the complete typed policy. The independent oracle admits an
unaligned listener and the exact boundary span `[0xfffffffc, 0x100000000)`,
demonstrating that the contract requires a complete guest span rather than
invented alignment.

## Null and invalid-allocation prefix semantics

A null allocation is an authenticated normal original route. The original
skips the vtable write, publishes zero to `0x119f3858`, invokes FaceFX with a
null listener, performs its no-op cleanup, and returns AL one. The portable
route likewise performs all three injected effects—allocate, publish null,
and start FaceFX with null—does not mutate guest bytes, and publishes AL one.
A zero-length state view is sufficient for this route, although its host base
must still satisfy the borrowed-view contract.

A nonnull allocation result is deliberately narrower than the original's
unchecked native pointer store. The port rejects a result below the view,
after the view, truncated at its end, or wrapping the guest32 address space.
It returns `ROME2_100E87A0_ALLOCATION_RESULT_INVALID` after the allocation
callback only. No listener bytes are written, publish and FaceFX do not run,
and AL remains unchanged. The allocation effect is a committed prefix and is
not rolled back. This explicit stop replaces the original's potential invalid
write or fault; it is a port safety policy, not a claim that x86 performed the
same check.

On successful paths, injected effects and the optional store commit in order
and are never rolled back. The callback contract is total, so the model adds
no synthetic failure after publication begins.

## Validation, aliases, and snapshot contract

Before allocation, the adapter validates the state-view descriptor, effects
descriptor, and one-byte output as complete numeric host objects. It requires
natural alignment for the state view and effects, pairwise-disjoint control
objects, a nonnull state backing pointer, a guest interval contained in the
32-bit address space, a non-wrapping host interval, and no physical overlap
between that backing interval and any control object. It then snapshots the
entire state view and effects descriptor and requires all three initialized
callback representations plus a nonnull context.

Any validation failure emits no callback, changes no guest byte, and preserves
the output. Numeric guest or host wrap reports
`ROME2_100E87A0_RANGE_OVERFLOW`; malformed objects, alignments, aliases, or
callbacks report `ROME2_100E87A0_BAD_ARGUMENT`.

Callbacks are required to be total and non-reentrant, return normally, retain
no borrowed object, leave guest bytes and the AL output untouched, and mutate
only disjoint context storage. The runtime oracle additionally mutates the
caller's effects descriptor during allocation as an adversarial robustness
probe and confirms that later callbacks still come from the pre-effect
snapshot; that probe does not widen the callback contract.

## Excluded native and global effects

The original suffix cannot safely become a direct native x64 boundary:

- `0x100d12b0` is a 15-byte wrapper that forwards `(4, 0)` to the 380-byte
  allocator `0x100fcc80`. The latter reaches registry, process-heap, and
  mutable global machinery, including `RegOpenKeyExW`, `GetProcessHeap`,
  `HeapSetInformation`, `0x101254a0`, and `DAT_119f3eb4`.
- Policy identities `0x100e2190` and `0x100e21a0` lead to the same allocator
  family and free helper `0x100fcc50`. They remain numeric transcript data.
- The original directly publishes the listener to process global
  `0x119f3858`. The port replaces that store with an injected publication
  callback.
- `0x10ed67a0` is a 2,967-byte FaceFX startup routine with SHA-256
  `c07f0a38172dd4db4e4b744c36202247fc9ec71d7521f35497672f2c62bc97cd`.
  It consumes mutable FaceFX global state including `0x119f3890` and contains
  the authenticated startup message `Starting up FaceFX SDK...`.

The port calls none of those recovered addresses, allocator or free paths,
FaceFX code, platform APIs, or process globals. It performs no guest/native
pointer cast and never derives a function pointer from guest data.

## Final headless composition and containment

`rome2_headless64` exercises the adapter exactly twice: once from standalone
router dispatch and once from the injected outer-initializer dispatch. Each
composition uses a pre-provisioned listener span, verifies allocator arguments
`(4, 0)`, the optional vtable store, allocate/publish/FaceFX order, the typed
policy and log level, and that AL remains unpublished during every callback.
The two listeners occupy independent router and outer backing offsets
`0x300` and `0x1300`.

The truthful completion token is
`initializer-handler-100e87a0=injected-transcript-complete`. The final direct
link tail is the injected `0x100ea4d0` outer initializer followed by the
`0x100e9340`, `0x100e92c0`, and `0x100e87a0` handler transcripts. This
handler's own runtime predecessor remains
`startup_100e92c0_handler_transcript_reload_verified`; its post-PE and
bootstrap route establishes terminal fixture
`startup_100e87a0_handler_transcript_reload_verified` for the headless
lifecycle.

The transcript remains a BUILD_TESTING-only static library. Its only direct
consumers are its independent runtime test and `rome2_headless64`, and no
transcript symbol is admitted to the export manifest or either DEF surface.
Unknown handler fallbacks in both headless dispatch paths now fail closed
rather than returning a synthetic success value.

## Frozen authorities and verification

The immutable implementation surfaces are:

| Authority | SHA-256 |
|---|---|
| `ported_100e87a0_handler_transcript.h` | `a5383761f2e0c332cc14655c2f51b7fe750d8429988a289aad32367d8435cc9f` |
| `ported_100e87a0_handler_transcript.c` | `2c0563c48b80d587ad3405f80203ed2d6a79258e9cde562286e786e6f50004ac` |
| `test_startup_100e87a0_handler_transcript.c` | `601e1466be3bbb590c4c64c8286d889373ce69aa7983d6ac19fe3031399fbab3` |
| executable provenance test | `20973ba2220e109b7ff2a3a042c8c8b2f827371f64d35492416bb4f350aa9865` |
| fail-closed static gate | `87d448ceb67d4af67def44111ac27b72e08b36a5666e7d501fa52509ee46a7df` |
| reciprocal mutant suite | `26431bc5e1db3da09965a3513b5abda4774b6d1c4a9089a50958c02baf91e8da` |

The strict runtime oracle passes all 9/9 cases and emits
`100e87a0 handler transcript runtime: 9/9 cases passed`. It covers nonnull and
null success, exact effect/store/publication order, address-space-end and
unaligned listeners, complete snapshotting, four invalid-allocation prefixes,
control/backing aliases, host and guest overflow, alignment, missing callback
state, and no-effect validation failures. The provenance suite passes 7/7
tests and pins the body, branches, direct calls, registered pair, listener
vtable, policy construction and callback identities, allocator chain, global
publication, FaceFX tuple, no-op cleanup, canonical rows, and AL-only return.
The reciprocal static-gate suite passes 9/9 tests, and the live containment
CLI reports zero findings across payload, provenance, headless, CMake, and all
three export surfaces.

The handler-completion checkpoint contained 136 CTests and terminated at the
`0x100e87a0` reload fixture. The later 148-test chain continued through both
bounded `0x100df270` transcripts. The current empty-preloop parent checkpoint
registers 154 tests and terminates at
`startup_100ed3c0_empty_preloop_reload_verified`. Strict MSVC analysis and
execution are clean.
The `/MT /fsanitize=address` executable also passes 9/9 with exit zero when
the matching Visual Studio `clang_rt.asan_dynamic-x86_64.dll` directory is on
`PATH`. Without that runtime DLL search path, ASan executables entered a
zero-CPU `LpcReply` wait; the resolved symptom was an environment launch issue,
not a transcript defect or sanitizer finding.

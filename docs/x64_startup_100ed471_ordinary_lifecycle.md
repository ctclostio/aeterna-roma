# Ordinary-domain lifecycle evidence for `0x100ed471`

Status: authenticated bounded executable adapter, runtime oracle, and native
headless composition.  The admission is test-only and executes no original
address.

## Byte and control-flow boundary

The complete original interval `[0x100ed471,0x100ed550)` is 223 bytes at
`.text` raw offset `0x000ec871`, SHA-256
`0b45d268790485df8fa87a28b8cabfb1fa08ebd7baac5a93dfa7c259f9d36bd9`.
It is exactly the tail of the pinned 400-byte `0x100ed3c0` parent and ends at
the original `ret`.

| Raw interval | Role | SHA-256 |
|---|---|---|
| `[0x100ed471,0x100ed4c1)` | setup, first indirect seam, timestamp | `ede782ca57dcfe346d62243bf817ab481b5a3dfa86adb168ac9c8b207e363733` |
| `[0x100ed4c1,0x100ed4d4)` | poll and `2`/`1` decisions | `cbec5f0803aee5e4667fae58f23b30896440fae3bfbf06ad4fa97b359032c7bd` |
| `[0x100ed4d4,0x100ed51b)` | result-one list path and outer backedge | `f325609f08094ee3703cf520a594fc4e821a5c00f462931d2997005f3a129019` |
| `[0x100ed51b,0x100ed550)` | terminal teardown and cleanup | `218a4f1c55b348abc89d0a63b62c6fbacfd33c825a88c2073efd1976ecce6501` |

The raw CFG has three backedges: the poll backedge
`0x100ed4d2 -> 0x100ed4c1`, the result-one list backedge
`0x100ed509 -> 0x100ed4f0`, and the outer lifecycle backedge
`0x100ed516 -> 0x100ed472`. `push esi` at `0x100ed471` runs once; the outer
backedge deliberately targets the following instruction.

There are eleven direct call sites, in order:

`0x100ea060`, `0x112dcaf0`, `0x100d6560`, `0x112e3d20`, `0x112e2bb0`,
`0x100ec5c0`, `0x100e0650`, then four calls to `0x100f1cc0`.

The first indirect call is exactly `0x100ed49e: call [edx+0x54]`. The getter
at `0x112e3d20` can return the canonical static object at `0x119e1004`, whose
vtable slot `+0x54` contains `0x100f3d00`. Its constructor path writes vtable
`0x11897870`, whose same slot contains raw-code target `0x112e2cd0`. These are
two authenticated constructions, not an exhaustive target proof: the getter
can return a pre-existing process-global pointer without constructing it in
that invocation. A port must never dereference or call any recovered target.

The second indirect call is exactly `0x100ed4fe: call [eax]`, with list-element
receiver in ECX and literal argument `1`. It exists only on the result-one
path.

## Ordinary return proof

The exact 1,199-byte `0x100ec5c0` polling body has SHA-256
`bf1adcefe07251e80f2711a590dcc479071d845c00535ec57d5b0f7385e25e5e`.
Five branches converge on an epilogue that loads literal `2`. Its other
ordinary epilogue converts AL to a Boolean mask and applies `and eax,2`, so it
returns only `0` or `2`. The apparent decompiler return after the debug route
is contradicted by raw code: that route ends in `INT3`, not `ret`.

Therefore the ordinary domain is exactly `{0,2}`. Result `0` follows the poll
backedge and result `2` enters terminal cleanup. Result `1` cannot arise from
an authenticated ordinary return, so `[0x100ed4d4,0x100ed51b)`, the second
indirect call, the list backedge, and the outer backedge are structurally
present but ordinary-domain unreachable. This proof does not prove that the
original poll terminates.

## Frame identities and writes

Let `F` be the frame base established by the preceding admitted `0x90c`-byte
pre-loop. `push esi` makes ESP equal `F-4` throughout this interval until the
epilogue. The normalized identities are:

| Identity | Frame offset |
|---|---:|
| lifecycle/poll/teardown receiver | `F+0x64` |
| timestamp destination argument | `F+0x28` |
| copied timestamp low/high dwords | `F+0x904`, `F+0x908` |
| result-one list count/base | `F+0x8d0`, `F+0x8d4` |
| terminal nonowning objects | `F+0x48`, `F+0x3c`, `F+0x10`, `F+0x04` |

The parent directly writes the two timestamp dwords at `F+0x904` and
`F+0x908`. The original timestamp callee writes its 64-bit result through
`F+0x28`, returns that address, and the parent copies the pair to the frame
tail. The only other direct frame write is `F+0x8d0 = 0` on the excluded
result-one path. Calls operating on `F+0x64` may have broader original side
effects; this evidence does not model them as direct parent stores.

On result `2`, the exact terminal call order is:

`0x100e0650 -> 0x100f1cc0(F+0x48) -> 0x100f1cc0(F+0x3c) ->`
`0x100f1cc0(F+0x10) -> 0x100f1cc0(F+0x04) -> ret`.

## Intended executable projection

The implementation slice is a finite, injected ordinary-domain projection,
not a call-through port:

1. Preflight a finite poll transcript containing zero or more `0` values and
   one terminal `2`, all within an explicit positive budget. Reject result
   `1`, any other value, budget exhaustion, or trailing values before effects.
2. Represent the `0x100ea060` step, the `"Init completed"` log, and the first
   slot-`0x54` dispatch as typed injected observer events. Never obtain,
   dereference, or invoke an original object or function pointer.
3. Accept an injected `uint64_t` timestamp, write its complete checked value
   at `F+0x28`, and copy its low/high dwords to `F+0x904/F+0x908` exactly as
   authenticated.
4. Emit the prevalidated poll events. A terminal `2` emits a typed injected
   `0x100e0650` teardown event, then invokes the four already admitted
   nonowning cleanup adapters in original order.
5. Return normally as native control flow. Original PCs are data only.

The result-one path, both list pointers, the second indirect call, the outer
backedge, unbounded polling, original direct callees, native allocation,
platform APIs, and process-global mutation are hard exclusions. Validation
must complete before the first observer event or frame write; failure leaves
the frame, output, and transcript state unchanged.

The provenance oracle is
`scripts/test_x64_startup_100ed471_ordinary_lifecycle_provenance.py`. It pins
the PE mapping, whole and split bytes, all 60 instruction boundaries, exact
CFG, direct and indirect call shapes, frame writes, mapped target bodies,
candidate vtable evidence, canonical maps/decompilation, and the independent
`0x100ec5c0` return-domain authority.

## Native admission

`port/x64_ported/ported_100ed471_ordinary_lifecycle.{h,c}` implements the
projection above.  Its fixed effects object snapshots a poll transcript of at
most 64 values.  The adapter admits only a nonempty sequence whose final value
is `2` and whose preceding values are all `0`; the sequence count must fit the
caller's explicit positive budget.  It rejects malformed or exhausted
transcripts before the first observer or frame write.

The dispatch view is read-only guest32 data.  It may describe either the
authenticated dynamic-vtable/method pair or the exact static fallback
object/vtable/method triple.  The recovered slot identity is emitted only as
by-value transcript data and is never converted to or invoked as a native
function pointer.  Frame and dispatch backings, public controls, observer
context, and all live private state are checked for forbidden aliases before
effects.

`port/x64_runtime/test_startup_100ed471_ordinary_lifecycle.c` exercises 68
strict cases, including one-, three-, and 64-result success transcripts, both
dispatch constructions, exact step and write ordering, snapshot behavior,
all malformed poll shapes, descriptor failures, range failures, and host,
guest, control, backing, context, and private-state alias rejection.  The
source passes the hardened MSVC x64 build and AddressSanitizer runtime.

`rome2_headless64` composes the adapter directly after the admitted
`[0x100ed3c0,0x100ed471)` parent, reusing that parent's exact `0x90c`-byte
frame.  It injects `0,0,2`, checks all 14 observer events, verifies timestamp
writes and final result-last commit, and reports
`startup-100ed471-ordinary-lifecycle=injected-bounded-complete`.  The library,
runtime oracle, static gates, and headless composition remain inside
`BUILD_TESTING`; the production bootstrap pair does not link this slice.

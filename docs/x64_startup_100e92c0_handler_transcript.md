# Injected handler transcript for `0x100e92c0`

`0x100e92c0` is the fifth slot-4 method registered by original
`0x100ea4d0`. Its bounded x64 model preserves three authenticated predicate
routes and the data dependency between two Steam-backed getters, while
representing every original call as an injected, by-value transcript effect.

## Authenticated body and vtable identity

The pinned original is `empire.retail.dll`, exactly 28,278,272 bytes with
SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
The complete handler is the 116-byte interval
`[0x100e92c0, 0x100e9334)`, at `.text` raw offset `0x000e86c0`, with
SHA-256
`6a667df2e872494bc91549ca47c5fe87664bfe94737a065b8bd7018154715e6d`.
Twelve `0xcc` bytes bound each side of the body.

The two-cell vtable record at `0x1173f2ec`, raw offset `0x0173dcec`, contains
`(0x100e18c0, 0x100e92c0)`. Its eight bytes have SHA-256
`096ded79eb865c98c3857f0bb8397834ef3e717011263891f2d6182e858eb5e6`.
Constructor `0x100e18c0` publishes that vtable, and the pinned image contains
no direct `call` or `jmp` reference to the handler; it is reached through the
vtable.

The six possible direct calls occur in this exact order:

| Ordinal | Target | Authenticated role |
|---:|---:|---|
| 1 | `0x100d6970` | unconditional global/platform prefix |
| 2 | `0x10fde370` | first Steam-context predicate |
| 3 | `0x10fde9d0` | second Steam-context predicate |
| 4 | `0x10fde270` | first two-word getter |
| 5 | `0x10fde990` | second two-word getter |
| 6 | `0x100d5150` | final four-word global/platform suffix |

Both conditional branches target fallback block `0x100e930e`. The successful
getter path jumps to the shared final-call setup at `0x100e931e`. After that
call completes, the handler executes `mov al, 1` and `ret 4`; it defines only
AL, not the upper bits of EAX. The receiver and incoming stack argument are
never inspected.

## Three predicate routes

`rome2_port_100e92c0_run_handler_transcript` snapshots two injected predicate
bits and three injected getter words. Both predicates must be exactly zero or
one, including the second predicate when the first makes it inactive.

The resulting routes are:

| Route | Ordered transcript | Final `0x100d5150` arguments |
|---|---|---|
| First predicate false | `100d6970`, `10fde370`, `100d5150` | `(0, 0, 0, 0)` |
| First true, second false | `100d6970`, `10fde370`, `10fde9d0`, `100d5150` | `(0, 0, 0, 0)` |
| Both predicates true | `100d6970`, `10fde370`, `10fde9d0`, `10fde270`, `10fde990`, `100d5150` | `(first_low, 0, second_low, second_high)` |

Thus the admitted paths contain exactly three, four, or six effects. Inactive
predicate/getter calls are not emitted. The getter result words are otherwise
opaque 32-bit values; zero and `0xffffffff` are both admissible.

Every receiver and argument bit pattern is accepted as an opaque
`rome2_guest_addr32`, including zero and unaligned values, because the
authenticated body ignores both inputs. Only after the final callback on any
route does the adapter publish `return_al_out = 1`. It exposes no full EAX
value and invents no native return.

## Shared getter-local semantics

The original zeroes four stack-local words before evaluating either
predicate. On the both-true route, it passes the same two-word local pair by
address to both getters. The first `lea` is `[esp+0x10]`; its pushed argument
remains on the stack, so the second `lea [esp+0x14]` resolves to the same
address after ESP has moved by four bytes. Both getter arguments are then
discarded together.

`0x10fde270` writes `(first_low, 0)` into that pair and returns its address.
The handler preserves those two words in ESI and EDI. `0x10fde990` observes
the same pair as `(first_low, 0)`, replaces it with
`(second_low, second_high)`, and returns its address. The handler loads that
second pair into ECX and EAX. Its final raw pushes are EAX, ECX, EDI, ESI, so
the callee-visible argument order is exactly:

```text
(first_low, 0, second_low, second_high)
```

The transcript records this dependency without exposing a host stack
address. The first getter record has two results and a local transition from
the implicit zero pair to `(first_low, 0)`. The second has two results and an
explicit transition from `(first_low, 0)` to
`(second_low, second_high)`. On either false route the getters never run, the
zero-initialized four-word state reaches the fallback block unchanged, and
the final call receives four zeros.

## Admitted boundary and failure atomicity

The effects object and one-byte output are required valid, disjoint borrowed
objects, and the effects object must satisfy its natural alignment. Before
the first callback, the adapter validates both host spans for numeric wrap,
checks their overlap and alignment, snapshots the complete effects object,
and validates the snapshotted callback, context, and both predicate fields.

Null objects, a missing callback or context, misalignment, overlap, or either
predicate wider than one fail before any effect and preserve the output.
Numeric effects-span wrap reports `ROME2_GUEST_RANGE_OVERFLOW`; the other
rejections report `ROME2_GUEST_BAD_ARGUMENT`. Validation deliberately applies
to an inactive second predicate as well, so route selection cannot hide
malformed snapshotted state.

On an admitted route, callback effects commit sequentially and are not rolled
back. The callback is required to be total and non-reentrant, return normally,
avoid retaining borrowed objects, and leave the output untouched. It may
mutate its context or the caller's original effects object because all route
selection and injected values come from the pre-effect snapshot. Callback
contract violations and original x86 faults or exceptions are outside the
model; no synthetic mid-transcript recovery status is introduced.

## Injected Steam, platform, and global effects

All six call records denote normally completed original effects. None is an
authorized native x64 call target:

- The 335-byte `0x100d6970` prefix invokes additional recovered machinery,
  including `0x116bc5fe`, `0x10fde340`, and `0x10fdeb00`, and publishes
  global `DAT_119ef8d5`.
- Each predicate/getter enters the process-global Steam context through
  imported `SteamInternal_ContextInit` and context identity `0x119da098`.
  Predicate `0x10fde370` tests the interface at context offset `+0x0c`;
  `0x10fde9d0` tests offset `+0x04`. Getter `0x10fde270` dispatches virtual
  slot `+0x24` through the first interface and forces its high result word to
  zero. Getter `0x10fde990` dispatches virtual slot `+0x08` through the
  second interface and copies two returned words.
- The 3,531-byte `0x100d5150` suffix sets `DAT_119ef8d7`, calls
  `CoCreateGuid`, stores the four handler arguments in
  `DAT_119f2dd8` through `DAT_119f2de4`, and calls
  `GlobalMemoryStatusEx` amid further global initialization.

The portable adapter instead injects the two predicate outcomes and three
getter words, then emits immutable records. It calls no original address,
Steam or platform API, allocator, TLS routine, or global state. It performs
no guest dereference and no guest/native pointer cast. Supplying completed
results deliberately excludes null Steam contexts, null interfaces,
unreadable returned pairs, virtual-call failures, and their native fault
behavior.

## Frozen authorities and verification

The milestone is frozen by these independent surfaces:

| Authority | SHA-256 |
|---|---|
| `ported_100e92c0_handler_transcript.h` | `6cb1465e69cffc4a935aca41ea767ab750d510c109d31f4081ccea791350d508` |
| `ported_100e92c0_handler_transcript.c` | `a806d3b5a75d3683710e694a887e84d2a46b9abde80aa96e613867f666a211f1` |
| `test_startup_100e92c0_handler_transcript.c` | `a4765be524776960dd368b5c1896128239daa62342ce7a9e6f88005231e5c28e` |
| executable provenance test | `c25665b5eb9f12cad8381578feeee65dd2113566a38e08d7159c7f2e1a4fdeb6` |

The independent runtime oracle covers all three exact routes, final argument
order, shared-local before/after state, zero and all-one result boundaries,
opaque receiver/argument boundaries, complete snapshotting, final AL
publication, host-span overflow, misalignment, effects/output aliasing, null
borrowed objects, missing callback/context, and malformed active or inactive
predicates. Its strict build runs successfully and emits
`100e92c0 handler transcript: ok`.

The provenance suite passes 8/8 tests and pins the PE identity, exact handler
and boundary bytes, all six direct calls, both false branches and the success
join, local-pair address equivalence, final push order, AL-only publication,
vtable/constructor mapping, all callee bodies, the Steam import, canonical
source identities, and the excluded global/platform effects.

The final registered slot-4 method after this fifth transcript, `0x100e87a0`,
now has an independently authenticated bounded adapter and completes the
six-handler composition. Its original native allocator and FaceFX effects
remain outside this milestone.

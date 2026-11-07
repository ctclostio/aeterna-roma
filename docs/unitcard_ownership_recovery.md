# Unit-card composition — step 2, layer 3

This layer implements the attachment copy, scalar-vector growth, owned fauna
records, and a native unit-card owner with typed UTF-16 text. It completes the
listed native ownership work for the recovered constructor domain with an
explicit decoded-configuration input. Original XML/resource loading, callable
game methods, and whole-game behavior remain outside that domain.

## Evidence and corrected types

The original image identity remains SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`,
28,278,272 bytes. A private REA/Ghidra 12.1.3 session reused the retained
snapshot, authenticated eight further helper bodies, saved its evidence, and
closed. It did not open or modify `workspace/TW2` or publish canonical exports.

| Original function | Observation / admitted native behavior | REA Evidence |
|---|---|---|
| `10132c50` | String-vector copy reads count at +4 and items at +8; source capacity is unread | `ev_4d271f9be6645d40ffdbe2fafcdf04731eb13cc0dd6a182770c4de074fcc4adc` |
| `1016db10` | Append a 32-bit word to the vector at card +0x5c; update shared index | `ev_66f88db527f6d20ed9b342023c4f4e67ea32a7ee50b8ca19e12ae075c4e6a0ee` |
| `101a9110` | Append an eight-byte pair, with capacity doubling and source-alias handling | `ev_cd00e0dc74338c2003c829a8cb6a683d178aa9860233e53620b3d7f21985e869` |
| `1016ee30` | Pair-vector receiver is card +0x68; normalize appended pair and update shared index | `ev_6b7d02ac2962667b184d91c480a54c6e6c8ff3d02b82fc7ae019829bd300f0f5` |
| `101a97f0` | Destroy nested fauna string vectors, reset count, retain outer capacity/backing, then set up configuration | `ev_7b6863671fc50ad38a60a2a553fce559bb5e6ba704d5024df453fabab39b0995` |
| `1015e280` | Iterate XML children through a receiver holding a pointer to the card, then append at card +0x15c | `ev_ad7a45b5717687f2c28b079901eacb47930e8b9978ad5f204f1a7a259cc44a9e` |
| `101a8b20` | Append a 44-byte record: eight opaque words plus a deep-owned narrow-string vector | `ev_3aa4ccf0a3ce56af0311f30dd08b56f86dc85c963f60ef9e9656f63c08c8d99b` |
| `10141630` | XML-to-record decoder; body authenticated, native decoder remains unimplemented | `ev_b9dd73fd819f29a1558cfe618c45b8a84c63575231003d649c7787942a99a534` |

The registry now checks 26 complete original bodies/stack returns, 12 data
values, nine vtable first slots and 20 original instruction windows. Its
`rea_layer3_evidence` records the complete retained files and digests. The saved
session is `out/type-layer3-20261103/session.rea.json`. These are static
observations and checked original bytes, not original source declarations or
runtime observations.

`FUN_101350c0` copies the previously omitted scalar at guest +0x50, using
`MOV EAX,[ESI+50h]` at `1013515a` and `MOV [EDI+50h],EAX` at `10135161`.
The native entity now represents it at +0x60. Its activation/count/owner fields
shift four bytes until the climate record; the climate record stays at +0x80
and the native entity remains 288 bytes because the old alignment gap absorbs
the new word. The ordinary constructor projection zeroes this unassigned
member as an explicit host policy; the copy preserves source bits.

The entity vector's names and offsets now reflect its actual order:

| Member | Guest offset | Native offset |
|---|---:|---:|
| `item_capacity` | 0xb4 | 0xd8 |
| `item_count` | 0xb8 | 0xdc |
| `items` | 0xbc | 0xe0 |

The source capacity is ignored by the copy helper. Both destination integers
receive source count. Native tests use deliberately different source capacity
and count, so reversing them cannot pass unnoticed.

## Owning implementations

`rome2_owned_battle_entity_copy` constructs the two fixed literal names and
derived dispatch identities, copies all seven other source strings and every
item string independently, and preserves every observed scalar field's bits.
The source's literal-name descriptors and dispatch cells are never read. The
implementation reuses the stable entity owner and its captured release records;
all failures roll back before publishing a handle.

`scalar_vectors.h` provides opaque owners for the four-byte words and eight-byte
float pairs. Native descriptors are 16 bytes, with pointers at +8. Backing
capacity follows 0→1→2→4→8, copies live elements, then releases the old raw
allocation. Pair input is captured before growth so it can refer to an element
in the old array. The word remains an opaque 32-bit value: pointer meaning or
ownership has not been established, so it is not widened into a host pointer.

The normalization helper preserves the observed binary32 order: compute y*y,
x*x, add, compare with 1.0, then multiply components by the reciprocal of the
square root. It compiles with `/fp:strict`. The native admitted domain requires
finite components and a non-overflowing squared length; unsupported coordinates
are rejected without publishing a changed value. Original exceptional values,
floating-point environment changes, and wrapped allocation routes are not
emulated. The shared index is zero if either vector is empty, otherwise
`min(word_count, pair_count)-1`.

`owned_fauna.h` describes each record as eight opaque words followed by a narrow
string vector: 44 bytes in the guest and 48 bytes natively. Array growth moves
views and pointers to stable private owners; address-bound string owners never
move through a raw structure copy. Published nested descriptors are separate
copies, so cleanup does not trust a published count, data pointer or descriptor.
`clear` destroys the nested resources and retains backing capacity. `reserve_min`
uses the same doubling sequence. Appending an existing element deep-copies it
before releasing any old backing array.

The native APIs use captured class-zero allocators, exact raw/size pairing,
alignment slack, and string-only release observers. Their metadata requests and
checked failure behavior are deliberate native adaptations. Callback reentrancy,
unsynchronised access, arbitrary private-memory corruption and dangling handle
aliases are outside their contracts.

## Native unit-card owner and configuration boundary

`owned_unit_card.h` introduces a separate, 472-byte native prefix. The legacy
456-byte scalar projection remains available for its bounded tests and is not
promoted to a complete constructor. The new record has real native subobject
pointers, typed vectors and a true UTF-16 descriptor:

| Member | Guest offset | New native offset |
|---|---:|---:|
| Word vector | 0x5c | 0x80 |
| Pair vector | 0x68 | 0x90 |
| UTF-16 member | 0xfc | 0x148 |
| Shared index | 0x120 | 0x174 |
| Four-word auxiliary object | 0x13c | 0x194 |
| Fauna vector | 0x15c | 0x1b8 |

These are known-prefix extents and chosen native layouts, not whole-class size
proofs. `guest32_layouts.h` retains the original four-byte address cells and
adds the precise helper vector/record layouts and setup receiver prefix.

The factory initializes the word vector with arg06, the pair vector with the
normalized global pair, a deep-owned tag and optional attachment, readable native
empty narrow strings, and a native UTF-16 empty sentinel. Nonempty text values
are owned through the checked string primitive. It then copies explicit
decoded configuration. Whole input forests are validated before allocator
effects. No image sentinel or original function address is published as a
dereferenceable native pointer.

The UTF-16 setter composes the already verified string primitive with checked
move/cleanup. It copies a new value before releasing the old one, allowing the
old text to be a source, and preserves the old value on allocation failure.
This is an explicit native writer, not a claim to have recovered a game setter.
Appending words/pairs updates the two descriptors and shared index. Config
replacement is transactional and retains at least the previous outer capacity;
clear retains the original backing capacity while releasing nested strings.

The original setup's zero-argument branch loads `Script/fauna_config.xml`,
looks up `fauna_config`, and invokes the XML decoder. Its helper at `1015e280`
receives a holder containing the card pointer, not the card directly. The
new factory is therefore named `create_from_config` and requires a non-NULL
decoded configuration view. An explicit count-zero view is accepted; omitting
the view returns `CONFIG_REQUIRED` before allocation. No native XML loader or
successful resource I/O is fabricated. Connecting the game's resource system
and porting `10141630` remain necessary before full setup/constructor equivalence.

## Verification

The attachment suite covers all 15 allocation failure positions at each raw
alignment 0–7, all copied scalars, ignored source fields, independent strings,
and source revocation. The scalar suite covers all 16 grants in an interleaved
growth sequence at all alignments, source aliasing, preserved pair bits,
normalization and rejected values. The fauna suite covers all 22 grants at all
alignments, clear/reuse, retained capacity, deep alias copies, stable string
owners across growth and private release authority.

All twelve native suites pass `/W4 /WX /analyze` and ASan, and all 82 focused
Python checks pass. The integrated unit-card suite performs 1,228,292 active
checks: every byte of the native prefix, source revocation, independent sibling
cards, 41 malformed-input cases, captured allocators, typed UTF-16 replacement,
growth and config replacement. Failure injection covers 36 full-factory
positions, ten empty-parts positions, seven minimal positions, twelve config
replacement positions and eight alias-replacement positions, each at all
eight raw alignments. All 23 faulty scratch implementations fail that suite;
the unmodified control passes.

The requested Claude Code workers used `claude-opus-5-5` at `xhigh` for tests
and read-only review. Review identified callback publication timing and an
entity liveness check that depended on a published pointer. Root fixed both,
added direct cached-view observer regressions and strengthened the entity
view-corruption regression. Follow-up review confirmed the fixes. The observer
suite checks text replacement, config replacement and fauna clear; card
destruction consumes the handle and invalidates cached views before callbacks.
The scalar suite also freezes the (3,14) normalization bits, detecting a switch
from reciprocal multiplication to direct division. Root independently passed
the complete final analyzer and ASan builds.

The checks admit the native ownership domain documented above. They do not
admit the XML/resource loader, all engine classes or game playability. See root
[progress.md](../progress.md) and `port/recovered_types/verification.json` for
the final evidence records and remaining work.

The layer 4 continuation now implements the native resource-backed domain and
clear-before-load setup described in
[unitcard_resource_recovery.md](unitcard_resource_recovery.md). The boundary and
test counts above describe the earlier layer 3 milestone.

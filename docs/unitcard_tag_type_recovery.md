# Unit-card tag types and ownership — step 2, layer 2

The tag/container copy domain now has exact guest layouts and a deep-owned
native implementation. The unit-card helper boundary has typed source and
receiver parameters with native allocation extents. This does not admit the
complete unit-card constructor or make the game playable.

## Original evidence

The pinned `empire.retail.dll` is 28,278,272 bytes, SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
All addresses below describe that x86 image. A private REA/Ghidra 12.1.3 session
used the immutable source; the shared `workspace/TW2` project was not opened.
The private session was saved and closed.

| Function | Body extent | Evidence |
|---|---|---|
| Tag vector copy, `0x10132ce0` | 534 bytes, through `0x10132ef5` | `ev_1e5fef19ff860e18bd220c5bce833b9d165b4d056aa7432ed8aedf7aeba823d2` |
| UTF-16 copy, `0x100f1aa0` | 32 bytes, through `0x100f1abf` | parent `ev_f4044fa497324a66d26296519d34811c0bcf8e44492ecff43d3c3f02afb0a86c`; assembly view `ev_40720dc470541c21756ede0f0c0413312b73009a56ef6a5c6b5ce35c4fb36365` |
| Attachment copy, `0x101350c0` | 485 bytes, through `0x101352a4` | `ev_1a9c91ac141a4e6c224c85b54d73c516574ed85768db8e637c36cd549bc3a03b` |
| Unit-card constructor, `0x10145c70` | 832 bytes, through `0x10145faf` | `ev_a355774563bb8c74423af13b900a74319d2a5b04dd084a65e441fa3ee91bb8c2` |

The three newly admitted function byte hashes and their `ECX` receiver / `RET 4`
contracts are in `port/recovered_types/contracts.json`. Two additional original
instruction windows pin the source adjustment and attachment receiver:

```text
10145f4a  MOV ECX,[ESP+10h]    ; original arg01
10145f4e  ADD ECX,4
10145f51  PUSH ECX             ; source vector at arg01+4
10145f52  LEA ECX,[EDI+4]      ; allocated tag's vector receiver
10145f55  CALL 10132ce0
10145f5a  MOV [EDI],1173fae4h

10145f80  PUSH EDI            ; attachment source, arg00
10145f81  MOV ECX,EAX         ; allocated attachment block
10145f83  CALL 101350c0       ; returns that receiver in EAX
```

The wide-copy dossier exceeded REA's MCP transport budget because its complete
reference data was large. The analysis completed and remained retained. The
assembly view above contains all 15 instructions, including the doubled source
length and call to `0x100ef330`; no truncated dossier is used as evidence.
Complete retained session evidence is in
`out/type-layer2-20261103/session.rea.json`. The contract registry records local
record digests and reproduction commands. These are static observations;
decompiler signatures are not original C declarations.

## Recovered copy domain

The vector is `{capacity, count, data32}` at guest offsets `0,4,8`. The copy
helper does not read source capacity. It writes both destination integers from
source count and allocates class-zero storage at the following strides.

| Record | Guest bytes | Native bytes |
|---|---:|---:|
| Vector descriptor | 12 | 16 |
| Tag: vtable identity plus vector | 16 | 24 |
| Outer element | 136 (`0x88`) | 152 (`0x98`) |
| Nested element | 76 (`0x4c`) | 80 (`0x50`) |

`guest32_layouts.h` and `tag_types.h` assert these distinct offsets and extents.
The native vector starts at tag offset 8; guest offset 4 must never be applied
as a native byte offset. The vtable value remains an integer identity.

| Outer guest range | Observed operation |
|---|---|
| `0x00..0x0b` | Deep-copy narrow descriptor through `0x100f1700` |
| `0x0c..0x1b` | Copy four opaque dwords |
| `0x1c..0x1d` | Copy one word |
| `0x20..0x4f` | Copy twelve opaque dwords |
| `0x50..0x56` | Copy seven bytes |
| `0x58..0x5b` | Copy one opaque dword |
| `0x5c..0x67` | Deep-copy UTF-16 descriptor through `0x100f1aa0` |
| `0x68..0x7b` | Copy five opaque dwords |
| `0x7c..0x87` | Construct nested vector, source count at `0x80`, data at `0x84` |

Guest gaps `0x1e..0x1f` and `0x57` are not copied. Each nested element contains
a narrow descriptor at `0x00` and 16 opaque dwords at `0x0c..0x4b`. The native
copy preserves every admitted scalar bit, including float-like NaN patterns,
without assigning speculative meanings to those words.

## Native ownership

`owned_tag.h` publishes an opaque `rome2_owned_unit_card_tag` handle and a const
native tag view. Creation copies both array levels, every narrow name, and each
UTF-16 text independently. Source capacities for vectors are ignored as in the
observed helper; published capacities equal counts. Source string capacities
are validated as an additional host precondition. Empty arrays use NULL and
empty strings use readable native sentinels. Unknown gaps and native padding
are zeroed, which is an explicit host choice.

Owners stay at stable addresses. The captured allocator and private raw grant
records determine release, including when the caller later replaces its
allocator object. Published pointers and counts cannot redirect cleanup.
String payloads preserve the already verified allocation formulas and observer
behavior; metadata blocks use separate native extents and alignment slack.
Malformed input is rejected before allocation. Every partial copy rolls back
all acquired grants and leaves the output handle unchanged.

This is native ownership with defined failure behavior. Original exception
paths, wrapped byte counts, original destructor ordering, allocator failure
behavior, thread safety, and callable virtual methods remain unproved. Nothing
assumes that the first vtable slot is a destructor.

## Unit-card boundary changes

The legacy `rome2_unit_card_tag` payload pointer has been replaced by the typed
vector. `arg01` now names a native tag source; its vector member is passed to
the initializer. The attachment callback receives both its allocated native
entity projection and its source. Native allocations use 24 and 288 bytes;
the historical guest requests remain separately named as 16 and 232 bytes.
Missing initializers suppress their allocation. A NULL native tag source means
an empty vector. These guards are explicit host behavior.

The legacy constructor's callbacks still own their nested-data policy and
their blocks must be released by its caller. The independent owned-tag API
provides a concrete lifetime implementation for the recovered tag copy domain;
it does not add complete ownership to the legacy unit-card constructor.

## Verification and next boundary

The new native suite checks every copied scalar range, independent narrow and
UTF-16 data, embedded zeros and surrogate units, source revocation, native
sentinels, ignored source vector capacity, captured allocator identity, guard
bytes, and all eleven allocation failure positions at all eight raw alignments.
It also checks rejection before effects and release independence from published
descriptor corruption. The unit-card regression checks member-based source and
receiver identity, native allocation extents, missing callbacks, and failures
at either allocation. All seven native suites pass `/W4 /WX /analyze` and ASan.

The subsequent [layer 3 ownership work](unitcard_ownership_recovery.md) implements
the attachment copy, adds its `+0x50` field, corrects capacity/count order,
recovers the word/pair containers and fauna ownership, and adds a native
unit-card owner with typed UTF-16 lifetime. Whole setup/constructor equivalence
still requires the game's XML/resource loader and decoder; the new native
factory explicitly requires already decoded configuration.

# Phase 4.2 — Battle Unit Card Descriptor (`0x10145c70`)

Status: bounded test-only projection. Step 2 layer 2 corrected the typed tag
vector source/receiver boundary and the attachment's allocated receiver. A
separate native owner now composes the recovered tag, attachment, scalar
containers, fauna records and typed UTF-16 lifetime for explicit decoded
configuration. Original XML/resource setup still prevents full constructor
equivalence. See [ownership recovery](unitcard_ownership_recovery.md) for scope.

Reconstruction of the battle unit card descriptor constructor recovered from
`empire.retail.dll`. This is the record the settlement battle benchmark harness
at `0x100e39c0` instantiates for each unit under test.

## Recovered shape

| Property | Value |
|---|---|
| Entry | `FUN_10145c70 @ 0x10145c70` |
| Body | `0x10145c70 .. 0x10145faf` (832 bytes) |
| Convention | `__thiscall`, `ECX = this`, `RET 0x44` |
| Stack arguments | 17 (`E0+4 .. E0+0x44`) |
| Return | `EAX = this` (`MOV EAX,ESI` before both `RET 0x44` sites) |

Call sites recovered from the Ghidra reference graph:

| Caller | Call site |
|---|---|
| `FUN_100e39c0` (settlement battle benchmark) | `0x100e4363` |
| `FUN_10747450` | `0x107479b8` |
| `FUN_108cb2e0` | `0x108cb572` |
| `FUN_10ec7f40` | `0x10ec8a06` |
| `FUN_10f60ef0` | `0x10f60f77` |
| `FUN_1105ba50` | `0x1105bbc5` |

## Argument map

Every stack word was resolved by subtracting the live `SUB ESP` / `PUSH` depth
at each reading instruction. The result was cross-checked against the 17 pushes
at `0x100e4363`; the two derivations agree exactly, which is what fixes the map.

| Word | Offset | Read at | Recovered use |
|---|---|---|---|
| arg00 | `E0+0x04` | `0x10145f67` | gates the attachment allocation and supplies `FUN_101350c0` |
| arg01 | `E0+0x08` | `0x10145f4a` | tag construction source is `arg01 + 4`; ECX becomes block + 4 at `0x10145f52` |
| arg02 | `E0+0x0c` | `0x10145cac` | byte → `this+0x024` |
| arg03 | `E0+0x10` | `0x10145c8f` | dword → `this+0x00c` |
| arg04 | `E0+0x14` | `0x10145cc3` | byte → `this+0x040` |
| arg05 | `E0+0x18` | `0x10145cdf` | dword → `this+0x054` |
| arg06 | `E0+0x1c` | `0x10145ea3` | forwarded to `FUN_1016db10`; never stored |
| arg07 | `E0+0x20` | `0x10145ce6` | dword → `this+0x058` |
| arg08 | `E0+0x24` | `0x10145d1d` | dword → `this+0x074`; also drives `this+0x128` through the class 6 / class 14 comparisons |
| arg09 | `E0+0x28` | `0x10145cd5` (`MOVSS`) | float → `this+0x078` |
| arg10 | `E0+0x2c` | `0x10145d25` | dword → `this+0x07c` |
| arg11 | `E0+0x30` | — | never read |
| arg12 | `E0+0x34` | `0x10145e07` | byte → `this+0x119` |
| arg13 | `E0+0x38` | `0x10145e11` | byte → `this+0x11a` |
| arg14 | `E0+0x3c` | `0x10145e1b` | byte → `this+0x11b` |
| arg15 | `E0+0x40` | `0x10145dfe` | OR-ed with `DAT_11afbd20` → `this+0x11c` |
| arg16 | `E0+0x44` | `0x10145e8f` | byte → `this+0x138` |

## Behavioural gates

The class predicate is one of the scalar decision sequences in the body:

```
0x10145e64  CMP EDI,0x6     ; unit class 6
0x10145e69  CMP EDI,0xe     ; unit class 14
0x10145e7a  MOV [ESI+0x128],AL
```

Classes 6 and 14 clear `this+0x128`; every other class sets it. The exported
helper `rome2_unit_card_class_is_immutable` is exactly this predicate.

```
0x10145dfe  CMP byte [ESP+0x48],0x0     ; arg15
0x10145e34  CMP byte [0x11afbd20],0x0   ; DAT_11afbd20
0x10145e43  MOV [ESI+0x11c],AL
```

`this+0x11c` is the truth-table OR of the two, rendered as `0`/`1`.

## Recovered literals and anchors

| Address | Value | Destination |
|---|---|---|
| `0x10145e25` | literal `1` | `this+0x118` |
| `0x10145e5a` | literal `0x14` (20) | `this+0x124` |
| `0x11afbf14` | `0.0f` | `this+0x094`, `this+0x09c` |
| `0x11afbf18` | `0.0f` | `this+0x098`, `this+0x0a0` |
| `0x11971460` | `0xbf800000` (`-1.0f`) | `this+0x154` |
| `0x11971464` | `0xbf800000` (`-1.0f`) | `this+0x158` |
| `0x1173fae4` | vtable anchor | first dword of the `0x10` tag block |

`this+0x154` / `this+0x158` are the **tactical grid bounds**. Both are seeded
to the `-1.0f` "unbounded" sentinel, so a freshly constructed card carries no
grid extent until the caller narrows it.

## String ABI

The five helpers in the `0x100f1xxx` cluster were disassembled individually to
recover their sentinel handling, since Ghidra's summary inlines them away:

| Helper | Body | Behaviour |
|---|---|---|
| `FUN_100f1700` | `0x100f1700..0x100f171f` | deep-copy `length` bytes through `FUN_100ef2c0(data, data+length)`; resulting capacity equals length; `RET 4` |
| `FUN_100f1800` | `0x100f1800..0x100f182d` | `strlen` then assign; `RET 4` |
| `FUN_100f1850` | `0x100f1850..0x100f1866` | `{0, 0, 0x11af408e}`, bare `RET` |
| `FUN_100f1c10` | `0x100f1c10..0x100f1c26` | `{0, 0, 0x11af4090}`, bare `RET` |
| `FUN_100f1c80` | `0x100f1c80..0x100f1cb3` | rejects `0x11af408e` and `NULL`, else frees `data[-4]` |

The constructor initializes fourteen descriptor members. Thirteen use sentinel
`A` (`0x11af408e`); the
member at `this+0x0fc` is the only one cleared through `FUN_100f1c10` and
therefore carries sentinel `B` (`0x11af4090`). Both sentinels are zero-filled
image regions, so they are distinguishable pointers that both spell `""`.

## Heap sub-objects

```
0x10145f3a  PUSH 0x10              ; FUN_100d12b0 -> 0x10 byte tag block
0x10145f4e  ADD ECX,0x4           ; original arg01+4 source vector
0x10145f52  LEA ECX,[EDI+0x4]      ; construct the payload at block+4
0x10145f5a  MOV [EDI],0x1173fae4   ; install the vtable
0x10145f64  MOV [ESI+0x20],EDI     ; store at this+0x020

0x10145f6f  PUSH 0xe8              ; FUN_100d12b0 -> 0xE8 byte attachment
0x10145f81  MOV ECX,EAX           ; allocated attachment receiver
0x10145f83  CALL 0x101350c0        ; source arg00 on stack
0x10145f8c  MOV [ESI+0x1c],EAX     ; store at this+0x01c
```

The attachment allocation is gated on `arg00 != 0` (`TEST EDI,EDI` at
`0x10145f6b`). A failed allocation still falls through to `FUN_101a97f0`, which
closes both exits.

## Host port

`rome2_unit_card_ctor` projects selected fields; the unimplemented helper and
ownership effects listed above prevent full constructor equivalence. The
`RET 0x44` shape has no Win64 equivalent, so the seventeen words arrive in a
`rome2_unit_card_args` record whose member order is the stack index.

The observed x86 constructor prefix spans `0x178` bytes; this alone does not
prove the size of the complete class. The separate native host projection is
`0x1C8` bytes, reflecting its explicit C fields and host alignment. The header
pins selected host offsets with `_Static_assert`; original x86 offsets are
recorded separately. `port/recovered_types/guest32_layouts.h` now provides an
independent fixed-width original prefix and stack-argument layout.

`FUN_1024e480` is entered with
`ECX = this+0x13c`, and the next write in the constructor is at `this+0x14c`.
The authenticated helper performs four zero dword stores. The recovered
layout therefore gives that region an explicit four-word type. This does not
establish its later methods or lifetime. The legacy host projection retains a
zeroed byte region at its chosen native offset.

The new native string runtime and typed initial-global snapshots are described
in [type_recovery.md](type_recovery.md). The nested tag types and owning copy
are documented in [unitcard_tag_type_recovery.md](unitcard_tag_type_recovery.md).
Native tag storage is 24 bytes and native attachment projection storage is
288 bytes, separately from the original 16/232-byte requests. The callback
now receives the allocated attachment receiver. Layer 3 implements those
subobjects and typed UTF-16 lifetime in a separate 472-byte native owning
projection; the legacy projection remains bounded. Original XML/resource
loading and decoding still require implementation.

## Verification

`port/x64_runtime/test_battle_unitcard_10145c70.c` checks original projections
and the explicit native boundary rules:

- record layout and every pinned host offset;
- both string sentinels and the fourteen-member census;
- the class 6 / class 14 immutability predicate;
- every literal-zeroed field;
- the `DAT_11afbf14`/`18` colour duplication and the `-1.0f` grid bound;
- the full scalar projection;
- the byte-flag projection;
- the `arg15 || DAT_11afbd20` truth table in all four combinations;
- the mutable-class gate across seven classes;
- typed vector source/receiver identity, native allocation extents, and the
  separately retained original `0x10`/`0xE8` requests;
- failures at either allocation and missing initializer guards;
- NULL host and NULL argument guards.

`assert` is elided under the `/DNDEBUG` Release profile, so the harness uses a
`REQUIRE` macro that always evaluates, reports the failing expression with file
and line, and exits non-zero. CTest name: `battle_unitcard_10145c70_runtime`.

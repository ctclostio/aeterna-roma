# VFS dispatch and filename-table recovery

This milestone traces the XML loader into the original VFS and adds native
helpers for dispatch observation, filename hashing and name-table probing.
They operate on bounded byte spans and fixed-width guest views. File opening,
mount creation, name lifetime, locking and exception handling remain outside
the native helpers.

## Selected interface and targets

The XML loader calls `0x112e3d20`, adjusts the returned manager address by
four bytes, loads that interface's table, and calls table slot `+4`.
The getter initializes the active manager if necessary before checking the
mode byte at `0x12031a88`. A zero mode selects the static manager at
`0x119e1004`; a nonzero mode selects the active-manager pointer.
Initial zero-filled image values do not establish runtime mode or mount state.

| Observed manager | Interface/table | Slot `+4` target |
|---|---|---|
| Static `0x119e1004` | interface `0x119e1008`, table `0x11897994` | `0x112bd0c0` |
| Active constructor's receiver | interface `receiver+4`, table `0x118978e8` | `0x112bd3b0` |

The active constructor writes tables at receiver `+0`/`+4`, initializes a
counter at `+8`, and supplies `receiver+0xc` to critical-section initialization.
The native layout admits only the eight-byte dispatch prefix. The getter,
allocator and full manager class have not been ported.

`rome2_vfs_read_open_dispatch32` reads the selected interface and slot across
separate object/table views. Only the two selected four-byte cells need mapping.
It returns a 32-bit code identity without invoking it or assigning a native
function prototype. Null entries, missing mappings and arithmetic overflow have
explicit statuses; every failure preserves output. The observed table words
do not prove complete vtable boundaries.

## Active hit and miss paths

The full assembly of `0x112bd3b0` contains two hit branches omitted from the
decompiler's pseudocode. After `0x112bd6f0`, it checks the first candidate and
then the second before constructing an empty result. Those branches must not
be removed when reconstructing the operation.

With a stable enabled mode, the ordinary path enters the manager's critical
section and increments its active-call counter. The candidate paths and miss
path decrement that counter before leaving the section. This observation
does not establish exception-unwind or concurrent mode-change behavior.

When neither candidate is present and allocation succeeds, the active open
operation creates a 12-byte wrapper with table `0x11897be0`, a copied name word
and a zero counter at `+8`. It publishes the wrapper and zero range/state
metadata, then invokes slot `+0x1c`. That slot is the six-byte routine
`0x112d0c80`: it increments counter `+8` and returns while consuming eight
otherwise-unused argument bytes. A recovered prototype that omits those stack
arguments would be wrong.

The wrapper's length slot `+0x10` and data slot `+0x2c` both reference the
shared constant-zero body at `0x100dbc00`. Thus an ordinary active miss reaches
the XML loader as a non-null empty wrapper. The disabled/static open operation
uses a separately initialized static empty-file object.

The XML loader's temporary memory-reader initializer still returns `AL=1` for
zero length. Its next copy requests zero bytes, and byte preparation leads
toward empty parser input. The original path also peeks a word from a
one-byte allocation; release entry `0x112daae0` lacks a decoded procedure in
this provider, and allocation/unwind behavior remains unresolved. These limits
prevent a claim of complete defined quiet-failure equivalence. Existing native
resource APIs retain their explicit diagnostics.

## Filename hash and table

`0x100f3040` adds signed bytes at even positions into a 16-bit low half and
odd positions into an independent 16-bit high half. Each half wraps modulo
`2^16`; processing stops at NUL. It performs no case folding or normalization.
For example, `Script/fauna_config.xml` hashes to `0x045104b2` for exactly those
bytes. `rome2_vfs_hash_name_bytes` provides the same arithmetic over a bounded
span, stopping at its first NUL or end.

`0x112c1130` operates on this wire layout:

| Object | Offset | Observed field |
|---|---|---|
| Table descriptor, 12 bytes | `+0` | Items address, 32-bit |
| | `+4` | Bucket count, 32-bit |
| | `+8` | Empty-name identity, 32-bit |
| Slot, stride 8 | `+0` | Name identity, 32-bit |
| | `+4` | Stored value, 32-bit |

It starts at unsigned `hash % bucket_count`, scans forward, and wraps once.
Query-name equality is checked before the empty-name marker. Equality compares
all 32 bits through `0x101206e0`. A hit returns the **address of slot `+4`**,
not the stored value. `0x1011fe30` copies one name word; its body does not prove
reference counting or ownership. The default table initializer uses 2,003
buckets, but the native probe accepts other valid counts.

`rome2_vfs_probe_name32` takes a precomputed hash and opaque name identity.
It returns the matched value cell, a checked observation of its stored value,
slot index and probe count. A matched NULL value remains a match; a missing key
has a separate status. The helper adds descriptor/numeric-array validation,
checks only visited keys and a matched value mapping, and bounds work by the
smaller of bucket count and caller-supplied probe budget. Budget exhaustion
before a complete scan is inconclusive, not a missing-key result. All non-OK
results preserve output.

The helpers do not intern names or populate the table. Probe order establishes
collision handling, while mount and insertion policy determine which file value
is stored. Full archive/mod/dependency precedence remains open.

## Evidence and checks

Target: `empire.retail.dll`, 28,278,272 bytes, SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.

| Observation | REA Evidence ID |
|---|---|
| Manager getter | `ev_4d0e00db30ddc08a5a13b20a0d0fc035caf0872c9f2bcd6877815632c67930eb` |
| Manager constructor | `ev_6c40ca90fe707265a35b6480edc7c8841d27b514404cac9945b1b268c157a7dc` |
| Active open, including hit branches | `ev_51f0ccc9883c4bf5b5380f385aa21392604ccc645ad1971966094701daaaf37e` |
| Candidate lookup | `ev_83d0b52360a70d3967dc94ba52451c8a22a5e430e20d97b5ca3b8873b828e171` |
| Name-table probe | `ev_46568ec6ecd324258cbb2d93ed839de0abc54f24decbd44d86a13f5d92d47cd4` |
| Signed-byte hash | `ev_e4ef52a235eebce63bbe514cc075de91b8d27dc9cb159bc2723aad513c358a3f` |
| Constant-zero method body | `ev_b64e0ec622feb710c3ce1b7ba220e46aeba3858e7e38b452e7161a58e3b0b433` |

The constructor and table initializer have disjoint database-reported bodies:
943 code bytes within a 952-byte span, and 180 within a 183-byte span. The
validator now supports explicit inclusive body ranges, hashes their code bytes
in order, and requires return instructions to lie wholly inside a body range.
The nine- and three-byte gaps remain outside the admitted code. Legacy
contiguous contracts retain their behavior.

Verification: **64 local native suites** pass in optimized and ASan profiles.
The dispatch suite runs **2,459 checks** and the names suite **134,705**, including
all two-byte hash inputs, signed/16-bit wrap cases, collisions differing only in
high identity bits, unsigned hashes, split/unaligned mappings, wrap order,
empty/match order, NULL values, probe budgets and 32-bit endpoints. The focused
contract module passes **37 tests**. Clean public Python runs pass **865 tests**
on 3.14 and 3.15, with 264 expected private-evidence skips each.

The registry verifies **72 function bodies, 63 globals, 12 first vtable slots
and 62 instruction windows**. The private 28-record bundle was validated and
the native session closed. The large constant-zero dossier exceeded the MCP
response budget; retained views and its complete exported record were used
without repeating analysis. Argon's native code review found no confirmed defect.

These results combine static original-image evidence with separately tested
native adaptations. The game was not executed. Shared Ghidra state, canonical
exports and frozen admission locks were unchanged. Game binaries, assets and
full retained evidence remain outside Git. See [progress.md](../progress.md).

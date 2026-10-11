# Injected handler transcript for `0x100e9340`

`0x100e9340` is the fourth slot-4 method registered by original
`0x100ea4d0`. This milestone admits a four-step, injected transcript of its
normally completed path. It preserves the handler's authenticated dataflow
and publication order without calling recovered x86 addresses or reproducing
the original process-global, TLS, allocator, or platform effects.

## Authenticated body and vtable identity

The pinned original is `empire.retail.dll`, exactly 28,278,272 bytes with
SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
The complete handler is the 74-byte interval
`[0x100e9340, 0x100e938a)`, at `.text` raw offset `0x000e8740`, with
SHA-256
`52f130537cbe5ce500544e8f55fc50daa848c9202bd515f11cb173a6a602d1b6`.
Twelve `0xcc` bytes precede it and six `0xcc` bytes follow it.

The canonical function index has no `0x100e9340` entry: the body occupies the
gap between indexed intervals `0x100e92c0-0x100e9333` and
`0x100e9390-0x100e948a`. Its two-cell vtable record is at `0x1173f224`, raw
offset `0x0173dc24`, and contains `(0x100e1900, 0x100e9340)`. The eight record
bytes have SHA-256
`a68ce6065bb6d0e257c3678a0cbbbfc4cc1b10565ca46f46a417162b09ffcf8d`.
Constructor `0x100e1900` publishes that vtable, and the pinned image contains
no direct `call` or `jmp` reference to the handler; the method is reached
through the vtable.

The original body obtains the service rooted at `[0x119f3140] + 0x874` twice.
It invokes virtual slot `+0x0c` with selector `0x12` and loads a dword from
the returned pointer, then invokes virtual slot `+0x1c` with selector `0x49`
and loads one byte from that returned pointer. It next calls `0x112e1830`,
uses that call's returned native singleton pointer as ECX, and calls
`0x112cbbb0` with three stack arguments.

The helper's second argument has an unusual but authenticated origin. The
entry `push ecx` saves the receiver; after `push esi`,
`mov byte ptr [esp+4], al` replaces only that saved receiver's low byte. The
result is therefore:

```text
patched_receiver = (guest_receiver & 0xffffff00) | selected_byte_49
```

The incoming stack argument is never loaded. After the helper completes, the
body executes `mov al, 1` and `ret 4`; it defines only AL, not the upper bits
of EAX.

## Four-step portable contract

`rome2_port_100e9340_run_handler_transcript` accepts the receiver and ignored
argument as opaque `rome2_guest_addr32` values. Every 32-bit bit pattern,
including zero and unaligned identities, is admissible because neither value
is dereferenced. The injected `selected_dword_12` supplies the completed
four-byte lookup result, while `selected_byte_49` must be in `[0, 255]` and
supplies the completed one-byte result.

On success the adapter emits exactly these by-value records:

| Step | Transcript kind | Arguments | Exposed result |
|---:|---|---|---|
| 1 | `LOOKUP_DWORD_12` | selector `0x12` | width 4, `selected_dword_12` |
| 2 | `LOOKUP_BYTE_49` | selector `0x49` | width 1, `selected_byte_49` |
| 3 | `CALL_112E1830` | none | none; native singleton pointer suppressed |
| 4 | `CALL_112CBBB0` | `(selected_dword_12, patched_receiver, 0)` | none |

Only after the fourth callback returns does the adapter publish
`return_al_out = 1`. It exposes no full EAX value and invents no portable
return for the original native singleton getter.

This is deliberately a completed-path boundary. Supplying already-loaded
lookup values excludes null or unreadable lookup-result pointers and their
x86 faults. Likewise, the last two records mean that the original getter and
helper completed normally; they are evidence identities, not authorized call
targets.

## Failure atomicity and callback boundary

Before the first effect, the adapter validates the complete borrowed effects
object and one-byte output object, including numeric host-span overflow,
natural alignment of the effects object, and pairwise disjointness. It then
snapshots the complete effects object and validates the snapshotted callback,
context, and byte value. A null object, missing callback or context,
misalignment, overlap, or out-of-range byte fails closed. Numeric host-span
wrap reports `ROME2_GUEST_RANGE_OVERFLOW`; other rejected arguments report
`ROME2_GUEST_BAD_ARGUMENT`.

Every validation failure occurs before a callback, emits no record, and
leaves the output byte unchanged. On the admitted path, callback effects are
committed sequentially and are not rolled back. The callback contract is
therefore intentionally narrow: it is total and non-reentrant, returns
normally, does not retain borrowed objects, and does not modify the output.
It may mutate its own context or the caller's original effects object because
all four records use the pre-effect snapshot. A callback contract violation
is outside this model; there is no invented mid-transcript recovery status.

## Excluded native effects

The direct-call suffix cannot safely become a native x64 call boundary:

- `0x112e1830` is an authenticated 290-byte singleton getter at raw offset
  `0x012e0c30`, SHA-256
  `64d02765657eae86676a99593cc1783853cab51a531931597a30b2218ca4edd2`.
  Its initialization path allocates `0x6c` bytes, calls `TlsAlloc` twice,
  obtains the current thread ID, initializes two critical sections, invokes
  `0x100fcc80`, and publishes process-global/TLS state including
  `DAT_12032e68`, `DAT_12031ad0`, and `DAT_12031ad4`.
- `0x112cbbb0` is an unindexed 86-byte helper at raw offset `0x012cafb0`,
  SHA-256
  `8cac67abb474a5043787387b354a6ec3171a9e14a261137c30b9a392464a5d28`.
  It mutates the singleton, calls `TlsSetValue` twice, calls unindexed
  `0x1136a220`, stores that result, and passes callback identity `0x112c6d60`
  to `0x10113620`, which publishes `_DAT_119f3eac` and sets
  `DAT_119f3d8a` to one.

The port performs none of those operations. It has no native/original
allocator, TLS, platform, singleton, or mutable-global dependency; performs
no guest dereference or guest/native cast; and never executes a recovered
address.

## Containment and verification

The frozen implementation and its independent oracle are:

| Authority | SHA-256 |
|---|---|
| `ported_100e9340_handler_transcript.h` | `03f7a477e4a5ee5b0aa2dc77b70ba0bc492dbe6531fd505f9c455ded3f8d75a9` |
| `ported_100e9340_handler_transcript.c` | `ca6e27ef29f255795567784c354551c3dc114d223aea9611e62930433cd4aec5` |
| `test_startup_100e9340_handler_transcript.c` | `eebc924d6f95e842a11756f7f0bc4e2bbec75186ad3fa38562d02f5c34528455` |
| executable provenance test | `f17a82848edd7d02957dbd21a892faf6e6ba553a7d9ad26a5cef74e2e31757a2` |
| fail-closed static gate | `b0218352428e75182a34bda52a606b19a2e1bf52639607b6ea6f585f471fcb41` |
| reciprocal mutant suite | `e7b0d4535b77b9a2201c4d9e114d2885ec1861e5eaa5f20a741d4f61dc7b6e2f` |

The runtime oracle checks exact four-step order and contents, receiver
boundary substitutions, ignored argument opacity, complete effects
snapshotting, output publication after the final callback, malformed and
overlapping borrowed objects, and invalid injected values. The provenance
suite pins the original image, body boundaries, vtable/constructor mapping,
both lookup sequences, saved-receiver byte replacement, direct targets,
AL-only publication, imported TLS/platform APIs, and the unindexed discovery
gaps.

The static gate admits the transcript only as the BUILD_TESTING-only static
library `rome2_startup_100e9340_handler_transcript_runtime`. Its only direct
consumers are the dedicated runtime test and `rome2_headless64`; it has no
link dependency and no export-manifest, legacy-DEF, or probe-DEF surface. The
headless composition calls it once from standalone router dispatch and once
from injected outer dispatch, then reports
`initializer-handler-100e9340=injected-transcript-complete`.

The chronological link tail begins with the injected `0x100ea4d0` outer
initializer followed by this transcript. Its runtime follows fixture
`startup_100ea4d0_injected_reload_verified`, and its post-PE/bootstrap chain
establishes `startup_100e9340_handler_transcript_reload_verified` before the
`0x100e92c0` and `0x100e87a0` chains continue to the headless lifecycle.

The runtime passed strict MSVC C17 compilation with `/W4 /WX /sdl /GS
/guard:cf /analyze` and a separate `/MT /fsanitize=address` build/run. The
runtime emits `100e9340 handler transcript: ok`; the provenance suite passes
8/8 tests, and the reciprocal static-gate suite passes 12/12 tests.

The registered slot-4 handlers after this fourth transcript, `0x100e92c0` and
`0x100e87a0`, now have independently authenticated bounded adapters and are
joined after it. Their original native callees remain outside this milestone.

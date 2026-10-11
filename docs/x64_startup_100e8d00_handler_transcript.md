# Bounded handler transcript for `0x100e8d00`

`0x100e8d00` is the first slot-4 method registered by original
`0x100ea4d0`. The x64 milestone preserves its authenticated call transcript,
but does not call any recovered x86 target or reproduce those targets' native
side effects.

## Authenticated original behavior

The complete original body is the 55-byte interval
`[0x100e8d00, 0x100e8d37)`, at raw file offset `0x000e8100`, with SHA-256
`721c0a9b4df58497dd3362758ecbb2f73be24e5223bbad3faf01b3442811b3fe`.
The method identity is pinned at vtable `0x1173f20c + 4`; the surrounding
two-cell record is `(0x100e1720, 0x100e8d00)`.

The exact direct-call sequence is:

| Step | Target | Raw push order | Callee-visible arguments |
|---:|---:|---|---|
| 1 | `0x10cb6160` | `1`, `0` | `(0, 1)` |
| 2 | `0x10115d40` | `0` | `(0)` |
| 3 | `0x112dc9f0` | `0`, `0x1173fb44` | `(0x1173fb44, 0)` |
| 4 | `0x101150a0` | `1` | `(1)` |
| 5 | `0x101151d0` | `0` | `(0)` |
| 6 | `0x112e2cb0` | none | `()` |

The identity `0x1173fb44` addresses the authenticated 16-byte object
`"PRE_DB_APP_INIT\0"`. The first seven pushed dwords are removed together by
`add esp, 0x1c` before step six. Only after the sixth call returns does the
method execute `mov al, 1; ret 4`. Neither the thiscall receiver nor the sole
stack argument is inspected.

## Portable boundary

`rome2_port_100e8d00_run_handler_transcript` accepts the receiver and argument
as opaque `rome2_guest_addr32` values and emits six typed, by-value steps to a
required callback. Arguments are represented in callee-visible order; original
target addresses and the static string identity remain numeric evidence, never
native function or data pointers.

The complete callback/context pair is snapshotted before the first effect.
Each callback must be total and non-reentrant. The one-byte AL output remains
unchanged during all callbacks and is set to one only after step six returns.
This makes ordering observable without introducing native calls, allocation,
platform APIs, or mutable global state.

## Deliberate safety narrowing

The original body assumes that its process-global callees and stack are valid.
The portable API instead rejects a null callback, null context, null output,
numeric host-span overflow, or overlap between the borrowed effects object and
the output. Such validation failures emit no step and preserve the output.
These checks are port policy; they are not claims that the x86 body performed
equivalent validation.

## Composition and verification surfaces

The milestone consists of:

- `port/x64_ported/ported_100e8d00_handler_transcript.{h,c}`;
- the independent runtime oracle
  `port/x64_runtime/test_startup_100e8d00_handler_transcript.c`;
- exact original-byte provenance in
  `scripts/test_x64_startup_100e8d00_handler_transcript_provenance.py`; and
- a fail-closed static gate with reciprocal mutants.

`rome2_headless64` uses the transcript when injected dispatch encounters method
identity `0x100e8d00` and reports
`initializer-handler-100e8d00=injected-transcript-complete`. This is an
executable model of the handler's observable call shape, not execution of the
six original callees.

The next registered method is the bounded `0x100e85d0` adapter. All five later
slot-4 methods now also have bounded executable adapters, and the two composed
routers dispatch all six without a synthetic success fallback.

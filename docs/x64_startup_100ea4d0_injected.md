# Bounded injected outer registration for `0x100ea4d0`

The executable `0x100ea4d0` milestone composes the unified `0x100e2460`
storage router around six injected handler allocations and six authenticated
vtable identities. It is a test-only guest32 model, not a native call to the
original function or allocator.

## What the original bytes establish

The full original body is the 265-byte interval
`[0x100ea4d0, 0x100ea5d9)`, at raw offset `0x000e98d0`, with SHA-256
`582b4c4324650b88f969c1af5fac0dce0d6ffd69e1043ee99d834e6b102c7af3`.
It derives the common dispatch argument at `receiver + 0x824` and vector at
`receiver + 0x854`. Six unrolled registrations then call
`0x100d12b0(4)`, conditionally store one vtable identity, and call
`0x100e2460` in this order:

| Registration | Vtable | Slot `+4` method |
|---:|---:|---:|
| 1 | `0x1173f20c` | `0x100e8d00` |
| 2 | `0x1173f214` | `0x100e85d0` |
| 3 | `0x1173f21c` | `0x100e8580` |
| 4 | `0x1173f224` | `0x100e9340` |
| 5 | `0x1173f2ec` | `0x100e92c0` |
| 6 | `0x1173f2dc` | `0x100e87a0` |

The original skips a vtable store when allocation returns null but still
reaches the corresponding router call. A zero result from `0x100e2460`
deliberately reaches a null-write trap. There is no early allocation-free
branch and no meaningful native return value.

## Injected executable design

`rome2_port_100ea4d0_run_injected` accepts bounded writable state and read-only
vtable views, an opaque guest receiver, a complete effects object, and a finite
Peek budget. After validating and snapshotting the control surface, it performs
six iterations:

1. call the total injected handler allocator with `(4, 0)`;
2. validate the returned four-byte guest span and its disjointness;
3. store the corresponding authenticated vtable identity;
4. invoke `rome2_port_100e2460_run_router` with the shared vector, handler, and
   derived argument identities;
5. verify that every registered handler still contains its exact vtable; and
6. require router success and a nonzero returned AL.

The router supplies the admitted capacity-zero, growth, and preallocated
storage sequence. Allocation, old-backing release, dispatch, and Peek behavior
remain injected; no original allocator, original handler, USER32 API, or guest
function pointer is called.

## Safety narrowing

The port deliberately rejects states the original could enter:

- null, overflowing, unmapped, or overlapping control/view objects;
- zero Peek budget;
- receiver overflow while deriving `+0x824` or `+0x854`;
- handler results that are null, unmapped, overlap each other, or alias the
  vector, argument cell, complete active backing, or vtable view;
- invalid current backing state;
- router failure or zero AL; and
- any router-induced corruption of the accumulated handler graph.

The original null-allocation continuation and null-write trap are therefore
replaced by explicit statuses. Requiring the complete active backing and
argument cell to be mapped, and rejecting physical as well as logical aliases,
are also port policy rather than recovered x86 checks.

## Prefix-commit semantics

Prevalidation failures have no effect. Once iteration begins, effects commit
in original order and are never rolled back. An invalid allocation result
leaves that allocator callback and all prior registrations committed. A later
router failure may leave the current allocation, vtable store, vector changes,
allocation/release callbacks, dispatch, and Peek effects committed. Graph
corruption and zero AL are reported only after the current router call has
returned.

This explicit prefix policy avoids pretending that arbitrary injected effects
can be undone.

## Handler coverage and verification surfaces

The composed headless dispatch executes bounded models for all six method
identities:

- `0x100e8d00`: six-step injected transcript;
- `0x100e85d0`: effect-free AL adapter;
- `0x100e8580`: nine-step dependent injected transcript;
- `0x100e9340`: four-step lookup/singleton/helper transcript;
- `0x100e92c0`: six-step both-predicates-true transcript in the composed host,
  with all three authenticated branch routes covered independently; and
- `0x100e87a0`: injected listener allocation, checked vtable store,
  publication, and FaceFX-startup transcript.

There are no synthetic method-success returns left in either composed router.
Every original native callee behind these transcripts remains injected rather
than linked or called.

The milestone is covered by the independent runtime oracle
`test_startup_100ea4d0_injected.c`, the source-pinned executable provenance
test, the earlier full-body evidence authority, and a fail-closed static gate
with reciprocal mutants. `rome2_headless64` reports
`initializer-100ea4d0=injected-complete` only after the six-registration
composition succeeds. The handler checkpoint was covered by 136 CTests; the
later 148-test chain continued through both bounded `0x100df270` transcripts.
The current empty-preloop parent checkpoint registers 154 tests and composes
those transcripts inside `[0x100ed3c0,0x100ed471)`. Its testing-disabled
control contains neither the outer target nor any other test-only port.

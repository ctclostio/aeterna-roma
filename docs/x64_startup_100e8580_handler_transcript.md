# Dependent handler transcript for `0x100e8580`

`0x100e8580` is the third slot-4 method registered by original
`0x100ea4d0`. Its bounded x64 model preserves nine direct-call steps and makes
the result dependency between calls seven and eight explicit.

## Authenticated original behavior

The complete body is the 75-byte interval `[0x100e8580, 0x100e85cb)`, at raw
offset `0x000e7980`, with SHA-256
`baeed663cb3c273a7e4a6cceb6cd6976695f2226e321bb231e484758a2cf3dfe`.
The vtable record at `0x1173f21c` is `(0x100e1250, 0x100e8580)`.

The authenticated sequence is:

| Step | Target | Callee-visible arguments or result |
|---:|---:|---|
| 1 | `0x100d6560` | `()`; authenticated no-op helper |
| 2 | `0x112d0510` | `()` |
| 3 | `0x112e0950` | `(1)` |
| 4 | `0x100d9810` | `()` |
| 5 | `0x100ddf50` | `()` |
| 6 | `0x112e0950` | `(0)` |
| 7 | `0x100e8240` | `(0)`, returning an identity in EAX |
| 8 | `0x112bfee0` | `(step_7_result + 0x68)` |
| 9 | `0x112dcaf0` | `(0x1173fb54, 0, 0)` |

`0x1173fb54` identifies the authenticated object `"Finished run_vars\0"`.
The flag pushes for steps three and six are discarded together with
`add esp, 8`. The five later pushed dwords are discarded with
`add esp, 0x14`. `AL=1` is defined only after step nine returns, followed by
`ret 4`. The receiver and incoming stack argument are ignored.

## Portable boundary and result dependency

`rome2_port_100e8580_run_handler_transcript` emits typed steps through a total,
non-reentrant callback. The effects object includes an explicit injected
`result_100e8240`; step seven publishes that identity as its result, and the
adapter passes checked `result + 0x68` to step eight. The complete callback,
context, and injected result are snapshotted before step one, so callback-side
mutation cannot redirect later effects or change the dependency.

The output remains unchanged throughout all callbacks and is set to one only
after step nine. No recovered target is called, and no guest identity becomes
a native pointer.

## Deliberate safety narrowing and prefix commits

Borrowed-object validation is fail-closed and precedes every callback. Null or
overlapping effects/output objects, missing callback/context, and numeric host
span overflow emit nothing.

After step seven, the adapter applies the guest32 checked-add policy. A zero
result returns `ROME2_GUEST_NULL_ADDRESS`; a value above `0xffffff97` returns
`ROME2_GUEST_RANGE_OVERFLOW`. Exactly seven callback effects remain committed,
steps eight and nine do not run, and AL remains unpublished. The original x86
`add eax, 0x68` itself was wrapping arithmetic and did not perform these null
or overflow checks. The new failures are intentional safety narrowing.

## Composition and verification surfaces

The implementation lives in
`port/x64_ported/ported_100e8580_handler_transcript.{h,c}`. Its independent
runtime oracle covers the ordinary and maximum admissible dependency,
null/overflow prefix behavior, callback snapshotting, publication ordering,
aliases, and opaque inputs. Original body, calls, pushes, cleanups, vtable, and
string identity are pinned by
`scripts/test_x64_startup_100e8580_handler_transcript_provenance.py`; a static
gate and reciprocal mutants enforce the boundary.

`rome2_headless64` selects the adapter for method `0x100e8580` and reports
`initializer-handler-100e8580=injected-transcript-complete`. This completes
bounded models for the first three registered handlers. The subsequent
`0x100e9340`, `0x100e92c0`, and `0x100e87a0` adapters are now authenticated and
joined too, so the composed routers no longer use synthetic handler returns.

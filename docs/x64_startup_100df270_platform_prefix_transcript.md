# Injected platform-prefix call-shape transcript for `0x100df270`

Status: admitted, native, and `BUILD_TESTING`-only. This milestone covers the
complete first 211 bytes of original `0x100df270` as exact deterministic
guest32 writes plus a typed transcript of every call shape. It does not invoke
Win32, load resource contents, create a native mutex, change mouse settings,
show a dialog, or terminate the process.

## Authenticated boundary

The admitted interval is `[0x100df270, 0x100df343)`, at `.text` raw offset
`0x000de670`. Its 211 bytes have SHA-256
`7d21f9b8d851f08196dbe6ae51dfc4a1743169ac320098979603a1c0f5a54dda`.
The interval begins at the original function entry and ends immediately before
the already-admitted deterministic field projection at `0x100df343`. Together
with that 298-byte projection and the 131-byte suffix transcript, the three
boundaries account for all 640 bytes of the original function without making
the excluded native effects executable.

The provenance authority parses the pinned 28,278,272-byte original PE as
inert data (SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`)
and authenticates:

- both calls through the `LoadStringW` IAT cell at `0x1172f66c`, with resource
  IDs `0x6d` and `0x67`, destinations `receiver + 0x408` and
  `receiver + 0x08`, and capacity `0x200` UTF-16 code units;
- `CreateMutexW` through IAT cell `0x1172f17c`, the `0x100f3880`
  `GetLastError` thunk, `MessageBoxW` through `0x1172f69c`, and both
  `SystemParametersInfoW` calls through `0x1172f6a8`;
- direct calls `0x100df2c6/0x100df305 -> 0x100edfe0` and
  `0x100df321 -> 0x10102850`, plus their exact bodies;
- both short branches to `0x100df326`, including the exact
  `ERROR_ALREADY_EXISTS` value `0xb7` and packet-byte test at `+0x2c`;
- the first adjacent byte at `0x100df343`, the full parent body, and canonical
  function-index/source authorities.

The resource-dependent call sites are evidence, not invented text. The two
resource payloads returned for IDs `0x6d` and `0x67` are deliberately not
materialized. The three fixed UTF-16 literals used around them are pinned
separately, including their terminating NULs:

| Original identity | Text | Bytes | Raw offset | SHA-256 |
|---|---|---:|---:|---|
| `0x1173f440` | `Mutex error` | 24 | `0x0173de40` | `0852874ae53ba9395b0353e84928f99ff68211f97250e8c5ce56d34e93805ee9` |
| `0x1173f460` | `%s instance verification mutex` | 62 | `0x0173de60` | `27d4b227aa2df8c194ae21002c4a24d7e0591e4c12107245e0df862691cb9622` |
| `0x1173f4a0` | `Another instance of %s is running.\nThis instance will terminate.` | 130 | `0x0173dea0` | `8386f33ed228dfb9194d46af71f49253b21b058edf6c86f1acb4a8d9b6ce13ee` |

## Executable contract

```c
rome2_guest_status rome2_port_100df270_run_platform_prefix_transcript(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_packet,
    const rome2_100df270_prefix_effects *effects,
    rome2_guest_addr32 *return_receiver_out);
```

Steps contain four typed argument slots and one typed result slot. A value is
explicitly classified as a scalar, guest identity, original-image identity,
symbolic local-buffer identity, opaque x86 value, or unused zero. Original
identities remain evidence data and are never converted to native pointers.
The original 512-element stack buffer is represented only by symbolic local
buffer ID `1`. Every step is passed to the total observer callback by value.

The normal route emits exactly seven steps:

1. `LOAD_TITLE`: `(opaque instance, 0x6d, receiver + 0x408, 0x200)`;
2. `LOAD_NAME`: `(opaque instance, 0x67, receiver + 0x08, 0x200)`;
3. `FORMAT_MUTEX_NAME`: `(local buffer 1, 0x200, 0x1173f460,
   receiver + 0x08)`;
4. `CREATE_MUTEX`: `(NULL security, TRUE, local buffer 1)`, returning the
   injected opaque 32-bit mutex value;
5. `GET_LAST_ERROR`, returning the injected scalar error;
6. `GET_MOUSE_TRAILS`: `(0x5e, 0, 0x119f3854, 0)`; and
7. `SET_MOUSE_TRAILS`: `(0x5d, 0, 0, 0)`.

Exactly when the snapshotted error is `0xb7` and packet byte `+0x2c` is zero,
three steps are inserted after `GET_LAST_ERROR`, producing ten steps:

6. `FORMAT_DUPLICATE_MESSAGE`: `(local buffer 1, 0x200, 0x1173f4a0,
   receiver + 0x08)`;
7. `SHOW_DUPLICATE_MESSAGE`: `(NULL owner, local buffer 1, 0x1173f440,
   0x10)`; and
8. `TERMINATE_PROCESS`, representing direct helper `0x10102850`.

The two mouse-trails steps then remain steps 9 and 10. This fallthrough is
intentional: the exact 16-byte `0x10102850` body calls `GetCurrentProcess`,
calls `TerminateProcess` with exit code zero, and contains a `ret`. A real
successful termination would prevent observation, but a total injected
callback returns and preserves the original machine-code fallthrough without
terminating the test process.

## Exact writes and commit order

Only three guest dword writes are executable:

| Commit point | Destination | Value |
|---|---|---|
| Before the first callback | `receiver + 0x04` | packet dword at `+0x00` |
| Before the first callback | `receiver + 0x00` | initial vtable identity `0x1173f208` |
| After `CREATE_MUTEX`, before `GET_LAST_ERROR` | `receiver + 0x808` | injected opaque mutex value |

The original store order is `+0x04`, then `+0x00`. During the
`CREATE_MUTEX` callback, `receiver + 0x808` still has its entry value; the
injected mutex becomes visible at the following `GET_LAST_ERROR` callback.
The caller's receiver output remains unchanged throughout every callback and
is published only after the final mouse-trails callback returns.

The complete packet, the two `LoadStringW` destination buffers, and every
receiver byte outside those three dwords remain unchanged. In particular, the
transcript does not pretend that the observer populated resource strings or
the original global at `0x119f3854`.

## Fail-closed boundary

The API requires a complete non-null `0x80c`-byte receiver and a complete
non-null `0x2d`-byte packet in one borrowed guest32 write view. Their logical
and physical spans must be disjoint. The view, effects descriptor, and output
must have complete non-wrapping host ranges, natural alignment, pairwise-
disjoint control storage, and no overlap with the view backing interval. Guest
and host interval ends, every receiver-derived identity, and the full spans
are checked before commit; an interval ending exactly at `2^32` is valid.
Guest spans may be unaligned because all guest cells are assembled and stored
bytewise.

The view, complete effects descriptor, packet instance, and packet branch byte
are snapshotted before the first write or callback. Invalid input emits no
step and preserves all guest bytes and the output. After emission begins,
callbacks and the three deterministic writes form an observable committed
prefix; there are no fallible operations left in the adapter. Callbacks are
total and nonreentrant, retain no borrowed object, and may mutate only their
disjoint modeled context. The runtime oracle also adversarially rewrites the
caller's effects object after the first callback and confirms that every later
field and the route still come from the pre-effect snapshot.

## Containment and headless composition

`rome2_startup_100df270_platform_prefix_transcript_runtime` is a static
library created only under `if(BUILD_TESTING)`. It links the shared guest32
runtime as its explicit public dependency. Its only consumers are its
independent runtime test and `rome2_headless64`; it is absent from the
production DLL, probe DLL, export manifest, and all DEF surfaces.

The headless harness executes the normal seven-step route before the existing
post-platform projection, using opaque instance `0x00400000`, injected mutex
`0xdecafbad`, and last error zero. It validates every typed field and commit
point, then reports
`startup-100df270-platform-prefix=injected-call-shape-complete`. It continues
to report `platform-effects=not-run` and
`post-platform-state=bounded-empty-projection`; those qualifiers are essential
to the token's meaning.

## Verification chain

This historical platform-prefix checkpoint contained 148 named CTests. The
current empty-preloop parent checkpoint registers 154. This slice contributes
the standard six-stage chain:

1. original-PE and resource/callee provenance;
2. reciprocal static-gate mutant tests;
3. the live containment/static gate;
4. the independent 36-case native runtime oracle;
5. the post-slice PE/export containment gate; and
6. bootstrap DLL reload after that PE gate.

The runtime fixture requires the preceding
`startup_100df270_suffix_transcript_reload_verified` fixture plus this slice's
provenance and static gates. The PE gate requires the runtime and shared PE
tool. Its reload establishes
`startup_100df270_platform_prefix_transcript_reload_verified`, which is then
required by the composed headless lifecycle. The current terminal fixture is
`startup_100ed3c0_empty_preloop_reload_verified`.

The 36-case oracle covers exact 7/10 order, every value domain and unused-zero
field, the full two-by-two branch matrix, all three commit points, delayed
output, effects snapshotting, exact byte preservation, zero and all-ones
opaque inputs, unaligned spans, the guest32 upper endpoint, and fail-closed
range/wrap/truncation/alias/control/misalignment failures. Strict MSVC
`/W4 /WX /sdl /GS /guard:cf /analyze` and the `/MT /fsanitize=address`
runtime both pass.

## Remaining boundary

This milestone closes the local byte coverage of `0x100df270` only as a
bounded composition of an injected call-shape prefix, a deterministic
post-platform projection, and an injected suffix. A real x64 host adapter for
resource loading, named-mutex policy, dialog/termination behavior, and mouse
settings remains separate work. The empty-input straight-line parent interval
`[0x100ed3c0,0x100ed471)` is now admitted as a bounded injected composition;
the following `[0x100ed471,0x100ed550)` lifecycle interval, the rest of the
launcher-facing parent, and gameplay remain outside the executable boundary.

# Bounded headless projection from `0x100df270`

Status: admitted, native, and `BUILD_TESTING`-only. This milestone implements
one deterministic middle slice of the original function. It does not port or
simulate the full platform constructor.

## Accepted boundary

The original 640-byte function has three materially different regions:

1. `0x100df270-0x100df342` performs object writes plus resource loading,
   mutex creation, last-error handling, an optional message/termination path,
   and two `SystemParametersInfoW` calls.
2. `0x100df343-0x100df46c` performs deterministic field writes and four direct
   calls to small recovered helpers.
3. `0x100df46d-0x100df4ef` publishes a global object, enters additional
   initializer/allocation-capable code, performs two indirect virtual calls,
   conditionally invokes four more side-effecting helpers, and returns through
   the original x86 epilogue.

This projection admits region 2. The adjacent suffix milestone now admits
region 3 separately as an injected transcript. The two calls to `0x100f1aa0`
in region 2 are accepted only for the already-proven zero-count route. The
native projection API therefore requires both embedded sequence descriptors at
packet offsets `+0x08` and `+0x14` to have zero counts.

```c
rome2_guest_status rome2_port_100df270_project_headless_empty_state(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_object,
    rome2_guest_addr32 guest_packet,
    rome2_guest_addr32 *guest_return_out);
```

The complete `0x8a8`-byte object and `0x2d`-byte packet must be present,
non-null, and disjoint inside one borrowed guest32 view. Guest identities stay
32-bit values. Every validation failure preserves the full view and return
output. Successful execution changes only the authenticated destinations:

| Object offsets | Final value |
|---|---|
| `+0x000` | guest identity `0x1173f2f4` |
| `+0x80c` | guest identity `0x11741e08` |
| `+0x810`, `+0x814`, `+0x81c`, `+0x820` | zero |
| `+0x824`, `+0x828` | packet `u32` values at `+0x00`, `+0x04` |
| `+0x82c`, `+0x838` | `{0, 0, 0x11af4090}` empty triplets |
| `+0x844`, `+0x848`, `+0x84c`, `+0x850` | packet values at `+0x20`, `+0x24`, `+0x28`, `+0x2c` with their original widths |
| `+0x854`, `+0x864` | unchanged 32-bit `guest_object` identity |
| `+0x858-0x860`, `+0x868-0x870`, `+0x878-0x880` | zero cells |
| `+0x874` | guest identity `0x1173dc18` |
| `+0x888`, `+0x88c`, `+0x894`, `+0x89c`, `+0x8a0`, `+0x8a4` | zero |
| `+0x898` | `0xffffffff` |

All other object bytes remain unchanged. In particular the platform-owned
resource buffers, mutex cell at `+0x808`, and unwritten holes at `+0x818`,
`+0x884`, and `+0x890` are not fabricated.

## Raw provenance

The verifier parses the pinned 28,278,272-byte original PE as inert data
(SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`)
and authenticates:

- full `0x100df270`, raw offset `0x000de670`, 640 bytes, SHA-256
  `d5a89108422a8c8a07d7150501805b70cedf81686b2f6a7e105e6d39d3a725f7`;
- the exact 298-byte accepted slice at `0x100df343`, raw offset
  `0x000de743`, SHA-256
  `a28d5aa15f78ba8ae4aac1738d5163d4cccf7d1d6d124eb0c117a6d09914beff`;
- direct slice calls `0x100df351 -> 0x100f0eb0`,
  `0x100df386/0x100df395 -> 0x100f1aa0`, and
  `0x100df468 -> 0x1014d170`, plus each exact leaf body;
- `0x100f1aa0`'s call at `0x100f1ab4` resolving to `0x100ef330`, and the
  helper's exact 23-byte zero branch, which writes `0x11af4090` without reading
  the collapsed source arguments;
- the immediately preceding system-parameter window and the following global,
  initializer, virtual-dispatch, and 15-byte epilogue windows as explicit
  exclusions;
- the parent call packet at `0x100ed454-0x100ed470`, including
  `0x100ed463 -> 0x100df270`;
- exact canonical sources and function-index rows for the parent, body, and
  three admitted direct callees.

Canonical C remains a cross-check. It is not used as the x86 ABI oracle.

## Containment and execution

`rome2_startup_100df270_headless_runtime` is a static library created only
inside `if(BUILD_TESTING)`. Its only consumers are its dedicated runtime test
and `rome2_headless64`. The static gate rejects shared/production/probe/export
routes, native-pointer conversion of guest identities, platform APIs,
allocation, excluded recovered targets, changed span checks, nonempty source
acceptance, writes to excluded holes, and early output mutation.

The headless harness now executes the projection and reports both
`platform-effects=not-run` and
`post-platform-state=bounded-empty-projection`. This is useful deterministic
state construction. The composed headless harness now continues through the
separately bounded initializer graph and final suffix transcript, but it is not
permission to call the original parent or native virtual targets.

## Remaining boundary

The three neighboring direct calls and their enclosing final suffix now have
bounded executable models: the `0x100e8240` no-crash fast path, the short
nonallocating branch reached by `0x100df482 -> 0x100f2750`, the complete
injected six-registration graph at `0x100df489 -> 0x100ea4d0`, and the ordered
suffix transcript described in
`docs/x64_startup_100df270_suffix_transcript.md`. The remaining part of
`0x100df270` is its platform-bound prefix. A real adapter for resource strings,
single-instance policy, error handling, and system-parameter changes needs an
independently specified host contract. The recovered parent lifecycle, broader
initializer graph, and gameplay remain outside the executable boundary.

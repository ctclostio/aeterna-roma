# Guest32 entry-policy selector contract

Status: implemented and supervisor-validated as a static, test-only x64 slice.
The separately frozen DLL-boundary probe in
`docs/x64_entry_policy_dynamic_probe_spec.md` may also link the selector, but
this does not authorize linkage into `empire.retail64.dll` or weaken any other
rule below.

## Objective

Reproduce only the original `entry_point` decision that compares its third
argument with the exact UTF-16LE string `-no_exception_handler`.

The result is a pure policy value:

- exact match: `ROME2_INVALID_PARAMETER_SKIP_HANDLER`;
- any ordinary string mismatch: `ROME2_INVALID_PARAMETER_INSTALL_HANDLER`.

This milestone does not install an invalid-parameter handler, call
`0x100ed3c0`, run an initializer, access a native command line, or link the
guest32 library into `empire.retail64.dll`.

## Pinned evidence

The authoritative original DLL is
`Total War Rome II/empire.retail.dll`, 28,278,272 bytes, SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.

The canonical function is
`src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_100edd70.c`,
SHA-256
`ec93da6e0523b5558068cc6cc2cb7acfe686cbb201f3d35bf4f0168e0e1e3c34`.
Its indexed size is 535 bytes with body ranges
`100edd70-100edf49,100edf73-100edfaf`.

The decision block is VA `0x100edecc` through `0x100edf04`, raw file offset
`0x0ed2cc`, 57 bytes, SHA-256
`11bc65f6b73602d0b4a7c974728793ca5d817cc974a5c8ff91ab1e98b64e7ebc`:

```text
8b7d108bcfb894f87311668b10663b11751e6685d27415668b5002663b5102750f83c00483c1046685d275de33c0eb051bc083c80185c0746e
```

The literal is VA `0x1173f894` through `0x1173f8bf`, raw file offset
`0x173e294`, 44 bytes/22 UTF-16LE code units including its terminator, SHA-256
`158c0c7b39632eaab540612eb67ded95089a82894e7a91edbff93866b072c86e`:

```text
2d006e006f005f0065007800630065007000740069006f006e005f00680061006e0064006c00650072000000
```

Equality takes the final conditional jump to `0x100edf73`, which skips the
handler-registration block. A normal mismatch falls through to `0x100edf05`.
Both paths subsequently call `0x100ed3c0` in the original; this contract stops
before either action.

## Required internal API

Extend `port/x64_runtime/guest32.h` with a bounded unaligned little-endian unit
read:

```c
rome2_guest_status rome2_guest_read_u16_le(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 unit,
    uint16_t *value_out);
```

It follows the existing view, numeric host-range, null-address, status, and
unchanged-output rules used by `rome2_guest_read_addr32_le`. It must byte-assemble
the value and must not assume host alignment or endianness.

Add a port-layer function in new `ported_100edd70_policy.h/.c` files:

```c
typedef uint32_t rome2_invalid_parameter_policy;

#define ROME2_INVALID_PARAMETER_INSTALL_HANDLER UINT32_C(0)
#define ROME2_INVALID_PARAMETER_SKIP_HANDLER UINT32_C(1)

rome2_guest_status rome2_port_100edd70_select_invalid_parameter_policy(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 command_line,
    rome2_invalid_parameter_policy *policy_out);
```

The function compares exactly 22 fixed `uint16_t` units, including the NUL. It
reads units in order and stops on the first mismatch. Therefore a mismatch is a
successful `INSTALL_HANDLER` result even if the unread guest suffix lies outside
the view. A matching prefix whose required next unit is unavailable is an error.

All guest `+2` operations must be checked. The output is assigned only after a
normal mismatch or the matching terminator is proven; it remains byte-for-byte
unchanged on every error.

## Required behavior tests

At minimum, centrally run tests must cover:

- exact literal and terminator selects skip;
- prefix, suffix, empty string, ASCII case change, leading/trailing space, and
  quote characters select install;
- mismatch in the first unit succeeds with a two-byte view;
- a later mismatch succeeds without reading a missing suffix;
- matching prefix with missing terminator, one-byte final unit, and truncated
  interior unit fail;
- unaligned guest address succeeds;
- a valid view whose end is exactly `2^32` succeeds;
- null command address, null arguments, malformed guest extent, numeric host
  range overflow, and required checked-address overflow fail;
- every failure preserves both unit-read and policy outputs;
- a genuine host buffer above 4 GiB is accepted without truncation.

Tests must use `uint16_t` units or explicit bytes. Windows `wchar_t`, `wcscmp`,
`wcsncmp`, and an unbounded scan are prohibited.

## Build and containment gates

- Compile as x64 C17 under `/W4 /WX /sdl /GS /guard:cf`.
- Keep `rome2_guest32_runtime` `STATIC EXCLUDE_FROM_ALL`, linked only by its
  CTest executable.
- Require a provenance CTest fixture that independently verifies the DLL hash,
  decision-block bytes/hash/control-flow targets, literal bytes/hash, canonical
  hash, and indexed function identity.
- Leave `empire.retail64.dll`, its sparse exports/status/ABI, `DllMain`, inert
  `entry_point`, link graph, and imports unchanged.
- Leave original and canonical artifacts immutable.
- Continue to pass the export contract, startup audit, canonical validation,
  compile island, existing guest32 tests, both absolute/relative loader tests,
  and `git diff --check`.

## Hard rejection conditions

Reject an implementation for any native/guest pointer cast, widened guest cell,
native `wchar_t` dependency, unbounded read, output mutation on error, fail-open
or skipped provenance, handler installation, global/default arena, bootstrap
linkage, warning suppression, canonical edit, or inferred general command-line
parser behavior.

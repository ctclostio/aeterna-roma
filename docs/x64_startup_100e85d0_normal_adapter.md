# Effect-free handler adapter for `0x100e85d0`

`0x100e85d0` is the second slot-4 method registered by original
`0x100ea4d0`. Unlike the neighboring transcript handlers, its authenticated
body has no modeled external effect.

## Authenticated original behavior

The complete original body is the 15-byte interval
`[0x100e85d0, 0x100e85df)`, at raw offset `0x000e79d0`, with SHA-256
`1bf8d344edb832e512961f8bbafeb5f9a04cceb1e70cbf31d758151c6df970ff`.
It performs this exact sequence:

1. pushes zero;
2. calls `0x100d6560`;
3. discards the pushed dword;
4. defines `AL=1`; and
5. returns with `ret 4`.

`0x100d6560` is separately authenticated as a one-byte `ret`, so the call adds
no observable effect in this bounded model. The vtable record at `0x1173f214`
is `(0x100d38b0, 0x100e85d0)`. The method ignores both its thiscall receiver
and its sole stack argument, and the original bytes define only AL rather than
the upper 24 bits of EAX.

## Portable boundary

`rome2_port_100e85d0_normal_adapter` accepts the two ignored identities as
opaque `rome2_guest_addr32` values. Every 32-bit pattern, including zero, is
admitted. A successful call writes exactly one to a required one-byte output
and returns `ROME2_GUEST_OK`.

The port does not call or link `0x100d6560`. It performs no guest dereference,
allocation, platform operation, callback, or context mutation, and it makes no
claim to reproduce the native x86 thiscall ABI or undefined upper EAX.

## Deliberate safety narrowing

The only new failure is a null output, which returns
`ROME2_GUEST_BAD_ARGUMENT`. The output object is a portable API requirement;
the original function returned AL in a register and therefore had no
corresponding pointer check. No nonzero restriction is imposed on the ignored
receiver or argument.

## Composition and verification surfaces

The implementation and its independent oracle are
`port/x64_ported/ported_100e85d0_normal_adapter.{h,c}` and
`port/x64_runtime/test_startup_100e85d0_normal_adapter.c`. Original bytes,
the one-byte helper, and the vtable slot are pinned by
`scripts/test_x64_startup_100e85d0_normal_adapter_provenance.py`; a static gate
and reciprocal mutants enforce the no-effect boundary.

Injected headless dispatch selects this adapter for method `0x100e85d0` and
reports `initializer-handler-100e85d0=effect-free-complete`. The next concrete
handler model is the dependent transcript at `0x100e8580`. The final three
registered methods remain pending.

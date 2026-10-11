# Bounded startup seams (`0x100f1bb0` and `0x100f1cc0`)

Status: admitted, native, and `BUILD_TESTING`-only. This milestone ports two
small behaviors needed by the startup closure. It does not make either original
function generally callable.

## Admitted behavior

`rome2_port_100f1bb0_measure_utf16` reproduces only the UTF-16LE scan and
length calculation at original `0x100f1bc0-0x100f1bd1`. Unlike the unbounded
x86 loop, the native API requires a terminator-inclusive `max_units`, rejects
zero and values above 32,768, uses checked guest32 reads, and preserves its
output on failure. A missing terminator within the bound is `OUT_OF_RANGE`.

```c
rome2_guest_status rome2_port_100f1bb0_measure_utf16(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 guest_text,
    uint32_t max_units,
    uint32_t *length_out);
```

The original stores that length and then calls allocator-capable helper
`0x100ef330`. The port stops before the store and call. It neither allocates nor
copies a nonempty string.

`rome2_port_100f1cc0_accept_nonowning_noop` reproduces only the two comparisons
that make the original return without dereferencing storage: guest null and
guest identity `0x11af4090`.

```c
rome2_guest_status rome2_port_100f1cc0_accept_nonowning_noop(
    rome2_guest_addr32 guest_storage);
```

Every other identity is `BAD_ARGUMENT`. The native seam never reads
`guest_storage - 4`, calls release helper `0x10124e50`, or calls mutable global
callback `DAT_119f3eb0`.

## Raw provenance

The standard-library verifier parses the pinned 28,278,272-byte original PE as
inert data (SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`)
and authenticates:

- `0x100f1bb0`, raw offset `0x000f0fb0`, 53 bytes, SHA-256
  `94088db58e056bb26dba6ce27d33c6353afce3b9300dfa63810c813dd115b2eb`;
- its exact 18-byte scan/length window at `0x100f1bc0`, SHA-256
  `aba7a7430b421914b8b6d6c603995dbbc06c93b0b97de47d61bb633e889c5555`;
- the excluded direct call at `0x100f1bd9`, whose rel32 target is
  `0x100ef330`;
- `0x100f1cc0`, raw offset `0x000f10c0`, 51 bytes, SHA-256
  `bfd9dcaa85b434c25e5a4d48c326f43f9adf0c0b75ddf8d129030723a0f7cef4`;
- its exact 16-byte null/sentinel decision prefix, SHA-256
  `520e0b8dca85eb186a400c043dcd137c68bbb3da2d1f6990ab2e86590caa9172`,
  with both branches targeting the `pop esi; ret` epilogue;
- the excluded release-helper call target `0x10124e50` and indirect callback;
- parent window `0x100ed42c-0x100ed470`, including direct calls to
  `0x100f1bb0`, excluded platform function `0x100df270`, and `0x100f1cc0`;
- exact canonical sources and index rows for both seams and their parent.

## Containment and execution

`rome2_startup_safe_seams_runtime` is a static library created only inside
`if(BUILD_TESTING)`. Its only consumers are its dedicated runtime test and
`rome2_headless64`. The static gate rejects any shared-library, bootstrap,
shipped-host, probe, or export route, as well as allocation, platform calls,
guest-to-host casts, an unbounded scan, output mutation on failure, or admitting
an owning cleanup identity.

`rome2_headless64` composes these four stages plus the separately admitted
deterministic field projection from `0x100df270`. The projection does not run
that function's Win32 prefix or side-effecting suffix. Initializers, real
platform setup, the parent startup loop, and gameplay remain unlinked.

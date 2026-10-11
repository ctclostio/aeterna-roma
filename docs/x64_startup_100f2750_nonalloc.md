# Bounded nonallocating copy from `0x100f2750`

Status: admitted, native, and `BUILD_TESTING`-only. This milestone ports one
short, forward, disjoint branch of the original descriptor-copy function. It
does not port its allocation, ownership-release, callback, overlap, or
optimized large-copy behavior.

## Accepted boundary

The original descriptor is three little-endian guest32 cells:
`{count, capacity/comparison value, payload identity}`. Raw code first compares
the source count with the destination comparison cell.

- If `source_count > destination_capacity`, execution enters the excluded
  allocation/release route at `0x100f278a`.
- Otherwise, equal descriptor identities are a no-op and return the destination.
- Otherwise, `0x100f2766` computes `2 * source_count + 2`, calls the recovered
  copy helper, writes the source count to the destination count cell, and
  returns the destination.

The native API is:

```c
rome2_guest_status rome2_port_100f2750_copy_nonallocating_short(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_destination_descriptor,
    rome2_guest_addr32 guest_source_descriptor,
    uint32_t max_units,
    rome2_guest_addr32 *guest_return_out);
```

`max_units` is terminator-inclusive and must be from 1 through 15. The source
count must be smaller than that bound and no larger than the destination
comparison cell. The function copies exactly `2 * (source_count + 1)` bytes;
it deliberately does not interpret or synthesize the final unit.

The 15-unit ceiling is mechanical, not heuristic. The helper compares its byte
count with 32. Counts 0 through 14 produce 2 through 30 bytes and jump directly
to its scalar forward tail. Count 15 produces 32 bytes and enters excluded
CPU-feature-dependent code.

For distinct descriptors, both complete 12-byte descriptors and both complete
payload spans must be present and pairwise disjoint in one borrowed writable
guest32 view. This deliberately excludes the helper's backward overlap path
and ambiguous cases where a payload write could change a descriptor before the
original post-copy count reload. Equal descriptor identities retain the raw
no-op after the count/bound/capacity decisions and do not require a usable
payload identity.

All validation completes before the first guest write. Every failure preserves
the view descriptor, every guest byte, and the output byte-for-byte. Guest
identities remain 32-bit values and are never converted directly to native
pointers.

## Raw provenance

The verifier parses the pinned 28,278,272-byte original PE as inert data
(SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`)
and authenticates:

- full `0x100f2750`, raw offset `0x000f1b50`, 157 bytes, SHA-256
  `bf302936751abe0c0d8d59c44a0f1903e1f427f4388fe85b397f73d692243744`;
- the 47-byte nonallocating/control window at `0x100f275b`, raw offset
  `0x000f1b5b`, SHA-256
  `0a2a9e2f5ee334ba45835b9626381c0469c6d9f2b6f29ea7bcced218b6cbee1c`;
- its call at `0x100f2774` resolving exactly to `0x116bde50`, the
  `2 * count + 2` width calculation, and the post-copy count write;
- the excluded 99-byte allocation/release/callback route at `0x100f278a`,
  SHA-256
  `a3202d7bd2e087f54099e3538f0f866d37e753abfbed186cc25708f65c590199`,
  including calls to `0x100ef330` and `0x10124e50`, global
  `0x119f3eb0`, and indirect callback `FF D0`;
- the 41-byte helper entry at `0x116bde50`, raw offset `0x016bd250`,
  SHA-256
  `8667436f1a982774ffd568c2cc5662bf2502d3d8c069e74e4f97c68556743f9f`,
  proving both the backward-overlap branch and the `< 32` forward-tail branch;
- the exact 60-byte scalar forward tail at `0x116be34b`, raw offset
  `0x016bd74b`, SHA-256
  `21bc1288b991185718be8173454906f71342c430083019a29fe503f38f7634eb`;
- the parent window at `0x100df46d`, including
  `0x100df482 -> 0x100f2750`, plus its two neighboring direct calls; and
- exact canonical sources and function-index rows for `0x100f2750`,
  `0x116bde50`, and the parent. Canonical C is a cross-check, not the ABI oracle.

## Verification and containment

The runtime suite independently checks zero-count, ordinary, and maximum
30-byte copies; an uninterpreted nonzero final unit; the equal-descriptor
no-op; insufficient capacity; every descriptor and payload range edge;
descriptor/payload overlap; output/view aliasing; host/guest numeric overflow;
and byte-for-byte failure atomicity.

The reciprocal static-gate suite mutates the bound, capacity comparison,
overlap checks, scalar-loop limit, platform/allocation/helper usage,
guest-to-native casts, CMake linkage, exports, and mandatory runtime cases.
The gate permits only a static library inside `if(BUILD_TESTING)`, consumed by
its dedicated test and `rome2_headless64`. Production DLLs, the probe, and the
export surfaces cannot consume it.

The headless lifecycle now performs a deterministic ten-byte copy of the
UTF-16LE payload `Rome` and reports
`short-copy=nonallocating-10-byte`. It still reports platform effects,
initializers, and gameplay as not run/not linked.

## Remaining boundary

The full `0x100f2750` remains unported: allocation, replacement of owned
storage, release callbacks, arbitrary sizes, and overlap are all NO-GO. In the
`0x100df270` suffix, the neighboring `0x100e8240` and `0x100ea4d0` calls now
have independent bounded executable models. The next unclosed region is the
global-publication and two-call virtual-dispatch suffix that follows them.

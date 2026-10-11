# Static guest32 startup triplet (`0x100f1c10`)

Status: accepted implementation contract and completed test-only milestone
after the x64 entry-policy DLL probe. This ports one 23-byte leaf. It is not
permission to execute `0x100ed3c0` or recovered startup.

## Objective and stop line

Port only the deterministic behavior of original function `0x100f1c10`: write
three little-endian guest32 cells `{0, 0, 0x11af4090}` to one caller-owned
12-byte destination and return the unchanged guest destination value.

The value `0x11af4090` is an identity token from the original x86 address
space. It must stay a `uint32_t`; it is never widened, converted to, or
dereferenced as a native pointer.

This milestone is static and `BUILD_TESTING`-only. It adds no DLL export and
does not change or link the existing entry-policy probe, bootstrap DLL, or
launcher-facing entry adapter.

## Pinned provenance

The independent provenance gate must authenticate all of these inputs before
any behavior test runs:

- original `empire.retail.dll`: 28,278,272 bytes, SHA-256
  `d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`;
- canonical function index SHA-256
  `d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5`;
- canonical `decomp_fn_100f1c10.c`: entry `0x100f1c10`, size 23,
  range `100f1c10-100f1c26`, SHA-256
  `ec3103cb0e6c9060bdb7a027949e496a9a4e81dc13ec5d3918638feeea071ed7`;
- original leaf bytes at raw offset `0x0f1010`, 23 bytes, SHA-256
  `6c689fc50bf6bfcfb73dc23095cfc6c98a757df32867c8d8b77514129bb8a2a1`:
  `c701000000008bc1c7410400000000c741089040af11c3`;
- canonical `decomp_fn_100ed3c0.c`: entry `0x100ed3c0`, size 400,
  SHA-256
  `6d0eee208220ce8b14a6d5f8b154d74b7768b1f0d276a0ee86466c60aeed83b8`;
- original `0x100ed3c0-0x100ed3ec` prefix at raw offset `0x0ec7c0`,
  45 bytes, SHA-256
  `3a9aed8d84672298e7b237e62c45b7a7056ce3aed7c555e2e80ce4c6037813df`.

The prefix contains direct calls at `0x100ed3df` and `0x100ed3e8`; both resolve
to `0x100f1c10`. The immediately preceding `lea ecx` instructions identify two
12-byte-adjacent stack destinations. This establishes the leaf's local use; it
does not establish a safe callable ABI for `0x100ed3c0`.

The provenance gate also authenticates
`port/startup_audit/startup_slots.tsv` as SHA-256
`453de546bbbd64e858aa80cd2ce09552904098e02cb0861689c24bd21e67ff6b`
and proves that `0x100f1c10`, `0x100ed3c0`, and `0x100edd70` are absent as
direct initializer-table targets. That absence makes no claim about transitive
prerequisites.

## Port-layer contract

Use the existing `rome2_guest_addr32` and numeric `rome2_guest_status` values.
Add a writable view type scoped to this test-only slice:

```c
typedef struct rome2_guest_write_view {
    uint8_t *host_base;
    uint32_t guest_base;
    uint64_t byte_count;
} rome2_guest_write_view;

rome2_guest_status rome2_port_100f1c10_initialize_triplet(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_destination,
    rome2_guest_addr32 *guest_return_out);
```

`host_base` borrows a genuinely writable native interval of exactly
`byte_count` bytes. `view`, `guest_return_out`, and their referenced storage
must be valid for their stated access. The output cell must not overlap the
borrowed host interval; overlap is rejected without mutation. The other
coordinates remain x86 values. No native pointer, allocation, ownership,
callback, structure layout, or persistent state crosses the boundary.

All validation completes before the first byte is written. Status precedence is
frozen:

1. null view, output, or host base: `BAD_ARGUMENT`;
2. guest view wider than 2^32, guest end above 2^32, numeric native-host end
   overflow, or numeric output-cell end overflow: `RANGE_OVERFLOW`;
3. output/view overlap: `BAD_ARGUMENT`;
4. zero destination: `NULL_ADDRESS`;
5. destination below the guest base or any part of the 12-byte span outside
   the view: `OUT_OF_RANGE`;
6. otherwise write the exact bytes and return `OK`.

On `OK`, only the 12 destination bytes change and `guest_return_out` receives
the original `guest_destination`. On every failure, the entire writable view
and output canary remain byte-for-byte unchanged.

## Canonical requirement IDs

- `ST1-PROV-001`: pinned original, canonical, prefix, leaf, and startup-audit
  evidence runs first;
- `ST1-ARCH-001`: native build is x64 while guest cells and identities stay
  exactly 32 bits;
- `ST1-SEM-001`: exact `{0,0,0x11af4090}` little-endian writes and unchanged
  guest return;
- `ST1-MEM-001`: borrowed writable span, checked guest/native arithmetic, and
  all-or-nothing mutation;
- `ST1-TEST-001`: independent boundary and preservation tests with reciprocal
  mutants;
- `ST1-CONT-001`: static `BUILD_TESTING`-only linkage and unchanged existing
  artifacts;
- `ST1-NOGO-001`: no `0x100ed3c0`, initializer, platform, middleware, handler,
  launcher-entry, or gameplay execution.

## Required tests and reciprocal mutants

The supervisor-owned expected data is the literal 12-byte sequence
`00000000000000009040af11`; it must not be generated by calling a second copy
of the ported function.

- aligned and genuinely unaligned host/guest destinations;
- exact 12-byte view and a view ending exactly at 2^32;
- two adjacent successful destinations, preserving both triplets;
- guard-page placement with the write ending at the final writable byte;
- null view/host/output/destination, below-base, 0- through 11-byte short
  spans, guest-end overflow, view wider than 2^32, and numeric host-end
  overflow without dereference;
- complete input/output canaries on every failure and adjacent-byte canaries on
  success;
- genuine native allocation above 4 GiB, repetition, and deterministic
  stateless behavior;
- clean C17 `/W4 /WX /sdl /GS /guard:cf` x64 build;
- existing 15-test probe/bootstrap suite passes before and after, with the
  bootstrap SHA-256 values unchanged.

Mutants must include at least: `0x11af408a` in place of `0x11af4090`, native
host-pointer substitution for the third cell, writes before validation
completes or partial writes, wrong guest return, 8- or 16-byte spans,
off-by-one end acceptance, unchecked native overflow, output mutation on
failure, and any linkage outside `BUILD_TESTING`. Reordering only the three
successful stores is not a distinct observable C behavior and is not a useful
mutant.

## Hard rejection conditions

Reject any guest-to-host cast, widened guest identity, dereference of
`0x11af4090`, partial failure mutation, unchecked arithmetic, writable/global
default arena, allocation inside the port function, canonical edit, warning
suppression, DLL export, bootstrap link, or call into `0x100ed3c0` or another
recovered function.

The canonical declaration of `0x100ed3c0` has three parameters while both
authenticated callers push four positions. This milestone intentionally avoids
freezing or repairing that unresolved ABI.

## Acceptance result

The hardened Release build passes 21/21 CTest cases. The leaf-specific chain
includes the four-test provenance gate, a ten-test reciprocal-mutant/static-gate
suite, the native x64 runtime matrix, a post-runtime PE/hash gate, and a final
bootstrap load smoke. The runtime target builds as C17 under `/W4 /WX /sdl /GS`
and `/guard:cf`.

A fresh `BUILD_TESTING=OFF` configure and build contains no `0x100f1c10`
target, compile edge, artifact, CTest file, probe, or other test executable. The
authenticated production bootstrap remains byte-identical:

- `empire.retail64.dll` SHA-256
  `fa4c0584790894e85a60427e0cb6adbf1266d14ddc321c122206365bdca8e3a0`;
- `rome2_host64.exe` SHA-256
  `007b75d58e6cb6890d98b102f07fd2be353423c4f31af41f11c366679a567708`.

The next boundary remains leaf-first analysis of the other `0x100ed3c0`
dependencies. The parent itself stays uncallable until its ABI, globals,
platform seams, indirect calls, and initializer prerequisites are resolved.

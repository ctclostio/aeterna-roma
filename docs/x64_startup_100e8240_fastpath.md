# Bounded no-crash fast path from `0x100e8240`

Status: admitted, native, and `BUILD_TESTING`-only. This milestone ports one
read-only branch of the original crash-record function `0x100e8240`. It does
not port the crash-handler initialization, the crash-file path, or any global
write. The adjacent suffix call `0x100ea4d0` is separately authenticated and
implemented as a bounded injected composition; its original native effects
remain excluded (see
[`x64_startup_100ea4d0_injected.md`](x64_startup_100ea4d0_injected.md)).

## Accepted boundary

The original reads four guest32 cells and returns the crash-record identity
`0x119f3a38`:

1. the TLS slot index from the zero-initialized global `0x12125644`;
2. the thread's TLS data pointer from the TLS-vector slot
   `[guest_tls_vector + 4 * index]`, where `guest_tls_vector` is the injected
   `TEB.ThreadLocalStoragePointer` value loaded by `FS:[0x2c]`;
3. the signed TLS value at `[tls_data + 4]`;
4. the signed global threshold from the zero-initialized `0x119f3ab0`.

The pinned branch bytes at `0x100e8257` are `cmp eax, [ecx+4]; jg +9`. The
comparison computes `threshold - tls_value`, so the crash-handler window
`0x100e8268-0x100e8375` is taken when the signed threshold is strictly greater
than the signed TLS value (equivalently `tls_value < threshold`). The original
otherwise falls through and returns the crash-record identity `0x119f3a38`
without any write. The canonical decompilation renders the same branch as
`tls_value < threshold`, which the pinned bytes confirm.

The native API is:

```c
rome2_guest_status rome2_port_100e8240_crash_record_fastpath(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 guest_tls_vector,
    rome2_guest_addr32 guest_tls_index_cell,
    rome2_guest_addr32 guest_threshold_cell,
    rome2_guest_addr32 *guest_record_out);
```

The borrowed read-only guest32 view must contain, pairwise disjoint and
non-null: the TLS index cell, the TLS-vector slot cell
(`guest_tls_vector + 4 * index`), the TLS value cell (`tls_data + 4`), and the
threshold cell. `guest_tls_vector` is not a TEB base. A TLS index above
`0x3fffffff`, a TLS-vector/TLS-data address that overflows 32 bits, a null
TLS-vector/TLS-data address, or an out-of-view cell rejects the call as a
fail-closed modeling precondition. Only `tls_value < threshold` is the original
condition that enters the excluded crash-handler initialization and crash-file
window `0x100e8268-0x100e8375`.

The TLS-index and threshold cells correspond to distinct original globals;
the selected TLS-vector slot and TLS-block value are thread-dependent cells.
The port additionally requires all four cells to be pairwise disjoint as a
fail-closed admission restriction, rejecting equal offsets and overlaps.
Likewise, the `0x3fffffff` index ceiling is a checked-arithmetic policy that
prevents `index * 4` from wrapping; it is not presented as an original loader
limit.
Every failure preserves the view, all guest bytes, and `guest_record_out`
byte-for-byte. Guest identities remain 32-bit values and are never converted
directly to native pointers.

## Raw provenance

The verifier parses the pinned 28,278,272-byte original PE as inert data
(SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`)
and authenticates:

- the 40-byte admitted fast path at `0x100e8240`, raw offset `0x000e7640`,
  SHA-256
  `cbc2db249bbf073aa791853d526ca1d6597f77906875020ae36a3a5d7a4be4c1`,
  including the `FS:[0x2c]` load of `TEB.ThreadLocalStoragePointer`, the TLS
  index global `0x12125644`, the TLS-vector slot read
  `[tls_vector + index*4]`, the threshold global `0x119f3ab0`, the
  `cmp eax, [ecx+4]` / `jg +9` branch, and the `0x119f3a38` return;
- the complete 270-byte excluded crash-handler/crash-file window at
  `0x100e8268`, raw
  offset `0x000e7668`, SHA-256
  `eeb4d55d5e4e4efdd3debf8d54dad445971b977b82697031de247bf4bd6b67fa`,
  including the crash-detector call `0x11683a32`, the threshold compare, and
  every crash-record data cell, and the complete final `jmp rel32` back to
  `0x100e825f`;
- the 21-byte parent window at `0x100df47a`, raw offset `0x000de87a`,
  SHA-256
  `0c6026216d10621f29aa2fbb5ef9d2399b4a97e545cef108c68599b8ba6ebc3c`,
  with its three call targets resolving exactly to `0x100e8240`,
  `0x100f2750`, and `0x100ea4d0`;
- the 96-byte `0x100ea4d0` evidence entry at raw offset `0x000e98d0`,
  SHA-256
  `b0c23cef41978027ff45cba5761bc0f64f48a67d683355cbdff6f4e7d38c5c3a`,
  proving the allocation and heap/object-graph mutation boundary; and
- exact canonical sources and function-index rows for `0x100df270`,
  `0x100e8240`, `0x100ea4d0`, and `0x100f2750`. Canonical C is a cross-check,
  not the ABI oracle.

## Verification and containment

The runtime suite independently checks the admitted fast path (TLS value above,
equal to, and above-a-negative threshold), both cross-sign signed-order cases,
the nonzero TLS index slot, the excluded crash route, the negative-value
below-threshold route, every null and out-of-view cell, the TLS index bound,
the TLS-vector/TLS-data 32-bit overflow,
every pairwise-disjoint and aliasing edge, output/view descriptor aliasing,
host numeric overflow, and byte-for-byte failure atomicity.

The reciprocal static-gate suite mutates the branch direction, the
pairwise-disjoint checks, the commit identity, the bounds and overflow checks,
platform/allocation/helper usage, guest-to-native casts, CMake linkage,
exports, and mandatory runtime cases. The gate permits only a static library
inside `if(BUILD_TESTING)`, consumed by its dedicated test and
`rome2_headless64`. Production DLLs, the probe, and the export surfaces cannot
consume it. It also hash-pins the headless source and requires the exact
TLS-vector setup, fast-path call, result check, and lifecycle report. The
fixture chain starts only after the preceding `0x100f2750`
post-PE verification, then runs a fresh post-PE gate and bootstrap reload for
this slice before the final headless lifecycle. Reciprocal CMake mutants pin
those dependency edges.

The later append-prefix reproducibility milestone used
`out/repro-100e2460-verified-on` and
`out/repro-100e2460-verified-off`. Those are historical paths; the current
authoritative build matrix is named by
`scripts/x64_reproducible_build_v2_manifest.json` and verified from its
configured Ninja graphs and DLL/host artifacts.

The headless lifecycle now drives the fast path with a zero TLS index, an
injected TLS-vector base whose selected slot points at a TLS data cell with a
`+4` value of `1`, and a zero threshold, and reports
`crash-record=fast-path-no-crash`. The subsequent `0x100e2460` composition now
runs the preallocated, capacity-zero, and normal growth branches with injected
allocation, release, dispatch, and queue adapters. Native allocation/release,
native platform effects, and gameplay remain not run/not linked.

## Remaining boundary

The excluded crash-handler/crash-file window `0x100e8268-0x100e8375` remains
unported: it initializes the crash record, opens the crash file, and writes
global state, all of which are outside this read-only adapter. The adjacent
`0x100ea4d0` suffix now has a separate bounded injected composition covering
all six allocations, vtable stores, router calls, and handler adapters. It
still does not authorize the original allocator, platform effects, globals, or
guest-derived native dispatch.

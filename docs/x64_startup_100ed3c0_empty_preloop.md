# Empty-input pre-loop composition for `0x100ed3c0`

Status: admitted, native, and `BUILD_TESTING`-only. This milestone composes the
straight-line original interval `[0x100ed3c0,0x100ed471)` for the single empty
UTF-16 input route. It constructs the authenticated caller frame, executes the
bounded `0x100df270` prefix/middle/suffix composition, accepts the nonowning
descriptor cleanup, and stops before the first unported loop instruction.

## Authenticated boundary

The admitted interval is 177 bytes at `.text` raw offset `0x000ec7c0`, with
SHA-256
`b9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626`.
The excluded interval `[0x100ed471,0x100ed550)` is 223 bytes with SHA-256
`0b45d268790485df8fa87a28b8cabfb1fa08ebd7baac5a93dfa7c259f9d36bd9`.
This adapter's hard stop is immediately before `0x100ed471: push esi`; the
following loop, both indirect calls, and original return are outside this
adapter and are handled only by the separately bounded lifecycle projection.

The byte authority also authenticates the complete 400-byte parent, both
original callers, the exact `0x90c` local-frame allocation, all seven direct
call sites and their five target bodies, the two global byte-store identities,
and the fact that only caller stack positions 1 and 3 are read in this interval.
The native API therefore accepts those two positions explicitly and does not
claim a semantic prototype or recovered x86 calling convention.

## Executable contract

```c
rome2_guest_status rome2_port_100ed3c0_run_empty_preloop(
    const rome2_guest_write_view *frame_view,
    rome2_guest_addr32 guest_frame,
    uint32_t argument_position1,
    const rome2_guest_read_view *text_view,
    rome2_guest_addr32 argument_position3_text,
    uint32_t text_max_units,
    const rome2_guest_write_view *selector_view,
    const rome2_100ed3c0_preloop_effects *effects,
    rome2_100ed3c0_preloop_result *result_out);
```

`frame_view` must describe exactly `0x90c` bytes beginning at `guest_frame`.
`text_max_units` must equal one, the complete two-byte UTF-16LE unit must be in
`text_view`, and that unit must be zero. A nonempty unit is rejected before any
effect because the original `0x100f1bb0` route would enter allocator-capable
`0x100ef330`. `selector_view` is separate injected storage for the two
`0x100df270` virtual-query results; evidence does not assign those cells local
frame offsets.

The successful result contains only checked guest identities:

- child receiver `F + 0x64`;
- child packet `F + 0x34`;
- child descriptor argument `F + 0x28`; and
- the excluded-boundary identity `0x100ed471`, returned as data rather than a
  native continuation.

## Exact frame state

Let `F` be `guest_frame` and `P = F + 0x34`. The receiver begins at `F + 0x64`,
occupies exactly `0x8a8` bytes, and ends at the frame endpoint `F + 0x90c`.

| Frame range | Successful pre-child state |
|---|---|
| `F+0x000..003` | zero scratch dword |
| `F+0x004..00f` | `{0,0,0x11af4090}` |
| `F+0x010..01b` | `{0,0,0x11af4090}` |
| `F+0x01c..01f` | caller-position-1 opaque value |
| `F+0x020` | zero byte; `F+0x021..023` preserved |
| `F+0x024..027` | zero dword |
| `F+0x028..033` | measured empty descriptor `{0,0,0x11af4090}` |
| `F+0x034..060` | complete `0x2d` child packet |
| `F+0x061..063` | preserved padding |
| `F+0x064..90b` | complete child receiver |

The packet is materialized as:

| Packet field | Value |
|---|---|
| `P+0x00` | caller-position-1 opaque value |
| `P+0x04` | zero |
| `P+0x08` | `{0,0,0x11af4090}` |
| `P+0x14` | `{0,0,0x11af4090}` |
| `P+0x20` | caller-position-1 opaque value |
| `P+0x24` | zero byte; `P+0x25..27` preserved |
| `P+0x28` | zero dword |
| `P+0x2c` | zero byte |

Triplet initialization and empty copies call the already admitted
`0x100f1c10` and empty `0x100f1aa0` ports. After the bounded measure proves
length zero, the descriptor is materialized with the same admitted triplet
writer. This implementation reuse is not evidence of a third original
`0x100f1c10` call: the original seventh call is `0x100f1bb0`, whose admitted
zero-length branch stores the equivalent descriptor.

## Nine parent operations

The parent observer receives exactly these typed operations by value:

1. represent byte store `(0x119f31c8, 1)`;
2. represent byte store `(0x119f31c5, 1)`;
3. initialize the triplet at `F + 0x04`;
4. initialize the triplet at `F + 0x10`;
5. copy the empty source `F + 0x04 -> F + 0x3c`;
6. copy the empty source `F + 0x10 -> F + 0x48`;
7. build the empty descriptor at `F + 0x28` from caller position 3;
8. run `0x100df270(receiver F+0x64, packet F+0x34, argument F+0x28)`;
9. accept the descriptor sentinel through the admitted nonowning cleanup.

The two process-global writes are transcript data only. No process global is
modified. Operation 8 composes the seven/ten-step injected platform prefix,
the deterministic empty-packet middle projection, and the seven/eleven-step
injected suffix in original order. No original address, platform API, native
allocator, guest-derived function pointer, or indirect dispatch is invoked.

## Unified fail-closed preflight

Before the first parent callback or frame write, the adapter snapshots and
validates every external view, effects descriptor, callback, result, complete
host interval, and derived guest identity. The frame, text, selector backing,
and external controls must be physically disjoint; active spans must also be
logically disjoint. Guest and host endpoints, including the valid guest end at
exactly `2^32`, are checked without native/guest pointer conversion.

The adapter measures the one-unit empty text, builds the predicted frame in
private storage through the admitted leaf APIs, and dry-runs all three child
slices with no-op observers and a private selector preview. Private child
effects, views, outputs, and preview storage are checked against caller
backings before this preflight. Consequently no nested validator can discover
a new ordinary input failure after the first real effect. Validation failure
emits nothing and preserves the frame, selector storage, and output byte for
byte.

Callbacks are a documented total, nonreentrant boundary: they return normally,
retain nothing, and mutate only their disjoint context. After emission begins,
callbacks and deterministic writes form the authenticated committed prefix.

## Containment

The adapter, its runtime oracle, and the composed headless harness exist only
inside `if(BUILD_TESTING)`. The parent static library links only the previously
admitted guest32, triplet, empty-copy, bounded-measure/nonowning, and three
`0x100df270` test-only libraries. It is absent from the production bootstrap
DLL and host, probe binaries, export manifest, export contract, and all DEF
surfaces.

The headless token
`startup-100ed3c0-empty-preloop=injected-composition-complete` means only that the
empty straight-line boundary ran with injected observers. It does not mean the
excluded loop, gameplay, native Win32 effects, native allocation, recovered
indirect calls, or a launcher ABI ran.

## Verification status

The focused provenance suite passes 17/17 checks, the reciprocal static-gate
suite passes 14/14, and the independent runtime oracle passes 50/50 under both
the strict MSVC build and AddressSanitizer. The live containment gate reports
zero findings. The configured primary tree now registers 180 named CTests; its
fixture feeds the adjacent lifecycle chain, whose terminal fixture is
`startup_100ed471_ordinary_lifecycle_reload_verified`. The separately admitted
owned UTF-16 and persistent first-use chain terminates at
`startup_100f2750_sentinel_owned_runtime_verified`.

The primary and fresh testing-enabled trees each pass all 180/180 CTests. The
fresh testing-disabled control exposes no headless, startup, or test targets.
All three matrix trees reproduce the pinned production DLL and host byte for
byte, and the v2 reproducibility verifier passes.

## Subsequent continuation

The adjacent `[0x100ed471,0x100ed550)` adapter now consumes this exact frame and
admits the ordinary `0* -> 2` lifecycle through injected dispatch, timestamp,
poll, teardown, and cleanup events. Result one, the outer/list backedge, and
the second indirect call remain structurally present but ordinary-domain
unreachable. The bounded nonempty `0x100f1bb0 -> 0x100ef330` constructor and
owning `0x100f1cc0` cleanup are now admitted as a separate one-shot ownership
leaf, but this parent still rejects nonempty input. Its child `0x100f2750`
copy now has the required persistent crash-descriptor allocation and registered
teardown authority. The separately admitted nonempty preloop binds that child
seam while preserving both ownership lifetimes, and the standalone whole
nonempty composition continues through the finite ordinary lifecycle to the
original `0x100ed550` return identity. This historical empty-input adapter
continues to reject nonempty input by design.

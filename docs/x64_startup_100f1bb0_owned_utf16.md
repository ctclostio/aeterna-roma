# Owned UTF-16 descriptor evidence for `0x100f1bb0`

Status: admitted bounded native leaf with a standalone `BUILD_TESTING` target.
No headless route, export, production link, or original-address execution is
admitted by this document.
No original address is executable.

## Authenticated path

The normal nonempty construction path is `0x100f1bb0 -> 0x100ef330`.
Original `0x100f1bb0` scans UTF-16 words until it observes zero, derives the
number of preceding words, stores that count in descriptor field zero, and
calls `0x100ef330(begin, terminator)`. The scan is unbounded in the original;
the evidence does not make that loop safe or callable.

The original PE is 28,278,272 bytes, SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
The focused oracle parses it only as inert data and pins:

| Interval | Raw offset | Bytes | SHA-256 |
|---|---:|---:|---|
| `[0x100f1bb0,0x100f1be5)` | `0x000f0fb0` | 53 | `94088db58e056bb26dba6ce27d33c6353afce3b9300dfa63810c813dd115b2eb` |
| scan `[0x100f1bc0,0x100f1bd2)` | `0x000f0fc0` | 18 | `aba7a7430b421914b8b6d6c603995dbbc06c93b0b97de47d61bb633e889c5555` |
| `[0x100ef330,0x100ef3ac)` | `0x000ee730` | 124 | `b343025d84a700b1a9e37ffcafc5222ad53a23643c1c99aede37ab1e2193b93d` |
| nonempty `[0x100ef347,0x100ef3ac)` | `0x000ee747` | 101 | `3eefe45e2edf1ac01217f8e6c2cacb641abf3487d2a5086a930d7e7b12b148e1` |
| `[0x100f1cc0,0x100f1cf3)` | `0x000f10c0` | 51 | `bfd9dcaa85b434c25e5a4d48c326f43f9adf0c0b75ddf8d129030723a0f7cef4` |
| owning `[0x100f1cd0,0x100f1cf1)` | `0x000f10d0` | 33 | `f0b105a03ba3a9db83e64919dcf949d49226b575bc0d3d04df7884103e8dbcc1` |

The oracle fixes every instruction boundary: 22 wrapper instructions, 48
helper instructions, and 21 cleanup instructions. It also fixes the three
normal CFGs. The wrapper has only its scan backedge; the helper has the
empty/nonempty split and one copy backedge; cleanup has sentinel, null,
raw-metadata, and optional-hook decisions. Exception and fault propagation is
not represented as an admitted CFG edge.

The direct calls are exact:

- `0x100f1bd9 -> 0x100ef330`;
- `0x100ef354 -> 0x100fcc80` with allocation mode zero; and
- `0x100f1cd8 -> 0x10124e50`.

Cleanup's optional callback at `0x100f1cec` is indirect `call eax`, after a
load from mutable global `0x119f3eb0`. It is evidence of an unsafe process
hook, not an allowed target or native ABI.

## Exact descriptor construction

Let `N` be the number of nonzero UTF-16 code units before the first zero word.
For the ordinary wrapper path, `N > 0`.

1. `0x100f1bb0` starts at `begin`, loads a 16-bit word, advances by two, and
   loops until the loaded word is zero. It computes
   `(cursor-begin-2) >> 1`, which is `N` for the normal nonwrapping path.
2. It stores `N` at descriptor offset `+0`, computes `end=begin+2*N`, and
   calls the helper with `begin` and that terminator address.
3. `0x100ef330` copies `N` to descriptor offset `+4`.
4. The nonempty branch requests exactly `2*N+10` bytes from `0x100fcc80`,
   passing allocator selector zero.
5. If the returned raw allocation identity is `raw`, usable storage is
   exactly `(raw+8)&~3`. Thus storage is four-byte aligned and lies five to
   eight bytes after `raw` according to `raw mod 4`.
6. The helper stores `raw` in the four bytes at `storage-4`, then stores
   `storage` at descriptor offset `+8`.
7. Its inclusive-end arithmetic derives `N` again for the wrapper's
   `begin <= end` shape. The copy loop transfers exactly `N` two-byte units;
   it does not copy the input terminator.
8. It writes one two-byte terminator at `storage+2*N`.

The ten overhead bytes are sufficient for every raw alignment residue:
metadata begins one to four bytes after `raw`, storage begins five to eight
bytes after it, and the terminating word ends no later than
`raw + (2*N+10)`. No padding byte receives a specified value.

The terminator load is the exact instruction
`mov ax,word ptr [0x11af408c]`. Address `0x11af408c` lies in the zero-fill tail
of `.data`: its section-relative delta is `0x1c108c`, beyond raw size
`0x0bc200` but within virtual size `0x7f3c40`. The PE therefore initializes
that word to zero. This is distinct from the empty-storage identity
`0x11af4090`, four bytes later.

That raw/BSS proof is independent of the injected model below. The port writes
a literal zero only because zero is the authenticated value; it neither maps
nor reads the original BSS address.

## Allocator and release seams

Original allocator `0x100fcc80` is 380 bytes at raw `0x000fc080`, SHA-256
`da50f0daf59ed3194f95fcb7c9df0198debdd7c8244497c026acb485100d44d8`.
It is not a leaf allocator. Its authenticated body reaches registry and heap
platform imports, mutable heap globals, an underlying allocator at
`0x101254a0`, optional fill/accounting behavior, and the same mutable hook at
`0x119f3eb0`. The exact 16-byte hook window
`[0x100fcce6,0x100fccf6)` has SHA-256
`3b3c733a35be8150ff7d6b405c5294a5afef98de50fdafcef30a022471d76054`;
its `push size; push raw; call eax` shape calls the optional hook as
`(raw,requested_size)`. If the underlying allocator returns zero, the exact
interval
`[0x100fccff,0x100fcd17)` builds a `"bad allocation"` object through
`0x100f1c50` and calls the recognized nonreturning C++ throw helper
`0x116bebf1`. `0x100ef330` has no null-result check after its allocator call;
its ordinary continuation assumes allocation returned normally.

Original release target `0x10124e50` is 1,613 bytes at raw `0x00124250`,
SHA-256
`6fa1eace89e5d98c429f6b1cbe487ce288afe0b204548a85b5df5a60df32ec96`.
It is a mutable custom-heap operation with synchronization, global free-list
state, and `VirtualQuery`/`VirtualFree` routes. Its null-input branch is pinned,
but the admitted owning route never supplies null.

For a descriptor whose storage is neither null nor `0x11af4090`, original
`0x100f1cc0` reads `raw` from `storage-4`. A zero raw value is a no-op.
Otherwise it calls `0x10124e50(raw)`, then reads `0x119f3eb0`; if that hook is
nonzero it calls the hook with `(raw,0)`. Release precedes the optional hook.
The descriptor is not cleared, and no rollback is visible in the normal body.

## Parent construction and cleanup context

The exact parent interval `[0x100ed42c,0x100ed471)` is 69 bytes at raw
`0x000ec82c`, SHA-256
`8be7ffb391c31778f273fcd94315254c837528f6a5bf0f37004d4513aeb4148d`.
Within the parent's `0x90c`-byte local frame `F`, its normal call sequence is:

1. `0x100ed454`: build the descriptor at `F+0x28` from caller stack position
   three;
2. `0x100ed463`: call original `0x100df270` with receiver `F+0x64`, packet
   `F+0x34`, and the descriptor identity returned by `0x100f1bb0`; and
3. `0x100ed46c`: clean up the descriptor at `F+0x28`.

For `N > 0`, a normally completed construction produces owning storage, so
the third call follows the owning `0x100f1cc0` route. This is only normal-flow
context. The interval contains no local failure branch or cleanup-on-exception
edge. The evidence does not claim that cleanup runs if scanning faults,
allocation throws, the child faults, or an external callback does not return.

## Failure and exception boundary

The originals have no status-return contract for this path:

- the scan is unbounded and may fault or wrap before finding zero;
- length, `2*N+10`, `raw+8`, and pointer differences use 32-bit arithmetic
  without the guest-range checks required by the x64 port;
- allocator failure throws after descriptor fields `+0` and `+4` have already
  been written;
- a malformed storage identity can fault on the `storage-4` read;
- allocator, releaser, platform imports, and both mutable-hook calls can have
  process-wide effects or fail; and
- the parent has no authenticated local unwind cleanup.

Those behaviors are evidence, not requirements for native emulation. A safe
projection must reject every invalid condition knowable before its first write
or callback. A malformed allocator grant can be known only after the one
injected allocation effect and therefore follows the explicit compensating-
release protocol below.

## Finite injected executable contract

The next implementation slice has two bounded operations: construct one
owning descriptor, then consume that descriptor's private owner once. The API
shape remains provisional, but the fail-closed protocol is fixed.

Construction accepts `max_units` in `[2,32768]`, including the required zero
terminator, and admits `N` in `[1,32767]`. Consequently the largest readable
source span is 65,536 bytes and the largest exact request is
`2*32767+10 = 65544` (`0x10008`) bytes. All source, descriptor, heap-arena,
effect/context, owner, grant, and return intervals; guest32 arithmetic; native
endpoints; alignment; and logical and physical aliases are validated as far
as possible before the first effect. The descriptor is unowned placement
scratch and may initially contain arbitrary bytes. `owner_out` must begin as
the canonical all-zero `EMPTY` record, and the return slot is preserved until
success.

The snapshotted injected allocator is called exactly once with
`(2*N+10,class=0)` and a zeroed grant output. It either denies the request or
grants `{nonzero opaque token, raw_base guest32}`. A denial changes no guest or
output byte; only the allocator's disjoint declared context may change. The
heap write view may be a larger arena, but it must contain the entire exact
raw interval `[raw_base,raw_base+2*N+10)`. After the grant, the adapter checks
that interval, `(raw_base+8)&~3`, `storage-4`, the payload and terminator, and
all remaining aliases before any guest write.

Every nonzero-token grant that fails those post-grant mapping or layout checks
gets exactly one compensating release of the exact
`{token,raw_base,2*N+10,class=0}` tuple. Compensation never emits the optional
hook. Descriptor, heap bytes, owner, and return remain unchanged, although the
two injected callbacks may update only their disjoint context. A denied grant
has no release; a purported granted result with a zero token is an effect-
protocol failure and supplies no release authority.

For a valid grant, the adapter writes the raw header at `storage-4`, copies
exactly `N` units, writes a literal zero terminator, writes descriptor
`{N,N,storage}`, commits the exact token/raw/layout tuple as a private `LIVE`
owner, and commits the descriptor guest identity to the return slot last. It
never uses guest metadata as ownership authority.

Owning cleanup first requires a `LIVE` owner and verifies, before effects, the
matching descriptor header, checked `2*N+10` formula, aligned storage, hidden
raw header, complete mapped raw extent, and zero terminator. It deliberately
does not compare payload bytes with the former source: the owner retains no
source identity or hash. Cleanup then commits `CONSUMED` before release, calls
the injected releaser exactly once with the owner's exact tuple, and only then
may call a separately predeclared typed hook `(raw_base,0)`. Callbacks are
total, normally returning, non-reentrant, retain no borrowed addresses, and
may mutate only their declared disjoint context. A consumed owner returns an
already-consumed status without another effect; guest descriptor and heap
bytes remain unchanged as auditable dangling evidence.

No model callback invokes an original or native allocator/releaser. The
adapter never reads `0x119f3eb0`, converts a guest identity into a native
pointer or function pointer, or executes the parent or child. Pre-effect
failure preserves descriptor, heap, owner, and return bytes. Once an allocator
grant exists, the only admitted failure effect is its exact compensating
release.

## Hard exclusions and acceptance gate

The executable slice must exclude original execution, unbounded scanning,
unchecked arithmetic, native allocation or release, registry/heap/virtual
memory APIs, process globals, original exceptions and unwind behavior,
unverified metadata release, parent `0x100ed3c0`, child `0x100df270`, and the
following lifecycle at `0x100ed471`.

`scripts/test_x64_startup_100f1bb0_owned_utf16_provenance.py` is the authority for
this evidence. It pins the PE, all core bytes and CFGs, call targets, allocator
failure path, release body, zero-fill terminator, canonical maps/decompilation,
import evidence, parent context, finite model, and reciprocal evidence mutants.
The admitted leaf passes 149/149 direct runtime cases under both the strict
MSVC `/std:c17 /W4 /WX /analyze` build and AddressSanitizer, 16/16 provenance
checks, 32/32 reciprocal static-gate mutants, the live static gate with zero
findings, and the full 168/168 `BUILD_TESTING` matrix. Its production-off build
remains byte-identical to the pinned DLL and host. Its first-use persistent
consumer is separately admitted; composition into the nonempty parent lifecycle
remains a separate reviewed slice.

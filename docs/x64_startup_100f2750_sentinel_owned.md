# First-use persistent descriptor replacement at `0x100f2750`

Status: admitted bounded native leaf with a standalone `BUILD_TESTING` target.
No headless route, export, or production link is admitted. The original PE is
read only as inert data. No original address is executable.

## Authenticated first-use route

The bounded route is the first nonempty assignment into the persistent
descriptor at guest identity `0x119f3aa0`:

1. slow initialization in original `0x100e8240` executes the exact site
   `0x100e82e7`, setting `ECX=0x119f3aa0` and calling `0x100f1c10`;
2. `0x100f1c10` writes the descriptor `{0,0,0x11af4090}`;
3. the same initialization registers `0x116ddc80` through `_atexit` at
   `0x116838ea` before returning;
4. parent `0x100df270` receives `0x119f3a38` from `0x100e8240`, derives
   `0x119f3a38+0x68 = 0x119f3aa0`, and calls `0x100f2750` with the separate
   source descriptor; and
5. for source count `N>0`, the `CMP` begins at `0x100f275d` and the `JA`
   opcode at `0x100f2760` branches to `0x100f278a` for replacement.

The original PE is 28,278,272 bytes, SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
The focused oracle parses its PE32 section table and pins:

| Interval | Raw offset | Bytes | SHA-256 |
|---|---:|---:|---|
| full `0x100f2750` | `0x000f1b50` | 157 | `bf302936751abe0c0d8d59c44a0f1903e1f427f4388fe85b397f73d692243744` |
| replacement `[0x100f278a,0x100f27ed)` | `0x000f1b8a` | 99 | `a3202d7bd2e087f54099e3538f0f866d37e753abfbed186cc25708f65c590199` |
| first-use build/commit `[0x100f278a,0x100f27be)` | `0x000f1b8a` | 52 | `5330cfe4cfc72298be8730653327985d50e435354ae996c6f9a43d8a766b4ccd` |
| helper `0x100ef330` | `0x000ee730` | 124 | `b343025d84a700b1a9e37ffcafc5222ad53a23643c1c99aede37ab1e2193b93d` |
| initializer `0x100f1c10` | `0x000f1010` | 23 | `6c689fc50bf6bfcfb73dc23095cfc6c98a757df32867c8d8b77514129bb8a2a1` |
| init/register `[0x100e82e7,0x100e8363)` | `0x000e76e7` | 124 | `485deab3aa21dafdaa4e3cc288d9a5a45b91b34099791572a324c5195a2fe15b` |
| destructor `[0x116ddc80,0x116ddca8)` | `0x016dd080` | 40 | `8a601eaf8096b5c4eab87bd6af2fcbcb05242de6b9bb6e8537d1977dbf729faf` |
| `_atexit` `0x116838ea` | `0x01682cea` | 21 | `efae0e05a589276306c3c87f5a7eac21406f050c14251fdc660fa00f91ff430f` |
| `0x100df270` suffix | `0x000de86d` | 33 | `723bd9e4fdab4eaa8aa9ea40b1f6b01661d2d388c59dacf4ac8f488ca59ee8ed` |
| source owner parent `[0x100ed42c,0x100ed471)` | `0x000ec82c` | 69 | `8be7ffb391c31778f273fcd94315254c837528f6a5bf0f37004d4513aeb4148d` |

The oracle fixes every instruction boundary in the 99-byte replacement and
its normal CFG. It also resolves the exact direct calls and the short
conditional branches rather than treating the canonical C as an ABI oracle.

## Exact replacement order

At `0x100f278a`, source count `N` is already saved and the source payload is
loaded. Original `0x100f2750` then performs this order:

1. form source end `source_payload+2*N`;
2. call `0x100ef330(begin,end)` on a 12-byte temporary descriptor;
3. after the helper returns normally, commit destination count from saved `N`;
4. commit destination capacity from the temporary descriptor;
5. snapshot the old destination payload;
6. commit the new payload from the temporary descriptor; and
7. test the old payload for `0x11af4090`, null, and releasable metadata.

The first-use precondition makes the old-payload test at `0x100f27b6` equal,
so execution jumps directly to the epilogue at `0x100f27e3`. It does not read
`sentinel-4`, call `0x10124e50`, read mutable hook global `0x119f3eb0`, or
invoke an indirect hook. Those operations remain authenticated as the other
replacement outcomes; they are not admitted by this first-use slice.

The helper layout is exact. For nonzero `N`, it requests `2*N+10` bytes in
allocator class zero. If the raw guest identity is `raw`, the payload identity
is `(raw+8)&~3`; the four bytes at `payload-4` receive `raw`; exactly `N`
UTF-16LE units are copied; and a literal zero word is written at
`payload+2*N`. The destination descriptor becomes `{N,N,payload}`. The ten
overhead bytes contain the header, alignment padding, and terminator for every
raw residue modulo four.

For the finite native projection, `N` is restricted to `[1,32767]`. The
largest exact request is `2*32767+10 = 65544` (`0x10008`) bytes. Every size,
guest32 endpoint, host endpoint, offset, alignment expression, and alias must
be checked before the first effect or write.

## Persistent identity and registered teardown

`0x119f3aa0` is a 12-byte interval in the zero-fill tail of `.data`: it is
beyond the section's `0x000bc200` raw size but within its `0x007f3c40` virtual
size. The image therefore supplies no file-backed descriptor bytes there.
The initializer, rather than raw file contents, establishes the sentinel
triplet.

The little-endian literal `a0 3a 9f 11` occurs exactly twice in the original
file: as the `MOV ECX,0x119f3aa0` immediate at `0x100e82e7`, and as the first
descriptor immediate in destructor `0x116ddc80`. The runtime call site does
not embed the identity; it derives it with checked evidence
`0x119f3a38+0x68`.

Initialization pushes `0x116ddc80` at `0x100e82fd` and, with no intervening
stack adjustment, calls `_atexit` at `0x100e835e`. The registered destructor
has this exact cleanup order:

1. call `0x100f1cc0(0x119f3aa0)`;
2. call `0x100f1cc0(0x119f3a80)`;
3. call `0x100f1cc0(0x119f3a74)`; and
4. tail-jump to `0x100f1cc0(0x119f3a4c)`.

Thus the persistent descriptor is the first member cleaned. The original
cleanup accepts the sentinel as a no-op and, after first-use replacement,
releases the raw identity stored at payload minus four before an optional
`(raw,0)` hook. Neither `_atexit`, its `_onexit` dependency, the original
cleanup, the original releaser, nor the mutable hook is safe to execute in a
64-bit port.

The safe projection therefore requires a typed host-owned teardown
registration before a persistent owner may become `LIVE`. Registration uses
no original address or guest function identity. Its private lifecycle is
one-shot: `REGISTERED_SENTINEL -> REGISTERED_LIVE -> CONSUMED`. A failed or
missing registration cannot publish a live persistent grant. Deterministic
explicit shutdown may drive the typed teardown, but silently relying on the
process CRT's native `_atexit` list is outside the boundary.
This is the admitted finite `SENTINEL -> LIVE` operation.

## Separate source and destination ownership

The source descriptor is not storage to transfer. The exact parent window
builds it at `0x100ed454`, passes its identity into child `0x100df270` at
`0x100ed463`, and cleans it independently at `0x100ed46c`. Inside the child,
`0x100f2750` asks `0x100ef330` for a second allocation and copies the source
payload into it.

A future native state must therefore carry two non-aliasing private owner
records:

- `source_owner`: already `LIVE`, authenticating the source token, raw base,
  payload, `N`, exact `2*N+10` extent, descriptor, metadata, and terminator;
- `persistent_owner`: canonical all-zero while the persistent descriptor is
  the sentinel, then committed `LIVE` with the new destination grant and
  layout, and finally `CONSUMED` by registered teardown.

Success leaves every source descriptor byte, source allocation byte, and
source-owner field unchanged. It never copies, transfers, consumes, or
releases the source token. Source cleanup consumes only `source_owner` after
the child returns. Persistent teardown consumes only `persistent_owner`.

The descriptor and private owner form a coupled state:

| Lifecycle | Persistent descriptor | Private persistent owner |
|---|---|---|
| registered sentinel | `{0,0,0x11af4090}` | canonical all-zero/no authority |
| live | `{N,N,payload}` | exact nonzero token/raw/payload/size/N, `LIVE` |
| consumed | unchanged dangling evidence | exact tuple retained, `CONSUMED` |

This first slice rejects a destination already `LIVE`, a null destination,
any noncanonical sentinel descriptor, and any nonempty initial persistent
owner. Preallocated assignment and `LIVE -> LIVE` replacement are later
slices.

## Injected allocation and compensation protocol

All controls, complete view backings, callback context, both owners, the
grant, lifecycle state, and return slot must be snapshotted and mutually
protected. The source allocation and any granted destination allocation may
reside in one containing heap arena, but their exact raw, header, payload, and
terminator spans must be disjoint.

After complete preflight, the snapshotted allocator receives one exact
`(2*N+10,class=0)` request and a zeroed grant. A canonical denial changes only
the declared callback context and must leave the grant zero. By contract, any
callback-written nonzero token is fresh one-shot release authority even when
paired with an inconsistent result discriminator; it must never be stale or
reused. A purported granted result with a zero token is a protocol failure
without release authority. The destination token must also
differ from the still-`LIVE` source token. Equality is
`EFFECT_PROTOCOL_INVALID` with no compensating release and no guest/output
mutation: calling release on the colliding token could consume the source's
authority. Globally unique one-shot tokens are an allocator protocol
requirement. Every other malformed nonzero-token grant is consumed exactly
once by the injected releaser with the exact
`{token,raw,2*N+10,class=0}` tuple. Compensation never invokes the optional
teardown hook.

Until a grant passes mapping, guest32 arithmetic, alignment, containment,
source/destination disjointness, and all remaining alias checks, the
persistent descriptor, both owners, both allocations, and return slot remain
byte-for-byte unchanged. After validation, success order is raw header,
payload copy, zero terminator, destination descriptor, persistent `LIVE`
owner, then destination return. No fallible operation follows the first guest
write.

Registered teardown requires the exact `LIVE` owner, matching descriptor,
allocation formula, aligned payload, complete raw extent, hidden header, and
zero terminator. Guest metadata is evidence, never authority. It commits
`CONSUMED` before the exact injected release and only then may invoke a
predeclared typed `(raw,0)` hook. Guest bytes remain unchanged. Repeated
teardown returns already-consumed without another effect.

The wrapper retains a defensive `REGISTERED_LIVE` rollback if the established
owned cleanup ever rejects after that commit. Under this finite contract the
wrapper prevalidates every condition that the cleanup can reject, and the
release and hook effects return no status, so no current input can reach that
rollback. Runtime tests therefore describe and cover pre-effect teardown
validation failures; they do not claim to force an unreachable delegate
failure. A future fallible cleanup effect would require a new oracle before
the rollback could become an admitted runtime route.

## Hard exclusions and next gate

This leaf admits no execution of original `0x100f2750`, `0x100ef330`,
`0x100f1c10`, `0x100f1cc0`, `0x10124e50`, `0x116838ea`, or `0x116ddc80`.
It also excludes native allocation/release/CRT registration, process globals,
the mutable hook, original exceptions, unchecked arithmetic, unbounded scans,
guest-to-native pointer or function conversion, source-token transfer,
sentinel release, unregistered persistent ownership, double teardown,
preallocated assignment, `LIVE -> LIVE` replacement, parent execution,
headless composition, exports, and production linkage.

The next executable gate is a bounded nonempty pre-loop composition of
`0x100ed3c0`: build the temporary owned UTF-16 descriptor, pass that distinct
owner through the admitted first-use persistent replacement, consume only the
temporary owner at `0x100ed46c`, and stop before `0x100ed471`. The persistent
owner remains registered for explicit one-shot shutdown. Preallocated
assignment and eventual `LIVE -> LIVE` replacement remain later slices.

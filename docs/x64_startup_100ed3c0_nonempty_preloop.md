# Bounded nonempty `0x100ed3c0` preloop

Status: independently implemented behind `BUILD_TESTING`; not linked by the
headless harness, an export, a probe, or either production binary.

## Boundary and composition

`rome2_port_100ed3c0_run_nonempty_preloop` models only the authenticated
177-byte original interval `[0x100ed3c0,0x100ed471)`. The raw interval SHA-256
is `b9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626`.
The loop beginning at `0x100ed471`, its indirect calls, terminal local cleanup,
native entry, and gameplay remain excluded.

The new leaf is a sibling of the frozen empty adapter. It keeps the same exact
`0x90c` frame and nine parent operations:

1. observe the two authenticated global byte-store identities;
2. initialize the two sentinel triplets at frame `+0x04` and `+0x10`;
3. copy them into frame `+0x3c` and `+0x48`;
4. build the nonempty owned UTF-16 descriptor at frame `+0x28`;
5. run the admitted `0x100df270` prefix and deterministic middle;
6. run its delegated suffix, binding the exact `CALL 0x100f2750` position to
   the admitted first-use owned leaf;
7. clean up only the temporary owner at the original `0x100ed46c` position;
8. commit the parent result last and return `0x100ed471` only as data.

The push-adjusted packet fields remain identical to the empty route. In
particular, frame `+0x60` (packet `+0x2c`) is the copied zero byte, not the text
length. Frame `+0x28` is never pre-zeroed; it remains placement scratch until
the owned builder commits `{N,N,payload}`.

## Inputs and defensive boundary

The text budget includes its terminator and is restricted to `[2,32768]`, so
the first zero follows `N` opaque UTF-16LE units for `N` in `[1,32767]`.
Temporary and persistent heaps each have room for the exact `2*N+10` request.
The frame, text, selector, temporary heap, persistent descriptor, and
persistent heap views must be pairwise disjoint in both host and guest space.

The persistent descriptor at guest identity `0x119f3aa0` must enter as
`{0,0,0x11af4090}`. Registration is deliberately external: the persistent
owner enters canonical `EMPTY`, while its lifecycle is already
`REGISTERED_SENTINEL`. The temporary owner also enters canonical `EMPTY`.

Parent, prefix, suffix, temporary-owned, and persistent-owned callback contexts
have complete declared host spans. Exactly identical spans are allowed so one
recorder can observe the entire order; partially overlapping spans are
rejected. All contexts are disjoint from controls, guest backings, and private
adapter state. Views, effects, identities, owner entries, lifecycle, selector
branch input, and result sentinel are snapshotted before observation.

Deterministic validation includes a private denial preflight of the owned
builder and private no-op previews of the frame prefix, child prefix/middle,
and delegated suffix. Persistent descriptor, lifecycle, capacity, and alias
preconditions are checked directly. Re-authentication of the temporary source
inside first use is construction-derived from the same already-admitted owned
builder; no native allocation or 128 KiB preview heaps are used.

## Ownership and failures

On success, the temporary owner follows `EMPTY -> LIVE -> CONSUMED`. Its release
and optional hook occur only after parent operation nine is observed. The
persistent owner follows `EMPTY -> LIVE`, and its lifecycle becomes
`REGISTERED_LIVE` inside the delegated call before the suffix resumes with
`CALL 0x100ea4d0`. Persistent teardown is a separate explicit API outside the
parent interval.

All deterministic failures are Tier 0: no external callback or guest write,
with every backing, owner, lifecycle, and result preserved. Once observation
begins, effects form an ordered committed prefix and no rollback is claimed.
A temporary allocation denial leaves both owners unchanged. A persistent
allocation or protocol failure occurs after the first three suffix observations
and leaves the temporary owner `LIVE`, persistent owner `EMPTY`, lifecycle
`REGISTERED_SENTINEL`, selector marker and parent result uncommitted. The caller
must explicitly clean up that temporary owner. A persistent grant token equal
to the live temporary token is rejected without release, preserving the source
authority. Other malformed nonzero grants receive the admitted single
compensating release and never the optional hook.

Owned statuses are preserved exactly. The status-typed suffix seam receives a
generic failure value only as flow control; the parent retains and returns the
precise owned status recorded by its typed delegate context.

## Independent oracle

`test_startup_100ed3c0_nonempty_preloop.c` contains 48 cases. One shared
recorder covers parent, prefix, suffix, both allocation domains, temporary
release/hook, and delegated first use. It checks:

- `N=1` and `N=32767`;
- all 16 temporary/persistent raw-residue pairs;
- byte-exact frame, descriptor, heap, selector, owner, lifecycle, and result
  outcomes;
- effect-descriptor snapshot mutation after the first parent observation;
- fourteen Tier-0 preservation failures;
- seven temporary allocation denial/protocol/mapping prefixes;
- five delegated persistent denial/protocol/collision prefixes;
- explicit cleanup of every escaped live temporary owner; and
- live persistent teardown, repeated teardown, and registered-sentinel
  no-effect teardown outside the parent.

The library and executable exist only inside `if(BUILD_TESTING)`. No original
address, native allocator, CRT registration list, platform API, process global,
guest-derived native call, or recovered implementation is executed.

## Verification and admission

The final frozen leaf passes all six provenance checks, all 19 reciprocal
static-gate tests, the zero-finding live static gate, and the independent
48-case runtime oracle. The source and oracle also pass strict MSVC
`/analyze /WX` compilation and an AddressSanitizer build/run.

Three independent testing-enabled build graphs each pass all 180/180 named
CTest cases. The testing-disabled control exposes zero tests and contains none
of the new target or source tokens. Across all four trees the production
artifacts remain byte-for-byte unchanged:

- `rome2.dll`: 107520 bytes,
  `d5f432084f4638a69fc3ef1b155c973c281f7704af1be6eca7f5aa63c7ca12a5`;
- `rome2_host64.exe`: 144384 bytes,
  `be4048881e43c09b5b9a9c22381aa8f02f74a9ed0a47221bb1022cb727bd4e73`.

Read-only DeepSeek V4 Flash workers in the Pi harness first reviewed the
contract and oracle, then found one real defensive ownership leak in the first
code audit. After that branch was repaired and mechanically tested, both final
admission reviewers returned `READY`. Their retained reports are under
`out/pi-swarm/20260831-nonempty-preloop-implementation-design/`,
`out/pi-swarm/20260831-nonempty-preloop-code-audit/`, and
`out/pi-swarm/20260831-nonempty-preloop-admission-audit/`.

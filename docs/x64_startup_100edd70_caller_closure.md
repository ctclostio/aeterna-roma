# Exact `0x100edd70` caller-closure binder

Status: implemented as a test-only x64 composition and admitted only for the
two authenticated caller windows around the already frozen nonempty parent.
It is not linked into either production DLL or the headless executable.

## Bounded objective

`rome2_port_100edd70_run_caller_closure` closes these original half-open
windows:

- handler-registered policy: `[0x100edf20,0x100edf41)`;
- handler-skipped policy: `[0x100edf73,0x100edf94)`.

Each window contains the same four machine-order pushes, one call to the exact
400-byte parent `[0x100ed3c0,0x100ed550)`, two constant keeper calls, and one
grouped `add esp,0x18`. The hard stops are `0x100edf41` and `0x100edf94`.
Handler registration, both epilogues, `CoUninitialize`, process-global restore,
and the eventual entry-point return remain excluded.

The binder consumes an already-decided `rome2_invalid_parameter_policy` as
data. It does not call the entry-policy selector. Policy zero selects the
handler-registered window; policy one selects the skip-handler window. Any
other value fails before an effect.

## Pinned original evidence

The authority is `Total War Rome II/empire.retail.dll`, 28,278,272 bytes,
SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.

The handler-registered window starts at raw `0x0ed320`, is 33 bytes, and has
SHA-256
`52227b99b8d956f8926eb0f02b0f3b8c62a229dee20653b5608dc81a96e41084`:

```text
ff752457ff750c56e893f4ffff6a01e89c5702006860650d10e8b271020083c418
```

Its continuation `[0x100edf2d,0x100edf41)` is 20 bytes, SHA-256
`16059cc15e0932ce776ddaeb4f7e5e991eb8fe6776f279d8b3dacc4238826954`.
The parent call is at `0x100edf28`, the keeper calls are at `0x100edf2f` and
`0x100edf39`, and cleanup is at `0x100edf3e`.

The skip-handler window starts at raw `0x0ed373`, is 33 bytes, and has SHA-256
`76a454a3f06c1c8de33f0b3b0ab432e059de9abca52b342b8cac0e9f50198d6a`:

```text
ff752457ff750c56e840f4ffff6a01e8495702006860650d10e85f71020083c418
```

Its continuation `[0x100edf80,0x100edf94)` is 20 bytes, SHA-256
`2bb4e7d91eb623e2d1bb5e99c1c71431bd06fb60fb1ae5316da895dcdad3e7ba`.
The parent call is at `0x100edf7b`, the keeper calls are at `0x100edf82` and
`0x100edf8c`, and cleanup is at `0x100edf91`.

Both rel32 parent calls resolve to `0x100ed3c0`. The four pushes are preserved
as result data in machine order: caller position four to callee position four,
position three to three, position two to two, and position one to one. Only
positions one and three are forwarded because the authenticated parent body
reads only those two entry-stack positions. Positions two and four remain
opaque values; no register def/use path is invented.

The byte keeper at `0x101136d0` is the exact ten-byte leaf
`8a442404a28e3d9f11c3`, SHA-256
`22b0fe50342cb045ba9144d7d8060d9752e1f72b353436d7a43194e03c3c7bc0`.
It represents storing byte `1` to identity `0x119f3d8e`. The dword keeper at
`0x101150f0` is `8b442404a35c3f9f11c3`, SHA-256
`a4e8fe0de027b3efd0a36a670c540ef75256b470d380c4b3124e91e5e61332c5`.
It represents storing `0x100d6560` to identity `0x119f3f5c`. These are typed
observer steps, not native calls or guest writes.

The excluded registration interval `[0x100edf05,0x100edf20)` is 27 bytes,
SHA-256
`207f89cc1284f85df0955249dd435c83e869d52a33903b2cf25c3adf6ac677fb`.
The provenance gate pins it precisely so omission cannot silently expand the
contract. It likewise pins the installed-branch hard-stop bytes beginning at
`0x100edf41` and the skip epilogue beginning at `0x100edf94`.

## Transaction and ownership contract

Before the parent can emit or write, the binder validates and snapshots an
exact thirteen-control, seven-backing, seven-context universe. The controls are
seven view descriptors, parent effects, continuation effects, two owners, the
persistent lifecycle, and the combined result. The backings are the same seven
guest views used by the parent. The contexts are the parent's six callback
spans plus the continuation observer span.

Controls and backings must be pairwise host-disjoint; backing guest intervals
must also be pairwise disjoint. Contexts may be exactly identical so one
recorder can prove total order, or fully disjoint; partial overlap is rejected.
Every context is disjoint from controls, backings, and private state. Numeric
host and guest extents, object alignment, the exact `0x90c` frame, callbacks,
policy, and aliases are settled before the parent call.

The parent is called exactly once with private result storage. A failure is
returned unchanged. Its documented committed prefix and escaped ownership are
preserved, no continuation event occurs, no rollback is attempted, and the
caller result remains byte-for-byte unchanged.

After parent success no fallible operation remains. The binder verifies the
frozen parent seam and ownership states, then emits exactly three by-value
steps:

1. byte keeper store;
2. dword keeper store;
3. grouped 24-byte cleanup.

It then commits the combined result exactly once and last. With a parent poll
count `P`, the shared recorder contains `45 + P` events: 46 for `P=1`, 48 for
`P=3`, and 109 for `P=64`. A callback may mutate the caller-owned effects
objects after the first parent event; the complete snapshot keeps all later
parent and continuation behavior unchanged.

Success leaves the temporary owner consumed, the persistent owner live, and
the first-use lifecycle registered-live. The persistent authority remains for
explicit one-shot teardown outside both caller windows.

## Verification and containment

The native runtime has exactly 54 cases: ten success cases across both policies
and boundary values, 37 silent deterministic denials, five inherited
committed-prefix failures, and two teardown cases. It proves machine-order push
data, branch-specific call and hard-stop identities, keeper shapes, `45 + P`
order, result-last publication, input snapshotting, alias rejection, exact
status propagation, and persistent teardown.

The provenance oracle independently parses the PE32 as inert bytes and pins
the windows, continuations, rel32 targets, keeper leaves, excluded registration
and epilogue bytes, canonical exports, ABI fixture, and frozen parent. The
static gate and reciprocal unit gate reject at least 24 contract mutations,
including wrong windows, policy mapping, keeper constants, target identities,
call order, parent call count, cleanup size, result timing, alias dimensions,
selector use, native APIs, original identifiers, and production linkage.

The library is `STATIC EXCLUDE_FROM_ALL` inside the sole `if(BUILD_TESTING)`
block. Its only consumer is its runtime test. The admitted whole-parent library
therefore has exactly two test-only consumers: its own runtime and this binder
library. Six new CTests extend the central inventory from 180 to 186. With
testing disabled, no caller-closure file or target token is present in the
generated graph, and the production DLL/host hashes remain unchanged.

This closes a precise caller boundary, not the whole game. Canonical export
coverage remains 63,326/63,326, while FuncID semantic reconstruction and a
playable game-equivalent runtime remain separate, much larger completion axes.

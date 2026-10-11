# Whole nonempty `0x100ed3c0` lifecycle composition

Status: implemented as a standalone `BUILD_TESTING` composition. It is not
linked by the headless harness, an export, a probe, or either production
binary.

## Exact boundary

`rome2_port_100ed3c0_run_nonempty_lifecycle` composes the two independently
admitted children over the complete original parent interval
`[0x100ed3c0,0x100ed550)`:

- the 177-byte nonempty preloop `[0x100ed3c0,0x100ed471)`, SHA-256
  `b9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626`;
- the 223-byte finite ordinary lifecycle `[0x100ed471,0x100ed550)`, SHA-256
  `0b45d268790485df8fa87a28b8cabfb1fa08ebd7baac5a93dfa7c259f9d36bd9`.

Together they are the exact 400-byte body at raw offset `0x000ec7c0`,
SHA-256
`b606895706a18f44d27babaef870efc60b362733d01af389b96a10e7c0e5d206`.
The children share the authenticated `0x90c`-byte frame, the preloop next
identity is exactly the lifecycle start, and the composition stops at the
original return identity `0x100ed550`. Original PCs remain data only.

The lifecycle cleanup order consumes exactly the four sentinel triplets made
by the preloop: frame `+0x48`, `+0x3c`, `+0x10`, then `+0x04`. The lifecycle
timestamp write at frame `+0x28` deliberately overwrites the preloop's
temporary owned-descriptor placement, matching the original parent.

## Transaction boundary and order

The nonempty child can begin committed allocation and observer effects before
the lifecycle child sees its inputs. To prevent a deterministic successor
rejection after those effects, the composition validates the enlarged alias
universe and runs a private lifecycle preview first. The preview uses:

- a private `0x90c` frame seeded with the four admitted sentinel triplets;
- the snapshotted dispatch view, finite poll transcript, budget, and timestamp;
- a private no-op observer context and private result; and
- no caller backing, result, owner, lifecycle, or callback.

The externally visible order is then exactly one nonempty-preloop call,
followed only on success by exactly one ordinary-lifecycle call. Registration
is already part of the admitted nonempty child. Persistent teardown remains a
separate explicit operation outside this interval.

The whole adapter snapshots all seven guest backings and every input control
before the preview or any external effect. Frame, text, selector, temporary
heap, persistent descriptor, persistent heap, and dispatch views must be
pairwise disjoint in both host and guest address space. Twelve public control
objects must be mutually disjoint and disjoint from all backings and private
state. Six callback contexts have complete declared host spans; exactly
identical spans may share one total-order recorder, while partial overlap is
rejected. Contexts must also be disjoint from controls, backings, and private
state.

## Success and failures

On success, the temporary owner is `CONSUMED`, the persistent owner is `LIVE`,
and its lifecycle is `REGISTERED_LIVE`. The child results are held privately
and the combined result commits once and last. The real lifecycle result must
exactly match its private preview.

For the oracle's mismatch-selector route and a poll transcript containing `P`
results, the shared external recorder sees `31` preloop events and `11 + P`
lifecycle events, or `42 + P` total. The admitted mismatch-route success
transcripts therefore produce 43 events for `P=1`, 45 for `P=3`, and 106 for
the maximum `P=64`. The public composition does not impose that fixture route.

All deterministic argument, range, transcript, dispatch, descriptor, budget,
and alias failures are rejected before an external callback or guest write.
Once the nonempty child begins, its existing committed-prefix rules remain
authoritative. Allocation denials and malformed grants preserve the exact
escaped-owner states produced by that child; the whole adapter performs no
implicit rollback. Escaped temporary and live persistent owners are cleaned
up only through the admitted explicit APIs. The combined result remains
unchanged on every failure.

## Independent runtime oracle

`port/x64_runtime/test_startup_100ed3c0_nonempty_lifecycle.c` contains exactly
36 cases. One total-order recorder covers parent, prefix, suffix, both
allocation domains, both hooks, temporary cleanup, and the lifecycle observer.
It checks:

- one-, three-, and 64-result successes plus the authenticated fallback
  dispatch construction;
- `N=1`, `N=32767`, cross-residue allocations, the exact frame endpoint, and
  effects-object snapshot mutation;
- exact event ordering, timestamp timing, frame bytes, owner phases, child
  results, and combined result-last publication;
- malformed transcripts and budgets, mixed dispatch identities, backing,
  control, context, and endpoint overlap/range failures, including direct
  context-to-control and control-to-backing cases;
- ownership, lifecycle, descriptor, text, and crash-shape Tier-0 rejection;
- temporary and persistent denial/protocol/token-collision prefixes; and
- explicit escaped-temporary cleanup, persistent teardown, registered-sentinel
  teardown, and repeated teardown behavior.

The source uses only admitted guest32 and child APIs. It does not execute an
original address, recovered implementation, native allocator, platform API,
CRT registration list, process global, or guest-derived native function
pointer, and performs no guest/native pointer cast.

## Admission boundary

The composition library has exactly two test-only consumers: its standalone
runtime test and the exact `0x100edd70` caller-closure library. The two child
libraries gain only the whole composition as their additional consumer. No
headless source, export manifest, DEF file, probe, or production target contains
the whole-composition API or library token.

Admission evidence is complete. The focused provenance oracle passes 6/6, the
reciprocal mutation suite passes 22/22, the live static gate reports zero
findings, and the strict MSVC runtime passes all 36 cases. The source and oracle
also pass `/analyze /WX` and AddressSanitizer builds/runs. The primary,
manifest-fresh, and independently clean testing-enabled graphs each pass all
186/186 named CTests; the testing-disabled control exposes zero tests and none
of the composition target/source tokens. Post-build PE and bootstrap-reload
gates pass.

The production artifacts remain byte-for-byte unchanged across the primary,
testing-enabled, and testing-disabled trees:

- `empire.retail64.dll`: 107,520 bytes, SHA-256
  `d5f432084f4638a69fc3ef1b155c973c281f7704af1be6eca7f5aa63c7ca12a5`;
- `rome2_host64.exe`: 144,384 bytes, SHA-256
  `be4048881e43c09b5b9a9c22381aa8f02f74a9ed0a47221bb1022cb727bd4e73`.

Read-only DeepSeek V4 Flash reviews and exact-model launch receipts are
retained under `out/pi-swarm/20260831-nonempty-lifecycle-code-audit/` and
`out/pi-swarm/20260831-nonempty-lifecycle-admission-audit/`.

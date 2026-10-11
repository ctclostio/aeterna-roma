# Bounded nonempty `0x100ed3c0` preloop plan

Status: fully admitted as a standalone `BUILD_TESTING` sibling with an
independent 48-case runtime oracle, provenance and reciprocal static admission,
and the complete build matrix. The exact mid-suffix seam is independently
admitted in the `0x100df270` suffix leaf. No headless route, export, probe, or
production link is authorized by this document.

## Evidence boundary

The parent executes the same authenticated 177-byte interval
`[0x100ed3c0,0x100ed471)` for empty and nonempty text. Its raw SHA-256 is
`b9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626`.
The exact nonempty-relevant call order is already pinned:

1. `0x100ed454 -> 0x100f1bb0`, producing the descriptor at frame `+0x28`;
2. `0x100ed463 -> 0x100df270`, with receiver at frame `+0x64`, packet at
   frame `+0x34`, and the descriptor as the pending child argument; and
3. `0x100ed46c -> 0x100f1cc0`, consuming the temporary descriptor.

Inside the child suffix, the exact original order is publish receiver,
`0x100e8240`, derive `0x119f3a38 + 0x68 = 0x119f3aa0`, call `0x100f2750`,
then call `0x100ea4d0`, perform two selector queries, and publish marker
`0x4e3b`. Original addresses are evidence identities only.

## Resolved prerequisite

The original suffix transcript was observation-only. Its callback contract
forbade executing the persistent descriptor write from inside an observer, and
running the write before or after the complete suffix would reorder it around
`0x100e8240` or `0x100ea4d0`.

`rome2_port_100df270_run_suffix_transcript_delegated` resolves that boundary
without weakening the original API. It snapshots a typed, status-returning
delegate before the first observer, emits the authenticated
`CALL_100F2750(0x119f3aa0, source)` step, executes the delegate exactly once,
and resumes with `CALL_100EA4D0` only after success. On delegate failure it
returns immediately: the first three suffix observations are a committed
prefix, while the marker cell and receiver output remain unchanged. The
original `rome2_port_100df270_run_suffix_transcript` remains observation-only.

The delegated seam does not select a callee. The admitted parent adapter binds
it specifically to `rome2_port_100f2750_first_use_owned` after validating that
all persistent views, owners, lifecycle controls, and allocation effects are
disjoint from the suffix state and controls.

## Admitted parent composition

The parent remains a separate sibling of the frozen empty adapter. It reuses
the exact `0x90c` frame layout and nine parent operations:

1. represent the two authenticated global byte stores;
2. initialize the two sentinel triplets;
3. copy those two still-empty triplets into the packet;
4. call `rome2_port_100f1bb0_build_owned_utf16` for `N` in `[1,32767]`,
   committing a temporary `LIVE` owner at frame `+0x28`;
5. run the existing child prefix and deterministic middle;
6. run the delegated suffix with
   `rome2_port_100f2750_first_use_owned` at the exact call position, committing
   a distinct persistent `LIVE` owner and `REGISTERED_LIVE` lifecycle;
7. call `rome2_port_100f1cc0_cleanup_owned_utf16` for only the temporary owner;
   and
8. commit the parent result last and stop before `0x100ed471`.

Registration of the persistent sentinel is an external prerequisite. The
adapter requires descriptor `{0,0,0x11af4090}`, an empty persistent owner, and
lifecycle `REGISTERED_SENTINEL` on entry. It does not hide registration as
a preflight mutation.

## Ownership and failure contract

The two allocation tokens are never interchangeable:

- the temporary owner follows `EMPTY -> LIVE -> CONSUMED` within a successful
  parent call and is released at the original `0x100ed46c` cleanup position;
- the persistent owner follows `EMPTY -> LIVE` and leaves the interval with
  lifecycle `REGISTERED_LIVE`; only the separately admitted explicit teardown
  may consume it later; and
- a persistent grant whose token collides with the still-live temporary token
  is rejected without releasing that source authority.

Full rollback after effects begin is impossible and is not claimed. All
deterministic view, range, alias, ownership, descriptor, and callback checks
must finish before the first parent observer. Allocation outcomes remain
effect-time facts. A failure while building the temporary owner follows the
owned leaf's exact denial/compensation contract. A failure in the delegated
persistent step leaves the already-built temporary owner `LIVE`, does not emit
later suffix steps, does not commit the parent result, and requires explicit
caller cleanup. Malformed nonzero destination grants may receive exactly one
compensating release; the optional teardown hook is never compensation.

On success, temporary cleanup completes before the parent result. Persistent
teardown remains outside `[0x100ed3c0,0x100ed471)` and outside the adjacent
ordinary lifecycle adapter.

## Completed admission

The implementation lands as the standalone
`ported_100ed3c0_nonempty_preloop` leaf without widening the frozen empty API.
Its admission includes:

- a nonempty-specific raw/provenance cross-check over the existing parent,
  child-suffix, owned-builder, first-use, and owning-cleanup authorities;
- a single total-order runtime recorder spanning parent, prefix, suffix,
  allocation, release, hook, and delegated-call events;
- the `1` and `32767` unit endpoints, all 16 temporary/persistent raw-residue
  pairs, distinct-token enforcement, Tier-0 preservation, Tier-1 committed
  prefixes, callback snapshot adversaries, and separate persistent teardown;
- reciprocal static mutants for every new ownership, ordering, alias,
  containment, and result-last claim; and
- a standalone `BUILD_TESTING` target with no headless, export, probe, or
  production consumer until the entire composition is independently admitted.

Native allocation, CRT registration, process globals, original exception
execution, guest-derived native calls, `LIVE -> LIVE` replacement, the loop at
`0x100ed471`, launcher entry, and gameplay remain excluded.

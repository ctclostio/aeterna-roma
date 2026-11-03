# x64 startup `0x100edd70` entry-decision composition

This milestone composes the admitted command-line selector with the conditional
registration-data interval and the admitted caller closure.  It is a bounded,
test-only x64 port named `rome2_port_100edd70_run_selected_route`; it is not a
native invalid-parameter-handler installation and it does not execute recovered
code.

## Frozen evidence and boundary

`docs/x64_startup_100edd70_entry_decision_evidence.md` and its read-only
provenance oracle authenticate:

- selector `[0x100edecc,0x100edf05)` (57 bytes);
- conditional registration data `[0x100edf05,0x100edf20)` (27 bytes);
- install caller window `[0x100edf20,0x100edf41)` and hard stop `0x100edf41`;
- skip caller window `[0x100edf73,0x100edf94)` and hard stop `0x100edf94`;
- inert callee identity `0x11687a4a`, inert handler identity `0x100ee5d0`,
  cleanup PC `0x100edf0f`, and store PCs `0x100edf12`/`0x100edf19`.

The evidence document's three-record transaction was explicitly provisional.
The independent contract adjudication froze four records, matching the already
admitted caller convention: argument pushes may be folded into their consuming
call shape, but a physically separate `add esp` remains its own cleanup record.

## Exact route

The selector runs exactly once against the snapshotted `text_view` and
`caller_position3_text`.  That one ABI position is structurally both the command
line and the text forwarded to the child; there is no redundant address or
runtime equality check.

Policy `INSTALL_HANDLER` emits, in order:

1. call shape at `0x100edf0a`, folded push at `0x100edf05`, callee identity
   `0x11687a4a`, handler argument `0x100ee5d0`, width 4;
2. cleanup-4 at `0x100edf0f`;
3. zero frame-store record at `0x100edf12`, displacement `-0x20`, width 4;
4. zero frame-store record at `0x100edf19`, displacement `-0x04`, width 4.

The four records are inert, by-value observer data.  They neither call
`__set_invalid_parameter_handler` nor `RaiseException`, and the frame-store
records perform no guest write.  Policy `SKIP_HANDLER` emits zero registration
records.  Both policies then invoke the admitted caller closure exactly once.

For child poll count `P`, the skip route emits `45 + P` events and the install
route emits `49 + P`.  The exact success totals are therefore:

| Route | P=1 | P=3 | P=64 |
|---|---:|---:|---:|
| skip | 46 | 48 | 109 |
| install | 50 | 52 | 113 |

The child's five callback-driven failure prefixes remain
`8/9/20/21/20`; install registration precedes them, so the install totals are
`12/13/24/25/24`.  There is no rollback.  A content-dependent deterministic
child denial can likewise follow the four-record install prefix: the runtime
pins empty position-three text to exactly four events, no child event, and an
unchanged outer result.  This ordering mirrors the original registration-before-
parent control flow.

## Transaction and alias contract

Before the selector or first effect, the adapter validates the enlarged outer
universe:

- fourteen controls: seven view objects, parent effects, continuation effects,
  registration effects, temporary owner, persistent owner, lifecycle, and
  result;
- seven pairwise host-and-guest-disjoint backing intervals;
- eight callback context spans: the parent's six, continuation, and
  registration.

Controls, backings, contexts, and private state are mutually disjoint.  Context
spans may be exactly identical to share a total-order recorder; partial overlap
is rejected.  Scalars, views, and all three effect objects are snapshotted by
value.  Owners and lifecycle are deliberately validated stateful pass-through
objects, because the admitted child advances their phases.

The outer preflight also checks frame identity, scalar ceilings, canonical empty
owners, `REGISTERED_SENTINEL` lifecycle state, and the fixed sentinel descriptor.
Those denials emit zero events.  Content-dependent child checks remain inside
the child and may therefore preserve an install prefix.  Callbacks are total,
non-reentrant, retain no borrowed address, and access only their declared
context; the mutation adversaries prove that later changes to caller-owned view
and effect objects cannot redirect execution.

Every failure leaves the caller's outer result byte-for-byte unchanged.  On
success the result records the selector policy, zero or four registration
records, and embeds the admitted `rome2_100edd70_caller_closure_result` without
duplicating its schema.  The result is assigned exactly once and last.

## Runtime and containment

The outer oracle has exactly 44 cases:

- six route-success cases (two policies times P=1/3/64);
- two selector-boundary cases;
- thirteen pre-effect denial cases, with additional ownership-prestate
  subchecks;
- eleven enlarged-alias cases;
- two mutation-isolation cases;
- six inherited failure-prefix cases;
- one result-last case;
- two one-shot teardown cases;
- one committed-prefix deterministic child denial.

The test executable first re-runs the unchanged 54-case caller-closure oracle,
then runs the 44-case outer registry. Strict `/W4 /WX` is enforced by the
ordinary build. Separate `/analyze /WX` and AddressSanitizer runs,
primary/fresh `BUILD_TESTING=ON`, and token-free `BUILD_TESTING=OFF` are required.
Six CTests extend the active inventory from 186 to 192; with the
Phase 4.2 battle entity pair the active inventory is from 186 to 194.
The new library is
`STATIC EXCLUDE_FROM_ALL`, has one test executable consumer, and is absent from
headless, export, probe, and production surfaces.  Production DLL and host
hashes must remain unchanged.

The hardened-run evidence is retained rather than implied by the ordinary
CMake flags. Both analyzer outputs under `work/entry_decision_analyze/` are
59-byte XML documents containing an empty `DEFECTS` set:

- `ported_100edd70_entry_decision.nativecodeanalysis.xml`;
- `test_startup_100edd70_entry_decision.nativecodeanalysis.xml`.

The separate `work/entry_decision_asan` graph records
`CMAKE_C_FLAGS=/fsanitize=address`; its target compile line also retains
`/W4 /WX /sdl /GS /guard:cf`. The focused CTest transcript at
`work/entry_decision_asan/Testing/Temporary/LastTest.log` records the unchanged
54-case child and all 44 outer cases passing under that instrumented binary.
These retained runs are admission evidence; they are not presented as flags
that every ordinary 194-test invocation silently enables.

Excluded beyond the hard stops: installed tail, exception gap, common epilogue,
`CoUninitialize`, SEH restoration, the `0x119f3144` read, native `wchar_t`, CRT
mutation, recovered callbacks, and every guest/native pointer cast.

`DONE-20260901-selector-to-caller-route: decision [0x100edecc,0x100edf05) -> registration-data(policy0,R=4) -> caller windows [0x100edf20,0x100edf41)|[0x100edf73,0x100edf94) -> hard stops 0x100edf41|0x100edf94; totals skip 45+P (46/48/109), install 49+P (50/52/113)`

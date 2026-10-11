# x64 bootstrap DLL

The repository now has a deliberately small, loadable x64 boundary. It proves
the compiler, linker, CRT startup, canonical-snapshot binding, exported probe
ABI, and a native host before any recovered x86 engine code is admitted to the
link. It is not yet a playable engine DLL.

## Build and test

From `X:\decompilation`:

```powershell
cmd /d /c scripts\build_x64_bootstrap.bat
```

Visual Studio Build Tools already supplies the local dependencies used here:
CMake 4.3.1, Ninja 1.13.2, and MSVC x64 19.51. The wrapper discovers the latest
Visual Studio C++ installation with `vswhere`, initializes `vcvars64`, configures
Ninja, builds with warnings as errors, and runs CTest with `--no-tests=error`.
These environment variables can override discovery:

- `ROME2_BUILD_DIR`
- `ROME2_BUILD_TESTING` (`ON` by default; `OFF` builds shipped targets only)
- `ROME2_VS_ROOT`
- `ROME2_VCVARS64`
- `ROME2_CMAKE_EXE`
- `ROME2_CTEST_EXE`
- `ROME2_NINJA_EXE`

Successful output is written under `out\x64-bootstrap`:

- `empire.retail64.dll`
- `empire.retail64.lib`
- `rome2_host64.exe`
- `rome2_entry_policy_tests.exe`
- `rome2_guest32_probe64.dll` (test builds only)
- `rome2_guest32_probe_host64.exe` (test builds only)

Run the local x64 scaffold directly after a successful build:

```powershell
.\out\x64-bootstrap\rome2_host64.exe `
  .\out\x64-bootstrap\empire.retail64.dll
```

It currently reports the accepted canonical fingerprint and the explicit
`startup=inert;entry=inert;gameplay=not-linked` status. A successful run proves
the native host/DLL boundary; it does not yet start the game.

The first recovered startup decision can also be executed locally, but remains
in a separate test executable:

```powershell
.\out\x64-bootstrap\rome2_entry_policy_tests.exe
```

It reproduces the bounded `-no_exception_handler` selector from original
function `0x100edd70`; it does not install a handler or enter the engine.

The same decision now runs through a real native DLL load/call/unload boundary:

```powershell
.\out\x64-bootstrap\rome2_guest32_probe_host64.exe `
  .\out\x64-bootstrap\rome2_guest32_probe64.dll
```

The host reports 13 passing behavior, memory, loader, repetition, and
concurrency groups. Both artifacts are test-only and disappear when CMake is
configured with `BUILD_TESTING=OFF`. See `docs/x64_entry_policy_probe.md` for
the acceptance boundary and direct gate commands.

The first composed native lifecycle harness is also available in test builds:

```powershell
.\out\x64-bootstrap\rome2_headless64.exe
```

It runs the admitted `0x100edd70` entry-policy decision, the bounded UTF-16
length loop from `0x100f1bb0`, the empty-source route through
`0x100f1aa0 -> 0x100f1c10`, and the null/sentinel no-op branch from
`0x100f1cc0`. It also executes the deterministic field projection at
`0x100df343-0x100df46c` with empty embedded descriptors, the no-crash
`0x100e8240` return branch, and the two-cell no-growth append prefix of
`0x100e2460`. It continues through that branch's mandatory common tail with
total injected dispatch and `PeekMessageW`-shaped effects, and separately
executes the complete intended `capacity == count == backing == 0` branch with
an injected allocator returning a pre-provisioned four-byte guest cell. A third
synthetic arena executes the normal full-vector growth route with injected
allocation and release, exact ascending copy/append order, and the same bounded
tail. A fourth persistent arena routes six ordered insertions through all three
branches, reproducing the original capacity/count sequence through final state
`8/6` with pre-provisioned 4/8/16/32-byte spans and three injected releases.

The handler wave now includes bounded models for all six method identities:
the six-step `0x100e8d00` transcript, effect-free `0x100e85d0`, the nine-step
`0x100e8580` transcript with an injected `0x100e8240` result, the four-step
`0x100e9340` lookup/singleton/helper transcript, the 3/4/6-route `0x100e92c0`
predicate/getter transcript, and the `0x100e87a0` listener-allocation,
publication, and FaceFX-startup transcript. A further arena runs the bounded
`0x100ea4d0` outer composition: six injected four-byte handler allocations,
six authenticated vtable stores, and six calls through the unified router.
Both dispatch adapters execute all six bounded models; no synthetic handler
success remains. The final arena executes the authenticated 131-byte suffix of
`0x100df270`: receiver publication, the three adjacent direct-call shapes, two
selector-2 queries, the mismatch-only four-call sequence, marker store, and
receiver return are represented as ordered injected effects.

The queue adapter is always probed at least once and is capped by a finite drain
bound. No original allocator, release routine, recovered x86 callee, USER32
API, or pending handler is executed. The current status suffix includes:

```text
initializer-append=preallocated-prefix;
initializer-branch=preallocated-complete;
initializer-capacity-zero=injected-complete;
initializer-growth=injected-complete;
initializer-router=injected-complete;
initializer-handler-100e8d00=injected-transcript-complete;
initializer-handler-100e85d0=effect-free-complete;
initializer-handler-100e8580=injected-transcript-complete;
initializer-100ea4d0=injected-complete;
initializer-handler-100e9340=injected-transcript-complete;
initializer-handler-100e92c0=injected-transcript-complete;
initializer-handler-100e87a0=injected-transcript-complete;
startup-100df270-suffix=injected-transcript-complete;
platform-effects=not-run;
post-platform-state=bounded-empty-projection;
allocator=injected-4-byte;native-allocator=not-run;
growth-allocator=injected-16-byte;
growth-release=injected-old-backing;native-release=not-run;
initializer-dispatch=injected-complete;
queue-drain=injected-bounded-complete;gameplay=not-linked
```

The storage branches, all six handler models, outer registration graph, and
final `0x100df270` suffix are now joined in a guest32 test-only composition
rather than a complete game.
Handler transcripts expose authenticated call shapes through injected effects;
they do not execute the original callees. Native platform calls and allocation,
the recovered launcher-facing startup parent, rendering, simulation, and the
main loop remain outside the executable. Listener/global publication in the
sixth handler is injected and observed rather than applied to process globals.
See
`docs/x64_startup_100df270_headless.md`,
`docs/x64_startup_100e2460_preallocated_branch.md`, and
`docs/x64_startup_100e2460_capacity_zero_branch.md`, and
`docs/x64_startup_100e2460_growth_branch.md`, and
`docs/x64_startup_100e2460_router.md`,
`docs/x64_startup_100e8d00_handler_transcript.md`,
`docs/x64_startup_100e85d0_normal_adapter.md`,
`docs/x64_startup_100e8580_handler_transcript.md`,
`docs/x64_startup_100e9340_handler_transcript.md`,
`docs/x64_startup_100e92c0_handler_transcript.md`,
`docs/x64_startup_100e87a0_handler_transcript.md`, and
`docs/x64_startup_100ea4d0_injected.md`, and
`docs/x64_startup_100df270_suffix_transcript.md` for the exact projection and
injected-effects boundaries.

The `64` suffix is intentional. The original `Rome2.exe` is x86 and cannot load
a PE32+ DLL, so the bootstrap must not be mistaken for a drop-in replacement for
`Empire.Retail.dll`. Only the suffixed DLL and `rome2_host64.exe` are accepted
outputs; any unsuffixed files left in the ignored build directory by an earlier
development run are stale.

## Canonical-stage gate

CMake reads
`src_canonical_out\empire.retail.dll\canonical_snapshot.tsv`, locates the
matching immutable stage at `generated\canonical\<mapping-fingerprint>`, and
requires its `validation_summary.json` and staged snapshot. Configuration fails
unless:

- the snapshot schema, format, SHA-256 values, and counts are well formed;
- the summary says the corpus is complete and the executable was verified;
- fingerprint, executable hash, function count, data count, and successful
  source count agree;
- both exporter and staged snapshot hashes match the summary.

A generated `canonical_identity.h` is the single source for both the DLL and
host. The load test therefore checks the built DLL against the accepted stage,
not against a second hand-copied fingerprint literal. The accepted snapshot is
currently 63,326 functions and 4,143 addressable data symbols with fingerprint
`0a7281990e144bc4ed54d432c4fd59aaa98b32c7bb9711e565bae2a304c2ff70`.

## Loader and binary policy

The DLL lets the current x64 MSVC CRT provide `_DllMainCRTStartup`; it never
links or calls the recovered x86 CRT, SEH, security-cookie, or initializer-table
code. Its user `DllMain` is inert and preserves thread notifications, which the
statically linked CRT requires.

The Release targets use C17, `/MT`, `/W4 /WX /sdl /GS /guard:cf`, and link with
ASLR, high-entropy ASLR, NX, CFG, CET compatibility, linker warnings as errors,
and no identical COMDAT folding in the DLL. The DLL has preferred base
`0x180000000`, Windows CUI subsystem version 6.0, and no custom `/ENTRY`.

The current binary acceptance check reports:

- PE32+ machine `0x8664` (x64);
- a normal CRT-selected DLL entry point and x64 unwind sections;
- an inert `entry_point` at ordinal 520 plus three diagnostic probes at reserved
  scaffold ordinals 523-525;
- only `KERNEL32.dll` as a load dependency;
- successful `LoadLibraryEx`, matching name/ordinal lookup for `entry_point`, a
  harmless nine-argument adapter call, ABI/fingerprint/status calls, and
  `FreeLibrary` from `rome2_host64.exe` using both absolute and working-directory
  relative DLL paths.

## Deliberate boundary

The three diagnostic probes report
`canonical-corpus-ready;startup=inert;entry=inert;gameplay=not-linked`. The
adapter at ordinal 520 models the nine launcher argument positions, dereferences
nothing, and returns zero. The bootstrap does not yet reproduce the complete
522-name/ordinal export table, run the 9,865 recovered program initializers,
link a canonical translation unit, or load any legacy middleware. Its sparse
520-525 export range is intentionally not the final ABI contract.

Five enabling milestones are complete: the lossless 522-export contract, the
strict 16-TU canonical compile island, the bounded static entry-policy selector,
its separately named test-only native DLL probe, and the first bounded
post-policy startup leaf (`0x100f1c10`). The probe passes an
independent PE/export/import/hardening gate, a link-map membership gate, and 13
native boundary groups. `rome2_guest32_runtime` remains isolated from the
bootstrap DLL; CMake fails configuration if the bootstrap gains a direct link
dependency on it.

The integrated hardened suite now includes raw return-domain authentication for
`0x100ec5c0`, native tests for the bounded `0x100f1bb0`/`0x100f1cc0` seams,
and the complete bounded nonempty owned-descriptor lifecycle through
`0x100f1bb0 -> 0x100ef330` and owning `0x100f1cc0` cleanup,
plus the first-use sentinel-to-owned persistent `0x100f2750` route and its
registered one-shot teardown,
the bounded post-platform state projection from `0x100df270`, and the complete
allocation-free, capacity-zero, and normal growth branches of `0x100e2460`.
The unified router, independent six-append oracle, all six bounded handler
models, injected `0x100ea4d0` outer graph, and authenticated prefix and suffix
of `0x100df270` extend that lifecycle without entering either shipped PE. The
suffix now also exposes an independently admitted, status-returning typed
substitution seam at its observed `0x100f2750` position; existing headless and
empty-parent consumers remain on the observation-only entry. The
empty-input straight-line interval `[0x100ed3c0,0x100ed471)` composes those
children inside the exact parent frame. The adjacent ordinary-domain lifecycle
adapter now continues through `[0x100ed471,0x100ed550)` using a prevalidated
finite `0* -> 2` transcript, checked by-value first dispatch, injected
timestamp/teardown, and four nonowning cleanups. The result-one list path and
second indirect call remain ordinary-domain unreachable and excluded. All
provenance, runtime, static-containment, and composed headless checks remain
`BUILD_TESTING`-only. The separately admitted nonempty sibling now composes the
temporary `0x100f1bb0` owner, persistent `0x100f2750` owner, delegated child,
and temporary cleanup in exact original order. A standalone whole-parent
adapter now joins that sibling to the admitted ordinary lifecycle across the
exact 400-byte interval `[0x100ed3c0,0x100ed550)`, with a private successor
preview before any external nonempty effect. This checkpoint registers 180
named CTests. The composed headless chain still terminates at
`startup_100ed471_ordinary_lifecycle_reload_verified`, while the standalone
whole nonempty chain terminates at
`startup_100ed3c0_nonempty_lifecycle_reload_verified`; the testing-disabled
control still builds only the unchanged bootstrap pair.

The next behavior milestone must remain outside this finite ordinary domain:
the poll-result-one list/second-indirect route and the outer caller/lifecycle
are still excluded. No recovered startup path is linked to the bootstrap's
launcher-facing entry. Native Win32 platform behavior, broader initializer
order, gameplay, and external dependencies remain later
subsystem-by-subsystem work.

Never replace the original game DLL with this bootstrap.

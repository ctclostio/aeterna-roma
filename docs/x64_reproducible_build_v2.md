# Reproducible x64 bootstrap build v2

Status: active production-artifact authentication record. The original binary
gate and its three milestone documents remain frozen as v1 forensic evidence.
This record supersedes only their two bootstrap artifact hashes.

## Why v2 exists

The first clean relink after the 2026-08-26 reboot changed the SHA-256 of both
bootstrap artifacts even though no production source changed. Byte-level PE
forensics proved that the historical pair and the current pre-v2 pair differed
only in three replicated wall-clock `TimeDateStamp` fields per artifact. Setting
those fields in memory to `0x6a8c75d6` for the DLL and `0x6a8cecf1` for the host
reproduced the exact v1 hashes. No exact v1 artifact copy remained.

Restoring an older retained host was rejected because it had genuinely older
code and section layout. Timestamp-patching was also rejected because the next
link would immediately recreate the problem.

## Active build contract

MSVC compile and link commands now receive `/Brepro`. This removes wall-clock
COFF/PE identity from shipped Release DLLs and executables while preserving the
existing hardening flags. The active v2 artifacts are:

- `empire.retail64.dll`: 107,520 bytes,
  SHA-256 `d5f432084f4638a69fc3ef1b155c973c281f7704af1be6eca7f5aa63c7ca12a5`;
- `rome2_host64.exe`: 144,384 bytes,
  SHA-256 `be4048881e43c09b5b9a9c22381aa8f02f74a9ed0a47221bb1022cb727bd4e73`.

The active matrix contract contains the primary `BUILD_TESTING=ON` tree plus
fresh `BUILD_TESTING=ON` and `BUILD_TESTING=OFF` trees after admission of the
standalone whole nonempty parent composition over
`[0x100ed3c0,0x100ed550)` and its test-only caller-closure binder over the two
33-byte `entry_point` windows `[0x100edf20,0x100edf41)` and
`[0x100edf73,0x100edf94)`, now selected by the exact entry-decision intervals
`[0x100edecc,0x100edf05)` and `[0x100edf05,0x100edf20)`. The composition joins
the admitted owned UTF-16,
persistent first-use, delegated `0x100df270`, and finite ordinary-lifecycle
children without changing the production or headless link graph. The two
fresh manifest evidence paths are
`out/repro-100edd70-entry-decision-verified-on` and
`out/repro-100edd70-entry-decision-verified-off`. Earlier parent, prefix,
suffix, handler, router, and branch milestones produced the same production
pair. The checkpoint is admitted only when absolute and relative smoke loading
succeeds wherever testing is enabled and both testing-enabled graphs pass the
expected 192/192 CTests. The primary and fresh testing-enabled graphs both
pass 192/192, the testing-disabled control exposes no test or headless targets,
and all three trees reproduce the pinned production DLL and host byte for byte.
An additional clean testing-enabled proof at
`out/repro-100ed3c0-nonempty-lifecycle-verified-on` also passes 180/180. The v2
verifier therefore admits the three paths named by the manifest. Prior
`out/repro-100ed3c0-empty-preloop-verified-{on,off}`,
`out/repro-100e87a0-handler-verified-{on,off}`,
`out/repro-100ea4d0-injected-verified-{on,off}`,
`out/repro-100e2460-router-verified-{on,off}`,
`out/repro-100e2460-growth-verified-{on,off}`,
`out/repro-100e2460-capacity-zero-verified-{on,off}` and
`out/repro-100e2460-verified-{on,off}` trees are superseded by this milestone;
the still earlier `out/repro-100e2460-final-{on,off}` scratch configurations
were never admitted because their Release/default flag cache entries are blank
and their artifacts do not match the v2 pair.

The PE gate confirms AMD64 PE32+, high-entropy ASLR, dynamic base, NX/DEP, CFG
instrumentation and function table, CET compatibility, `/GS`, the sparse
bootstrap contract, and the diagnostic probe's exact import/export boundary.
The artifacts remain unsigned, as expected for this local development build.

## Rebuild recipe

Run from an MSVC x64 developer environment with the toolchain pinned in
`scripts/x64_reproducible_build_v2_manifest.json`:

```powershell
cmake -S . -B <fresh-dir> -G Ninja `
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build <fresh-dir> --config Release
ctest --test-dir <fresh-dir> -C Release --output-on-failure --no-tests=error
```

Repeat with `BUILD_TESTING=OFF`; both production hashes must remain identical.
The manifest verifier authenticates the live production inputs, tool binaries,
v1 and v2 gates, v2 output pair, the exact Release/default compiler and linker
cache entries, and all twenty-nine named active CMake gate routes, including
`startup_100edd70_entry_decision_post_pe_gate`,
`startup_100edd70_caller_closure_post_pe_gate`, and
`startup_100ed471_ordinary_lifecycle_post_pe_gate`. It also runs the
pinned Ninja with `-n` against every matrix tree and rejects any pending build
step. Any future toolchain or production-input change requires a separately
reviewed, versioned migration rather than an in-place repin.

This remains an inert loader/bootstrap scaffold. Reproducible bytes do not make
it a runnable game and do not widen the admitted recovered-code boundary.

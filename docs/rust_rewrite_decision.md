# Architectural Decision: Rust Rewrite After Decompilation

**Date**: 2026-11-19  
**Status**: Approved  
**Decision**: The Total War: Rome II engine will be rewritten in Rust after the decompilation and validation phases are complete.

## Context

This project (`X:\decompilation`) is a long-horizon effort to decompile the entire Total War: Rome II game engine (`empire.retail.dll`, 28 MB x86 PE32) into a native, modern codebase. The current pipeline is:

1. **Decompilation** (current phase): Full auto-analysis and export of all 81,280 functions
2. **Type Recovery** (current phase): Guest32 layouts, contracts, and bounded C17 reconstructions
3. **Validation**: x64 port milestones, test-only transcripts, and original-byte provenance
4. **Rewrite in Rust** (future phase): After validation is complete

## Decision

After the decompilation is finished and validated, the reconstructed engine will be **rewritten in Rust** rather than remaining as C/C++ or being ported directly to 64-bit C++.

## Rationale

1. **Memory Safety**: Rust's ownership model eliminates entire classes of bugs (use-after-free, buffer overflows, data races) that are endemic to the original MSVC codebase.

2. **Modern Tooling**: Cargo, rustfmt, clippy, and the Rust ecosystem provide superior build tooling, dependency management, and static analysis compared to the existing CMake/MSVC setup.

3. **Concurrency Safety**: The original engine uses Win32 threading primitives. Rust's `Send`/`Sync` traits and fearless concurrency model will make the codebase safer to modify.

4. **Long-Term Maintainability**: A Rust codebase will be easier to extend and modify for future contributors.

5. **FFI Compatibility**: Rust has excellent C FFI support, allowing gradual migration and interop with any remaining C components, D3D/OpenGL bindings, and Steam API.

## Scope

The Rust rewrite applies to the **game engine logic** decompiled from `empire.retail.dll`. This includes:

- Startup and initialization
- VFS (Virtual File System)
- Campaign and battle systems
- Render pipeline abstraction (D3D9/D3D11 bindings via `windows-rs` or similar)
- Audio, UI, networking, and save systems

## Dependencies

The rewrite depends on:

1. **Completion of decompilation**: All 81,280 functions exported (✓ done)
2. **Function identification**: Currently at 11.1% (9,036/81,280 named)
3. **Type recovery**: Currently at Layer 60 with 1,251 functions recovered
4. **Validation**: x64 port milestones with test-only execution and original-byte provenance
5. **Full semantic understanding**: Engine architecture, class hierarchies, and data flow

## Timeline

The Rust rewrite will begin only after:

1. All critical engine modules are identified and documented
2. Type recovery covers all major subsystems
3. x64 validation proves behavioral equivalence for key paths
4. The team has sufficient understanding to write idiomatic Rust rather than transliterating C

This is a **multi-year** effort. The Rust rewrite is the final phase, not a near-term milestone.

## Alternatives Considered

1. **Stay with C/C++**: Rejected due to memory safety concerns and long-term maintainability.
2. **Direct x64 C++ port**: The current test-only x64 work serves as validation, but the final target is Rust.
3. **Other memory-safe languages (Zig, Odin)**: Rust has the most mature ecosystem and FFI story for this scale of project.

## Verification Criteria

Before the Rust rewrite begins, the following must be true:

- [ ] All major engine subsystems have documented type layouts
- [ ] Critical paths have validated x64 test-only transcripts
- [ ] Function identification reaches at least 50% coverage
- [ ] Engine architecture document covers all major modules
- [ ] At least one full startup-to-menu path is understood end-to-end

## References

- [README.md](../README.md): Project overview and current status
- [progress.md](../progress.md): Detailed type recovery and milestone records
- [docs/engine_architecture.md](engine_architecture.md): Engine module documentation
- [docs/type_recovery.md](type_recovery.md): Type recovery methodology

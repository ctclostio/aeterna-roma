# Next x64 execution milestone: caller-closure binder

Status: evidence candidate frozen after admission of the standalone whole
nonempty ordinary-domain parent. Implementation remains `BUILD_TESTING`-only
and is not yet admitted.

## Current successor boundary

The next bounded slice is not the result-one list route inside `0x100ed3c0`.
The authenticated `0x100ec5c0` ordinary return domain is exactly `{0,2}`, so a
port must not synthesize result `1` or claim the structurally present second
indirect call is ordinarily reachable.

Instead, bind the newly admitted whole-parent adapter to the two exact
`entry_point` caller/continuation windows already authenticated by
`scripts/x64_startup_100ed3c0_abi_fixture.json`:

| Branch | Exact interval | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| handler registered | `[0x100edf20,0x100edf41)` | 33 | `52227b99b8d956f8926eb0f02b0f3b8c62a229dee20653b5608dc81a96e41084` |
| handler skipped | `[0x100edf73,0x100edf94)` | 33 | `76a454a3f06c1c8de33f0b3b0ab432e059de9abca52b342b8cac0e9f50198d6a` |

Each window pushes the same four caller positions, calls `0x100ed3c0`, then
executes the same two keeper calls and a grouped 24-byte stack cleanup. The
call sites are `0x100edf28` and `0x100edf7b`; their continuations call
`0x101136d0(1)` and `0x101150f0(0x100d6560)` in that order. The two keeper
bodies are independently bounded leaves:

- `0x101136d0`, raw offset `0x00112ad0`, 10 bytes
  `8a442404a28e3d9f11c3`, SHA-256
  `22b0fe50342cb045ba9144d7d8060d9752e1f72b353436d7a43194e03c3c7bc0`;
- `0x101150f0`, raw offset `0x001144f0`, 10 bytes
  `8b442404a35c3f9f11c3`, SHA-256
  `a4e8fe0de027b3efd0a36a670c540ef75256b470d380c4b3124e91e5e61332c5`.

The executable projection will accept the already-admitted invalid-parameter
policy as data, snapshot and validate its complete alias universe, preserve
the four caller-position identities, invoke the whole nonempty parent exactly
once, represent both keeper stores as typed injected effects, publish one
result last, and return the branch-specific continuation boundary as data.

The hard stops are `0x100edf41` and `0x100edf94`, before either epilogue. The
handler-registration body `[0x100edf05,0x100edf20)`, `0x11687a4a`,
`CoUninitialize`, exception-frame restoration, recovered process globals,
original calls, native/CRT behavior, exports, probes, and production/headless
consumers remain excluded. Admission requires independent byte/canonical
provenance, a total-order runtime oracle, reciprocal and live static gates,
strict MSVC analysis, AddressSanitizer, testing-disabled containment, the full
CTest graph, and unchanged production hashes.

This candidate was independently recommended by the exact-model DeepSeek V4
Flash review retained under
`out/pi-swarm/20260831-nonempty-lifecycle-closeout/next-milestone/`.

# Historical x64 execution milestone: frozen candidate packet

This packet bounds the evidence stage that follows the first guest32 behavior
slice. It compares two candidates; it is not permission to implement either
one until the evidence stage is reconciled and an independent acceptance oracle
is frozen.

## Current executable boundary

The repository builds and locally runs a PE32+ host and DLL:

```powershell
cmd /d /c scripts\build_x64_bootstrap.bat
.\out\x64-bootstrap\rome2_host64.exe `
  .\out\x64-bootstrap\empire.retail64.dll
```

The host loads the DLL by both absolute and relative paths, resolves the sparse
scaffold exports, calls the inert nine-position `entry_point` adapter, verifies
the canonical fingerprint, and unloads the DLL. The reported status remains
`startup=inert;entry=inert;gameplay=not-linked`. The original x86 launcher
cannot load this x64 DLL.

Pinned inputs:

- `Total War Rome II/Rome2.exe`: 804,864 bytes, SHA-256
  `332de1aac9303ce71dbee82fe2f8fcb9d2f82766ebd2e6943db6fe9dac30519d`.
- `Total War Rome II/empire.retail.dll`: 28,278,272 bytes, SHA-256
  `d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.

The launcher's `0x00402492` through `0x004024c2` call sequence is at file
offset `0x1892`, is 49 bytes, and has SHA-256
`0a37a289d5e49348f28d6aea2970f9b7ce1345ce5080d5cbfbe4a30a0d7d8cd6`.
It pushes nine values, calls the resolved export at `0x004024be`, removes
`0x24` bytes of arguments, and later tests the returned low byte. This proves
the number of caller-supplied positions, not the semantic type of every value.

## Candidate A: diagnostic DLL guest32 bridge

Expose the already-tested `0x1093c450` to `0x100e81a0` behavior through one
temporary, fixed-width diagnostic DLL adapter. This would be the first recovered
behavior executed through the loaded x64 DLL, while `DllMain`, `entry_point`,
legacy ordinals 1 through 522, and all startup initializers remain inert.

Pinned behavior:

- `0x1093c450`, file offset `0x93b850`, bytes `8b09e949bd7aff`, SHA-256
  `f7ae2c69da41f139815d8f7f3ef3b4e16b9315deff22fd399fee79822ebb41cf`:
  load one four-byte cell and tail-jump to `0x100e81a0`.
- `0x100e81a0`, file offset `0x0e75a0`, bytes `8d4104c3`, SHA-256
  `4181cb1fec090d6487f323c8ce84a17ff37429613d7843b4f5f40f5eae266b77`:
  return the x86 address plus four.
- Canonical hashes are
  `df5a37ce9129cf6fabd29d1484cb1fc659bb74beae1da1d4a1f24e1e1b1828a6`
  and
  `55b88a81ff531950985f43699115453b1f11439b8c0b79b2232ece28fb0fb6b4`.

The proposed public shape uses only fixed-width scalars and caller-owned
read-only bytes. It must never return a host pointer. A temporary scaffold
ordinal, if accepted, must be above the original 1 through 522 contract.

Primary benefit: proves recovered semantics across the real host/DLL boundary.
Primary cost: links previously isolated guest32 code into the bootstrap and
adds a temporary nonlegacy ABI without reducing the original startup closure.

## Candidate B: static entry-policy selector

Extend the isolated guest32 runtime with a bounded UTF-16LE reader and reproduce
only the exact inline `-no_exception_handler` branch decision from the original
`entry_point`. It must remain static and test-only for this milestone: it does
not install a handler or call the main engine path.

Pinned behavior:

- Canonical `decomp_fn_100edd70.c` SHA-256
  `ec93da6e0523b5558068cc6cc2cb7acfe686cbb201f3d35bf4f0168e0e1e3c34`.
- Selector VA range `0x100edecc` through `0x100edf04`, file offset `0x0ed2cc`,
  57 bytes, SHA-256
  `11bc65f6b73602d0b4a7c974728793ca5d817cc974a5c8ff91ab1e98b64e7ebc`.
- Exact literal VA `0x1173f894` through `0x1173f8bf`, file offset
  `0x173e294`, 44 bytes including the UTF-16LE terminator, SHA-256
  `158c0c7b39632eaab540612eb67ded95089a82894e7a91edbff93866b072c86e`.
- Equality jumps to `0x100edf73`, skipping invalid-parameter-handler
  installation. An ordinary mismatch falls through to `0x100edf05`; both
  branches later call `0x100ed3c0` in the original.

The port candidate may decide only `skip_handler_install` versus
`install_handler`. Null, truncated, overflowing, or otherwise malformed guest
input must fail with its output unchanged. It must use `uint16_t`, not native
Windows `wchar_t`, and must preserve early-mismatch behavior without reading an
irrelevant suffix.

Primary benefit: reduces the actual startup decision closure while preserving
guest32 containment. Primary cost: it does not yet execute through the loaded
DLL and requires a carefully bounded guest UTF-16LE API.

## Common hard rejection gates

Reject either candidate if it introduces any of the following:

- guest-to-host pointer casts or widened four-byte guest cells;
- a writable/global default guest arena;
- an unbounded guest string operation;
- recovered initializer, COM, registry, filesystem, process, handler, or main
  loop execution;
- a custom DLL entry point or recovered x86 CRT/SEH state;
- a legacy export prototype inferred from an x86-decorated name;
- warning suppression, canonical-source edits, or a fail-open evidence gate;
- output mutation on error or tests that serve as their own only oracle.

The decision is not made by majority vote. Conflicting claims must be resolved
against the pinned binaries, and every accepted correlated defect becomes a
mandatory regression mutant before implementation begins.

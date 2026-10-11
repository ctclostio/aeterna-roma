# x64 guest32 entry-policy DLL probe

Status: implemented and locally accepted on 2026-08-25. This is the first
recovered startup decision executed through a real x64 DLL boundary. It is not
game startup.

## Run it locally

From `X:\decompilation`, build and run the repository suite:

```powershell
cmd /d /c scripts\build_x64_bootstrap.bat
```

Then invoke the native probe directly:

```powershell
.\out\x64-bootstrap\rome2_guest32_probe_host64.exe `
  .\out\x64-bootstrap\rome2_guest32_probe64.dll
```

A successful run ends with:

```text
probe runtime passed: 13 cases
```

The ordinary inert bootstrap remains separately runnable:

```powershell
.\out\x64-bootstrap\rome2_host64.exe `
  .\out\x64-bootstrap\empire.retail64.dll
```

That command must still report
`startup=inert;entry=inert;gameplay=not-linked`.

## What executes

`rome2_guest32_probe_host64.exe` loads `rome2_guest32_probe64.dll` with
`LoadLibraryExW`, resolves exactly two exports by name, calls them, and unloads
the DLL. The adapter constructs one borrowed `rome2_guest_read_view` and
delegates directly to
`rome2_port_100edd70_select_invalid_parameter_policy`.

The boundary uses only fixed-width values:

```c
uint64_t Rome2Guest32ProbeAbiVersion(void);

uint32_t Rome2Guest32ProbeSelectEntryPolicy(
    const uint8_t *host_base,
    uint32_t guest_base,
    uint64_t byte_count,
    uint32_t command_line,
    uint32_t *policy_out);
```

The binaries are PE32+ AMD64. The `uint32_t` addresses model cells in the
original x86 address space; they are never converted into native pointers.

## Acceptance evidence

The Release build uses C17 with warnings as errors and the repository hardening
options. The integrated CTest suite passes 15/15 and includes:

- pinned original-byte and canonical-source provenance;
- the token-aware static selector gate and its mutant tests;
- independent PE32+/AMD64, exact-export, import, CFG, CET, and bootstrap-hash
  checks;
- a link-map check proving only `guest32.c.obj` and
  `ported_100edd70_policy.c.obj` are admitted from
  `rome2_guest32_runtime`, while the unrelated `ported_1093c450` slice is not;
- 13 DLL-boundary groups covering exact and mismatching strings, truncation,
  checked guest ranges, a view ending at 2^32, unaligned input, a genuine
  native address above 4 GiB, absolute/relative loading, invalid name
  resolution, repeated load cycles, repetition, and concurrency;
- independent bootstrap hash/PE gates before and after the probe runtime, plus
  inert smoke tests at both ends.

The authenticated bootstrap artifacts remain:

- `empire.retail64.dll` SHA-256
  `fa4c0584790894e85a60427e0cb6adbf1266d14ddc321c122206365bdca8e3a0`;
- `rome2_host64.exe` SHA-256
  `007b75d58e6cb6890d98b102f07fd2be353423c4f31af41f11c366679a567708`.

Configuring and building with `BUILD_TESTING=OFF` creates no probe target, test,
DLL, host, import library, or map. Nothing is installed or packaged.

## Deliberate stop line

The probe does not load the original x86 DLL, install the original invalid
parameter handler, run recovered initializers, call `0x100ed3c0`, expose a
legacy export, or enter gameplay. The original x86 `Rome2.exe` cannot load
these x64 artifacts.

The next safe step is to freeze evidence and an independent acceptance oracle
for bounded pieces of the `0x100ed3c0` post-policy closure. No part of that
closure should be attached to the launcher-facing bootstrap entry until its
platform calls, global state, dependencies, and initializer prerequisites are
understood and tested in isolation.

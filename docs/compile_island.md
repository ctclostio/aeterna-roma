# Strict canonical compile island

`scripts/gen_compile_island.py` creates an immutable, bounded x64 syntax
island from a canonical staged export. It never includes `functions.h`,
`globals_decls.h`, `umbrella.h`, or the wholesale opaque-type header.

For every selected translation unit, the generator verifies the staged source
hash and lexical reference inventory, then emits one stable-sorted
`decomp_fn_<address>.deps.h`. Each direct-callee prototype is the exact
`joined_manifest.tsv` declaration with a semicolon appended. The generator
does not create implicit, old-style `()`, pointer-sized-integer, or byte-array
fallbacks. Legacy storage names, address-valued labels, unknown declaration
types, and unregistered canonical data enter quarantine.

Clean publication requires an explicit compiler gate. The wrapper discovers the
accepted fingerprint and x64 MSVC environment, then runs the default island:

```powershell
cmd /d /c scripts\build_compile_island.bat
```

The equivalent direct invocation is:

```powershell
python -B scripts\gen_compile_island.py `
  generated\canonical\0a7281990e144bc4ed54d432c4fd59aaa98b32c7bb9711e565bae2a304c2ff70 `
  --compiler cl.exe `
  --base-compat src\include\ghidra_compat.h
```

Run that command in an x64 MSVC developer environment. The generator copies
the exact base header into the island, force-includes a generated compile-time
`sizeof(void *) == 8` gate, and invokes each TU with:

```text
/nologo /TC /Zs /W3 /we4013
```

It records the exact relative response files, command manifest, compiler
content/version hashes, per-TU logs, and results. Only a 16/16 result receives
`COMPILE_VERIFIED`. A structurally clean dry run is not compiler-verified, and
any compiler failure is atomically published below `_quarantine`.

The current x64 baseline passes all 16 translation units under policy
`8afc796a13d6959beac0d1a34370f4a071b25f2bc4f7d1cef17307d39afeb592`.
MSVC reports 228 non-fatal level-3 warnings: 126 C4312, 40 C4047, 32 C4311,
25 C4024, two C4146, and one each of C4244, C4305, and C4554. These warnings
remain preserved in the per-TU logs; `COMPILE_VERIFIED` means that the bounded
sources pass the x64 syntax and implicit-declaration gate, not that their
recovered pointer types or ABI are correct.

The same island deliberately fails 16/16 under an x86 MSVC environment at the
generated `sizeof(void *) == 8` gate. Repeated negative runs reproduce the same
quarantine policy and artifacts; compiler paths rooted in the atomic temporary
directory are normalized to `<ISLAND_ROOT>` before publication.

The policy also pins the current `src\include\ghidra_compat.h` bytes (SHA-256
`90078d227dfa4a585d9170b3d79ef7064e5338385b48d1f86f24fae87002378d`),
the generator, the `cl.exe` binary, its MSVC inventory and target, and the x64
pointer-width gate. `COMPILE_VERIFIED` requires one successful result for every
selected TU from a compiler whose `/Bv` inventory identifies the x64 target.
The gate is not a fully hermetic toolchain capture: compiler-pass DLLs and
Windows/SDK headers are version-inventoried by MSVC but are not content-pinned.

## Default island selection

The original audit proposed these 16 roots:

```text
10161140 101627c0 101bd660 101c9910
101d7cb0 102667a0 102773a0 10282130
102d8900 1032ce70 103d76e0 10450190
104a1980 10512450 10679cf0 10682fc0
```

Exact prototypes exposed recovered-signature contradictions: only
`103d76e0`, `104a1980`, and `10512450` passed, so that set is retained as
`AUDITED_ROOTS` evidence but is not the CLI default.

The replacement was selected with this bounded, deterministic policy:

1. Form the address-sorted universe of roots having 1–8 indexed canonical
   function targets and no canonical data target.
2. Rank each address by
   `SHA256(UTF-8("rome2-exact-prototype-island-v1") + 0x00 + ASCII(address))`.
3. Inspect only the first 256 ranked roots with the generator's structural
   gates. There were 106 structurally clean candidates.
4. Run those 106 candidates through exact per-TU prototypes and the x64 MSVC
   gate. Twenty passed.
5. Select the lowest-address 16 passing roots.

The verified default is:

```text
102df760 10328370 104c76c0 1064d4e0
10698600 10802630 108a8e80 1093c450
109555c0 10981dd0 109871d0 10a132b0
10c93ea0 10f17100 10f4f540 10f537c0
```

This is a syntax/prototype gate, not an ABI or behavioral correctness claim.
The preserved pointer-width warnings are the next porting gate.

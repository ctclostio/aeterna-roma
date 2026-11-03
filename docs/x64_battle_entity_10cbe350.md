# Battle entity projection (`0x10cbe350`)

Status: bounded, standalone `BUILD_TESTING` adapter. The 2026-11-02 correction
separates the origin pair from the item vector, fixes the suffix argument map,
rejects unsupported counts before effects, and pairs vector allocation with
the supplying host's release callback. It does not integrate the game engine.

## Original evidence

The authority is `Total War Rome II/empire.retail.dll`, 28,278,272 bytes,
SHA-256 `d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
The saved `workspace/TW2` Ghidra database was inspected read-only, without
analysis, with `scripts/ProbeFunc.java`. The retained instruction listing is
`out/continue-battle-20261102/battle_probe.log`; no target execution was used.

| Function | Bytes | SHA-256 |
| --- | ---: | --- |
| `0x10cbe350` | 512 | `1a9cdb6c8d2dbeafae459afa588c05fc2f3ca2361bcde655da5183e241e55525` |
| `0x10cc1a10` | 127 | `2c717aad747c2446ea358488d2d4b9c0c7ddcde3c482398ced48ac23b816227c` |
| `0x100f1700` | 32 | `b914ce9c4151eda34ea7777f588df95d50c9b94093c4ee3d3513192c6e5c517d` |
| `0x100ef2c0` | 111 | `12af44082fcc9372e2f8a1e93544777c847dfba294763d08b2d7b672c8712c07` |

`scripts/test_x64_battle_entity_10cbe350_provenance.py` authenticates the whole
image, all four bodies, and the instruction windows used for the mapping below.
It skips when the copyrighted image is absent.

## Corrected argument map

The constructor returns `this` in EAX and ends with `RET 0x4c`: nineteen stack
words, indexed from zero, with arg N at entry ESP + `4 + 4*N`. Its normal local
frame is `0x18` bytes. Three pushes and a twelve-byte by-value scratch string
temporarily increase that depth before the climate constructor's `RET 0x18`.

| Argument | Original read | Recovered destination/use |
| --- | --- | --- |
| arg00 | `0x10cbe440` | string source -> `this+0xa0` |
| arg01 | `0x10cbe44f` | pair -> `this+0xac/+0xb0` |
| arg02/03/04 | `0x10cbe3fb/3f4/3ec` | three climate dwords |
| arg05 | `0x10cbe3f0` | dword -> `this+0x60` |
| arg06/07/08 | `0x10cbe522/540` | by-value string released on exit |
| arg09 | `0x10cbe3b3` | origin pair -> `this+0x28/+0x2c` |
| arg10 | `0x10cbe453` | separate vector descriptor; +4 count, +8 source |
| arg11 | `0x10cbe50f` | string source -> `this+0xd0` |
| arg12 | `0x10cbe3ff` | low byte -> `this+0x64` |
| arg13 | `0x10cbe51e` | low byte -> `this+0xdc` |
| arg14 | `0x10cbe409` | dword -> `this+0x6c` |
| arg15 | `0x10cbe52c` | full dword -> `this+0xe0` |
| arg16 | `0x10cbe536` | low byte -> `this+0xe4` |
| arg17 | `0x10cbe4f6` | string source -> `this+0xc0` |
| arg18 | `0x10cbe505` | low byte -> `this+0xcc` |

For example, `MOV EBX,[ESP+0x44]` at `0x10cbe453` selects entry ESP+`0x2c`
(arg10), whereas `MOV ECX,[ESP+0x40]` at `0x10cbe3b3` selects arg09.
Their sources are independent. Arg14 is a dword, not a second interpretation
of the arg17 string pointer.

The empty climate scratch string is explicitly constructed at `0x10cbe433`;
it is not an uninitialised caller read. The final incoming-string destructor
addresses entry ESP+`0x1c` (arg06), not arg03.

## Host behavior and limits

The native projection is `0x120` bytes, with sixteen-byte string records and
eight-byte host pointers. It is not an overlay of the original x86 object;
dispatch values remain inert original image identities. Layout assertions pin
the selected host fields. Original untouched padding and write order are
outside the contract.

The original allocation clamps negative counts to zero at `0x10cbe4a1`, but
its copy loop reloads the unchanged count at `0x10cbe4da`. The adapter rejects
counts greater than `UINT32_MAX / 12`, excluding both negative signed values
and overflow of the original byte request. Accepted host allocations use
`count * sizeof(rome2_recovered_str)`; zero count calls no allocator.

Nonempty vectors require readable source records and both `alloc_items` and
`free_items`. Invalid input, a missing service, or a failed allocation returns
NULL and leaves the destination unchanged. Construction requires fresh or
already released storage and disjoint input/output/vector spans. Optional null
origin, descriptor and string inputs project as zero/empty; that convenience
is specific to this adapter.

String lengths and capacities project the `0x100f1700 -> 0x100ef2c0` path:
capacity becomes length and an empty string uses `0x11af408e`. Text bytes are
borrowed instead of deep-copied. They must remain readable for the lifetime of
the resulting views. Only the vector allocation is owned; release uses the
same host, clears both counts, and supports repeated calls. Missing release
authority leaves a live vector unchanged and returns false.

Native string allocation/destruction, ownership transfer of arg06..arg08,
callable dispatch tables, engine integration and runtime equivalence remain
unimplemented. The neighboring unit-card helper boundary is still provisional;
see `docs/x64_battle_unitcard_10145c70.md`.

## Verification

The entity runtime has ten test groups, including distinct origin/vector
sources, independent suffix arguments with different upper and lower bytes,
negative and overflowing counts, missing inputs/services, allocation failure,
the largest admitted request through a failing allocator, a custom allocator
that returns static storage, borrowed-string capacity/empty handling, and
one-shot cleanup. Assertions remain active in Release builds.

CTest names are `battle_entity_10cbe350_runtime` and
`battle_unitcard_10145c70_runtime`. The original-byte checks run separately:

```powershell
python scripts/test_x64_battle_entity_10cbe350_provenance.py
```

Recorded on 2026-11-02: **194/194 CTests** and **4/4 original-byte tests**
passed. The entity source also passed MSVC `/analyze /W4 /WX`; all ten runtime
groups passed under AddressSanitizer. Logs and build commands are retained in
`out/continue-battle-20261102/`. A fresh `BUILD_TESTING=OFF` graph excludes the
battle targets, and both its production DLL/host and the testing-enabled pair
match the unchanged reproducible-build hash pins in
`scripts/x64_reproducible_build_v2_manifest.json`.

The regression cleanup preserves exact authority bytes: three unit-test reads
now avoid CRLF translation, and the historical wave wiring pin includes the
artifact-absence skip guards already merged in `658d6a2/acfb6a1`. The oracle
test file has an LF checkout rule so that updated pin remains reproducible.

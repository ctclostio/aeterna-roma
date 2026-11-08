# XML loader policy and linked readiness

The native XML loader policy helpers recover three bounded operations: a
narrow path-prefix predicate, legacy BOM byte preparation, and a reader for the
original linked readiness state. They perform no file I/O or parsing. Original
loader assembly establishes several failure-path distinctions below; full
resource-manager mount order, normalization rules, parser equivalence and
complete XML class layouts remain separate recovery obligations.

## Path-prefix predicate

`FUN_100f3b20` tests byte 1 for `':'`, then byte 2 for `'/'` or `'\\'`.
It never validates byte 0 as a drive letter and performs no existence check.
Only `AL` receives the Boolean result; the remaining bits of `EAX` are not
an integer Boolean return value. The original 27-byte instruction sequence is
checked against the pinned image by the original-image contract suite.

`rome2_xml_path_is_drive_rooted` accepts an already-normalized borrowed byte
span and implements that predicate. NULL or spans shorter than three bytes
return false as a native bounds adaptation. It does not reproduce the path
normalizer that precedes the original predicate, resolve aliases, check files,
or choose among archives.

| Normalized prefix | Predicate result |
|---|---|
| `C:/`, `c:\` | true |
| `1:/`, `?:\` | true; the first byte is not validated |
| `C:relative`, `Script/`, `/Script/` | false |
| `\\server\share` | false |

## Legacy BOM byte preparation

The loader reads the first word at `0x112a7d4b`. For either `FF FE` or `FE FF`
it skips those two bytes, visits each remaining **byte**, and copies only
nonzero bytes toward the start of the same buffer. It then appends NUL.
Without either marker it preserves the input bytes and appends NUL at the
original byte length. The source advances by `INC ECX`, not a UTF-16 stride;
the decompiler's `short *` variable is misleading here.

| Input bytes | Prepared prefix including appended NUL |
|---|---|
| `FF FE 41 00 42 00` | `41 42 00` |
| `FE FF 00 41 00 42` | `41 42 00` |
| `FF FE 00 01` | `01 00`; no Unicode transcoding |
| `EF BB BF 41` | `EF BB BF 41 00`; UTF-8 BOM is not recognized |

`rome2_xml_prepare_legacy_text` implements this operation in place with an
explicit writable capacity and result byte count. Capacity must exceed input
size. Bad arguments preserve both the buffer and output. Zero/one-byte inputs
are treated deterministically as not having either marker, rather than copying
the original unchecked initial word read. Unfiltered input may contain embedded
NUL bytes; its result byte count is not necessarily `strlen`.

The helper is isolated. Existing XmlLite/fauna resource APIs retain their
documented input domain and explicit errors; they have not been switched to
this legacy byte preparation or the original parser.

## Linked readiness state

The XML constructor `0x112aab60` writes a NULL source link at offset `+0`
and the little-endian word `0x0001` at `+4`. `FUN_101b9270` follows links at
`+0` until a NULL link, then returns the final object's raw byte at `+4`.
Intermediate objects' readiness bytes are not read.

| Offset | Observed field | Scope |
|---|---|---|
| `+0` | 32-bit state-source address | Followed by the readiness helper; ownership is not inferred. |
| `+4` | Raw readiness byte | Root constructor initializes it to 1. |
| `+5` | Adjacent byte | Root constructor initializes it to 0; its meaning is not recovered here. |
| `+6..+7` | Unobserved prefix bytes | No native meaning is assigned. |

`rome2_xml_state_prefix32` records this eight-byte prefix with fixed-width guest
addresses and compile-time offset checks. It is not a complete XML class.

`rome2_xml_read_root_state32` reads a borrowed guest-memory view and returns
the root address, unchanged raw flag value and number of visited objects.
It needs four mapped bytes for intermediate links and five for the final
object. Unaligned addresses and a mapped interval ending exactly at `2^32`
are supported. Guest addresses are never cast to native pointers.

The native reader adds a caller-supplied node budget, including the root.
Exhaustion, including cycles, returns `HOP_LIMIT`. Bad arguments or unmapped,
overflowing or invalid views fail explicitly. Every failure preserves the
output. This bounds an original walk that has no observed cycle check or
work limit. Inputs remain borrowed and immutable; no allocation or callback
occurs.

## Callback adapter

The callback at `0x112b5110` occupies **20 bytes including its final RET**.
Its instruction window forwards the document/path stack arguments, points
`ECX` into local stack scratch, and calls `0x112a7b60`. The constructor invokes
the callback indirectly and then removes eight argument bytes from its stack.
The window is registered as instruction evidence; it is not presented as a
Ghidra-recognized standalone function or a recovered C++ class signature.

## Filename-loader control flow

The complete `0x112a7b60` assembly and focused callee dossiers establish these
ordinary control-flow observations:

1. Path conversion/normalization through `0x10103d10` and `0x10121510` precedes
   the prefix predicate. A true predicate selects direct-file access through
   `0x101049d0`; false selects the VFS interface obtained through `0x112e3d20`.
   This is not an existence-based loose-file fallback. Normalization can depend
   on registered prefixes, whose complete rules remain open; the native
   predicate alone does not select a backend for arbitrary original paths.
2. Direct-file open failure returns at `0x112a7bf2`, before buffer allocation,
   parsing or import. For a freshly constructed destination, no children have
   been imported on that path. Combined with setup's missing-root check, this
   supports an ordinary quiet-empty outcome for that specific path. It does
   not establish how missing virtual entries behave.
3. A failed `ReadFile` call captures an error, and a short read stores `0x26`,
   but both still join buffer preparation at `0x112a7d4b`. A failed or short
   read therefore cannot be treated as proof of empty XML output. The native
   resource adapters do not reproduce parsing of incomplete/uninitialized data.
4. The VFS branch calls `0x10104b10` to initialize a temporary memory reader.
   This helper always returns `AL=1` on its ordinary return. The loader's
   subsequent false branch is real code but is not evidence of a VFS
   not-found test. Virtual-dispatch targets, lookup failures and unwinding still
   need recovery before mapping native `PACK_NOT_FOUND` to original behavior.
5. A false `0x101271a0` parser result takes a diagnostic-string path and then
   rejoins the same import preparation at `0x112a7e14`. The import loop is not
   gated on parser success. The recursive parser `0x10127640` calls the
   append helper `0x101279d0` before completing tag validation; its failure
   epilogue does not roll back those nodes. Thus failure can leave temporary
   nodes for import. Exact malformed-input outcomes and exceptions require
   further parser recovery or an original runtime oracle.

The importer `0x112ce6b0` stores its explicitly supplied second stack argument
as the new object's `+0` state-source link. Initial imports supply zero;
recursive imports forward the previous destination argument. The link is not
admitted as a direct XML-parent or ownership pointer. The prefix and native
reader deliberately call it `state_source`.

Ghidra's default signatures label several functions `__stdcall` or assign
unrelated FaceFX pointer types. The curated registry takes argument widths,
`ECX` context, callee cleanup and return width from decoded assembly and its
callers. Those ABI shapes do not recover a source C++ class or callable x64
function address.

## Evidence and verification

The target remains `empire.retail.dll`, 28,278,272 bytes, SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.

| Observation | REA Evidence ID |
|---|---|
| Linked root-state walk at `0x101b9270` | `ev_aa31274202561cd8d9d53aeef31268ad5e9a99e38600d316c4acd3408917cae3` |
| XML constructor and callback invocation at `0x112aab60` | `ev_64e526309bbaa085161f3ef849568558602f64f8ff76d86fa96e7209f2805fae` |
| Filename loader at `0x112a7b60` | `ev_eca13a1b967d37d502eb0d8663455d08b4ab433b4149ddd5d476351462df626a` |
| Prefix predicate at `0x100f3b20` | `ev_3261555d0c6647ba15668b6a35e3c3f8770db8b44383577f55644a489dedafe4` |
| Temporary reader initialization at `0x10104b10` | `ev_a3340283dfd2fdcfa09d4dfc7859380446225a762d83f9458d6b41e712cdcd6d` |
| Direct file-open helper at `0x101049d0` | `ev_ed9a47359e6ce6e1cee946f1304e5a073236b4c9b268caa97e35fa6ccdd4072c` |
| Parser entry at `0x101271a0` | `ev_d04c524676064bc11bb4a77bf15739e7bd7d59dabe654694cefa4618e615bd3f` |
| Node importer at `0x112ce6b0` | `ev_98f061488778849275f1f7fc0bb815206b04c93e8dc09bff693bf1a90369614a` |
| Path normalizer composition at `0x10121510` | `ev_8d77228d5b602ac97dd7f54aa94baa178471a148abc308ee53274488b88617e8` |
| Recursive parser at `0x10127640` | `ev_78b1a4a5fcfa2c4a2bfd2987deef75b94cba0d4bae4c1663627aec729d852f6d` |
| Parsed-node append at `0x101279d0` | `ev_dd41731ecbfcec7873446befe95aac36a4092a4c16a61c1582eec4394aaf9a9c` |
| Complete 20-byte callback window | `ev_b055a0dd49d3546c10effd2d2e63bb4f7f2b99e48d7378598b6ef070ed131c4a` |

The native policy suite performs **200,779 checks**: all 65,536 two-byte
prefixes for legacy preparation, short/empty inputs and capacity rejection,
byte preservation, prefix routing, every raw
flag value, a 256-object non-monotone chain at all address alignment residues,
every truncation of its mapped view, self/multiple-object cycles, exact node
budgets, output preservation and the end of the 32-bit address space.
All **62 local native suites** pass in optimized and ASan builds. The clean
public worktree passes **856 Python tests** on 3.14 and 3.15, with 257 expected
private-evidence skips in each run. All **28 original-image contract tests**
pass. Argon's read-only review reported no confirmed defect in the helpers.

The registry now verifies 55 function bodies and their stack returns, 57
globals, nine first vtable slots and 45 instruction windows. Twelve new
retained records are hash-pinned. The private session was closed and its
55-record Evidence bundle independently validated. Canonical exports and shared
`workspace/TW2` were unchanged; no game binaries, assets or full REA records
are published.

These are static original-image observations plus separately tested native
adaptations; the game was not executed. Existing
[resource/XML-node setup](unitcard_resource_recovery.md) APIs retain their
explicit diagnostics. No missing VFS entry or malformed XML is silently
converted to native success on the basis of this policy work.

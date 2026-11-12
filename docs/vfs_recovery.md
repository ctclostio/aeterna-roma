# VFS dispatch, filename-table and candidate-policy recovery

This document traces the XML loader into the original VFS and records native
helpers for dispatch observation, filename hashing, name-table probing and
fixed-capacity name-table assignment. They operate on bounded byte spans and
fixed-width guest views. File opening, mount creation, table growth, name
lifetime, locking and exception handling remain outside the native helpers.

## Selected interface and targets

The XML loader calls `0x112e3d20`, adjusts the returned manager address by
four bytes, loads that interface's table, and calls table slot `+4`.
The getter initializes the active manager if necessary before checking the
mode byte at `0x12031a88`. A zero mode selects the static manager at
`0x119e1004`; a nonzero mode selects the active-manager pointer.
Initial zero-filled image values do not establish runtime mode or mount state.

| Observed manager | Interface/table | Slot `+4` target |
|---|---|---|
| Static `0x119e1004` | interface `0x119e1008`, table `0x11897994` | `0x112bd0c0` |
| Active constructor's receiver | interface `receiver+4`, table `0x118978e8` | `0x112bd3b0` |

The active constructor writes tables at receiver `+0`/`+4`, initializes a
counter at `+8`, and supplies `receiver+0xc` to critical-section initialization.
The native layout admits only the eight-byte dispatch prefix. The getter,
allocator and full manager class have not been ported.

`rome2_vfs_read_open_dispatch32` reads the selected interface and slot across
separate object/table views. Only the two selected four-byte cells need mapping.
It returns a 32-bit code identity without invoking it or assigning a native
function prototype. Null entries, missing mappings and arithmetic overflow have
explicit statuses; every failure preserves output. The observed table words
do not prove complete vtable boundaries.

## Active hit and miss paths

The full assembly of `0x112bd3b0` contains two hit branches omitted from the
decompiler's pseudocode. After `0x112bd6f0`, it checks the first candidate and
then the second before constructing an empty result. Those branches must not
be removed when reconstructing the operation.

With a stable enabled mode, the ordinary path enters the manager's critical
section and increments its active-call counter. The candidate paths and miss
path decrement that counter before leaving the section. This observation
does not establish exception-unwind or concurrent mode-change behavior.

When neither candidate is present and allocation succeeds, the active open
operation creates a 12-byte wrapper with table `0x11897be0`, a copied name word
and a zero counter at `+8`. It publishes the wrapper and zero range/state
metadata, then invokes slot `+0x1c`. That slot is the six-byte routine
`0x112d0c80`: it increments counter `+8` and returns while consuming eight
otherwise-unused argument bytes. A recovered prototype that omits those stack
arguments would be wrong.

The wrapper's length slot `+0x10` and data slot `+0x2c` both reference the
shared constant-zero body at `0x100dbc00`. Thus an ordinary active miss reaches
the XML loader as a non-null empty wrapper. The disabled/static open operation
uses a separately initialized static empty-file object.

The XML loader's temporary memory-reader initializer still returns `AL=1` for
zero length. Its next copy requests zero bytes, and byte preparation leads
toward empty parser input. The original path also peeks a word from a
one-byte allocation; release entry `0x112daae0` lacks a decoded procedure in
this provider, and allocation/unwind behavior remains unresolved. These limits
prevent a claim of complete defined quiet-failure equivalence. Existing native
resource APIs retain their explicit diagnostics.

## Filename hash and table

`0x100f3040` adds signed bytes at even positions into a 16-bit low half and
odd positions into an independent 16-bit high half. Each half wraps modulo
`2^16`; processing stops at NUL. It performs no case folding or normalization.
For example, `Script/fauna_config.xml` hashes to `0x045104b2` for exactly those
bytes. `rome2_vfs_hash_name_bytes` provides the same arithmetic over a bounded
span, stopping at its first NUL or end.

`0x112c1130` operates on this wire layout:

| Object | Offset | Observed field |
|---|---|---|
| Table descriptor, 12 bytes | `+0` | Items address, 32-bit |
| | `+4` | Bucket count, 32-bit |
| | `+8` | Empty-name identity, 32-bit |
| Slot, stride 8 | `+0` | Name identity, 32-bit |
| | `+4` | Stored value, 32-bit |

It starts at unsigned `hash % bucket_count`, scans forward, and wraps once.
Query-name equality is checked before the empty-name marker. Equality compares
all 32 bits through `0x101206e0`. A hit returns the **address of slot `+4`**,
not the stored value. `0x1011fe30` copies one name word; its body does not prove
reference counting or ownership. The default table initializer uses 2,003
buckets, but the native probe accepts other valid counts.

`rome2_vfs_probe_name32` takes a precomputed hash and opaque name identity.
It returns the matched value cell, a checked observation of its stored value,
slot index and probe count. A matched NULL value remains a match; a missing key
has a separate status. The helper adds descriptor/numeric-array validation,
checks only visited keys and a matched value mapping, and bounds work by the
smaller of bucket count and caller-supplied probe budget. Budget exhaustion
before a complete scan is inconclusive, not a missing-key result. All non-OK
results preserve output.

The probe helper does not intern names or populate the table. Probe order
establishes collision handling, while assignment, archive-manifest indexing and
candidate comparison determine which entry is stored or selected.

## Name-table assignment and population policies

Generic assignment routine `0x112ddee0` takes the 12-byte table descriptor in
`ECX` and two stack pointers (`[ESP+0x24]` key address, `[ESP+0x28]` value
address) with `RET 0x8`. It starts at unsigned `hash % bucket_count`
(`0x112ddf17`), scans `[index, count)`, and wraps once across `[0, index)`.
At each slot, full 32-bit key equality via `0x101206e0` (`0x112ddf51`,
`0x112ddfb1`) precedes empty-marker equality against `descriptor+8`
(`0x112ddf6c`, `0x112ddfc9`):

- **Equal key (`0x112de0a0`)**: overwrites only `slot+4` with `*value_ptr` and
  returns the `slot+4` address in `EAX`.
- **Unequal empty slot (`0x112de073`)**: copies the 32-bit key word into
  `slot+0` via `0x1011fe30`, writes `*value_ptr` into `slot+4`, and returns
  the `slot+4` address in `EAX`.
- **Full scan (`0x112ddfea`)**: grows bucket count to `2 * count + 1`,
  allocates `count * 8` bytes via `0x10102f50`, initializes only the key words
  with the empty marker (`0x112de010`), recursively reinserts non-sentinel
  entries (`0x112de040`), frees the old buffer via `0x100fcc50`, and retries.

`rome2_vfs_assign_name32` adapts the fixed-capacity assignment loop over a
checked read-only descriptor view and a writable slot view:

- It validates descriptor mapping, nonzero `items` and `bucket_count`, and
  whole-array 32-bit extent (`buckets * 8 <= 2^32 - items`) before probing.
- Only visited keys and the selected slot's value cell must be mapped. All
  read preflight checks complete before the first byte is written; any non-OK
  result preserves all backing bytes and the caller's output struct.
- Equality has priority over the empty marker at the same slot. An equal key
  writes only `slot+4`; an unequal empty slot writes both `slot+0` and `slot+4`.
- `matched_key` reports `key == name` rather than claiming live occupancy.
  When `name == empty_name`, equality wins and updates `slot+4` while leaving
  `slot+0` equal to the empty marker; callers requiring live occupancy must
  reserve the descriptor's empty-name identity.
- A full scan without a candidate returns `ROME2_VFS_NAME_TABLE_FULL`; stopping
  earlier at `max_probes < bucket_count` returns `ROME2_VFS_NAME_PROBE_LIMIT`.
  No table growth, allocation, old-value release, or new-value retain is
  performed.

Three distinct population behaviors exist in the original binary and must not
be conflated:

1. **Generic table assignment (`0x112ddee0`)**: unconditionally overwrites
   `slot+4` on key match and returns `slot+4`.
2. **Loose-file cache replacement (`0x112b8830`)**: probes the global loose-file
   table (`0x112bbd10` -> `0x120329b4`) via `0x112c1130`. If the existing slot
   holds a nonzero pointer, it invokes vtable slot `+0` with argument `1`
   (`0x112b8848`) before allocating a `0x20`-byte entry (vtable `0x11897710`).
   If allocation returns `NULL`, it zeroes the new pointer (`0x112b8861`,
   `0x112b88b6`) and still assigns through `0x112ddee0`.
3. **Archive-local duplicate suppression (`0x112a9560`)**: initializes an
   archive-local table at `receiver+4` with 8 buckets (`0x112a957c`). While
   reading manifest records, equal-key hits in either probe segment (`0x112a98a5`,
   `0x112a98f1`) reach `0x112a9913` (`ADD ECX, 4; JNZ 0x112a9ae2`), testing the
   non-null value-cell address rather than dereferencing its stored value. A
   hit skips pooled entry allocation (vtable `0x118976c0`) and `0x112ddee0`
   insertion (`0x112a99b2`), retaining the **first equal key within a single
   archive**.

## Archive-name tree and candidate comparison

Cross-archive lookup does not use a single flat hash table:

- `0x112c01f0` initializes and returns the global archive-name tree header at
  `0x12032a34` (`0x112c020c`), distinct from the loose-file hash table at
  `0x120329b4` (`0x112bbd10`) and the archive-entry vector at `0x12032a7c`.
- `0x112ce0c0` searches `0x12032a34` via `0x112c0250`, selects an archive
  candidate from the matched node, and probes that archive's local table at
  `archive+4` via `0x112c1130` (`0x112ce0f2`).
- Archive registration `0x112cfc10` recurses on dependency names (`0x112cfde8`)
  and installs candidate comparator `0x112e1500` via `0x112a7690` (`0x112d03ee`).
- Comparator `0x112e1500` tests relationship predicate `0x112d59f0(b+0x14, a+0x14)`
  first (`0x112e1513`, returning `AL=1` when true), then `0x112d59f0(a+0x14, b+0x14)`
  second (`0x112e1530`, returning `AL=0` when true). When both are false, it
  compares low nibbles `((*a)[0x1c] & 0xf) > ((*b)[0x1c] & 0xf)` (`0x112e1553`,
  `CMP CL, AL; SETA AL`).
- Predicate `0x112d59f0` (`ECX` receiver, `RET 0x8`) returns `AL=0` (`0x112d5a50`)
  when the two name words are equal or either tree lookup misses (`0x112d5a21`,
  `0x112d5a36`), and otherwise delegates to `0x112b5090`.

Graph relation orientation, transitivity, cycle handling, tie behavior, mount
order and complete mod/dependency precedence remain open and are not claimed by
the native table helpers.

## Evidence and checks

Target: `empire.retail.dll`, 28,278,272 bytes, SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.

| Observation | REA Evidence ID |
|---|---|
| Manager getter (`0x112e3d20`) | `ev_4d0e00db30ddc08a5a13b20a0d0fc035caf0872c9f2bcd6877815632c67930eb` |
| Manager constructor (`0x112a8ff0`) | `ev_6c40ca90fe707265a35b6480edc7c8841d27b514404cac9945b1b268c157a7dc` |
| Active open, including hit branches (`0x112bd3b0`) | `ev_51f0ccc9883c4bf5b5380f385aa21392604ccc645ad1971966094701daaaf37e` |
| Candidate lookup (`0x112bd6f0`) | `ev_83d0b52360a70d3967dc94ba52451c8a22a5e430e20d97b5ca3b8873b828e171` |
| Name-table probe (`0x112c1130`) | `ev_46568ec6ecd324258cbb2d93ed839de0abc54f24decbd44d86a13f5d92d47cd4` |
| Signed-byte hash (`0x100f3040`) | `ev_e4ef52a235eebce63bbe514cc075de91b8d27dc9cb159bc2723aad513c358a3f` |
| Constant-zero method body (`0x100dbc00`) | `ev_b64e0ec622feb710c3ce1b7ba220e46aeba3858e7e38b452e7161a58e3b0b433` |
| Generic name-table assignment (`0x112ddee0`) | `ev_fc90da58242a60ebfdb5e2fa7d5ae21fb245d4afea335dfab2beeaedffc949fa` |
| Loose-file cache replacement (`0x112b8830`) | `ev_9a424b1e81cb60c6d63f498df934a1f51f9b743f7fb7c9d7c12ff3e0443d0384` |
| Archive-local index construction (`0x112a9560`) | `ev_56c2b42df7f1403fcced8983ee13f77d0b406a05a5d06e1bb24a5bcf4f841c0c` |
| Archive/loose candidate resolver (`0x112ce0c0`) | `ev_3d0b3efb24d97b171c7c41937beda85442aaabc9b08628cf55821e8c8f6c6efc` |
| Archive-name tree getter (`0x112c01f0`) | `ev_1e177296ddb686297577c33c9f8dd17ba5db33e3fcb4d95c5676534da2a8d42d` |
| Archive-name tree search (`0x112c0250`) | `ev_6d43de59e9579357a63ee90a6c1924faf96f6521a82717260b123b47f4c41ea3` |
| Archive registration & comparator setup (`0x112cfc10`) | `ev_fcd3057b7759aa6242448c9dc812e4e863017604cda5e5e2ed21b8b5a6026c34` |
| Archive-candidate comparator (`0x112e1500`) | `ev_33395abb4c1e84da327073bed4a7a78ac27c75a560061386e0527fe3394c13fe` |
| Archive relationship predicate (`0x112d59f0`) | `ev_b9b2dff7841abfef758940617640957886af8fca4b5240625fac37cdedb31d61` |

The constructor and table initializer have disjoint database-reported bodies:
943 code bytes within a 952-byte span, and 180 within a 183-byte span. The
validator supports explicit inclusive body ranges, hashes their code bytes
in order, and requires return instructions to lie wholly inside a body range.
The nine- and three-byte gaps remain outside the admitted code. Legacy
contiguous contracts retain their behavior.

Verification: **65 local native suites** pass in optimized (`/W4 /WX /analyze`)
and ASan profiles. The dispatch suite runs **2,459 checks**, the name-probe
suite **134,705 checks**, and the name-assignment suite **346,378 checks**
(including an exhaustive minimum-circular-distance oracle across all 3-key
states of 1-to-5-slot tables, all start indices, probe budgets, sentinel and
zero queries, alignment residues 0–7, truncations, partial slot mappings,
full-table replacement and 32-bit endpoints). The focused contract module
passes **41 tests**. Clean public Python runs pass **869 tests** on 3.14 and
3.15, with 269 expected private-evidence skips each.

The registry verifies **90 function bodies, 71 globals, 14 first vtable slots
and 110 instruction windows**. The resumed private REA session reused the
28-record Layer 7 snapshot, added 14 new records (9 function dossiers and 5
data reads), validated the 42-record bundle, and closed the session cleanly.
Argon High's read-only code and original-assembly reviews found no confirmed
defect.

## Layer 9 — archive-name tree search, narrow string8 comparator chain, winning-archive resolution, and dependency-graph reachability

### Original-image evidence (`out/vfs-layer9-20261112/`)

Layer 9 reuses the closed 42-record Layer 8 REA snapshot and adds 12 new
shipped-artifact records (`54` total validated records in
`out/vfs-layer9-20261112/validated-evidence-bundle.json`):

1. **Name-entry less-than comparator chain (`0x101206f0 -> 0x100f2fe0 -> 0x100f7040`)**:
   - `0x101206f0` (`ev_b86b5e36108b208f0c86bdbe8a98a00df14bf7a88062a5178c6244f66171739a`,
     `__thiscall`, `ECX` left name-cell address, `[ESP+4]` right name identity,
     `RET 0x4` at `0x101206f8`, `0x10120705`, `0x10120712`): loads `ECX = [ECX]`;
     if `ECX == 0`, returns `AL = 1` immediately (`0x101206f6`) even when
     `[ESP+4] == 0`. Otherwise loads `EAX = [ESP+4]`; if `EAX == 0`, returns
     `AL = 0` (`0x10120703`). When both identities are nonzero, calls
     `0x100f2fe0(ECX, EAX)`.
   - `0x100f2fe0` (`ev_c652589f2c76214017fd3649e08a8eb98468899f181f293c28d7bf08338f60be`,
     `cdecl`, 8 stack bytes, `RET` at `0x100f2ff0`): forwards both narrow
     string descriptor addresses to `0x100f7040` and shifts bit 31 into `AL`
     (`SHR EAX, 0x1f` at `0x100f2fed`).
   - `0x100f7040` (`ev_fa78e06ba01a3fc4fb9c8446c50fb33a7ff18dc1c6a0fb24570bb2cb04e32f02`,
     `__thiscall`, `ECX` left descriptor, `[ESP+4]` right descriptor, `RET 0x4`
     at `0x100f707f`, `0x100f70b1`, `0x100f70d4`, `0x100f70e1`): reads only `+0`
     (`length`) and `+8` (`data`) of each `rome2_string8_layout32` (`+4`
     capacity is untouched), compares `min(len_lhs, len_rhs)` bytes, and at the
     first differing byte computes a signed difference (`MOVSX` at
     `0x100f7070`, `0x100f70a0`, `0x100f70d7`). When the shared prefix matches,
     returns `-1` (`len_lhs < len_rhs`), `+1` (`len_lhs > len_rhs`), or `0`
     (`len_lhs == len_rhs`). Zero-length prefixes do not dereference `data`.
2. **Archive-name red-black tree and candidate-set sentinel initializers (`0x112a7550`, `0x112a7690`) and tree search (`0x112c0250`)**:
   - `0x112a7550` (`ev_409142c5c63fb96cfdbcf6b5f5c63eb8e529d7f55427587e1b99a26bdbe13ff2`,
     `__thiscall`, `ECX` 8-byte tree header, `RET` at `0x112a75ab`): zeroes
     `+0` and `+4`, allocates a 24-byte sentinel head via `0x101060c0`,
     self-links `+0/+4/+8`, writes `0x0101` at `+0x0c` (`color = 1`, `is_nil = 1`
     at `+0x0d`), and stores the sentinel head at `header+0`.
   - `0x112a7690` (`ev_0037c46d40dd10fb2e5c5701164c6b75e969b27be4f524a77ca5db1b9a241715`,
     `__thiscall`, `ECX` 12-byte candidate-set header, `[ESP+4]` comparator
     pointer, `RET 0x4` at `0x112a76f5`): copies `*comparator_ptr` to `set+0`,
     zeroes `set+4` and `set+8`, allocates a 20-byte sentinel head via
     `0x10106000`, self-links `+0/+4/+8`, writes `0x0101` at `+0x0c`, and stores
     the sentinel head at `set+4`.
   - `0x112c0250` (`ev_9ee17fa70254b62aa68e29487792b2bc5067beee9f432b44456ab17e76c90051`):
     loads `head = [ECX]`, `candidate = head`, `node = [head + 4]`, and loops
     while `byte [node + 0x0d] == 0`, stepping right (`[node + 8]`) when
     `0x101206f0(node + 0x10, *query_ptr)` is nonzero and otherwise setting
     `candidate = node` and stepping left (`[node + 0]`). After reaching a nil
     node, requires `candidate != head` and `0x101206f0(query_ptr, [candidate + 0x10]) == 0`.
     Because `0x101206f0` returns `1` whenever `*ECX == 0`, `*query_ptr == 0`
     never matches any tree node.
3. **Static archive dependency-graph singleton and transitive walk (`0x112d4fa0`, `0x112a77b0`, `0x112afff0`, `0x112b5090`)**:
   - `0x112d4fa0` (`ev_64053e6da557d0ef414bcdf45dbcaab0df623e720a7b7938ab39321b5526e5ab`):
     TLS-guarded initializer for `0x12032a40` (`data-12032a40.json`,
     `ev_6006e5e5bc9e5a0cad55b1a9682223c1301269e5209b4e4564abce6791311c30`) and
     its embedded hash map at `0x12032a58` (`data-12032a58.json`,
     `ev_8b62b947a06d64c8d13348aa2b45dca89fcdeba8343af5fc1ba85cad64ba8df3`),
     alongside VFS archive-tree carrier `0x12032950` (`data-12032950.json`,
     `ev_dbad385843b9414480f1f8d571f5673c6f2887418b41f1455e9dcc2fff542720`).
   - `0x112a77b0` (`ev_d4da763e91620b284792ec898207df25daedbb9d57d0b6de177e04d9e895f562`):
     initializes the 32-byte string hash map with a 36-byte list sentinel at
     `+4`, 8 `(first, last)` bucket pairs at `+0x0c`, mask `7` at `+0x18`,
     threshold `8` at `+0x1c`, and float `1.0f` (`0x3f800000`) at `+0`.
   - `0x112afff0` (`ev_6317dc58ab050ab8a3b434b4aa97d42307ac69c47f9a3d0f9431d198a38d0fa6`):
     hashes query string data via `0x10101a40` + `0x100f3040`, masks with
     `[ECX + 0x18]`, and walks the bucket chain comparing `node + 8` via
     `0x100f28a0`.
   - `0x112b5090` (`ev_017d17ce35975c7ab7c06101ab2337d356133eb32bd6df25884a76aa19529fd8`):
     walks the in-order dependency tree rooted at `[node + 0x1c]`, returning
     `AL = 1` on direct string equality (`0x100f28a0(cur + 0x10, target)`) or
     recursive reachability (`0x112afff0` + `0x112b5090`).

### Native layout and bounded helper verification

`port/recovered_types/guest32_layouts.h` adds fixed-width guest layouts
`rome2_vfs_tree_header_layout32` (`8` bytes), `rome2_vfs_tree_node_prefix32`
(`24` bytes), `rome2_vfs_candidate_set_layout32` (`12` bytes), and
`rome2_vfs_candidate_node_prefix32` (`20` bytes).
`port/recovered_types/vfs_archive_tree.h` and `vfs_archive_tree.c` implement
`rome2_vfs_compare_name_less32` and `rome2_vfs_search_archive_tree32`,
bounding tree steps by `max_steps` and string prefix comparisons by
`max_name_bytes`, and optionally resolving the winning archive's local name
table descriptor (`[winner + 0x10] + 4`) for composition with
`rome2_vfs_probe_name32`.

Both `/W4 /WX /analyze` and ASan native profiles pass **66 test suites**, with
`rome2_vfs_archive_tree_tests` executing **134,286 checks** across exhaustive
256x256 signed-byte comparisons, zero-identity asymmetry, 0-to-7-node BSTs
across alignment residues 0–7, duplicate lower-bound selection, cycle/step
limits, and end-to-end winning-archive table probing. All **44 focused contract
tests** pass in `scripts/test_type_recovery_contracts.py`.

These results combine static original-image evidence with separately tested
native adaptations. The game was not executed. Shared Ghidra state, canonical
exports and frozen admission locks were unchanged. Game binaries, assets and
## Layer 10: Dependency-Graph Traversal, Candidate Comparator & Registration Callees

Layer 10 promotes the static dependency-graph observations from Layer 9 into checked C17 implementations and extends REA static recovery across `0x112cfc10`'s registration, table-lookup, and RB-tree insertion callees.

- New REA dossier evidence (closing snapshot `out/vfs-layer10-20261112/session.rea.json`, 70 total validated records: 54 reused Layer 9 + 13 new primary records + 3 `inspect_analysis_view` projections for `0x10101a40`):
  - `0x10101a40` (`ev_92e95663ffcfed02c3de66bce4c48650ad0878878dd2946d50c6aaf51bb57c26`, 4 bytes): unchecked `[ECX + 8]` C-string data accessor (`MOV EAX, [ECX + 8]; RET`). Exceeded default direct MCP budget (`resource_constraint`) and was recovered through `inspect_analysis_view` and the validated evidence bundle.
  - `0x112ac2d0` (`ev_d886b60b9a9acf9283e9015b56674f0ae9752649fd67c1865d3df963ccd1323f`, 83 bytes): `_Tree_unchecked_const_iterator::operator++` over RB-tree nodes using `is_nil` at `+0x0d`; descends right subtree's leftmost child when non-nil, else climbs parents (`+0x04`) while non-nil and equal to `parent->right` (`+0x08`).
  - `0x112a4c00` (`ev_5c40521d8cc010eb33d429a4d376d187aafea12d87060663d3fd14abf8439406`, 119 bytes, `cdecl`, 16 stack bytes): linear RB-tree scan over `[first, last)` comparing node `+0x10` `string8` via `0x100f28a0`.
  - `0x112bb620` (`ev_b69d6b0d80533e14c2d52d8087da07db2887a1a582b92549227a49938d613d54`, 365 bytes): recursive dependency closure collector over graph `+0x08` RB-tree building an output 28-byte-sentinel RB-tree via `0x112a4230`/`0x112a3c90`.
  - `0x112a4320` (`ev_9b22125fccc9184239bf334455c84a47d2bfd2d47d3c70401d67e951f158d724`, 323 bytes) & `0x112a30b0` (`ev_bafb8b6e62bb1162abcb510a0fd8e55288e5c8e5ba3188844ba882a415e839f8`, 617 bytes): unique-key RB-tree find-or-insert (`0x101206f0` + `0x112a37b0`) and 20-byte candidate-set node allocation + red-black fixup.
  - `0x112d4cc0` (`ev_84e72b10cacc48b42a1d015f57e536e58f03dd71bc565fdea35b6036e6e3bdd0`, 274 non-contiguous bytes) & `0x112d4de0` (`ev_b04046b9f9970f5b28941c7244915474b3f1943f4c2461e3069cdea054a6db11`, 278 non-contiguous bytes): guarded static initializers for `0x12032a1c` (71-bucket 8-byte VFS archive hash table) and `0x120329e0` (71-bucket 20-byte open-pack hash table with `0x12032a8c` empty sentinel).
  - `0x112c13f0` (`ev_a513e1632234915a3a0d5f4c746d7e2b66f485d1c32e80d4c8cb9d6c7c3434eb`, 183 bytes): linear probing hash lookup in `0x120329e0` (`hash % [ECX+4]`), returning `slot + 0x0c` on match.
  - `0x112dd6b0` (`ev_326584ba7fc290fa27fe593e0079408239a2cf6ce7553ca99b75897f2bfa2838`, 560 bytes): normalized hash-table `emplace` with `2*count + 1` growth on 8-byte name tables (`0x12032a1c`).
  - Data reads: `0x12032944` (`ev_9adca7b9f466d009acb9789d963f8242014d35a093ab4548a53badf1e32c3e10`, 8 bytes zero-fill), `0x12032960` (`ev_aa8e0ac600d85125077f9557d06b2dce3c3498c3cfcb19b39d341a659c2b4c7c`, 12 bytes zero-fill), and `0x1173dfac` (`ev_0573040a0a8632af60b29250cec4553d9ea50d2b777c638cdb595f45b3e19e57`, `"\\"` + `"1.21"`).
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_dependency_graph.h/.c`, `test_vfs_dependency_graph.c`):
  - Fixed-width 32-bit layouts: `rome2_vfs_dep_bucket_pair32` (8 bytes), `rome2_vfs_dep_hashmap_layout32` (32 bytes), `rome2_vfs_dep_graph_node_prefix32` (36 bytes), `rome2_vfs_dep_edge_node_prefix32` (28 bytes), and `rome2_vfs_archive_candidate_prefix32` (32 bytes).
  - Bounded helpers: `rome2_vfs_string8_equals32` (`0x100f28a0`), `rome2_vfs_dep_hashmap_find32` (`0x112afff0`), `rome2_vfs_dep_edge_next32` (`0x112ac2d0`), `rome2_vfs_dep_reachable32` (`0x112d59f0` -> `0x112b5090`), and `rome2_vfs_compare_archive_candidates32` (`0x112e1500`: `b` depends on `a` -> `true`; `a` depends on `b` -> `false`; else `((*(*a))[0x1c] & 0xf) > ((*(*b))[0x1c] & 0xf)` read lazily). Unlike original `0x112b5090`, cycles and oversized chains fail closed with `ROME2_VFS_DEP_STEP_LIMIT`.

full retained evidence remain outside Git. See [progress.md](../progress.md).

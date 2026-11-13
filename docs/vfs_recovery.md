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

## Layer 11: Archive Registration (`0x112cfc10`) Preconditions, Candidate Insertion Policy & Remaining Callees

Layer 11 completes REA static recovery for the remaining callees of `0x112cfc10`, `0x112bb620`, and `0x112a4320`, locks the exact precondition and candidate-set insertion policy of `0x112cfc10`, and validates bounded C17 helpers in `port/recovered_types/vfs_archive_register.h/.c`.

- New REA dossier evidence (closing snapshot `out/vfs-layer11-20261112/session.rea.json`, **91** total validated records in `out/vfs-layer11-20261112/validated-evidence-bundle.json`: `70` reused Layer 10 + `15` new primary records + `6` `inspect_analysis_view` projections):
  - `0x101028f0` (`ev_fff8271246cf9b468b4a069c7f90f4a67004790c7ee79d52e579def82726882e`, 3 bytes) & `0x10121690` (`ev_b5617fc3566aa0252729b5c36de6b88ed940b8699d5696600ac2b6d938dc1a87`, 20 bytes): `FxName::GetNameEntry` (`MOV EAX, [ECX]; RET`) and null/empty `FxName` predicate (`AL = 1` when `ECX == 0` or `*ECX == 0`). `0x101028f0` hit direct MCP `resource_constraint` and was retrieved via `inspect_analysis_view` and the validated bundle record.
  - `0x112a37b0` (`ev_ff2a029db4349d89f979f5a4a7b00345f840004502562a980046ccee15508129`, 663 bytes, `RET 0x10`), `0x112a3c90` (`ev_8aa07d119a7b31a2e193300a1664d94aad6bdf65e29b158c330d2edb8bbd2ba0`, 587 bytes, `RET 0xc`), `0x112a4230` (`ev_ede48618b9b750cd85e1d2e933eca911c926d9948b74d71e1ff28c5938deae9f`, 238 bytes, `RET 0x10`), `0x112a4470` (`ev_7dd452f2e3c9b552f963711361da86a5c485532782a56960749c8267c685b3ab`, 323 bytes, `RET 0x10`), & `0x112a27c0` (`ev_22e08cbfbeddac68452a918885d2ba72fc4de17d7f2019c4102f9f6df7b33ab4`, 67 bytes, `RET 0x8`): 28-byte RB-tree node allocator/rebalancer (with `0x9249248` max-count guard), `_Insert_hint`, unique-key inserters (ordered by `0x100f2fe0` for path/closure strings and `0x101206f0` for normalized `0x12032944` entries), and recursive post-order deleter.
  - `0x112a20b0` (`ev_7f5253774e47f4825f5c8e48dd4d66fa5045c4880f1558f71d2377ec807c3167`, 306 bytes, `cdecl`, 12 stack bytes) & `0x112a5840` (`ev_ee8146dbbb2c1702b78529bfd29b7ee1f898cac5afd7b80abec40e26c276188c`, 106 bytes, `cdecl`, 4 stack bytes): archive-name tree value constructor (`0x1189a434` vtable + inner RB-tree via `0x112a24f0`) and global keyed lookup dispatcher (`0x112e32b0` -> `0x100d79c0` -> `0x11346530`).
  - `0x112c0b20` (`ev_ab1edf10318d1338fae386b1dc3d882c365f44318c4080e29af1b1082217a3b2`, 138 bytes, `RET 0x4`) & `0x112c0bb0` (`ev_3efcb02a31c1d18e0afef2f6e8a223c06bf410faf7877cf7ca7cc91bad8183d8`, 135 bytes, `RET 0x4`): open-pack (20-byte slot) and name-table (8-byte slot) slice iterators.
  - `0x112c9ad0` (`ev_c231ee5538a9b49556e3ef7ccdbeab07cf8b3e269793698b10ead8659fdec851`, 6,655 bytes, containing internal anchor `0x112ca9d0`, `RET` at `0x112cb415`): retrieved via `inspect_analysis_view` and the validated bundle record.
  - Initial zero-fill data reads: `0x120329e0` (`ev_1449849b68391923d4e96520a0db0c0735623fe24511432252a97b89a4933368`, 24 bytes: open-pack 20-byte-slot hash-table descriptor), `0x12032a1c` (`ev_b5d697865199884d355ee2d142a66d8091c066b53bd4ff50fa6b32c765dbfa2c`, 24 bytes: registered-archive 8-byte-slot hash-table descriptor), and `0x12032a8c` (`ev_bc2cfa3c9e1031a56877a4c61a241e6109629da7ed23b676c5e6862c98225886`, 12 bytes: `string8` empty-key sentinel for `0x120329e0`).
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_archive_register.h/.c`, `test_vfs_archive_register.c`):
  - Fixed-width 32-bit layouts: `rome2_vfs_open_pack_slot_layout32` (`0x14` bytes: `string8 name` at `+0x00`, 8-byte payload starting at `+0x0c`) and `rome2_vfs_open_pack_table_layout32` (`0x14` bytes: `items`, `bucket_count`, `empty_key`).
  - Bounded helpers: `rome2_vfs_open_pack_find32` (`0x112c13f0` single-wrap linear probe stopping on match-before-empty), `rome2_vfs_blacklist_contains32` (`0x112a4c00` over `0x12032a40+0x10` RB-tree head), `rome2_vfs_check_registration_preconditions32` (exact `0x112cfc10` gate precedence `1` already registered in `0x12032a1c` -> `2` blacklisted -> `3` pack not open in `0x120329e0` -> `0` eligible), and `rome2_vfs_probe_candidate_insert32` (`0x112cfc10` + `0x112a30b0` + `0x112e1500` unique-key lower-bound/predecessor tie probe, `param_2 != 0` new-candidate rejection code `8`, and leftmost `head->left` winner displacement detection).
  - Verified **119 checks** in `test_vfs_archive_register.c`, **68/68** native suites on `/W4 /WX /analyze` and ASan, **46** contract tests against **112 functions, 77 globals, 14 vtables, and 143 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

## Layer 12: Archive Carrier (`0x112a9560`), Path Normalization & Recursive Dependency Collection (`0x112cfc10`)

Layer 12 recovers the next batch of callees inside `0x112cfc10` (`0x112a9560` archive carrier constructor, path reverse-find/truncate/assign normalization, `0x1011fdd0`/`0x1011fe40`, `0x10cb8f10`, and the remaining RB-tree node cloners/linkers), locks the internal structure of `rome2_vfs_archive_candidate_prefix32` (`0x20` bytes), and promotes those rules into bounded C17 helpers in `port/recovered_types/vfs_archive_mount_step.h/.c`.

- New REA dossier evidence (closing snapshot `out/vfs-layer12-20261112/session.rea.json`, **105** total validated records in `out/vfs-layer12-20261112/validated-evidence-bundle.json`: `91` reused Layer 11 + `14` new records across 12 functions and 4 data reads):
  - `0x112a9560` (`ev_6b656cea85fe5e436214b4b411345022a2792cfc0e4092d1acbcb1fadffa74f5`, 1,622 bytes, `RET 0x4`): fills the `0x20`-byte carrier with `pack_props` (`+0x00`), an 8-bucket 8-byte-slot VFS name table (`+0x04..+0x0f`, empty sentinel from `0x112e3690`), the leaf pack name after the final `'\\'` (`+0x14`), populates entries and the global pending-entry vector (`0x12032a7c`), and sets `*(pack_props + 0x40)` when `(*pack_props + 0x1c & 0xf) != 4`.
  - `0x101141f0` (`ev_6f6d06fe22b4eabaed4e4fb6d5d74c494970b496cf0bf3859f730519656e9695`, 151 bytes, `RET 0x8`), `0x10113c10` (`ev_bb70d0e29541ce01a889b202958481c76f65311cab647c271d793c219ff41a3e`, 170 bytes, `RET 0x4`), `0x100f2610` (`ev_93f42a5b1dcfa2ded496fb5cf1149bb0e2aa5c59c5136790f854b20a6b46d1b8`, 150 bytes, `RET 0x4`), `0x1011fdd0` (`ev_3e2abb4915a0a61ae13de1bb67c1bcb644706d65587f11da7c338efe397f5657`, 95 bytes, `RET 0x4`), & `0x1011fe40` (`ev_bdd50f6b7558a267dccc61c80b9d0c413331cc10e6a2954a69337b26d81fa54e`, 89 bytes, `RET 0x4`): `string8` reverse-find (`rfind`), resize/truncate, copy-assign, and `FxName` constructors (`0x10101a40`/`0x100f1800` -> `0x10120b30`). In `0x112cfc10`, `0x101141f0` searches each entry path for `'\\'` (`0x1173dfac`), truncating via `0x10113c10` when found or falling back to global sentinel `0x12032960` (`0x100f2610`) when absent.
  - `0x101206e0` (`ev_cce28526e8656a768ad1a3cd66adfe399a25fe88beaa51d0297b369abf690956`, 12 bytes, `RET 0x4`) & `0x10cb8f10` (`ev_be95c908fdb9873f483534a8bd2c6ddb7c582e9cb3ccf186e8d86fa5ba31cdc4`, 117 bytes, `cdecl`, 0 stack bytes): 32-bit `FxName` equality (`[ECX] == [ESP+4]`) and `L"vfs_log_level"` (`0x117df544`) setting query (`>= 1` via `0x112c02e0` -> `0x11346530`).
  - `0x112a24f0` (`ev_1b2e249e6a3b4cd2b0c2f0c13ef446898a41d53d4b264b1bb05214da3ae3acc4`, 179 bytes, `RET 0xc`), `0x112a2e80` (`ev_a68a6544c9e6f85c041324728ea35854a0d3fcef4fabe971cb19ce5c71144209`, 545 bytes, `RET 0x10`), `0x112a3570` (`ev_9f5fdeb60cff830f2a8708d94db144e60ca8af1d863187d0417c0867b0b253a8`, 572 bytes, `RET 0x10`), & `0x112a3a50` (`ev_293e3e54a585498cf26d89c4a146c00b03fca4ac093b4930dd86706da218e0bc`, 572 bytes, `RET 0x10`): 20-byte inner RB-tree cloner (`[node+0xd] == 0`), caller-supplied 28-byte RB-tree linker (`0x9249248` max guard), and 28-byte / 20-byte (`0xccccccb` max guard) RB-tree node allocators.
  - Data reads: `0x117df544` (`ev_3167b217d8918fe25b6eae61394458b48be541bed4f4cc7b5357e09a8cdb8d85`, UTF-16LE `L"vfs_log_level"`, 28 bytes pinned in `contracts.json`), plus verification reads for already-pinned `0x12032a34`, `0x12032a7c`, and `0x12032960`.
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_archive_mount_step.h/.c`, `test_vfs_archive_mount_step.c`):
  - Refined `rome2_vfs_archive_candidate_prefix32` (`+0x00 pack_props`, `+0x04 name_table` `rome2_vfs_name_table_layout32`, `+0x10 unobserved_010`, `+0x14 archive_name`) and added `rome2_vfs_pending_entry_vec_layout32` (`0x12032a7c..0x12032a84`, `{capacity, count, items}`).
  - Bounded helpers: `rome2_vfs_archive_leaf_name` (`0x112a9560` leaf substring after `'\\'`), `rome2_vfs_entry_dir_prefix` (`0x112cfc10` parent-directory prefix truncation vs `0x12032960` root fallback), `rome2_vfs_carrier_pack_props_gate32` (`(*pack_props + 0x1c) & 0xf` checks `== 3` and `== 4`), `rome2_vfs_carrier_next_nonempty_slot32` (`0x112c0bb0` + `0x101206e0` cursor over carrier `+0x04` 8-byte slots), `rome2_vfs_collect_pending_deps32` (two-pass non-mutating scan over `0x120329e0` collecting transitive dependency packs via `rome2_vfs_dep_reachable32`), and `rome2_vfs_dep_status_acceptable` (`0`/`1` tolerance gate at `0x112cfe00`).
  - Verified **63 checks** in `test_vfs_archive_mount_step.c`, **69/69** native suites on `/W4 /WX /analyze` and ASan, **47** contract tests against **122 functions, 78 globals, 14 vtables, and 157 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

## Layer 13: Pack Entry Vtable (`0x118976c0`), Winner Notification (`+0x34`) & `0x112a9560` Stream/Pool Callees

Layer 13 resolves the runtime virtual table (`0x118976c0`) assigned to each `0x28`-byte pack entry inside `0x112a9560`, inspects its key non-procedure virtual slot handlers (`+0x04` and `+0x34`), recovers the remaining CRT/string/stream/pool callees of `0x112a9560` and `0x112cfc10`, locks `rome2_vfs_pack_props_prefix32` (`0x44` bytes) and `rome2_vfs_pack_entry_layout32` (`0x28` bytes), and validates bounded C17 helpers in `port/recovered_types/vfs_pack_entry.h/.c`.

- New REA dossier evidence (closing snapshot `out/vfs-layer13-20261112/session.rea.json`, **131** total validated records in `out/vfs-layer13-20261112/validated-evidence-bundle.json`: `105` reused Layer 12 + `26` new records across `11` functions, `2` vtables, and `2` non-procedure virtual slot handlers):
  - `0x118976c0` (`ev_605746424cbdf3cf12c647a07acaa412f68f74e5891e10e8441eb6e8446475bc`, 64 bytes / 16 slots): pack-entry vtable assigned at `0x112a9963`. Non-procedure slot handlers confirmed via negative `resolve_containing_procedure` checks + raw image reads:
    - Slot `+0x34` (`0x112d2900`, `ev_b9d718bf802820cd190e24c22b42e0965494050f1b65d646de431130ed3764b6` / `ev_5584dcd906989db2cca4948b56c4af54c091aa1375bfa1cf43684779cfc83d0a`, 5 bytes `c6 41 24 01 c3`): `mov byte ptr [ecx+0x24], 1; ret` (marks the winning pack entry in `0x112cfc10` at `0x112d01a9` and `0x112d0228`).
    - Slot `+0x04` (`0x112d3270`, `ev_2ac393f47883cd021819551e9154c5b950257899d2318ddd35cebf3e40181e2c` / `ev_ead0f5420780a207244d157ec48aa83929761fef3f87ce1c11c02be764d86d44`, 20 bytes `8d 41 04 8b 4c 24 04 50 e8 b3 cb e4 fe 8b 44 24 04 c2 04 00`): forwards `&this->name_id` (`+0x04`) to `FxName` copy helper `0x1011fe30` and returns `[esp+4]` (`RET 0x4`).
  - `0x1189a434` (`ev_5c6612186f14a16e8a7f96d394dabff4a162678c205219e5d9ac8fd740b17fa0`, 32 bytes / 8 slots, slot 0 = `0x112afd00`): archive-name tree entry vtable pinned in `contracts.json`.
  - Pool & observer singletons: `0x10106120` (`ev_02f25daecbb963cd94567cb8e55aa5bd4235d3b498e89c034e6d94dd6c672312`, 81 bytes, TLS getter for 12-byte pool header `0x11934518` `{freelist_head, slab_list, initial_slab_count=0x1060}`), `0x103282b0` (`ev_d3348bb2df228e465b23de991a16178b716d7e011d52fa02e0e3d8ddb015af12`, 86 bytes, `RET 0x8`, allocates `count * 0x28` slab and links stride-`0x28` freelist), and `0x112e1560` (`ev_27a762dd633fe308b9c7f0d145f141cd1f5b7e0d768a3f71eecf17d2517e3d65`, 81 bytes, TLS getter for `0x12032a7c` pending archive-entry observer vector).
  - File/stream prefix & string/CRT helpers: `0x10115530` (`ev_c0503379ea6d3fd79fc1ec8a750cefece4fd2da68cd5d8e4bc0ab25f3af385f7`, 12 bytes, tests `[ECX+4]` error flag), `0x101146c0` (`ev_ef459b4f70055e00feb2a81c19301d9634eb42521e2d22f4447101f3afc8eb0c`, 64 bytes, `RET 0x4`, `SetFilePointer` `FILE_END`/`FILE_BEGIN` updating `[ECX+4]`), `0x101157c0` (`ev_33980655ceb44a8071e86b8b1ef68dc99257d49ee1ead53369dac579d5caa364`, 49 bytes, `SetFilePointer` `FILE_CURRENT`), `0x101048f0` (`ev_96f6fe60580e84889fee9fa4845f0fa4e8c7052d619b6f729f5c97c2ce3ad648`, 216 bytes, `RET 0x8`, close + `CreateFileA` `[0x1172f19c]`), `0x101155a0` (`ev_b5c29366fa8f20119bfd235af39e8eb8c7b23cf554854bba892fb2d0f8ad1b75`, 146 bytes, `RET 0xc`, `string8::substr`), and `0x100d12b0` (`ev_c86bc88dc0359c3b91e17468761629ce222d72b87fc1d1db488b8163706f566c`, 15 bytes), `0x100f16b0` (`ev_bc7c9f05b1259ca22901ce3e0b73ed5e3a77cb791878c558710c7e6abce6aa3c`, 67 bytes, `RET 0x4`), `0x100f1bb0` (`ev_8a7916745ff80bfb12da9ee25d7421244ece233ca3b1bb1660a2f2bea9aabaca`, 53 bytes, `RET 0x4`) recovered via `inspect_analysis_view` and the validated bundle record due to MCP `resource_constraint`.
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_pack_entry.h/.c`, `test_vfs_pack_entry.c`):
  - Fixed-width 32-bit layouts: `rome2_vfs_pack_props_prefix32` (`0x44` bytes: `+0x00 file_handle`, `+0x04 last_error`, `+0x1c flags`, `+0x24 header_base`, `+0x28 entry_count`, `+0x2c index_bytes`, `+0x30 default_entry_meta`, `+0x34 pack_path`, `+0x40 flag_040`) and `rome2_vfs_pack_entry_layout32` (`0x28` bytes: `+0x00 vtable = 0x118976c0`, `+0x04 name_id`, `+0x08 byte_size`, `+0x10/+0x14 data_offset`, `+0x18 entry_meta`, `+0x1c carrier`, `+0x20`, `+0x24 winner_notified`).
  - Bounded helpers: `rome2_vfs_decode_pack_index_record` (parses `byte_size`, conditional `entry_meta` when `pack_flags & 0x40`, leading `0x00` padding skip, NUL-terminated path up to `max_path_bytes`, checked 64-bit cumulative `io_data_offset`), `rome2_vfs_pack_props_read_prefix32`, `rome2_vfs_entry_read32`, and `rome2_vfs_entry_notify_winner32` (bounds- and vtable-checked model of `0x112d2900` over `rome2_vfs_guest_write_view32`); every non-OK status leaves caller outputs and mutable spans untouched.
  - Verified **61 checks** in `test_vfs_pack_entry.c`, **70/70** native suites on `/W4 /WX /analyze` and ASan, **48** contract tests against **133 functions, 79 globals, 15 vtables, and 168 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

## Layer 14: Complete `0x118976c0` Pack-Entry Virtual Dispatch Table & `0x112a9560` Remaining Non-CRT Callees

Layer 14 recovers the remaining non-CRT direct `CALL` callees inside `0x112a9560` (`0x100f3880` and `0x10102f50`) plus all remaining 13 virtual dispatch slots of pack-entry vtable `0x118976c0` (`+0x00`, `+0x08..+0x0c`, `+0x14..+0x30`, `+0x38..+0x3c`), refines field `+0x20` (`stream_state`) in `rome2_vfs_pack_entry_layout32`, and validates bounded C17 stream/slice helpers in `port/recovered_types/vfs_pack_stream.h/.c`.

- New REA dossier evidence (closing snapshot `out/vfs-layer14-20261112/session.rea.json`, **152** total validated records in `out/vfs-layer14-20261112/validated-evidence-bundle.json`: `131` reused Layer 13 + `21` new records across `9` functions/thunks and `6` non-procedure virtual slot handlers):
  - Remaining non-CRT `0x112a9560` callees: `0x100f3880` (`ev_bf24460e01439887b4b77b3e4ad958fa9f229c45cb786c886dd7abba7b9956ea`, 6-byte IAT jump thunk `JMP dword ptr [0x1172f1d8]` for `GetLastError`) and `0x10102f50` (`ev_5a2384eda9a929b6ba7839e035be8092e2b46af8b86acf5528f21b8bbcc571e6`, 61 bytes, `cdecl`, 8 stack bytes: aligned heap buffer wrapper adding `4 + max(4, align)` overhead and storing raw pointer at `[aligned - 4]`).
  - Complete procedure & non-procedure dispatch map for the remaining 13 slots of `0x118976c0`:
    - `+0x00` (`0x112ad1b0`, `ev_04eb5a19a405cf2ec4c9286b4446ab81efc6709186de40e556542abe3f7790d3` / `ev_e3cbc3a5ae8206644191c83595a9c53c9220602e778bb4ef85a75d237418f578`, non-proc 33B): scalar deleting destructor (`0x11849278`, sized free `0x28`).
    - `+0x08` (`0x112e0d80`, `ev_e5dd1be8dadec4fe2adbd5aba413fc8211a84cd34d01cf42479527ffc60d2bb5` / `ev_0435fe021a113bafff6bd8dce92a45c4b5fe63d61d15c9f2e05c9ed929ce0413`, non-proc 23B): copies `carrier->archive_name` (`[ECX+0x1c]+0x14`) via `0x1011fdd0` (`RET 0x4`).
    - `+0x0c` (`0x10171400`, `ev_431c1f4e8b00582ccf4b31eca507c6957478e72a1ea74c26d8e9abbb789b8e73`, 4B) & `+0x28` (`0x10269610`, `ev_7897eff3b2a3f6a92cf386d30096812f99ddec1aa9c59a4383e8184e43ed1cb5`, 4B): accessor slots returning `entry_meta` (`[ECX+0x18]`) and `stream_state` (`[ECX+0x20]`).
    - `+0x14` (`0x112c8be0`, `ev_bf5a626f16d3f316d786e6a80ade2b4f073beb673ef8b9e4a7279df0e00a7ab6`, 79B), `+0x24` (`0x112dab70`, `ev_b213db91c9901b629c031be7df18d92f348ff8c8587beba211d617091d5234c1`, 81B), & `+0x3c` (`0x112c0dd0`, `ev_d85a958734a380cb49008757784542df24b1aace429d7d418c49d3b9993f4dcf`, 28B): VFS-mutex-guarded (`0x112bff80`) stream readiness (`stream->vtable[+0x14]()`), conditional release (`stream->vtable[+0x10]() == 0` -> destroy and zero `[ECX+0x20]`), and byte-size completeness check (`stream->vtable[+0x20]() == [ECX+0x08]`).
    - `+0x18` (`0x112c9540`, `ev_cec25785a9ac28b769b2b80332c1cd92068d531dbf08fc22dd2e60ab910347ea` / `ev_f36e1a3cad5582f05d914bfe2b6e77dfa5230caa458097403221ddc72be263ef`, non-proc 14B): reads `((*carrier->pack_props)->flags >> 6) & 1`.
    - `+0x1c` (`0x112d0c90`, `ev_7c104658aad498d0e263970f48af922bf142817ac0e37e60e2bd7deac663d3f0`, 135B, `RET 0x8`) & `+0x20` (`0x112d0d80`, `ev_993ab31d47b34059c6ac04f5353e365f744007110e79dd184918bad1c2bb0959`, 101B, `RET 0x4`): locked and unlocked slice clamping (`min(byte_size - req_offset, req_len)` when `req_len != 0`, else `byte_size - req_offset`) dispatching to `stream_state->vtable[+0x04]` / `[+0x08]` with 64-bit `data_offset`.
    - `+0x2c` (`0x112baf20`, `ev_f20e5496c66bbdf46cc16acc519aa4b285aa26019b9bb2ab4d69fa4e8c4722ab` / `ev_8a4026e7e9daa866c99ec411d657406dcce2a950f06c1ec01b3567eda7e0f67b`, non-proc 8B), `+0x30` (`0x112d9890`, `ev_6c221700dd37160fe9433fb2e95e682d32d16d23143ad67384a0d532fee6c2d2` / `ev_b5530e0d127c908c2ec7d645243ea8e70cee270b20238cbdc87a756593097f00`, non-proc 16B), & `+0x38` (`0x112d0bd0`, `ev_5a9c4928500c45faf06b2bc89d539c83e3b680b32c359f08092cbc2f9397eafd` / `ev_a4ade6490c55d1dd31e4c893f6f17676e66398d674d67f78946e6bddcb9828bf`, non-proc 24B): virtual forwarding and flag `[+0x18]` tests on `[ECX+0x20]`.
  - High-caller-count CRT allocation & SEH/lock helpers (`0x100fcc50`, `0x100fcc80`, `0x116835d7`, `0x116838ea`, `0x116839e8`, `0x11683a32`) remain deferred to a standalone delta session to avoid cumulative evidence-bundle heap saturation.
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_pack_stream.h/.c`, `test_vfs_pack_stream.c`):
  - Promoted `rome2_vfs_pack_entry_layout32` offset `+0x20` to `stream_state` (`rome2_data_address32`) with updated `ROME2_LAYOUT_ASSERT`.
  - Bounded helpers: `rome2_vfs_plan_aligned_alloc` (`0x10102f50` checked alignment & 32-bit overflow prevention), `rome2_vfs_entry_clamp_slice32` (underflow-safe slice clamping from `+0x1c`/`+0x20` + 64-bit `slice_pack_offset`), `rome2_vfs_entry_has_per_entry_meta32` (`+0x18` checked carrier -> `pack_props` flag bit 6), and `rome2_vfs_entry_read_stream_info32` (`+0x0c`/`+0x10`/`+0x28`/`+0x34` + `stream_vtable` check); non-OK returns preserve caller outputs.
  - Verified **155 checks** in `test_vfs_pack_stream.c` (**61 checks** in `test_vfs_pack_entry.c`), **71/71** native suites on `/W4 /WX /analyze` and ASan, **49** contract tests against **141 functions, 79 globals, 15 vtables, and 180 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

## Layer 15: Archive-Name Disposer Vtable (`0x1189a434`), Base Vtable (`0x11849278`), VFS Mutex/Global Map (`0x112bff80`/`0x112e32b0`), & Pool Slabs

Layer 15 recovers the 15-slot base pack-entry vtable (`0x11849278`), the archive-name disposer/wrapper vtable implementations (`0x1189a434` / `0x1189a444`), the VFS mutex wrapper singleton (`0x112bff80`), the global UTF-16LE registry hash table (`0x112c02e0` / `0x112e32b0`), the virtual-base setting resolver (`0x11346530`), freelist pool singletons (`0x10106000` / `0x10106060` / `0x101060c0`), and `0x1c`-stride slab initializer `0x10328250`, validating fixed-width layouts in `port/recovered_types/guest32_layouts.h` and bounded C17 helpers in `port/recovered_types/vfs_pool_slab.h/.c`.

- New REA dossier evidence (closing snapshot `out/vfs-layer15-20261113/session.rea.json`, **174** total validated records in `out/vfs-layer15-20261113/validated-evidence-bundle.json`: `152` reused Layer 14 + `22` new records across `13` functions, `1` base vtable read + `2` xrefs, and `3` non-procedure virtual slot handlers):
  - Base pack-entry vtable `0x11849278` (`ev_9994dd0e2c06a163cd95728ff4cd5cce5e1503217f2109b36fa6c62da243d774`, `60` bytes / `15` slots, xrefs `ev_5398ffc06c9ee581f2c83af1ca9d76384e01d25486cff11a686782802a14f5e9` = 12 references including destructor `0x112ad1b8`; vs `0x118976c0` xref `ev_debb88476d0978de7e05ee1b0fa8d9e115ccdb8bf8d1b0b251fbc4939ae8bcb0` = `0x112a9963`): 11 `__purecall` (`0x116bd8af`) entries followed by concrete slots `0x10fa1340`, `0x10f9f6e0`, `0x10f9faa0`, and `0x10f9fae0`.
  - Archive-name disposer & wrapper vtable slots (`0x1189a434` / `0x1189a444`):
    - Non-procedure slots confirmed via negative `resolve_containing_procedure` + `read_bytes`: `0x112afd00` (`ev_810a0f0c60912fdfb3100f497fe1a4232890076d890010832c446963b1ff4765` / `ev_297e755b68d0eac4bb491fd989cc4ce4aaab73d84249573c9da49f578043f3d9`, 33B: destroys `[ECX+0x10]` via `0x10cf4d20` and pushes it onto `0x119344f4`), `0x112acd70` (`ev_d399eda38b88b3ff1585046b402e1e7726d706e0024c2531e98b609c2713491c` / `ev_266cc3c12ce40faf994392559c14638f85d8a3fa5cce4c788c4b351351511beb`, 27B: scalar deleting destructor freeing `0x18` bytes via `0x116835d5`), and `0x112acd30` (`ev_eb7f8daf125821be59fc4b6127dde47958689113860003c0ccba5e103f1e26c3` / `ev_40a2c777604b14d603a58fb3427f466db2a0938b2cbf18cfd9025b4005157e09`, 27B: scalar deleting destructor freeing `0x2c` bytes via `0x116835d5`).
    - Procedure slots & companion helper: `0x112afbf0` (`ev_c39b61c0a0e5cbb381e97fbb353f3e27d4cdc9a628566534204d7cd593a410aa`, 23B: calls `this->vtable[+0x08](0)` and recycles `this` onto `0x11934500`), `0x10128c50` (`ev_47dcb59e8d175fc46f875cc37afefb0ef84c99fd8ad1937ed1ab57b47ed92d29`, 5B, `RET 0x4`: returns `0`), `0x112afcd0` (`ev_71bb41b89fdb6c8a32486c74f89b66e773494d51835946ebf1e9e3b5b674c85f`, 11B: forwards `[ECX+0x0c]->vtable[+0x00](0)`), `0x1090bb10` (`ev_6d64542c2db404e368011b726e73a32a5480524ffd54323c0d22cc3de9fd285c`, 12B: null-checked `vtable[+0x08](1)`), and `0x112afd30` (`ev_4a4b89045a1fe73c1536d9e179337fb31351bde2aaa0b512f9124997b0cbd43a`, 28B, `RET 0x4`: destroys `[arg+0x10]` via `0x100f1c80` and frees `0x1c` bytes via `0x116835d7`).
  - VFS mutex, global hash map, & virtual-base setting flags: `0x112bff80` (`ev_f72df41b568b646ee7309ea4fcecdebedc2d28a5938d338078a3b9b04abf18fa`, 92B: TLS-guarded initializer returning 28B `0x12032b10` with `InitializeCriticalSection(&DAT_12032b14)`), `0x112e32b0` (`ev_286bbe82528302fcfbf86cfdaf3f07c81d96164fde691a05b38a2784e199a559`, 252B non-contiguous: initializes `0x12032bf4` with `8` x `16`-byte buckets via `0x10102f50` and `L"Removed_key"`/`L"Unused_key"`), `0x112c02e0` (`ev_4f81a827ae2501d32a9c0bd0c1a26c4d4a413598ce2dfbb901553a0714f1f20b`, 26B: queries `0x12032bf4` via `0x100d79c0`), and `0x11346530` (`ev_91e5519d2b6110890a541437d46d687550d2bbf23f4f57d9443e3fac32ac5e89`, 171B, `RET 0x4`: reads vbptr offset `[this->vtable+0x04]` and merges 4-bit flags `[vb+0x04]`).
  - Freelist pools & `0x1c`-stride slab builder: `0x10106000` (`ev_ddb7433225727b41f03fdd034b25b182aad723fadc28fb5205297b2bb8455034`, 81B -> `0x119344f4`), `0x10106060` (`ev_5d78523322e739d9358c54f45a39218854cf158ef4797635e8fec8d6d5df0156`, 81B -> `0x11934500`), `0x101060c0` (`ev_99982a3585427652ffc2b96c849939b115d1fd677eae62e5fc47c1adda347370`, 81B -> `0x1193450c`), and `0x10328250` (`ev_cf5f23fd9212345bf183d0fb31651b280dd7e74da633eb24bc83ed792a714a52`, 86B, `RET 0x8`: allocates `count * 0x1c` bytes via `0x100fcc80`, links `0x1c`-stride singly-linked freelist pointers, and writes `{node_array, next_slab}`).
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_pool_slab.h/.c`, `test_vfs_pool_slab.c`):
  - Fixed-width 32-bit layouts: `rome2_vfs_freelist_pool_header32` (`12`B), `rome2_vfs_slab_descriptor32` (`8`B), `rome2_vfs_archive_name_disposer32` (`24`B), `rome2_vfs_mutex_box32` (`28`B), and `rome2_vfs_global_map32` (`36`B).
  - Bounded helpers: `rome2_vfs_decode_freelist_pool_header32`, `rome2_vfs_decode_slab_descriptor32`, `rome2_vfs_stride28_slab_byte_size`, `rome2_vfs_init_stride28_slab`, `rome2_vfs_verify_stride28_slab_chain`, `rome2_vfs_decode_archive_disposer32`, `rome2_vfs_decode_pack_entry_base_vtable32`, `rome2_vfs_decode_mutex_box32`, `rome2_vfs_decode_global_map32`, and `rome2_vfs_setting_flags_compute32`; non-OK status leaves caller outputs and mutable buffers untouched.
  - Verified **45 checks** in `test_vfs_pool_slab.c`, **72/72** native suites on `/W4 /WX /analyze` and ASan, **50** contract tests against **154 functions, 87 globals, 16 vtables, and 187 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

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

## Layer 16 — Pack-entry site `0x112a9963`, base concrete slots `0x11849278`, quota tracker, RB sentinel/recycler & global map probe

- REA session (`out/vfs-layer16-20261113/session.rea.json`, **195** validated records = **174** reused Layer 15 + **21** new in [contracts.json](../port/recovered_types/contracts.json) `rea_layer16_evidence`):
  - Pack-entry vtable assignment & base concrete slots (`0x11849278` + `0x1189a454`): `resolve_containing_procedure(0x112a9963)` (`ev_b92d370539dc6113a3c29643963244c20245899aaca032f43e0c02e8ac51f066`, `read_bytes(0x112a9950)` `ev_1eaf5d1d8c1ab706253fe2f5016c328b71a8094d3189f994fba724736217e0ab`) confirms `0x112a9963` (`MOV dword ptr [ESI], 0x118976c0`) lies inside `0x112a9560`; base slot `+0x30` is `0x10f9f6e0` (`ev_c27af034f2397b7312c8887b1e6cf2e14aa43ef1b105a7d2aa5c86423e450ccc`, 949B, `RET 0x4` x4); non-procedure slots `+0x2c` (`0x10fa1340`, 43B), `+0x34` (`0x10f9faa0`, 55B), `+0x38` (`0x10f9fae0`, 34B prefix), and vtable `0x1189a454` slot `+0x00` (`0x112afca0`, 30B calling `DeleteCriticalSection` `[0x1172f1fc]`) are pinned via negative `resolve_containing_procedure` + exact code bytes (`ev_6fc71457142a9222e9547fb1f1073aad0c848a4c41619f49393fa489e59da1a8`/`ev_10dd71f6a6f66f14a956c675ea3e54440f5bca4521538d1c7f914a2b74e7b1b4`, `ev_21d6e653cc966f88831f953296bc05f318f76099812e800621e61d5f3a8b72bf`/`ev_55f3443b6994883ec2982c6f41907530a51c46af4fbcb590ac2e07e37c057ece`, `ev_940011794372a2ff72f5abbe1b1db600ea9564220d4159be0b4d0072fa43a699`/`ev_d47c40b87a2356abc342337cd0977bf2c883b5a1203166d3bca82110d1938f56`, `ev_5d00422d51278cce4721585403f0ddc82b30d689056a1b80621093c67adc3d4e`/`ev_5d9d1ea16a0574231f6b51ac61dc35ef41f933b4b8897250ece45a698ef2e5ba`).
  - `0x11346530` iostream callees: `0x113492c0` (`ev_35a762afc3784c0624fb4436775b5111c9c70967542e7ac3ac920deef31f8494`, 349B, `RET 0x4` x2: `std::basic_istream<wchar_t>::sentry` tie/whitespace skipping) and `0x11347360` (`ev_8a6b9ce77a1ccee61177808f6a7ce5b3729cf296af5dbba5d9726872e10d2780`, 303B, `cdecl`, 32B stack args: `use_facet<ctype<wchar_t>>` extraction).
  - Pack wire header, quota, stream, mount & RB tree callees: `0x112a9bc0` (`ev_28b48a97a94e0822e9578db48313ae3fe91ffdc018741a6be752307cdab4da37`, 556B, `RET 0x4`: reads `0x1c`-byte `.pack` header into `[ECX+0x18..+0x33]` and sets `+0x04 = 0x26` `ERROR_HANDLE_EOF` on short read), `0x112a45c0` (`ev_0d5c4300a639ec9ca9a054528644000febc6ab35669c262bac733a2a8fd840db`, 202B, `cdecl`: per-thread `GetCurrentThreadId` `[0x1172f224]` quota tracker checking `used_ops < max_ops && used_bytes + delta <= max_bytes`), `0x112aa5d0` (`ev_b269c6b619c4436075114eccc7b83b0d895a4cc45bbb0d5219f87ba6db28fdc9`, 58B, `RET 0x4`: builds 16B `rome2_vfs_stream_slice_view32`), `0x112ba6c0` (`ev_cacf04b3e3805868b2c9acbd688b9618273b8351c964f50a454bc88b2642a5ad`, 380B, `cdecl`: `0x3c`B stream wrapper under `DAT_120326e0 == 0`), `0x112b5730` (`ev_8d09b9dc2d0410fda41782fc59e6f5a415285e2ab7cec66a52317e90cf4af657`, 819B across 4 ranges with gaps 10/21/30: root archive scan/mount setting `DAT_12031a88 = 1` and lazy `0x180`B `DAT_119e11e8`), `0x112e3eb0` (`ev_7632f140f98bf58ec3c538a997ee18c00bc27765d3c0ca97611884a4e35ba786`, 107B: allocates `0x14`B RB sentinel at `0x12032944`), `0x10cf4d20` (`ev_0bde83a9171520f2b34ae902279d7a0817ce2043d504a47b88338fcfff1f0b44`, 59B, `RET 0x8`: recursive right + iterative left RB node recycler pushing onto `0x119344f4`), and fresh re-verification of `0x100d79c0` (`ev_333aa842ce1441a457733474ca7f5037aa0e3526c175760073eeb17bdde73376`, 231B: reverse rotate-XOR UTF-16LE map probe seeded with `0xf73a51c9`).
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_quota_map.h/.c`, `test_vfs_quota_map.c`):
  - Fixed-width 32-bit layouts: `rome2_vfs_pack_header_wire32` (`28`B), `rome2_vfs_rb_sentinel_node32` (`20`B), `rome2_vfs_quota_frame32` (`32`B), and `rome2_vfs_stream_slice_view32` (`16`B).
  - Bounded helpers: `rome2_vfs_hash_utf16_key32`, `rome2_vfs_global_map_probe32`, `rome2_vfs_pack_header_decode32`, `rome2_vfs_quota_check_and_reserve`, `rome2_vfs_count_rb_live_nodes32`, and `rome2_vfs_build_stream_slice_view32`; non-OK status preserves caller outputs and mutable frames.
  - Verified **25 checks** in `test_vfs_quota_map.c`, **73/73** native suites on `/W4 /WX /analyze` and ASan, **51** contract tests against **164 functions, 93 globals, 17 vtables, and 197 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

## Layer 17 — Direct VFS callees of root scan, per-thread quota, stream wrappers & `pack_props`

- REA session (`out/vfs-layer17-20261113/session.rea.json`, **208** validated records = **195** reused Layer 16 + **13** new in [contracts.json](../port/recovered_types/contracts.json) `rea_layer17_evidence`):
  - Root scan & post-mount callees (`0x112b5730`): `0x112d4160` (`ev_1fe82383ecd0f4c72e56e65db4340a0a33ea63b3175c81302bc1a5520909dfb9`, 226B: queries `0x112d4de0`/`0x112c13f0`, allocates `0x50`-byte ref-counted block with vtable `0x1189a424` and embedded `0x44`B `pack_props` at `+0x0c`), `0x112d4c50` (`ev_8d88e1d7889ec005c5db3e4b58aaa76385880879aab447bbf553658e7c250d34`, 100B: TLS-guarded `0x12032a14` initializer for `0x180`-byte `DAT_119e11e8`), `0x112baf90` (`ev_074dcf08850fd1ca9f20b555e5a6630b99a696c355fb24fc6107a7d0e0b77c57`, 180B 2-range gap 3: initializes `0x3cb` `8`-byte slots at `0x120329c8` with default `DAT_120329d0`), `0x112b5450` (`ev_3d56d5a3865f716e7661de4912fd241ab1ee679ca2c5220997c0fccf97bc944f`, 68B: sweeps `0x120329c8` slots resetting mismatches to default), and `0x112a4e10` (`ev_294a74ccde986aed59990423869e50549a1ef05c0ba9dba61d77f28dbcf16b0c`, 397B, 20B stack args: trace/visitor dispatch with `0x1173f1f0` `ev_876647f8e142b3becf148b8c79026d7381a44d13b549fb3bbe6b76ce6b07ed0e` & `0x1173dad0` `ev_177c48daf4b3a2cdcfb187d1b45470d8cbe3616b395c1f8040dbf8167744a0b3`).
  - Per-thread quota & open-bucket maps (`0x112a45c0`): `0x112e3db0` (`ev_5a812ab7a18b0c8c54c3392687821540c8b9fce9d2eda13962e1cda0e7593009`, 230B 2-range gap 13: TLS-guarded `0x12032af4` singleton `0x119e120c`), `0x101f4f90` (`ev_3cbd21bf8a654cbacf7a3656bad410e83e9fc3274a1806932a06bcc4523c67b1`, 123B, `RET 0x8` x2: `(thread_id ^ 0x4a545eed) % bucket_count` open-bucket lookup in `12`B chains), and `0x112cbe10` (`ev_5347586c5ae787714e64254fc717d1f9344dd4ef92d6f374afff32a014a3dd99`, 476B, `RET 0x8` x2: open-bucket set insert/rehash `2*n+1` on float load factor vs `[this+0x14]`).
  - Stream wrappers & dependency table (`0x112ba6c0`, `0x112a9bc0`): `0x112a7ae0` (`ev_ed783e595cfab640ffaad31170aaa40f6fc71aaa0b1810cb6eef664c88e4231a`, 115B, `RET 0x1c`: `0x38`B wrapper with vtable `0x118977ec`), `0x112a94d0` (`ev_43ef81d32e3bae542eb4d937254345431262b39bcd2ce1767bfeb8a92380853c`, 119B, `RET 0x10`: `0x3c`B wrapper with vtable `0x11897790`), and `0x112bb790` (`ev_a6c89b55fcfc477b85080db255aff1a56956d71b3e22196c634526775b721d39`, 299B, `RET 0x8` x3: `pack_props` dependency tree update).
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_scan_mount.h/.c`, `test_vfs_scan_mount.c`):
  - Fixed-width 32-bit layouts: `rome2_vfs_ref_pack_block_header32` (`12`B + `0x44`B `rome2_vfs_pack_props_prefix32` == `0x50`B), `rome2_vfs_open_bucket_map32` (`24`B), `rome2_vfs_open_bucket_slot32` (`12`B), `rome2_vfs_thread_node32` (`12`B), `rome2_vfs_post_scan_table32` (`16`B), `rome2_vfs_stream_wrap_a32` (`0x38`B), and `rome2_vfs_stream_wrap_b32` (`0x3c`B).
  - Bounded helpers: `rome2_vfs_thread_bucket_hash32`, `rome2_vfs_thread_bucket_lookup32`, `rome2_vfs_bucket_map_should_rehash32`, `rome2_vfs_decode_ref_pack_block32`, `rome2_vfs_scan_post_mount_mismatches32`, `rome2_vfs_validate_stream_wrap_a32`, and `rome2_vfs_validate_stream_wrap_b32`; non-OK status preserves caller outputs.
  - Verified **32 checks** in `test_vfs_scan_mount.c`, **74/74** native suites on `/W4 /WX /analyze` and ASan, **52** contract tests against **175 functions, 101 globals, 20 vtables, and 204 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

## Layer 18 — `0x1189a424` / stream-wrapper vtable slots, bucket rehash `0x112d9e20` & `0x112bb790` dependency sub-callees

- REA session (`out/vfs-layer18-20261113/session.rea.json`, **231** validated records = **208** reused Layer 17 + **23** new in [contracts.json](../port/recovered_types/contracts.json) `rea_layer18_evidence`):
  - Ref-pack block (`0x1189a424`) and stream-wrapper (`0x118977ec` / `0x11897790`) vtable prefix slots:
    - Vtable reads (`0x1189a424` `ev_9f3d4b5cf355d81238b62aa8747a2be49b0e15ea90828814adcdae7f92bdd9ca`, `0x118977ec` `ev_81e5d68394fd5cacc442737db1f2360acb7afc21d83dcdae29066f99304a95df`, `0x11897790` `ev_d7ed47becc72e2beb48f501f1fe297ebeb4644073df22c99cef2d86980bd418b`) plus non-procedure slot handlers (`0x112acd50` `ev_ba4ed6f83ae04d31defaf432479bf05d8322a7a7e7f9f0ba2f5c5a93106e0e15` / `ev_4955110d5483002036b0105690e029abaa01d90d349efe5b421872fb9be64d98` freeing `0x50`B via `PUSH 0x50`; `0x112d8d30` `ev_0ee3c6407993235f35193d254cb37b68bf07a0a923525f4df29682c90ea44b6c` / `ev_7057d89b125e2a2639137c5d37b27a81e9d9cbae6864a84954e78f2ac86e5ec8`; `0x112d8e20` `ev_57e2266eee6de6ca2f75413c5f333c6af4d4da72255b0cf4b6f62b40dfc38737` / `ev_9a19f15a20ab1f5638c7db531e4edfd3f940bcae3e0773eeb9f741385525da31` pushing `"normals\\normal_"` at `0x11897c70`) and tail-jump slot `0x112afce0` (`ev_1700b666fbc9607a9520f5e43f810169bf090ae2a3e3ef504fcef117b0d9421c`, 28B `JMP 0x100f2170`) pinned via instruction witnesses.
    - Stream-wrapper destructors `0x112acde0` (`ev_aaaecae7dad318c6c997e38ddd6d61aa5888bc6ba253687124b5872189202835`, 54B, `RET 0x4`: releases `+0x30` handle and frees `0x38`B) and `0x112ad0f0` (`ev_b6af9f90638384a55ba12ce52dfdfe98e7528baf9abad239f6c48ac06bd82ee4`, 80B, `RET 0x4`: calls `UnmapViewOfFile` `[0x1172f24c]`, frees 8B view box, and frees `0x3c`B).
  - Open-bucket rehash & dependency RB / open-pack sub-callees (`0x112d9e20`, `0x112bb790`):
    - `0x112d9e20` (`ev_a7f4b1fd1e265fada8965d14d90ffa5da299d1e970049afcbf6488f2e5e3055e`, 547B, `RET 0x4`: computes `ceil(element_count / max_load_factor)` with x87 `RC=0x800` via `OR EAX, 0x800; FLDCW; FISTP`, resizes bucket vector via `0x112dbe10`, and re-links live entries).
    - `0x112a2760` (`ev_97431c43f18ce8ef20b2bc099dac2dd05ff5ce1e6cbe348f136e51a05a66e7c4`, 92B, `RET 0x8`), `0x112a4090` (`ev_eb3e765adb44aa5f31843017943358ce5ccad770eee25726e561514cd06bf884`, 411B, `RET 0x10` x2), `0x112a4b60` (`ev_8e03bec79809bd4cac77f91d4ca0e6f07b022dd45c52c3b4dc45982bb46c4dfa`, 148B, `cdecl`), `0x112a59c0` (`ev_a500138ffc38ff3873d9f9625acead37d01c19e9f8d34db0fc2a67dd12297f66`, 45B, `RET 0x8`), `0x112a7700` (`ev_ab57e716e01b87769c12f12337e3f02ebe3fc1d46f41d56f1c9bbf8436b0e5be`, 163B, `RET 0x4` x2), and `0x112be300` (`ev_c5abf9c29ad73aeaa9eafc2111cc3ce138c72fc9f8ff6ad7541a025058ff3bb9`, 75B, `RET 0x8`) operate on `0x28`-byte RB nodes (`is_nil @ +0x0d`, pair `{name_a @ +0x10, name_b @ +0x1c}`).
    - `0x112af270` (`ev_00a67946f3c3b2c4b07ea33d4b4de94748fa5113084944216b715e2d885dd90f`, 86B, `cdecl`: TLS-guarded `0x12032964`/`0x12125644` static `"<root>"` `0x11897bc8` handle `0x12032960`), `0x112d57f0` (`ev_7b2c4f5c4b6a7b0a9fec61a62b5db6c1b7acd19a7bd0641882481074eb3590d6`, 501B, `RET 0x8` x3), `0x112ddb30` (`ev_0447897541722f8753f943c1cde897ffb16ce6dc69989ba048e7ca4d71df75a2`, 568B, `RET 0x8` x2: `0x14`-byte-strided `(uVar11 * 0x14)` wrap-around open-pack hash probe), and `0x112e3ae0` (`ev_9db2c1d50a9427193897b0eff9cc2b14aa5cc8611e2dcea34ceac812112704c0`, 369B, `RET 0x4`: `0x1c`-byte RB cycle sentinel builder).
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_dep_rehash.h/.c`, `test_vfs_dep_rehash.c`):
  - Fixed-width 32-bit layouts: `rome2_vfs_dep_rb_node32` (`40`B), `rome2_vfs_cycle_rb_sentinel32` (`28`B), `rome2_vfs_ref_block_vtable32` (`16`B), and `rome2_vfs_stream_wrap_vtable_prefix32` (`32`B).
  - Bounded helpers: `rome2_vfs_compute_rehash_target32`, `rome2_vfs_decode_dep_rb_node32`, `rome2_vfs_count_dep_rb_nodes32`, `rome2_vfs_dep_pair_compare32`, `rome2_vfs_decode_ref_block_vtable32`, `rome2_vfs_decode_stream_wrap_vtable_prefix32`, and `rome2_vfs_open_pack_stride20_slot_offset32`; non-OK status preserves caller outputs.
  - Verified **23 checks** in `test_vfs_dep_rehash.c`, **75/75** native suites on `/W4 /WX /analyze` and ASan, **53** contract tests against **188 functions, 106 globals, 20 vtables, and 216 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

## Layer 19 — Deep VFS leaf/mutation sub-callees of Layer 18 (`0x112a21f0`–`0x112dbe10`)

- REA session (`out/vfs-layer19-20261113/session.rea.json`, **246** validated records = **231** reused Layer 18 + **15** new functions in [contracts.json](../port/recovered_types/contracts.json) `rea_layer19_evidence`):
  - Dependency RB tree mutation, cloning & merge callees: `0x112a21f0` (`ev_b367bf35...` range erase, 633B, `RET 0x8` x3), `0x112a25b0` (163B, `RET 0xc` x2: deep copy of `0x28`B RB subtrees), `0x112a2810` (130B, `cdecl`: clears root pointer and resets min/max links via `0x112a2760`), `0x112a3320` (589B, `RET 0x10`: enforces `0x06666665` node ceiling before `"map/set<T> too long"` `0x1177ddbc` and inserts/rebalances `0x28`B RB node), `0x112a5ce0` (457B, `cdecl`, `28`B stack args: sorted RB range intersection/merge), and `0x112afd50` (672B, `RET 0x4`: RB erase/rebalance unlink via `0x112b07a0`).
  - Hash container & open-bucket vector helpers: `0x112afc10` (120B, `RET 0x4` x2: computes `ceil(count / *(float*)this)`, clamps to `8`, scales small tables `< 0x200` by `8x`), `0x112b0070` (831B, `RET 0x4`: checks `<= 0x10000000` before `"invalid hash bucket count"` `0x11745c98`, rounds up to next power of 2, reallocates `2*buckets` vector), `0x112ab420` (106B, `thiscall`, `0` stack args: destroys aligned `>= 0x1000` vector allocation with `0x23`/`0x1f` header guard check), `0x112b41a0` (179B, `stdcall`, `8`B stack args), `0x112cd780` (853B, `stdcall`, `4`B stack args), `0x112ab310` (60B, `thiscall`: clears `0x0c`B bucket slot list), `0x112d8550` (581B, `RET 0x4` x3: pushes/doubles `0x0c`B bucket vector slots), and `0x112dbe10` (258B, `RET 0x4`: reserves `param_1 * 0x0c` bytes and frees old bucket array).
  - Ref-counted handle box close: `0x112ac430` (145B, `stdcall`, `4`B stack args: sets `+0x0c/+0x0d = 1` under `0x112bff80` critical section `KERNEL32!EnterCriticalSection`/`LeaveCriticalSection` IAT `0x1172f1f0`/`0x1172f1f4`, releases primary/secondary refs, and frees `0x14`B `stream_handle_box`).
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_rb_bucket_ops.h/.c`, `test_vfs_rb_bucket_ops.c`):
  - Fixed-width 32-bit layouts: `rome2_vfs_stream_handle_box32` (`20`B) and `rome2_vfs_bucket_vec_header32` (`12`B), reusing Layer 18 `rome2_vfs_dep_rb_node32` and Layer 10 `rome2_vfs_dep_hashmap_layout32` (`32`B).
  - Bounded helpers: `rome2_vfs_dep_rb_can_allocate32`, `rome2_vfs_hash_next_power_of_2_buckets32`, `rome2_vfs_hash_desired_buckets32`, `rome2_vfs_decode_stream_handle_box32`, `rome2_vfs_decode_bucket_vec_header32`, `rome2_vfs_bucket_vec_next_capacity32`, and `rome2_vfs_validate_aligned_vec_free32`; non-OK status preserves caller outputs.
  - Verified **21 checks** in `test_vfs_rb_bucket_ops.c`, **76/76** native suites on `/W4 /WX /analyze` and ASan, **54** contract tests against **203 functions, 110 globals, 20 vtables, and 224 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

## Layer 20 — Stream-wrapper vtable slots `+0x08..+0x1c` & RB rotate/iterator leaves

- REA session (`out/vfs-layer20-20261113/session.rea.json`, **267** validated records = **246** reused Layer 19 + **21** new = `9` `analyze_function` + `6` paired `resolve_containing_procedure`/`read_bytes` in [contracts.json](../port/recovered_types/contracts.json) `rea_layer20_evidence`):
  - Stream-wrapper vtable slots `+0x08..+0x1c` (`0x118977ec` `stream_wrap_a` & `0x11897790` `stream_wrap_b`):
    - Shared COMDAT virtual no-ops at `+0x08` (`0x10190580` `ev_ca86acb9...`, 3B `RET 0xc`) and `+0x0c` (`0x100e22c0` `ev_b216bc03...`, 3B `RET 0x8`).
    - Reference-release slots `+0x10`: `0x112da9f0` (`ev_2bab2198...`, 80B `thiscall`: decrements `+0x2c`, zeroes `+0x20..+0x28` low byte/+0x30, releases `stream_handle_box` via `0x112ac430`) and `0x112dab00` (`ev_06dea47c...`, 110B `thiscall`: decrements `+0x38`, calls `UnmapViewOfFile` `[0x1172f24c]`, frees 8B view box via `0x116835d7`, clears `+0x20..+0x34`).
    - Non-procedure status/accessor slots anchored via `resolve_containing_procedure` + `read_bytes` + `instruction_witnesses`: `0x112c8b80` (`ev_5be02284...`, 8B `stream_wrap_a +0x14` handle check `+0x30 != 0`), `0x112d9860` (`ev_c4f05a14...`, 22B `stream_wrap_a +0x18` `handle_box->sentinel_or_state->eof_or_closed_00c == 0`), `0x112badf0` (`ev_fcbbe6e8...`, 38B `stream_wrap_a +0x1c` sync call `0x112c0c60` + tail `JMP [state->vtable+0x08]`), `0x112c8bc0` (`ev_b420f276...`, 32B `stream_wrap_b +0x14` view/bound check against `+0x28` override or `+0x0c` tag), `0x10369160` (`ev_bf444873...`, 8B `stream_wrap_b +0x18` view check `+0x20 != 0`), and `0x112baef0` (`ev_30180dca...`, 7B `stream_wrap_b +0x1c` dereferencing `view_box.data_ptr` at `+0x04`).
  - RB rotate & iterator leaves (`0x112a2470`, `0x112b0710`, `0x112b0760`, `0x112b0780`, `0x112b07a0`):
    - `0x112a2470` (`ev_dc331d01...`, 113B `RET 0x8` x2: clones RB tree via `0x112a2660`, copies size `+0x04`, updates sentinel `_Lmost`/`_Rmost` via inline min/max walks), `0x112b0710` (`ev_a4be4dc0...`, 77B `RET 0x4` x3: `_Lrotate`), `0x112b07a0` (`ev_f98b11c9...`, 81B `RET 0x4` x3: `_Rrotate`), `0x112b0760` (`ev_c1682d02...`, 30B `cdecl` `_Max`), and `0x112b0780` (`ev_b9e8a1e9...`, 31B `cdecl` `_Min`).
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_stream_wrap_ops.h/.c`, `test_vfs_stream_wrap_ops.c`):
  - Fixed-width 32-bit layouts: `rome2_vfs_stream_view_box32` (`8`B), `rome2_vfs_stream_state_prefix32` (`16`B), and `rome2_vfs_rb_tree_head32` (`8`B).
  - Bounded helpers: `rome2_vfs_stream_wrap_a_release_ref32`, `rome2_vfs_stream_wrap_b_release_ref32`, `rome2_vfs_stream_wrap_a_has_handle32`, `rome2_vfs_stream_wrap_a_is_open32`, `rome2_vfs_stream_wrap_a_plan_slot1c32`, `rome2_vfs_stream_wrap_b_has_view32`, `rome2_vfs_stream_wrap_b_is_at_bound32`, `rome2_vfs_stream_wrap_b_read_view_box32`, `rome2_vfs_rb_find_extreme_index`, and `rome2_vfs_rb_rotate_and_refresh_extremes`; non-OK status preserves caller outputs and node tables.
  - Verified **18 checks** in `test_vfs_stream_wrap_ops.c`, **77/77** native suites on `/W4 /WX /analyze` and ASan, **55** contract tests against **218 functions, 110 globals, 20 vtables, and 233 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

## Layer 21 — Deferred VFS sub-callees, stream-wrapper open slots & ref-block destructors (`0x112a2660`–`0x112d8e20`)

- REA session (`out/vfs-layer21-20261114/session.rea.json`, **281** validated records = **267** reused Layer 20 + **14** net new unique evidence IDs across **18** retained envelopes = `8` `analyze_function` + `5` paired `resolve_containing_procedure`/`read_bytes(length=320)` in [contracts.json](../port/recovered_types/contracts.json) `rea_layer21_evidence`):
  - Adjacency hash-list & `0x1c`B dependency RB helpers: `0x112a2660` (`ev_df420ab9...`, 141B `RET 0xc` x2: recursive `_Copy` of `0x1c`B RB subtree allocating nodes via `0x100d12b0(0x1c)` and copying string payload `+0x10` via `0x100f1700`), `0x112a2910` (`ev_dc3c317c...`, 654B across `112a2910..112a2a1e` and `112a2a20..112a2b9e` with 1B `0x90` NOP gap at `0x112a2a1f`, `RET 0xc` x4: enforces `0x071c71c7` ceiling before `"unordered_map/set too long"` `0x11745c7c` and inserts/rehashes `0x24`B adjacency hash-list nodes), `0x112a3ee0` (`ev_bdc9dd9b...`, 420B `RET 0xc` x8: hinted RB `_Insert_hint` on `0x1c`B dependency RB tree calling `0x112a3ca0`), `0x112ac1a0` (`ev_ee4bcdcc...`, 284B `RET 0x4` x2: allocates `0x24`B adjacency node plus two `0x1c`B RB sentinels at `+0x14`/`+0x1c`, inserts via `0x112a2910`, frees on duplicate key), and `0x112be350` (`ev_e6dc6306...`, 345B `RET 0x4` x2: `equal_range` + `erase(key)` returning erased count).
  - Stream wait, pointer-vector push, & flag-chain leaves: `0x112c0c60` (`ev_645448ae...`, 137B `thiscall`: unwinds recursive VFS mutex depth via `LeaveCriticalSection` `[0x1172f1f4]`, spin-waits while `+0x0d == 0 && +0x0c == 0`, re-acquires depth via `EnterCriticalSection` `[0x1172f1f0]`), `0x112cd4c0` (`ev_732afb10...`, 20B `thiscall`: recursively clears byte flag `+0x04 = 0` along `+0x00` singly-linked chain), and `0x112d8c50` (`ev_7916d749...`, 215B `RET 0x4` x2: `vector<uint32_t>::push_back` on 12B `{first, last, end}` triple enforcing `0x3fffffff` element ceiling and 1.5x growth).
  - Virtual stream-wrap `+0x04` open slots & ref-block scalar deleting destructors (anchored via `resolve_containing_procedure` + `read_bytes(length=320)` + `instruction_witnesses`): `0x112accd0` (`0x1189a454 +0x08`, 27B `RET 0x4`: `0x38`B), `0x112acd50` (`0x1189a424 +0x08`, 27B `RET 0x4`: `0x50`B), `0x112acd70` (`0x1189a434 +0x08`, 27B `RET 0x4`: `0x18`B), `0x112d8d30` (`stream_wrap_a` `0x118977ec +0x04`, 216B `RET 0xc` x2), and `0x112d8e20` (`stream_wrap_b` `0x11897790 +0x04`, 300B `RET 0xc`: tests `.data` `zero_fill` flag `0x12031a8a`, calls `[0x1172f670]` and `UnmapViewOfFile` `[0x1172f24c]`).
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_adj_open_ops.h/.c`, `test_vfs_adj_open_ops.c`):
  - Fixed-width 32-bit layouts: `rome2_vfs_adj_hash_node32` (`36`B), `rome2_vfs_recursive_mutex_prefix32` (`8`B), `rome2_vfs_u32_ptr_vec32` (`12`B), and `rome2_vfs_flag_chain_node32` (`8`B).
  - Bounded helpers: `rome2_vfs_adj_hash_can_allocate32`, `rome2_vfs_decode_adj_hash_node32`, `rome2_vfs_u32_vec_plan_push32`, `rome2_vfs_state_wait_plan32`, `rome2_vfs_stream_wrap_check_open_reentry32`, `rome2_vfs_clear_flag_chain_bounded`, and `rome2_vfs_ref_block_delete_size32`; non-OK status preserves caller outputs and node arrays.
  - Verified **20 checks** in `test_vfs_adj_open_ops.c`, **78/78** native suites on `/W4 /WX /analyze` and ASan, **56** contract tests against **231 functions, 113 globals, 20 vtables, and 241 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

## Layer 22 — Stream handle-box/view-map callees, pack-entry vtable `0x118976c0` completion & ref-block destructors (`0x10102f90`–`0x116835d7`)

- REA session (`out/vfs-layer22-20261114/session.rea.json`, **302** validated records = **281** reused Layer 21 + **18** primary new unique IDs + **3** `inspect_analysis_view` extras for `0x116835d7` across `24` primary + `3` view retained files in [contracts.json](../port/recovered_types/contracts.json) `rea_layer22_evidence`):
  - Vector/aligned-32 alloc & CRT delete: `0x112afb90` (`ev_e485c6c1...`, 88B `thiscall`, `RET 0xc`: releases existing allocation validating `[base-4] <= 0x1f` guard header when `>= 0x1000` before `0x116835d7` free or `0x116879f9` abort and rebinds 12B triple), `0x101d9910` (`ev_315a1045...`, 95B `stdcall`, `RET 0x4`: enforces `<= 0x3fffffff`, adds `0x23` / masks `0xffffffe0` storing raw base at `[aligned-4]` for `>= 0x1000`), and `0x116835d7` (`ev_233612c1...` via validated bundle record + 3 views, 14B `cdecl`: delegates stack arg to CRT free wrapper `0x100d12c0`).
  - Handle-box, file-mapping/view ctor, telemetry singleton, & leaf utilities: `0x112a7860` (`ev_80b1abba...`, 633B `thiscall`, `RET 0x24`: initializes handle-box wrapper, constructs `0x2c`B state ref block with `0x1189a444` -> `0x118977bc`/`0x118977d4`, calls `0x10102f90`, uses `GetLastError` `[0x1172f23c]` / `CloseHandle` `[0x1172f184]`, waits via `0x112c0c60`), `0x10102f90` (`ev_cebda47e...`, 318B `thiscall`, `RET 0x10`: aligns window down to allocation granularity, calls `CreateFileMappingA` `[0x1172f248]` + `MapViewOfFile` `[0x1172f244]` + `CloseHandle` `[0x1172f184]` to populate 8B view box), `0x112e1830` (`ev_38c9bc7e...`, 290B `cdecl`: constructs `0x6c`B pack-telemetry singleton with `0x118976a4` and `0x3e5` slots cached in `.data` `zero_fill` `[0x12032e68]`), `0x10e13a60` (`ev_9728c1b0...`, 63B `cdecl`: NUL-terminated ASCII substring search), and `0x10115900` (`ev_0eeb116e...`, 55B `cdecl`: page-stride touch loop updating `.data` `zero_fill` accumulator `[0x11af4268]`).
  - Pack-entry vtable `0x118976c0` completion & ref-block deleting destructors (anchored via `resolve_containing_procedure` [`6` reused from Layer 18, `2` new] + `read_bytes(length=768)` + `instruction_witnesses`): `0x112ad1b0` (`0x118976c0 +0x00`, 33B `RET 0x4`: `0x28`B resetting vtable `0x11849278`), `0x112d3270` (`+0x04`, 20B `RET 0x4`), `0x112e0d80` (`+0x08`, 23B `RET 0x4`), `0x112c9540` (`+0x10`, 14B `cdecl/thiscall` reading archive descriptor flag bit 6), `0x112afd00` (`0x1189a434 +0x00`, 33B `thiscall` RB tree clear at `+0x10`), `0x112accf0` (`0x118977bc +0x00`, 27B `RET 0x4`: `0x20`B), `0x112acd10` (27B `RET 0x4`: `0x1c`B), and `0x112acd30` (`0x118977d4 +0x00`, 27B `RET 0x4`: `0x2c`B).
- Native checked recovery (`port/recovered_types/guest32_layouts.h`, `vfs_view_map_ops.h/.c`, `test_vfs_view_map_ops.c`):
  - Fixed-width 32-bit layouts: `rome2_vfs_state_ref_block32` (`44`B), `rome2_vfs_pack_telemetry_mgr32` (`108`B), and `rome2_vfs_pack_vtable_76c0_prefix32` (`40`B).
  - Bounded helpers: `rome2_vfs_plan_u32_aligned_alloc32`, `rome2_vfs_u32_vec_plan_rebind32`, `rome2_vfs_plan_view_map_window32`, `rome2_vfs_decode_state_ref_block32`, `rome2_vfs_decode_pack_telemetry_mgr32`, `rome2_vfs_ascii_contains_bounded`, `rome2_vfs_prefetch_pages_sum32`, `rome2_vfs_pack_entry_read_archive_bit6_32`, and `rome2_vfs_deleting_dtor_size32`; non-OK status preserves caller outputs.
  - Verified **21 checks** in `test_vfs_view_map_ops.c`, **79/79** native suites on `/W4 /WX /analyze` and ASan, **57** contract tests against **247 functions, 119 globals, 24 vtables, and 253 instruction witnesses**, and clean-public Python suites; full retained evidence remains outside Git. See [progress.md](../progress.md).

## Layer 23 — Stream-State Inner Vtables `0x118977bc`–`0x118977e0`, Async View-Map / Page-Prefetch / Heap-Free Callees & Pack Telemetry Vtable `0x118976a4` Completion

- **21 Stream-State, Cache/View-Map, SysInfo/Prefetch, Heap-Free & Telemetry Contracts**:
  - **Stream-State Inner Vtables (`0x118977bc`, `0x118977c8`, `0x118977d4`, `0x118977e0`) (`7`)**:
    - `0x112acd90` (`66`B `thiscall`, `RET 0x4`): `0x118977bc` / `0x118977e0 +0x00` scalar deleting dtor for `0x10`B inner state unmapping `+0x04` view box via `[0x1172f24c]` (`UnmapViewOfFile`) and freeing view box / `this`.
    - `0x112ad140` (`105`B `thiscall`, `RET 0x4`): `0x118977d4 +0x00` scalar deleting dtor for `0x20`B inner state releasing `+0x10` extra allocation via `[0x1172f184]` (`VirtualFree` with `MEM_RELEASE=0x8000`) + `0x116835d7` before resetting vtable to `0x118977bc` and unmapping `+0x04`.
    - `0x112acfe0` (`142`B `thiscall`, `RET 0x4`): `0x118977c8 +0x00` scalar deleting dtor for `0x1c`B listener inner state notifying registered listener slots `+0x24`, freeing list nodes via `0x100fcc50`, resetting vtable to `0x118977bc`, and unmapping `+0x04`.
    - `0x112bade0` (`7`B `thiscall`, `RET`), `0x112baf00` (`27`B `thiscall`, `RET`), `0x112d9640` (`22`B `thiscall`, `RET`), `0x112d97f0` (`80`B `thiscall`, `RET`): inner data-pointer accessor `[[ECX+0x04]+0x04]`, spin-wait/`*extra_010` accessor (`closed_00d`/`eof_or_closed_00c`), cancellable mapped-view prefetch trampoline forwarding `&closed_00d` to `0x10115940`, and compressed (`0x100fcfd0`) vs uncompressed (`0x100fa6d0`) completion dispatcher setting `eof_or_closed_00c = 1`.
  - **Cache/Async View-Map, Lazy `SYSTEM_INFO`, Page Prefetch & Heap Free Callees (`5`)**:
    - `0x112c0300` (`496`B `cdecl` stack `16`): searches open-stream cache `0x112b3270()`, allocates `0x20`B ref-block (`0x1189a464`) + `0x10`B list node via `0x100fcc80` on miss, and returns retained `(stream_ptr, ref_block_ptr)` pair.
    - `0x112d91c0` (`625`B `thiscall` stack/pop `24`): queues async mapped-view request allocating `0x1c`B ref-block (`0x1189a474`, inner `0x118977bc -> 0x118977e0`), signaling `[0x1172f208]` (`ReleaseSemaphore`), and tracking `[0x12031ac0]` active / `[0x12031ac4]` high-water counts.
    - `0x10115730` (`133`B `cdecl`), `0x10115940` (`57`B `cdecl` stack `12`), `0x100fcc50` (`37`B `cdecl` stack `4`): lazy `36`B `SYSTEM_INFO` cache `[0x11af40e0]` guarded by `[0x11af4104]`, cancellable page-stride dword prefetch loop accumulating into `[0x11af426c]`, and CRT heap free dispatcher calling `0x10124e50` and optional `[0x119f3eb0]`.
  - **Pack Telemetry Vtable `0x118976a4` Slots & Singleton TLS Callbacks (`9`)**: `0x112d36f0` (`5`B `thiscall`), `0x100e80b0` (`4`B `thiscall`), `0x112badd0` (`13`B `thiscall` `TlsGetValue([0x12031ad0])`), `0x10299640` (`4`B `thiscall` `ECX+0x3c`), `0x10497c50` (`4`B `thiscall` `ECX+0x50`), `0x112e1780` (`94`B `thiscall` `RET 0x4`), `0x112e17e0` (`77`B `thiscall` `RET 0x4`), `0x112e1960` (`79`B `cdecl` `[0x119f3ed8]`), `0x112e19b0` (`80`B `cdecl` `[0x119f3edc]`).
- **Layouts, Native Helpers & Verification**:
  - Locked `rome2_vfs_state_ref_block28_32` (`28`B), `rome2_vfs_state_inner_listener28_32` (`28`B), `rome2_vfs_sys_info32` (`36`B), and `rome2_vfs_pack_vtable_76a4_32` (`28`B) in [guest32_layouts.h](../port/recovered_types/guest32_layouts.h) with `_Static_assert` verification.
  - Added 9 overflow- and range-checked C17 helpers in [vfs_state_telemetry_ops.h](../port/recovered_types/vfs_state_telemetry_ops.h) and [vfs_state_telemetry_ops.c](../port/recovered_types/vfs_state_telemetry_ops.c).
  - Verified **21 checks** in [test_vfs_state_telemetry_ops.c](../port/recovered_types/test_vfs_state_telemetry_ops.c), **80/80** native suites on `/W4 /WX /analyze` and ASan, **58** contract tests against **268 functions, 131 globals, 28 vtables, and 270 instruction witnesses**, and **886** clean-public Python tests (**286** skipped) on Python 3.14 and 3.15; full retained REA evidence (`336` records) remains outside Git. See [progress.md](../progress.md).
- Layer 24 closes stream cipher/cache/async-worker/tagged-allocator/CRT-64 callees plus full pack-entry (`0x118976c0`), stream (`0x11897790`/`0x118977ec`), and ref-block (`0x1189a414`) vtable tails across **22 functions** (`0x100fa6d0`, `0x100fcfd0`, `0x100f19f0`, `0x100ff8c0`, `0x112b3270`, `0x112b2f40`, `0x100fcc80`, `0x11684200`, `0x11684270`, `0x112d9890`, `0x112d2900`, `0x112d0bd0`, `0x112dd2f0`, `0x112c0090`, `0x112c0c40`, `0x1018ad20`, `0x108b2600`, `0x112b3190`, `0x101a0430`, `0x105cd140`, `0x112b30b0`, `0x1090b600`), **14 globals** (`0x12032b38`, `0x119e1230`, `0x12032b0c`, `0x12032b04`, `0x12032b08`, `0x119e1010`, `0x1172f1ec`, `0x119f3eb4`, `0x119f3f68`, `0x11af4288`, `0x11af4284`, `0x11af4285`, `0x119f3f57`, `0x11934484`), and vtable `0x1189a414` (`first_slot_code_identity = 0x112afcd0`):
  - Reused the closed Layer 23 REA snapshot to close `out/vfs-layer24-20261114/session.rea.json` (`367` validated records = `336` reused from Layer 23 + `31` new IDs: `13` `analyze_function` including `0x100fcc80` via validated bundle record and `3` `inspect_analysis_view` calls, `6` new `resolve_containing_procedure` + `3` reused from Layers 13/14, and `9` `read_bytes`).
  - Locked `rome2_vfs_open_cache_entry16_32`, `rome2_vfs_async_worker_ref_block56_32`, `rome2_vfs_stream_vtable_11slot32`, and `rome2_vfs_pack_vtable_76c0_full32` in [guest32_layouts.h](../port/recovered_types/guest32_layouts.h) and added **13** checked C17 helpers in [vfs_stream_completion_ops.h](../port/recovered_types/vfs_stream_completion_ops.h) and [vfs_stream_completion_ops.c](../port/recovered_types/vfs_stream_completion_ops.c) (including `0x8feb2a6740a6920eULL` 8-byte stream XOR cipher `0x100fcfd0`, CRT `__allmul`/`__aulldiv`, cancellable page copy `0x100fa6d0`, open-stream cache init/read, and pack/stream tail slot semantics).
  - Verified **21 checks** in [test_vfs_stream_completion_ops.c](../port/recovered_types/test_vfs_stream_completion_ops.c), **81/81** native suites on `/W4 /WX /analyze` and ASan, **59** contract tests against **290 functions, 145 globals, 29 vtables, and 286 instruction witnesses**, and **887** clean-public Python tests (**287** skipped) on Python 3.14 and 3.15; full retained REA evidence (`367` records) remains outside Git. See [progress.md](../progress.md).
- Layer 25 closes Win32 semaphore/file-handle box/open-file-mapping lifecycle, `std::bad_alloc` (`0x11741d78`), intrusive queue teardown (`0x112ab350`), atexit teardown (`0x11724950`), `0x11897be0` (`17/17` slots), `0x11897c24` (`+0x00`), and `0x11897c44` (`8/8` slots) across **24 functions** (`0x100f2230`, `0x100f12c0`, `0x100f2170`, `0x100f1080`, `0x100f2350`, `0x100f1a30`, `0x10104b60`, `0x100fcb00`, `0x112ab350`, `0x100f1c50`, `0x100d6770`, `0x100d6900`, `0x100f3d00`, `0x100d6560`, `0x112ad6a0`, `0x101e48d0`, `0x11724950`, `0x112acf80`, `0x112daae0`, `0x112ad6d0`, `0x112c8c60`, `0x112c0d90`, `0x112dc250`, `0x112d32b0`), **10 globals** (`0x1172f1fc`, `0x1172f278`, `0x1172f178`, `0x1172f1d8`, `0x1172f19c`, `0x1172f1b8`, `0x1172f240`, `0x1172fa00`, `0x12126348`, `0x11741d84`), **2 vtables** (`0x11741d78` -> `0x100f3820`, `0x11897c44` -> `0x112ad6d0`), and **16 instruction witnesses** (`0x112afcc0`, `0x116bd8af`, `0x11724990`, `0x100d12c0`, plus the 8 non-proc virtual/atexit slots and 4 control/ref-count witnesses):
  - Opened a clean **48-record** REA partition snapshot at `out/vfs-layer25-20261114/session.rea.json` (`13` primitive `analyze_function` entries, `3` `resource_constraint` validated bundle records + `9` `inspect_analysis_view` calls, `8` `invalid_request` targets backed by `8` `resolve_containing_procedure` + `8` `read_bytes`, and `7` extra `read_bytes`) because Layer 24 reached `532,429,932` bytes (~`507.8` MiB, near V8's `536,870,888`-byte max string limit), while retaining the **415-record** cumulative bundle outside Git alongside the `49,807,427`-byte partition bundle (`39` records referenced in `contracts.json["rea_layer25_evidence"]`).
  - Locked `rome2_vfs_win32_handle_box8_32` (`8`B), `rome2_vfs_open_file_mapping16_32` (`16`B), `rome2_vfs_bad_alloc_exc8_32` (`8`B), `rome2_vfs_pack_vtable_7be0_17slot32` (`68`B), and `rome2_vfs_pack_vtable_7c44_8slot32` (`32`B) in [guest32_layouts.h](../port/recovered_types/guest32_layouts.h) and added **15** checked C17 helpers plus the mockable `rome2_vfs_win32_handle_ops` interface in [vfs_handle_lifecycle_ops.h](../port/recovered_types/vfs_handle_lifecycle_ops.h) and [vfs_handle_lifecycle_ops.c](../port/recovered_types/vfs_handle_lifecycle_ops.c).
  - Verified **21 checks** in [test_vfs_handle_lifecycle_ops.c](../port/recovered_types/test_vfs_handle_lifecycle_ops.c), **82/82** native suites on `/W4 /WX /analyze` and ASan, **60** contract tests against **314 functions, 155 globals, 31 vtables, and 302 instruction witnesses**, and **888** clean-public Python tests (**288** skipped) on Python 3.14 and 3.15; full retained REA evidence remains outside Git. See [progress.md](../progress.md).
- Layer 26 completes the loose-file entry (`0x11897710`, `20/20` slots), pack-wrapper (`0x11897760`, `12/12` slots), buffered parent-releasing substream (`0x11897c24`, `8/8` slots), and `std::exception` / `std::bad_alloc` (`0x11741d58` / `0x11741d78`, `3/3` slots) vtables plus 4 leaf Win32/stat/SSE2-copy callees across **30 functions** (`0x112acf40`, `0x10a34b40`, `0x101d9800`, `0x112c8b90`, `0x112d0bf0`, `0x112d0d20`, `0x112daa40`, `0x101d97f0`, `0x112baeb0`, `0x112d9880`, `0x112d0bb0`, `0x112c0db0`, `0x112dd2e0`, `0x112bffe0`, `0x112ace20`, `0x10abbf90`, `0x112c9520`, `0x112c8c80`, `0x112c8c40`, `0x112c0cf0`, `0x112dc1a0`, `0x112d3290`, `0x112d5690`, `0x112d57d0`, `0x100f3820`, `0x10115df0`, `0x100f6fd0`, `0x10104cc0`, `0x1011fda0`, `0x112b43d0`), **8 globals** (`0x11741d58`, `0x11741d64`, `0x11741d78`, `0x11897718`, `0x11897760`, `0x11897c24`, `0x11897c44`, `0x11848c9c`), **3 vtables** (`0x11897760` -> `0x112ace20`, `0x11897c24` -> `0x112ad6a0`, `0x11741d58` -> `0x100f3820`), and **16 instruction witnesses**:
  - Extended the clean Layer 25 REA snapshot (`48` reused records) to `95` session records (`47` new: `20` direct `analyze_function`, `10` `invalid_request` targets backed by `10` `resolve_containing_procedure` + `10` `read_bytes(length=320)`, and `7` extra `read_bytes` calls) and merged via `import_evidence_bundle` + `rea evidence-export` into the **462-record** cumulative validated bundle outside Git.
  - Locked `rome2_vfs_loose_file_entry32` (`32`B), `rome2_vfs_buffered_substream40_32` (`40`B), `rome2_vfs_file_stat20_32` (`20`B), `rome2_vfs_loose_vtable_7710_20slot32` (`80`B), `rome2_vfs_pack_wrap_vtable_7760_12slot32` (`48`B), and `rome2_vfs_substream_vtable_7c24_8slot32` (`32`B) in [guest32_layouts.h](../port/recovered_types/guest32_layouts.h) and added **15** overflow/range-checked C17 helpers in [vfs_substream_loose_ops.h](../port/recovered_types/vfs_substream_loose_ops.h) and [vfs_substream_loose_ops.c](../port/recovered_types/vfs_substream_loose_ops.c).
  - Verified **22 checks** in [test_vfs_substream_loose_ops.c](../port/recovered_types/test_vfs_substream_loose_ops.c), **83/83** native suites on `/W4 /WX /analyze` and ASan, **61** contract tests against **344 functions, 163 globals, 34 vtables, and 318 instruction witnesses**, and **889** clean-public Python tests (**289** skipped) on Python 3.14 and 3.15; full retained REA evidence remains outside Git. See [progress.md](../progress.md).
- Layer 27 completes the dual-slot async/mapped backing view (`0x11897818`, `11/11` slots), async in-memory/cipher backing view (`0x11897844`, `9/9` slots), delegating stream adapter (`0x11897c90`, `15/15` slots) + base `0x1173db9c` vtable initializer (`0x112a9550`), and loose-file stat/path-join/string helpers called by Layer 26 `0x112bffe0` across **30 functions** (`0x112ad210`, `0x112d8f50`, `0x112dd2c0`, `0x112dabd0`, `0x112c8c30`, `0x112d98a0`, `0x112baf30`, `0x112ce900`, `0x105df630`, `0x112b31c0`, `0x112ba840`, `0x112a2090`, `0x112ab500`, `0x112d8e10`, `0x112dd2b0`, `0x112bff30`, `0x1074b430`, `0x105d0b30`, `0x105d1200`, `0x112bae20`, `0x112ad1e0`, `0x101d3b10`, `0x112c6b10`, `0x112a9550`, `0x101153f0`, `0x101154a0`, `0x10115540`, `0x101211b0`, `0x100f1720`, `0x100f3090`), **6 globals** (`0x11897818`, `0x11897844`, `0x11897c90`, `0x1173db9c`, `0x11af406c`, `0x11af407c`), **3 vtables** (`0x11897818` -> `0x112ad210`, `0x11897844` -> `0x112ace20`, `0x11897c90` -> `0x112ad1e0`), and **20 instruction witnesses**:
  - Extended the Layer 26 REA snapshot (`95` reused records) to `156` session records (`61` new: `18` direct `analyze_function`, `2` `resource_constraint` bundle records `0x100f1720` / `0x100f3090` + `6` `inspect_analysis_view` view records, `10` `invalid_request` targets backed by `10` `resolve_containing_procedure` + `10` `read_bytes(length=320)`, and `15` extra `read_bytes` calls) and merged via `import_evidence_bundle` + `rea evidence-export` into the **523-record** cumulative validated bundle outside Git.
  - Locked `rome2_vfs_dual_slot_entry32` (`16`B), `rome2_vfs_dual_slot_view32` (`84`B), `rome2_vfs_cipher_mem_view32` (`32`B), `rome2_vfs_stream_delegate_adapter32` (`20`B), and `rome2_vfs_file_stat32` (`16`B) in [guest32_layouts.h](../port/recovered_types/guest32_layouts.h) and added **24** overflow/range-checked C17 helpers in [vfs_stream_mux_async_ops.h](../port/recovered_types/vfs_stream_mux_async_ops.h) and [vfs_stream_mux_async_ops.c](../port/recovered_types/vfs_stream_mux_async_ops.c).
  - Verified `3` suites (`129` `CHECK` evaluations) in [test_vfs_stream_mux_async_ops.c](../port/recovered_types/test_vfs_stream_mux_async_ops.c), **84/84** native suites on `/W4 /WX /analyze` and ASan, **62** contract tests against **374 functions, 169 globals, 37 vtables, and 338 instruction witnesses**, and **890** clean-public Python tests (**290** skipped) on Python 3.14 and 3.15; full retained REA evidence remains outside Git. See [progress.md](../progress.md).
- Layer 28 completes both base/static VFS FileSystem vtables (`0x1189791c` 30/30 slots, `0x11897994` 13/13 slots + static initializer `0x117240b0`), `std::tr1::_Ref_count_base` (`0x1189a520` 4/4 slots), and all 11 remaining slots of active VFS FileSystem secondary interface (`0x118978e8` 13/13 slots) across **30 functions** (`0x117240b0`, `0x1018bd90`, `0x112b0810`, `0x112e14a0`, `0x102fcc90`, `0x112bbaf0`, `0x112d5bd0`, `0x1108d3b0`, `0x11002ca0`, `0x112c9550`, `0x10457110`, `0x112acfb0`, `0x112e0ed0`, `0x112ce3b0`, `0x112d2980`, `0x112d2a70`, `0x10180300`, `0x112afc90`, `0x112accb0`, `0x112bd130`, `0x112cdde0`, `0x112e10e0`, `0x112e0f30`, `0x112ce410`, `0x112d2b60`, `0x112d2bb0`, `0x112d9660`, `0x112b30e0`, `0x112cf6c0`, `0x112e3480`), **17 globals** (`0x1189791c`, `0x1189799c`, `0x118978f0`, `0x1189a520`, `0x118979c8`, `0x119e1000`, `0x12032890`, `0x1203289c`, `0x120328a0`, `0x120328c0`, `0x120328c8`, `0x120328e8`, `0x120328ec`, `0x120328f8`, `0x12032af8`, `0x12032afc`, `0x120325e0`), **2 vtables** (`0x1189791c` -> `0x100f3d00`, `0x1189a520` -> `0x112afc90`), and **22 instruction witnesses**:
  - Extended the Layer 27 REA snapshot (`156` reused records) to `216` validated session records (`60` net new IDs: `15` direct `analyze_function` procedures, `1` `resource_constraint` procedure `0x1018bd90` + `3` `inspect_analysis_view` records, `14` `invalid_request` targets paired with `resolve_containing_procedure` + `read_bytes(length=320)`, and `13` extra `read_bytes(length=128)` records covering `.rdata`/`.data` globals and helper callees `0x112b3040`, `0x112bcea0`, `0x112bcf00`, `0x112d28a0`, `0x11724620`, `0x117246d0`, `0x11724a80`) and merged via `import_evidence_bundle` + `rea evidence-export` into the **583-record** cumulative validated bundle outside Git.
  - Locked `rome2_vfs_base_fs_obj32` (`8`B), `rome2_vfs_base_fs_vtable_30slot32` (`120`B), `rome2_vfs_fs_secondary_vtable_13slot32` (`52`B), `rome2_vfs_u64_pair32` (`8`B), `rome2_vfs_entry_info32` (`32`B), `rome2_vfs_sp_ctrl_block32` (`16`B), `rome2_vfs_sp_ctrl_vtable_4slot32` (`16`B), `rome2_vfs_sp_pair32` (`8`B), `rome2_vfs_pack_wrap_singleton28_32` (`28`B), and `rome2_vfs_fs_secondary_hdr32` (`32`B) in [guest32_layouts.h](../port/recovered_types/guest32_layouts.h) and added **15** bounded C17 helpers in [vfs_fs_secondary_ops.h](../port/recovered_types/vfs_fs_secondary_ops.h) and [vfs_fs_secondary_ops.c](../port/recovered_types/vfs_fs_secondary_ops.c).
  - Verified `3` suites (`78` `CHECK` evaluations) in [test_vfs_fs_secondary_ops.c](../port/recovered_types/test_vfs_fs_secondary_ops.c), **85/85** native suites on `/W4 /WX /analyze` and ASan, **63** contract tests against **404 functions, 186 globals, 39 vtables, and 360 instruction witnesses**, and **891** clean-public Python tests (**291** skipped) on Python 3.14 and 3.15; full retained REA evidence remains outside Git. See [progress.md](../progress.md).
- Layer 29 closes the active VFS FileSystem primary interface (`0x11897870`, `30/30` slots: `26` new RET-bearing slot functions + `2` prior contracts `0x100f3d00`/`0x112c9550` + `2` tail-jump thunks `0x112beac0`/`0x112b0870`) and `6` companion TLS singleton / vector helpers across **32 functions** (`0x112e36f0`, `0x112d0720`, `0x112df040`, `0x112cf920`, `0x112b3230`, `0x112e14b0`, `0x112bbb50`, `0x112bdb10`, `0x112e4000`, `0x112bbb10`, `0x112d5bf0`, `0x112bba90`, `0x112bbaa0`, `0x112d4f00`, `0x112d4bd0`, `0x100ead40`, `0x112df270`, `0x112e3460`, `0x112e2cd0`, `0x112c8bb0`, `0x112cddd0`, `0x112c95a0`, `0x112c9430`, `0x112de350`, `0x112c00b0`, `0x112ad070`, `0x112beb10`, `0x100eb330`, `0x112d30c0`, `0x112bcf00`, `0x112bbca0`, `0x112e3c60`), **17 globals** (`0x11897870`, `0x119e0fe8`, `0x119e11b8`, `0x119e11c4`, `0x119e11d0`, `0x119e11ec`, `0x12031ad8`, `0x12031ae0`, `0x12031ae7`, `0x12032080`, `0x12032435`, `0x12032438`, `0x1203291c`, `0x12032920`, `0x12032930`, `0x120329b0`, `0x120329dc`), **1 vtable** (`0x11897870` -> `0x112beac0`), and **23 instruction witnesses**:
  - Extended the Layer 28 REA snapshot (`216` reused records) to `279` validated session records (`63` new: `12` direct `analyze_function` procedures, `20` `invalid_request` targets paired with `resolve_containing_procedure` + `read_bytes(length=320)`, and `11` extra `read_bytes` records covering `0x11897870`, tail-jump thunks `0x112beac0`/`0x112b0870`, `0x112e3f20`, `0x112d5cc0`, `0x112e1a00`, and `.data` globals) and merged via `import_evidence_bundle` + `rea evidence-export` into the **646-record** cumulative validated bundle outside Git.
  - Locked `rome2_vfs_active_fs_obj32` (`40`B), `rome2_vfs_mount_vec_header12_32` (`12`B), `rome2_vfs_root_archive_header20_32` (`20`B), `rome2_vfs_loose_table12_32` (`12`B), and `rome2_vfs_large_hash16_32` (`16`B) in [guest32_layouts.h](../port/recovered_types/guest32_layouts.h) and added bounded C17 helpers in [vfs_fs_primary_ops.h](../port/recovered_types/vfs_fs_primary_ops.h) and [vfs_fs_primary_ops.c](../port/recovered_types/vfs_fs_primary_ops.c).
  - Verified **65 checks** in [test_vfs_fs_primary_ops.c](../port/recovered_types/test_vfs_fs_primary_ops.c), **86/86** native suites on `/W4 /WX /analyze` and ASan, **64** contract tests against **436 functions, 203 globals, 40 vtables, and 383 instruction witnesses**, and **892** clean-public Python tests (**292** skipped) on Python 3.14 and 3.15; full retained REA evidence remains outside Git. See [progress.md](../progress.md).

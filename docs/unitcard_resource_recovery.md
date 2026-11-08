# Unit-card resource and XML-node setup

The native resource path now reads `Script/fauna_config.xml` from explicitly
ordered PFH4 archives, decodes its records, and creates or updates a native
unit-card owner. The supported domain is plain PFH4 types 0–4 (optionally with
per-entry timestamps), the documented XmlLite XML frontend, and the bounded
native ownership APIs. Setup can also consume the direct children of an
existing native XML node. This is a component milestone, not whole-constructor or
resource-manager equivalence.

## Setup state order

`FUN_101a97f0` releases the previous records' nested strings, clears the fauna
count at guest offset `+0x160`, then takes the explicit-node or default-resource
branch. The count-zero store at **0x101a9860** precedes the default-resource
loader call at **0x101a989b**. The original vector's backing capacity and pointer
are retained by this clear.

The existing native reload was intentionally transactional. It retained the
previous configuration if resource loading or decoding failed, so it could not
stand in for the observed setup order. The added
`rome2_owned_unit_card_setup_from_packs` validates its inputs, captures the
loading allocator, clears fauna, and then loads the default resource. A normal
load or allocation failure reports its actual stage and leaves fauna empty.
Other card fields and the retained outer capacity are preserved.

| API | Behavior on resource/configuration failure |
|---|---|
| `rome2_owned_unit_card_create_from_packs` | No new card is published. |
| `rome2_owned_unit_card_reload_from_packs` | The previous fauna remains available. |
| `rome2_owned_unit_card_setup_from_packs` | Existing fauna has already been cleared. |
| `rome2_owned_unit_card_setup_from_xml_node` | Existing fauna has already been cleared. |

Native clear publishes the empty public view before releasing nested owned
allocations so observer callbacks do not see freed records. That publication
timing is a native ownership choice; the original assembly clears its raw count
after its nested-release loop. The new API models clear-before-load order,
without claiming identical allocator callbacks or original exception behavior.

## Explicit XML-node setup

At **0x101a986a**, the original tests the node argument. Zero branches to the
default resource path at `0x101a9883`; nonzero pushes the node and calls
`0x1015e280` through the local card-pointer holder. That decoder visits every
direct child in document order. The explicit branch performs no filename or
`fauna_config` parent-name lookup.

`rome2_fauna_config_decode_node` and
`rome2_owned_unit_card_setup_from_xml_node` implement that control flow using
native XML nodes. The supplied node must belong to the supplied live document;
membership is checked by identity without dereferencing foreign nodes.
The document and its immutable views remain borrowed throughout the call.
Successful records and climate strings are deep-owned and survive document
destruction. Invalid arguments preserve the old card and allocate nothing;
later allocation failures leave fauna empty with its prior backing and capacity.
No callback reentry, concurrent source mutation or destruction is supported.

Loading uses a captured transient allocator; final records use the card owner's
independently captured allocator. An empty successful setup retains the exact
backing pointer and makes no new card-owner allocation. Nonempty setup uses the
native transactional replacement helper after clearing, so it can allocate new
backing even when prior capacity was sufficient. Original in-place allocation
and callback equivalence is not claimed. The XML-node diagnostic reports
`pack=OK`, `xml=OK`, and `selected_archive=SIZE_MAX` because this entrypoint
performs neither archive lookup nor byte parsing.

## Recovered behavior and host adapters

- `pack_resource.c` validates the complete PFH4 index and payload bounds,
  rejects duplicate matching paths, and reads the requested payload without
  extracting files. Archive priority is explicit, highest priority first.
- `native_xml.c` owns UTF-16 names and direct text, preserves document order,
  and rejects unsupported DTDs/namespaces. It uses XmlLite rather than overlaying
  the game's XML object layout. Limits are 16 MiB input, depth 128 and one million
  element nodes.
- `fauna_config.c` implements the recovered animal ordinals, first matching
  scalar keys, repeated condition/climate keys, condition masks, modulo-32-bit
  digit conversion and case-sensitive lookup. Climate strings use the observed
  independent UTF-16-unit encoding followed by ASCII folding.
- Probability decoding retains the recovered bounded decimal normalization and
  binary32 scaling order, with a private C-locale CRT conversion. Full historical
  CRT, locale and floating-point environment equivalence remains unproved.
- `unit_card_resource.c` composes these adapters with the native owning card.
  Missing resources/root and unsupported input remain explicit diagnostic
  errors. It does not fabricate successful resource I/O.

## Original-image evidence

Target: `empire.retail.dll`, 28,278,272 bytes, SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
Complete retained REA dossiers were checked against the hashes recorded in
[`contracts.json`](../port/recovered_types/contracts.json).

| Function | Observation | REA Evidence ID |
|---|---|---|
| `0x101a97f0` | Fauna clear, default resource path and root lookup, explicit-node branch | `ev_7b6863671fc50ad38a60a2a553fce559bb5e6ba704d5024df453fabab39b0995` |
| `0x1015e280` | Child iteration and holder containing the card pointer | `ev_ad7a45b5717687f2c28b079901eacb47930e8b9978ad5f204f1a7a259cc44a9e` |
| `0x10141630` | Fauna record fields, condition masks and climate append logic | `ev_b9dd73fd819f29a1558cfe618c45b8a84c63575231003d649c7787942a99a534` |
| `0x10103d10` | Independent UTF-16-unit conversion used for climate strings | `ev_16746c228920411e01586976c341703f98870f2830b2d28592cb49763b1c40de` |

The registry also identifies the integer, string comparison, XML lookup and
floating conversion helpers. It now verifies **46 complete function bodies /
stack returns, 57 global values, nine first vtable slots and 34 instruction
windows**. The loader-call, explicit-node branch and count-zero windows
authenticate the order used by the native setup APIs. These are static
observations; they do not establish that the original game executed a test.

The shared Ghidra database and canonical exports were not changed.

## Verification on 2026-11-07

- All **61 local native tests** pass in the optimized profile (including the
  recovered-types `/analyze` checks) and AddressSanitizer profile. Public CI runs
  the asset-free subset; the additional installed-asset oracle stays local.
- The original-image contract module passes all **23 Python tests**.
- A clean public worktree passes all **851 Python tests** on 3.14 and 3.15,
  with 252 expected skips for unavailable private evidence in each run.
- The resource suite performs **3,153,797 active checks**. It injects failure at
  52 factory, 46 reload and 46 setup allocation positions, each at all eight raw
  alignments. Every run destroys its handles and verifies zero live grants.
- Setup tests cover missing resources/root, malformed XML, empty configuration,
  unchanged unrelated fields, retained capacity, input validation, publication
  before release/observer callbacks, and allocator capture before a callback
  mutates the caller's policy. Separate owner/loading allocators and two-archive
  tests distinguish a missing entry (fallback) from a corrupt, unsupported or
  unreadable archive (stop). Present malformed XML, wrong-case/missing roots
  and empty configurations shadow lower-priority valid entries. These are
  explicit native resolution rules, not inferred game mount precedence.
  Existing transactional reload checks remain active.
- The XML-node suite performs **311,049 active checks**, including all nine
  decoder/loading and eight card-owner allocation-failure positions at eight
  raw alignments. It checks foreign/fabricated nodes, arbitrary parent names,
  subtree selection, deep ownership after document destruction, distinct
  allocator policies, clear callback order, retained backing on empty setup
  and unchanged unrelated fields. Every sweep ends with zero live grants.
- An independent Python PFH4/XML oracle compares all eight semantic words and
  every climate byte for both installed archives. It checks both factory and
  setup entrypoints, each archive alone and both explicit precedence orders.
  Each shipped configuration has 13 records.

Two read-only Google Argon reviews completed; the patch review reported no
confirmed defect. Argon High was the highest available installed model/effort;
the requested Max effort was rejected by the CLI. Review suggestions were
verified against the code and original evidence before adoption.

[`fauna_assets.json`](../port/recovered_types/fauna_assets.json) records only
archive/index/payload identities, offsets and semantic digests. XML payloads,
the game binaries and full local REA dossiers remain outside Git.

## Remaining work

Recover the complete game resource manager's mount/dependency/mod precedence,
the original quiet-failure and exception paths, and the original XML object ABI.
The callback at `0x112b5110` is not a standalone Ghidra procedure; the subsequent
[filename-loader recovery](xml_loader_recovery.md) follows its 20-byte adapter
into `0x112a7b60` and establishes specific read/parse failure distinctions.
Missing VFS entries, full normalization/mount policy and parser equivalence
remain open. The native explicit-node adapter above is verified independently
from retained setup/child decoder evidence. Continue the other unit-card methods
and opaque-word meanings. Complete
engine/FaceFX layouts, callable vtables, allocator/threading behavior and game
playability remain outside this milestone. See [progress.md](../progress.md).

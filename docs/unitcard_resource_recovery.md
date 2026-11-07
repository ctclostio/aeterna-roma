# Resource-backed unit-card setup

The native resource path now reads `Script/fauna_config.xml` from explicitly
ordered PFH4 archives, decodes its records, and creates or updates a native
unit-card owner. The supported domain is plain PFH4 types 0–4 (optionally with
per-entry timestamps), the documented XmlLite XML frontend, and the bounded
native ownership APIs. This is a component milestone, not whole-constructor or
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

Native clear publishes the empty public view before releasing nested owned
allocations so observer callbacks do not see freed records. That publication
timing is a native ownership choice; the original assembly clears its raw count
after its nested-release loop. The new API models clear-before-load order,
without claiming identical allocator callbacks or original exception behavior.

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
stack returns, 57 global values, nine first vtable slots and 33 instruction
windows**. The new loader-call window and the existing count-zero window
authenticate the order used by the native setup API. These are static
observations; they do not establish that the original game executed a test.

The shared Ghidra database and canonical exports were not changed.

## Verification on 2026-11-07

- All **60 local native tests** pass in the optimized profile (including the
  recovered-types `/analyze` checks) and AddressSanitizer profile. Public CI runs
  the asset-free subset; the additional installed-asset oracle stays local.
- The original-image contract module passes all **22 Python tests**.
- The resource suite performs **3,065,966 active checks**. It injects failure at
  52 factory, 46 reload and 46 setup allocation positions, each at all eight raw
  alignments. Every run destroys its handles and verifies zero live grants.
- Setup tests cover missing resources/root, malformed XML, empty configuration,
  unchanged unrelated fields, retained capacity, input validation, publication
  before clear callbacks, and allocator capture before a callback mutates the
  caller's policy. Existing transactional reload checks remain active.
- An independent Python PFH4/XML oracle compares all eight semantic words and
  every climate byte for both installed archives. It checks both factory and
  setup entrypoints, each archive alone and both explicit precedence orders.
  Each shipped configuration has 13 records.

[`fauna_assets.json`](../port/recovered_types/fauna_assets.json) records only
archive/index/payload identities, offsets and semantic digests. XML payloads,
the game binaries and full local REA dossiers remain outside Git.

## Remaining work

Recover the complete game resource manager's mount/dependency/mod precedence,
the original quiet-failure and exception paths, and direct original XML-node
setup. Continue the other unit-card methods and opaque-word meanings. Complete
engine/FaceFX layouts, callable vtables, allocator/threading behavior and game
playability remain outside this milestone. See [progress.md](../progress.md).

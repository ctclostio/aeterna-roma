# Legacy export contract

The x64 port has a lossless, hash-locked description of the original
`empire.retail.dll` export surface. The sole authority is the raw PE with
SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
Canonical Ghidra indexes are cross-checks that bind every exported target to one
`decomp_fn_*` or `decomp_g_*` identity; they are not substituted for the PE
export directory.

## Generate or verify

Regenerate the reviewed artifacts:

```powershell
python -B scripts\gen_x64_export_contract.py
```

Require byte identity without changing them:

```powershell
python -B scripts\gen_x64_export_contract.py --check
python -B scripts\test_gen_x64_export_contract.py
```

The generator pins the original DLL, canonical function index, canonical data
index, snapshot, mapping fingerprint, row counts, PE machine, ordinal base, and
DLL name. It rejects hash drift, malformed/truncated PE structures, holes,
unnamed exports, forwarders, unsafe DEF names, and missing or ambiguous
canonical joins.

## Reviewed artifacts

The checked-in lock is under `port\x64_exports`:

- `export_manifest.tsv` — one row per public name, in ordinal order, including
  name hint, original RVA/VA, section and characteristics, code/data kind,
  stable x64 target symbol, and canonical identity;
- `empire.retail.exports.def` — an ordinal-explicit linker blueprint using one
  stable right-hand-side symbol per original target and `DATA` on data exports;
- `export_contract.json` — input/artifact hashes, PE directory fields, counts,
  and generator identity.

Current accepted facts:

| Property | Value |
|---|---:|
| Named exports / EAT slots | 522 / 522 |
| Ordinal range | 1-522, no holes |
| Code rows | 493 |
| Data rows | 29 |
| Unique targets | 434 |
| Unique code / data targets | 405 / 29 |
| Duplicate-target groups | 44 |
| Names in duplicate groups | 132 |
| Alias rows beyond unique targets | 88 |
| Forwarders / unnamed exports | 0 / 0 |

`entry_point` is code export ordinal 520 at original VA `0x100edd70`.
Ordinals 521 and 522 are
`need_to_show_mod_options_notification` and `set_or_get_mod_options`.

## Legacy metadata warning

Do not generate an ABI from `pe_meta\empire.retail_exports.txt`. The legacy
`scripts\pe_info.py` indexes names by target RVA and therefore reduces this DLL
to 434 lines, overwriting 88 alias names. It also does not preserve ordinals or
code/data classification. The new manifest retains all 522 rows.

## Deliberate boundary

The DEF is not linked into the bootstrap yet. It names 405 code targets and 29
data targets for future implementations, but it does not invent prototypes,
object layouts, vtables, or storage. Old x86-decorated FaceFX names and ordinal
identity can be preserved at the PE lookup layer without implying x64 C++ ABI
compatibility.

Before a strict 522-export DLL is accepted, its finished PE must be compared
independently against this manifest:

- exact `(ordinal, name)` set and no extra names;
- name lookup equals ordinal lookup for every row;
- exact original alias equivalence relation, with `/OPT:NOICF` preventing new
  accidental folds;
- all 493 code and 29 data classifications, including import-library kind;
- runtime invocation only of typed implementations such as `entry_point`—never
  of generic fail-fast placeholders.

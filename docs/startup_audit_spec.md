# Startup initializer audit contract

The next startup milestone is an evidence-only inventory of the original x86
initializer pointer tables. It does not execute, classify as safe, translate,
or register any initializer in the x64 CRT.

## Inputs

The generator accepts exactly these required options:

```text
--dll PATH --function-index PATH --output-dir PATH [--check]
```

It uses only the Python standard library and requires Python 3.10 or newer.
The accepted production inputs are pinned byte-for-byte:

| Input | SHA-256 |
|---|---|
| `Total War Rome II/empire.retail.dll` | `d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528` |
| `src_canonical_out/empire.retail.dll/canonical_function_index.tsv` | `d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5` |

The DLL must also validate as PE32 x86 (`Machine == 0x014c`, optional-header
magic `0x010b`) with image base `0x10000000`. The declared optional header must
be at least 96 bytes, `SizeOfImage` must be nonzero and fit the PE32 address
space, and there must be 1 through 96 sections. The implementation parses
section mappings and characteristics itself and rejects raw-file overlap, RVA
mapping overlap, ranges past EOF, ranges past `SizeOfImage`, and arithmetic
overflow. Each four-byte table slot and the addressed byte of every nonzero
target must fit wholly within exactly one raw-backed section. Every nonzero
target must be in that same section's `IMAGE_SCN_MEM_EXECUTE` mapping.

The function index is tab-separated UTF-8 with LF or CRLF line endings. Its
header must contain unique `entry` and `canonical_name` columns, and every body
row must have exactly the header's field count. Blank rows and blank canonical
names fail. Canonical names cannot contain tab, CR, or LF. Entry values are
unique, exactly eight lowercase hexadecimal digits, and exact address equality
is the only permitted join. A body-range or nearest-function match is not an
exact join.

## Source-backed table definitions

`buildable/11683f08_FUN_11683f08.c` establishes the invocation order and
bounds. `buildable/116a2432___initterm_e.c` establishes that the first walker
tests each initializer's integer result, while
`buildable/116a23ed___initterm.c` establishes that the second discards each
result. The installed UCRT `corecrt_startup.h` definitions of `_PIFV` and
`_PVFV` establish the `__cdecl` calling convention. Together they give two
distinct call contracts:

1. `__initterm_e(&DAT_11739430, &DAT_11739450)` invokes
   `int (__cdecl *)(void)` cells.
2. On success, `__initterm(&DAT_1172fa04, &DAT_1173942c)` invokes
   `void (__cdecl *)(void)` cells.

All ranges are start-inclusive and end-exclusive arrays of little-endian
32-bit VAs. The audit table IDs and acceptance facts are:

| ID | Start | End | Signature | Slots | Null slots | Nonzero unique | Exact joins | Unresolved exact |
|---|---:|---:|---|---:|---|---:|---:|---:|
| `initterm_e_int` | `11739430` | `11739450` | `int __cdecl(void)` | 8 | slot 0 only | 7 | 1 | 6 |
| `initterm_void` | `1172fa04` | `1173942c` | `void __cdecl(void)` | 9,866 | slot 0 only | 9,865 | 1,110 | 8,755 |

The zero is a leading CRT sentinel, not a terminator. The last slot in each
range is nonzero. All nonzero values within each table are unique. A generator
must fail closed if any acceptance fact differs.

## Outputs

Successful generation creates exactly two owned files in `--output-dir`:

- `startup_slots.tsv`
- `startup_summary.json`

The generator owns only those two names. It preserves and ignores unrelated
directory entries. Its `.startup-audit.lock` and names beginning
`.startup-audit-txn-` are reserved transaction artifacts and make generation
or checking fail closed rather than being removed automatically.

Content is deterministic UTF-8 without a BOM, uses LF line endings, and ends
with one newline. Hexadecimal addresses are eight lowercase digits without a
prefix. `slot_index` is base 10. Rows are ordered first by invocation order
(`initterm_e_int`, then `initterm_void`) and then by ascending slot index. The
TSV has exactly 9,874 data rows (9,875 physical lines including its header).

`startup_slots.tsv` has this exact header:

```text
table\tslot_index\tslot_va\traw_target_va\tis_null\ttarget_rva\ttarget_section\ttarget_executable\texact_canonical_entry\texact_canonical_name\texact_join
```

Boolean cells are `yes` or `no`. Null rows use `00000000` for
`raw_target_va`, `yes` for `is_null`, `no` for `target_executable` and
`exact_join`, and empty target/join detail cells. Nonzero rows contain the
target RVA, PE section name, executable status, and exact canonical entry/name
when present. No nearest-symbol inference is allowed.

`startup_summary.json` uses schema `rome2-startup-audit-v1`, sorted JSON keys,
two-space indentation, and this exact key shape:

```text
generator: {sha256}
inputs: {
  dll: {byte_count, sha256},
  function_index: {byte_count, sha256}
}
invocation_order
schema
startup_slots: {data_row_count, sha256}
tables: [{
  id, start_va, end_va, signature,
  slot_count, null_count, nonzero_count, unique_nonzero_count,
  exact_join_count, unresolved_exact_count, null_indices,
  first_raw_value, last_raw_value
}]
totals: {
  slot_count, null_count, nonzero_count,
  exact_join_count, unresolved_exact_count
}
```

Input provenance never includes an absolute path. The real TSV is 660,926
bytes with SHA-256
`453de546bbbd64e858aa80cd2ce09552904098e02cb0861689c24bd21e67ff6b`.

The summary records evidence only. It must not label an initializer pure,
portable, supported, executable-on-x64, or safe.

## Failure and check behavior

All input validation and rendering occurs before either owned output is
replaced. Publication uses a cooperative exclusive lock, stages and flushes
both streams in the output directory, backs up prior files, installs the TSV
first and its hashing summary last, and verifies the installed bytes. A caught
replacement or verification failure rolls back prior byte content and presence
in reverse order. Successful publication and successful rollback clean their
transaction artifacts.

This is process-transactional, not crash-atomic: two fixed filenames cannot be
made atomically visible as one filesystem operation. Power loss, process
termination, an uncooperative writer, rollback failure, or post-commit cleanup
failure can require manual recovery. On rollback failure, the generator exits
nonzero and deliberately preserves its lock and transaction directory rather
than deleting the only recovery evidence.

Recovery is deliberately manual: preserve a copy of the reported transaction
directory, inspect its `old-*` backups and the two final paths, restore the
intended pair, verify it with `--check`, and only then remove the reserved
transaction directory and lock. The generator never guesses which mixed state
is authoritative.

`--check` is strictly read-only: it does not create the output directory or a
lock. It recomputes the two expected byte streams, requires both regular,
non-symlink output files to exist and match byte-for-byte, returns zero on a
match, and returns nonzero for a missing or changed output or a reserved
transaction artifact. It ignores unrelated entries and must not change file
contents or modification timestamps. Do not run generation and `--check`
concurrently: a read-only checker cannot participate in the publisher's
exclusive lock without changing filesystem state. Concurrent races fail safe
in ordinary use but are outside the transaction guarantee.

Unknown command-line options, unpinned inputs, malformed/truncated PE files,
overlapping or unmappable raw section ranges, non-executable nonzero targets,
malformed/duplicate index entries, and any count mismatch are hard failures.

## Generation and verification

Run from the repository root:

```powershell
python -B scripts\test_gen_startup_audit.py

python -B scripts\gen_startup_audit.py `
  --dll "Total War Rome II\empire.retail.dll" `
  --function-index "src_canonical_out\empire.retail.dll\canonical_function_index.tsv" `
  --output-dir "port\startup_audit"

python -B scripts\gen_startup_audit.py `
  --dll "Total War Rome II\empire.retail.dll" `
  --function-index "src_canonical_out\empire.retail.dll\canonical_function_index.tsv" `
  --output-dir "port\startup_audit" `
  --check
```

The checked-in implementation and tests use only the Python standard library.
Synthetic fixtures exercise low-level negative cases without weakening the
production SHA pins. Do not accept regenerated evidence unless both the test
suite and the final read-only check pass.

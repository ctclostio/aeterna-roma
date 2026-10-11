# Canonical-address decompilation export

The canonical exporter produces a stable C corpus for compilation work without
permanently changing the analyzed Ghidra project. It is the source of truth for
downstream build generation; the older name-preserving export under `src_out/`
remains useful for reverse-engineering reference only.

## Current coordination state

As of 2026-08-24, Pi/DeepSeek was deliberately suspended before this export.
That specific Pi process later disappeared without being resumed or terminated
by this workflow; its session file remains preserved. A process audit after the
final verification found no Pi, `prune_opaque.py`, or Ghidra headless writer.
The complete 63,326-function canonical export and its final fresh-process
rollback check finished successfully. Treat a continued or replacement Pi
session as a new writer: do not start it on any task that can write
`workspace/TW2` while a later export or rollback verifier is active.

The current snapshot reports 63,326 internal functions and 4,143 addressable data
symbols. Those counts and the current fingerprint are observations, not constants:
all consumers must read them from `canonical_snapshot.tsv`.

## Why names are changed in Ghidra

The old exporter emits recovered symbols directly. That is useful to an analyst,
but it is not a safe compilation identity:

- C++ qualified names can occur in function bodies while a source postprocessor
  changes only the definition.
- Overloaded methods share short names, so a textual collision suffix cannot tell
  which address a call targeted.
- Thunks and their targets can have the same recovered name.
- A change made only to a function definition does not update all of its callers.

`ExportCanonicalDecompiled.java` instead changes the Ghidra database temporarily,
before decompilation. Every non-external function is moved to the global namespace
and named `decomp_fn_<address>`. Each eligible primary data symbol outside a
function is similarly named `decomp_g_<address>`. Ghidra's decompiler then emits
the same unique identity at definitions and resolved reference sites.

The exporter first moves all selected symbols to collision-free
`__decomp_tmp_fn_*` and `__decomp_tmp_g_*` names, then assigns final canonical
names. The original name, qualified name, namespace, source type, signature,
thunk relationship, and data type metadata are retained in TSV indexes.

True external functions are not renamed. Imports therefore retain the names
needed for eventual linkage. Canonical addresses are original-binary identities;
they are not intended to be runtime addresses in the new x64 image.

## Components and fixed paths

| Component | Path or value |
|---|---|
| Batch wrapper and acceptance gate | `scripts\export_canonical_dll.bat` |
| Exporter | `scripts\ExportCanonicalDecompiled.java` |
| Fresh-process rollback verifier | `scripts\VerifyCanonicalRollback.java` |
| Ghidra project | `workspace\TW2` |
| Program | `empire.retail.dll` |
| Generated root | `src_canonical_out\empire.retail.dll` |
| Canonical C directory | `src_canonical_out\empire.retail.dll\canonical_decomp` |
| Format marker | `canonical-address-v2` |

The wrapper uses absolute paths rooted at `X:\decompilation` and invokes both
headless processes with `-noanalysis`.

## Exclusive-writer rule

Never run two Ghidra writers against `workspace/TW2`. This prohibition includes:

- parallel canonical batches, even when their numeric ranges do not overlap;
- Pi/DeepSeek analysis or symbol-application jobs;
- the legacy export/analyze scripts;
- a manual Ghidra session that can save changes;
- an exporter and a manually launched rollback verifier at the same time.

The exporter temporarily renames the complete function/data symbol set, and all
batches share the same indexes, snapshot, status files, and output directory.
Disjoint ranges therefore do not make concurrent jobs safe. Run batches strictly
sequentially through the wrapper.

Before starting a batch, confirm that no existing canonical wrapper, Ghidra
headless JVM, or decompiler child is still working on the project. A useful
read-only check in PowerShell is:

```powershell
Get-CimInstance Win32_Process |
  Where-Object {
    ($_.Name -eq 'java.exe' -and $_.CommandLine -match 'AnalyzeHeadless.*workspace.*TW2') -or
    $_.Name -eq 'decompile.exe'
  } |
  Select-Object ProcessId, ParentProcessId, Name, CommandLine
```

An empty result is required before launching the next batch. Keep Pi suspended
through the rollback-verification process as well as the export process.

## Running exports

Run the wrapper from `X:\decompilation`. Do not invoke the Java exporter directly
for normal operation, because the wrapper is what performs the mandatory
fresh-process rollback verification.

Full corpus, using default timeouts:

```powershell
cmd /c scripts\export_canonical_dll.bat
```

A zero-based, half-open batch:

```powershell
cmd /c scripts\export_canonical_dll.bat 0 5000
cmd /c scripts\export_canonical_dll.bat 5000 10000
```

The range indexes the ordered list returned by Ghidra's
`FunctionManager.getFunctions(true)` after external functions are excluded.
`batchEnd` is clamped to the function count. A negative start, an end below its
start, or a start beyond the function count is rejected.

Custom normal and retry timeouts, in seconds:

```powershell
cmd /c scripts\export_canonical_dll.bat 10000 15000 120 900
```

The wrapper accepts exactly zero, two, or four arguments:

```text
export_canonical_dll.bat [batchStart batchEnd [timeoutSeconds retryTimeoutSeconds]]
```

At the start of every invocation, it deletes the previous export and rollback
status files. This prevents an old `ok` result from being mistaken for the current
run.

## Normal and pathological retry resources

| Pass | Timeout | Payload limit | Process behavior |
|---|---:|---:|---|
| Normal | 90 seconds by default | Inherited from Ghidra's program options | Reuses the current decompiler until a timeout |
| Automatic timeout retry | 600 seconds by default | At least 512 MiB | Disposes the current interface and opens a fresh decompiler before retrying once |
| Manual pathological retry | Operator-selected positive values | At least 512 MiB on the retry pass | Run a one-function or small range through the same wrapper |

Only a genuine first-pass timeout receives the automatic high-resource retry.
Cancellation, an identity mismatch, blank C, and other incomplete results are
recorded as failures without an automatic retry.

For a pathological function, find its zero-based index in the function TSV and
rerun only that row with larger timeouts:

```powershell
$rows = Import-Csv `
  src_canonical_out\empire.retail.dll\canonical_function_index.tsv `
  -Delimiter "`t"

for ($i = 0; $i -lt $rows.Count; $i++) {
  if ($rows[$i].entry -eq '114f9210') { $i }
}

cmd /c scripts\export_canonical_dll.bat 51262 51263 300 1800
```

Replace the example range with the index actually printed by the loop. Do not
infer a batch index from the address. The current implementation has already
verified the automatic path on `decomp_fn_114f9210`: it timed out at 90 seconds,
was retried with 600 seconds and a payload increase from 50 MiB to 512 MiB, and
ended with a valid success sentinel.

After the first timeout in a batch, the replacement decompiler and its enlarged
payload setting remain in use for subsequent normal attempts in that headless
invocation. A later timeout still disposes that interface and opens another fresh
one for the long retry.

Rerunning the same range is safe. Valid files are skipped; timed-out, failed,
truncated, stale-fingerprint, or otherwise incomplete files are atomically
replaced. Never repair a failed file by manually adding an EOF sentinel.

## Output layout

```text
src_canonical_out/
└── empire.retail.dll/
    ├── canonical_decomp/
    │   ├── decomp_fn_10002070.c
    │   └── ...
    ├── canonical_function_index.tsv
    ├── canonical_data_index.tsv
    ├── canonical_snapshot.tsv
    ├── canonical_export_status.tsv
    └── canonical_rollback_status.tsv
```

All TSV metadata and C files are UTF-8. Indexes, snapshots, status records, and
function files are written through a temporary file followed by replacement. A
consumer must ignore temporary files and must never treat mere existence or a
nonzero length as proof of completion.

### Function index

`canonical_function_index.tsv` has one row for every internal function and this
schema:

```text
entry
canonical_name
original_name
original_qualified_name
symbol_id
namespace_id
source_type
signature
size
kind
body_ranges
direct_thunk_target
resolved_thunk_target
```

`kind` is `func` or `thunk`. Thunk target fields retain whether a target was
internal or external, its entry address, and its original qualified name. The
index is a pre-rename snapshot and is rewritten atomically on every batch.

### Data index

`canonical_data_index.tsv` contains eligible primary `LABEL` and `GLOBAL_VAR`
symbols outside functions:

```text
address
canonical_name
original_name
original_qualified_name
symbol_id
namespace_id
source_type
symbol_type
data_type_path
data_type_length
code_unit_length
```

This index does not claim that every `DAT_*`, `PTR_*`, or other decompiler token
has been semantically typed. It records exactly the data symbols selected for the
temporary canonical rename.

### Snapshot

`canonical_snapshot.tsv` is a single data row:

```text
format  executable_sha256  mapping_fingerprint  functions  data_symbols
```

The SHA-256 binds the export to the input executable. The mapping fingerprint
binds it to the complete function/data snapshot, not merely the current batch.

### Canonical C record

A successful file includes these identity fields before the decompiled C:

```c
// Export format: canonical-address-v2
// Mapping fingerprint: <sha256>
// Canonical function: decomp_fn_10002070
// Original function: FUN_10002070
// Entry: 0x10002070  Size: 34
// Original signature: undefined FUN_10002070(void)
// Export result: success
```

A timeout retry adds its normal/retry timeout and payload values. The exact final
logical line of a reusable file is:

```text
// Canonical export EOF: success <canonical_name> <mapping_fingerprint>
```

A failed file instead contains `Export result: timeout` or
`Export result: failed` plus `DECOMPILATION FAILED`. It has no success EOF and is
never eligible for resume skipping.

## Fingerprint and resume contract

The mapping fingerprint is SHA-256 over the format marker, executable SHA-256,
and the complete ordered metadata snapshot. Function fields include identities,
original names and signatures, namespaces, source types, body ranges, sizes, and
thunk targets. Data fields include identities, original names, namespaces, source
and symbol types, and type/code-unit lengths.

Consequences:

- A Ghidra symbol, signature, body, thunk, namespace, or selected-data change
  changes the fingerprint and invalidates every old C file for resume purposes.
- Batches from an unchanged project share one fingerprint and can safely resume
  each other's valid files.
- Batches from different fingerprints must never be combined.
- The exporter skips a file only when it contains the format marker, expected
  canonical name, current fingerprint, and the exact success EOF as its final
  logical line.
- A trailing blank line after the EOF, truncation, stale marker, wrong name, or
  wrong fingerprint makes the file incomplete and causes regeneration.

The export status is overwritten for each batch, so `export_ok` for the last
batch does not prove that every function in the corpus exists. Per-file identity
and EOF validation is the authoritative corpus-completeness check.

## Status meanings

### `canonical_export_status.tsv`

While work is in progress, the file uses this provisional schema:

```text
state  format  mapping_fingerprint  batch_start  batch_end  functions  data_symbols
```

On normal completion it is atomically replaced with the final schema:

```text
state  format  mapping_fingerprint  batch_start  batch_end  functions
data_symbols  succeeded  failed  skipped  first_pass_timeouts
recovered_timeouts  final_timeouts  other_failures  retry_max_payload_mbytes
```

| State | Meaning | May downstream consume the corpus? |
|---|---|---|
| `running` | Indexes and snapshot were written and the export transaction is active or did not finish cleanly | No |
| `export_ok` | This batch ended with zero failed decompilations | Only after rollback is `ok` and corpus-wide file validation passes |
| `export_partial` | This batch wrote one or more timeout/failed records | No; rerun the failed range |
| missing file | The exporter did not reach status creation, or the wrapper has just cleared the old result | No |

The final export row also records batch bounds, total snapshot counts,
`succeeded`, `failed`, `skipped`, first-pass/recovered/final timeout counts, other
failures, and the retry payload limit. For a completed batch:

```text
succeeded + failed + skipped == batch_end - batch_start
```

### `canonical_rollback_status.tsv`

The rollback verifier writes this schema:

```text
state  function_mismatches  data_mismatches  snapshot_mismatches
function_leaks  symbol_leaks
```

| State | Meaning |
|---|---|
| `ok` | The freshly reopened database exactly matches the pre-rename indexes and contains no temporary canonical names |
| `failed` | At least one function, data symbol, snapshot field, row count, or temporary-name leak differed |
| missing file | Rollback has not been verified for this invocation |

The rollback row reports function, data, and snapshot mismatch counts plus
function-name and symbol-name leak counts. Any nonzero count is fatal.

The batch wrapper exits zero only when all of these are true:

1. the exporter headless process exits zero;
2. export state is `export_ok`;
3. the batch has `failed == 0`;
4. the fresh verifier process exits zero;
5. rollback state is `ok` and its status file exists.

## Fresh-process rollback guarantee

Ghidra scripts run inside an outer transaction. The exporter starts a nested
transaction for temporary names and executes
`endTransaction(transaction, false)` in `finally`, including after ordinary
errors and cancellation. The outer transaction does not finish rolling back until
the exporter script returns.

For that reason, checking names inside the exporter process is insufficient. The
wrapper always starts `VerifyCanonicalRollback.java` in a second headless
invocation after the exporter returns. The verifier reopens the project and
compares it with the pre-rename indexes, including:

- function names, qualified names, IDs, namespaces, source types, signatures,
  sizes, body ranges, and thunk targets;
- data names, IDs, namespaces, source/symbol types, and type/code-unit metadata;
- executable SHA-256, format, fingerprint, and function/data counts;
- absence of all `decomp_*` and `__decomp_tmp_*` names in the reopened database.

This separate reopen plus exact comparison is the rollback acceptance guarantee.
Do not accept an export merely because the first process ended or the C files look
complete.

If the batch wrapper itself is forcibly terminated before it can launch the
verifier, keep Pi suspended and run the verifier manually before any other writer:

```powershell
cmd /c "ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat X:\decompilation\workspace TW2 -process empire.retail.dll -noanalysis -scriptPath X:\decompilation\scripts -postScript VerifyCanonicalRollback.java X:\decompilation\src_canonical_out"
```

Proceed only if that command exits zero and
`canonical_rollback_status.tsv` says `ok`. If the indexes/snapshot are missing or
the verifier reports a mismatch, treat both project and export state as
unaccepted; do not start another writer until the discrepancy is resolved.

## Downstream corpus validation

No build-skeleton, header, call-graph, or module generator may consume the
canonical directory without validating all of the following:

1. `canonical_snapshot.tsv` has exactly one data row, format
   `canonical-address-v2`, a nonblank executable hash and mapping fingerprint,
   and parseable function/data counts.
2. Function and data indexes have their exact expected headers. Address and
   canonical-name columns are unique, and their row counts equal the snapshot.
3. Every indexed function has exactly one file named
   `<canonical_name>.c` in `canonical_decomp/`; no unindexed `.c` files are
   silently included.
4. Every C file contains the expected format, canonical name, and current mapping
   fingerprint, reports success, and ends on the exact matching EOF sentinel.
   Reject `DECOMPILATION FAILED`, timeout, blank-C, and identity-mismatch records.
5. Every `decomp_fn_*` definition has the identity implied by its filename/index,
   and each direct `decomp_fn_*` call resolves to an indexed function. External
   calls may retain their ABI names.
6. Every `decomp_g_*` reference resolves to the data index. Remaining legacy data
   tokens such as `DAT_*` are a separate typing/reconstruction queue and must not
   be mistaken for canonicalized or defined storage.
7. All files share the one snapshot fingerprint. A single stale batch invalidates
   the corpus as a unit.
8. The latest completed wrapper result has export state `export_ok` and rollback
   state `ok`. Because export status is batch-local, this is necessary but not
   sufficient; the file/index checks prove full-corpus coverage.
9. Batch accounting is exact, and no temporary `*.tmp` files are treated as
   source inputs.

Downstream generators should preserve `decomp_fn_*` and `decomp_g_*` identities
verbatim. They must not repeat the old strategy of flattening qualified names or
adding collision suffixes to definitions. Human FuncID names belong in generated
metadata, comments, aliases, or export maps until a later semantics-aware rename
can update the entire graph consistently.

Only after this validation succeeds should a generator create prototypes,
translation-unit manifests, global declarations, or an x64 build tree.

## Recommended batch loop

1. Keep Pi/DeepSeek suspended and verify there is no Ghidra/decompiler process.
2. Run one batch through `export_canonical_dll.bat`.
3. Wait for both headless invocations and the wrapper to exit.
4. Require `export_ok`, `failed == 0`, wrapper exit code zero, and rollback `ok`.
5. Run the next non-overlapping range sequentially. Existing valid files in a
   repeated/overlapping range will be skipped by fingerprint and EOF.
6. Isolate final timeouts into one-function pathological retries.
7. Run the full downstream corpus validator.
8. Resume Pi only after no Ghidra writer is active and rollback remains verified.

# Process & bug audit

Date: 2026-10-11
Branch: `audit/process-hardening` (isolated worktree; does not touch `main`)
Method: empirical only — every number below was measured, not inferred.

## 1. The test suite cannot run on a clean clone

**This is the headline finding.** A fresh checkout of `main` reports:

```
Ran 832 tests — FAILED (failures=20, errors=249, skipped=17)
```

**239 of the 249 errors are a single `FileNotFoundError`** — the copyrighted
game binary `Total War Rome II/empire.retail.dll`, which `.gitignore`
excludes. They come from module- and class-level `DLL.read_bytes()` calls that
collapse whole modules into one error each.

A suite that reports 249 errors on a clean checkout cannot be used as a signal.
Anyone running it on a fresh machine sees noise and learns nothing about whether
their change broke something.

### Artifacts the suite silently requires

| Artifact | Path | Size | Why |
|---|---|---:|---|
| Game binary | `Total War Rome II/empire.retail.dll` | 27 MB | provenance pin hashing |
| Canonical export | `src_canonical_out/empire.retail.dll/` | 148 MB | pin hashing, stage hashes |
| Canonical stage | `generated/canonical/<fingerprint>/` | 199 MB | `references.tsv` pin |
| Decomp export | `src_out/empire.retail.dll/` | large | export-dependent gates |
| Swarm fixtures | `out/pi-swarm/*` | 191 MB | frozen r10 wave fixtures |

All five are gitignored. The oracle gates additionally reference **25 distinct
authority paths** across the three main artifacts.

### Fix applied (4 files, verified)

`test_pi_startup_abi_oracle_gate{,_v2,_v3,_v4}.py` all funnel authority
hashing through one module-level helper:

```python
def _pin_values(authority: str) -> tuple[str, int]:
    path = REPO_ROOT.joinpath(*Path(authority).parts)
    if not path.is_file():
        raise unittest.SkipTest(
            "declared authority is absent from this checkout: " + authority
        )
    raw = path.read_bytes()
```

A missing authority now **skips** instead of erroring. Measured effect on a
clean checkout:

| | before | after |
|---|---:|---:|
| tests run | 832 | 832 |
| failures | 20 | 20 |
| errors | 249 | **36** |
| skipped | 17 | **230** |

Test count is unchanged, so nothing was silently dropped, and no new failures
were introduced.

### The fix is provably behaviour-preserving

The guard only fires when `path.is_file()` is false; otherwise it falls through
to the original `read_bytes()`. Verified three ways:

1. **Control** — the unmodified files pass 213/213 in `main`.
2. **With all authorities present** — in the audit worktree, v1/v2/v4 run
   (155 tests, `OK`) rather than skipping.
3. **Differential** — restoring the *original* unmodified v3 into the audit
   worktree produced the identical 58 failures, proving those failures are
   environmental (absent wave fixtures), not caused by the change.

## 2. 37 of 80 test modules are not hermetic

`scripts/hermeticity_report.py` classifies modules by the artifacts they
reference:

```
modules: 80 total | 43 hermetic | 37 need local artifacts
```

The 43 hermetic modules are the realistic CI candidate set. Note the tool is
*static and conservative*: it flags references, not true hard requirements, so
modules that skip gracefully (for example `test_funcid_corpus_integrity.py`)
are over-counted. Run it with `--json` for the per-module breakdown.

## 3. Copy-paste forks with no deprecation marker

`scripts/` has accumulated versioned forks with no record of which is current:

| Family | Variants | Notes |
|---|---:|---|
| `pi_wave3_startup_abi*.json` | 9 | config payloads, 39 KB → 67 KB, same schema |
| `pi_swarm_worker*.ps1` | 5 | |
| `pi_wave3_supervisor*.ps1` | 5 | |
| `pi_wave3_tests*.ps1` | 5 | |
| `pi_startup_abi_oracle_gate*.py` | 4 | `_pin_values` is **byte-identical** in all four |

Four byte-identical copies of one 4-line function is the clearest evidence:
these are edit-and-copy, not shared code. Nothing in the repo says which
variant is authoritative.

## 4. There is no CI, and naive CI would be red

No `.github/` directory exists. Adding a workflow that runs
`unittest discover` today would fail immediately for the reasons in §1.

The realistic sequence is: land the hermeticity guards, adopt
`hermeticity_report.py` as the CI scope definition, then add CI over the 43
hermetic modules. Adding CI before that produces a permanently-red badge that
everyone learns to ignore — worse than none.

## 5. Open conflict: the terminal-transcript containment test (Track 1 decision)

Two tests have been failing on `main` since before this audit and were never
investigated:

```
FAIL test_live_cmake_and_production_exclude_candidate
     port/x64_ported/ported_100edd70_unified_entry.c
     port/x64_ported/ported_100edd70_unified_entry.h
     AssertionError: 'candidate reference on production/build surface' != []
```

The gate `test_x64_startup_100edd70_terminal_transcript_containment.py`
forbids any reference to `rome2_port_100edd70_project_terminal_transcript`
on the production surface. `ported_100edd70_unified_entry.c` calls that
function at line 92 and its header includes
`ported_100edd70_terminal_transcript.h` at line 5.

Neither file appears in `CMakeLists.txt`, so nothing is actually built — the
containment holds in practice. The file arrived with the `port/` tree in
commit `f904425` and has **no spec doc**.

This is a **milestone-boundary decision, not a bug to quietly patch**: either
the composition graduates the candidate (and the gate is retired with a
doc recording it), or the file belongs in a test-only location. Both routes
change a deliberate architectural invariant, so it is left for Track 1 to
decide rather than silently "fixed" here.

## 6. Smaller items

- `docs/funcid_report.md` still cites 5,452 as the headline count. That is
  right for its specific artifact but no longer the corpus total (9,036);
  README now carries the corpus figure, the report carries the artifact figure.
- `pi_wave3_startup_abi*.json` variants are 440 KB of accumulated config with
  no indication of the live one.

## Suggested order of work

1. Decide §5 (Track 1) — it is the only finding that blocks another track.
2. Adopt `hermeticity_report.py`; add guards to the remaining 37 modules as
   their owning agent next touches them, rather than in one bulk change that
   would collide with in-flight edits.
3. Only then add CI over the hermetic set.
4. Collapse the `_vN` forks behind one module once their owners are idle.

## 2023-10-27 - Repeated vcvars64.bat Invocation Overhead
**Learning:** In a Windows MSVC environment, calling `vcvars64.bat` is extremely expensive (0.5s - 1s per call) because it queries the registry and configures paths. Invoking it inside a tight loop or a ThreadPoolExecutor for compiling hundreds of tiny files (like `cl.exe` probe commands) causes a massive performance bottleneck, slowing down the script by minutes.
**Action:** When invoking the MSVC compiler in Python scripts via `subprocess`, run the `vcvars64.bat` setup script once, capture the environment block (using `set`), parse the resulting environment variables, and pass that dictionary via the `env` parameter to subsequent `subprocess.run` calls.

## 2024-10-24 - [Overzealous test artifacts]
**Learning:** Running test suites and profiling tools often generates temporary files in the repository. These must be explicitly cleaned up to avoid committing garbage to version control.
**Action:** Always run `git clean -fdx` or check `git status` carefully before committing changes.

## 2024-05-24 - Optimizing strip_templates with lambda removal
**Learning:** In Python `re.sub()`, using a lambda function when a static replacement string will suffice causes a significant overhead (about 28% slower).
**Action:** Replace lambda with a static string `''` in `re.sub(r'<[^<>]*>', '', txt)` to eliminate the lambda overhead.

## 2024-10-19 - Initial Analysis
**Learning:** Python tests here use the standard library `unittest` module heavily, with complex custom static gates checking reproducible build state and byte-for-byte exact decompilation metrics.
**Action:** Before optimizing anything in Python scripts, ensure we don't break reproducible test logic. This is an x86 to x64 port - memory addresses, layouts, and bytecode offsets are critical and statically checked.

## 2024-10-19 - Replacing `struct.unpack(..., bytes[a:b])` with `struct.unpack_from(..., bytes, a)`
**Learning:** Python's `struct.unpack` on a slice like `data[a:b]` copies the sub-byte string. For performance, especially in inner loops when parsing large PE or evidence files, `struct.unpack_from` is significantly faster because it operates without the intermediate slice copy. Profiling showed 40%+ overhead from slicing.
**Action:** Replace `struct.unpack` calls with `struct.unpack_from` across test files to improve performance of the test suite.

## 2024-10-23 - Python Character-by-Character String Parsing is a Massive Bottleneck
**Learning:** In Python, iterating over a large string character-by-character (using a `while` loop and indexing `text[index]`) and calling `.append(char)` on a list for every character is extremely slow. In a static gate script (`sanitize_c`), this single operation accounted for over 50% of the entire test suite's runtime (~80s out of 133s) due to millions of Python-level append calls.
**Action:** Replace character-by-character parsing with bulk string operations: locate the next token, bulk-append the text before it with `output.append(text[index:start])`, then process the token. Drive the scan with `pattern.search(text, index)` from the current position, never `re.finditer`: a `finditer` match that starts inside an already-consumed comment or literal swallows the first character of the next real token (the second comment in `/**//* x */` was lost). Find a line end with one search for either CR or LF; separate unbounded `find` calls for each rescan the rest of the file per comment and go quadratic. `scripts/test_x64_entry_policy_sanitize_c.py` keeps the original scanner as the oracle, and any change to `sanitize_c` must keep it green.

## 2024-11-04 - Native string operations outperform re.sub
**Learning:** In hot loops, replacing re.sub with split/join for whitespace removal yields a >5x performance improvement because Python's native string methods bypass regex engine overhead and execute directly in C.
**Action:** For simple character stripping and whitespace manipulation, always prioritize split, join, and replace over regular expressions.

## 2026-11-23 - SHA-pinned gate scripts are frozen evidence
**Learning:** Some gate scripts are pinned byte-for-byte by manifests, docs tables and local-only provenance tests that public CI does not run, so an edit passes CI and silently breaks the pin. Pinned today: `pi_startup_abi_oracle_gate*.py`, `pi_startup_abi_evidence_gate_v2.py`, `x64_startup_100df270_suffix_transcript_static_gate.py`, `x64_startup_100f1bb0_owned_utf16_static_gate.py`, `x64_startup_100f2750_sentinel_owned_static_gate.py`.
**Action:** Before editing any script, `git grep` the SHA-256 of its current bytes. If anything pins it, leave the file alone; a micro-optimization never justifies re-pinning evidence.

## 2026-11-23 - Settled: do not re-propose
**Learning:** `extract_strings.py` categorizes by the first subsystem in dict order that matches; a single combined alternation picks the leftmost match instead and changes the counts. Further tuning saves about 0.3s on a 28 MB binary. A regex replacement that is not exact changes behavior: two `replace` calls for `(*)` and `(**)` do not cover a pattern that accepts any number of stars, and split/strip/join around `::` also strips the ends of the string.
**Action:** Profile `scripts/run_public_tests.py` before proposing an optimization, and prove equivalence against the old code on real inputs, not just the happy path.

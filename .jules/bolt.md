## 2023-10-27 - Repeated vcvars64.bat Invocation Overhead
**Learning:** In a Windows MSVC environment, calling `vcvars64.bat` is extremely expensive (0.5s - 1s per call) because it queries the registry and configures paths. Invoking it inside a tight loop or a ThreadPoolExecutor for compiling hundreds of tiny files (like `cl.exe` probe commands) causes a massive performance bottleneck, slowing down the script by minutes.
**Action:** When invoking the MSVC compiler in Python scripts via `subprocess`, run the `vcvars64.bat` setup script once, capture the environment block (using `set`), parse the resulting environment variables, and pass that dictionary via the `env` parameter to subsequent `subprocess.run` calls.

## 2024-10-24 - [Overzealous test artifacts]
**Learning:** Running test suites and profiling tools often generates temporary files in the repository. These must be explicitly cleaned up to avoid committing garbage to version control.
**Action:** Always run `git clean -fdx` or check `git status` carefully before committing changes.

## 2024-05-19 - Regex Compilation Overhead
**Learning:** For simple string manipulations in Python (e.g., stripping whitespace or removing specific characters), preferring native string methods (`str.split()`, `str.join()`, `str.replace()`) over regular expressions (`re.sub`) avoids regex compilation and execution overhead, maximizing code performance.
**Action:** Replaced `re.sub(r"\s+", " ", value).strip()` with `" ".join(value.split())` in scripts like `pi_startup_abi_oracle_gate.py`.

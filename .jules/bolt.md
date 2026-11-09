## 2023-10-27 - Repeated vcvars64.bat Invocation Overhead
**Learning:** In a Windows MSVC environment, calling `vcvars64.bat` is extremely expensive (0.5s - 1s per call) because it queries the registry and configures paths. Invoking it inside a tight loop or a ThreadPoolExecutor for compiling hundreds of tiny files (like `cl.exe` probe commands) causes a massive performance bottleneck, slowing down the script by minutes.
**Action:** When invoking the MSVC compiler in Python scripts via `subprocess`, run the `vcvars64.bat` setup script once, capture the environment block (using `set`), parse the resulting environment variables, and pass that dictionary via the `env` parameter to subsequent `subprocess.run` calls.

## 2024-10-24 - [Overzealous test artifacts]
**Learning:** Running test suites and profiling tools often generates temporary files in the repository. These must be explicitly cleaned up to avoid committing garbage to version control.
**Action:** Always run `git clean -fdx` or check `git status` carefully before committing changes.

## 2024-11-04 - [Regex flag performance in tight loops]
**Learning:** In Python, passing `re.I` to `re.compile()` and running it in a tight loop over hundreds of thousands of lines can be significantly slower than lowercasing the target string once and running a case-sensitive regex search. Also, accessing `.items()` on a dictionary within a hot loop adds unnecessary overhead compared to pre-computing a list of tuples.
**Action:** When performing substring searches or regex matching in a hot loop (O(N*M) where N is large), pre-process the data (e.g., lowercasing strings) and pre-compute iteration structures (like lists of tuples instead of `.items()`) outside the loop to minimize per-iteration overhead.

## 2023-10-27 - Repeated vcvars64.bat Invocation Overhead
**Learning:** In a Windows MSVC environment, calling `vcvars64.bat` is extremely expensive (0.5s - 1s per call) because it queries the registry and configures paths. Invoking it inside a tight loop or a ThreadPoolExecutor for compiling hundreds of tiny files (like `cl.exe` probe commands) causes a massive performance bottleneck, slowing down the script by minutes.
**Action:** When invoking the MSVC compiler in Python scripts via `subprocess`, run the `vcvars64.bat` setup script once, capture the environment block (using `set`), parse the resulting environment variables, and pass that dictionary via the `env` parameter to subsequent `subprocess.run` calls.

## 2024-10-24 - [Overzealous test artifacts]
**Learning:** Running test suites and profiling tools often generates temporary files in the repository. These must be explicitly cleaned up to avoid committing garbage to version control.
**Action:** Always run `git clean -fdx` or check `git status` carefully before committing changes.

## 2024-03-24 - [Regex Matching Loop Optimization]
**Learning:** Checking a large number of regular expressions against strings in a loop is extremely slow in Python (taking O(N*M) where N is strings and M is patterns).
**Action:** Always prefer combining regexes into a single regex with named capture groups `re.compile('(?P<group1>pattern1)|(?P<group2>pattern2)')`. This enables O(1) matching in Python, taking advantage of the underlying C regex engine. Using `match.lastgroup` easily recovers which pattern matched.

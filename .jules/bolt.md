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
**Action:** Replace character-by-character parsing with bulk string operations. Use `re.finditer` to locate the start of interesting tokens (like comments or string literals), bulk-append the normal text between tokens using slicing `output.append(text[index:start])`, and process the token. This leverages the C-backed regex and string APIs, speeding up the function by orders of magnitude.

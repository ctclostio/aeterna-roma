## 2024-10-19 - Initial Analysis
**Learning:** Python tests here use the standard library `unittest` module heavily, with complex custom static gates checking reproducible build state and byte-for-byte exact decompilation metrics.
**Action:** Before optimizing anything in Python scripts, ensure we don't break reproducible test logic. This is an x86 to x64 port - memory addresses, layouts, and bytecode offsets are critical and statically checked.

## 2024-10-19 - Replacing `struct.unpack(..., bytes[a:b])` with `struct.unpack_from(..., bytes, a)`
**Learning:** Python's `struct.unpack` on a slice like `data[a:b]` copies the sub-byte string. For performance, especially in inner loops when parsing large PE or evidence files, `struct.unpack_from` is significantly faster because it operates without the intermediate slice copy. Profiling showed 40%+ overhead from slicing.
**Action:** Replace `struct.unpack` calls with `struct.unpack_from` across test files to improve performance of the test suite.

## 2025-02-12 - Re.search vs Compiled Regex in Tight Loops
**Learning:** Even though `re.search` caches patterns, pre-compiling multiple patterns using `re.compile()` into a dictionary and calling `.search(s)` explicitly outside of a heavy data extraction hot loop yields almost a 2x performance increase. Internal cache lookups still add up significantly.
**Action:** Always pre-compile regexes (`re.compile`) when evaluating across large collections of items (like string extraction lines from binary dumps).

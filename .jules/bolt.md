## 2024-10-24 - Pre-compiling Regex in extract_strings.py
**Learning:** In python scripts that process large binary files, regular expression compiling inside loops causes unnecessary overhead.
**Action:** Always pre-compile regular expressions outside of loops, particularly when matching against large numbers of extracted strings.

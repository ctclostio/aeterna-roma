## 2024-10-24 - [Overzealous test artifacts]
**Learning:** Running test suites and profiling tools often generates temporary files in the repository. These must be explicitly cleaned up to avoid committing garbage to version control.
**Action:** Always run `git clean -fdx` or check `git status` carefully before committing changes.

## 2024-03-24 - [Regex Matching Loop Optimization]
**Learning:** Checking a large number of regular expressions against strings in a loop is extremely slow in Python (taking O(N*M) where N is strings and M is patterns).
**Action:** Always prefer combining regexes into a single regex with named capture groups `re.compile('(?P<group1>pattern1)|(?P<group2>pattern2)')`. This enables O(1) matching in Python, taking advantage of the underlying C regex engine. Using `match.lastgroup` easily recovers which pattern matched.

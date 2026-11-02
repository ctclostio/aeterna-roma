## 2024-10-24 - [Overzealous test artifacts]
**Learning:** Running test suites and profiling tools often generates temporary files in the repository. These must be explicitly cleaned up to avoid committing garbage to version control.
**Action:** Always run `git clean -fdx` or check `git status` carefully before committing changes.

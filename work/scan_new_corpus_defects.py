#!/usr/bin/env python3
"""Quick post-export warning census for the full canonical corpus."""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DECOMP = ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_decomp"

PATTERNS = [
    ("jumptable_failure", re.compile(r"Could not recover jumptable|Could not find normalized switch")),
    ("indirect_jump_as_call", re.compile(r"Treating indirect jump as call")),
    ("type_propagation", re.compile(r"Type propagation algorithm not settling")),
    ("restart_limit", re.compile(r"Exceeded maximum restarts")),
    ("readonly_write", re.compile(r"Read-only address .* is written")),
    ("switch_case_unlabeled", re.compile(r"may not be properly labeled as switch case")),
    ("halt_baddata", re.compile(r"halt_baddata\(\)")),
    ("decompile_failed", re.compile(r"DECOMPILATION FAILED|Export result: failed|Export result: timeout")),
]


def main() -> int:
    counts = Counter()
    functions = Counter()
    files = 0
    failed_files = []
    for path in DECOMP.glob("*.c"):
        files += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        if "// Export result: success" not in text:
            failed_files.append(path.name)
        for name, pattern in PATTERNS:
            n = len(pattern.findall(text))
            if n:
                counts[name] += n
                functions[name] += 1
    print("files:", files)
    print("not success:", len(failed_files), failed_files[:5])
    for name, _ in PATTERNS:
        print(f"  {name}: {counts[name]} occurrences / {functions[name]} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

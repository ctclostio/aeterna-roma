"""Writes the lifted tier's row of the README status table from port/lifted/manifest.json.

Run it after `driver.py ledger`. scripts/test_lift_ledger.py checks that the
README holds exactly the row this module builds, so the table cannot drift
from the ledger.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "port" / "lifted" / "manifest.json"
README = ROOT / "README.md"
ROW = re.compile(r"(?m)^\| Lifted C differential tests \|.*$")


def row(manifest: dict) -> str:
    instructions, counts, trials = manifest["instructions"], manifest["status_counts"], manifest["verified_trials"]
    covered, total = instructions["covered_in_verified"], instructions["total"]
    open_rows = [f"{counts[status]:,} {text}" for status, text in (
        ("unsupported", "contain instructions that are not translated yet"),
        ("mismatch", "differ from the original on a trial"),
        ("uncomparable", "have too few comparable trials"),
        ("untested", "have not been run"),
    ) if counts[status]]
    return (
        f"| Lifted C differential tests | {covered:,} / {total:,} instructions ({100 * covered / total:.1f}%) | "
        f"Generated tier, counted apart from the handwritten one: {counts['verified']:,} of "
        f"{manifest['functions']:,} functions are translated instruction by instruction into C (`scripts/lift/`) "
        f"and match the original machine code, run natively in a debugged child process, on every comparable "
        f"deterministic trial ({trials['comparable']:,} trials, at least "
        f"{manifest['trial_parameters']['min_comparable_trials']} per function). The axis counts the instructions "
        f"those matching trials reach; {instructions['verified_functions_fully_covered']:,} functions are reached "
        f"in full and the rest are pinned only on the paths taken. "
        + (f"Not verified: {'; '.join(open_rows)}. " if open_rows else "")
        + "Callees are stubbed, so each function is checked in isolation, at raw offsets with no named types. "
        "See `docs/lifted_tier.md` and `port/lifted/manifest.json`. |"
    )


def main() -> int:
    text = README.read_text(encoding="utf-8")
    new, n = ROW.subn(lambda _: row(json.loads(MANIFEST.read_text(encoding="ascii"))), text)
    if n != 1:
        raise SystemExit(f"expected one lifted-tier row in README.md, found {n}")
    README.write_text(new, encoding="utf-8", newline="\n")
    print("README.md row " + ("updated" if new != text else "already current"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

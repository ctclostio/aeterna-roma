#!/usr/bin/env python3
"""Consistency of the committed lifted-tier ledger (docs/lifted_tier.md).

These tests need neither the game image nor a compiler. They check that the
ledger covers the function inventory row for row, that its counts are the ones
the manifest and the README state, and that it was produced by the tool sources
in this tree: a change to the lifter, the runtime or the reference without a
new run fails here.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "port" / "lifted"
CONTRACTS = ROOT / "work" / "binary_contracts"
COLUMNS = ["address", "bytes_sha256", "lift_sha256", "status", "mode", "trials", "matched", "insn_total",
           "insn_covered", "note"]
STATUSES = {"verified", "mismatch", "unsupported", "uncomparable", "untested"}
MIN_COMPARABLE = 8
INPUT_COLUMNS = ("address", "body_ranges", "sha256", "callee_pop_bytes", "return_type")


def read_tsv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


class LedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads((LEDGER / "manifest.json").read_text(encoding="ascii"))
        cls.rows = [row for name in sorted(cls.manifest["ledger"]) for row in read_tsv(LEDGER / name)]

    def test_parts_match_manifest(self) -> None:
        for name, part in self.manifest["ledger"].items():
            data = (LEDGER / name).read_bytes().replace(b"\r\n", b"\n")
            self.assertEqual(hashlib.sha256(data).hexdigest(), part["sha256"], name)
            lines = data.decode("ascii").splitlines()
            self.assertEqual(lines[0].split("\t"), COLUMNS)
            self.assertEqual(len(lines) - 1, part["rows"])
            self.assertFalse(any(line != line.rstrip() or "\t\t" in line for line in lines), name)

    def test_rows_are_the_inventory(self) -> None:
        inventory = [row for part in ("function_contracts_part1.tsv", "function_contracts_part2.tsv")
                     for row in read_tsv(CONTRACTS / part)]
        self.assertEqual(len(self.rows), self.manifest["functions"])
        self.assertEqual([(r["address"], r["bytes_sha256"]) for r in self.rows],
                         sorted((r["address"], r["sha256"]) for r in inventory))

    def test_row_fields(self) -> None:
        for row in self.rows:
            trials, matched = int(row["trials"]), int(row["matched"])
            total, covered = int(row["insn_total"]), int(row["insn_covered"])
            self.assertIn(row["status"], STATUSES, row["address"])
            self.assertLessEqual(matched, trials, row["address"])
            self.assertLessEqual(covered, total, row["address"])
            if row["status"] == "verified":
                self.assertGreaterEqual(trials, MIN_COMPARABLE, row["address"])
                self.assertEqual(matched, trials, row["address"])
                self.assertIn(row["mode"], ("fast", "step"), row["address"])
                self.assertRegex(row["lift_sha256"], r"^[0-9a-f]{64}$", row["address"])

    def test_counts_match_manifest(self) -> None:
        counts = {status: sum(1 for r in self.rows if r["status"] == status) for status in STATUSES}
        self.assertEqual(counts, self.manifest["status_counts"])
        verified = [r for r in self.rows if r["status"] == "verified"]
        self.assertEqual(self.manifest["instructions"], {
            "total": sum(int(r["insn_total"]) for r in self.rows),
            "covered_in_verified": sum(int(r["insn_covered"]) for r in verified),
            "verified_functions_fully_covered": sum(1 for r in verified if r["insn_covered"] == r["insn_total"]),
        })
        self.assertEqual(self.manifest["verified_trials"], {
            "comparable": sum(int(r["trials"]) for r in verified),
            "matched": sum(int(r["matched"]) for r in verified),
        })

    def test_ledger_was_made_by_these_sources(self) -> None:
        for name, digest in self.manifest["tool_sources"].items():
            if name.endswith(".tsv"):
                # Contract tables are pinned over the columns the tier reads; the
                # others change with every handwritten layer (batch_verify.py).
                h = hashlib.sha256()
                for row in read_tsv(ROOT / name):
                    h.update(("\t".join(row[c] for c in INPUT_COLUMNS) + "\n").encode())
                self.assertEqual(h.hexdigest(), digest, name)
                continue
            data = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest, name)
        tracked = {p.relative_to(ROOT).as_posix() for p in (ROOT / "scripts" / "lift" / "ops").glob("*.py")}
        self.assertLessEqual(tracked, self.manifest["tool_sources"].keys())

    def test_readme_row_states_the_manifest(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts" / "lift"))
        import readme_row
        self.assertIn(readme_row.row(self.manifest), (ROOT / "README.md").read_text(encoding="utf-8").splitlines())


if __name__ == "__main__":
    unittest.main()

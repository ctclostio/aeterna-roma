#!/usr/bin/env python3
"""The live-run milestone ladder (scripts/lift/milestones.py) and its README row.

Needs neither the game nor a compiler: the committed ladder must be well formed, a ladder (no rung held above
one that is not), and the README must hold exactly the row the ladder gives.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lift"))
import milestones  # noqa: E402


class LadderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ladder = json.loads(milestones.LADDER.read_text(encoding="utf-8"))

    def test_rungs_are_the_declared_ones(self) -> None:
        self.assertEqual([(r["id"], r["title"]) for r in self.ladder["rungs"]], [(r[0], r[1]) for r in milestones.RUNGS])

    def test_it_is_a_ladder(self) -> None:
        reached = [r["reached"] for r in self.ladder["rungs"]]
        self.assertEqual(reached, sorted(reached, reverse=True), "a rung is reached above one that is not")
        for r in self.ladder["rungs"]:
            self.assertEqual(r["reached"], r["reached"] and r["evidence"] is not None, r["id"])
            self.assertFalse(r["compared"] and not r["reached"], r["id"])

    def test_a_rung_without_a_rule_is_not_reached(self) -> None:
        for (key, _, _, rule, _), r in zip(milestones.RUNGS, self.ladder["rungs"]):
            if rule is None:
                self.assertFalse(r["reached"] or r["compared"], key)

    def test_readme_row(self) -> None:
        found = milestones.ROW.search(milestones.README.read_text(encoding="utf-8"))
        self.assertIsNotNone(found, "README.md has no 'Live x64 run milestones' row")
        self.assertEqual(found.group(0), milestones.row(self.ladder))

    def test_rules(self) -> None:
        log = ("REACHED: DLL entry returned 1 for DLL_PROCESS_ATTACH (x)\nlauncher: blocks 1\n"
               "imports called: CreateWindowExW=1 IDXGIFactory1#12=2 ID3D11Device#3=0\nSTOP: here\n")
        calls = {"CreateWindowExW": 1, "IDXGIFactory1#12": 2, "ID3D11Device#3": 0}
        got = {key: rule(log, calls) for key, _, _, rule, _ in milestones.RUNGS if rule}
        self.assertTrue(got["dll_init"] and got["entry_point"] and got["adapters"] and got["window"])
        self.assertIsNone(got["vfs"])
        self.assertIsNone(got["device"], "a slot counted 0 times is not a call")
        self.assertIsNone(got["present"])


if __name__ == "__main__":
    unittest.main()

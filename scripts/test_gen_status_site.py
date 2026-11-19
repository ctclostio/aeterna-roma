#!/usr/bin/env python3
"""Tests for the status-page generator's source parsers and SVG cards."""
from __future__ import annotations

import json
import unittest
import xml.etree.ElementTree as ET

import gen_status_site as g

README = """\
## Progress tracker

| Axis | Current state | What it means |
| --- | ---: | --- |
| Canonical decompiler export | 10 / 10 (100%) | All exported. See `docs/x.md`. |
| Function identification | 2 / 10 (20.0%) | Named across `work/*.tsv`. |
| Decompiler-warning triage | 9 warnings / 3 functions | Mostly dispatch. |
| Playable | <1% (planning estimate) | Nothing integrated. |

- [x] Done item
- [~] Partial **item**. Long tail note.
- [ ] Open <item> → `docs/y.md`
- [ ] RTTI class recovery → headers
"""


class ParserTests(unittest.TestCase):
    def test_tracker_rows(self) -> None:
        rows = g.parse_tracker(README)
        self.assertEqual([r["axis"] for r in rows], [
            "Canonical decompiler export", "Function identification",
            "Decompiler-warning triage", "Playable"])
        self.assertEqual((rows[0]["done"], rows[0]["total"], rows[0]["pct"]), (10, 10, 100.0))
        self.assertIsNone(rows[2]["pct"])
        self.assertTrue(rows[3]["below"])
        self.assertEqual(rows[0]["meaning_html"], "All exported.")

    def test_checklist_escapes_and_trims(self) -> None:
        checklist = g.parse_checklist(README)
        self.assertEqual(checklist["done"], 1)
        self.assertEqual([o["html"] for o in checklist["open"]], [
            "Partial <strong>item</strong>.", "Open &lt;item&gt;", "RTTI class recovery → headers"])
        self.assertTrue(checklist["open"][0]["partial"])

    def test_progress_takes_latest_counts(self) -> None:
        progress = (
            "### Layer 1 — old\nVerified **10/10** CTest, **5** contract tests, **90**\n"
            "  public Python tests (`9` skipped).\n\n### Remaining work\n\n1. First thing. More.\n"
            "2. Second `x`.\n\n### Layer 2: new\nVerified **12/12** native CTest suites, **6** contract\n"
            "tests, and **95** clean-public Python tests (**11** skipped); **40** cumulative.\n")
        parsed = g.parse_progress(progress)
        self.assertEqual(parsed["ctest"], {"passed": 12, "total": 12})
        self.assertEqual(parsed["contract_tests"], 6)
        self.assertEqual(parsed["python_tests"], {"run": 95, "skipped": 11})
        self.assertEqual(parsed["rea_records"], 40)
        self.assertEqual(parsed["latest_heading"], "Layer 2: new")
        self.assertEqual(parsed["remaining"], ["First thing.", "Second <code>x</code>."])


class RepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.status = g.build_status()

    def test_counts_match_contracts(self) -> None:
        contracts = json.loads((g.ROOT / g.CONTRACTS).read_text(encoding="utf-8"))
        for key in g.COUNTED:
            self.assertEqual(self.status["contracts"][key], len(contracts[key]))
        self.assertTrue(self.status["tracker"])
        layers = [row["layer"] for row in self.status["history"]]
        self.assertEqual(layers, sorted(set(layers)))

    def test_cards_are_well_formed_svg(self) -> None:
        for theme in g.THEMES:
            root = ET.fromstring(g.render_card(self.status, theme))
            self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")


if __name__ == "__main__":
    unittest.main()

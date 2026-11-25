#!/usr/bin/env python3
"""Tests for the status-page generator's source parsers and SVG cards."""
from __future__ import annotations

import json
import unittest
import xml.etree.ElementTree as ET

import gen_status_site as g

README = """\
# Project

## Status

| Axis | Current state | What it means |
| --- | ---: | --- |
| Canonical decompiler export | 10 / 10 (100%) | All exported. See `docs/x.md`. |
| Function identification | 2 / 10 (20.0%) | Named across `work/*.tsv`. |
| Decompiler-warning triage | 9 warnings / 3 functions | Mostly dispatch. |
| Playable | <1% (planning estimate) | Nothing integrated. |

Ledger link.

## Open work

- **Next milestone:** not frozen. Past the
  hard stops lie `0x1`.
- **Unit <cards>:** finish **ownership**.

## Getting started
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

    def test_open_work_escapes_and_joins_lines(self) -> None:
        self.assertEqual(g.parse_open_work(README), [
            {"label": "Next milestone", "html": "not frozen. Past the hard stops lie <code>0x1</code>."},
            {"label": "Unit <cards>", "html": "finish <strong>ownership</strong>."},
        ])

    def test_progress_takes_latest_counts(self) -> None:
        progress = (
            "# Ledger\n\n## x64 port milestones\n\n- [x] One\n  more\n- [x] Two\n\n"
            "## Type-recovery layers\n\n- [x] not a milestone\n\n"
            "### Layer 1 — old (2026-01-01)\nVerified **10/10** CTest, **5** contract tests, **90**\n"
            "  public Python tests (`9` skipped).\n\n"
            "### Layer 2 — new (2026-01-02)\nVerified **12/12** native CTest suites, **6** contract\n"
            "tests, and **95** clean-public Python tests (**11** skipped); **40** cumulative.\n")
        parsed = g.parse_progress(progress)
        self.assertEqual(parsed["port_milestones"], 2)
        self.assertEqual(parsed["ctest"], {"passed": 12, "total": 12})
        self.assertEqual(parsed["contract_tests"], 6)
        self.assertEqual(parsed["python_tests"], {"run": 95, "skipped": 11})
        self.assertEqual(parsed["rea_records"], 40)
        self.assertEqual(parsed["latest_heading"], "Layer 2 — new (2026-01-02)")


class RepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.status = g.build_status()

    def test_counts_match_contracts(self) -> None:
        contracts = json.loads((g.ROOT / g.CONTRACTS).read_text(encoding="utf-8"))
        for key in g.COUNTED:
            self.assertEqual(self.status["contracts"][key], len(contracts[key]))
        self.assertTrue(self.status["tracker"])
        self.assertTrue(self.status["open_work"])
        self.assertGreater(self.status["progress"]["port_milestones"], 0)
        layers = [row["layer"] for row in self.status["history"]]
        self.assertEqual(layers, sorted(set(layers)))

    def test_lifted_counts_match_ledger(self) -> None:
        manifest = json.loads((g.ROOT / g.LIFTED / "manifest.json").read_text(encoding="ascii"))
        lifted = self.status["lifted"]
        self.assertEqual(lifted["functions"], manifest["functions"])
        self.assertEqual(lifted["verified"], manifest["status_counts"]["verified"])
        self.assertEqual(lifted["pinned"], lifted["typed"] + lifted["lifted_only"])
        self.assertLessEqual(lifted["typed"], self.status["contracts"]["functions"])
        self.assertLessEqual(lifted["pinned"], lifted["functions"])
        row = next(r for r in g.card_rows(self.status) if r[3] is not None)
        self.assertEqual(row[0], "Functions pinned with tests")
        self.assertLess(row[3], row[2])

    def test_cards_are_well_formed_svg(self) -> None:
        for theme in g.THEMES:
            root = ET.fromstring(g.render_card(self.status, theme))
            self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")


if __name__ == "__main__":
    unittest.main()

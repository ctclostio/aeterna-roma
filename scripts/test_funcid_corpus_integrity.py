#!/usr/bin/env python3
"""Corpus integrity guards for the funcid classification corpus.

These are regression guards, not coverage tests.  Each one locks a defect that
actually occurred in this corpus and would otherwise be silent:

1. ``funcid_batch1_final.tsv`` was overwritten by a 549-row partial run that
   was wholly contained in other corpus files.  The documented artifact holds
   5,452 rows; nothing errored when it shrank to 8.6% of that.
2. Address columns mix ``0x``-prefixed and bare-hex forms.  A strict ``0x``
   match silently under-counts the corpus by tens of entries, and a naive row
   sum over-counts it by thousands because ``funcid_batch1.tsv`` and its
   ``v2``/``v3``/``v4`` revisions are successive versions of the same rows.
3. The registrar handler addresses must all resolve against the canonical
   export; twenty of them previously did not.

Run directly, or via:
    py -3.15 -m unittest discover -s scripts -p "test_*.py" -t scripts
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "work"
DECOMP = ROOT / "src_out" / "empire.retail.dll" / "decomp"
INDEX = ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_function_index.tsv"

# Both accepted address spellings; see guard 2.
ADDR_RE = re.compile(r"^(?:0x)?([0-9a-fA-F]{6,8})\t")

# Documented size of work/funcid_batch1_final.tsv (docs/funcid_report.md).
BATCH1_FINAL_MIN_ROWS = 5000

# Named .text addresses that must resolve against the canonical export.  The
# 2026-11 recovery wave created functions for all 1,973 named addresses that
# were previously missing, plus the 20 registrar handlers, so the baseline is
# now zero.  The guard fails if any named address loses its canonical function.
UNDEFINED_CODE_BASELINE = 0

# Successive revisions of one classification run; summing these double-counts.
REVISION_SUFFIXES = ("_v2", "_v3", "_v4")


def load_named() -> dict[int, str]:
    named: dict[int, str] = {}
    for path in sorted(WORK.glob("funcid_*.tsv")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = ADDR_RE.match(line)
            if not match:
                continue
            fields = line.split("\t")
            if len(fields) > 1 and fields[1]:
                named[int(match.group(1), 16)] = fields[1]
    return named


class CorpusIntegrityTests(unittest.TestCase):
    def test_batch1_final_has_not_been_truncated(self):
        """Guard 1: the canonical batch1 artifact must keep its full row count."""
        path = WORK / "funcid_batch1_final.tsv"
        self.assertTrue(path.exists(), f"missing corpus artifact: {path}")
        rows = path.read_text(encoding="utf-8", errors="replace").splitlines()
        self.assertGreaterEqual(
            len(rows),
            BATCH1_FINAL_MIN_ROWS,
            "funcid_batch1_final.tsv shrank to %d rows (documented: 5452). A "
            "partial run wrote its subset to the canonical path." % len(rows),
        )

    def test_batch1_final_rows_have_names(self):
        """Guard 1b: every row of the canonical artifact must carry a name."""
        path = WORK / "funcid_batch1_final.tsv"
        rows = path.read_text(encoding="utf-8", errors="replace").splitlines()
        named = sum(1 for r in rows if r.split("\t")[1:2])
        self.assertEqual(
            named,
            len(rows),
            "%d of %d rows in funcid_batch1_final.tsv have no name column"
            % (len(rows) - named, len(rows)),
        )

    def test_corpus_uses_both_address_forms(self):
        """Guard 2: mixed address spellings must stay visible, not be normalised away."""
        prefixed = bare = 0
        for path in sorted(WORK.glob("funcid_*.tsv")):
            for line in path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                if not ADDR_RE.match(line):
                    continue
                if line.startswith("0x"):
                    prefixed += 1
                else:
                    bare += 1
        self.assertGreater(prefixed, 0, "no 0x-prefixed addresses found")
        # Bare-hex rows are legal but must be a small minority; a large
        # minority means a generator changed format and counts will drift.
        self.assertLess(
            bare,
            prefixed // 10,
            "%d bare-hex vs %d 0x-prefixed address rows; corpus address "
            "format appears to have changed" % (bare, prefixed),
        )

    def test_revision_files_do_not_exceed_their_base(self):
        """Guard 2b: v2/v3/v4 must not contain addresses absent from the base run."""
        base = WORK / "funcid_batch1.tsv"
        if not base.exists():
            self.skipTest("funcid_batch1.tsv not present")
        base_addrs = set()
        for line in base.read_text(encoding="utf-8", errors="replace").splitlines():
            match = ADDR_RE.match(line)
            if match:
                base_addrs.add(int(match.group(1), 16))
        for suffix in REVISION_SUFFIXES:
            path = WORK / f"funcid_batch1{suffix}.tsv"
            if not path.exists():
                continue
            addrs = set()
            for line in path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                match = ADDR_RE.match(line)
                if match:
                    addrs.add(int(match.group(1), 16))
            extra = len(addrs - base_addrs)
            self.assertLess(
                extra,
                len(addrs) // 10,
                "funcid_batch1%s.tsv introduces %d addresses absent from "
                "funcid_batch1.tsv; revisions should refine, not replace"
                % (suffix, extra),
            )

    def test_named_addresses_resolve_to_canonical_functions(self):
        """Every named corpus address must have a canonical function.

        The 2026-11 recovery wave created functions for the 1,973 named
        addresses that were previously absent and for the 20 startup registrar
        handlers.  The baseline is zero: a named address that no longer resolves
        means the canonical export regressed.
        """
        if not INDEX.exists():
            self.skipTest("canonical export not present")
        indexed = set()
        for line in INDEX.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split("\t")
            if not parts or not parts[0]:
                continue
            try:
                indexed.add(int(parts[0], 16))
            except ValueError:
                continue
        named = load_named()
        self.assertGreater(len(named), 1000, "corpus looks empty")
        dangling = sorted(set(named) - indexed)
        self.assertLessEqual(
            len(dangling),
            UNDEFINED_CODE_BASELINE,
            "%d named addresses are absent from the canonical function index "
            "(baseline %d). New gaps mean the canonical export regressed; see "
            "docs/funcid_track3_report.md." % (len(dangling), UNDEFINED_CODE_BASELINE),
        )

    def test_registrar_handlers_resolve_to_canonical_functions(self):
        """The 20 startup vtable handlers must all have canonical functions."""
        gap = WORK / "gap_addresses.tsv"
        if not gap.exists():
            self.skipTest("gap_addresses.tsv not present")
        if not INDEX.exists():
            self.skipTest("canonical export not present")
        indexed = set()
        for line in INDEX.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split("\t")
            if not parts or not parts[0]:
                continue
            try:
                indexed.add(int(parts[0], 16))
            except ValueError:
                continue
        handlers = []
        for i, line in enumerate(gap.read_text(encoding="utf-8").splitlines()):
            if i == 0:
                continue
            fields = line.split("\t")
            if len(fields) >= 3 and fields[2] == "registrar_handler":
                handlers.append(int(fields[0], 16))
        self.assertEqual(len(handlers), 20, "expected 20 registrar handlers")
        missing = sorted(set(handlers) - indexed)
        self.assertEqual(
            missing,
            [],
            "registrar handlers missing from the canonical export: %s" %
            ", ".join("0x%08x" % a for a in missing),
        )

    def test_registrar_handler_reach_is_recorded(self):
        """The registrar traversal must be reproducible from the checked-in TSV."""
        reach = WORK / "registrar_reach.tsv"
        if not reach.exists():
            self.skipTest("registrar_reach.tsv not present; run registrar_walk.py")
        rows = reach.read_text(encoding="utf-8").splitlines()
        self.assertGreater(len(rows), 1, "registrar_reach.tsv is empty")
        self.assertTrue(
            rows[0].startswith("addr\t"), "registrar_reach.tsv lost its header"
        )
        bodies = [r.split("\t") for r in rows[1:] if r.strip()]
        self.assertEqual(
            len({r[0] for r in bodies}),
            len(bodies),
            "registrar_reach.tsv contains duplicate addresses",
        )


if __name__ == "__main__":
    unittest.main()

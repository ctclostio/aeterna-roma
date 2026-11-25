#!/usr/bin/env python3
"""Tests for the lifted tier's batch comparison and driver helpers.

They exercise the pure decision logic (trial comparison, function status,
job-file handling, trace differences) and need neither the game image nor a
compiler. The end-to-end behaviour is covered by scripts/lift/selftest_e2e.py.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lift"))

try:
    import batch_verify as bv
    import driver
    from build_batch import FunctionInfo
except ImportError as error:  # capstone is not installed everywhere
    bv = driver = FunctionInfo = None
    IMPORT_ERROR = str(error)
else:
    IMPORT_ERROR = ""

SEEDS = list(range(100, 116))


def line(status=0, tkind=1, a=0xDEAD, b=0, digest="00000000000000aa", steps=0) -> "bv.Line":
    text = f"10001000 1 0 {status} {tkind} {a:x} {b:x} {digest} {steps}"
    return bv.Line(status, tkind, a, b, digest, steps, text)


@unittest.skipIf(bv is None, f"lifted-tier modules unavailable: {IMPORT_ERROR}")
class CompareTest(unittest.TestCase):
    def test_equal_records_match(self) -> None:
        self.assertEqual(bv.compare(line(), line()), "match")

    def test_every_field_of_the_record_is_compared(self) -> None:
        for change in ({"tkind": 2}, {"a": 0xBEEF}, {"b": 1}, {"digest": "00000000000000ab"}, {"steps": 3}):
            with self.subTest(change=change):
                self.assertEqual(bv.compare(line(), line(**change)), "mismatch")

    def test_reference_exclusions_come_first(self) -> None:
        self.assertEqual(bv.compare(line(status=bv.S_TIMEOUT), line(status=bv.S_FOREIGN)), "ref_timeout")
        self.assertEqual(bv.compare(line(status=bv.S_HARNESS), None), "ref_harness")

    def test_lifted_exclusions(self) -> None:
        for status, reason in ((bv.S_FOREIGN, "lift_foreign"), (bv.S_BUDGET, "lift_budget"),
                               (bv.S_UNSUPPORTED, "lift_unsupported"), (bv.S_HARNESS, "lift_harness")):
            self.assertEqual(bv.compare(line(), line(status=status)), reason)

    def test_a_missing_line_is_not_a_match(self) -> None:
        self.assertEqual(bv.compare(None, line()), "ref_missing")
        self.assertEqual(bv.compare(line(), None), "lift_missing")


@unittest.skipIf(bv is None, f"lifted-tier modules unavailable: {IMPORT_ERROR}")
class ClassifyTest(unittest.TestCase):
    def info(self, unsupported=()) -> "FunctionInfo":
        return FunctionInfo(entry=0x10001000, n_insn=10, lift_sha256="ab" * 32, unsupported=list(unsupported))

    def classify(self, fast, step=None, at_budget=(), unsupported=()):
        return bv.classify(0x10001000, self.info(unsupported), SEEDS, fast, step or {}, set(at_budget))

    def test_all_fast_trials_match(self) -> None:
        row = self.classify({s: "match" for s in SEEDS})
        self.assertEqual((row["status"], row["mode"], row["trials"], row["matched"]), ("verified", "fast", 16, 16))

    def test_eight_comparable_trials_are_enough(self) -> None:
        fast = {s: "match" if i < 8 else "ref_timeout" for i, s in enumerate(SEEDS)}
        row = self.classify(fast)
        self.assertEqual((row["status"], row["trials"]), ("verified", 8))
        self.assertEqual(row["excluded_fast"], {"ref_timeout": 8})

    def test_seven_comparable_trials_are_not(self) -> None:
        fast = {s: "match" if i < 7 else "lift_foreign" for i, s in enumerate(SEEDS)}
        step = {s: "lift_foreign" for s in SEEDS}
        row = self.classify(fast, step)
        self.assertEqual(row["status"], "uncomparable")
        self.assertIn("lift_foreign=16", row["note"])

    def test_step_retry_verifies(self) -> None:
        fast = {s: "ref_timeout" for s in SEEDS}
        step = {s: "match" for s in SEEDS}
        row = self.classify(fast, step, at_budget=SEEDS)
        self.assertEqual((row["status"], row["mode"], row["trials"], row["matched"]), ("verified", "step", 16, 16))

    def test_one_fast_mismatch_is_a_mismatch(self) -> None:
        fast = {s: "match" for s in SEEDS}
        fast[SEEDS[3]] = "mismatch"
        row = self.classify(fast, {SEEDS[3]: "mismatch"})
        self.assertEqual((row["status"], row["trials"], row["matched"]), ("mismatch", 16, 15))

    def test_fast_difference_resolved_by_a_complete_step_trial(self) -> None:
        fast = {s: "match" for s in SEEDS}
        fast[SEEDS[0]] = "mismatch"
        row = self.classify(fast, {SEEDS[0]: "match"})
        self.assertEqual((row["status"], row["mode"], row["trials"], row["matched"]), ("verified", "fast", 16, 16))
        self.assertEqual(row["resolved_in_step"], 1)

    def test_step_trial_that_stops_at_its_budget_resolves_nothing(self) -> None:
        fast = {s: "match" for s in SEEDS}
        fast[SEEDS[0]] = "mismatch"
        row = self.classify(fast, {SEEDS[0]: "match"}, at_budget=[SEEDS[0]])
        self.assertEqual(row["status"], "mismatch")
        self.assertEqual(row["resolved_in_step"], 0)

    def test_excluded_step_trial_resolves_nothing(self) -> None:
        fast = {s: "match" for s in SEEDS}
        fast[SEEDS[0]] = "mismatch"
        self.assertEqual(self.classify(fast, {SEEDS[0]: "lift_foreign"})["status"], "mismatch")

    def test_step_mismatch_overrides_matching_fast_trials(self) -> None:
        fast = {s: "match" if i < 4 else "ref_timeout" for i, s in enumerate(SEEDS)}
        step = {s: "match" for s in SEEDS}
        step[SEEDS[9]] = "mismatch"
        self.assertEqual(self.classify(fast, step, at_budget=SEEDS)["status"], "mismatch")

    def test_untranslated_instruction_wins_over_matching_trials(self) -> None:
        row = self.classify({s: "match" for s in SEEDS},
                            unsupported=[(0x10001004, "vpxor", "c5f9efc0", "VEX encoding")])
        self.assertEqual(row["status"], "unsupported")
        self.assertIn("vpxor", row["note"])


@unittest.skipIf(bv is None, f"lifted-tier modules unavailable: {IMPORT_ERROR}")
class FilesTest(unittest.TestCase):
    JOB = ("F 10001000 1 1 0 0\nR 10001000 10001010\nC 10001008 4 1\nT 5 0 0\nT 6 0 0\nE\n"
           "F 10002000 1 0 1 1\nR 10002000 10002004\nI 10002000 2 1\nW 10002004 10002010\nT 7 0 0\nE\n")

    def test_job_round_trip_with_new_trials(self) -> None:
        heads = bv.split_jobs(self.JOB)
        self.assertEqual(sorted(heads), [0x10001000, 0x10002000])
        self.assertEqual(bv.job_text(heads, {0x10001000: [(5, 0, 0), (6, 0, 0)], 0x10002000: [(7, 0, 0)]}), self.JOB)
        step = bv.job_text(heads, {0x10002000: [(7, 1, 4000)], 0x10001000: []})
        self.assertEqual(step, "F 10002000 1 0 1 1\nR 10002000 10002004\nI 10002000 2 1\nW 10002004 10002010\n"
                               "T 7 1 4000\nE\n")

    def test_results_and_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.out"
            out.write_text("10001000 5 0 0 1 dead 0 00000000000000aa 0\n10001000 6 1 1 0 0 0 0000000000000000 0\n",
                           encoding="ascii")
            got = bv.read_results(out)
            self.assertEqual(got[(0x10001000, 5, 0)].record, (1, 0xDEAD, 0, "00000000000000aa", 0))
            self.assertEqual(got[(0x10001000, 6, 1)].status, bv.S_TIMEOUT)
            cov = Path(tmp) / "r.cov"
            cov.write_text("T 10001000 5 0 9 3 0502\nF 10001000 10 3 0502\nT 10001000 6 0 0 0 \n", encoding="ascii")
            bitmaps = bv.read_coverage(cov)
            self.assertEqual(bitmaps[(0x10001000, 5, 0)], 0b10_0000_0101)
            self.assertEqual(bitmaps[(0x10001000, 6, 0)], 0)

    def test_batch_key_depends_on_every_input(self) -> None:
        base = bv.batch_key("t", [1, 2], bv.Params())
        self.assertEqual(base, bv.batch_key("t", [1, 2], bv.Params()))
        self.assertNotEqual(base, bv.batch_key("u", [1, 2], bv.Params()))
        self.assertNotEqual(base, bv.batch_key("t", [1, 3], bv.Params()))
        self.assertNotEqual(base, bv.batch_key("t", [1, 2], bv.Params(seeds=8)))


@unittest.skipIf(driver is None, f"lifted-tier modules unavailable: {IMPORT_ERROR}")
class MergeTest(unittest.TestCase):
    def result(self, seeds: int, finished: float, status: str) -> dict:
        return {"params": {"seeds": seeds}, "finished": finished,
                "functions": [{"address": "10001000", "status": status}]}

    def merged(self, *results: dict) -> dict:
        return driver.rows_by_address(driver.merge_order(list(results)))[0x10001000]

    def test_second_round_replaces_the_first(self) -> None:
        row = self.merged(self.result(64, 1.0, "verified"), self.result(16, 2.0, "uncomparable"))
        self.assertEqual((row["status"], row["seeds"]), ("verified", 64))

    def test_newer_result_of_the_same_round_wins(self) -> None:
        row = self.merged(self.result(16, 2.0, "verified"), self.result(16, 1.0, "uncomparable"))
        self.assertEqual(row["status"], "verified")

    def test_a_mismatch_is_never_replaced(self) -> None:
        row = self.merged(self.result(64, 1.0, "verified"), self.result(16, 2.0, "mismatch"))
        self.assertEqual((row["status"], row["seeds"]), ("mismatch", 16))

    def test_second_round_needs_more_seeds_than_the_first(self) -> None:
        self.assertEqual(driver.retry_params(bv.Params(), 64), bv.Params(seeds=64))
        self.assertIsNone(driver.retry_params(bv.Params(), 0))
        self.assertIsNone(driver.retry_params(bv.Params(seeds=64), 64))


@unittest.skipIf(driver is None, f"lifted-tier modules unavailable: {IMPORT_ERROR}")
class TraceTest(unittest.TestCase):
    REF = ("trial 10001000 00000005 1\npage 5feff000\nstep 0 10001000 eax=00000001 df=0\n"
           "step 1 10001002 eax=00000002 df=0\nterm kind=1 a=0000dead b=00000000 eax=00000002 df=0\n"
           "mem 30000000 11\nend status=0 digest=00000000000000aa steps=2\n")

    def test_page_lines_are_not_part_of_a_trace(self) -> None:
        sections = driver.trace_sections(self.REF)
        self.assertEqual(list(sections), [1])
        self.assertFalse(any(text.startswith("page ") for text in sections[1]))

    def test_first_difference(self) -> None:
        ref = driver.trace_sections(self.REF)[1]
        self.assertIsNone(driver.first_difference(ref, list(ref)))
        lift = [text.replace("eax=00000002 df=0", "eax=00000003 df=0") for text in ref]
        self.assertEqual(driver.first_difference(ref, lift), 2)
        self.assertEqual(driver.first_difference(ref, ref[:4]), 4)

    def test_differing_field(self) -> None:
        self.assertEqual(driver.differing_field("step 1 10001002 eax=00000002 df=0",
                                                "step 1 10001002 eax=00000003 df=0"), "step.eax")
        self.assertEqual(driver.differing_field("step 1 10001002 eax=1 df=0", "step 1 10001004 eax=1 df=0"), "step.eip")
        self.assertEqual(driver.differing_field("term kind=1 a=0000dead b=0", "term kind=2 a=0000dead b=0"), "term.kind")
        self.assertEqual(driver.differing_field("mem 30000000 11", "mem 30000004 11"), "mem")
        self.assertEqual(driver.differing_field("xmm3 00", "xmm3 01"), "xmm3")
        self.assertEqual(driver.differing_field("mem 30000000 11", "end status=0"), "mem vs end")
        self.assertEqual(driver.differing_field("end status=0", ""), "missing line")

    def test_coverage_buckets(self) -> None:
        self.assertEqual(driver.coverage_bucket(10, 10), "100%")
        self.assertEqual(driver.coverage_bucket(0, 10), "0-9%")
        self.assertEqual(driver.coverage_bucket(99, 100), "90-99%")
        self.assertEqual(driver.coverage_bucket(55, 100), "50-59%")
        self.assertEqual(driver.coverage_bucket(0, 0), "100%")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Public CI-safe validation tests for decompiler warning triage & switch recovery."""
from __future__ import annotations

import collections
import csv
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import triage_decompiler_warnings as tdw

TEXT_LO = 0x10001000
TEXT_HI = 0x1172E4EA
HEX_RE = re.compile(r"^0x[0-9a-f]{8}$")


class WarningTriageArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.work = ROOT / "work"
        with open(cls.work / "decomp_defects_after.tsv", encoding="utf-8") as f:
            cls.raw_rows = list(csv.DictReader(f, delimiter="\t"))
        with open(cls.work / "decomp_defects_triaged_after.tsv", encoding="utf-8") as f:
            cls.tri_rows = list(csv.DictReader(f, delimiter="\t"))
        with open(cls.work / "switch_tables_recovered_after.tsv", encoding="utf-8") as f:
            cls.sw_rows = list(csv.DictReader(f, delimiter="\t"))
        with open(cls.work / "switch_table_repairs_after.tsv", encoding="utf-8") as f:
            cls.rep_rows = list(csv.DictReader(f, delimiter="\t"))
        cls.summary_md = (cls.work / "decomp_defects_triage_summary_after.md").read_text(encoding="utf-8")

    def test_exact_bijection_and_zero_untriaged(self) -> None:
        self.assertEqual(len(self.raw_rows), 9856)
        self.assertEqual(len(self.tri_rows), 9856)

        for idx, (raw, tri) in enumerate(zip(self.raw_rows, self.tri_rows), start=1):
            self.assertEqual(int(tri["row_id"]), idx)
            self.assertEqual(tri["function_entry"], f"0x{tdw._norm_hex8(raw['function_entry'])}")
            self.assertEqual(tri["category"], raw["category"])
            self.assertEqual(tri["severity"], raw["severity"])
            self.assertEqual(tri["confidence"], "high")
            self.assertTrue(tri["triage_class"], msg=f"missing triage_class at row {idx}")
            self.assertTrue(tri["disposition"], msg=f"missing disposition at row {idx}")
            self.assertTrue(tri["resolved_detail"], msg=f"missing resolved_detail at row {idx}")
            self.assertTrue(tri["evidence"], msg=f"missing evidence at row {idx}")

    def test_paired_indirect_jump_and_iat_imports(self) -> None:
        by_fn_jf: dict[str, list[dict]] = collections.defaultdict(list)
        by_fn_ij: dict[str, list[dict]] = collections.defaultdict(list)
        ro_rows = []
        rl_rows = []
        iat_rows = []

        for row in self.tri_rows:
            cat = row["category"]
            if cat == "jumptable_failure" and row["warning_address"]:
                by_fn_jf[row["function_entry"]].append(row)
            elif cat == "indirect_jump_as_call":
                by_fn_ij[row["function_entry"]].append(row)
            elif cat == "readonly_write":
                ro_rows.append(row)
            elif cat == "restart_limit":
                rl_rows.append(row)
            if row["triage_class"] == "iat_dispatch_tailcall":
                iat_rows.append(row)

        self.assertEqual(set(by_fn_jf.keys()), set(by_fn_ij.keys()))
        for fe, jf_list in by_fn_jf.items():
            ij_list = by_fn_ij[fe]
            self.assertEqual(len(jf_list), len(ij_list), msg=fe)
            for jf, ij in zip(jf_list, ij_list):
                self.assertEqual(ij["warning_address"], jf["warning_address"])
                self.assertEqual(ij["triage_class"], jf["triage_class"])
                self.assertEqual(ij["disposition"], jf["disposition"])
                self.assertEqual(ij["resolved_detail"], jf["resolved_detail"])

        self.assertEqual(len(iat_rows), 450)
        for row in iat_rows:
            self.assertIn("!", row["resolved_detail"], msg=row)
            dll, sym = row["resolved_detail"].split("!", 1)
            self.assertTrue(dll.endswith((".DLL", ".dll")), msg=row)
            self.assertTrue(sym, msg=row)

        self.assertEqual(len(ro_rows), 6)
        for row in ro_rows:
            self.assertEqual(row["triage_class"], "ghidra_ssa_rodata_alias")
            self.assertEqual(row["disposition"], "benign_decompiler_artifact")

        self.assertEqual(len(rl_rows), 2)
        for row in rl_rows:
            self.assertEqual(row["triage_class"], "decompiler_restart_cap")
            self.assertEqual(row["disposition"], "body_exported_verify_on_port")

    def test_switch_tables_47_across_16_functions(self) -> None:
        self.assertEqual(len(self.sw_rows), 47)
        sw_funcs = {r["function_entry"] for r in self.sw_rows}
        self.assertEqual(len(sw_funcs), 16)

        kind_counts = collections.Counter(r["warning_kind"] for r in self.sw_rows)
        self.assertEqual(kind_counts["addressed_jump"], 21)
        self.assertEqual(kind_counts["selector_normalization"], 26)

        by_jump = {r["jump_address"]: r for r in self.sw_rows}
        self.assertEqual(len(by_jump), 47)

        for rep in self.rep_rows:
            if rep["kind"] == "addressed_jump":
                jaddr = rep["jump_address"].lower()
                self.assertIn(jaddr, by_jump)
                sw = by_jump[jaddr]
                self.assertEqual(sw["table_address"], rep["table_address"].lower())
                self.assertEqual(sw["entry_count"], rep["entries"])

        for sw in self.sw_rows:
            self.assertRegex(sw["function_entry"], HEX_RE)
            self.assertRegex(sw["jump_address"], HEX_RE)
            self.assertRegex(sw["table_address"], HEX_RE)
            self.assertEqual(sw["all_targets_in_text"], "true")
            self.assertEqual(sw["all_slots_pe_reloc"], "true")
            tgts = sw["targets"].split(";")
            self.assertEqual(len(tgts), int(sw["entry_count"]))
            self.assertEqual(len(set(tgts)), int(sw["unique_target_count"]))
            for t in tgts:
                self.assertRegex(t, HEX_RE)
                va = int(t, 16)
                self.assertTrue(TEXT_LO <= va < TEXT_HI, msg=f"bad switch target {t}")

    def test_artifact_sizes_and_summary_present(self) -> None:
        self.assertIn("9,856", self.summary_md)
        self.assertIn("47 (across 16 functions)", self.summary_md)
        for fname in (
            "switch_tables_recovered_after.tsv",
            "decomp_defects_triaged_after.tsv",
            "decomp_defects_triage_summary_after.md",
        ):
            self.assertLess((self.work / fname).stat().st_size, 25 * 1024 * 1024, msg=fname)

    def test_norm_hex8_helper(self) -> None:
        self.assertEqual(tdw._norm_hex8("0x103e76a0"), "103e76a0")
        self.assertEqual(tdw._norm_hex8("103E76A0"), "103e76a0")


if __name__ == "__main__":
    unittest.main()

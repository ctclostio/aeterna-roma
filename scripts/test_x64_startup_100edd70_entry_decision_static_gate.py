from __future__ import annotations

import pathlib
import unittest

import x64_startup_100edd70_entry_decision_static_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "port/x64_ported/ported_100edd70_entry_decision.h"
SOURCE = ROOT / "port/x64_ported/ported_100edd70_entry_decision.c"
RUNTIME = ROOT / "port/x64_runtime/test_startup_100edd70_entry_decision.c"
PROVENANCE = ROOT / "scripts/test_x64_startup_100edd70_entry_decision_provenance.py"
DOC = ROOT / "docs/x64_startup_100edd70_entry_decision.md"
CMAKE = ROOT / "CMakeLists.txt"
PRODUCTION_PATHS = (
    ROOT / "port/x64_headless/headless_main.c",
    ROOT / "port/x64_exports/export_manifest.tsv",
    ROOT / "docs/x64_export_contract.md",
    ROOT / "port/x64_exports/empire.retail.exports.def",
    ROOT / "port/x64_bootstrap/empire_bootstrap.def",
    ROOT / "port/x64_probe/probe_exports.def",
)


class Startup100edd70EntryDecisionStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.runtime = RUNTIME.read_text(encoding="utf-8")
        cls.provenance = PROVENANCE.read_text(encoding="utf-8")
        cls.doc = DOC.read_bytes().decode("utf-8")
        cls.cmake = CMAKE.read_text(encoding="utf-8")

    def mutate(self, payload: str, old: str, new: str) -> str:
        mutant = payload.replace(old, new, 1)
        self.assertNotEqual(payload, mutant, f"mutation anchor absent: {old!r}")
        return mutant

    def assert_mutant(self, inspector, payload: str, old: str, new: str) -> None:
        findings = inspector(self.mutate(payload, old, new))
        self.assertTrue(findings, f"mutant passed: {old!r} -> {new!r}")

    def test_live_artifacts_pass(self) -> None:
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_test_text(self.runtime), [])
        self.assertEqual(gate.inspect_provenance_text(self.provenance), [])
        self.assertEqual(gate.inspect_doc_text(self.doc), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_live_production_surfaces_exclude_entry_decision(self) -> None:
        for path in PRODUCTION_PATHS:
            with self.subTest(path=path):
                self.assertEqual(
                    gate.inspect_production_text(path.read_text(encoding="utf-8")),
                    [],
                )

    def test_header_record_identity_and_structural_api_mutants_fail(self) -> None:
        mutants = (
            ("REGISTRATION_RECORD_COUNT UINT32_C(4)",
             "REGISTRATION_RECORD_COUNT UINT32_C(3)"),
            ("REGISTRATION_CALL_PC UINT32_C(0x100edf0a)",
             "REGISTRATION_CALL_PC UINT32_C(0x100edf0b)"),
            ("REGISTRATION_CLEANUP_PC UINT32_C(0x100edf0f)",
             "REGISTRATION_CLEANUP_PC UINT32_C(0x100edf10)"),
            ("STORE_MINUS_20_PC UINT32_C(0x100edf12)",
             "STORE_MINUS_20_PC UINT32_C(0x100edf13)"),
            ("STORE_MINUS_04_PC UINT32_C(0x100edf19)",
             "STORE_MINUS_04_PC UINT32_C(0x100edf18)"),
            ("REGISTRATION_CALLEE_PC UINT32_C(0x11687a4a)",
             "REGISTRATION_CALLEE_PC UINT32_C(0x11687a4b)"),
            ("REGISTRATION_HANDLER_ARGUMENT UINT32_C(0x100ee5d0)",
             "REGISTRATION_HANDLER_ARGUMENT UINT32_C(0x100ee5d1)"),
            ("rome2_100edd70_caller_closure_result child;",
             "uint32_t child;"),
        )
        for old, new in mutants:
            with self.subTest(old=old):
                self.assert_mutant(gate.inspect_header_text, self.header, old, new)
        self.assertTrue(gate.inspect_header_text(
            self.header.replace(
                "    uint32_t caller_position4,",
                "    uint32_t caller_position4,\n"
                "    rome2_guest_addr32 command_line,",
                1,
            )
        ))

    def test_source_alias_selector_registration_and_result_mutants_fail(self) -> None:
        mutants = (
            ("ENTRY_CONTROL_COUNT 14U", "ENTRY_CONTROL_COUNT 13U"),
            ("ENTRY_BACKING_COUNT 7U", "ENTRY_BACKING_COUNT 6U"),
            ("ENTRY_CONTEXT_COUNT 8U", "ENTRY_CONTEXT_COUNT 7U"),
            ("state.parent_effects = *parent_effects;",
             "state.parent_effects = state.parent_effects;"),
            ("state.continuation_effects = *continuation_effects;",
             "state.continuation_effects = state.continuation_effects;"),
            ("state.registration_effects = *registration_effects;",
             "state.registration_effects = state.registration_effects;"),
            ("status = rome2_100edd70_entry_validate_ownership_prestate(",
             "status = rome2_removed_prestate("),
            ("guest_status = rome2_port_100edd70_select_invalid_parameter_policy(",
             "guest_status = rome2_removed_selector("),
            ("status = rome2_port_100edd70_run_caller_closure(",
             "status = rome2_removed_child("),
            ("state.registration[1] = rome2_100edd70_entry_make_step(",
             "state.registration[0] = rome2_100edd70_entry_make_step("),
            ("    *result_out = state.combined_result;",
             "    /* result removed */"),
        )
        for old, new in mutants:
            with self.subTest(old=old):
                self.assert_mutant(gate.inspect_source_text, self.source, old, new)
        for suffix in (
            "\nstatic void bad(void) { RaiseException(0,0,0,0); }\n",
            "\nstatic void bad(void) { decomp_fn_11687a4a(); }\n",
            f"\nstatic void bad(void) {{ {gate.SELECTOR_FUNCTION}(); }}\n",
            f"\nstatic void bad(void) {{ {gate.CHILD_FUNCTION}(); }}\n",
        ):
            with self.subTest(suffix=suffix):
                self.assertTrue(gate.inspect_source_text(self.source + suffix))

    def test_runtime_registry_total_prefix_alias_and_mutation_mutants_fail(self) -> None:
        mutants = (
            ("ENTRY_TEST_EXPECTED_CASES UINT32_C(44)",
             "ENTRY_TEST_EXPECTED_CASES UINT32_C(43)"),
            ("UINT32_C(45) + poll_count + registration_count",
             "UINT32_C(44) + poll_count + registration_count"),
            ('"skip P64"', '"skip maximum removed"'),
            ('"install P64"', '"install maximum removed"'),
            ('"registration effects snapshot"', '"registration mutation removed"'),
            ('"child effects snapshot through route"', '"child mutation removed"'),
            ('"install F1 temporary denial"', '"F1 removed"'),
            ('"install F5 token collision"', '"F5 removed"'),
            ('"skip F1 temporary denial"', '"skip F1 removed"'),
            ('"install committed-prefix child denial"', '"prefix denial removed"'),
            ('"identical shared recorder"', '"shared recorder removed"'),
            ("entry_case_count == ENTRY_TEST_EXPECTED_CASES",
             "entry_case_count != ENTRY_TEST_EXPECTED_CASES"),
        )
        for old, new in mutants:
            with self.subTest(old=old):
                self.assert_mutant(gate.inspect_test_text, self.runtime, old, new)

    def test_provenance_and_doc_mutants_fail(self) -> None:
        provenance_mutants = (
            ('"68d0e50e10"', '"68d1e50e10"'),
            ('"83c404"', '"83c408"'),
            ("0x100EDF12", "0x100EDF13"),
            ("0x100EDF19", "0x100EDF18"),
            ("0x11687A4A", "0x11687A4B"),
            ("0x100EE5D0", "0x100EE5D1"),
            ("test_reciprocal_evidence_mutants_fail_and_oracle_is_read_only",
             "test_mutants_removed"),
        )
        for old, new in provenance_mutants:
            with self.subTest(old=old):
                self.assert_mutant(
                    gate.inspect_provenance_text, self.provenance, old, new
                )
        doc_mutants = (
            ("four records", "three records"),
            ("49 + P", "48 + P"),
            ("50 | 52 | 113", "49 | 51 | 112"),
            ("exactly 44 cases", "exactly 43 cases"),
            ("from 186 to 194", "from 186 to 191"),
            ("STATIC EXCLUDE_FROM_ALL", "SHARED"),
        )
        for old, new in doc_mutants:
            with self.subTest(old=old):
                self.assert_mutant(gate.inspect_doc_text, self.doc, old, new)

    def test_cmake_count_dependency_consumer_and_fixture_mutants_fail(self) -> None:
        mutants = (
            (f"    {gate.LIBRARY}\n    STATIC EXCLUDE_FROM_ALL",
             f"    {gate.LIBRARY}\n    SHARED"),
            (f"    PRIVATE {gate.CHILD_LIBRARY}", "    PRIVATE removed_child"),
            (f"    PRIVATE {gate.LIBRARY}", "    PRIVATE removed_entry"),
            ("FIXTURES_SETUP startup_100edd70_entry_decision_reload_verified",
             "FIXTURES_SETUP startup_100edd70_entry_decision_reload_removed"),
            ("NAME startup_100edd70_entry_decision_provenance",
             "NAME startup_100edd70_entry_decision_provenance_removed"),
        )
        for old, new in mutants:
            with self.subTest(old=old):
                self.assert_mutant(gate.inspect_cmake_text, self.cmake, old, new)
        consumer = self.cmake + (
            f"\ntarget_link_libraries(rome2_headless64 PRIVATE {gate.LIBRARY})\n"
        )
        self.assertTrue(gate.inspect_cmake_text(consumer))

    def test_production_escape_mutants_fail(self) -> None:
        for path in PRODUCTION_PATHS:
            payload = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertTrue(gate.inspect_production_text(
                    payload + f"\n{gate.FUNCTION}\n"
                ))


if __name__ == "__main__":
    unittest.main()

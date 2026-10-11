from __future__ import annotations

import pathlib
import unittest

import x64_startup_100edd70_caller_closure_static_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "port/x64_ported/ported_100edd70_caller_closure.h"
SOURCE = ROOT / "port/x64_ported/ported_100edd70_caller_closure.c"
RUNTIME = ROOT / "port/x64_runtime/test_startup_100edd70_caller_closure.c"
PROVENANCE = (
    ROOT / "scripts/test_x64_startup_100edd70_caller_closure_provenance.py"
)
DOC = ROOT / "docs/x64_startup_100edd70_caller_closure.md"
CMAKE = ROOT / "CMakeLists.txt"
PRODUCTION_PATHS = (
    ROOT / "port/x64_headless/headless_main.c",
    ROOT / "port/x64_exports/export_manifest.tsv",
    ROOT / "docs/x64_export_contract.md",
    ROOT / "port/x64_exports/empire.retail.exports.def",
    ROOT / "port/x64_bootstrap/empire_bootstrap.def",
    ROOT / "port/x64_probe/probe_exports.def",
)


class Startup100edd70CallerClosureStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.runtime = RUNTIME.read_text(encoding="utf-8")
        cls.provenance = PROVENANCE.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")
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

    def test_live_production_surfaces_exclude_caller_closure(self) -> None:
        for path in PRODUCTION_PATHS:
            with self.subTest(path=path):
                self.assertEqual(
                    gate.inspect_production_text(path.read_text(encoding="utf-8")),
                    [],
                )

    def test_header_boundary_policy_keeper_and_cleanup_mutants_fail(self) -> None:
        mutants = (
            ("WINDOW_START_PC UINT32_C(0x100edf20)",
             "WINDOW_START_PC UINT32_C(0x100edf21)"),
            ("HANDLER_HARD_STOP_PC UINT32_C(0x100edf41)",
             "HANDLER_HARD_STOP_PC UINT32_C(0x100edf42)"),
            ("SKIP_WINDOW_START_PC UINT32_C(0x100edf73)",
             "SKIP_WINDOW_START_PC UINT32_C(0x100edf72)"),
            ("SKIP_HARD_STOP_PC UINT32_C(0x100edf94)",
             "SKIP_HARD_STOP_PC UINT32_C(0x100edf95)"),
            ("KEEPER_BYTE_TARGET UINT32_C(0x101136d0)",
             "KEEPER_BYTE_TARGET UINT32_C(0x101136d1)"),
            ("KEEPER_BYTE_DESTINATION UINT32_C(0x119f3d8e)",
             "KEEPER_BYTE_DESTINATION UINT32_C(0x119f3d8f)"),
            ("KEEPER_BYTE_VALUE UINT32_C(1)",
             "KEEPER_BYTE_VALUE UINT32_C(2)"),
            ("KEEPER_DWORD_TARGET UINT32_C(0x101150f0)",
             "KEEPER_DWORD_TARGET UINT32_C(0x101150f1)"),
            ("KEEPER_DWORD_DESTINATION UINT32_C(0x119f3f5c)",
             "KEEPER_DWORD_DESTINATION UINT32_C(0x119f3f60)"),
            ("KEEPER_DWORD_VALUE UINT32_C(0x100d6560)",
             "KEEPER_DWORD_VALUE UINT32_C(0x100d6561)"),
            ("CALLER_CLEANUP_BYTES UINT32_C(24)",
             "CALLER_CLEANUP_BYTES UINT32_C(20)"),
            ("CONTINUATION_STEP_COUNT UINT32_C(3)",
             "CONTINUATION_STEP_COUNT UINT32_C(2)"),
            (gate.FUNCTION, "rome2_port_removed_caller_closure"),
        )
        for old, new in mutants:
            with self.subTest(old=old):
                self.assert_mutant(gate.inspect_header_text, self.header, old, new)

    def test_source_alias_snapshot_and_parent_call_mutants_fail(self) -> None:
        mutants = (
            ("CLOSURE_CONTROL_COUNT 13U", "CLOSURE_CONTROL_COUNT 12U"),
            ("CLOSURE_BACKING_COUNT 7U", "CLOSURE_BACKING_COUNT 6U"),
            ("CLOSURE_CONTEXT_COUNT 7U", "CLOSURE_CONTEXT_COUNT 6U"),
            ("state.parent_effects = *parent_effects;",
             "state.parent_effects = state.parent_effects;"),
            ("state.continuation_effects = *continuation_effects;",
             "state.continuation_effects = state.continuation_effects;"),
            ("contexts[first].start != contexts[second].start",
             "contexts[first].start == contexts[second].start"),
            ("status = rome2_port_100ed3c0_run_nonempty_lifecycle(",
             "status = rome2_port_removed_parent("),
            ("ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED",
             "ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE"),
            ("persistent_owner->phase != ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE",
             "persistent_owner->phase != ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED"),
        )
        for old, new in mutants:
            with self.subTest(old=old):
                self.assert_mutant(gate.inspect_source_text, self.source, old, new)

    def test_source_keeper_order_result_and_bypass_mutants_fail(self) -> None:
        mutants = (
            ("ROME2_100EDD70_CALLER_STEP_KEEPER_BYTE_STORE,",
             "ROME2_100EDD70_CALLER_STEP_KEEPER_DWORD_STORE,"),
            ("ROME2_100EDD70_CALLER_STEP_KEEPER_DWORD_STORE,",
             "ROME2_100EDD70_CALLER_STEP_CLEANUP_24,"),
            ("ROME2_100EDD70_CALLER_STEP_CLEANUP_24,",
             "ROME2_100EDD70_CALLER_STEP_KEEPER_BYTE_STORE,"),
            ("    *result_out = state.combined_result;",
             "    /* result commit removed */"),
            ("    *result_out = state.combined_result;",
             "    *result_out = state.combined_result;\n"
             "    *result_out = state.combined_result;"),
        )
        for old, new in mutants:
            with self.subTest(old=old, new=new):
                self.assert_mutant(gate.inspect_source_text, self.source, old, new)
        for suffix in (
            "\nstatic void bad(void) { malloc(4); }\n",
            "\nstatic void bad(void) { decomp_fn_101136d0(); }\n",
            f"\nstatic void bad(void) {{ {gate.SELECTOR_FUNCTION}(); }}\n",
            f"\nstatic void bad(void) {{ {gate.PARENT_FUNCTION}(); }}\n",
        ):
            with self.subTest(suffix=suffix):
                self.assertTrue(gate.inspect_source_text(self.source + suffix))

    def test_runtime_count_policy_order_alias_and_registry_mutants_fail(self) -> None:
        mutants = (
            ("TEST_EXPECTED_CASES UINT32_C(54)",
             "TEST_EXPECTED_CASES UINT32_C(53)"),
            ("expected_count == UINT32_C(45) +",
             "expected_count == UINT32_C(44) +"),
            ('"handler caller packet"', '"handler packet removed"'),
            ('"skip-handler caller packet"', '"skip packet removed"'),
            ('"maximum poll transcript"', '"poll maximum removed"'),
            ('"combined effects snapshot"', '"snapshot removed"'),
            ("    failed |= test_caller_tier0_cases();",
             "    /* caller tier zero removed */"),
            ("    failed |= test_effect_failures();",
             "    /* prefix failures removed */"),
            ("    failed |= test_teardown_cases();",
             "    /* teardown removed */"),
            ('"invalid policy"', '"policy rejection removed"'),
            ('"partial continuation context overlap"', '"partial removed"'),
            ('"continuation context overlaps result"', '"result alias removed"'),
            ('"null result"', '"null output removed"'),
        )
        for old, new in mutants:
            with self.subTest(old=old):
                self.assert_mutant(gate.inspect_test_text, self.runtime, old, new)

    def test_provenance_window_keeper_exclusion_and_readonly_mutants_fail(self) -> None:
        mutants = (
            ('"start": 0x100EDF20', '"start": 0x100EDF21'),
            ('"start": 0x100EDF73', '"start": 0x100EDF72'),
            ("0x101136D0:", "0x101136D1:"),
            ("0x101150F0:", "0x101150F1:"),
            ("0x100EDF05:", "0x100EDF06:"),
            ("0x100EDF41:", "0x100EDF42:"),
            ("0x100EDF94:", "0x100EDF95:"),
            ("test_oracle_is_standard_library_only_and_read_only",
             "test_oracle_may_write"),
        )
        for old, new in mutants:
            with self.subTest(old=old):
                self.assert_mutant(
                    gate.inspect_provenance_text, self.provenance, old, new
                )

    def test_doc_scope_transaction_event_and_containment_mutants_fail(self) -> None:
        mutants = (
            ("[0x100edf20,0x100edf41)", "[0x100edf20,0x100edf42)"),
            ("[0x100edf73,0x100edf94)", "[0x100edf73,0x100edf95)"),
            ("45 + P", "44 + P"),
            ("exactly 54 cases", "exactly 53 cases"),
            ("STATIC EXCLUDE_FROM_ALL", "SHARED"),
            ("180 to 186", "180 to 185"),
        )
        for old, new in mutants:
            with self.subTest(old=old):
                self.assert_mutant(gate.inspect_doc_text, self.doc, old, new)

    def test_cmake_count_library_dependency_consumer_and_fixture_mutants_fail(self) -> None:
        mutants = (
            (f"    {gate.LIBRARY}\n    STATIC EXCLUDE_FROM_ALL",
             f"    {gate.LIBRARY}\n    SHARED"),
            (f"    PRIVATE {gate.PARENT_LIBRARY}", "    PRIVATE removed_parent"),
            ("FIXTURES_SETUP startup_100edd70_caller_closure_reload_verified",
             "FIXTURES_SETUP startup_100edd70_caller_closure_reload_removed"),
            ("NAME startup_100edd70_caller_closure_provenance",
             "NAME startup_100edd70_caller_closure_provenance_removed"),
        )
        for old, new in mutants:
            with self.subTest(old=old):
                self.assert_mutant(gate.inspect_cmake_text, self.cmake, old, new)
        escaped = f"# {gate.LIBRARY}\n" + self.cmake
        self.assertTrue(gate.inspect_cmake_text(escaped))
        consumer = self.cmake + (
            f"\ntarget_link_libraries(rome2_headless64 PRIVATE {gate.LIBRARY})\n"
        )
        self.assertTrue(gate.inspect_cmake_text(consumer))
        removed_consumer = self.mutate(
            self.cmake,
            f"    PRIVATE {gate.LIBRARY}",
            "    PRIVATE removed_caller_consumer",
        )
        self.assertTrue(gate.inspect_cmake_text(removed_consumer))

    def test_production_escape_mutants_fail(self) -> None:
        for path in PRODUCTION_PATHS:
            payload = path.read_text(encoding="utf-8") + f"\n{gate.FUNCTION}\n"
            with self.subTest(path=path):
                self.assertTrue(gate.inspect_production_text(payload))


if __name__ == "__main__":
    unittest.main(verbosity=2)

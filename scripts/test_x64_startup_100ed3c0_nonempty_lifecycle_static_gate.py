from __future__ import annotations

import pathlib
import unittest

import x64_startup_100ed3c0_nonempty_lifecycle_static_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "port/x64_ported/ported_100ed3c0_nonempty_lifecycle.h"
SOURCE = ROOT / "port/x64_ported/ported_100ed3c0_nonempty_lifecycle.c"
RUNTIME = ROOT / "port/x64_runtime/test_startup_100ed3c0_nonempty_lifecycle.c"
PROVENANCE = (
    ROOT / "scripts/test_x64_startup_100ed3c0_nonempty_lifecycle_provenance.py"
)
DOC = ROOT / "docs/x64_startup_100ed3c0_nonempty_lifecycle.md"
CMAKE = ROOT / "CMakeLists.txt"
PRODUCTION_PATHS = (
    ROOT / "port/x64_headless/headless_main.c",
    ROOT / "port/x64_exports/export_manifest.tsv",
    ROOT / "docs/x64_export_contract.md",
    ROOT / "port/x64_exports/empire.retail.exports.def",
    ROOT / "port/x64_bootstrap/empire_bootstrap.def",
    ROOT / "port/x64_probe/probe_exports.def",
)


class Startup100ed3c0NonemptyLifecycleStaticGateTests(unittest.TestCase):
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

    def assert_finding(self, findings: list[str], fragment: str) -> None:
        self.assertTrue(
            any(fragment in finding for finding in findings),
            f"expected {fragment!r}; got {findings!r}",
        )

    def assert_mutant(
        self,
        inspector,
        payload: str,
        old: str,
        new: str,
        expected: str,
    ) -> None:
        self.assert_finding(inspector(self.mutate(payload, old, new)), expected)

    def test_live_artifacts_pass(self) -> None:
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_test_text(self.runtime), [])
        self.assertEqual(gate.inspect_provenance_text(self.provenance), [])
        self.assertEqual(gate.inspect_doc_text(self.doc), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_live_production_surfaces_exclude_whole_parent(self) -> None:
        for path in PRODUCTION_PATHS:
            with self.subTest(path=path):
                self.assertEqual(
                    gate.inspect_production_text(path.read_text(encoding="utf-8")),
                    [],
                )

    def test_header_boundary_frame_and_cardinality_mutants_fail(self) -> None:
        mutants = (
            ("START_PC UINT32_C(0x100ed3c0)",
             "START_PC UINT32_C(0x100ed3c1)", "start identity"),
            ("RETURN_PC UINT32_C(0x100ed550)",
             "RETURN_PC UINT32_C(0x100ed551)", "return identity"),
            ("FRAME_BYTES UINT32_C(0x90c)",
             "FRAME_BYTES UINT32_C(0x90d)", "frame size"),
            ("MISMATCH_PRELOOP_EVENTS \\\n    UINT32_C(31)",
             "MISMATCH_PRELOOP_EVENTS \\\n    UINT32_C(30)", "event cardinality"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_header_text, self.header, old, new, expected
                )

    def test_header_context_result_and_api_mutants_fail(self) -> None:
        mutants = (
            ("uint64_t ordinary_context_byte_count;",
             "uint64_t ordinary_context_size;",
             "callback span"),
            ("rome2_100ed471_lifecycle_result ordinary;",
             "rome2_100ed471_lifecycle_result removed;",
             "ordinary result embedding"),
            (gate.FUNCTION, "rome2_port_removed_whole_parent",
             "exactly one typed"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_header_text, self.header, old, new, expected
                )

    def test_header_preview_failure_and_containment_contract_mutants_fail(self) -> None:
        mutants = (
            ("private scratch frame", "caller scratch frame", "contract"),
            ("combined result commits once and last",
             "combined result commits first", "contract"),
            ("performs no rollback", "rolls every effect back", "contract"),
            ("performs no guest/native pointer cast",
             "casts guest addresses to native pointers", "contract"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_header_text, self.header, old, new, expected
                )

    def test_source_child_call_count_mutants_fail(self) -> None:
        self.assert_mutant(
            gate.inspect_source_text,
            self.source,
            "owned_status = rome2_port_100ed3c0_run_nonempty_preloop(",
            "owned_status = rome2_port_removed_nonempty_preloop(",
            "nonempty child exactly once",
        )
        self.assert_mutant(
            gate.inspect_source_text,
            self.source,
            "guest_status = rome2_port_100ed471_run_ordinary_lifecycle(",
            "guest_status = rome2_port_removed_lifecycle(",
            "exactly twice",
        )

    def test_source_preview_preloop_real_order_mutant_fails(self) -> None:
        preview = self.source.index(
            "guest_status = rome2_port_100ed471_run_ordinary_lifecycle("
        )
        preloop = self.source.index(
            "owned_status = rome2_port_100ed3c0_run_nonempty_preloop("
        )
        prefix = self.source[:preview]
        preview_block = self.source[preview:preloop]
        suffix = self.source[preloop:]
        mutant = prefix + suffix + preview_block
        self.assert_finding(
            gate.inspect_source_text(mutant), "preview, preloop, lifecycle"
        )

    def test_source_frame_seam_and_cleanup_assertion_mutants_fail(self) -> None:
        mutants = (
            ("ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC ==\n"
             "        ROME2_PORT_100ED471_START_PC",
             "ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC !=\n"
             "        ROME2_PORT_100ED471_START_PC", "exact seam"),
            ("ROME2_PORT_100ED471_CLEANUP0_OFFSET ==\n"
             "            ROME2_PORT_100ED3C0_PRELOOP_COPY1_OFFSET",
             "ROME2_PORT_100ED471_CLEANUP0_OFFSET ==\n"
             "            ROME2_PORT_100ED3C0_PRELOOP_COPY0_OFFSET",
             "cleanup-to-preloop"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_alias_universe_mutants_fail(self) -> None:
        mutants = (
            ("LIFECYCLE_CONTROL_COUNT 12U", "LIFECYCLE_CONTROL_COUNT 11U",
             "twelve-control"),
            ("LIFECYCLE_BACKING_COUNT 7U", "LIFECYCLE_BACKING_COUNT 6U",
             "seven-backing"),
            ("LIFECYCLE_CONTEXT_COUNT 6U", "LIFECYCLE_CONTEXT_COUNT 5U",
             "six-context"),
            ("contexts[first].start != contexts[second].start",
             "contexts[first].start == contexts[second].start",
             "exact-identical or disjoint"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_private_preview_mutants_fail(self) -> None:
        mutants = (
            ("state.preview_effects.emit_step = "
             "rome2_100ed3c0_lifecycle_preview_emit;",
             "state.preview_effects.emit_step = state.effects.ordinary.emit_step;",
             "private observer"),
            ("state.preview_effects.context = &state.preview_trace;",
             "state.preview_effects.context = state.effects.ordinary.context;",
             "context must remain private"),
            ("        &state.preview_result);",
             "        &state.ordinary_result);", "preview call"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_snapshot_and_result_commit_mutants_fail(self) -> None:
        self.assert_mutant(
            gate.inspect_source_text,
            self.source,
            "    state.effects = *effects;",
            "    state.effects = state.effects;",
            "complete input snapshot",
        )
        early = self.mutate(
            self.source,
            "    owned_status = rome2_port_100ed3c0_run_nonempty_preloop(\n",
            "    *result_out = state.combined_result;\n"
            "    owned_status = rome2_port_100ed3c0_run_nonempty_preloop(\n",
        )
        self.assert_finding(
            gate.inspect_source_text(early), "commit exactly once and last"
        )

    def test_source_owner_seam_mutants_fail(self) -> None:
        mutants = (
            ("ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED",
             "ROME2_PORT_100F1BB0_OWNED_OWNER_EMPTY", "temporary ownership"),
            ("ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||",
             "ROME2_PORT_100F1BB0_OWNED_OWNER_EMPTY ||", "persistent ownership"),
            ("ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE",
             "ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL",
             "lifecycle ownership"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_bypass_native_and_guest_cast_mutants_fail(self) -> None:
        bypass = self.source + (
            "\nstatic void bad(void) { "
            "rome2_port_100f2750_teardown_first_use_owned(); }\n"
        )
        self.assert_finding(gate.inspect_source_text(bypass), "bypass admitted")
        native = self.source + "\nstatic void *bad(void) { return malloc(8); }\n"
        self.assert_finding(gate.inspect_source_text(native), "forbidden native")
        casted = self.source + (
            "\nstatic void *bad(rome2_guest_addr32 guest_frame) { "
            "return (void *)guest_frame.value; }\n"
        )
        self.assert_finding(gate.inspect_source_text(casted), "guest/native pointer cast")

    def test_runtime_count_event_math_and_success_mutants_fail(self) -> None:
        mutants = (
            ("TEST_EXPECTED_CASES UINT32_C(36)",
             "TEST_EXPECTED_CASES UINT32_C(35)", "exactly 36 cases"),
            ("expected_count == UINT32_C(42) +",
             "expected_count == UINT32_C(41) +", "42+P"),
            ('"maximum poll transcript"', '"removed poll transcript"',
             "P=64"),
            ('"combined effects snapshot"', '"effects changed"', "snapshot"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_test_text, self.runtime, old, new, expected
                )

    def test_runtime_tier0_failure_and_teardown_mutants_fail(self) -> None:
        mutants = (
            ("    failed |= test_tier0_cases();",
             "    /* tier zero removed */", "Tier-0 group registry"),
            ("    failed |= test_effect_failures();",
             "    /* failures removed */", "effect-failure group registry"),
            ('"persistent token collision"', '"collision removed"',
             "token collision"),
            ('"repeated persistent teardown emitted an effect"',
             '"repeat proof removed"', "repeat teardown"),
            ("test_result_is_sentinel(&fixture->trace)",
             "1", "result-sentinel"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_test_text, self.runtime, old, new, expected
                )

    def test_provenance_boundary_and_partition_mutants_fail(self) -> None:
        mutants = (
            ("PARENT_SIZE = 400", "PARENT_SIZE = 399", "boundary/authority"),
            ("PRELOOP_SIZE = 177", "PRELOOP_SIZE = 176", "boundary/authority"),
            ("LIFECYCLE_SIZE = 223", "LIFECYCLE_SIZE = 224",
             "boundary/authority"),
            ("b606895706a18f44d27babaef870efc60b362733d01af389b96a10e7c0e5d206",
             "0606895706a18f44d27babaef870efc60b362733d01af389b96a10e7c0e5d206",
             "boundary/authority"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_provenance_text,
                    self.provenance,
                    old,
                    new,
                    expected,
                )

    def test_provenance_child_new_and_readonly_mutants_fail(self) -> None:
        mutants = (
            ("test_admitted_children_are_frozen",
             "test_children_are_mutable", "boundary/authority"),
            ("test_whole_composition_artifacts_are_one_coherent_snapshot",
             "test_unpinned_artifacts", "boundary/authority"),
            ("test_oracle_is_standard_library_only_and_read_only",
             "test_oracle_writes", "boundary/authority"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_provenance_text,
                    self.provenance,
                    old,
                    new,
                    expected,
                )

    def test_doc_boundary_preview_alias_failure_and_containment_mutants_fail(self) -> None:
        mutants = (
            ("[0x100ed3c0,0x100ed550)", "[0x100ed3c0,0x100ed551)",
             "documentation contract"),
            ("private lifecycle preview", "public lifecycle preview",
             "documentation contract"),
            ("42 + P", "41 + P", "documentation contract"),
            ("exactly two test-only consumers", "several consumers",
             "documentation contract"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_doc_text, self.doc, old, new, expected
                )

    def test_cmake_count_and_testing_containment_mutants_fail(self) -> None:
        removed = self.mutate(
            self.cmake,
            "  add_test(\n    NAME startup_100ed3c0_nonempty_lifecycle_provenance",
            "  # removed test(\n    # startup_100ed3c0_nonempty_lifecycle_provenance",
        )
        self.assert_finding(gate.inspect_cmake_text(removed), "exactly 194 CTests")
        escaped = f"# {gate.LIBRARY}\n" + self.cmake
        self.assert_finding(gate.inspect_cmake_text(escaped), "escapes BUILD_TESTING")

    def test_cmake_library_dependency_and_consumer_mutants_fail(self) -> None:
        shared = self.mutate(
            self.cmake,
            f"    {gate.LIBRARY}\n    STATIC",
            f"    {gate.LIBRARY}\n    SHARED",
        )
        self.assert_finding(gate.inspect_cmake_text(shared), "exact static")
        removed_child = self.mutate(
            self.cmake,
            f"      {gate.LIFECYCLE_LIBRARY}\n",
            "      removed_lifecycle_child\n",
        )
        self.assert_finding(gate.inspect_cmake_text(removed_child), "two-child")
        consumer = self.cmake + (
            f"\ntarget_link_libraries(rome2_headless64 PRIVATE {gate.LIBRARY})\n"
        )
        self.assert_finding(gate.inspect_cmake_text(consumer), "two test-only")

    def test_cmake_cli_and_fixture_mutants_fail(self) -> None:
        self.assert_mutant(
            gate.inspect_cmake_text,
            self.cmake,
            "      --doc \"${CMAKE_CURRENT_SOURCE_DIR}/docs/"
            "x64_startup_100ed3c0_nonempty_lifecycle.md\"\n",
            "",
            "static-gate argument",
        )
        self.assert_mutant(
            gate.inspect_cmake_text,
            self.cmake,
            "FIXTURES_SETUP startup_100ed3c0_nonempty_lifecycle_reload_verified",
            "FIXTURES_SETUP startup_100ed3c0_nonempty_lifecycle_reload_removed",
            "fixture chain",
        )

    def test_production_escape_mutants_fail(self) -> None:
        for path in PRODUCTION_PATHS:
            payload = path.read_text(encoding="utf-8") + f"\n{gate.FUNCTION}\n"
            with self.subTest(path=path):
                self.assert_finding(
                    gate.inspect_production_text(payload), "escaped production"
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)

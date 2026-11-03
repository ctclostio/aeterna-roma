from __future__ import annotations

import pathlib
import unittest

import x64_startup_100ed3c0_nonempty_preloop_static_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "port" / "x64_ported" / "ported_100ed3c0_nonempty_preloop.h"
SOURCE = ROOT / "port" / "x64_ported" / "ported_100ed3c0_nonempty_preloop.c"
RUNTIME = (
    ROOT / "port" / "x64_runtime" /
    "test_startup_100ed3c0_nonempty_preloop.c"
)
PROVENANCE = (
    ROOT / "scripts" /
    "test_x64_startup_100ed3c0_nonempty_preloop_provenance.py"
)
DOC = ROOT / "docs" / "x64_startup_100ed3c0_nonempty_preloop.md"
CMAKE = ROOT / "CMakeLists.txt"
PRODUCTION_PATHS = (
    ROOT / "port" / "x64_headless" / "headless_main.c",
    ROOT / "port" / "x64_exports" / "export_manifest.tsv",
    ROOT / "docs" / "x64_export_contract.md",
    ROOT / "port" / "x64_exports" / "empire.retail.exports.def",
    ROOT / "port" / "x64_bootstrap" / "empire_bootstrap.def",
    ROOT / "port" / "x64_probe" / "probe_exports.def",
)


class Startup100ed3c0NonemptyPreloopStaticGateTests(unittest.TestCase):
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

    def test_live_artifacts_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_test_text(self.runtime), [])
        self.assertEqual(gate.inspect_provenance_text(self.provenance), [])
        self.assertEqual(gate.inspect_doc_text(self.doc), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_live_production_surfaces_exclude_leaf(self):
        for path in PRODUCTION_PATHS:
            with self.subTest(path=path):
                self.assertEqual(
                    gate.inspect_production_text(path.read_text(encoding="utf-8")),
                    [],
                )

    def test_header_count_order_context_and_api_mutants_fail(self):
        mutants = (
            ("NONEMPTY_STEP_COUNT UINT32_C(9)",
             "NONEMPTY_STEP_COUNT UINT32_C(8)", "exactly nine"),
            ("NONEMPTY_STEP_BUILD_OWNED_DESCRIPTOR = 7",
             "NONEMPTY_STEP_BUILD_OWNED_DESCRIPTOR = 6", "step ordinal"),
            ("child_prefix_context_byte_count",
             "child_prefix_context_size", "prefix callback span"),
            ("rome2_100f1bb0_owned_owner *temporary_owner,",
             "const rome2_100f1bb0_owned_owner *temporary_owner,",
             "ownership controls must be mutable"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_header_text, self.header, old, new, expected
                )

    def test_header_failure_and_result_contract_mutants_fail(self):
        mutants = (
            ("performs no implicit rollback", "rolls every effect back",
             "ownership/containment contract"),
            ("result_out is\n * committed only after successful temporary cleanup",
             "result_out is\n * committed before temporary cleanup",
             "ownership/containment contract"),
            ("Owned status values are\n * propagated exactly",
             "Owned status values are\n * collapsed to one value",
             "ownership/containment contract"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_header_text, self.header, old, new, expected
                )

    def test_source_snapshot_preflight_and_packet_mutants_fail(self):
        mutants = (
            ("    state.effects = *effects;",
             "    state.effects = state.effects;", "effects must be snapshotted"),
            ("rome2_100ed3c0_nonempty_deny_allocate;",
             "effects->temporary_owned.allocate;", "preflight sequence"),
            ("PRELOOP_PACKET_FLAG_OFFSET] = UINT8_C(0);",
             "PRELOOP_PACKET_FLAG_OFFSET] = UINT8_C(1);",
             "packet +0x2c flags"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_child_call_count_and_delegation_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_source_text,
            self.source,
            "rome2_port_100df270_run_suffix_transcript_delegated(",
            "rome2_port_100df270_run_suffix_transcript_removed(",
            "admitted child call count",
        )
        self.assert_mutant(
            gate.inspect_source_text,
            self.source,
            "rome2_port_100df270_run_suffix_transcript_delegated(",
            "rome2_port_100df270_run_suffix_transcript(",
            "only the delegated suffix",
        )
        self.assert_mutant(
            gate.inspect_source_text,
            self.source,
            "ROME2_100ED3C0_NONEMPTY_STEP_RUN_100DF270);",
            "ROME2_100ED3C0_NONEMPTY_STEP_CLEANUP_OWNED_DESCRIPTOR);",
            "parent operation missing or duplicated",
        )

    def test_source_owner_status_and_cleanup_mutants_fail(self):
        mutants = (
            ("*persistent_owner = state.persistent_owner_work;",
             "*persistent_owner = state.persistent_owner_initial;",
             "persistent ownership publication"),
            ("return state.owned_delegate_context.owned_status;",
             "return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;",
             "delegated owned status"),
            ("        &state.effects.temporary_owned,\n        temporary_owner);",
             "        &state.effects.temporary_owned,\n"
             "        &state.temporary_owner_work);",
             "caller-visible temporary owner"),
            ("*state->lifecycle_external = *state->lifecycle_work;",
             "*state->lifecycle_external = *state->lifecycle_external;",
             "successful first-use lifecycle"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_entry_owner_descriptor_and_rollback_mutants_fail(self):
        mutants = (
            ("!rome2_100ed3c0_nonempty_owner_is_empty(\n"
             "            &state.temporary_owner_initial)",
             "rome2_100ed3c0_nonempty_owner_is_empty(\n"
             "            &state.temporary_owner_initial)",
             "temporary owner must enter canonical EMPTY"),
            ("persistent_descriptor_bytes + 8U) !=\n"
             "            ROME2_PORT_100F2750_FIRST_USE_SENTINEL",
             "persistent_descriptor_bytes + 8U) ==\n"
             "            ROME2_PORT_100F2750_FIRST_USE_SENTINEL",
             "persistent descriptor sentinel authority"),
            ("*persistent_owner = state.persistent_owner_initial;",
             "*persistent_owner = state.persistent_owner_work;",
             "pre-first-use persistent owner rollback"),
            ("*lifecycle = state.lifecycle_initial;",
             "*lifecycle = state.lifecycle_work;",
             "pre-first-use lifecycle rollback"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_preflight_text_capacity_and_delegate_mutants_fail(self):
        mutants = (
            ("state.deny_context.call_count != UINT32_C(1)",
             "state.deny_context.call_count != UINT32_C(2)",
             "allocate exactly once"),
            ("state.text_length == UINT32_C(0)",
             "state.text_length != UINT32_C(0)",
             "nonempty text lower bound"),
            ("&state.persistent_heap_view, state.allocation_bytes);",
             "&state.persistent_heap_view, UINT32_C(1));",
             "both temporary and persistent heap capacities"),
            ("state.owned_delegate_context.expected_destination.value =\n"
             "        ROME2_PORT_100F2750_FIRST_USE_DESTINATION;",
             "state.owned_delegate_context.expected_destination.value =\n"
             "        UINT32_C(0);",
             "owned delegate destination binding"),
            ("state->guest_return.value != guest_destination.value",
             "state->guest_return.value == guest_destination.value",
             "first-use return identity"),
            ("state.owned_delegate_context.call_count == UINT32_C(1) &&",
             "state.owned_delegate_context.call_count == UINT32_C(2) &&",
             "exact-status path"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_result_commit_mutant_fails(self):
        mutant = self.mutate(
            self.source,
            "    owned_status = rome2_port_100f1cc0_cleanup_owned_utf16(\n",
            "    result_out->child_receiver = state.guest_receiver;\n"
            "    owned_status = rome2_port_100f1cc0_cleanup_owned_utf16(\n",
        )
        self.assert_finding(
            gate.inspect_source_text(mutant),
            "bounded result fields must commit exactly once",
        )

    def test_source_native_original_and_guest_cast_mutants_fail(self):
        native = self.source + "\nstatic void *bad(void) { return malloc(8); }\n"
        self.assert_finding(
            gate.inspect_source_text(native), "forbidden native/original"
        )
        original = self.source + "\nstatic void bad(void) { decomp_fn_100ed3c0(); }\n"
        self.assert_finding(
            gate.inspect_source_text(original), "recovered/original identifiers"
        )
        casted = self.source + (
            "\nstatic void bad(rome2_guest_addr32 guest_value) { "
            "uint8_t *p = (uint8_t *)guest_value; (void)p; }\n"
        )
        self.assert_finding(
            gate.inspect_source_text(casted), "guest/native pointer cast"
        )

    def test_runtime_cardinality_residue_and_endpoint_mutants_fail(self):
        mutants = (
            ("TEST_EXPECTED_CASES UINT32_C(48)",
             "TEST_EXPECTED_CASES UINT32_C(47)", "exactly 48 cases"),
            ("temporary_residue < UINT32_C(4)",
             "temporary_residue < UINT32_C(3)", "four temporary residues"),
            ('"maximum N=32767"', '"maximum N=32766"', "maximum N=32767"),
            ('"effects snapshot"', '"effects changed"', "snapshot adversary"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_test_text, self.runtime, old, new, expected
                )

    def test_runtime_failure_cleanup_teardown_and_event_mutants_fail(self):
        mutants = (
            ('"persistent token collision"', '"persistent collision removed"',
             "token collision case"),
            ('"explicit cleanup of the torn temporary owner failed"',
             '"cleanup proof removed"', "escaped temporary cleanup proof"),
            ('"the registered-sentinel no-effect teardown changed"',
             '"sentinel proof removed"', "sentinel no-effect teardown proof"),
            ("TEST_EVENT_ALLOCATE_PERSISTENT UINT32_C(0x402)",
             "TEST_EVENT_ALLOCATE_PERSISTENT_REMOVED UINT32_C(0x402)",
             "total-order recorder event"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_test_text, self.runtime, old, new, expected
                )

    def test_runtime_registry_mutant_fails(self):
        self.assert_mutant(
            gate.inspect_test_text,
            self.runtime,
            "    failed |= test_persistent_failures();",
            "    /* persistent group removed */",
            "runtime group definition/registry",
        )

    def test_provenance_boundary_and_authority_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_provenance_text,
            self.provenance,
            "PRELOOP_SIZE = 177",
            "PRELOOP_SIZE = 176",
            "boundary token",
        )
        self.assert_mutant(
            gate.inspect_provenance_text,
            self.provenance,
            "17f8c4828490235d4734d734e3222be2c47ac9763bd69871b1e7cd2744fcae6f",
            "07f8c4828490235d4734d734e3222be2c47ac9763bd69871b1e7cd2744fcae6f",
            "authority/boundary token",
        )

    def test_doc_boundary_order_oracle_and_containment_mutants_fail(self):
        mutants = (
            ("[0x100ed3c0,0x100ed471)", "[0x100ed3c0,0x100ed472)",
             "documentation contract"),
            ("contains 48 cases", "contains 47 cases", "documentation contract"),
            ("either production binary", "the production binary",
             "documentation contract"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_doc_text, self.doc, old, new, expected
                )

    def test_cmake_count_containment_and_consumer_mutants_fail(self):
        removed = self.mutate(
            self.cmake,
            "  add_test(\n    NAME startup_100ed3c0_nonempty_preloop_provenance",
            "  # removed test(\n    # startup_100ed3c0_nonempty_preloop_provenance",
        )
        self.assert_finding(
            gate.inspect_cmake_text(removed), "exactly 194 CTests"
        )
        escaped = f"# {gate.LIBRARY}\n" + self.cmake
        self.assert_finding(
            gate.inspect_cmake_text(escaped), "escapes BUILD_TESTING"
        )
        consumer = self.cmake + (
            f"\ntarget_link_libraries(rome2_headless64 PRIVATE {gate.LIBRARY})\n"
        )
        self.assert_finding(
            gate.inspect_cmake_text(consumer), "standalone runtime test"
        )
        self.assert_finding(
            gate.inspect_cmake_text(consumer), "escaped into headless"
        )

    def test_cmake_gate_argument_and_fixture_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_cmake_text,
            self.cmake,
            "      --provenance \"${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_nonempty_preloop_provenance.py\"",
            "      --authority \"${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_nonempty_preloop_provenance.py\"",
            "static-gate argument changed",
        )
        self.assert_mutant(
            gate.inspect_cmake_text,
            self.cmake,
            "FIXTURES_SETUP startup_100ed3c0_nonempty_preloop_reload_verified",
            "FIXTURES_SETUP startup_100ed3c0_nonempty_preloop_reload_removed",
            "fixture chain changed",
        )

    def test_production_escape_mutant_fails(self):
        for path in PRODUCTION_PATHS:
            with self.subTest(path=path):
                payload = path.read_text(encoding="utf-8") + (
                    "\nrome2_port_100ed3c0_run_nonempty_preloop\n"
                )
                self.assert_finding(
                    gate.inspect_production_text(payload),
                    "escaped production",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)

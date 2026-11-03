#!/usr/bin/env python3
"""Reciprocal mutants for the bounded 0x100e8240 fast-path static gate."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import x64_startup_100e8240_fastpath_static_gate as gate  # noqa: E402


class Startup100e8240FastpathStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ported = ROOT / "port" / "x64_ported"
        runtime = ROOT / "port" / "x64_runtime"
        cls.payloads = {
            "header": (ported / "ported_100e8240_fastpath.h").read_text(),
            "source": (ported / "ported_100e8240_fastpath.c").read_text(),
            "test": (runtime / "test_startup_100e8240_fastpath.c").read_text(),
            "headless": (ROOT / "port" / "x64_headless" / "headless_main.c").read_text(),
        }
        cls.cmake = (ROOT / "CMakeLists.txt").read_text()

    def test_current_payloads_and_cmake_pass(self):
        for label, text in self.payloads.items():
            self.assertEqual(gate.inspect_payload_text(label, text), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_final_composition_size_and_count_mutants_fail(self):
        changed_size = self.payloads["headless"] + "\n"
        self.assertIn(
            "headless exact size changed",
            gate.inspect_payload_text("headless", changed_size),
        )
        extra_test = self.cmake + "\nadd_test(NAME fastpath_extra COMMAND false)\n"
        self.assertIn(
            "CMake add_test declaration count must remain 194",
            gate.inspect_cmake_text(extra_test),
        )

    def test_branch_direction_mutants_fail(self):
        inverted = self.payloads["source"].replace(
            "if (rome2_100e8240_signed_le(threshold, tls_value)) {",
            "if (rome2_100e8240_signed_le(tls_value, threshold)) {",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", inverted))
        strict = self.payloads["source"].replace(
            "(first ^ UINT32_C(0x80000000)) <=",
            "(first ^ UINT32_C(0x80000000)) <",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", strict))
        unsigned = self.payloads["source"].replace(
            "if (rome2_100e8240_signed_le(threshold, tls_value)) {",
            "if (threshold <= tls_value) {",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", unsigned))

    def test_disjointness_and_commit_mutants_fail(self):
        overlap = self.payloads["source"].replace(
            "if (rome2_100e8240_spans_overlap(\n"
            "            index_offset,\n"
            "            ROME2_PORT_100E8240_CELL_BYTES,\n"
            "            threshold_offset,\n"
            "            ROME2_PORT_100E8240_CELL_BYTES)) {",
            "if (0) {",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", overlap))
        identity = self.payloads["source"].replace(
            "guest_record_out->value = ROME2_PORT_100E8240_CRASH_RECORD;",
            "guest_record_out->value = UINT32_C(0x119f3a39);",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", identity))
        second_write = self.payloads["source"].replace(
            "return ROME2_GUEST_BAD_ARGUMENT;\n}",
            "guest_record_out->value = 0;\n    return ROME2_GUEST_BAD_ARGUMENT;\n}",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", second_write))

    def test_bound_and_overflow_mutants_fail(self):
        index_bound = self.payloads["source"].replace(
            "if (tls_index > ROME2_PORT_100E8240_MAX_TLS_INDEX) {",
            "if (tls_index > UINT32_MAX) {",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", index_bound))
        slot_overflow = self.payloads["source"].replace(
            "if (guest_tls_vector.value > UINT32_MAX - slot_displacement) {",
            "if (guest_tls_vector.value > UINT32_MAX) {",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", slot_overflow))
        tls_overflow = self.payloads["source"].replace(
            "if (tls_data > UINT32_MAX - UINT32_C(4)) {",
            "if (tls_data > UINT32_MAX) {",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", tls_overflow))

    def test_reverse_view_alias_arithmetic_mutant_fails(self):
        underflow = self.payloads["source"].replace(
            "host_address - view_address < sizeof(*view)",
            "view_address - host_address < sizeof(*view)",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", underflow))

    def test_platform_allocation_and_guest_cast_mutants_fail(self):
        platform = self.payloads["source"] + "\nvoid f(void) { ExitProcess(0); }\n"
        self.assertTrue(gate.inspect_payload_text("source", platform))
        allocation = self.payloads["source"] + "\nvoid *p = malloc(8);\n"
        self.assertTrue(gate.inspect_payload_text("source", allocation))
        helper = self.payloads["source"] + "\nvoid f(void) { memmove(0,0,0); }\n"
        self.assertTrue(gate.inspect_payload_text("source", helper))
        excluded = self.payloads["source"].replace(
            "guest_record_out->value = ROME2_PORT_100E8240_CRASH_RECORD;",
            "guest_record_out->value = 0x100ea4d0;",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", excluded))

    def test_shared_production_and_missing_headless_links_fail(self):
        shared = self.cmake.replace(
            "rome2_startup_100e8240_fastpath_runtime\n    STATIC",
            "rome2_startup_100e8240_fastpath_runtime\n    SHARED",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(shared))
        production = self.cmake.replace(
            "    PRIVATE rome2_guest32_runtime\n  )\n  set_property(\n"
            "    TARGET rome2_startup_100e8240_fastpath_runtime",
            "    PRIVATE rome2_guest32_runtime empire_retail_bootstrap\n  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100e8240_fastpath_runtime",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(production))
        missing = self.cmake.replace(
            "      rome2_startup_100e8240_fastpath_runtime\n", "", 1
        )
        self.assertTrue(gate.inspect_cmake_text(missing))
        successor_line = "      rome2_startup_100e2460_preallocated_branch_runtime\n"
        before, separator, after = self.cmake.rpartition(successor_line)
        self.assertEqual(separator, successor_line)
        missing_successor = before + after
        self.assertNotEqual(missing_successor, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(missing_successor))
        capacity_zero_line = (
            "      rome2_startup_100e2460_capacity_zero_branch_runtime\n"
        )
        before, separator, after = self.cmake.rpartition(capacity_zero_line)
        self.assertEqual(separator, capacity_zero_line)
        missing_capacity_zero = before + after
        self.assertNotEqual(missing_capacity_zero, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(missing_capacity_zero))
        substituted_capacity_zero = (
            before
            + "      rome2_startup_100e2460_preallocated_branch_runtime\n"
            + after
        )
        self.assertNotEqual(substituted_capacity_zero, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(substituted_capacity_zero))
        growth_line = "      rome2_startup_100e2460_growth_branch_runtime\n"
        before, separator, after = self.cmake.rpartition(growth_line)
        self.assertEqual(separator, growth_line)
        missing_growth = before + after
        self.assertNotEqual(missing_growth, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(missing_growth))
        substituted_growth = (
            before
            + "      rome2_startup_100e2460_capacity_zero_branch_runtime\n"
            + after
        )
        self.assertNotEqual(substituted_growth, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(substituted_growth))
        missing_router = self.cmake.replace(
            "      rome2_startup_100e2460_router_runtime\n", "", 1
        )
        self.assertNotEqual(missing_router, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(missing_router))
        substituted_router = self.cmake.replace(
            "      rome2_startup_100e2460_router_runtime\n",
            "      rome2_startup_100e2460_growth_branch_runtime\n",
            1,
        )
        self.assertNotEqual(substituted_router, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(substituted_router))
        for successor in (
            "rome2_startup_100e8d00_handler_transcript_runtime",
            "rome2_startup_100e85d0_normal_adapter_runtime",
            "rome2_startup_100e8580_handler_transcript_runtime",
            "rome2_startup_100ea4d0_injected_runtime",
            "rome2_startup_100e9340_handler_transcript_runtime",
            "rome2_startup_100e92c0_handler_transcript_runtime",
            "rome2_startup_100e87a0_handler_transcript_runtime",
            "rome2_startup_100df270_suffix_transcript_runtime",
            "rome2_startup_100df270_platform_prefix_transcript_runtime",
            "rome2_startup_100ed3c0_empty_preloop_runtime",
        ):
            successor_line = f"      {successor}\n"
            before, separator, after = self.cmake.rpartition(successor_line)
            self.assertEqual(separator, successor_line)
            missing_late_successor = before + after
            self.assertNotEqual(missing_late_successor, self.cmake)
            self.assertTrue(gate.inspect_cmake_text(missing_late_successor))
        reordered_terminal = self.cmake.replace(
            "      rome2_startup_100e2460_growth_branch_runtime\n"
            "      rome2_startup_100e2460_router_runtime\n",
            "      rome2_startup_100e2460_router_runtime\n"
            "      rome2_startup_100e2460_growth_branch_runtime\n",
            1,
        )
        self.assertNotEqual(reordered_terminal, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(reordered_terminal))
        reordered_outer_tail = self.cmake.replace(
            "      rome2_startup_100e8580_handler_transcript_runtime\n"
            "      rome2_startup_100ea4d0_injected_runtime\n",
            "      rome2_startup_100ea4d0_injected_runtime\n"
            "      rome2_startup_100e8580_handler_transcript_runtime\n",
            1,
        )
        self.assertNotEqual(reordered_outer_tail, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(reordered_outer_tail))
        reordered_final_tail = self.cmake.replace(
            "      rome2_startup_100df270_suffix_transcript_runtime\n"
            "      rome2_startup_100df270_platform_prefix_transcript_runtime\n"
            "      rome2_startup_100ed3c0_empty_preloop_runtime\n",
            "      rome2_startup_100df270_platform_prefix_transcript_runtime\n"
            "      rome2_startup_100df270_suffix_transcript_runtime\n"
            "      rome2_startup_100ed3c0_empty_preloop_runtime\n",
            1,
        )
        self.assertNotEqual(reordered_final_tail, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(reordered_final_tail))

    def test_lifecycle_fixture_mutants_fail(self):
        stale_predecessor = self.cmake.replace(
            "startup_100f2750_nonalloc_post_verified;"
            "startup_100e8240_fastpath_provenance_verified",
            "startup_100df270_headless_post_verified;"
            "startup_100e8240_fastpath_provenance_verified",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(stale_predecessor))
        missing_post = self.cmake.replace(
            "NAME startup_100e8240_fastpath_post_pe_gate",
            "NAME startup_100e8240_fastpath_post_pe_gate_removed",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(missing_post))
        bypassed_post = self.cmake.replace(
            "startup_100e8240_fastpath_runtime_verified;"
            "entry_policy_probe_pe_tool_verified",
            "startup_100f2750_nonalloc_runtime_verified;"
            "entry_policy_probe_pe_tool_verified",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(bypassed_post))
        stale_reload = self.cmake.replace(
            "x64_bootstrap_pre_verified;"
            "startup_100e8240_fastpath_post_verified",
            "x64_bootstrap_pre_verified;"
            "startup_100f2750_nonalloc_post_verified",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(stale_reload))
        missing_reload_setup = self.cmake.replace(
            "      FIXTURES_SETUP startup_100e8240_fastpath_reload_verified\n",
            "",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(missing_reload_setup))
        ungated_headless = self.cmake.replace(
            '      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"\n',
            "",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(ungated_headless))
        stale_headless_dependency = self.cmake.replace(
            "entry_policy_provenance_verified;entry_policy_static_verified;"
            "startup_100ed471_ordinary_lifecycle_reload_verified",
            "entry_policy_provenance_verified;entry_policy_static_verified;"
            "startup_100df270_platform_prefix_transcript_reload_verified",
            1,
        )
        self.assertNotEqual(stale_headless_dependency, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(stale_headless_dependency))

    def test_export_escape_and_missing_runtime_case_fail(self):
        self.assertTrue(
            gate.inspect_exports_text(
                "EXPORTS\n    rome2_port_100e8240_crash_record_fastpath\n"
            )
        )
        missing = self.payloads["test"].replace(
            "excluded crash route rejected", "crash route changed", 1
        )
        self.assertTrue(gate.inspect_payload_text("test", missing))
        missing_success = self.payloads["test"].replace(
            "tls value equal to threshold", "tls value matched threshold", 1
        )
        self.assertTrue(gate.inspect_payload_text("test", missing_success))
        missing_signed = self.payloads["test"].replace(
            "cross-sign signed reject", "cross-sign comparison changed", 1
        )
        self.assertTrue(gate.inspect_payload_text("test", missing_signed))

    def test_missing_headless_execution_or_report_fails(self):
        missing_call = self.payloads["headless"].replace(
            "status = rome2_port_100e8240_crash_record_fastpath(",
            "status = ROME2_GUEST_OK; /* removed fast-path call */ (",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("headless", missing_call))
        missing_report = self.payloads["headless"].replace(
            "crash-record=fast-path-no-crash;",
            "crash-record=not-verified;",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("headless", missing_report))
        stale_successor_report = self.payloads["headless"].replace(
            "initializer-dispatch=injected-complete;",
            "initializer-dispatch=not-linked;",
            1,
        )
        self.assertNotEqual(stale_successor_report, self.payloads["headless"])
        self.assertTrue(
            gate.inspect_payload_text("headless", stale_successor_report)
        )
        stale_allocator_report = self.payloads["headless"].replace(
            "allocator=injected-4-byte;native-allocator=not-run;",
            "allocator=not-run;native-allocator=not-run;",
            1,
        )
        self.assertNotEqual(stale_allocator_report, self.payloads["headless"])
        self.assertTrue(
            gate.inspect_payload_text("headless", stale_allocator_report)
        )
        stale_growth_report = self.payloads["headless"].replace(
            "initializer-growth=injected-complete;",
            "initializer-growth=not-linked;",
            1,
        )
        self.assertNotEqual(stale_growth_report, self.payloads["headless"])
        self.assertTrue(
            gate.inspect_payload_text("headless", stale_growth_report)
        )
        stale_router_report = self.payloads["headless"].replace(
            "initializer-router=injected-complete;",
            "initializer-router=not-linked;",
            1,
        )
        self.assertNotEqual(stale_router_report, self.payloads["headless"])
        self.assertTrue(
            gate.inspect_payload_text("headless", stale_router_report)
        )
        stale_release_report = self.payloads["headless"].replace(
            "growth-release=injected-old-backing;native-release=not-run;",
            "growth-release=not-run;native-release=not-run;",
            1,
        )
        self.assertNotEqual(stale_release_report, self.payloads["headless"])
        self.assertTrue(
            gate.inspect_payload_text("headless", stale_release_report)
        )
        for token in (
            "initializer-handler-100e8d00=injected-transcript-complete;",
            "initializer-handler-100e85d0=effect-free-complete;",
            "initializer-handler-100e8580=injected-transcript-complete;",
            "initializer-100ea4d0=injected-complete;",
            "initializer-handler-100e9340=injected-transcript-complete;",
            "initializer-handler-100e92c0=injected-transcript-complete;",
            "initializer-handler-100e87a0=injected-transcript-complete;",
            "startup-100df270-suffix=injected-transcript-complete;",
            "startup-100df270-platform-prefix=injected-call-shape-complete;",
            "startup-100ed3c0-empty-preloop=injected-composition-complete;",
        ):
            stale_completion = self.payloads["headless"].replace(
                token, token.replace("complete", "not-linked"), 1
            )
            self.assertNotEqual(stale_completion, self.payloads["headless"])
            self.assertTrue(
                gate.inspect_payload_text("headless", stale_completion)
            )
        for function in (
            "rome2_port_100e8d00_run_handler_transcript",
            "rome2_port_100e85d0_normal_adapter",
            "rome2_port_100e8580_run_handler_transcript",
            "rome2_port_100e9340_run_handler_transcript",
            "rome2_port_100e92c0_run_handler_transcript",
            "rome2_port_100e87a0_run_handler_transcript",
            "rome2_port_100ed3c0_run_empty_preloop",
        ):
            missing_handler_call = self.payloads["headless"].replace(
                function + "(", "removed_" + function + "(", 1
            )
            self.assertNotEqual(missing_handler_call, self.payloads["headless"])
            self.assertTrue(
                gate.inspect_payload_text("headless", missing_handler_call)
            )
        for removed_direct_child in (
            "rome2_port_100df270_run_suffix_transcript",
            "rome2_port_100df270_run_platform_prefix_transcript",
        ):
            injected_direct_child = self.payloads["headless"] + (
                "\nvoid rejected_direct_child(void) { "
                + removed_direct_child
                + "(); }\n"
            )
            self.assertTrue(
                gate.inspect_payload_text("headless", injected_direct_child)
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

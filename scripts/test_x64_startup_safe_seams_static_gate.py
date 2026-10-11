#!/usr/bin/env python3
"""Reciprocal mutants for the bounded startup safe-seam source/link gate."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import x64_startup_safe_seams_static_gate as gate  # noqa: E402


HEADLESS_SUCCESSOR_TAIL = (
    "      rome2_startup_100e2460_append_prefix_runtime\n"
    "      rome2_startup_100e2460_preallocated_branch_runtime\n"
    "      rome2_startup_100e2460_capacity_zero_branch_runtime\n"
    "      rome2_startup_100e2460_growth_branch_runtime\n"
    "      rome2_startup_100e2460_router_runtime\n"
    "      rome2_startup_100e8d00_handler_transcript_runtime\n"
    "      rome2_startup_100e85d0_normal_adapter_runtime\n"
    "      rome2_startup_100e8580_handler_transcript_runtime\n"
    "      rome2_startup_100ea4d0_injected_runtime\n"
    "      rome2_startup_100e9340_handler_transcript_runtime\n"
    "      rome2_startup_100e92c0_handler_transcript_runtime\n"
    "      rome2_startup_100e87a0_handler_transcript_runtime\n"
    "      rome2_startup_100df270_suffix_transcript_runtime\n"
    "      rome2_startup_100df270_platform_prefix_transcript_runtime\n"
    "      rome2_startup_100ed3c0_empty_preloop_runtime\n"
    "      rome2_startup_100ed471_ordinary_lifecycle_runtime\n"
)


def mutate_headless_successor(text: str, old: str, new: str) -> str:
    replacement = HEADLESS_SUCCESSOR_TAIL.replace(old, new, 1)
    return text.replace(HEADLESS_SUCCESSOR_TAIL, replacement, 1)


class StartupSafeSeamsStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ported = ROOT / "port" / "x64_ported"
        runtime = ROOT / "port" / "x64_runtime"
        cls.payloads = {
            "measure_header": (ported / "ported_100f1bb0_bounded.h").read_text(),
            "measure_source": (ported / "ported_100f1bb0_bounded.c").read_text(),
            "noop_header": (ported / "ported_100f1cc0_nonowning.h").read_text(),
            "noop_source": (ported / "ported_100f1cc0_nonowning.c").read_text(),
            "test": (runtime / "test_startup_safe_seams.c").read_text(),
        }
        cls.cmake = (ROOT / "CMakeLists.txt").read_text()

    def test_current_payloads_and_cmake_pass(self):
        for label, text in self.payloads.items():
            self.assertEqual(gate.inspect_payload_text(label, text), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_final_cmake_count_mutant_fails(self):
        mutant = self.cmake + "\nadd_test(NAME safe_seams_extra COMMAND false)\n"
        self.assertIn(
            "CMake add_test declaration count must remain 192",
            gate.inspect_cmake_text(mutant),
        )

    def test_unbounded_and_early_output_mutants_fail(self):
        source = self.payloads["measure_source"]
        unbounded = source.replace(
            "max_units > ROME2_PORT_100F1BB0_MAX_UNITS", "max_units > UINT32_MAX", 1
        )
        self.assertTrue(gate.inspect_payload_text("measure_source", unbounded))
        early = source.replace("cursor = guest_text;", "*length_out = 0;\n    cursor = guest_text;", 1)
        self.assertTrue(gate.inspect_payload_text("measure_source", early))

    def test_allocator_pointer_and_owning_mutants_fail(self):
        measure = self.payloads["measure_source"] + "\nvoid *p = malloc(4);\n"
        self.assertTrue(gate.inspect_payload_text("measure_source", measure))
        noop = self.payloads["noop_source"].replace(" ||", " &&", 1)
        self.assertTrue(gate.inspect_payload_text("noop_source", noop))
        pointer = self.payloads["noop_source"].replace(
            "{\n    if", "{\n    (void)*(uint8_t *)(uintptr_t)guest_storage.value;\n    if", 1
        )
        self.assertTrue(gate.inspect_payload_text("noop_source", pointer))

    def test_shared_production_and_missing_headless_links_fail(self):
        shared = self.cmake.replace(
            "rome2_startup_safe_seams_runtime\n    STATIC",
            "rome2_startup_safe_seams_runtime\n    SHARED",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(shared))
        production = self.cmake.replace(
            "    PRIVATE rome2_guest32_runtime\n  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_safe_seams_runtime",
            "    PRIVATE rome2_guest32_runtime empire_retail_bootstrap\n  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_safe_seams_runtime",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(production))
        missing = self.cmake.replace(
            "      rome2_startup_safe_seams_runtime\n", "", 1
        )
        self.assertTrue(gate.inspect_cmake_text(missing))
        missing_lifecycle_consumer = self.cmake.replace(
            "  target_link_libraries(\n"
            "    rome2_startup_100ed471_ordinary_lifecycle_runtime\n"
            "    PUBLIC rome2_guest32_runtime\n"
            "    PRIVATE rome2_startup_safe_seams_runtime\n"
            "  )\n",
            "",
            1,
        )
        self.assertNotEqual(missing_lifecycle_consumer, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(missing_lifecycle_consumer))
        missing_successor = mutate_headless_successor(
            self.cmake,
            "      rome2_startup_100e2460_preallocated_branch_runtime\n",
            "",
        )
        self.assertNotEqual(missing_successor, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(missing_successor))
        missing_capacity_zero = mutate_headless_successor(
            self.cmake,
            "      rome2_startup_100e2460_capacity_zero_branch_runtime\n",
            "",
        )
        self.assertNotEqual(missing_capacity_zero, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(missing_capacity_zero))
        substituted_capacity_zero = mutate_headless_successor(
            self.cmake,
            "      rome2_startup_100e2460_capacity_zero_branch_runtime\n",
            "      rome2_startup_100e2460_capacity_one_branch_runtime\n",
        )
        self.assertNotEqual(substituted_capacity_zero, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(substituted_capacity_zero))
        missing_growth = mutate_headless_successor(
            self.cmake,
            "      rome2_startup_100e2460_growth_branch_runtime\n",
            "",
        )
        self.assertNotEqual(missing_growth, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(missing_growth))
        substituted_growth = mutate_headless_successor(
            self.cmake,
            "      rome2_startup_100e2460_growth_branch_runtime\n",
            "      rome2_startup_100e2460_growth_branch_shared\n",
        )
        self.assertNotEqual(substituted_growth, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(substituted_growth))
        missing_router = mutate_headless_successor(
            self.cmake,
            "      rome2_startup_100e2460_router_runtime\n",
            "",
        )
        self.assertNotEqual(missing_router, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(missing_router))
        substituted_router = mutate_headless_successor(
            self.cmake,
            "      rome2_startup_100e2460_router_runtime\n",
            "      rome2_startup_100e2460_router_shared\n",
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
            "rome2_startup_100ed471_ordinary_lifecycle_runtime",
        ):
            missing_late_successor = mutate_headless_successor(
                self.cmake, f"      {successor}\n", ""
            )
            self.assertNotEqual(missing_late_successor, self.cmake)
            self.assertTrue(gate.inspect_cmake_text(missing_late_successor))
        reordered_final_tail = mutate_headless_successor(
            self.cmake,
            "      rome2_startup_100df270_suffix_transcript_runtime\n"
            "      rome2_startup_100df270_platform_prefix_transcript_runtime\n"
            "      rome2_startup_100ed3c0_empty_preloop_runtime\n"
            "      rome2_startup_100ed471_ordinary_lifecycle_runtime\n",
            "      rome2_startup_100df270_platform_prefix_transcript_runtime\n"
            "      rome2_startup_100df270_suffix_transcript_runtime\n"
            "      rome2_startup_100ed3c0_empty_preloop_runtime\n"
            "      rome2_startup_100ed471_ordinary_lifecycle_runtime\n",
        )
        self.assertNotEqual(reordered_final_tail, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(reordered_final_tail))
        stale_terminal_fixture = self.cmake.replace(
            '"entry_policy_provenance_verified;entry_policy_static_verified;'
            'startup_100ed471_ordinary_lifecycle_reload_verified"',
            '"entry_policy_provenance_verified;entry_policy_static_verified;'
            'startup_100df270_platform_prefix_transcript_reload_verified"',
            1,
        )
        self.assertNotEqual(stale_terminal_fixture, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(stale_terminal_fixture))

    def test_export_escape_fails(self):
        self.assertTrue(
            gate.inspect_exports_text("EXPORTS\n    Port100f1cc0\n")
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

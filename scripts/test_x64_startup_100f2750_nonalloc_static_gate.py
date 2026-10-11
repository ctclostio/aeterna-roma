#!/usr/bin/env python3
"""Reciprocal mutants for the bounded 0x100f2750 static gate."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import x64_startup_100f2750_nonalloc_static_gate as gate  # noqa: E402


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


class Startup100f2750NonallocStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ported = ROOT / "port" / "x64_ported"
        runtime = ROOT / "port" / "x64_runtime"
        cls.payloads = {
            "header": (ported / "ported_100f2750_nonalloc.h").read_text(),
            "source": (ported / "ported_100f2750_nonalloc.c").read_text(),
            "test": (runtime / "test_startup_100f2750_nonalloc.c").read_text(),
        }
        cls.cmake = (ROOT / "CMakeLists.txt").read_text()

    def test_current_payloads_and_cmake_pass(self):
        for label, text in self.payloads.items():
            self.assertEqual(gate.inspect_payload_text(label, text), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_final_cmake_count_mutant_fails(self):
        mutant = self.cmake + "\nadd_test(NAME nonalloc_extra COMMAND false)\n"
        self.assertIn(
            "CMake add_test declaration count must remain 192",
            gate.inspect_cmake_text(mutant),
        )

    def test_bound_capacity_overlap_and_copy_mutants_fail(self):
        header = self.payloads["header"].replace("UINT32_C(15)", "UINT32_C(16)", 1)
        self.assertTrue(gate.inspect_payload_text("header", header))
        capacity = self.payloads["source"].replace(
            "destination_capacity < source_count",
            "destination_capacity <= source_count",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", capacity))
        overlap = self.payloads["source"].replace(
            "destination_payload_offset,\n            copy_bytes,\n"
            "            source_payload_offset,\n            copy_bytes) ||",
            "destination_payload_offset,\n            0,\n"
            "            source_payload_offset,\n            0) ||",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", overlap))
        copy = self.payloads["source"].replace(
            "index < (size_t)copy_bytes", "index <= (size_t)copy_bytes", 1
        )
        self.assertTrue(gate.inspect_payload_text("source", copy))

    def test_platform_allocation_helper_and_guest_cast_mutants_fail(self):
        platform = self.payloads["source"] + "\nvoid f(void) { ExitProcess(0); }\n"
        self.assertTrue(gate.inspect_payload_text("source", platform))
        allocation = self.payloads["source"] + "\nvoid *p = malloc(8);\n"
        self.assertTrue(gate.inspect_payload_text("source", allocation))
        helper = self.payloads["source"] + "\nvoid f(void) { memmove(0,0,0); }\n"
        self.assertTrue(gate.inspect_payload_text("source", helper))
        pointer = self.payloads["source"].replace(
            "destination_descriptor =\n"
            "        view->host_base + (size_t)destination_descriptor_offset;",
            "destination_descriptor = (uint8_t *)(uintptr_t)"
            "guest_destination_descriptor.value;",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", pointer))

    def test_shared_production_and_missing_headless_links_fail(self):
        shared = self.cmake.replace(
            "rome2_startup_100f2750_nonalloc_runtime\n    STATIC",
            "rome2_startup_100f2750_nonalloc_runtime\n    SHARED",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(shared))
        production = self.cmake.replace(
            "    PRIVATE rome2_guest32_runtime\n  )\n  set_property(\n"
            "    TARGET rome2_startup_100f2750_nonalloc_runtime",
            "    PRIVATE rome2_guest32_runtime empire_retail_bootstrap\n  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100f2750_nonalloc_runtime",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(production))
        missing = self.cmake.replace(
            "      rome2_startup_100f2750_nonalloc_runtime\n", "", 1
        )
        self.assertTrue(gate.inspect_cmake_text(missing))
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

    def test_export_escape_and_missing_runtime_case_fail(self):
        self.assertTrue(
            gate.inspect_exports_text(
                "EXPORTS\n    rome2_port_100f2750_copy_nonallocating_short\n"
            )
        )
        missing = self.payloads["test"].replace(
            "allocation branch rejected", "allocation path changed", 1
        )
        self.assertTrue(gate.inspect_payload_text("test", missing))


if __name__ == "__main__":
    unittest.main(verbosity=2)

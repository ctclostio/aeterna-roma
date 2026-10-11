#!/usr/bin/env python3
"""Reciprocal mutants for the bounded 100df270 headless static gate."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import x64_startup_100df270_headless_static_gate as gate  # noqa: E402


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


class Startup100df270HeadlessStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ported = ROOT / "port" / "x64_ported"
        runtime = ROOT / "port" / "x64_runtime"
        cls.payloads = {
            "header": (ported / "ported_100df270_headless.h").read_text(),
            "source": (ported / "ported_100df270_headless.c").read_text(),
            "test": (runtime / "test_startup_100df270_headless.c").read_text(),
        }
        cls.cmake = (ROOT / "CMakeLists.txt").read_text()

    def test_current_payloads_and_cmake_pass(self):
        for label, text in self.payloads.items():
            self.assertEqual(gate.inspect_payload_text(label, text), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_final_cmake_count_mutant_fails(self):
        mutant = self.cmake + "\nadd_test(NAME headless_projection_extra COMMAND false)\n"
        self.assertIn(
            "CMake add_test declaration count must remain 192",
            gate.inspect_cmake_text(mutant),
        )

    def test_span_empty_gate_and_write_mutants_fail(self):
        header = self.payloads["header"].replace("0x8a8", "0x8a4", 1)
        self.assertTrue(gate.inspect_payload_text("header", header))
        nonempty = self.payloads["source"].replace(
            "rome2_read_u32_le(packet + 0x08) != 0",
            "rome2_read_u32_le(packet + 0x08) == 0",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", nonempty))
        sentinel = self.payloads["source"].replace("0x11af4090", "0x11af4094", 1)
        self.assertTrue(gate.inspect_payload_text("source", sentinel))
        hole = self.payloads["source"].replace(
            "object = view->host_base + (size_t)object_offset;",
            "object = view->host_base + (size_t)object_offset;\n"
            "    rome2_write_u32_le(object, 0x808, 0);",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", hole))

    def test_platform_allocation_and_guest_cast_mutants_fail(self):
        platform = self.payloads["source"] + "\nvoid f(void) { CreateMutexW(0,0,0); }\n"
        self.assertTrue(gate.inspect_payload_text("source", platform))
        allocation = self.payloads["source"] + "\nvoid *p = malloc(8);\n"
        self.assertTrue(gate.inspect_payload_text("source", allocation))
        pointer = self.payloads["source"].replace(
            "object = view->host_base + (size_t)object_offset;",
            "object = (uint8_t *)(uintptr_t)guest_object.value;",
            1,
        )
        self.assertTrue(gate.inspect_payload_text("source", pointer))

    def test_shared_production_and_missing_headless_links_fail(self):
        shared = self.cmake.replace(
            "rome2_startup_100df270_headless_runtime\n    STATIC",
            "rome2_startup_100df270_headless_runtime\n    SHARED",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(shared))
        production = self.cmake.replace(
            "    PRIVATE rome2_guest32_runtime\n  )\n  set_property(\n"
            "    TARGET rome2_startup_100df270_headless_runtime",
            "    PRIVATE rome2_guest32_runtime empire_retail_bootstrap\n  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100df270_headless_runtime",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(production))
        missing = self.cmake.replace(
            "      rome2_startup_100df270_headless_runtime\n", "", 1
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
            'startup_100ed3c0_empty_preloop_reload_verified"',
            1,
        )
        self.assertNotEqual(stale_terminal_fixture, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(stale_terminal_fixture))

    def test_export_escape_and_missing_runtime_case_fail(self):
        self.assertTrue(
            gate.inspect_exports_text(
                "EXPORTS\n    rome2_port_100df270_project_headless_empty_state\n"
            )
        )
        missing = self.payloads["test"].replace(
            "first descriptor nonempty", "first descriptor changed", 1
        )
        self.assertTrue(gate.inspect_payload_text("test", missing))


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Reciprocal mutants for the 0x100e2460 append-prefix static gate."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = ROOT / "scripts" / "x64_startup_100e2460_append_prefix_static_gate.py"
SPEC = importlib.util.spec_from_file_location("append_prefix_gate", GATE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load append-prefix static gate")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class Startup100e2460AppendPrefixStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read("port/x64_ported/ported_100e2460_append_prefix.h")
        cls.source = read("port/x64_ported/ported_100e2460_append_prefix.c")
        cls.test = read("port/x64_runtime/test_startup_100e2460_append_prefix.c")
        cls.headless = read("port/x64_headless/headless_main.c")
        cls.cmake = read("CMakeLists.txt")

    def test_live_inputs_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_test_text(self.test), [])
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_branch_and_commit_mutants_fail(self):
        wrong_branch = self.source.replace(
            "if (count >= capacity)", "if (count > capacity)", 1
        )
        self.assertTrue(gate.inspect_source_text(wrong_branch))
        wrong_scale = self.source.replace(
            "(uint64_t)count * UINT64_C(4)",
            "(uint64_t)count",
            1,
        )
        self.assertTrue(gate.inspect_source_text(wrong_scale))
        first = "rome2_100e2460_write_u32_le(append_cell, guest_element.value);"
        second = (
            "rome2_100e2460_write_u32_le(count_cell, count + UINT32_C(1));"
        )
        swapped = self.source.replace(first, "ROME2_SWAP_MARK", 1)
        swapped = swapped.replace(second, first, 1).replace("ROME2_SWAP_MARK", second, 1)
        self.assertTrue(gate.inspect_source_text(swapped))
        missing_overlap = self.source.replace(
            "if (rome2_100e2460_spans_overlap(", "if (0 && rome2_100e2460_spans_overlap(", 1
        )
        self.assertTrue(gate.inspect_source_text(missing_overlap))

    def test_allocator_platform_and_dispatch_mutants_fail(self):
        for injected in (
            "\nvoid *malloc(size_t);\n",
            "\nint PeekMessageW(void *, void *, unsigned, unsigned, unsigned);\n",
            "\nvoid (*dispatch)(void);\n",
        ):
            self.assertTrue(gate.inspect_source_text(self.source + injected))

    def test_runtime_and_headless_mutants_fail(self):
        missing_case = self.test.replace(
            '"zero capacity rejects allocator route"',
            '"zero capacity accidentally admitted"',
            1,
        )
        self.assertTrue(gate.inspect_test_text(missing_case))
        no_call = self.headless.replace(gate.FUNCTION, "removed_append_prefix", 1)
        self.assertTrue(gate.inspect_headless_text(no_call))
        false_claim = self.headless + '\n/* initializer-dispatch=executed */\n'
        self.assertTrue(gate.inspect_headless_text(false_claim))
        stale_allocator = self.headless.replace(
            "allocator=injected-4-byte;native-allocator=not-run;",
            "allocator=not-run;native-allocator=not-run;",
            1,
        )
        self.assertNotEqual(stale_allocator, self.headless)
        self.assertTrue(gate.inspect_headless_text(stale_allocator))
        stale_growth = self.headless.replace(
            "initializer-growth=injected-complete;",
            "initializer-growth=not-linked;",
            1,
        )
        self.assertNotEqual(stale_growth, self.headless)
        self.assertTrue(gate.inspect_headless_text(stale_growth))
        stale_router = self.headless.replace(
            "initializer-router=injected-complete;",
            "initializer-router=not-linked;",
            1,
        )
        self.assertNotEqual(stale_router, self.headless)
        self.assertTrue(gate.inspect_headless_text(stale_router))
        stale_release = self.headless.replace(
            "growth-release=injected-old-backing;native-release=not-run;",
            "growth-release=not-run;native-release=not-run;",
            1,
        )
        self.assertNotEqual(stale_release, self.headless)
        self.assertTrue(gate.inspect_headless_text(stale_release))

    def test_cmake_containment_and_fixture_mutants_fail(self):
        shared = self.cmake.replace(
            gate.LIBRARY + "\n    STATIC", gate.LIBRARY + "\n    SHARED", 1
        )
        self.assertTrue(gate.inspect_cmake_text(shared))
        no_headless = self.cmake.replace(
            "      " + gate.LIBRARY + "\n", "", 1
        )
        self.assertTrue(gate.inspect_cmake_text(no_headless))
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
        reordered_terminal = self.cmake.replace(
            "      rome2_startup_100e2460_growth_branch_runtime\n"
            "      rome2_startup_100e2460_router_runtime\n",
            "      rome2_startup_100e2460_router_runtime\n"
            "      rome2_startup_100e2460_growth_branch_runtime\n",
            1,
        )
        self.assertNotEqual(reordered_terminal, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(reordered_terminal))
        bypassed_successor = self.cmake.replace(
            "    PRIVATE rome2_startup_100e2460_append_prefix_runtime\n"
            "  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100e2460_preallocated_branch_runtime",
            "    PRIVATE rome2_guest32_runtime\n"
            "  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100e2460_preallocated_branch_runtime",
            1,
        )
        self.assertNotEqual(bypassed_successor, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(bypassed_successor))
        production = self.cmake + (
            "\ntarget_link_libraries(empire_retail_bootstrap PRIVATE "
            + gate.LIBRARY + ")\n"
        )
        self.assertTrue(gate.inspect_cmake_text(production))
        stale_predecessor = self.cmake.replace(
            "startup_100e8240_fastpath_reload_verified;"
            "startup_100e2460_append_prefix_provenance_verified",
            "startup_100e8240_fastpath_post_verified;"
            "startup_100e2460_append_prefix_provenance_verified",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(stale_predecessor))

    def test_post_reload_and_headless_fixture_mutants_fail(self):
        missing_post_setup = self.cmake.replace(
            "      FIXTURES_SETUP startup_100e2460_append_prefix_post_verified\n",
            "",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(missing_post_setup))
        missing_reload_setup = self.cmake.replace(
            "      FIXTURES_SETUP startup_100e2460_append_prefix_reload_verified\n",
            "",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(missing_reload_setup))
        stale_headless_dependency = self.cmake.replace(
            "entry_policy_provenance_verified;entry_policy_static_verified;"
            "startup_100ed471_ordinary_lifecycle_reload_verified",
            "entry_policy_provenance_verified;entry_policy_static_verified;"
            "startup_100df270_platform_prefix_transcript_reload_verified",
            1,
        )
        self.assertNotEqual(stale_headless_dependency, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(stale_headless_dependency))

    def test_final_outer_composition_mutants_fail(self):
        stale_unknown_fallback = self.headless.replace(
            "    ++context->bad_observations;\n    return UINT32_C(0);",
            "    return UINT32_C(0x600000b1) + append;",
            1,
        )
        self.assertNotEqual(stale_unknown_fallback, self.headless)
        self.assertTrue(any(
            "unknown-method fallbacks" in finding
            for finding in gate.inspect_headless_text(stale_unknown_fallback)
        ))
        for called_function, expected_count in gate.FINAL_HEADLESS_CALLS:
            if expected_count == 0:
                mutant = self.headless + (
                    "\nvoid direct_child_mutant(void) {\n    "
                    + called_function + "();\n}\n"
                )
            else:
                mutant = self.headless.replace(
                    called_function, "removed_final_call", 1
                )
            self.assertNotEqual(mutant, self.headless)
            self.assertTrue(any(
                "call-site count changed" in finding
                for finding in gate.inspect_headless_text(mutant)
            ))
        for token in gate.FINAL_HEADLESS_TOKENS:
            mutant = self.headless.replace(token, "missing-final-token", 1)
            self.assertNotEqual(mutant, self.headless)
            self.assertTrue(any(
                token in finding for finding in gate.inspect_headless_text(mutant)
            ))
        reversed_tokens = self.headless.replace(
            gate.FINAL_HEADLESS_TOKENS[-2], "__rome2_token_swap__", 1
        ).replace(
            gate.FINAL_HEADLESS_TOKENS[-1], gate.FINAL_HEADLESS_TOKENS[-2], 1
        ).replace(
            "__rome2_token_swap__", gate.FINAL_HEADLESS_TOKENS[-1], 1
        )
        self.assertNotEqual(reversed_tokens, self.headless)
        self.assertTrue(any(
            "token tail order" in finding
            for finding in gate.inspect_headless_text(reversed_tokens)
        ))
        outer = gate.FINAL_HEADLESS_LIBRARIES[-1]
        headless_link = self.cmake.index(
            "target_link_libraries(\n    rome2_headless64\n"
        )
        outer_line = "      " + outer + "\n"
        outer_position = self.cmake.index(outer_line, headless_link)
        missing_outer = (
            self.cmake[:outer_position]
            + self.cmake[outer_position + len(outer_line):]
        )
        self.assertNotEqual(missing_outer, self.cmake)
        self.assertTrue(any(
            "headless admitted-library composition changed" in finding
            for finding in gate.inspect_cmake_text(missing_outer)
        ))
        reordered_outer = self.cmake.replace(
            "      " + gate.FINAL_HEADLESS_LIBRARIES[-2] + "\n"
            "      " + outer + "\n",
            "      " + outer + "\n"
            "      " + gate.FINAL_HEADLESS_LIBRARIES[-2] + "\n",
            1,
        )
        self.assertNotEqual(reordered_outer, self.cmake)
        self.assertTrue(any(
            "headless admitted-library composition changed" in finding
            for finding in gate.inspect_cmake_text(reordered_outer)
        ))
        missing_ctest = self.cmake.replace("  add_test(\n", "  add_test_removed(\n", 1)
        self.assertNotEqual(missing_ctest, self.cmake)
        self.assertTrue(any(
            "194 CTests" in finding
            for finding in gate.inspect_cmake_text(missing_ctest)
        ))

    def test_export_escape_is_rejected(self):
        self.assertTrue(gate.inspect_exports_text("ordinal\t100e2460\n"))
        self.assertEqual(gate.inspect_exports_text("ordinal\tentry_point\n"), [])

    def test_suffix_successor_freeze_mutants_fail(self):
        direct_call = self.headless + (
            "\nvoid direct_suffix_mutant(void) {\n    "
            + gate.SUFFIX_FUNCTION + "();\n}\n"
        )
        self.assertNotEqual(direct_call, self.headless)
        self.assertTrue(any(
            "call-site count changed" in finding
            for finding in gate.inspect_headless_text(direct_call)
        ))
        missing_token = self.headless.replace(
            gate.FINAL_HEADLESS_TOKENS[-3], "missing-suffix-token", 1
        )
        self.assertNotEqual(missing_token, self.headless)
        self.assertTrue(any(
            gate.FINAL_HEADLESS_TOKENS[-3] in finding
            for finding in gate.inspect_headless_text(missing_token)
        ))
        suffix_line = "      " + gate.SUFFIX_LIBRARY + "\n"
        before, separator, after = self.cmake.rpartition(suffix_line)
        self.assertEqual(separator, suffix_line)
        missing_library = before + after
        self.assertNotEqual(missing_library, self.cmake)
        self.assertTrue(any(
            "headless admitted-library composition changed" in finding
            for finding in gate.inspect_cmake_text(missing_library)
        ))
        escaped_library = self.cmake + (
            "\nadd_library(" + gate.SUFFIX_LIBRARY + " STATIC escaped.c)\n"
        )
        self.assertTrue(any(
            "escapes BUILD_TESTING" in finding
            for finding in gate.inspect_cmake_text(escaped_library)
        ))
        comment_drift = self.headless + "\n/* suffix composition drift */\n"
        self.assertTrue(any(
            "headless exact digest changed" in finding
            for finding in gate.inspect_headless_text(comment_drift)
        ))
        cmake_drift = self.cmake + "\n# platform-prefix composition drift\n"
        self.assertTrue(any(
            "CMake exact digest changed" in finding
            for finding in gate.inspect_cmake_text(cmake_drift)
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)

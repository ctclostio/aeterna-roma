#!/usr/bin/env python3
"""Reciprocal mutants for the 0x100e2460 preallocated-branch static gate."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GATE_PATH = (
    ROOT / "scripts" /
    "x64_startup_100e2460_preallocated_branch_static_gate.py"
)
SPEC = importlib.util.spec_from_file_location("preallocated_branch_gate", GATE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load preallocated-branch static gate")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


class Startup100e2460PreallocatedBranchStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read(
            "port/x64_ported/ported_100e2460_preallocated_branch.h"
        )
        cls.source = read(
            "port/x64_ported/ported_100e2460_preallocated_branch.c"
        )
        cls.test = read(
            "port/x64_runtime/test_startup_100e2460_preallocated_branch.c"
        )
        cls.append_provenance = read_bytes(
            "scripts/test_x64_startup_100e2460_append_prefix_provenance.py"
        )
        cls.branch_provenance = read_bytes(
            "scripts/test_x64_startup_100e2460_preallocated_branch_provenance.py"
        )
        cls.headless = read("port/x64_headless/headless_main.c")
        cls.cmake = read("CMakeLists.txt")

    def assert_finding(self, findings: list[str], fragment: str) -> None:
        self.assertTrue(
            any(fragment in finding for finding in findings),
            f"expected finding containing {fragment!r}; got {findings!r}",
        )

    def test_live_core_inputs_and_authorities_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_test_text(self.test), [])
        self.assertEqual(
            gate.inspect_provenance_bytes(
                self.append_provenance,
                expected_sha256=gate.EXPECTED_APPEND_PROVENANCE_SHA256,
                label="append-prefix",
            ),
            [],
        )
        self.assertEqual(
            gate.inspect_provenance_bytes(
                self.branch_provenance,
                expected_sha256=gate.EXPECTED_BRANCH_PROVENANCE_SHA256,
                label="preallocated-branch",
            ),
            [],
        )

    def test_live_integration_inputs_pass(self):
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_provenance_authority_mutants_fail(self):
        changed_append = self.append_provenance + b"\n# authority mutant\n"
        findings = gate.inspect_provenance_bytes(
            changed_append,
            expected_sha256=gate.EXPECTED_APPEND_PROVENANCE_SHA256,
            label="append-prefix",
        )
        self.assert_finding(findings, "append-prefix provenance authority digest")

        changed_branch = self.branch_provenance.replace(
            b"COUNT_DISPATCH_BYTES", b"COUNT_DISPATCH_REMOVED"
        )
        findings = gate.inspect_provenance_bytes(
            changed_branch,
            expected_sha256=gate.EXPECTED_BRANCH_PROVENANCE_SHA256,
            label="preallocated-branch",
        )
        self.assert_finding(findings, "preallocated-branch provenance authority digest")
        self.assert_finding(findings, "branch provenance token missing")

    def test_unsigned_branch_and_scale_four_mutants_fail(self):
        wrong_branch = self.source.replace(
            "if (count >= capacity)", "if (count > capacity)", 1
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_branch),
            "unsigned count < capacity branch changed",
        )
        wrong_scale = self.source.replace(
            "(uint64_t)count * UINT64_C(4)",
            "(uint64_t)count * UINT64_C(8)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_scale),
            "scale-4 append calculation changed",
        )

    def test_handler_read_and_vtable_plus_four_mutants_fail(self):
        wrong_handler_read = self.source.replace(
            "state_view->host_base + (size_t)handler_offset",
            "state_view->host_base + (size_t)handler_offset + 4",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_handler_read),
            "handler/vtable +4 resolution changed",
        )
        wrong_slot = self.source.replace(
            "method_cell.value = vtable_identity.value + UINT32_C(4);",
            "method_cell.value = vtable_identity.value + UINT32_C(8);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_slot),
            "handler/vtable +4 resolution changed",
        )

    def test_prefix_composition_and_dispatch_order_mutants_fail(self):
        removed_prefix = self.source.replace(
            gate.PREFIX_FUNCTION, "removed_append_prefix", 1
        )
        self.assert_finding(
            gate.inspect_source_text(removed_prefix),
            "append-prefix composition changed",
        )

        prefix_start = self.source.index("    append_status = ")
        dispatch_start = self.source.index("    dispatch_eax = ", prefix_start)
        dispatch_end = self.source.index(
            "    null_identity.value = 0;", dispatch_start
        )
        prefix_block = self.source[prefix_start:dispatch_start]
        dispatch_block = self.source[dispatch_start:dispatch_end]
        dispatch_first = (
            self.source[:prefix_start]
            + dispatch_block
            + prefix_block
            + self.source[dispatch_end:]
        )
        self.assert_finding(
            gate.inspect_source_text(dispatch_first),
            "validation/append/dispatch/drain/AL effect order changed",
        )

    def test_peek_argument_tuple_mutants_fail(self):
        skipped_null = self.source.replace(
            "            null_identity,\n            null_identity,\n",
            "            null_identity,\n",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(skipped_null),
            "Peek-shaped argument tuple changed",
        )
        wrong_remove = self.source.replace(
            "            ROME2_PORT_100E2460_PM_REMOVE);",
            "            UINT32_C(0));",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_remove),
            "Peek-shaped argument tuple changed",
        )
        wrong_filter = self.source.replace(
            "            UINT32_C(0),\n            UINT32_C(0),\n"
            "            ROME2_PORT_100E2460_PM_REMOVE);",
            "            UINT32_C(1),\n            UINT32_C(0),\n"
            "            ROME2_PORT_100E2460_PM_REMOVE);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_filter),
            "Peek-shaped argument tuple changed",
        )

    def test_bounded_loop_and_polarity_mutants_fail(self):
        loop = (
            "for (peek_calls = 0; peek_calls < max_peek_calls; ++peek_calls)"
        )
        unbounded = self.source.replace(loop, "for (;;)", 1)
        self.assert_finding(
            gate.inspect_source_text(unbounded),
            "finite Peek-shaped loop bound changed",
        )
        inverted = self.source.replace(
            loop,
            "for (peek_calls = 0; peek_calls >= max_peek_calls; ++peek_calls)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(inverted),
            "finite Peek-shaped loop bound changed",
        )
        inverted_termination = self.source.replace(
            "if (peek_eax == 0)", "if (peek_eax != 0)", 1
        )
        self.assert_finding(
            gate.inspect_source_text(inverted_termination),
            "terminating-zero AL publish semantics changed",
        )

    def test_early_or_duplicate_al_publish_mutants_fail(self):
        early = self.source.replace(
            "    null_identity.value = 0;",
            "    *return_al_out = saved_al;\n    null_identity.value = 0;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(early),
            "return AL must be published exactly once",
        )
        removed_publish = self.source.replace(
            "            *return_al_out = saved_al;",
            "            saved_al = (uint8_t)peek_eax;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(removed_publish),
            "terminating-zero AL publish semantics changed",
        )

    def test_alias_matrix_mutants_fail(self):
        removed_alias = self.source.replace(
            "rome2_100e2460_spans_overlap(\n"
            "            (uintptr_t)return_al_out,",
            "rome2_100e2460_removed_alias_check(\n"
            "            (uintptr_t)return_al_out,",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(removed_alias),
            "required precommit alias-check matrix changed",
        )
        removed_method_alias = self.source.replace(
            "rome2_100e2460_spans_overlap(\n"
            "            (uint64_t)method_cell.value,",
            "rome2_100e2460_removed_alias_check(\n"
            "            (uint64_t)method_cell.value,",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(removed_method_alias),
            "required precommit alias-check matrix changed",
        )

    def test_control_alias_checks_precede_descriptor_dereferences(self):
        marker = "    /* Reject overlapping control objects before dereferencing"
        early_dereference = (
            "    status = rome2_100e2460_validate_interval(\n"
            "        state_view->host_base, state_view->guest_base, "
            "state_view->byte_count);\n\n"
        )
        reordered = self.source.replace(marker, early_dereference + marker, 1)
        self.assert_finding(
            gate.inspect_source_text(reordered),
            "control-object alias validation order changed",
        )

    def test_allocator_native_dynamic_and_guest_cast_mutants_fail(self):
        mutants = (
            ("\nvoid *malloc(size_t);\n", "malloc"),
            (
                "\nint PeekMessageW(void *, void *, unsigned, unsigned, unsigned);\n",
                "PeekMessageW",
            ),
            ("\nvoid *GetProcAddress(void *, const char *);\n", "GetProcAddress"),
        )
        for injected, identifier in mutants:
            with self.subTest(identifier=identifier):
                self.assert_finding(
                    gate.inspect_source_text(self.source + injected),
                    f"forbidden allocation/platform/dynamic identifier: {identifier}",
                )
        guest_cast = self.source + (
            "\nstatic void *bad_guest_cast(rome2_guest_addr32 guest)\n"
            "{\n    return (void *)(uintptr_t)guest.value;\n}\n"
        )
        self.assert_finding(
            gate.inspect_source_text(guest_cast),
            "guest identity is converted to a native pointer/address",
        )

    def test_header_and_runtime_oracle_mutants_fail(self):
        wrong_pm_remove = self.header.replace(
            "ROME2_PORT_100E2460_PM_REMOVE UINT32_C(1)",
            "ROME2_PORT_100E2460_PM_REMOVE UINT32_C(0)",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_pm_remove), "PM_REMOVE constant changed"
        )
        wrong_allocation_status = self.header.replace(
            "ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID = 6",
            "ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID = 7",
            1,
        )
        self.assertNotEqual(wrong_allocation_status, self.header)
        self.assert_finding(
            gate.inspect_header_text(wrong_allocation_status),
            "branch status contract changed",
        )
        missing_safety = self.header.replace("finite drain bound", "infinite drain")
        self.assert_finding(
            gate.inspect_header_text(missing_safety), "header safety contract"
        )
        missing_case = self.test.replace(
            '"drain limit keeps committed effects"',
            '"drain limit loses committed effects"',
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(missing_case), "required runtime case missing"
        )
        weakened_trace = self.test.replace(
            "fixture.context.trace[0] != 1",
            "fixture.context.trace[0] != 2",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(weakened_trace),
            "independent runtime oracle changed",
        )

    def test_headless_call_and_boundary_claim_mutants_fail(self):
        no_call = self.headless.replace(gate.FUNCTION, "removed_branch", 1)
        self.assert_finding(
            gate.inspect_headless_text(no_call), "execute the preallocated branch"
        )
        stale_claim = self.headless.replace(
            "initializer-dispatch=injected-complete",
            "initializer-dispatch=not-linked",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(stale_claim),
            "initializer-dispatch=injected-complete",
        )
        false_native_claim = self.headless + (
            "\n/* queue-drain=executed;allocator=executed */\n"
        )
        findings = gate.inspect_headless_text(false_native_claim)
        self.assert_finding(findings, "falsely claims excluded native behavior")
        stale_allocator = self.headless.replace(
            "allocator=injected-4-byte;native-allocator=not-run;",
            "allocator=not-run;native-allocator=not-run;",
            1,
        )
        self.assertNotEqual(stale_allocator, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(stale_allocator),
            "allocator=injected-4-byte",
        )
        stale_growth = self.headless.replace(
            "initializer-growth=injected-complete;",
            "initializer-growth=not-linked;",
            1,
        )
        self.assertNotEqual(stale_growth, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(stale_growth),
            "initializer-growth=injected-complete",
        )
        stale_router = self.headless.replace(
            "initializer-router=injected-complete;",
            "initializer-router=not-linked;",
            1,
        )
        self.assertNotEqual(stale_router, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(stale_router),
            "initializer-router=injected-complete",
        )
        stale_release = self.headless.replace(
            "growth-release=injected-old-backing;native-release=not-run;",
            "growth-release=not-run;native-release=not-run;",
            1,
        )
        self.assertNotEqual(stale_release, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(stale_release),
            "growth-release=injected-old-backing",
        )

    def test_cmake_containment_and_consumer_mutants_fail(self):
        shared = self.cmake.replace(
            gate.LIBRARY + "\n    STATIC",
            gate.LIBRARY + "\n    SHARED",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(shared), "BUILD_TESTING-only static library"
        )
        headless_library_line = "      " + gate.LIBRARY + "\n"
        before, separator, after = self.cmake.rpartition(headless_library_line)
        self.assertEqual(separator, headless_library_line)
        no_headless = before + after
        self.assert_finding(
            gate.inspect_cmake_text(no_headless), "unexpected consumer/dependency"
        )
        headless_growth_line = "      " + gate.GROWTH_LIBRARY + "\n"
        before, separator, after = self.cmake.rpartition(headless_growth_line)
        self.assertEqual(separator, headless_growth_line)
        missing_growth = before + after
        self.assertNotEqual(missing_growth, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(missing_growth),
            "exact headless admitted-slice link list changed",
        )
        substituted_growth = (
            before + "      " + gate.CAPACITY_ZERO_LIBRARY + "\n" + after
        )
        self.assertNotEqual(substituted_growth, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(substituted_growth),
            "exact headless admitted-slice link list changed",
        )
        missing_router = self.cmake.replace(
            "      " + gate.ROUTER_LIBRARY + "\n", "", 1
        )
        self.assertNotEqual(missing_router, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(missing_router),
            "exact headless admitted-slice link list changed",
        )
        substituted_router = self.cmake.replace(
            "      " + gate.ROUTER_LIBRARY + "\n",
            "      " + gate.GROWTH_LIBRARY + "\n",
            1,
        )
        self.assertNotEqual(substituted_router, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(substituted_router),
            "exact headless admitted-slice link list changed",
        )
        reordered_terminal = self.cmake.replace(
            "      " + gate.GROWTH_LIBRARY + "\n"
            "      " + gate.ROUTER_LIBRARY + "\n",
            "      " + gate.ROUTER_LIBRARY + "\n"
            "      " + gate.GROWTH_LIBRARY + "\n",
            1,
        )
        self.assertNotEqual(reordered_terminal, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(reordered_terminal),
            "exact headless admitted-slice link list changed",
        )
        missing_capacity_zero_dependency = self.cmake.replace(
            "    PRIVATE rome2_startup_100e2460_preallocated_branch_runtime\n"
            "  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100e2460_capacity_zero_branch_runtime",
            "    PRIVATE rome2_startup_100e2460_append_prefix_runtime\n"
            "  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100e2460_capacity_zero_branch_runtime",
            1,
        )
        self.assertNotEqual(missing_capacity_zero_dependency, self.cmake)
        findings = gate.inspect_cmake_text(missing_capacity_zero_dependency)
        self.assert_finding(
            findings,
            "capacity-zero branch must depend exactly on the preallocated branch",
        )
        self.assert_finding(findings, "unexpected consumer/dependency")
        removed_capacity_zero_dependency = self.cmake.replace(
            "    PRIVATE rome2_startup_100e2460_preallocated_branch_runtime\n"
            "  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100e2460_capacity_zero_branch_runtime",
            "  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100e2460_capacity_zero_branch_runtime",
            1,
        )
        self.assertNotEqual(removed_capacity_zero_dependency, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(removed_capacity_zero_dependency),
            "capacity-zero branch must depend exactly on the preallocated branch",
        )
        weakened_router_dependency = self.cmake.replace(
            "      rome2_startup_100e2460_preallocated_branch_runtime\n"
            "      rome2_startup_100e2460_capacity_zero_branch_runtime\n"
            "      rome2_startup_100e2460_growth_branch_runtime\n"
            "  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100e2460_router_runtime",
            "      rome2_startup_100e2460_capacity_zero_branch_runtime\n"
            "      rome2_startup_100e2460_growth_branch_runtime\n"
            "  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100e2460_router_runtime",
            1,
        )
        self.assertNotEqual(weakened_router_dependency, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(weakened_router_dependency),
            "router dependency set or order changed",
        )
        production = self.cmake + (
            "\ntarget_link_libraries(empire_retail_bootstrap PRIVATE "
            + gate.LIBRARY + ")\n"
        )
        findings = gate.inspect_cmake_text(production)
        self.assert_finding(findings, "escapes BUILD_TESTING")
        self.assert_finding(findings, "production/probe code")
        missing_authority_arg = self.cmake.replace(
            "      --branch-provenance "
            '"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
            'test_x64_startup_100e2460_preallocated_branch_provenance.py"\n',
            "",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(missing_authority_arg),
            "branch static-gate argument changed",
        )

    def test_cmake_fixture_chain_mutants_fail(self):
        stale_predecessor = self.cmake.replace(
            "startup_100e2460_append_prefix_reload_verified;"
            "startup_100e2460_preallocated_branch_provenance_verified",
            "startup_100e2460_append_prefix_post_verified;"
            "startup_100e2460_preallocated_branch_provenance_verified",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(stale_predecessor), "fixture-chain block changed"
        )
        missing_post_setup = self.cmake.replace(
            "      FIXTURES_SETUP "
            "startup_100e2460_preallocated_branch_post_verified\n",
            "",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(missing_post_setup), "fixture-chain block changed"
        )
        stale_headless = self.cmake.replace(
            "entry_policy_provenance_verified;entry_policy_static_verified;"
            "startup_100ed471_ordinary_lifecycle_reload_verified",
            "entry_policy_provenance_verified;entry_policy_static_verified;"
            "startup_100df270_platform_prefix_transcript_reload_verified",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(stale_headless), "fixture-chain block changed"
        )

    def test_export_escape_is_rejected(self):
        self.assertTrue(gate.inspect_exports_text(
            "ordinal\trome2_port_100e2460_run_preallocated_branch\n"
        ))
        self.assertTrue(gate.inspect_exports_text(
            "ordinal\trome2_100e2460_effects\n"
        ))
        self.assertEqual(gate.inspect_exports_text("ordinal\tentry_point\n"), [])

    def test_final_outer_composition_mutants_fail(self):
        stale_unknown_fallback = self.headless.replace(
            "    ++context->bad_observations;\n    return UINT32_C(0);",
            "    return UINT32_C(0x600000b1) + append;",
            1,
        )
        self.assertNotEqual(stale_unknown_fallback, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(stale_unknown_fallback),
            "unknown-method fallbacks",
        )
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
            self.assert_finding(
                gate.inspect_headless_text(mutant), "call-site count changed"
            )
        for token in gate.FINAL_HEADLESS_TOKENS:
            mutant = self.headless.replace(token, "missing-final-token", 1)
            self.assertNotEqual(mutant, self.headless)
            self.assert_finding(gate.inspect_headless_text(mutant), token)
        reversed_tokens = self.headless.replace(
            gate.FINAL_HEADLESS_TOKENS[-2], "__rome2_token_swap__", 1
        ).replace(
            gate.FINAL_HEADLESS_TOKENS[-1], gate.FINAL_HEADLESS_TOKENS[-2], 1
        ).replace(
            "__rome2_token_swap__", gate.FINAL_HEADLESS_TOKENS[-1], 1
        )
        self.assertNotEqual(reversed_tokens, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(reversed_tokens), "token tail order"
        )
        missing_outer = self.cmake.replace(
            "      " + gate.OUTER_LIBRARY + "\n", "", 1
        )
        self.assertNotEqual(missing_outer, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(missing_outer),
            "exact headless admitted-slice link list changed",
        )
        reordered_outer = self.cmake.replace(
            "      " + gate.HANDLER_8580_LIBRARY + "\n"
            "      " + gate.OUTER_LIBRARY + "\n",
            "      " + gate.OUTER_LIBRARY + "\n"
            "      " + gate.HANDLER_8580_LIBRARY + "\n",
            1,
        )
        self.assertNotEqual(reordered_outer, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(reordered_outer),
            "exact headless admitted-slice link list changed",
        )
        platform_line = "      " + gate.PLATFORM_PREFIX_LIBRARY + "\n"
        before, separator, after = self.cmake.rpartition(platform_line)
        self.assertEqual(separator, platform_line)
        missing_successor = before + after
        self.assertNotEqual(missing_successor, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(missing_successor),
            "exact headless admitted-slice link list changed",
        )
        successor_pair = (
            "      " + gate.SUFFIX_LIBRARY + "\n"
            "      " + gate.PLATFORM_PREFIX_LIBRARY + "\n"
        )
        before, separator, after = self.cmake.rpartition(successor_pair)
        self.assertEqual(separator, successor_pair)
        reversed_successors = (
            before
            + "      " + gate.PLATFORM_PREFIX_LIBRARY + "\n"
            + "      " + gate.SUFFIX_LIBRARY + "\n"
            + after
        )
        self.assertNotEqual(reversed_successors, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(reversed_successors),
            "exact headless admitted-slice link list changed",
        )
        missing_ctest = self.cmake.replace("  add_test(\n", "  add_test_removed(\n", 1)
        self.assertNotEqual(missing_ctest, self.cmake)
        self.assert_finding(gate.inspect_cmake_text(missing_ctest), "192 CTests")

    def test_suffix_successor_freeze_mutants_fail(self):
        direct_call = self.headless + (
            "\nvoid direct_suffix_mutant(void) {\n    "
            + gate.SUFFIX_FUNCTION + "();\n}\n"
        )
        self.assertNotEqual(direct_call, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(direct_call), "call-site count changed"
        )
        missing_token = self.headless.replace(
            gate.FINAL_HEADLESS_TOKENS[-3], "missing-suffix-token", 1
        )
        self.assertNotEqual(missing_token, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(missing_token),
            gate.FINAL_HEADLESS_TOKENS[-3],
        )
        suffix_line = "      " + gate.SUFFIX_LIBRARY + "\n"
        before, separator, after = self.cmake.rpartition(suffix_line)
        self.assertEqual(separator, suffix_line)
        missing_library = before + after
        self.assertNotEqual(missing_library, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(missing_library),
            "exact headless admitted-slice link list changed",
        )
        escaped_library = self.cmake + (
            "\nadd_library(" + gate.SUFFIX_LIBRARY + " STATIC escaped.c)\n"
        )
        self.assert_finding(
            gate.inspect_cmake_text(escaped_library), "escapes BUILD_TESTING"
        )
        comment_drift = self.headless + "\n/* suffix composition drift */\n"
        self.assert_finding(
            gate.inspect_headless_text(comment_drift), "headless exact digest changed"
        )
        cmake_drift = self.cmake + "\n# platform-prefix composition drift\n"
        self.assert_finding(
            gate.inspect_cmake_text(cmake_drift), "CMake exact digest changed"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

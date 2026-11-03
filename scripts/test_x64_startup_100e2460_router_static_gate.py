#!/usr/bin/env python3
"""Reciprocal mutants for the bounded 0x100e2460 router static gate."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
GATE_PATH = SCRIPTS / "x64_startup_100e2460_router_static_gate.py"
SPEC = importlib.util.spec_from_file_location("router_static_gate", GATE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load router static gate")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


class Startup100e2460RouterStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read("port/x64_ported/ported_100e2460_router.h")
        cls.source = read("port/x64_ported/ported_100e2460_router.c")
        cls.test = read("port/x64_runtime/test_startup_100e2460_router.c")
        cls.six_append_test = read(
            "port/x64_runtime/test_startup_100e2460_router_six_append.c"
        )
        cls.provenance = read_bytes(
            "scripts/test_x64_startup_100e2460_router_provenance.py"
        )
        cls.headless = read("port/x64_headless/headless_main.c")
        cls.cmake = read("CMakeLists.txt")
        cls.export_manifest = read("port/x64_exports/export_manifest.tsv")
        cls.legacy_def = read("port/x64_exports/empire.retail.exports.def")
        cls.probe_def = read("port/x64_probe/probe_exports.def")

    def assert_finding(self, findings: list[str], fragment: str) -> None:
        self.assertTrue(
            any(fragment in finding for finding in findings),
            f"expected finding containing {fragment!r}; got {findings!r}",
        )

    def test_live_inputs_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_test_text(self.test), [])
        self.assertEqual(
            gate.inspect_six_append_test_text(self.six_append_test), []
        )
        self.assertEqual(gate.inspect_provenance_bytes(self.provenance), [])
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])
        self.assertEqual(gate.inspect_exports_text(self.export_manifest), [])
        self.assertEqual(gate.inspect_exports_text(self.legacy_def), [])
        self.assertEqual(gate.inspect_exports_text(self.probe_def), [])

    def test_header_full_effects_api_and_contract_mutants_fail(self):
        smaller_effects = self.header.replace(
            "const rome2_100e2460_growth_effects *effects",
            "const rome2_100e2460_effects *effects",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(smaller_effects), "public router API contract"
        )
        wrong_parent = self.header.replace(
            '#include "ported_100e2460_growth_branch.h"',
            '#include "ported_100e2460_capacity_zero_branch.h"',
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_parent), "growth superset contract"
        )
        admits_reentry = self.header.replace(
            "exclusive, non-reentrant borrow", "shared, reentrant borrow", 1
        )
        self.assert_finding(
            gate.inspect_header_text(admits_reentry), "safety/selection contract"
        )

    def test_unsigned_selector_and_exact_offsets_mutants_fail(self):
        signed_or_equal = self.source.replace(
            "if (count < capacity)", "if ((int32_t)count <= (int32_t)capacity)", 1
        )
        self.assert_finding(
            gate.inspect_source_text(signed_or_equal),
            "unsigned preallocated selection/delegate changed",
        )
        swapped_offsets = self.source.replace(
            "vector + 4);\n    *count_out = "
            "rome2_100e2460_router_read_u32_le(vector + 8);",
            "vector + 8);\n    *count_out = "
            "rome2_100e2460_router_read_u32_le(vector + 4);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(swapped_offsets), "selector offsets changed"
        )
        weakened_end = self.source.replace(
            "UINT32_MAX -\n            (uint32_t)(",
            "UINT32_MAX - UINT32_C(4) -\n            (uint32_t)(",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(weakened_end), "checked guest32 end changed"
        )

    def test_full_effects_control_and_host_alias_mutants_fail(self):
        partial_effect_object = self.source.replace(
            "(uint64_t)(uintptr_t)effects,\n            sizeof(*effects)) ||",
            "(uint64_t)(uintptr_t)effects,\n"
            "            sizeof(effects->tail_effects)) ||",
            1,
        )
        findings = gate.inspect_source_text(partial_effect_object)
        self.assert_finding(findings, "pairwise alias validation changed")
        missing_output_effect_pair = self.source.replace(
            "        rome2_100e2460_router_spans_overlap(\n"
            "            (uint64_t)(uintptr_t)return_al_out,\n"
            "            sizeof(*return_al_out),\n"
            "            (uint64_t)(uintptr_t)effects,\n"
            "            sizeof(*effects));",
            "        0;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(missing_output_effect_pair),
            "full control/host alias matrix changed",
        )
        missing_state_bytes_effect_pair = self.source.replace(
            "        rome2_100e2460_router_spans_overlap(\n"
            "            (uint64_t)(uintptr_t)state_view->host_base,\n"
            "            state_view->byte_count,\n"
            "            (uint64_t)(uintptr_t)effects,\n"
            "            sizeof(*effects)) ||",
            "        0 ||",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(missing_state_bytes_effect_pair),
            "full control/host alias matrix changed",
        )

    def test_snapshot_before_selector_and_no_reread_mutants_fail(self):
        missing_snapshot = self.source.replace(
            "    effects_snapshot = *effects;\n", "", 1
        )
        self.assert_finding(
            gate.inspect_source_text(missing_snapshot), "validation/snapshot stage"
        )
        after_selector = self.source.replace(
            "    effects_snapshot = *effects;\n"
            "    status = rome2_100e2460_router_read_selector(",
            "    status = rome2_100e2460_router_read_selector(",
            1,
        ).replace(
            "    if (status != ROME2_100E2460_BRANCH_OK) {\n"
            "        return status;\n"
            "    }\n\n    if (count < capacity)",
            "    if (status != ROME2_100E2460_BRANCH_OK) {\n"
            "        return status;\n"
            "    }\n    effects_snapshot = *effects;\n\n    if (count < capacity)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(after_selector),
            "validation, snapshot, and selector order changed",
        )
        direct_effects = self.source.replace(
            "&effects_snapshot.tail_effects", "&effects->tail_effects", 1
        )
        self.assert_finding(
            gate.inspect_source_text(direct_effects),
            "unsigned preallocated selection/delegate changed",
        )

    def test_three_delegate_and_adapter_mutants_fail(self):
        wrong_preallocated = self.source.replace(
            "rome2_port_100e2460_run_preallocated_branch(",
            "rome2_port_100e2460_run_growth_branch(",
            1,
        )
        findings = gate.inspect_source_text(wrong_preallocated)
        self.assert_finding(findings, "preallocated selection/delegate changed")
        self.assert_finding(findings, "delegate must occur exactly once")
        wrong_zero_adapter = self.source.replace(
            "zero_effects.allocate = effects_snapshot.allocate;",
            "zero_effects.allocate = NULL;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_zero_adapter),
            "capacity-zero adapter/delegate changed",
        )
        releases_from_zero = self.source.replace(
            "zero_effects.allocate = effects_snapshot.allocate;",
            "zero_effects.allocate = effects_snapshot.allocate;\n"
            "    zero_effects.release = effects_snapshot.release;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(releases_from_zero),
            "must not expose inactive release",
        )
        wrong_growth = self.source.replace(
            "&effects_snapshot,\n        max_peek_calls,",
            "&zero_effects,\n        max_peek_calls,",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_growth), "nonzero-growth delegate changed"
        )

    def test_route_inactive_callback_rejection_is_forbidden(self):
        rejects_release = self.source.replace(
            "    effects_snapshot = *effects;",
            "    effects_snapshot = *effects;\n"
            "    if (effects_snapshot.release == NULL) {\n"
            "        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;\n"
            "    }",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(rejects_release),
            "must not reject route-inactive null callbacks",
        )
        rejects_allocate = self.source.replace(
            "    effects_snapshot = *effects;",
            "    effects_snapshot = *effects;\n"
            "    if (effects_snapshot.allocate == NULL) {\n"
            "        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;\n"
            "    }",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(rejects_allocate),
            "must not reject route-inactive null callbacks",
        )

    def test_native_allocator_release_platform_and_guest_cast_mutants_fail(self):
        for identifier in ("malloc", "free", "PeekMessageW", "GetProcAddress"):
            with self.subTest(identifier=identifier):
                mutant = self.source + f"\nvoid bad(void) {{ {identifier}(0); }}\n"
                self.assert_finding(
                    gate.inspect_source_text(mutant),
                    f"forbidden allocation/release/platform identifier: {identifier}",
                )
        guest_cast = self.source + (
            "\nstatic void *bad_guest_cast(rome2_guest_addr32 guest_handler)\n"
            "{ return (void *)guest_handler.value; }\n"
        )
        self.assert_finding(
            gate.inspect_source_text(guest_cast),
            "guest identity is converted to a native pointer",
        )

    def test_runtime_route_unsigned_and_inactive_callback_mutants_fail(self):
        missing_route = self.test.replace(
            "rome2_test_unsigned_preallocated_route",
            "rome2_test_removed_unsigned_route",
        )
        self.assert_finding(
            gate.inspect_test_text(missing_route), "route/edge oracle missing"
        )
        signed_boundary = self.test.replace(
            "UINT32_C(0x80000000)", "UINT32_C(0x7fffffff)", 1
        )
        self.assert_finding(
            gate.inspect_test_text(signed_boundary), "unsigned high-bit selector"
        )
        active_release = self.test.replace(
            "fixture.effects.release = NULL;", "fixture.effects.release = rome2_test_release;", 1
        )
        self.assert_finding(
            gate.inspect_test_text(active_release), "inactive release-null oracle"
        )

    def test_runtime_drain_partial_commit_and_alias_mutants_fail(self):
        lost_drain = self.test.replace(
            "ROME2_100E2460_BRANCH_DRAIN_LIMIT",
            "ROME2_100E2460_BRANCH_OK",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(lost_drain), "all-route drain-limit coverage"
        )
        lost_partial_commit = self.test.replace(
            "ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID",
            "ROME2_100E2460_BRANCH_BAD_ARGUMENT",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(lost_partial_commit),
            "partial-commit allocation coverage",
        )
        lost_physical_alias = self.test.replace(
            '"method physically aliases count write"',
            '"method does not alias count write"',
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(lost_physical_alias), "diagnostic/coverage case"
        )

    def test_six_append_sequence_effect_trace_and_boundary_mutants_fail(self):
        wrong_count = self.six_append_test.replace(
            "#define ROME2_TEST_APPEND_COUNT 6",
            "#define ROME2_TEST_APPEND_COUNT 5",
            1,
        )
        self.assert_finding(
            gate.inspect_six_append_test_text(wrong_count),
            "six-append count oracle changed",
        )
        wrong_sizes = self.six_append_test.replace(
            "{4, 8, 16, 32}", "{4, 8, 16, 16}", 1
        )
        self.assert_finding(
            gate.inspect_six_append_test_text(wrong_sizes),
            "allocation-size progression changed",
        )
        lost_release = self.six_append_test.replace(
            "ROME2_TEST_EVENT_RELEASE", "ROME2_TEST_EVENT_DISPATCH", 1
        )
        self.assert_finding(
            gate.inspect_six_append_test_text(lost_release),
            "release trace changed",
        )
        bypass_router = self.six_append_test.replace(
            gate.FUNCTION, "rome2_port_100e2460_run_growth_branch", 1
        )
        findings = gate.inspect_six_append_test_text(bypass_router)
        self.assert_finding(findings, "execute only the router boundary")
        self.assert_finding(findings, "bypasses router via delegate")

    def test_provenance_authority_truth_table_and_policy_mutants_fail(self):
        changed_digest = self.provenance.replace(
            b"CAPACITY_DISCRIMINATOR_BYTES", b"CAPACITY_ROUTING_BYTES"
        )
        findings = gate.inspect_provenance_bytes(changed_digest)
        self.assert_finding(findings, "authority digest changed")
        self.assert_finding(findings, "provenance token missing")
        signed_selector = self.provenance.replace(
            b"if count < capacity:", b"if int(count) <= int(capacity):", 1
        )
        self.assert_finding(
            gate.inspect_provenance_bytes(signed_selector), "authority digest changed"
        )
        false_policy = self.provenance.replace(
            b"none is claimed", b"allx is claimed",
            1,
        )
        self.assert_finding(
            gate.inspect_provenance_bytes(false_policy),
            "evidence/policy boundary missing",
        )

    def test_headless_router_call_and_truthful_tokens_mutants_fail(self):
        no_call = self.headless.replace(gate.FUNCTION, "removed_router", 1)
        self.assert_finding(
            gate.inspect_headless_text(no_call), "execute the router exactly once"
        )
        stale_router = self.headless.replace(
            "initializer-router=injected-complete",
            "initializer-router=not-linked",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(stale_router),
            "initializer-router=injected-complete",
        )
        false_native = self.headless.replace(
            "native-release=not-run", "native-release=executed", 1
        )
        findings = gate.inspect_headless_text(false_native)
        self.assert_finding(findings, "native-release=not-run")
        self.assert_finding(findings, "falsely claims excluded native behavior")
        lost_growth = self.headless.replace(
            "growth-release=injected-old-backing", "growth-release=not-run", 1
        )
        self.assert_finding(
            gate.inspect_headless_text(lost_growth),
            "growth-release=injected-old-backing",
        )

    def test_cmake_static_exact_dependencies_and_consumers_mutants_fail(self):
        shared = self.cmake.replace(
            gate.LIBRARY + "\n    STATIC", gate.LIBRARY + "\n    SHARED", 1
        )
        self.assert_finding(
            gate.inspect_cmake_text(shared), "BUILD_TESTING-only static library"
        )
        wrong_dependency = self.cmake.replace(
            "      " + gate.CAPACITY_ZERO_LIBRARY + "\n",
            "      " + gate.PREALLOCATED_LIBRARY + "\n",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(wrong_dependency),
            "exact three-delegate dependency list changed",
        )
        no_headless = self.cmake.replace("      " + gate.LIBRARY + "\n", "", 1)
        findings = gate.inspect_cmake_text(no_headless)
        self.assert_finding(findings, "unexpected consumer/dependency")
        self.assert_finding(findings, "exact headless admitted-slice link list")
        extra_consumer = self.cmake.replace(
            "  set_property(\n    TARGET " + gate.LIBRARY,
            "  target_link_libraries(empire_retail_bootstrap PRIVATE "
            + gate.LIBRARY + ")\n  set_property(\n    TARGET " + gate.LIBRARY,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(extra_consumer), "unexpected consumer/dependency"
        )

    def test_cmake_six_append_cli_and_fixture_mutants_fail(self):
        six_link = (
            "  target_link_libraries(\n"
            "    " + gate.SIX_APPEND_TEST_TARGET + "\n"
            "    PRIVATE " + gate.LIBRARY + "\n"
            "  )"
        )
        self.assertIn(six_link, self.cmake)
        no_six_link = self.cmake.replace(
            six_link,
            "  target_link_libraries(\n"
            "    " + gate.SIX_APPEND_TEST_TARGET + "\n"
            "    PRIVATE " + gate.GROWTH_LIBRARY + "\n"
            "  )",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(no_six_link), "six-append test must link"
        )
        no_provenance_arg = self.cmake.replace(
            "      --router-provenance "
            '"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
            'test_x64_startup_100e2460_router_provenance.py"\n',
            "",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(no_provenance_arg),
            "router static-gate argument changed",
        )
        stale_terminal = self.cmake.replace(
            "startup_100ed471_ordinary_lifecycle_reload_verified\"\n      TIMEOUT 90",
            "startup_100df270_platform_prefix_transcript_reload_verified\"\n      TIMEOUT 90",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(stale_terminal), "fixture-chain block changed"
        )
        bypass_six = self.cmake.replace(
            "startup_100e2460_router_six_append_runtime_verified;"
            "entry_policy_probe_pe_tool_verified",
            "startup_100e2460_router_runtime_verified;"
            "entry_policy_probe_pe_tool_verified",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(bypass_six), "fixture-chain block changed"
        )

    def test_export_escape_is_rejected(self):
        for token in (
            gate.FUNCTION, gate.LIBRARY, "ported_100e2460_router.h",
        ):
            with self.subTest(token=token):
                self.assertTrue(gate.inspect_exports_text("ordinal\t" + token + "\n"))
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
        self.assert_finding(gate.inspect_cmake_text(missing_ctest), "194 CTests")
        missing_outer_dependency = self.cmake.replace(
            "    PRIVATE " + gate.LIBRARY + "\n"
            "  )\n"
            "  set_property(\n"
            "    TARGET " + gate.OUTER_LIBRARY,
            "  )\n"
            "  set_property(\n"
            "    TARGET " + gate.OUTER_LIBRARY,
            1,
        )
        self.assertNotEqual(missing_outer_dependency, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(missing_outer_dependency),
            "outer initializer must depend only on the router",
        )

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

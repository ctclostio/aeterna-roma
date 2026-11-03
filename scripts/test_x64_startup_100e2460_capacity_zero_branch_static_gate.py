#!/usr/bin/env python3
"""Reciprocal mutants for the 0x100e2460 capacity-zero static gate."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
GATE_PATH = SCRIPTS / "x64_startup_100e2460_capacity_zero_branch_static_gate.py"
SPEC = importlib.util.spec_from_file_location("capacity_zero_branch_gate", GATE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load capacity-zero static gate")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


class Startup100e2460CapacityZeroStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read(
            "port/x64_ported/ported_100e2460_capacity_zero_branch.h"
        )
        cls.source = read(
            "port/x64_ported/ported_100e2460_capacity_zero_branch.c"
        )
        cls.test = read(
            "port/x64_runtime/test_startup_100e2460_capacity_zero_branch.c"
        )
        cls.preallocated_provenance = read_bytes(
            "scripts/test_x64_startup_100e2460_preallocated_branch_provenance.py"
        )
        cls.capacity_zero_provenance = read_bytes(
            "scripts/test_x64_startup_100e2460_capacity_zero_branch_provenance.py"
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

    def test_live_core_runtime_and_authorities_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_test_text(self.test), [])
        self.assertEqual(
            gate.inspect_provenance_bytes(
                self.preallocated_provenance, label="preallocated"
            ),
            [],
        )
        self.assertEqual(
            gate.inspect_provenance_bytes(
                self.capacity_zero_provenance, label="capacity-zero"
            ),
            [],
        )

    def test_live_integration_and_exports_pass(self):
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])
        self.assertEqual(gate.inspect_exports_text(self.export_manifest), [])
        self.assertEqual(gate.inspect_exports_text(self.legacy_def), [])
        self.assertEqual(gate.inspect_exports_text(self.probe_def), [])

    def test_header_allocator_width_class_and_api_mutants_fail(self):
        wrong_width = self.header.replace(
            "CAPACITY_ZERO_ALLOCATION_BYTES UINT32_C(4)",
            "CAPACITY_ZERO_ALLOCATION_BYTES UINT32_C(8)",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_width),
            "four-byte allocation contract changed",
        )
        wrong_class = self.header.replace(
            "CAPACITY_ZERO_ALLOCATION_CLASS UINT32_C(0)",
            "CAPACITY_ZERO_ALLOCATION_CLASS UINT32_C(1)",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_class),
            "allocation-class-zero contract changed",
        )
        wrong_result = self.header.replace(
            "typedef rome2_guest_addr32 (*rome2_100e2460_allocate_effect_fn)",
            "typedef uint64_t (*rome2_100e2460_allocate_effect_fn)",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_result),
            "total guest32 allocator adapter contract changed",
        )
        missing_parameter = self.header.replace(
            "    uint32_t max_peek_calls,\n", "", 1
        )
        self.assert_finding(
            gate.inspect_header_text(missing_parameter),
            "public capacity-zero API contract changed",
        )

    def test_header_partial_commit_and_ownership_contract_mutants_fail(self):
        no_invalid_contract = self.header.replace(
            "ALLOCATION_RESULT_INVALID", "ALLOCATION_REJECTED", 1
        )
        self.assert_finding(
            gate.inspect_header_text(no_invalid_contract),
            "header safety/effect contract",
        )
        no_ownership = self.header.replace(
            "ownership-safety", "ownership-unsafe", 1
        )
        self.assert_finding(
            gate.inspect_header_text(no_ownership),
            "header safety/effect contract",
        )

    def test_safe_zero_state_predicate_mutants_fail(self):
        nonzero_count = self.source.replace(
            "if (capacity != 0 || count != 0 || backing != 0)",
            "if (capacity != 0 || count > 1 || backing != 0)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(nonzero_count),
            "safe capacity/count/backing entry predicate changed",
        )
        stale_backing = self.source.replace(
            "if (capacity != 0 || count != 0 || backing != 0)",
            "if (capacity != 0 || count != 0)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(stale_backing),
            "safe capacity/count/backing entry predicate changed",
        )

    def test_capacity_before_allocate_order_and_arguments_mutants_fail(self):
        capacity_block = (
            "    rome2_100e2460_zero_write_u32_le(\n"
            "        state_view->host_base + (size_t)plan.capacity_offset, "
            "UINT32_C(1));\n"
        )
        allocation_block = (
            "    allocation = allocate(\n"
            "        context,\n"
            "        ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_BYTES,\n"
            "        ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_CLASS);\n"
        )
        self.assertIn(capacity_block + allocation_block, self.source)
        reordered = self.source.replace(
            capacity_block + allocation_block,
            allocation_block + capacity_block,
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(reordered),
            "prevalidate/capacity/allocate/validate/backing/tail effect order changed",
        )
        wrong_size = self.source.replace(
            "        ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_BYTES,",
            "        UINT32_C(8),",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_size),
            "total allocate(4,0) invocation changed",
        )
        wrong_class = self.source.replace(
            "        ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_CLASS);",
            "        UINT32_C(1));",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_class),
            "total allocate(4,0) invocation changed",
        )

    def test_allocation_result_null_range_and_mapping_mutants_fail(self):
        null_allowed = self.source.replace(
            "if (cell.value == 0)", "if (cell.value == UINT32_MAX)", 1
        )
        self.assert_finding(
            gate.inspect_source_text(null_allowed),
            "allocation-result null validation changed",
        )
        overflow_weakened = self.source.replace(
            "cell.value > UINT32_MAX - UINT32_C(3)",
            "cell.value > UINT32_MAX - UINT32_C(2)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(overflow_weakened),
            "allocation-result guest32 overflow validation changed",
        )
        truncation_weakened = self.source.replace(
            "ROME2_100E2460_ZERO_CELL_BYTES > byte_count - offset",
            "ROME2_100E2460_ZERO_CELL_BYTES >= byte_count - offset",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(truncation_weakened),
            "allocation-result mapped-cell/host-range validation changed",
        )

    def test_allocation_result_vector_and_handler_alias_mutants_fail(self):
        vector_weakened = self.source.replace(
            "            plan->vector_offset,\n"
            "            ROME2_PORT_100E2460_VECTOR_BYTES) ||",
            "            plan->capacity_offset,\n"
            "            ROME2_100E2460_ZERO_CELL_BYTES) ||",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(vector_weakened),
            "entire vector",
        )
        handler_removed = self.source.replace(
            "            plan->handler_offset,\n"
            "            ROME2_100E2460_ZERO_CELL_BYTES) ||",
            "            plan->handler_offset + UINT64_C(4),\n"
            "            ROME2_100E2460_ZERO_CELL_BYTES) ||",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(handler_removed),
            "handler cell",
        )

    def test_allocation_result_logical_and_physical_method_alias_mutants_fail(self):
        logical_removed = self.source.replace(
            "            (uint64_t)plan->method_cell.value,",
            "            (uint64_t)plan->method_cell.value + UINT64_C(4),",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(logical_removed),
            "logically disjoint from the method cell",
        )
        physical_result = (
            "            (uintptr_t)state_view->host_base + allocation_offset,\n"
            "            ROME2_100E2460_ZERO_CELL_BYTES,\n"
            "            (uintptr_t)vtable_view->host_base + plan->method_offset,"
        )
        physical_removed = self.source.replace(
            physical_result,
            "            (uintptr_t)state_view->host_base + allocation_offset,\n"
            "            ROME2_100E2460_ZERO_CELL_BYTES,\n"
            "            (uintptr_t)vtable_view->host_base + "
            "plan->method_offset + UINT64_C(4),",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(physical_removed),
            "physically disjoint from the method cell",
        )

    def test_invalid_result_partial_commit_status_mutants_fail(self):
        generic_status = self.source.replace(
            "return ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID;",
            "return ROME2_100E2460_BRANCH_BAD_ARGUMENT;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(generic_status),
            "dedicated invalid-allocation partial-commit result changed",
        )
        ignored_alias = self.source.replace(
            "status != ROME2_100E2460_BRANCH_OK ||",
            "status != ROME2_100E2460_BRANCH_OK &&",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(ignored_alias),
            "dedicated invalid-allocation partial-commit result changed",
        )

    def test_backing_then_preallocated_composition_mutants_fail(self):
        no_backing = self.source.replace(
            "        allocation.value);",
            "        UINT32_C(0));",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(no_backing), "backing publication changed"
        )
        no_composition = self.source.replace(
            gate.PREALLOCATED_FUNCTION, "removed_preallocated_tail", 1
        )
        self.assert_finding(
            gate.inspect_source_text(no_composition),
            "preallocated branch reuse/composition changed",
        )

    def test_precommit_method_and_alias_mutants_fail(self):
        wrong_method_slot = self.source.replace(
            "plan->method_cell.value = vtable_identity.value + UINT32_C(4);",
            "plan->method_cell.value = vtable_identity.value + UINT32_C(8);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_method_slot),
            "handler/vtable +4 resolution changed",
        )
        removed_handler_check = self.source.replace(
            "rome2_100e2460_zero_cell_overlaps_vector_writes(\n"
            "            plan->handler_offset, plan)",
            "rome2_100e2460_removed_handler_alias(\n"
            "            plan->handler_offset, plan)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(removed_handler_check),
            "handler/pending-write alias validation changed",
        )

    def test_native_allocator_platform_dynamic_and_guest_cast_mutants_fail(self):
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

    def test_runtime_success_and_partial_commit_oracle_mutants_fail(self):
        missing_success = self.test.replace(
            '"capacity zero allocates before empty queue tail"',
            '"capacity zero skips allocation"',
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(missing_success), "required runtime case missing"
        )
        early_count = self.test.replace(
            "context->vector_offset + 8) != 0",
            "context->vector_offset + 8) != 1",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(early_count),
            "runtime allocator pre-count oracle changed",
        )
        lost_partial_commit = self.test.replace(
            "expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 1);",
            "expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 0);",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(lost_partial_commit),
            "runtime exact capacity commit oracle changed",
        )
        allowed_dispatch = self.test.replace(
            "fixture->context.dispatch_calls != 0 ||",
            "fixture->context.dispatch_calls != 1 ||",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(allowed_dispatch),
            "runtime invalid-result callback boundary changed",
        )

    def test_runtime_precommit_and_effect_order_oracle_mutants_fail(self):
        wrong_trace = self.test.replace(
            "context->trace[1] != ROME2_TEST_EVENT_DISPATCH",
            "context->trace[1] != ROME2_TEST_EVENT_PEEK",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(wrong_trace), "runtime effect-order oracle changed"
        )
        allowed_precommit_allocate = self.test.replace(
            "fixture->context.allocate_calls != 0 ||",
            "fixture->context.allocate_calls != 1 ||",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(allowed_precommit_allocate),
            "runtime precommit callback-suppression oracle changed",
        )

    def test_provenance_authority_and_semantic_mutants_fail(self):
        changed_preallocated = self.preallocated_provenance + b"\n# mutant\n"
        self.assert_finding(
            gate.inspect_provenance_bytes(
                changed_preallocated, label="preallocated"
            ),
            "preallocated provenance authority digest changed",
        )
        changed_zero = self.capacity_zero_provenance.replace(
            b"ZERO_BODY_BYTES", b"ZERO_BODY_REMOVED"
        )
        findings = gate.inspect_provenance_bytes(
            changed_zero, label="capacity-zero"
        )
        self.assert_finding(
            findings, "capacity-zero provenance authority digest changed"
        )
        self.assert_finding(findings, "capacity-zero provenance token missing")
        wrong_order_claim = self.capacity_zero_provenance.replace(
            b"capacity=1 must precede allocator",
            b"allocator may precede capacity=1",
            1,
        )
        self.assert_finding(
            gate.inspect_provenance_bytes(wrong_order_claim, label="capacity-zero"),
            "no longer authenticates effect order",
        )

    def test_headless_call_tokens_and_effect_order_mutants_fail(self):
        no_call = self.headless.replace(gate.FUNCTION, "removed_zero_branch", 1)
        self.assert_finding(
            gate.inspect_headless_text(no_call),
            "execute the capacity-zero branch exactly once",
        )
        stale_token = self.headless.replace(
            "initializer-capacity-zero=injected-complete",
            "initializer-capacity-zero=not-linked",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(stale_token),
            "initializer-capacity-zero=injected-complete",
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
        wrong_capacity_observation = self.headless.replace(
            "capacity != 1 || count != 0 || backing != 0",
            "capacity != 0 || count != 0 || backing != 0",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(wrong_capacity_observation),
            "capacity-before-allocation",
        )
        false_native_claim = self.headless + "\n/* native-allocator=executed */\n"
        self.assert_finding(
            gate.inspect_headless_text(false_native_claim),
            "falsely claims excluded native behavior",
        )

    def test_cmake_containment_dependency_and_consumer_mutants_fail(self):
        shared = self.cmake.replace(
            gate.LIBRARY + "\n    STATIC",
            gate.LIBRARY + "\n    SHARED",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(shared), "BUILD_TESTING-only static library"
        )
        wrong_dependency = self.cmake.replace(
            "  target_link_libraries(\n"
            f"    {gate.LIBRARY}\n"
            f"    PRIVATE {gate.PREALLOCATED_LIBRARY}\n"
            "  )",
            "  target_link_libraries(\n"
            f"    {gate.LIBRARY}\n"
            "    PRIVATE rome2_guest32_runtime\n"
            "  )",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(wrong_dependency),
            "depend only on preallocated branch",
        )
        headless_library_line = "      " + gate.LIBRARY + "\n"
        before, separator, after = self.cmake.rpartition(headless_library_line)
        self.assertEqual(separator, headless_library_line)
        no_headless = before + after
        findings = gate.inspect_cmake_text(no_headless)
        self.assert_finding(findings, "unexpected consumer/dependency")
        self.assert_finding(findings, "exact headless admitted-slice link list")
        production = self.cmake + (
            "\ntarget_link_libraries(empire_retail_bootstrap PRIVATE "
            + gate.LIBRARY + ")\n"
        )
        findings = gate.inspect_cmake_text(production)
        self.assert_finding(findings, "escapes BUILD_TESTING")
        self.assert_finding(findings, "production/probe code")

    def test_cmake_exact_link_cli_and_fixture_mutants_fail(self):
        ordered_pair = (
            "      " + gate.PREALLOCATED_LIBRARY + "\n"
            "      " + gate.LIBRARY + "\n"
        )
        before, separator, after = self.cmake.rpartition(ordered_pair)
        self.assertEqual(separator, ordered_pair)
        reordered = (
            before
            + "      " + gate.LIBRARY + "\n"
            + "      " + gate.PREALLOCATED_LIBRARY + "\n"
            + after
        )
        self.assert_finding(
            gate.inspect_cmake_text(reordered),
            "exact headless admitted-slice link list changed",
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
        substituted_growth = before + "      " + gate.LIBRARY + "\n" + after
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
        weakened_router_dependency = self.cmake.replace(
            "      rome2_startup_100e2460_preallocated_branch_runtime\n"
            "      rome2_startup_100e2460_capacity_zero_branch_runtime\n"
            "      rome2_startup_100e2460_growth_branch_runtime\n"
            "  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100e2460_router_runtime",
            "      rome2_startup_100e2460_preallocated_branch_runtime\n"
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
        missing_authority_arg = self.cmake.replace(
            "      --capacity-zero-provenance "
            '"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
            'test_x64_startup_100e2460_capacity_zero_branch_provenance.py"\n',
            "",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(missing_authority_arg),
            "capacity-zero static-gate argument changed",
        )
        stale_predecessor = self.cmake.replace(
            "startup_100e2460_preallocated_branch_reload_verified;"
            "startup_100e2460_capacity_zero_branch_provenance_verified",
            "startup_100e2460_append_prefix_reload_verified;"
            "startup_100e2460_capacity_zero_branch_provenance_verified",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(stale_predecessor),
            "capacity-zero fixture-chain block changed",
        )
        stale_headless = self.cmake.replace(
            "entry_policy_provenance_verified;entry_policy_static_verified;"
            "startup_100ed471_ordinary_lifecycle_reload_verified",
            "entry_policy_provenance_verified;entry_policy_static_verified;"
            "startup_100df270_platform_prefix_transcript_reload_verified",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(stale_headless),
            "capacity-zero fixture-chain block changed",
        )

    def test_export_escape_is_rejected(self):
        self.assertTrue(gate.inspect_exports_text(
            "ordinal\trome2_port_100e2460_run_capacity_zero_branch\n"
        ))
        self.assertTrue(gate.inspect_exports_text(
            "ordinal\trome2_100e2460_capacity_zero_effects\n"
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
        self.assert_finding(gate.inspect_cmake_text(missing_ctest), "194 CTests")

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

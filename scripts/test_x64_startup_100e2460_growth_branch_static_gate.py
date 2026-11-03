#!/usr/bin/env python3
"""Reciprocal mutants for the 0x100e2460 growth-branch static gate."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
GATE_PATH = SCRIPTS / "x64_startup_100e2460_growth_branch_static_gate.py"
SPEC = importlib.util.spec_from_file_location("growth_branch_gate", GATE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load growth-branch static gate")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


class Startup100e2460GrowthBranchStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read("port/x64_ported/ported_100e2460_growth_branch.h")
        cls.source = read("port/x64_ported/ported_100e2460_growth_branch.c")
        cls.test = read("port/x64_runtime/test_startup_100e2460_growth_branch.c")
        cls.provenance = read_bytes(
            "scripts/test_x64_startup_100e2460_growth_branch_provenance.py"
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
        self.assertEqual(gate.inspect_provenance_bytes(self.provenance), [])
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])
        self.assertEqual(gate.inspect_exports_text(self.export_manifest), [])
        self.assertEqual(gate.inspect_exports_text(self.legacy_def), [])
        self.assertEqual(gate.inspect_exports_text(self.probe_def), [])

    def test_header_capacity_class_release_and_api_mutants_fail(self):
        wrong_limit = self.header.replace(
            "UINT32_C(0x1fffffff)", "UINT32_C(0x3fffffff)", 1
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_limit),
            "maximum safe old-capacity contract changed",
        )
        wrong_class = self.header.replace(
            "GROWTH_ALLOCATION_CLASS UINT32_C(0)",
            "GROWTH_ALLOCATION_CLASS UINT32_C(1)",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_class),
            "growth allocation-class-zero contract changed",
        )
        wrong_release = self.header.replace(
            "rome2_guest_addr32 allocation);", "uint64_t allocation);", 1
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_release),
            "total guest32 release adapter contract changed",
        )
        missing_budget = self.header.replace(
            "    uint32_t max_peek_calls,\n", "", 1
        )
        self.assert_finding(
            gate.inspect_header_text(missing_budget),
            "public growth API contract changed",
        )

    def test_header_partial_commit_self_alias_and_nonreentrancy_mutants_fail(self):
        no_partial = self.header.replace(
            "only the doubled-capacity store",
            "all guest writes",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(no_partial), "growth safety/effect contract"
        )
        admits_stack_alias = self.header.replace(
            "self-alias route is unrepresentable and excluded",
            "self-alias route is admitted",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(admits_stack_alias),
            "growth safety/effect contract",
        )
        reentrant = self.header.replace(
            "exclusive, non-reentrant borrow", "shared, reentrant borrow", 1
        )
        self.assert_finding(
            gate.inspect_header_text(reentrant), "growth safety/effect contract"
        )

    def test_capacity_count_and_checked_arithmetic_mutants_fail(self):
        admits_spare_capacity = self.source.replace(
            "plan->count != plan->capacity",
            "plan->count > plan->capacity",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(admits_spare_capacity),
            "capacity>0 and count==capacity entry predicate changed",
        )
        admits_zero = self.source.replace(
            "plan->capacity == 0 || ", "", 1
        )
        self.assert_finding(
            gate.inspect_source_text(admits_zero),
            "capacity>0 and count==capacity entry predicate changed",
        )
        wrong_limit = self.source.replace(
            "ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY",
            "UINT32_MAX / UINT32_C(4)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_limit),
            "checked maximum-capacity rejection changed",
        )
        wrong_scale = self.source.replace(
            "plan->new_capacity * UINT32_C(4)",
            "plan->new_capacity * UINT32_C(8)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_scale),
            "checked doubled-capacity/allocation arithmetic changed",
        )

    def test_full_span_null_overflow_and_mapping_mutants_fail(self):
        null_allowed = self.source.replace(
            "if (guest_start.value == 0)",
            "if (guest_start.value == UINT32_MAX)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(null_allowed),
            "full-span null validation changed",
        )
        overflow_weakened = self.source.replace(
            "span_byte_count >\n"
            "            ROME2_100E2460_GROWTH_ADDRESS_SPACE_SIZE -\n"
            "                (uint64_t)guest_start.value",
            "span_byte_count >=\n"
            "            ROME2_100E2460_GROWTH_ADDRESS_SPACE_SIZE -\n"
            "                (uint64_t)guest_start.value",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(overflow_weakened),
            "full-span guest-overflow validation changed",
        )
        mapping_weakened = self.source.replace(
            "span_byte_count > view_byte_count - offset",
            "span_byte_count >= view_byte_count - offset",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(mapping_weakened),
            "full-span mapping/host-offset validation changed",
        )

    def test_logical_and_physical_alias_combination_mutants_fail(self):
        logical_only = self.source.replace(
            "            second->byte_count) ||\n"
            "        rome2_100e2460_growth_spans_overlap(",
            "            second->byte_count);\n"
            "    /* removed physical alias */\n"
            "    return rome2_100e2460_growth_spans_overlap(",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(logical_only),
            "both logically and physically disjoint",
        )
        require_both = self.source.replace(
            "            second->byte_count) ||\n"
            "        rome2_100e2460_growth_spans_overlap(",
            "            second->byte_count) &&\n"
            "        rome2_100e2460_growth_spans_overlap(",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(require_both),
            "both logically and physically disjoint",
        )

    def test_precommit_pairwise_alias_mutants_fail(self):
        removed_old_method = self.source.replace(
            "            &plan->old_buffer, &plan->method)",
            "            &plan->old_buffer, &plan->handler)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(removed_old_method),
            "precommit pairwise disjointness changed",
        )
        wrong_method_slot = self.source.replace(
            "method_cell.value = vtable_identity.value + UINT32_C(4);",
            "method_cell.value = vtable_identity.value + UINT32_C(8);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_method_slot),
            "source executable-token digest changed",
        )

    def test_new_span_pairwise_alias_mutants_fail(self):
        labels = (
            ("&plan->vector", "new full-span disjointness changed"),
            ("&plan->old_buffer", "new full-span disjointness changed"),
            ("&plan->handler", "new full-span disjointness changed"),
            ("&plan->method", "new full-span disjointness changed"),
        )
        marker = "static int rome2_100e2460_growth_result_aliases_plan"
        prefix, result_helper = self.source.split(marker, 1)
        for target, finding in labels:
            with self.subTest(target=target):
                mutant_helper = result_helper.replace(target, "&plan->vector", 1)
                if target == "&plan->vector":
                    mutant_helper = result_helper.replace(
                        "allocation, &plan->vector",
                        "allocation, &plan->old_buffer",
                        1,
                    )
                self.assert_finding(
                    gate.inspect_source_text(prefix + marker + mutant_helper),
                    finding,
                )

    def test_callback_snapshot_and_reread_mutants_fail(self):
        direct_reread = self.source.replace(
            "release = effects_snapshot.release;",
            "release = effects->release;",
            1,
        )
        findings = gate.inspect_source_text(direct_reread)
        self.assert_finding(findings, "callback/context snapshot changed")
        self.assert_finding(findings, "reread after the snapshot")
        missing_snapshot = self.source.replace(
            "    effects_snapshot = *effects;\n", "", 1
        )
        self.assert_finding(
            gate.inspect_source_text(missing_snapshot),
            "callback/context snapshot changed",
        )

    def test_capacity_before_allocate_and_argument_mutants_fail(self):
        capacity_block = (
            "    rome2_100e2460_growth_write_u32_le(\n"
            "        state_view->host_base + (size_t)plan.capacity_offset,\n"
            "        plan.new_capacity);\n"
        )
        allocate_block = (
            "    allocation = allocate(\n"
            "        context,\n"
            "        plan.allocation_bytes,\n"
            "        ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS);\n"
        )
        self.assertIn(capacity_block + allocate_block, self.source)
        reordered = self.source.replace(
            capacity_block + allocate_block,
            allocate_block + capacity_block,
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(reordered),
            "snapshot/prevalidate/capacity/allocate/validate",
        )
        wrong_bytes = self.source.replace(
            "        plan.allocation_bytes,\n"
            "        ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS);",
            "        plan.new_capacity,\n"
            "        ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_bytes),
            "total allocate(new_capacity*4,0) call changed",
        )

    def test_posteffect_full_span_and_partial_commit_mutants_fail(self):
        one_cell_only = self.source.replace(
            "        plan.allocation_bytes,\n"
            "        &allocation_span);",
            "        ROME2_100E2460_GROWTH_CELL_BYTES,\n"
            "        &allocation_span);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(one_cell_only),
            "post-effect full new-span validation changed",
        )
        generic_status = self.source.replace(
            "return ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID;",
            "return ROME2_100E2460_BRANCH_BAD_ARGUMENT;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(generic_status),
            "capacity-only invalid-allocation partial-commit result changed",
        )
        ignores_alias = self.source.replace(
            "status != ROME2_100E2460_BRANCH_OK ||",
            "status != ROME2_100E2460_BRANCH_OK &&",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(ignores_alias),
            "capacity-only invalid-allocation partial-commit result changed",
        )

    def test_backing_ascending_copy_and_by_value_append_mutants_fail(self):
        descending = self.source.replace(
            "for (cell_index = 0; cell_index < plan.count; ++cell_index)",
            "for (cell_index = plan.count; cell_index != 0; --cell_index)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(descending),
            "ascending exact-count copy loop changed",
        )
        copies_new_to_old = self.source.replace(
            "plan.old_buffer.view_offset + cell_displacement",
            "allocation_span.view_offset + cell_displacement",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(copies_new_to_old),
            "old-buffer copy read changed",
        )
        wrong_append = self.source.replace(
            "        guest_handler.value);",
            "        guest_argument.value);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_append),
            "by-value normal-route append changed",
        )

    def test_release_before_count_and_dispatch_mutants_fail(self):
        release_block = "    release(context, plan.old_backing);\n"
        count_block = (
            "    rome2_100e2460_growth_write_u32_le(\n"
            "        state_view->host_base + (size_t)plan.count_offset,\n"
            "        plan.count + UINT32_C(1));\n"
        )
        self.assertIn(release_block + count_block, self.source)
        reordered = self.source.replace(
            release_block + count_block,
            count_block + release_block,
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(reordered),
            "snapshot/prevalidate/capacity/allocate/validate",
        )
        wrong_release = self.source.replace(
            "release(context, plan.old_backing);",
            "release(context, allocation);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_release),
            "total release(old_backing) call changed",
        )
        wrong_receiver = self.source.replace(
            "context, guest_handler, plan.method_identity, guest_argument",
            "context, allocation, plan.method_identity, guest_argument",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_receiver),
            "dispatch receiver/method/argument shape changed",
        )

    def test_bounded_peek_and_low_al_mutants_fail(self):
        unbounded = self.source.replace(
            "for (peek_calls = 0; peek_calls < max_peek_calls; ++peek_calls)",
            "for (;;)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(unbounded),
            "bounded at-least-once Peek loop changed",
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
        inverted = self.source.replace(
            "if (peek_eax == 0)", "if (peek_eax != 0)", 1
        )
        self.assert_finding(
            gate.inspect_source_text(inverted),
            "terminating-false low-AL publication changed",
        )
        early_publish = self.source.replace(
            "    null_identity.value = 0;",
            "    *return_al_out = saved_al;\n    null_identity.value = 0;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(early_publish),
            "return AL must be published exactly once",
        )

    def test_native_alloc_free_user32_dynamic_and_guest_cast_mutants_fail(self):
        mutants = (
            ("\nvoid *malloc(size_t);\n", "malloc"),
            ("\nvoid free(void *);\n", "free"),
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
                    f"forbidden allocation/release/platform identifier: {identifier}",
                )
        guest_cast = self.source + (
            "\nstatic void *bad_guest_cast(rome2_guest_addr32 guest)\n"
            "{\n    return (void *)(uintptr_t)guest.value;\n}\n"
        )
        self.assert_finding(
            gate.inspect_source_text(guest_cast),
            "guest identity is converted to a native pointer/address",
        )

    def test_provenance_authority_and_policy_boundary_mutants_fail(self):
        changed = self.provenance.replace(
            b"GROWTH_COPY_BYTES", b"GROWTH_COPY_REMOVED"
        )
        findings = gate.inspect_provenance_bytes(changed)
        self.assert_finding(findings, "growth provenance authority digest changed")
        self.assert_finding(findings, "growth provenance token missing")
        false_policy = self.provenance.replace(
            b"does not declare the recovered growth route safe",
            b"declares the recovered growth route safe now",
            1,
        )
        self.assert_finding(
            gate.inspect_provenance_bytes(false_policy),
            "growth evidence/policy boundary missing",
        )

    def test_runtime_success_order_and_storage_oracle_mutants_fail(self):
        missing_case = self.test.replace(
            '"capacity one grows, copies, releases, and drains"',
            '"capacity one skips release"',
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(missing_case), "required runtime case missing"
        )
        wrong_limit = self.test.replace(
            "UINT32_C(0x1fffffff),\n"
            '    "growth safe-capacity boundary changed"',
            "UINT32_C(0x3fffffff),\n"
            '    "growth safe-capacity boundary changed"',
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(wrong_limit),
            "runtime safe-capacity boundary oracle changed",
        )
        wrong_order = self.test.replace(
            "context->trace[1] != ROME2_TEST_EVENT_RELEASE",
            "context->trace[1] != ROME2_TEST_EVENT_DISPATCH",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(wrong_order),
            "runtime allocate-before-release oracle changed",
        )
        no_storage_check = self.test.replace(
            "!rome2_test_growth_storage_is_ready(context, 0)",
            "rome2_test_growth_storage_is_ready(context, 0)",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(no_storage_check),
            "runtime release(old) after copy/append oracle changed",
        )

    def test_runtime_partial_commit_precommit_and_by_value_mutants_fail(self):
        lost_capacity_commit = self.test.replace(
            "expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 4,\n"
            "        fixture->context.new_capacity);",
            "expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 4,\n"
            "        fixture->context.old_capacity);",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(lost_capacity_commit),
            "runtime capacity-only partial-commit oracle changed",
        )
        allowed_release = self.test.replace(
            "fixture->context.release_calls != 0 ||",
            "fixture->context.release_calls != 1 ||",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(allowed_release),
            "runtime invalid-result callback boundary changed",
        )
        weakened_precommit = self.test.replace(
            "memcmp(fixture, &snapshot, sizeof(*fixture)) != 0",
            "memcmp(fixture, &snapshot, 1) != 0",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(weakened_precommit),
            "runtime precommit full-fixture preservation oracle changed",
        )
        wrong_width = self.test.replace(
            "sizeof(by_value_handler) != 4",
            "sizeof(by_value_handler) != 8",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(wrong_width),
            "runtime native-stack self-alias exclusion oracle changed",
        )

    def test_headless_call_tokens_and_effect_order_mutants_fail(self):
        no_call = self.headless.replace(gate.FUNCTION, "removed_growth", 1)
        self.assert_finding(
            gate.inspect_headless_text(no_call),
            "execute the growth branch exactly once",
        )
        stale_token = self.headless.replace(
            "initializer-growth=injected-complete",
            "initializer-growth=not-linked",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(stale_token),
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
        false_native = self.headless.replace(
            "native-release=not-run", "native-release=executed", 1
        )
        findings = gate.inspect_headless_text(false_native)
        self.assert_finding(findings, "native-release=not-run")
        self.assert_finding(findings, "falsely claims excluded native behavior")
        wrong_release_order = self.headless.replace(
            "context->release_order != 2",
            "context->release_order != 3",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(wrong_release_order),
            "allocation/release order oracle changed",
        )

    def test_headless_final_state_mutants_fail(self):
        wrong_count = self.headless.replace(
            "ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 8) != 3",
            "ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 8) != 2",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(wrong_count),
            "final growth count oracle changed",
        )
        final_copy = (
            "            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 4) !=\n"
            "            ROME2_HEADLESS_GROWTH_OLD_CELL_B ||"
        )
        wrong_copy = self.headless.replace(
            final_copy,
            "            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 4) !=\n"
            "            ROME2_HEADLESS_GROWTH_OLD_CELL_A ||",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(wrong_copy),
            "final second copied-cell oracle changed",
        )
        final_append = (
            "            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 8) !=\n"
            "            growth_effect_context.expected_receiver ||"
        )
        wrong_append = self.headless.replace(
            final_append,
            "            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 8) !=\n"
            "            growth_effect_context.expected_allocation ||",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(wrong_append),
            "final appended-handler oracle changed",
        )

    def test_cmake_static_containment_and_no_dependency_mutants_fail(self):
        shared = self.cmake.replace(
            gate.LIBRARY + "\n    STATIC",
            gate.LIBRARY + "\n    SHARED",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(shared), "BUILD_TESTING-only static library"
        )
        unnecessary_dependency = self.cmake.replace(
            "  set_property(\n"
            f"    TARGET {gate.LIBRARY}\n",
            "  target_link_libraries(\n"
            f"    {gate.LIBRARY}\n"
            "    PRIVATE rome2_startup_100e2460_capacity_zero_branch_runtime\n"
            "  )\n"
            "  set_property(\n"
            f"    TARGET {gate.LIBRARY}\n",
            1,
        )
        findings = gate.inspect_cmake_text(unnecessary_dependency)
        self.assert_finding(findings, "unexpected consumer/dependency")
        self.assert_finding(findings, "no unnecessary link dependency")
        headless_library_line = "      " + gate.LIBRARY + "\n"
        before, separator, after = self.cmake.rpartition(headless_library_line)
        self.assertEqual(separator, headless_library_line)
        no_headless = before + after
        findings = gate.inspect_cmake_text(no_headless)
        self.assert_finding(findings, "unexpected consumer/dependency")
        self.assert_finding(findings, "exact headless admitted-slice link list")
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
            "      " + gate.LIBRARY + "\n",
            1,
        )
        self.assertNotEqual(substituted_router, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(substituted_router),
            "exact headless admitted-slice link list changed",
        )
        reordered_terminal = self.cmake.replace(
            "      " + gate.LIBRARY + "\n"
            "      " + gate.ROUTER_LIBRARY + "\n",
            "      " + gate.ROUTER_LIBRARY + "\n"
            "      " + gate.LIBRARY + "\n",
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
            "      rome2_startup_100e2460_capacity_zero_branch_runtime\n"
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

    def test_cmake_production_cli_and_fixture_mutants_fail(self):
        production = self.cmake + (
            "\ntarget_link_libraries(empire_retail_bootstrap PRIVATE "
            + gate.LIBRARY + ")\n"
        )
        findings = gate.inspect_cmake_text(production)
        self.assert_finding(findings, "escapes BUILD_TESTING")
        self.assert_finding(findings, "production/probe code")
        growth_gate_tail = (
            "      --growth-provenance "
            '"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
            'test_x64_startup_100e2460_growth_branch_provenance.py"\n'
            "      --headless "
            '"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"\n'
        )
        growth_provenance_only = (
            "      --growth-provenance "
            '"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
            'test_x64_startup_100e2460_growth_branch_provenance.py"\n'
        )
        missing_headless_arg = self.cmake.replace(
            growth_gate_tail, growth_provenance_only, 1
        )
        self.assertNotEqual(missing_headless_arg, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(missing_headless_arg),
            "growth static-gate argument changed",
        )
        stale_predecessor = self.cmake.replace(
            "startup_100e2460_capacity_zero_branch_reload_verified;"
            "startup_100e2460_growth_branch_provenance_verified",
            "startup_100e2460_preallocated_branch_reload_verified;"
            "startup_100e2460_growth_branch_provenance_verified",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(stale_predecessor),
            "growth fixture-chain block changed",
        )
        stale_terminal = self.cmake.replace(
            "entry_policy_provenance_verified;entry_policy_static_verified;"
            "startup_100ed471_ordinary_lifecycle_reload_verified",
            "entry_policy_provenance_verified;entry_policy_static_verified;"
            "startup_100df270_platform_prefix_transcript_reload_verified",
            1,
        )
        self.assertNotEqual(stale_terminal, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(stale_terminal),
            "growth fixture-chain block changed",
        )

    def test_export_escape_is_rejected(self):
        self.assertTrue(gate.inspect_exports_text(
            "ordinal\trome2_port_100e2460_run_growth_branch\n"
        ))
        self.assertTrue(gate.inspect_exports_text(
            "ordinal\trome2_100e2460_growth_effects\n"
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

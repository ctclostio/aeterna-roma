#!/usr/bin/env python3
"""Reciprocal mutants for the 0x100df270 suffix containment gate."""

from __future__ import annotations

import pathlib
import re
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import x64_startup_100df270_suffix_transcript_static_gate as gate


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


class Startup100df270SuffixTranscriptStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read(
            "port/x64_ported/ported_100df270_suffix_transcript.h"
        )
        cls.source = read(
            "port/x64_ported/ported_100df270_suffix_transcript.c"
        )
        runtime_path = (
            ROOT / "port/x64_runtime/test_startup_100df270_suffix_transcript.c"
        )
        cls.runtime = (
            runtime_path.read_text(encoding="utf-8")
            if runtime_path.exists() else None
        )
        cls.provenance = read_bytes(
            "scripts/test_x64_startup_100df270_suffix_transcript_provenance.py"
        )
        cls.cmake = read("CMakeLists.txt")
        cls.export_manifest = read("port/x64_exports/export_manifest.tsv")
        cls.legacy_def = read("port/x64_exports/empire.retail.exports.def")
        cls.probe_def = read("port/x64_probe/probe_exports.def")

    def assert_finding(self, findings: list[str], fragment: str) -> None:
        self.assertTrue(
            any(fragment in finding for finding in findings),
            f"expected finding containing {fragment!r}; got {findings!r}",
        )

    def mutate_source_function(
        self,
        function: str,
        old: str,
        new: str,
    ) -> str:
        body = gate._function_body(self.source, function)
        self.assertIsNotNone(body, f"missing source function {function}")
        assert body is not None
        self.assertEqual(body.count(old), 1, f"non-unique mutant in {function}")
        mutated_body = body.replace(old, new, 1)
        mutant = self.source.replace(body, mutated_body, 1)
        self.assertNotEqual(mutant, self.source)
        return mutant

    def test_live_core_provenance_containment_and_exports_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        if self.runtime is not None:
            self.assertEqual(gate.inspect_test_text(self.runtime), [])
        self.assertEqual(gate.inspect_provenance_bytes(self.provenance), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])
        self.assertEqual(gate.inspect_exports_text(self.export_manifest), [])
        self.assertEqual(gate.inspect_exports_text(self.legacy_def), [])
        self.assertEqual(gate.inspect_exports_text(self.probe_def), [])

    def test_header_counts_identities_vtable_slot_and_marker_mutants_fail(self):
        mutants = (
            (self.header.replace("STEP_COUNT UINT32_C(7)",
                                 "STEP_COUNT UINT32_C(8)", 1), "seven-step"),
            (self.header.replace("STEP_COUNT UINT32_C(11)",
                                 "STEP_COUNT UINT32_C(10)", 1), "eleven-step"),
            (self.header.replace("0x119f3140", "0x119f3144", 1),
             "global receiver"),
            (self.header.replace("0x119f3a38", "0x119f3a3c", 1),
             "crash-record"),
            (self.header.replace("0x1173dc18", "0x1173dc1c", 1), "vtable"),
            (self.header.replace("UINT32_C(0x0c)", "UINT32_C(0x08)", 1),
             "slot"),
            (self.header.replace("UINT32_C(0x4e3b)", "UINT32_C(0x4e3c)", 1),
             "marker"),
        )
        for mutant, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_finding(gate.inspect_header_text(mutant), expected)

    def test_header_typed_step_effects_callback_and_api_mutants_fail(self):
        reversed_kinds = self.header.replace(
            "ROME2_100DF270_SUFFIX_STEP_CALL_100E8240 = 2,\n"
            "    ROME2_100DF270_SUFFIX_STEP_CALL_100F2750 = 3,",
            "ROME2_100DF270_SUFFIX_STEP_CALL_100F2750 = 2,\n"
            "    ROME2_100DF270_SUFFIX_STEP_CALL_100E8240 = 3,", 1,
        )
        self.assert_finding(gate.inspect_header_text(reversed_kinds), "eight-kind")
        no_slot = self.header.replace(
            "    uint32_t dispatch_slot_offset;\n", "", 1
        )
        self.assert_finding(gate.inspect_header_text(no_slot), "step layout")
        pointer_step = self.header.replace(
            "    rome2_100df270_suffix_step step);",
            "    const rome2_100df270_suffix_step *step);", 1,
        )
        self.assert_finding(gate.inspect_header_text(pointer_step), "by-value")
        no_second = self.header.replace(
            "    rome2_guest_addr32 second_selector_result;\n", "", 1
        )
        self.assert_finding(gate.inspect_header_text(no_second), "effects layout")
        no_view = self.header.replace(
            "    const rome2_guest_write_view *state_view,\n", "", 1
        )
        self.assert_finding(gate.inspect_header_text(no_view), "public bounded")

    def test_source_prevalidation_snapshot_checked_add_and_span_mutants_fail(self):
        no_snapshot = self.source.replace(
            "    effects_snapshot = *effects;\n", "", 1
        )
        self.assert_finding(gate.inspect_source_text(no_snapshot), "effects snapshot")
        wrong_result_add = self.source.replace(
            "ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET,\n"
            "        &adjusted_100e8240_result);",
            "ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET,\n"
            "        &adjusted_100e8240_result);", 1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_result_add), "result +0x68")
        wrong_owner_add = self.source.replace(
            "guest_receiver,\n        ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET,",
            "guest_receiver,\n        ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET,", 1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_owner_add), "receiver +0x874")
        weak_cell = self.source.replace(
            "ROME2_100DF270_RESULT_CELL_BYTES UINT64_C(4)",
            "ROME2_100DF270_RESULT_CELL_BYTES UINT64_C(3)", 1,
        )
        self.assert_finding(gate.inspect_source_text(weak_cell), "four-byte")
        live_effects = self.source.replace(
            "effects_snapshot.second_selector_result,\n"
            "        &second_result_span);",
            "effects->second_selector_result,\n"
            "        &second_result_span);", 1,
        )
        self.assert_finding(gate.inspect_source_text(live_effects), "second selector")
        no_host_alias = self.source.replace(
            "if (rome2_100df270_host_interval_overlaps_controls(\n",
            "if (0 && rome2_100df270_host_interval_overlaps_controls(\n", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_host_alias), "host interval")

    def test_source_exact_result_step_payload_and_mismatch_route_mutants_fail(self):
        weak_result = self.source.replace(
            "ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD) {",
            "effects_snapshot.result_100e8240.value) {", 1,
        )
        self.assert_finding(gate.inspect_source_text(weak_result), "crash-record")
        wrong_pending_argument = self.source.replace(
            "step.argument1 = guest_argument.value;\n"
            "    effects_snapshot.emit_step(effects_snapshot.context, step);",
            "step.argument1 = guest_receiver.value;\n"
            "    effects_snapshot.emit_step(effects_snapshot.context, step);", 1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_pending_argument), "baseline step payload"
        )
        wrong_vtable = self.source.replace(
            "ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE;",
            "ROME2_PORT_100DF270_SUFFIX_GLOBAL_RECEIVER;", 1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_vtable), "step payload")
        wrong_conditional = self.source.replace("UINT32_C(0x16)",
                                                "UINT32_C(0x17)", 1)
        self.assert_finding(gate.inspect_source_text(wrong_conditional), "four-call")

    def test_source_marker_then_callback_then_output_order_mutants_fail(self):
        write_block = (
            "    rome2_100df270_write_u32_le(\n"
            "        state_snapshot.host_base + (size_t)second_result_span.view_offset,\n"
            "        ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER);\n\n"
        )
        emit_line = (
            "    effects_snapshot.emit_step(effects_snapshot.context, step);\n\n"
            "    return_receiver_out->value = guest_receiver.value;"
        )
        late_write = self.source.replace(write_block, "", 1).replace(
            emit_line,
            "    effects_snapshot.emit_step(effects_snapshot.context, step);\n\n"
            + write_block +
            "    return_receiver_out->value = guest_receiver.value;",
            1,
        )
        self.assert_finding(gate.inspect_source_text(late_write), "marker write")
        early_output = self.source.replace(
            emit_line,
            "    return_receiver_out->value = guest_receiver.value;\n"
            "    effects_snapshot.emit_step(effects_snapshot.context, step);",
            1,
        )
        self.assert_finding(gate.inspect_source_text(early_output), "output")

    def test_source_native_heap_global_recovered_and_pointer_escape_mutants_fail(self):
        payloads = (
            ("\nvoid bad(void) { malloc(4); }\n", "forbidden native"),
            ("\nstatic uint32_t bad_process_global;\n", "file-scope"),
            ("\nvoid bad(void) { decomp_fn_100e8240(); }\n", "recovered/native"),
            ("\nvoid bad(void) { ((void (*)(void))(uintptr_t)0x100e8240)(); }\n",
             "raw original address"),
            ("\nvoid *bad(rome2_guest_addr32 guest) { return (void *)guest.value; }\n",
             "native pointers"),
            ("\nstatic uint32_t DAT_119f3140;\n", "process-global"),
        )
        for payload, expected in payloads:
            with self.subTest(expected=expected):
                self.assert_finding(
                    gate.inspect_source_text(self.source + payload), expected
                )

    def test_runtime_route_boundary_snapshot_alias_and_commit_mutants_fail(self):
        if self.runtime is None:
            self.skipTest("independent runtime candidate has not landed")
        mutants = (
            (self.runtime.replace(
                "ROME2_PORT_100DF270_SUFFIX_ALREADY_MARKED_STEP_COUNT",
                "UINT32_C(8)", 1), "seven-step"),
            (self.runtime.replace(
                "ROME2_PORT_100DF270_SUFFIX_MISMATCH_STEP_COUNT",
                "UINT32_C(10)", 1), "eleven-step"),
            (self.runtime.replace("0x119f3aa0", "0x119f3aa1", 1), "+0x68"),
            (self.runtime.replace("0xfffff78c", "0xfffff78b", 1), "+0x874"),
            (self.runtime.replace("mutate_effects_after_first",
                                  "ignore_effects_after_first"),
             "snapshot"),
        )
        for mutant, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_finding(gate.inspect_test_text(mutant), expected)

    def test_delegated_suffix_api_order_and_runtime_mutants_fail(self):
        callback_void = self.header.replace(
            "typedef rome2_guest_status\n"
            "(*rome2_100df270_suffix_execute_100f2750_fn)(",
            "typedef void\n"
            "(*rome2_100df270_suffix_execute_100f2750_fn)(",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(callback_void), "status-returning"
        )
        no_context_size = self.header.replace(
            "    uint64_t context_byte_count;\n", "", 1
        )
        self.assert_finding(
            gate.inspect_header_text(no_context_size), "descriptor layout"
        )
        no_delegated_api = self.header.replace(
            "rome2_guest_status "
            "rome2_port_100df270_run_suffix_transcript_delegated(\n",
            "rome2_guest_status removed_delegated_suffix_api(\n",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(no_delegated_api), "public delegated"
        )

        no_snapshot = self.source.replace(
            "    delegate_snapshot = *delegate;\n", "", 1
        )
        self.assert_finding(
            gate.inspect_source_text(no_snapshot), "delegate snapshot"
        )
        live_delegate = self.source.replace(
            "status = delegate_snapshot.execute(\n",
            "status = delegate->execute(\n",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(live_delegate), "delegate invocation"
        )
        no_failure_stop = self.source.replace(
            "    if (status != ROME2_GUEST_OK) {\n"
            "        return status;\n"
            "    }\n\n"
            "    rome2_100df270_clear_step(&step);\n"
            "    step.kind = ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0;",
            "    rome2_100df270_clear_step(&step);\n"
            "    step.kind = ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0;",
            1,
        )
        self.assertNotEqual(no_failure_stop, self.source)
        self.assert_finding(
            gate.inspect_source_text(no_failure_stop), "emit-execute-stop-resume"
        )
        delegated_payload = self.mutate_source_function(
            gate.DELEGATED_FUNCTION,
            "    step.argument0 = guest_argument.value;",
            "    step.argument0 = guest_receiver.value;",
        )
        self.assert_finding(
            gate.inspect_source_text(delegated_payload),
            "delegated step payload",
        )
        delegated_observer_check = self.mutate_source_function(
            gate.DELEGATED_FUNCTION,
            "    if (effects_snapshot.emit_step == NULL ||\n",
            "    if (effects_snapshot.emit_step != NULL ||\n",
        )
        self.assert_finding(
            gate.inspect_source_text(delegated_observer_check),
            "delegated observer validation",
        )
        delegated_control_helper = self.mutate_source_function(
            "rome2_100df270_delegated_controls_overlap",
            "            (uint64_t)(uintptr_t)return_receiver_out,\n"
            "            sizeof(*return_receiver_out));",
            "            (uint64_t)(uintptr_t)effects,\n"
            "            sizeof(*effects));",
        )
        self.assert_finding(
            gate.inspect_source_text(delegated_control_helper),
            "control pairwise-disjointness helper",
        )
        delegated_state_helper = self.mutate_source_function(
            "rome2_100df270_delegated_state_overlaps_controls",
            "            (uint64_t)(uintptr_t)delegate,\n"
            "            sizeof(*delegate));",
            "            (uint64_t)(uintptr_t)effects,\n"
            "            sizeof(*effects));",
        )
        self.assert_finding(
            gate.inspect_source_text(delegated_state_helper),
            "state-backing disjointness helper",
        )
        delegated_context_helper = self.mutate_source_function(
            "rome2_100df270_validate_delegate_context",
            "        rome2_100df270_ranges_overlap(\n"
            "            context_start,\n"
            "            delegate_snapshot->context_byte_count,\n"
            "            (uint64_t)(uintptr_t)return_receiver_out,\n"
            "            sizeof(*return_receiver_out))) {",
            "        0) {",
        )
        self.assert_finding(
            gate.inspect_source_text(delegated_context_helper),
            "context authority helper",
        )
        delegated_state_snapshot = self.mutate_source_function(
            gate.DELEGATED_FUNCTION,
            "    state_snapshot = *state_view;\n",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(delegated_state_snapshot),
            "delegated complete state-view snapshot",
        )
        delegated_interval = self.mutate_source_function(
            gate.DELEGATED_FUNCTION,
            "    status = rome2_100df270_validate_interval(&state_snapshot);\n",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(delegated_interval),
            "delegated state interval validation",
        )
        delegated_effects_snapshot = self.mutate_source_function(
            gate.DELEGATED_FUNCTION,
            "    effects_snapshot = *effects;\n",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(delegated_effects_snapshot),
            "delegated complete effects snapshot",
        )
        delegated_conditional = self.mutate_source_function(
            gate.DELEGATED_FUNCTION,
            "            &effects_snapshot, &step, UINT32_C(0x16));",
            "            &effects_snapshot, &step, UINT32_C(0x17));",
        )
        self.assert_finding(
            gate.inspect_source_text(delegated_conditional),
            "delegated mismatch-only",
        )

        if self.runtime is None:
            self.skipTest("independent runtime candidate has not landed")
        runtime_mutants = (
            (self.runtime.replace(
                "mutate_delegate_after_first", "ignore_delegate_after_first"),
             "delegate snapshot"),
            (self.runtime.replace(
                "delegate_call_count == UINT32_C(1)",
                "delegate_call_count == UINT32_C(2)", 1),
             "one-shot delegate"),
            (self.runtime.replace(
                "fixture.trace.call_count == UINT32_C(3)",
                "fixture.trace.call_count == UINT32_C(4)", 1),
             "committed-prefix"),
            (self.runtime.replace(
                "fixture.delegate.context = fixture.memory.bytes;",
                "fixture.delegate.context = &fixture.trace;", 1),
             "context/state disjointness"),
            (self.runtime.replace(
                "delegated_status =\n"
                "        rome2_port_100df270_run_suffix_transcript_delegated(",
                "removed_delegated_status =\n"
                "        removed_delegated_preflight_call(", 1),
             "mirrored through the delegated entry"),
            (self.runtime.replace(
                "UINT32_C(0x11223344),\n"
                "        TEST_FIRST_OFFSET,\n"
                "        0,\n"
                "        0);",
                "UINT32_C(0x11223344),\n"
                "        TEST_SECOND_OFFSET,\n"
                "        0,\n"
                "        0);", 1),
             "delegated same-cell"),
            (self.runtime.replace(
                "UINT32_C(0x0badc0de),\n"
                "        TEST_SECOND_OFFSET,\n"
                "        1,\n"
                "        0);",
                "UINT32_C(0x0badc0de),\n"
                "        TEST_SECOND_OFFSET,\n"
                "        0,\n"
                "        0);", 1),
             "delegated effects snapshot"),
            (self.runtime.replace(
                "&fixture.delegate,\n"
                "        (rome2_guest_addr32 *)(void *)&fixture.delegate);",
                "&fixture.delegate, &fixture.return_receiver);", 1),
             "delegate descriptor/output alias"),
            (self.runtime.replace(
                "failed |= test_run_delegated_success(",
                "failed |= removed_delegated_success_case(", 1),
             "delegated success case inventory"),
            (self.runtime.replace(
                "failed |= test_run_success(",
                "failed |= removed_baseline_success_case(", 1),
             "baseline success case inventory"),
            (self.runtime.replace(
                "failed |= test_expect_precommit_failure(",
                "failed |= removed_precommit_case(", 1),
             "shared baseline/delegated precommit case inventory"),
            (self.runtime.replace(
                "failed |= test_expect_delegated_validation_failure(",
                "failed |= removed_delegate_boundary_case(", 1),
             "delegate-specific boundary case inventory"),
            (self.runtime.replace(
                "failed |= test_delegated_failure_is_exact_committed_prefix();",
                "failed |= removed_delegate_prefix_case();", 1),
             "delegated committed-prefix case inventory"),
            (self.runtime.replace("76/76 cases passed", "75/76 cases passed", 1),
             "expanded delegated runtime"),
        )
        for mutant, expected in runtime_mutants:
            with self.subTest(expected=expected):
                self.assert_finding(gate.inspect_test_text(mutant), expected)

    def test_provenance_range_calls_vtable_slot_marker_and_data_only_mutants_fail(self):
        text = self.provenance.decode("utf-8")
        mutants = (
            (text.replace("0x100DF46D", "0x100DF46E", 1), "authority marker"),
            (text.replace(
                "27ee666d2327c9360be2f4175ee5ea58bf49e112a6a29af6760451d6a7341b75",
                "0" * 64, 1), "authority marker"),
            (text.replace("0x1173DC18", "0x1173DC1C", 1), "authority marker"),
            (text.replace("0x100D7CB0", "0x100D7CA0", 1), "authority marker"),
            (text.replace("FINAL_MARKER = 0x4E3B", "FINAL_MARKER = 0x4E3C", 1),
             "authority marker"),
            (text + "\nimport ctypes\n", "data-only"),
        )
        for mutant, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_finding(
                    gate.inspect_provenance_bytes(mutant.encode("utf-8")), expected
                )

    def test_build_testing_future_containment_and_export_mutants_fail(self):
        escaped = self.cmake + (
            f"\nadd_library({gate.LIBRARY} STATIC escaped.c)\n"
        )
        self.assert_finding(gate.inspect_cmake_text(escaped), "BUILD_TESTING")
        for payload in (self.export_manifest, self.legacy_def, self.probe_def):
            mutant = payload + "\n" + gate.FUNCTION + "\n"
            self.assert_finding(gate.inspect_exports_text(mutant), "escaped exports")

    def test_cmake_exact_public_guest32_dependency_mutants_fail(self):
        pattern = re.compile(
            r"target_link_libraries\s*\(\s*"
            + re.escape(gate.LIBRARY)
            + r"\s+PUBLIC\s+rome2_guest32_runtime\s*\)",
            flags=re.S,
        )
        match = pattern.search(self.cmake)
        if match is None:
            self.skipTest("suffix CMake dependency block has not landed")
        block = match.group(0)
        private = self.cmake[:match.start()] + block.replace(
            "PUBLIC", "PRIVATE", 1
        ) + self.cmake[match.end():]
        self.assert_finding(
            gate.inspect_cmake_text(private), "exactly PUBLIC rome2_guest32_runtime"
        )
        wrong = self.cmake[:match.start()] + block.replace(
            "rome2_guest32_runtime", "rome2_startup_safe_seams_runtime", 1
        ) + self.cmake[match.end():]
        self.assert_finding(
            gate.inspect_cmake_text(wrong), "shared guest32 dependency"
        )
        extra = self.cmake[:match.start()] + block.replace(
            "rome2_guest32_runtime",
            "rome2_guest32_runtime rome2_startup_safe_seams_runtime", 1,
        ) + self.cmake[match.end():]
        self.assert_finding(
            gate.inspect_cmake_text(extra), "exactly PUBLIC rome2_guest32_runtime"
        )
        missing = self.cmake[:match.start()] + self.cmake[match.end():]
        self.assert_finding(
            gate.inspect_cmake_text(missing), "shared guest32 dependency"
        )
        missing_parent_consumer = self.cmake.replace(
            "      rome2_startup_100df270_suffix_transcript_runtime\n"
            "      rome2_startup_100df270_platform_prefix_transcript_runtime\n",
            "      rome2_startup_100df270_platform_prefix_transcript_runtime\n",
            1,
        )
        self.assertNotEqual(missing_parent_consumer, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(missing_parent_consumer),
            "unexpected or missing consumer",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

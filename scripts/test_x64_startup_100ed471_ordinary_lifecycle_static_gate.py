from __future__ import annotations

import pathlib
import unittest

import x64_startup_100ed471_ordinary_lifecycle_static_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "port" / "x64_ported" / "ported_100ed471_ordinary_lifecycle.h"
SOURCE = ROOT / "port" / "x64_ported" / "ported_100ed471_ordinary_lifecycle.c"
PROVENANCE = ROOT / "scripts" / "test_x64_startup_100ed471_ordinary_lifecycle_provenance.py"
DOC = ROOT / "docs" / "x64_startup_100ed471_ordinary_lifecycle.md"
RUNTIME = ROOT / "port" / "x64_runtime" / "test_startup_100ed471_ordinary_lifecycle.c"
CMAKE = ROOT / "CMakeLists.txt"
HEADLESS = ROOT / "port" / "x64_headless" / "headless_main.c"
EXPORT_MANIFEST = ROOT / "port" / "x64_exports" / "export_manifest.tsv"
EXPORT_CONTRACT = ROOT / "docs" / "x64_export_contract.md"
LEGACY_DEF = ROOT / "port" / "x64_exports" / "empire.retail.exports.def"
BOOTSTRAP_DEF = ROOT / "port" / "x64_bootstrap" / "empire_bootstrap.def"
PROBE_DEF = ROOT / "port" / "x64_probe" / "probe_exports.def"
REPRO_MANIFEST = ROOT / "scripts" / "x64_reproducible_build_v2_manifest.json"
REPRO_VERIFIER = ROOT / "scripts" / "test_x64_reproducible_build_v2.py"


class Startup100ed471OrdinaryLifecycleStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.provenance = PROVENANCE.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")
        cls.runtime = RUNTIME.read_text(encoding="utf-8")
        cls.cmake = CMAKE.read_text(encoding="utf-8")
        cls.headless = HEADLESS.read_text(encoding="utf-8")
        cls.export_surfaces = (
            EXPORT_MANIFEST.read_text(encoding="utf-8"),
            EXPORT_CONTRACT.read_text(encoding="utf-8"),
            LEGACY_DEF.read_text(encoding="utf-8"),
            BOOTSTRAP_DEF.read_text(encoding="utf-8"),
            PROBE_DEF.read_text(encoding="utf-8"),
        )
        cls.repro_manifest = REPRO_MANIFEST.read_bytes().decode("utf-8")
        cls.repro_verifier = REPRO_VERIFIER.read_text(encoding="utf-8")

    def assert_finding(self, findings: list[str], fragment: str) -> None:
        self.assertTrue(
            any(fragment in finding for finding in findings),
            f"expected {fragment!r}; got {findings!r}",
        )

    def test_live_header_source_provenance_and_doc_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_provenance_text(self.provenance), [])
        self.assertEqual(gate.inspect_doc_text(self.doc), [])
        self.assertEqual(gate.inspect_test_text(self.runtime), [])

    def test_runtime_boundary_step_and_timestamp_oracle_mutants_fail(self):
        wrong_boundary = self.runtime.replace(
            "ROME2_PORT_100ED471_RETURN_PC == UINT32_C(0x100ed550)",
            "ROME2_PORT_100ED471_RETURN_PC == UINT32_C(0x100ed54f)", 1,
        )
        self.assert_finding(gate.inspect_test_text(wrong_boundary), "runtime boundary")
        wrong_ceiling = self.runtime.replace(
            "ROME2_PORT_100ED471_MAX_POLL_CALLS == UINT32_C(64)",
            "ROME2_PORT_100ED471_MAX_POLL_CALLS == UINT32_C(63)", 1,
        )
        self.assert_finding(gate.inspect_test_text(wrong_ceiling), "64-poll")
        wrong_timestamp = self.runtime.replace(
            "    expected[5].result1 = timestamp_high;", "", 1
        )
        self.assert_finding(gate.inspect_test_text(wrong_timestamp), "through-pointer")
        swapped = self.runtime.replace(
            "ROME2_100ED471_STEP_CALL_112DCAF0",
            "ROME2_100ED471_STEP_CALL_100D6560", 1,
        )
        self.assert_finding(gate.inspect_test_text(swapped), "transcript step order")

    def test_runtime_poll_failure_snapshot_and_preservation_mutants_fail(self):
        missing_result_one = self.runtime.replace(
            '"ordinary-unreachable result one is rejected precommit"',
            '"ordinary result one accepted"', 1,
        )
        self.assert_finding(gate.inspect_test_text(missing_result_one), "result one")
        no_snapshot_adversary = self.runtime.replace(
            "        trace->caller_effects->poll_results[0] = UINT32_C(1);\n", "", 1
        )
        self.assert_finding(gate.inspect_test_text(no_snapshot_adversary), "snapshot adversary")
        no_frame_preserve = self.runtime.replace(
            "        memcmp(&fixture->frame, &frame_snapshot, sizeof(frame_snapshot)) == 0,",
            "        1,", 1,
        )
        self.assert_finding(gate.inspect_test_text(no_frame_preserve), "frame-preservation")
        no_result_preserve = self.runtime.replace(
            "        memcmp(\n"
            "                &fixture->result, &result_snapshot,\n"
            "                sizeof(result_snapshot)) == 0,",
            "        1,", 1,
        )
        self.assert_finding(gate.inspect_test_text(no_result_preserve), "result-preservation")

    def test_runtime_test_group_dispatch_alias_and_exact_pin_mutants_fail(self):
        no_dispatch = self.runtime.replace(
            "    failed |= test_dispatch_failures();\n", "", 1
        )
        self.assert_finding(gate.inspect_test_text(no_dispatch), "test-group order")
        no_alias = self.runtime.replace(
            '"frame and dispatch guest intervals overlap"',
            '"guest overlap accepted"', 1,
        )
        self.assert_finding(gate.inspect_test_text(no_alias), "guest intervals overlap")
        self.assert_finding(
            gate.inspect_test_text(self.runtime + "\n"), "runtime oracle exact digest"
        )

    def test_header_boundary_frame_poll_and_offset_mutants_fail(self):
        mutants = (
            ("UINT32_C(0x100ed471)", "UINT32_C(0x100ed472)", "start boundary"),
            ("UINT32_C(0x100ed4c1)", "UINT32_C(0x100ed4c2)", "poll boundary"),
            ("UINT32_C(0x100ed550)", "UINT32_C(0x100ed54f)", "return boundary"),
            ("FRAME_BYTES UINT32_C(0x90c)", "FRAME_BYTES UINT32_C(0x908)", "frame size"),
            ("MAX_POLL_CALLS UINT32_C(64)", "MAX_POLL_CALLS UINT32_C(65)", "64-result"),
            ("TIMESTAMP_OFFSET UINT32_C(0x28)", "TIMESTAMP_OFFSET UINT32_C(0x2c)", "timestamp destination"),
            ("TIMESTAMP_COPY_OFFSET UINT32_C(0x904)", "TIMESTAMP_COPY_OFFSET UINT32_C(0x900)", "timestamp copy"),
            ("CLEANUP3_OFFSET UINT32_C(0x04)", "CLEANUP3_OFFSET UINT32_C(0x08)", "cleanup3"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                mutant = self.header.replace(old, new, 1)
                self.assertNotEqual(mutant, self.header)
                self.assert_finding(gate.inspect_header_text(mutant), expected)

    def test_header_dispatch_allowlist_and_target_identity_mutants_fail(self):
        mutants = (
            ("LOCAL_VTABLE UINT32_C(0x11897870)", "LOCAL_VTABLE UINT32_C(0x11897874)", "local vtable"),
            ("LOCAL_METHOD UINT32_C(0x112e2cd0)", "LOCAL_METHOD UINT32_C(0x112e2cd4)", "local method"),
            ("FALLBACK_OBJECT UINT32_C(0x119e1004)", "FALLBACK_OBJECT UINT32_C(0x119e1008)", "fallback object"),
            ("TARGET_100EC5C0 UINT32_C(0x100ec5c0)", "TARGET_100EC5C0 UINT32_C(0x100ec5c4)", "100ec5c0"),
        )
        for old, new, expected in mutants:
            mutant = self.header.replace(old, new, 1)
            self.assert_finding(gate.inspect_header_text(mutant), expected)

    def test_header_step_effect_result_and_api_mutants_fail(self):
        swapped = self.header.replace(
            "ROME2_100ED471_STEP_CALL_112DCAF0 = 2,\n"
            "    ROME2_100ED471_STEP_CALL_100D6560 = 3,",
            "ROME2_100ED471_STEP_CALL_100D6560 = 2,\n"
            "    ROME2_100ED471_STEP_CALL_112DCAF0 = 3,", 1,
        )
        self.assert_finding(gate.inspect_header_text(swapped), "nine-kind")
        no_poll_array = self.header.replace(
            "    uint32_t poll_results[ROME2_PORT_100ED471_MAX_POLL_CALLS];\n", "", 1
        )
        self.assert_finding(gate.inspect_header_text(no_poll_array), "poll transcript")
        pointer_step = self.header.replace(
            "    uint32_t dispatch_target;", "    void *dispatch_target;", 1
        )
        self.assert_finding(gate.inspect_header_text(pointer_step), "pointer-free")
        no_terminal = self.header.replace(
            "    uint32_t terminal_poll_result;\n", "", 1
        )
        self.assert_finding(gate.inspect_header_text(no_terminal), "result layout")
        no_bound = self.header.replace("    uint32_t max_poll_calls,\n", "", 1)
        self.assert_finding(gate.inspect_header_text(no_bound), "public lifecycle")
        no_through_pointer = self.header.replace(
            " * result0/result1 are the injected low/high dwords written through argument0;\n",
            "", 1,
        )
        self.assert_finding(
            gate.inspect_header_text(no_through_pointer), "through-pointer"
        )

    def test_source_exact_frame_and_poll_budget_mutants_fail(self):
        mutants = (
            ("frame_snapshot.guest_base != guest_frame.value ||",
             "frame_snapshot.guest_base == guest_frame.value ||", "unified validation"),
            ("frame_snapshot.byte_count != ROME2_PORT_100ED471_FRAME_BYTES ||",
             "frame_snapshot.byte_count < ROME2_PORT_100ED471_FRAME_BYTES ||", "unified validation"),
            ("max_poll_calls == UINT32_C(0) ||",
             "max_poll_calls != UINT32_C(0) ||", "positive bounded"),
            ("max_poll_calls > ROME2_PORT_100ED471_MAX_POLL_CALLS ||",
             "max_poll_calls >= ROME2_PORT_100ED471_MAX_POLL_CALLS ||", "positive bounded"),
            ("effects_snapshot.poll_result_count > max_poll_calls)",
             "effects_snapshot.poll_result_count >= max_poll_calls)", "count/budget"),
        )
        for old, new, expected in mutants:
            mutant = self.source.replace(old, new, 1)
            self.assertNotEqual(mutant, self.source)
            self.assert_finding(gate.inspect_source_text(mutant), expected)
        nullable_dispatch = self.source.replace(
            "        dispatch_receiver_snapshot.value == UINT32_C(0) ||\n", "", 1
        )
        self.assert_finding(
            gate.inspect_source_text(nullable_dispatch), "unified validation"
        )

    def test_source_fixed_zero_star_terminal_two_transcript_mutants_fail(self):
        wrong_terminal = self.source.replace(
            "? UINT32_C(2)\n                : UINT32_C(0);",
            "? UINT32_C(1)\n                : UINT32_C(0);", 1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_terminal), "zero-star-terminal-two")
        wrong_prefix = self.source.replace(
            ": UINT32_C(0);", ": UINT32_C(2);", 1
        )
        self.assert_finding(gate.inspect_source_text(wrong_prefix), "zero-star-terminal-two")
        no_check = self.source.replace(
            "        if (effects_snapshot.poll_results[poll_index] != expected) {\n"
            "            return ROME2_GUEST_BAD_ARGUMENT;\n"
            "        }\n", "", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_check), "prevalidation")
        early_emit = self.source.replace(
            "    frame_snapshot = *frame_view;",
            "    effects->emit_step(effects->context, (rome2_100ed471_step){0});\n"
            "    frame_snapshot = *frame_view;", 1,
        )
        self.assert_finding(gate.inspect_source_text(early_emit), "snapshotted")

    def test_source_interval_host_and_checked_add_mutants_fail(self):
        no_host = self.source.replace(
            "    if (byte_count != 0U &&\n"
            "        byte_count - UINT64_C(1) >\n"
            "            (uint64_t)(UINTPTR_MAX - host_address)) {\n"
            "        return ROME2_GUEST_RANGE_OVERFLOW;\n"
            "    }\n", "", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_host), "host endpoint")
        widened = self.source.replace(
            "(uint64_t)guest_base + byte_count >",
            "(uint64_t)guest_base + byte_count >=", 1,
        )
        self.assert_finding(gate.inspect_source_text(widened), "guest interval")
        unchecked = self.source.replace(
            "return rome2_guest_add_checked(base, offset, result);",
            "result->value = base.value + offset; return ROME2_GUEST_OK;", 1,
        )
        self.assert_finding(gate.inspect_source_text(unchecked), "checked 32-bit")
        missing_add = self.source.replace(
            "            cleanup_offsets[cleanup_index],\n"
            "            &guest_cleanup[cleanup_index]);",
            "            UINT32_C(0),\n"
            "            &guest_cleanup[cleanup_index]);", 1,
        )
        self.assertNotEqual(missing_add, self.source)
        self.assert_finding(gate.inspect_source_text(missing_add), "cleanup identities")

    def test_source_external_and_logical_alias_mutants_fail(self):
        no_controls = self.source.replace(
            "    if (rome2_100ed471_controls_overlap(\n"
            "            controls, ROME2_100ED471_EXTERNAL_CONTROL_COUNT)) {\n"
            "        return ROME2_GUEST_BAD_ARGUMENT;\n"
            "    }\n", "", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_controls), "unified validation")
        no_logical = self.source.replace(
            "        rome2_100ed471_ranges_overlap(\n"
            "            (uint64_t)frame_snapshot.guest_base,\n"
            "            frame_snapshot.byte_count,\n"
            "            (uint64_t)dispatch_snapshot.guest_base,\n"
            "            dispatch_snapshot.byte_count) ||\n", "", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_logical), "logical guest-view")
        no_context = self.source.replace(
            "        rome2_100ed471_context_overlaps(\n"
            "            effects_snapshot.context,\n"
            "            &frame_backing,\n"
            "            &dispatch_backing,\n"
            "            controls,\n"
            "            ROME2_100ED471_EXTERNAL_CONTROL_COUNT)) {",
            "        0) {", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_context), "external context")

    def test_source_private_local_alias_slots_and_context_mutants_fail(self):
        no_effects_snapshot = self.source.replace(
            "    private_controls[2].start =\n"
            "        (uint64_t)(uintptr_t)&effects_snapshot;\n"
            "    private_controls[2].byte_count = sizeof(effects_snapshot);\n", "", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_effects_snapshot), "slot 2")
        wrong_count = self.source.replace(
            "#define ROME2_100ED471_PRIVATE_CONTROL_COUNT 18U",
            "#define ROME2_100ED471_PRIVATE_CONTROL_COUNT 17U", 1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_count), "eighteen private")
        no_receiver_snapshot = self.source.replace(
            "    private_controls[16].start =\n"
            "        (uint64_t)(uintptr_t)&dispatch_receiver_snapshot;\n"
            "    private_controls[16].byte_count = sizeof(dispatch_receiver_snapshot);\n",
            "", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_receiver_snapshot), "slot 16")
        no_result_destination = self.source.replace(
            "    private_controls[17].start =\n"
            "        (uint64_t)(uintptr_t)&result_destination;\n"
            "    private_controls[17].byte_count = sizeof(result_destination);\n",
            "", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_result_destination), "slot 17")
        no_private_context = self.source.replace(
            "        if (rome2_100ed471_span_overlaps_controls(\n"
            "                &context_point,\n"
            "                private_controls,\n"
            "                ROME2_100ED471_PRIVATE_CONTROL_COUNT)) {\n"
            "            return ROME2_GUEST_BAD_ARGUMENT;\n"
            "        }\n", "", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_private_context), "context/private-local")

    def test_source_dispatch_read_and_exact_allowlist_mutants_fail(self):
        no_read = self.source.replace(
            "    status = rome2_guest_read_addr32_le(\n"
            "        &dispatch_snapshot, dispatch_slot, &dispatch_target);",
            "    dispatch_target.value = ROME2_PORT_100ED471_LOCAL_METHOD;", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_read), "two checked guest32")
        widened = self.source.replace(
            "            (dispatch_vtable.value == ROME2_PORT_100ED471_LOCAL_VTABLE &&\n"
            "                dispatch_target.value == ROME2_PORT_100ED471_LOCAL_METHOD) ||",
            "            (dispatch_target.value == ROME2_PORT_100ED471_LOCAL_METHOD) ||", 1,
        )
        self.assert_finding(gate.inspect_source_text(widened), "dispatch pair allowlist")
        no_object = self.source.replace(
            "            (dispatch_receiver_snapshot.value ==\n"
            "                    ROME2_PORT_100ED471_FALLBACK_OBJECT &&\n", "            (", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_object), "dispatch pair allowlist")

    def test_source_six_setup_step_order_and_dispatch_shape_mutants_fail(self):
        swapped = self.source.replace(
            "&step, ROME2_100ED471_STEP_CALL_112DCAF0);",
            "&step, ROME2_100ED471_STEP_CALL_100D6560);", 1,
        )
        self.assert_finding(gate.inspect_source_text(swapped), "six setup")
        removed_emit = self.source.replace(
            "    effects_snapshot.emit_step(effects_snapshot.context, step);\n", "", 1
        )
        self.assert_finding(gate.inspect_source_text(removed_emit), "nine source emission")
        native_dispatch = self.source.replace(
            "    effects_snapshot.emit_step(effects_snapshot.context, step);",
            "    ((void (*)(void))(uintptr_t)dispatch_target.value)();", 1,
        )
        findings = gate.inspect_source_text(native_dispatch)
        self.assert_finding(findings, "function-pointer")

    def test_source_timestamp_event_write_and_poll_order_mutants_fail(self):
        wrong_copy = self.source.replace(
            "frame + ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET,\n"
            "        effects_snapshot.timestamp_low);",
            "frame + ROME2_PORT_100ED471_TIMESTAMP_OFFSET,\n"
            "        effects_snapshot.timestamp_low);", 1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_copy), "timestamp event/write/poll")
        missing_write = self.source.replace(
            "    rome2_100ed471_write_u32_le(\n"
            "        frame + ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET + UINT32_C(4),\n"
            "        effects_snapshot.timestamp_high);\n", "", 1,
        )
        self.assert_finding(gate.inspect_source_text(missing_write), "exactly four")
        early_poll = self.source.replace(
            "    for (poll_index = UINT32_C(0);\n"
            "         poll_index < effects_snapshot.poll_result_count;\n"
            "         ++poll_index) {\n"
            "        rome2_100ed471_clear_step(\n"
            "            &step, ROME2_100ED471_STEP_CALL_100EC5C0);",
            "    rome2_100ed471_clear_step(\n"
            "            &step, ROME2_100ED471_STEP_CALL_100EC5C0);", 1,
        )
        self.assert_finding(gate.inspect_source_text(early_poll), "timestamp event/write/poll")

    def test_source_cleanup_preflight_order_and_result_last_mutants_fail(self):
        reversed_cleanup = self.source.replace(
            "ROME2_PORT_100ED471_CLEANUP0_OFFSET,\n"
            "        ROME2_PORT_100ED471_CLEANUP1_OFFSET,",
            "ROME2_PORT_100ED471_CLEANUP1_OFFSET,\n"
            "        ROME2_PORT_100ED471_CLEANUP0_OFFSET,", 1,
        )
        self.assert_finding(gate.inspect_source_text(reversed_cleanup), "cleanup offset order")
        no_preflight = self.source.replace(
            "        if (!rome2_100ed471_empty_descriptor(\n"
            "                frame, cleanup_offsets[cleanup_index])) {\n"
            "            return ROME2_GUEST_BAD_ARGUMENT;\n"
            "        }\n", "", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_preflight), "validation-before-effects")
        early_result = self.source.replace(
            "    frame = frame_snapshot.host_base;",
            "    *result_destination = result;\n    frame = frame_snapshot.host_base;", 1,
        )
        self.assert_finding(gate.inspect_source_text(early_result), "commit exactly once")
        wrong_terminal = self.source.replace(
            "result.terminal_poll_result = UINT32_C(2);",
            "result.terminal_poll_result = UINT32_C(0);", 1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_terminal), "result-last")

    def test_source_allocator_platform_recovered_global_and_pointer_mutants_fail(self):
        payloads = (
            ("\nvoid bad(void) { malloc(4); }\n", "forbidden native"),
            ("\nvoid bad(void) { LoadStringW(0,0,0,0); }\n", "forbidden native"),
            ("\nvoid bad(void) { decomp_fn_100ec5c0(); }\n", "recovered/native"),
            ("\nstatic uint32_t DAT_12031f10;\n", "process-global"),
            ("\nvoid *bad(rome2_guest_addr32 guest_x) { return (void *)guest_x.value; }\n", "native pointers"),
            ("\nint bad = 0x100ed471;\n", "raw original address"),
        )
        for payload, expected in payloads:
            with self.subTest(expected=expected):
                self.assert_finding(gate.inspect_source_text(self.source + payload), expected)

    def test_source_unbounded_loop_extra_call_and_result_one_mutants_fail(self):
        loop = self.source.replace(
            "    result.dispatch_receiver = dispatch_receiver_snapshot;",
            "    while (effects_snapshot.poll_results[0] == 0) { }\n"
            "    result.dispatch_receiver = dispatch_receiver_snapshot;", 1,
        )
        self.assertNotEqual(loop, self.source)
        self.assert_finding(gate.inspect_source_text(loop), "unbounded while")
        extra_call = self.source + "\nvoid bad(void) { native_dispatch(); }\n"
        self.assert_finding(gate.inspect_source_text(extra_call), "unexpected native/helper")
        result_one = self.source.replace(
            "? UINT32_C(2)\n                : UINT32_C(0);",
            "? UINT32_C(1)\n                : UINT32_C(0);", 1,
        )
        self.assert_finding(gate.inspect_source_text(result_one), "zero-star-terminal-two")

    def test_provenance_boundary_domain_budget_and_exclusion_mutants_fail(self):
        mutants = (
            ("SLICE_END_VA = 0x100ED550", "SLICE_END_VA = 0x100ED54F", "slice end"),
            ('"poll_domain": (0, 2)', '"poll_domain": (0, 1, 2)', "poll domain"),
            ('"poll_budget_required": True', '"poll_budget_required": False', "finite poll budget"),
            ('"result_one_admitted": False', '"result_one_admitted": True', "result-one exclusion"),
            ('"second_indirect_dispatch": "excluded"', '"second_indirect_dispatch": "injected"', "second indirect"),
            ('"candidate_target_set_exhaustive": False', '"candidate_target_set_exhaustive": True', "non-exhaustiveness"),
        )
        for old, new, expected in mutants:
            mutant = self.provenance.replace(old, new, 1)
            self.assertNotEqual(mutant, self.provenance)
            self.assert_finding(gate.inspect_provenance_text(mutant), expected)
        self.assert_finding(
            gate.inspect_provenance_text(self.provenance + "\n"), "exact digest"
        )

    def test_doc_boundary_domain_transcript_and_fail_closed_mutants_fail(self):
        mutants = (
            ("[0x100ed471,0x100ed550)", "[0x100ed471,0x100ed54f)", "byte boundary"),
            ("ordinary domain is exactly `{0,2}`", "ordinary domain is `{0,1,2}`", "ordinary domain"),
            ("not an exhaustive target proof", "an exhaustive target proof", "candidate caveat"),
            ("Preflight a finite poll transcript", "Accept a live poll callback", "finite transcript"),
            ("Reject result\n   `1`", "Accept result\n   `1`", "result-one rejection"),
            ("Validation\nmust complete before the first observer event or frame write",
             "Validation may continue after the first frame write", "fail-closed order"),
        )
        for old, new, expected in mutants:
            mutant = self.doc.replace(old, new, 1)
            self.assertNotEqual(mutant, self.doc)
            self.assert_finding(gate.inspect_doc_text(mutant), expected)

    def test_live_integration_exports_and_reproducibility_pass(self):
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        for payload in self.export_surfaces:
            self.assertEqual(gate.inspect_exports_text(payload), [])
        self.assertEqual(
            gate.inspect_repro_manifest_text(self.repro_manifest), []
        )
        self.assertEqual(
            gate.inspect_repro_verifier_text(self.repro_verifier), []
        )
        self.assertEqual(
            gate.inspect_repro_cmake_pin(
                self.repro_manifest, self.repro_verifier, self.cmake
            ),
            [],
        )

    def test_cmake_containment_dependency_cli_fixture_and_count_mutants_fail(self):
        absent = self.cmake.replace(
            gate.LIBRARY, "removed_100ed471_lifecycle_library"
        )
        self.assert_finding(gate.inspect_cmake_text(absent), "token is missing")

        escaped = self.cmake + f"\nadd_library({gate.LIBRARY} STATIC escaped.c)\n"
        self.assert_finding(gate.inspect_cmake_text(escaped), "BUILD_TESTING")

        shared = self.cmake.replace(
            f"    {gate.LIBRARY}\n    STATIC",
            f"    {gate.LIBRARY}\n    SHARED",
            1,
        )
        self.assertNotEqual(shared, self.cmake)
        self.assert_finding(gate.inspect_cmake_text(shared), "exact static test-only")

        wrong_public = self.cmake.replace(
            f"    {gate.LIBRARY}\n    PUBLIC rome2_guest32_runtime",
            f"    {gate.LIBRARY}\n    PRIVATE rome2_guest32_runtime",
            1,
        )
        self.assertNotEqual(wrong_public, self.cmake)
        self.assert_finding(gate.inspect_cmake_text(wrong_public), "guest32/public")

        no_safe_seam = self.cmake.replace(
            f"    {gate.LIBRARY}\n"
            "    PUBLIC rome2_guest32_runtime\n"
            "    PRIVATE rome2_startup_safe_seams_runtime\n",
            f"    {gate.LIBRARY}\n"
            "    PUBLIC rome2_guest32_runtime\n"
            "    PRIVATE removed_safe_seams_runtime\n",
            1,
        )
        self.assertNotEqual(no_safe_seam, self.cmake)
        self.assert_finding(gate.inspect_cmake_text(no_safe_seam), "safe-seam/private")

        cli_line = (
            "      --repro-manifest \"${CMAKE_CURRENT_SOURCE_DIR}/scripts/"
            "x64_reproducible_build_v2_manifest.json\"\n"
        )
        gate_start = self.cmake.index(
            "scripts/x64_startup_100ed471_ordinary_lifecycle_static_gate.py"
        )
        cli_start = self.cmake.index(cli_line, gate_start)
        no_cli_arg = (
            self.cmake[:cli_start]
            + self.cmake[cli_start + len(cli_line):]
        )
        self.assertNotEqual(no_cli_arg, self.cmake)
        self.assert_finding(gate.inspect_cmake_text(no_cli_arg), "static-gate argument")

        wrong_fixture = self.cmake.replace(
            "startup_100ed471_ordinary_lifecycle_reload_verified",
            "startup_100ed471_wrong_reload_verified",
            1,
        )
        self.assertNotEqual(wrong_fixture, self.cmake)
        self.assert_finding(gate.inspect_cmake_text(wrong_fixture), "terminal reload")

        wrong_total = self.cmake.replace("add_test(", "removed_test(", 1)
        self.assert_finding(gate.inspect_cmake_text(wrong_total), "194 CTests")

    def test_headless_transcript_result_last_timestamp_and_token_mutants_fail(self):
        no_call = self.headless.replace(
            gate.FUNCTION, "removed_100ed471_lifecycle_call", 1
        )
        self.assert_finding(gate.inspect_headless_text(no_call), "exactly once")

        wrong_poll = self.headless.replace(
            "    lifecycle_effects.poll_results[2] = UINT32_C(2);",
            "    lifecycle_effects.poll_results[2] = UINT32_C(1);",
            1,
        )
        self.assertNotEqual(wrong_poll, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(wrong_poll), "invocation/result sequence"
        )

        wrong_observed_poll = self.headless.replace(
            "            ? UINT32_C(2)\n            : UINT32_C(0);",
            "            ? UINT32_C(1)\n            : UINT32_C(0);",
            1,
        )
        self.assertNotEqual(wrong_observed_poll, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(wrong_observed_poll), "0,0,2 event transcript"
        )

        wrong_count = self.headless.replace(
            "ROME2_HEADLESS_LIFECYCLE_STEP_COUNT UINT32_C(14)",
            "ROME2_HEADLESS_LIFECYCLE_STEP_COUNT UINT32_C(13)",
            1,
        )
        self.assert_finding(gate.inspect_headless_text(wrong_count), "fourteen-event")

        no_result_last = self.headless.replace(
            "    if (!rome2_headless_lifecycle_result_is_uncommitted(trace->result) ||\n",
            "    if (",
            1,
        )
        self.assertNotEqual(no_result_last, self.headless)
        self.assert_finding(gate.inspect_headless_text(no_result_last), "result-last")

        wrong_timestamp_check = self.headless.replace(
            "ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET) !=\n"
            "                ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW",
            "ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET) ==\n"
            "                ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW",
            1,
        )
        self.assertNotEqual(wrong_timestamp_check, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(wrong_timestamp_check),
            "timestamp destination checks",
        )

        wrong_token = self.headless.replace(
            gate.HEADLESS_TOKEN,
            "startup-100ed471-ordinary-lifecycle=wrong",
            1,
        )
        self.assert_finding(gate.inspect_headless_text(wrong_token), "completion token")

        native_child = self.headless + "\nvoid bad(void) { decomp_fn_100ec5c0(); }\n"
        self.assert_finding(
            gate.inspect_headless_text(native_child), "original lifecycle callees"
        )

    def test_export_and_reproducibility_mutants_fail(self):
        for payload in self.export_surfaces:
            mutant = payload + "\n" + gate.FUNCTION + "\n"
            self.assert_finding(gate.inspect_exports_text(mutant), "escaped exports")

        wrong_on = self.repro_manifest.replace(
            gate.REPRO_ON, "out/repro-wrong-on", 1
        )
        self.assert_finding(gate.inspect_repro_manifest_text(wrong_on), "ON/OFF matrix")

        wrong_artifact = self.repro_manifest.replace(
            "107520", "107521", 1
        )
        self.assert_finding(
            gate.inspect_repro_manifest_text(wrong_artifact), "production DLL/host"
        )

        wrong_verifier_matrix = self.repro_verifier.replace(
            gate.REPRO_OFF, "out/repro-wrong-off", 1
        )
        self.assert_finding(
            gate.inspect_repro_verifier_text(wrong_verifier_matrix), "OFF matrix"
        )

        missing_target = self.repro_verifier.replace(
            f'            "{gate.LIBRARY}",\n', "", 1
        )
        self.assertNotEqual(missing_target, self.repro_verifier)
        self.assert_finding(
            gate.inspect_repro_verifier_text(missing_target), "runtime target"
        )

        self.assert_finding(
            gate.inspect_repro_cmake_pin(
                self.repro_manifest, self.repro_verifier, self.cmake + "# mutant\n"
            ),
            "manifest CMake pin",
        )
        self.assert_finding(
            gate.inspect_repro_manifest_text(self.repro_manifest + "\n"),
            "repro manifest exact digest",
        )
        self.assert_finding(
            gate.inspect_repro_verifier_text(self.repro_verifier + "\n"),
            "repro verifier exact digest",
        )

    def test_whitespace_only_mutation_preserves_tokens_but_fails_exact_pin(self):
        mutant = self.source.replace("#include <stddef.h>", "#include  <stddef.h>", 1)
        findings = gate.inspect_source_text(mutant)
        self.assert_finding(findings, "exact digest")
        self.assertFalse(any("executable-token digest" in finding for finding in findings))


if __name__ == "__main__":
    unittest.main(verbosity=2)

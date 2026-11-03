from __future__ import annotations

import pathlib
import unittest

import x64_startup_100f1bb0_owned_utf16_static_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "port" / "x64_ported" / "ported_100f1bb0_owned_utf16.h"
SOURCE = ROOT / "port" / "x64_ported" / "ported_100f1bb0_owned_utf16.c"
PROVENANCE = (
    ROOT / "scripts" / "test_x64_startup_100f1bb0_owned_utf16_provenance.py"
)
DOC = ROOT / "docs" / "x64_startup_100f1bb0_owned_utf16.md"
RUNTIME = (
    ROOT / "port" / "x64_runtime" / "test_startup_100f1bb0_owned_utf16.c"
)
CMAKE = ROOT / "CMakeLists.txt"


class Startup100f1bb0OwnedUtf16StaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.provenance = PROVENANCE.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")
        cls.runtime = RUNTIME.read_text(encoding="utf-8")
        cls.cmake = CMAKE.read_text(encoding="utf-8")

    def assert_finding(self, findings: list[str], fragment: str) -> None:
        self.assertTrue(
            any(fragment in finding for finding in findings),
            f"expected {fragment!r}; got {findings!r}",
        )

    def mutate(self, payload: str, old: str, new: str) -> str:
        mutant = payload.replace(old, new, 1)
        self.assertNotEqual(mutant, payload, f"mutation anchor absent: {old!r}")
        return mutant

    def test_live_header_source_provenance_and_doc_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_provenance_text(self.provenance), [])
        self.assertEqual(gate.inspect_doc_text(self.doc), [])

    def test_live_runtime_oracle_passes(self):
        self.assertEqual(gate.inspect_test_text(self.runtime), [])

    def test_live_cmake_integration_passes(self):
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_cmake_pin_containment_dependency_cli_fixture_and_count_mutants_fail(self):
        absent = self.cmake.replace(
            gate.LIBRARY, "removed_100f1bb0_owned_utf16_library"
        )
        self.assertNotEqual(absent, self.cmake)
        self.assert_finding(gate.inspect_cmake_text(absent), "token is missing")

        escaped = (
            self.cmake
            + f"\nadd_library({gate.LIBRARY} STATIC escaped_owned_utf16.c)\n"
        )
        self.assert_finding(
            gate.inspect_cmake_text(escaped), "escapes BUILD_TESTING"
        )

        shared = self.mutate(
            self.cmake,
            f"    {gate.LIBRARY}\n    STATIC",
            f"    {gate.LIBRARY}\n    SHARED",
        )
        self.assert_finding(
            gate.inspect_cmake_text(shared), "exact static and test-only"
        )

        wrong_dependency = self.mutate(
            self.cmake,
            f"    {gate.LIBRARY}\n    PUBLIC rome2_guest32_runtime",
            f"    {gate.LIBRARY}\n    PRIVATE rome2_guest32_runtime",
        )
        self.assert_finding(
            gate.inspect_cmake_text(wrong_dependency), "exactly guest32/public"
        )

        extra_consumer = (
            self.cmake
            + f"\ntarget_link_libraries(rome2_headless64 PRIVATE {gate.LIBRARY})\n"
        )
        self.assert_finding(
            gate.inspect_cmake_text(extra_consumer),
            "standalone runtime test, sentinel-owned successor, and nonempty parent",
        )

        no_cli_arg = self.mutate(
            self.cmake,
            "      --owned-provenance \"${CMAKE_CURRENT_SOURCE_DIR}/scripts/"
            "test_x64_startup_100f1bb0_owned_utf16_provenance.py\"\n",
            "",
        )
        self.assert_finding(
            gate.inspect_cmake_text(no_cli_arg), "static-gate argument"
        )

        wrong_fixture = self.mutate(
            self.cmake,
            '        "' + gate.PREDECESSOR_FIXTURE
            + ";startup_100f1bb0_owned_utf16_provenance_verified;",
            '        "startup_100ed471_wrong_reload_verified;'
            "startup_100f1bb0_owned_utf16_provenance_verified;",
        )
        self.assert_finding(
            gate.inspect_cmake_text(wrong_fixture), "runtime fixture chain"
        )

        wrong_total = self.mutate(self.cmake, "add_test(", "removed_test(")
        self.assert_finding(gate.inspect_cmake_text(wrong_total), "194 CTests")

        whitespace = self.mutate(
            self.cmake,
            "  # Bounded nonempty UTF-16 descriptor construction",
            "   # Bounded nonempty UTF-16 descriptor construction",
        )
        self.assert_finding(gate.inspect_cmake_text(whitespace), "CMake exact digest")

    def test_header_bound_class_and_phase_mutants_fail(self):
        mutants = (
            ("MAX_UNITS UINT32_C(32768)", "MAX_UNITS UINT32_C(32767)",
             "32768-unit"),
            ("ALLOCATION_CLASS UINT32_C(0)", "ALLOCATION_CLASS UINT32_C(1)",
             "allocation class zero"),
            ("OWNER_LIVE UINT32_C(1)", "OWNER_LIVE UINT32_C(3)", "LIVE owner"),
            ("OWNER_CONSUMED UINT32_C(2)", "OWNER_CONSUMED UINT32_C(1)",
             "CONSUMED owner"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_finding(
                    gate.inspect_header_text(self.mutate(self.header, old, new)),
                    expected,
                )

    def test_header_status_and_grant_discriminator_mutants_fail(self):
        wrong_status = self.mutate(
            self.header,
            "ROME2_100F1BB0_OWNED_ALLOCATION_DENIED = 5",
            "ROME2_100F1BB0_OWNED_ALLOCATION_DENIED = 6",
        )
        self.assert_finding(gate.inspect_header_text(wrong_status), "ten-value")
        wrong_grant = self.mutate(
            self.header,
            "ROME2_100F1BB0_OWNED_GRANT_GRANTED = 1",
            "ROME2_100F1BB0_OWNED_GRANT_GRANTED = 2",
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_grant), "two-result grant"
        )

    def test_header_grant_and_private_owner_layout_mutants_fail(self):
        wrong_token = self.mutate(
            self.header, "    uint64_t token;", "    uint32_t token;"
        )
        findings = gate.inspect_header_text(wrong_token)
        self.assert_finding(findings, "grant token/raw/reserved")
        wrong_owner_order = self.mutate(
            self.header,
            "    uint32_t allocation_bytes;\n    uint32_t length_units;",
            "    uint32_t length_units;\n    uint32_t allocation_bytes;",
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_owner_order), "private owner layout"
        )
        pointer_owner = self.mutate(
            self.header,
            "    rome2_guest_addr32 payload;",
            "    rome2_guest_addr32 *payload;",
        )
        self.assert_finding(
            gate.inspect_header_text(pointer_owner), "pointer-free private authority"
        )

    def test_header_callback_exact_tuple_and_hook_mutants_fail(self):
        wrong_release = self.mutate(
            self.header,
            "    uint64_t token,\n    rome2_guest_addr32 raw_base,",
            "    rome2_guest_addr32 raw_base,\n    uint64_t token,",
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_release), "release callback exact-tuple"
        )
        wrong_hook = self.mutate(
            self.header,
            "    uint32_t zero_argument);",
            "    uint64_t zero_argument);",
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_hook), "optional release-hook ABI"
        )
        wrong_allocator = self.mutate(
            self.header,
            "        rome2_100f1bb0_owned_grant *grant_out);",
            "        const rome2_100f1bb0_owned_grant *grant_out);",
        )
        self.assert_finding(
            gate.inspect_header_text(wrong_allocator), "allocator grant callback ABI"
        )

    def test_header_effect_snapshot_and_public_api_mutants_fail(self):
        stale_token_contract = self.mutate(
            self.header,
            "Any\n * callback-written nonzero token is fresh one-shot release authority",
            "Any\n * callback-written nonzero token may be stale authority",
        )
        self.assert_finding(
            gate.inspect_header_text(stale_token_contract),
            "ownership/effect contract is missing",
        )
        reordered = self.mutate(
            self.header,
            "    void *context;\n    uint64_t context_byte_count;",
            "    uint64_t context_byte_count;\n    void *context;",
        )
        self.assert_finding(
            gate.inspect_header_text(reordered), "snapshottable effect table"
        )
        no_budget = self.mutate(self.header, "    uint32_t max_units,\n", "")
        self.assert_finding(
            gate.inspect_header_text(no_budget), "public owned-build API"
        )
        no_owner = self.mutate(
            self.header, "    rome2_100f1bb0_owned_owner *owner);", "    void);"
        )
        self.assert_finding(
            gate.inspect_header_text(no_owner), "public owning-cleanup API"
        )

    def test_source_exact_constants_mutants_fail(self):
        mutants = (
            ("DESCRIPTOR_BYTES UINT32_C(12)", "DESCRIPTOR_BYTES UINT32_C(8)",
             "12-byte descriptor"),
            ("HEADER_BYTES UINT32_C(4)", "HEADER_BYTES UINT32_C(8)",
             "four-byte hidden"),
            ("UNIT_BYTES UINT32_C(2)", "UNIT_BYTES UINT32_C(1)",
             "UTF-16 unit"),
            ("ALLOCATION_OVERHEAD UINT32_C(10)",
             "ALLOCATION_OVERHEAD UINT32_C(8)", "2N+10"),
            ("PAYLOAD_BIAS UINT32_C(8)", "PAYLOAD_BIAS UINT32_C(4)",
             "raw-plus-eight"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_finding(
                    gate.inspect_source_text(self.mutate(self.source, old, new)),
                    expected,
                )

    def test_source_control_view_and_span_range_mutants_fail(self):
        no_host_end = self.mutate(
            self.source,
            "    if (byte_count - 1U > UINTPTR_MAX - address) {\n"
            "        return ROME2_100F1BB0_OWNED_RANGE_OVERFLOW;\n"
            "    }\n",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(no_host_end), "host-endpoint validation"
        )
        widened_guest = self.mutate(
            self.source,
            "(uint64_t)guest_base + byte_count >",
            "(uint64_t)guest_base + byte_count >=",
        )
        self.assert_finding(
            gate.inspect_source_text(widened_guest), "guest view endpoint"
        )
        unchecked_span = self.mutate(
            self.source,
            "(uint64_t)span_byte_count >\n"
            "        ROME2_100F1BB0_OWNED_ADDRESS_SPACE_SIZE -",
            "(uint64_t)span_byte_count >=\n"
            "        ROME2_100F1BB0_OWNED_ADDRESS_SPACE_SIZE -",
        )
        self.assert_finding(
            gate.inspect_source_text(unchecked_span), "guest32 overflow"
        )
        no_size_max = self.mutate(
            self.source, " ||\n        offset > (uint64_t)SIZE_MAX", ""
        )
        self.assert_finding(
            gate.inspect_source_text(no_size_max), "mapping/host-offset"
        )

    def test_source_scan_bound_endpoint_and_first_zero_mutants_fail(self):
        wrong_lower = self.mutate(
            self.source,
            "max_units < UINT32_C(2)",
            "max_units < UINT32_C(1)",
        )
        self.assert_finding(gate.inspect_source_text(wrong_lower), "[2,32768]")
        unbounded = self.mutate(
            self.source,
            "for (index = 0; index < max_units; ++index)",
            "for (index = 0; ; ++index)",
        )
        self.assert_finding(
            gate.inspect_source_text(unbounded), "finite terminator-inclusive"
        )
        bad_endpoint = self.mutate(
            self.source,
            "guest_unit > UINT32_MAX - UINT32_C(1)",
            "guest_unit > UINT32_MAX",
        )
        self.assert_finding(
            gate.inspect_source_text(bad_endpoint), "UTF-16 guest endpoint"
        )
        empty_admitted = self.mutate(
            self.source,
            "            if (index == 0) {\n"
            "                return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;\n"
            "            }\n",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(empty_admitted), "first-zero/nonempty"
        )

    def test_source_pre_effect_heap_capacity_and_formula_mutants_fail(self):
        no_capacity = self.mutate(
            self.source,
            "    if (state.heap_available_bytes < "
            "(uint64_t)state.allocation_bytes) {\n"
            "        return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;\n"
            "    }\n",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(no_capacity), "pre-effect heap capacity"
        )
        wrong_formula = self.mutate(
            self.source,
            "state.payload_bytes + ROME2_100F1BB0_OWNED_ALLOCATION_OVERHEAD",
            "state.payload_bytes + UINT32_C(8)",
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_formula), "checked 2N+10"
        )
        allocation_call = (
            "    state.grant_result = state.effects.allocate(\n"
            "        state.effects.context,\n"
            "        state.allocation_bytes,\n"
            "        ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS,\n"
            "        &state.grant);\n"
        )
        without_effect = self.mutate(self.source, allocation_call, "")
        early_effect = self.mutate(
            without_effect,
            "    state.descriptor_view = *descriptor_view;",
            allocation_call +
            "    state.descriptor_view = *descriptor_view;",
        )
        findings = gate.inspect_source_text(early_effect)
        self.assert_finding(findings, "precede the sole allocator")

    def test_source_canonical_empty_owner_and_zero_grant_mutants_fail(self):
        owner_phase_admitted = self.mutate(
            self.source,
            "        owner->phase == UINT32_C(0) &&",
            "        owner->phase <= UINT32_C(1) &&",
        )
        self.assert_finding(
            gate.inspect_source_text(owner_phase_admitted),
            "canonical all-zero EMPTY",
        )
        dirty_grant_admitted = self.mutate(
            self.source,
            "        grant->reserved == UINT32_C(0);",
            "        grant->reserved <= UINT32_C(1);",
        )
        self.assert_finding(
            gate.inspect_source_text(dirty_grant_admitted),
            "canonical all-zero allocator grant",
        )

    def test_source_compensation_tuple_token_guard_and_no_hook_mutants_fail(self):
        no_guard = self.mutate(
            self.source,
            "    if (state->grant.token != UINT64_C(0)) {",
            "    if (1) {",
        )
        self.assert_finding(
            gate.inspect_source_text(no_guard), "compensation exact tuple"
        )
        wrong_tuple = self.mutate(
            self.source,
            "            state->grant.raw_base,\n"
            "            state->allocation_bytes,",
            "            state->grant.raw_base,\n            UINT32_C(4),",
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_tuple), "compensation exact tuple"
        )
        hook_compensation = self.mutate(
            self.source,
            "    }\n}\n\nstatic rome2_100f1bb0_owned_status\n"
            "rome2_100f1bb0_owned_validate_build_controls",
            "        state->effects.release_hook(state->effects.context, "
            "state->grant.raw_base, 0);\n    }\n}\n\n"
            "static rome2_100f1bb0_owned_status\n"
            "rome2_100f1bb0_owned_validate_build_controls",
        )
        self.assert_finding(
            gate.inspect_source_text(hook_compensation), "must never invoke the hook"
        )

    def test_source_denial_dirty_grant_and_protocol_compensation_mutants_fail(self):
        no_dirty_release = self.mutate(
            self.source,
            "        rome2_100f1bb0_owned_compensate_grant(&state);\n"
            "        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;",
            "        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;",
        )
        findings = gate.inspect_source_text(no_dirty_release)
        self.assert_finding(findings, "denied/dirty-grant")
        self.assert_finding(findings, "seven fail-closed")
        bad_token_admitted = self.mutate(
            self.source,
            "state.grant.token == UINT64_C(0) || ",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(bad_token_admitted),
            "discriminator/token/reserved",
        )

    def test_source_alignment_header_and_containment_mutants_fail(self):
        wrong_align = self.mutate(
            self.source, "~UINT64_C(3);", "~UINT64_C(7);",  # first use
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_align), "alignment formula"
        )
        wrong_header = self.mutate(
            self.source,
            "state.payload_identity.value - ROME2_100F1BB0_OWNED_HEADER_BYTES",
            "state.payload_identity.value + ROME2_100F1BB0_OWNED_HEADER_BYTES",
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_header), "payload-minus-four"
        )
        no_payload_containment = self.mutate(
            self.source,
            "        !rome2_100f1bb0_owned_span_is_contained(\n"
            "            &state.allocation, &state.payload) ||\n",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(no_payload_containment), "payload containment"
        )

    def test_source_copy_literal_zero_and_descriptor_triplet_mutants_fail(self):
        truncated_copy = self.mutate(
            self.source,
            "state.copy_index < state.payload_bytes",
            "state.copy_index + 1U < state.payload_bytes",
        )
        self.assert_finding(
            gate.inspect_source_text(truncated_copy), "commit order"
        )
        nonzero_terminator = self.mutate(
            self.source,
            "state.terminator.view_offset] =\n        UINT8_C(0);",
            "state.terminator.view_offset] =\n        UINT8_C(1);",
        )
        self.assert_finding(
            gate.inspect_source_text(nonzero_terminator), "commit order"
        )
        wrong_descriptor = self.mutate(
            self.source,
            "(size_t)state.descriptor.view_offset + 8U,\n"
            "        state.payload_identity.value);",
            "(size_t)state.descriptor.view_offset + 8U,\n"
            "        state.grant.raw_base.value);",
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_descriptor), "descriptor payload field"
        )

    def test_source_live_owner_and_return_last_mutants_fail(self):
        wrong_phase = self.mutate(
            self.source,
            "state.owner_commit.phase = ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE;",
            "state.owner_commit.phase = ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;",
        )
        self.assert_finding(gate.inspect_source_text(wrong_phase), "commit order")
        swapped = self.mutate(
            self.source,
            "    *owner_out = state.owner_commit;\n"
            "    *guest_return_out = guest_descriptor;",
            "    *guest_return_out = guest_descriptor;\n"
            "    *owner_out = state.owner_commit;",
        )
        self.assert_finding(gate.inspect_source_text(swapped), "commit order")

    def test_source_build_control_private_and_context_alias_mutants_fail(self):
        no_return_control = self.mutate(
            self.source,
            "    state->controls[5].start = (uint64_t)(uintptr_t)guest_return_out;\n"
            "    state->controls[5].byte_count = sizeof(*guest_return_out);\n",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(no_return_control), "control slot 5"
        )
        no_private = self.mutate(
            self.source,
            "    state->private_span.start = (uint64_t)(uintptr_t)state;\n"
            "    state->private_span.byte_count = sizeof(*state);\n",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(no_private), "private-local alias"
        )
        no_context = self.mutate(
            self.source,
            "    state->context.start = (uint64_t)(uintptr_t)state->effects.context;\n"
            "    state->context.byte_count = state->effects.context_byte_count;\n",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(no_context), "effect-context alias"
        )

    def test_source_logical_view_alias_mutants_fail(self):
        no_descriptor_text = self.mutate(
            self.source,
            "    if (rome2_100f1bb0_owned_views_logically_overlap(\n"
            "            state->descriptor_view.guest_base,\n"
            "            state->descriptor_view.byte_count,\n"
            "            state->text_view.guest_base,\n"
            "            state->text_view.byte_count) ||\n",
            "    if (",
        )
        self.assert_finding(
            gate.inspect_source_text(no_descriptor_text),
            "descriptor/text logical alias",
        )

    def test_source_cleanup_owner_formula_and_descriptor_mutants_fail(self):
        consumed_admitted = self.mutate(
            self.source,
            "state.owner.phase == ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED",
            "state.owner.phase == UINT32_C(99)",
        )
        self.assert_finding(
            gate.inspect_source_text(consumed_admitted), "already-CONSUMED"
        )
        live_not_required = self.mutate(
            self.source,
            "state.owner.phase != ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||",
            "state.owner.phase == ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||",
        )
        self.assert_finding(
            gate.inspect_source_text(live_not_required), "LIVE private-owner"
        )
        no_descriptor_payload = self.mutate(
            self.source,
            "        rome2_100f1bb0_owned_read_u32_le("
            "state.descriptor_bytes + 8U) !=\n"
            "            state.owner.payload.value ||\n",
            "",
        )
        self.assert_finding(
            gate.inspect_source_text(no_descriptor_payload),
            "descriptor payload validation",
        )

    def test_source_cleanup_consumes_before_exact_release_and_hook_mutants_fail(self):
        swapped = self.mutate(
            self.source,
            "    owner->phase = ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;\n"
            "    state.effects.release(",
            "    state.effects.release(",
        )
        self.assert_finding(
            gate.inspect_source_text(swapped), "CONSUMED-before-release"
        )
        wrong_release_size = self.mutate(
            self.source,
            "        state.owner.allocation_bytes,\n"
            "        ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS);",
            "        UINT32_C(4),\n"
            "        ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS);",
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_release_size),
            "CONSUMED-before-release",
        )
        wrong_hook = self.mutate(
            self.source,
            "            state.owner.raw_base,\n            UINT32_C(0));",
            "            state.owner.raw_base,\n            UINT32_C(1));",
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_hook), "CONSUMED-before-release"
        )

    def test_source_cleanup_must_not_revalidate_payload_bytes(self):
        invented = self.mutate(
            self.source,
            "    owner->phase = ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;",
            "    if (state.payload.view_offset != 0) { return "
            "ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID; }\n"
            "    owner->phase = ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;",
        )
        self.assert_finding(
            gate.inspect_source_text(invented), "invent payload/source"
        )

    def test_source_guest_pointer_cast_and_native_allocator_mutants_fail(self):
        guest_cast = self.source + (
            "\nstatic void *bad(rome2_guest_addr32 guest) {\n"
            "    return (void *)guest.value;\n}\n"
        )
        self.assert_finding(
            gate.inspect_source_text(guest_cast), "guest identity is converted"
        )
        native_alloc = self.source + "\nvoid bad(void) { (void)malloc(4); }\n"
        self.assert_finding(
            gate.inspect_source_text(native_alloc), "forbidden original/allocation"
        )
        original = self.source + "\nvoid bad(void) { decomp_fn_100fcc80(); }\n"
        self.assert_finding(
            gate.inspect_source_text(original), "forbidden original/allocation"
        )
        raw_original = self.source + (
            "\nstatic const uint32_t bad_address = UINT32_C(0x100fcc80);\n"
        )
        self.assert_finding(
            gate.inspect_source_text(raw_original), "forbidden original-address"
        )

    def test_provenance_and_doc_reciprocal_mutants_fail(self):
        provenance = self.mutate(
            self.provenance,
            '"payload_length_domain": (1, MAX_PAYLOAD_UNITS)',
            '"payload_length_domain": (1, MAX_SCAN_UNITS)',
        )
        self.assert_finding(
            gate.inspect_provenance_text(provenance), "provenance contract token"
        )
        doc = self.mutate(
            self.doc,
            "exactly one compensating release",
            "zero compensating releases",
        )
        self.assert_finding(gate.inspect_doc_text(doc), "doc contract")
        self.assert_finding(
            gate.inspect_doc_text(self.doc + "\n"), "doc exact digest"
        )

    def test_runtime_bound_abi_and_zero_grant_mutants_fail(self):
        wrong_bound = self.mutate(
            self.runtime,
            "ROME2_PORT_100F1BB0_OWNED_MAX_UNITS == UINT32_C(32768)",
            "ROME2_PORT_100F1BB0_OWNED_MAX_UNITS == UINT32_C(32767)",
        )
        self.assert_finding(
            gate.inspect_test_text(wrong_bound), "32768-unit bound"
        )
        wrong_abi = self.mutate(
            self.runtime,
            "sizeof(rome2_100f1bb0_owned_owner) == 32U",
            "sizeof(rome2_100f1bb0_owned_owner) == 24U",
        )
        self.assert_finding(gate.inspect_test_text(wrong_abi), "grant/owner ABI")
        no_reserved_observation = self.mutate(
            self.runtime,
            "        grant_out->reserved != UINT32_C(0) ||\n",
            "",
        )
        self.assert_finding(
            gate.inspect_test_text(no_reserved_observation), "canonical zero grant"
        )

    def test_runtime_compensation_and_consumed_observation_mutants_fail(self):
        no_phase_observation = self.mutate(
            self.runtime,
            "            context->observed_owner->phase != "
            "context->expected_owner_phase) {",
            "            0) {",
        )
        self.assert_finding(
            gate.inspect_test_text(no_phase_observation), "release and hook"
        )
        swapped_hook = self.mutate(
            self.runtime,
            "        context->events[0] != TEST_EVENT_RELEASE ||\n"
            "        context->events[1] != TEST_EVENT_HOOK ||",
            "        context->events[0] != TEST_EVENT_HOOK ||\n"
            "        context->events[1] != TEST_EVENT_RELEASE ||",
        )
        self.assert_finding(
            gate.inspect_test_text(swapped_hook), "release-before-hook"
        )
        hook_on_compensation = self.mutate(
            self.runtime,
            "fixture->context.release_calls == expected_release_calls &&\n"
            "            fixture->context.hook_calls == UINT32_C(0) &&",
            "fixture->context.release_calls == expected_release_calls &&\n"
            "            fixture->context.hook_calls == UINT32_C(1) &&",
        )
        self.assert_finding(
            gate.inspect_test_text(hook_on_compensation),
            "compensation-without-hook",
        )

    def test_runtime_failure_preservation_mutants_fail(self):
        no_owner = self.mutate(
            self.runtime,
            "        memcmp(\n"
            "            &fixture->owner,\n"
            "            &test_snapshot_storage.owner,\n"
            "            sizeof(fixture->owner)) == 0,",
            "        1,",
        )
        self.assert_finding(
            gate.inspect_test_text(no_owner), "owner-preservation"
        )
        no_return = self.mutate(
            self.runtime,
            "        fixture->guest_return.value ==\n"
            "            test_snapshot_storage.guest_return.value,",
            "        1,",
        )
        self.assert_finding(
            gate.inspect_test_text(no_return), "return-preservation"
        )
        no_context = self.mutate(
            self.runtime,
            "    if (expect_context_unchanged) {",
            "    if (0) {",
        )
        self.assert_finding(
            gate.inspect_test_text(no_context), "context-preservation"
        )

    def test_runtime_case_surface_and_group_registry_mutants_fail(self):
        missing_alias = self.mutate(
            self.runtime,
            '"bounded context aliases owner control"',
            '"context accepted"',
        )
        self.assert_finding(
            gate.inspect_test_text(missing_alias), "runtime reciprocal case"
        )
        missing_group = self.mutate(
            self.runtime,
            "    failures += test_heap_feasibility_preflight();\n",
            "",
        )
        findings = gate.inspect_test_text(missing_group)
        self.assert_finding(findings, "16-group registry")
        self.assert_finding(findings, "sixteen groups exactly once")
        renamed_group = self.mutate(
            self.runtime,
            "static int test_cleanup_does_not_require_allocator(void)",
            "static int test_cleanup_requires_allocator(void)",
        )
        self.assert_finding(
            gate.inspect_test_text(renamed_group), "runtime group definition"
        )

    def test_runtime_exact_pin_rejects_whitespace_only_change(self):
        mutant = self.mutate(
            self.runtime, "#include <stddef.h>", "#include  <stddef.h>"
        )
        findings = gate.inspect_test_text(mutant)
        self.assert_finding(findings, "runtime oracle exact digest")
        self.assertFalse(
            any("executable-token digest" in finding for finding in findings)
        )

    def test_whitespace_only_source_mutation_preserves_tokens_but_fails_exact_pin(self):
        mutant = self.mutate(
            self.source, "#include <stddef.h>", "#include  <stddef.h>"
        )
        findings = gate.inspect_source_text(mutant)
        self.assert_finding(findings, "source exact digest")
        self.assertFalse(
            any("executable-token digest" in finding for finding in findings)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

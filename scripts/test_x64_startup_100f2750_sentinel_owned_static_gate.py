from __future__ import annotations

import pathlib
import unittest

import x64_startup_100f2750_sentinel_owned_static_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = ROOT / "port" / "x64_ported" / "ported_100f2750_first_use_owned.h"
SOURCE = ROOT / "port" / "x64_ported" / "ported_100f2750_first_use_owned.c"
RUNTIME = (
    ROOT / "port" / "x64_runtime" / "test_startup_100f2750_sentinel_owned.c"
)
PROVENANCE = (
    ROOT / "scripts" / "test_x64_startup_100f2750_sentinel_owned_provenance.py"
)
DOC = ROOT / "docs" / "x64_startup_100f2750_sentinel_owned.md"
CMAKE = ROOT / "CMakeLists.txt"


class Startup100f2750SentinelOwnedStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.runtime = RUNTIME.read_text(encoding="utf-8")
        cls.provenance = PROVENANCE.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")
        cls.cmake = CMAKE.read_text(encoding="utf-8")

    def mutate(self, payload: str, old: str, new: str) -> str:
        mutant = payload.replace(old, new, 1)
        self.assertNotEqual(payload, mutant, f"mutation anchor absent: {old!r}")
        return mutant

    def assert_finding(self, findings: list[str], fragment: str) -> None:
        self.assertTrue(
            any(fragment in finding for finding in findings),
            f"expected {fragment!r}; got {findings!r}",
        )

    def assert_mutant(
        self,
        inspector,
        payload: str,
        old: str,
        new: str,
        expected: str,
    ) -> None:
        self.assert_finding(
            inspector(self.mutate(payload, old, new)), expected
        )

    def test_live_header_source_provenance_and_doc_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_provenance_text(self.provenance), [])
        self.assertEqual(gate.inspect_doc_text(self.doc), [])

    def test_live_runtime_oracle_passes(self):
        self.assertEqual(gate.inspect_test_text(self.runtime), [])

    def test_live_cmake_integration_passes(self):
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_header_identity_and_lifecycle_value_mutants_fail(self):
        mutants = (
            ("UINT32_C(0x119f3aa0)", "UINT32_C(0x119f3aa4)",
             "persistent descriptor identity"),
            ("UINT32_C(0x11af4090)", "UINT32_C(0x11af4094)",
             "empty-sentinel identity"),
            ("LIFECYCLE_EMPTY UINT32_C(0)",
             "LIFECYCLE_EMPTY UINT32_C(4)", "lifecycle EMPTY"),
            ("    UINT32_C(1)\n#define ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE",
             "    UINT32_C(4)\n#define ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE",
             "REGISTERED_SENTINEL lifecycle"),
            ("    UINT32_C(2)\n#define ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED",
             "    UINT32_C(4)\n#define ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED",
             "REGISTERED_LIVE lifecycle"),
            ("LIFECYCLE_CONSUMED UINT32_C(3)",
             "LIFECYCLE_CONSUMED UINT32_C(4)", "CONSUMED lifecycle"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_header_text, self.header, old, new, expected
                )

    def test_header_layout_api_and_contract_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_header_text, self.header,
            "    uint32_t reserved;\n} rome2_100f2750_first_use_lifecycle;",
            "    uint64_t reserved;\n} rome2_100f2750_first_use_lifecycle;",
            "phase/reserved lifecycle layout",
        )
        self.assert_mutant(
            gate.inspect_header_text, self.header,
            "sizeof(rome2_100f2750_first_use_lifecycle) == 8U",
            "sizeof(rome2_100f2750_first_use_lifecycle) == 16U",
            "eight-byte lifecycle ABI",
        )
        self.assert_mutant(
            gate.inspect_header_text, self.header,
            "rome2_100f2750_first_use_lifecycle *lifecycle_out);",
            "const rome2_100f2750_first_use_lifecycle *lifecycle_out);",
            "typed registration API",
        )
        self.assert_mutant(
            gate.inspect_header_text, self.header,
            "rome2_guest_addr32 *guest_return_out);",
            "const rome2_guest_addr32 *guest_return_out);",
            "sentinel-to-live API",
        )
        self.assert_mutant(
            gate.inspect_header_text, self.header,
            "advances the lifecycle to CONSUMED",
            "leaves the lifecycle registered",
            "header lifecycle contract",
        )

    def test_source_constant_and_private_transaction_mutants_fail(self):
        mutants = (
            ("ADDRESS_SPACE_SIZE UINT64_C(0x100000000)",
             "ADDRESS_SPACE_SIZE UINT64_C(0xffffffff)", "address-space bound"),
            ("DESCRIPTOR_BYTES UINT32_C(12)",
             "DESCRIPTOR_BYTES UINT32_C(8)", "descriptor extent"),
            ("UNIT_BYTES UINT32_C(2)", "UNIT_BYTES UINT32_C(1)",
             "UTF-16 unit extent"),
            ("ALLOCATION_OVERHEAD UINT32_C(10)",
             "ALLOCATION_OVERHEAD UINT32_C(8)", "2*N+10 overhead"),
            ("CONTROL_COUNT 9U", "CONTROL_COUNT 8U", "control-slot count"),
            ("BACKING_COUNT 4U", "BACKING_COUNT 3U", "backing count"),
            ("    uint32_t copy_index;", "    uint64_t copy_index;",
             "private transaction state"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_original_native_scan_delegate_and_guest_cast_mutants_fail(self):
        native = self.source + "\nstatic void *bad(void) { return malloc(8); }\n"
        self.assert_finding(
            gate.inspect_source_text(native), "forbidden native/original identifier"
        )
        delegated = self.source.replace(
            "return ROME2_100F1BB0_OWNED_OK;\n}\n\nrome2_100f1bb0_owned_status\n"
            "rome2_port_100f2750_teardown_first_use_owned(",
            "return rome2_port_100f1bb0_build_owned_utf16(0);\n}\n\n"
            "rome2_100f1bb0_owned_status\n"
            "rome2_port_100f2750_teardown_first_use_owned(",
            1,
        )
        self.assertNotEqual(delegated, self.source)
        self.assert_finding(
            gate.inspect_source_text(delegated), "must not delegate"
        )
        scanned = self.source + "\nstatic int scan_for_zero(void) { return 0; }\n"
        self.assert_finding(gate.inspect_source_text(scanned), "must not scan")
        casted = self.source + (
            "\nstatic void bad_cast(rome2_guest_addr32 guest) { "
            "uint8_t *p = (uint8_t *)guest.value; (void)p; }\n"
        )
        self.assert_finding(
            gate.inspect_source_text(casted), "native pointer"
        )

    def test_source_empty_owner_lifecycle_and_grant_predicate_mutants_fail(self):
        mutants = (
            ("owner->reserved == UINT32_C(0);",
             "owner->reserved != UINT32_C(0);", "EMPTY owner predicate"),
            ("lifecycle->reserved == UINT32_C(0);",
             "lifecycle->reserved != UINT32_C(0);", "EMPTY lifecycle predicate"),
            ("grant->reserved == UINT32_C(0);",
             "grant->reserved != UINT32_C(0);", "zero-grant predicate"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_compensation_tuple_and_no_hook_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_source_text, self.source,
            "            state->allocation_bytes,\n"
            "            ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS);",
            "            state->allocation_bytes - 1U,\n"
            "            ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS);",
            "one exact nonzero-token tuple",
        )
        hooked = self.mutate(
            self.source,
            "    }\n}\n\nstatic rome2_100f1bb0_owned_status\n"
            "rome2_100f2750_first_use_validate_controls(",
            "        state->effects.release_hook(state->effects.context, "
            "state->grant.raw_base, UINT32_C(0));\n"
            "    }\n}\n\nstatic rome2_100f1bb0_owned_status\n"
            "rome2_100f2750_first_use_validate_controls(",
        )
        self.assert_finding(
            gate.inspect_source_text(hooked), "must never invoke the hook"
        )

    def test_source_control_private_backing_and_logical_alias_mutants_fail(self):
        mutants = (
            ("state->controls[7].start = (uint64_t)(uintptr_t)lifecycle;",
             "state->controls[7].start = (uint64_t)(uintptr_t)guest_return_out;",
             "protected control slot changed: lifecycle"),
            ("state->private_spans[0].byte_count = sizeof(*state);",
             "state->private_spans[0].byte_count = 1U;",
             "private state is not protected"),
            ("state->backings[3].byte_count = state->persistent_heap_view.byte_count;",
             "state->backings[3].byte_count = UINT64_C(1);",
             "complete backing slot changed: persistent_heap_view"),
            ("rome2_100f2750_first_use_views_logically_overlap(\n"
             "            state->persistent_descriptor_view.guest_base,",
             "rome2_100f2750_first_use_ranges_overlap(\n"
             "            state->persistent_descriptor_view.guest_base.value,",
             "four first-use guest views"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_temporary_owner_authentication_mutants_fail(self):
        mutants = (
            ("temporary_owner.phase !=\n"
             "            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE",
             "temporary_owner.phase ==\n"
             "            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE",
             "temporary owner must be LIVE"),
            ("temporary_owner.length_units >=\n"
             "            ROME2_PORT_100F1BB0_OWNED_MAX_UNITS",
             "temporary_owner.length_units >\n"
             "            ROME2_PORT_100F1BB0_OWNED_MAX_UNITS",
             "exactly 1..32767"),
            ("state->payload_bytes =\n"
             "        state->temporary_owner.length_units *\n"
             "        ROME2_100F2750_FIRST_USE_UNIT_BYTES;",
             "state->payload_bytes = state->temporary_owner.length_units;",
             "exact 2*N payload formula"),
            ("descriptor_bytes + 8U) !=\n"
             "            state->temporary_owner.payload.value",
             "descriptor_bytes + 8U) ==\n"
             "            state->temporary_owner.payload.value",
             "descriptor payload authentication"),
        )
        for old, new, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_mutant(
                    gate.inspect_source_text, self.source, old, new, expected
                )

    def test_source_registration_validation_commit_and_effect_free_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_source_text, self.source,
            "lifecycle_out->phase =\n"
            "        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL;",
            "lifecycle_out->phase =\n"
            "        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE;",
            "registration validation/commit order",
        )
        self.assert_mutant(
            gate.inspect_source_text, self.source,
            "state.controls[2].start = (uint64_t)(uintptr_t)lifecycle_out;",
            "state.controls[2].start = (uint64_t)(uintptr_t)persistent_owner;",
            "registration protected control slot changed: lifecycle_out",
        )
        injected = self.mutate(
            self.source,
            "    lifecycle_out->phase =\n"
            "        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL;",
            "    state.effects.allocate(0);\n"
            "    lifecycle_out->phase =\n"
            "        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL;",
        )
        self.assert_finding(
            gate.inspect_source_text(injected), "must be allocation/release/cleanup free"
        )

    def test_source_preallocation_and_exact_single_effect_mutants_fail(self):
        moved = self.mutate(
            self.source,
            "    state.grant_result = state.effects.allocate(\n",
            "    state.effects.allocate(state.effects.context, state.allocation_bytes, "
            "ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS, &state.grant);\n"
            "    state.grant_result = state.effects.allocate(\n",
        )
        self.assert_finding(
            gate.inspect_source_text(moved), "exactly one injected allocation"
        )
        self.assert_mutant(
            gate.inspect_source_text, self.source,
            "state.persistent_available_bytes = state.persistent_heap_view.byte_count;",
            "state.persistent_available_bytes = UINT64_C(1);",
            "persistent-heap feasibility changed",
        )

    def test_source_collision_no_compensation_and_other_compensation_mutants_fail(self):
        collision_release = self.mutate(
            self.source,
            "    if (state.grant.token == state.temporary_owner.token) {\n"
            "        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;\n"
            "    }",
            "    if (state.grant.token == state.temporary_owner.token) {\n"
            "        rome2_100f2750_first_use_compensate_grant(&state);\n"
            "        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;\n"
            "    }",
        )
        self.assert_finding(
            gate.inspect_source_text(collision_release),
            "source-token collision must fail immediately",
        )
        no_compensation = self.mutate(
            self.source,
            "        rome2_100f2750_first_use_compensate_grant(&state);",
            "        /* removed compensation */",
        )
        self.assert_finding(
            gate.inspect_source_text(no_compensation),
            "every other malformed nonzero grant",
        )

    def test_source_destination_disjointness_and_opaque_copy_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_source_text, self.source,
            "            state.temporary_allocation.byte_count) ||\n"
            "        rome2_100f2750_first_use_ranges_overlap(\n"
            "            state.persistent_allocation.host_start,",
            "            state.temporary_allocation.byte_count) ||\n"
            "        rome2_100f2750_first_use_ranges_overlap(\n"
            "            state.persistent_allocation.guest_start,",
            "source/destination host allocations",
        )
        self.assert_mutant(
            gate.inspect_source_text, self.source,
            "         state.copy_index < state.payload_bytes;",
            "         state.copy_index + 1U < state.payload_bytes;",
            "preserve exactly opaque 2*N source bytes",
        )

    def test_source_commit_order_owner_fields_and_result_last_mutants_fail(self):
        swapped = self.mutate(
            self.source,
            "    lifecycle->phase =\n"
            "        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE;\n"
            "    *guest_return_out = persistent_descriptor_identity;",
            "    *guest_return_out = persistent_descriptor_identity;\n"
            "    lifecycle->phase =\n"
            "        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE;",
        )
        self.assert_finding(
            gate.inspect_source_text(swapped), "commit order changed"
        )
        self.assert_mutant(
            gate.inspect_source_text, self.source,
            "state.persistent_owner_commit.token = state.grant.token;",
            "state.persistent_owner_commit.token = state.temporary_owner.token;",
            "persistent LIVE owner commit changed",
        )
        source_mutation = self.source.replace(
            "    *persistent_owner_out = state.persistent_owner_commit;",
            "    temporary_owner->phase = ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;\n"
            "    *persistent_owner_out = state.persistent_owner_commit;",
            1,
        )
        self.assertNotEqual(source_mutation, self.source)
        self.assert_finding(
            gate.inspect_source_text(source_mutation),
            "must not mutate or consume source ownership",
        )

    def test_source_teardown_sentinel_repeat_and_control_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_source_text, self.source,
            "state.controls[4].start = (uint64_t)(uintptr_t)lifecycle;",
            "state.controls[4].start = (uint64_t)(uintptr_t)persistent_owner;",
            "teardown protected control slot changed: lifecycle",
        )
        self.assert_mutant(
            gate.inspect_source_text, self.source,
            "return ROME2_100F1BB0_OWNED_ALREADY_CONSUMED;",
            "return ROME2_100F1BB0_OWNED_OK;",
            "effect-free ALREADY_CONSUMED",
        )
        sentinel_release = self.mutate(
            self.source,
            "        lifecycle->phase =\n"
            "            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED;\n"
            "        return ROME2_100F1BB0_OWNED_OK;",
            "        lifecycle->phase =\n"
            "            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED;\n"
            "        state.effects.release(state.effects.context, 0, "
            "state.owner.raw_base, 0, 0);\n"
            "        return ROME2_100F1BB0_OWNED_OK;",
        )
        self.assert_finding(
            gate.inspect_source_text(sentinel_release),
            "registered-sentinel teardown must emit no effect",
        )

    def test_source_teardown_formula_consumed_order_and_cleanup_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_source_text, self.source,
            "state.owner.length_units * ROME2_100F2750_FIRST_USE_UNIT_BYTES;",
            "state.owner.length_units + ROME2_100F2750_FIRST_USE_UNIT_BYTES;",
            "teardown exact 2*N formula",
        )
        swapped = self.mutate(
            self.source,
            "    lifecycle->phase =\n"
            "        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED;\n"
            "    state.status = rome2_port_100f1cc0_cleanup_owned_utf16(",
            "    state.status = rome2_port_100f1cc0_cleanup_owned_utf16(",
        )
        self.assert_finding(
            gate.inspect_source_text(swapped), "CONSUMED before exact owned cleanup"
        )
        self.assert_mutant(
            gate.inspect_source_text, self.source,
            "        &state.effects,\n        persistent_owner);",
            "        &state.effects,\n        &state.owner);",
            "owned-cleanup argument tuple",
        )

    def test_provenance_and_doc_reciprocal_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_provenance_text, self.provenance,
            '"compensate_a_source_token_collision"',
            '"compensate_every_token_collision"',
            "both collision exclusion witnesses",
        )
        self.assert_mutant(
            gate.inspect_provenance_text, self.provenance,
            "self.assertEqual(mutant_count, 115)",
            "self.assertEqual(mutant_count, 114)",
            "provenance contract changed",
        )
        self.assert_mutant(
            gate.inspect_doc_text, self.doc,
            "Every other malformed nonzero-token grant",
            "Some other malformed nonzero-token grant",
            "doc sentinel-owned contract changed",
        )
        self.assert_mutant(
            gate.inspect_doc_text, self.doc,
            "`REGISTERED_SENTINEL -> REGISTERED_LIVE -> CONSUMED`",
            "`REGISTERED_SENTINEL -> CONSUMED`",
            "doc sentinel-owned contract changed",
        )

    def test_runtime_identity_lifecycle_and_validation_observer_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            "ROME2_PORT_100F2750_FIRST_USE_SENTINEL == UINT32_C(0x11af4090)",
            "ROME2_PORT_100F2750_FIRST_USE_SENTINEL == UINT32_C(0x11af4094)",
            "runtime sentinel assertion",
        )
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            "context->observed_return->value == context->return_before.value",
            "context->observed_return->value != context->return_before.value",
            "descriptors/owners/lifecycle/return unchanged",
        )
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            "context->observed_lifecycle, &context->lifecycle_before",
            "&context->lifecycle_before, &context->lifecycle_before",
            "descriptors/owners/lifecycle/return unchanged",
        )

    def test_runtime_allocator_compensation_and_teardown_observer_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            "byte_count != context->expected_bytes",
            "byte_count == context->expected_bytes",
            "exact allocation-size observation",
        )
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            "context->expected_release_mode == TEST_RELEASE_COMPENSATE",
            "context->expected_release_mode != TEST_RELEASE_COMPENSATE",
            "compensation observer",
        )
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            "context->observed_lifecycle->phase !=\n"
            "                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED",
            "context->observed_lifecycle->phase ==\n"
            "                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED",
            "lifecycle CONSUMED",
        )
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            "context->events[0] != TEST_EVENT_RELEASE ||\n"
            "        context->events[1] != TEST_EVENT_HOOK",
            "context->events[0] != TEST_EVENT_HOOK ||\n"
            "        context->events[1] != TEST_EVENT_RELEASE",
            "release-before-hook order",
        )

    def test_runtime_registration_success_and_failure_preservation_mutants_fail(self):
        registration = self.mutate(
            self.runtime,
            "    status = rome2_port_100f2750_register_first_use_owned(",
            "    status = rome2_port_100f2750_first_use_owned(",
        )
        self.assert_finding(
            gate.inspect_test_text(registration), "register the sentinel"
        )
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            "fixture->context.observed_allocate_bytes ==\n"
            "            fixture->length_units * UINT32_C(2) + UINT32_C(10)",
            "fixture->context.observed_allocate_bytes == fixture->length_units",
            "exact 2*N+10 request oracle",
        )
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            "memcmp(&fixture->temporary_owner,",
            "memcmp(&fixture->persistent_owner,",
            "exact failure-preservation matrix",
        )
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            "memcmp(&fixture->temporary_heap,\n"
            "            &before->temporary_heap, sizeof(fixture->temporary_heap))",
            "memcmp(&fixture->persistent_heap,\n"
            "            &before->temporary_heap, sizeof(fixture->temporary_heap))",
            "exact failure-preservation matrix",
        )

    def test_runtime_interior_zero_cases_groups_and_completion_mutants_fail(self):
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            '"opaque source units include an interior zero"',
            '"opaque source units are all nonzero"',
            "runtime reciprocal case is missing",
        )
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            "failed |= test_teardown_contract();",
            "failed |= test_preflight_failures();",
            "seven-group registry order",
        )
        self.assert_mutant(
            gate.inspect_test_text, self.runtime,
            '"100f2750 first-use owned runtime checks passed (%u cases)\\n"',
            '"100f2750 runtime done (%u cases)\\n"',
            "completion/cardinality report",
        )

    def test_runtime_deepseek_boundary_case_mutants_fail(self):
        labels = (
            "source raw residue %u / destination raw residue %u",
            "minimum finite owned payload",
            "denied destination with live source token collision",
            "zero-length temporary owner",
            "out-of-domain temporary owner length",
            "temporary descriptor guest range overflow",
            "persistent heap guest range overflow",
            "zero-based persistent heap lacks a usable first byte",
            "backing overlaps lifecycle control",
            "teardown callback context overlaps control",
            "teardown null callback context",
            "teardown empty callback context",
            "teardown null release effect",
            "null teardown descriptor view",
            "null teardown heap view",
            "null teardown effects",
            "null teardown owner",
        )
        for label in labels:
            with self.subTest(label=label):
                self.assert_mutant(
                    gate.inspect_test_text,
                    self.runtime,
                    f'"{label}"',
                    f'"removed {label}"',
                    "runtime reciprocal case is missing",
                )

    def test_cmake_containment_dependency_consumer_cli_fixture_and_count_mutants_fail(self):
        absent = self.cmake.replace(
            gate.LIBRARY, "removed_100f2750_sentinel_owned_library"
        )
        self.assertNotEqual(absent, self.cmake)
        self.assert_finding(gate.inspect_cmake_text(absent), "token is missing")
        escaped = self.cmake + (
            f"\nadd_library({gate.LIBRARY} STATIC escaped_sentinel.c)\n"
        )
        self.assert_finding(
            gate.inspect_cmake_text(escaped), "escapes BUILD_TESTING"
        )
        self.assert_mutant(
            gate.inspect_cmake_text, self.cmake,
            f"    {gate.LIBRARY}\n    STATIC",
            f"    {gate.LIBRARY}\n    SHARED",
            "exact static and test-only",
        )
        self.assert_mutant(
            gate.inspect_cmake_text, self.cmake,
            f"    {gate.LIBRARY}\n    PUBLIC "
            "rome2_startup_100f1bb0_owned_utf16_runtime",
            f"    {gate.LIBRARY}\n    PRIVATE "
            "rome2_startup_100f1bb0_owned_utf16_runtime",
            "exactly owned-UTF16/public",
        )
        extra = self.cmake + (
            f"\ntarget_link_libraries(rome2_headless64 PRIVATE {gate.LIBRARY})\n"
        )
        self.assert_finding(
            gate.inspect_cmake_text(extra), "its test and nonempty parent"
        )
        self.assert_mutant(
            gate.inspect_cmake_text, self.cmake,
            "      --sentinel-provenance \"${CMAKE_CURRENT_SOURCE_DIR}/scripts/"
            "test_x64_startup_100f2750_sentinel_owned_provenance.py\"\n",
            "",
            "static-gate argument",
        )
        self.assert_mutant(
            gate.inspect_cmake_text, self.cmake,
            '        "' + gate.PREDECESSOR_FIXTURE + ";",
            '        "startup_wrong_predecessor_verified;',
            "runtime fixture chain",
        )
        wrong_count = self.mutate(self.cmake, "add_test(", "removed_test(")
        self.assert_finding(
            gate.inspect_cmake_text(wrong_count),
            f"{gate.EXPECTED_CTEST_COUNT} CTests",
        )

    def test_exact_pins_reject_whitespace_only_mutations(self):
        cases = (
            (gate.inspect_header_text, self.header, "#define ROME2_PORT", "#define  ROME2_PORT", "header exact digest"),
            (gate.inspect_source_text, self.source, "#include <limits.h>", "#include  <limits.h>", "source exact digest"),
            (gate.inspect_test_text, self.runtime, "#include <stddef.h>", "#include  <stddef.h>", "runtime oracle exact digest"),
            (gate.inspect_provenance_text, self.provenance, "from __future__", "from  __future__", "provenance exact digest"),
            (gate.inspect_doc_text, self.doc, "# ", "#  ", "doc exact digest"),
        )
        for inspector, payload, old, new, expected in cases:
            with self.subTest(expected=expected):
                self.assert_mutant(inspector, payload, old, new, expected)


if __name__ == "__main__":
    unittest.main()

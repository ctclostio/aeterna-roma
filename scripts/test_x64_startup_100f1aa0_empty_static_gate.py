from __future__ import annotations

import pathlib
import unittest
from unittest import mock

import x64_startup_100f1aa0_empty_static_gate as gate


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


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "port" / "x64_ported" / "ported_100f1aa0_empty.c"
HEADER_PATH = ROOT / "port" / "x64_ported" / "ported_100f1aa0_empty.h"
CMAKE_PATH = ROOT / "CMakeLists.txt"
TEST_PATH = ROOT / "port" / "x64_runtime" / "test_startup_100f1aa0_empty.c"
EXPORT_MANIFEST_PATH = ROOT / "port" / "x64_exports" / "export_manifest.tsv"
LEGACY_DEF_PATH = ROOT / "port" / "x64_exports" / "empire.retail.exports.def"
PROBE_DEF_PATH = ROOT / "port" / "x64_probe" / "probe_exports.def"


class Startup100f1aa0EmptyStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")
        cls.header = HEADER_PATH.read_text(encoding="utf-8")
        cls.cmake = CMAKE_PATH.read_text(encoding="utf-8")
        cls.test_source = TEST_PATH.read_text(encoding="utf-8")
        cls.export_manifest = EXPORT_MANIFEST_PATH.read_text(encoding="utf-8")
        cls.legacy_def = LEGACY_DEF_PATH.read_text(encoding="utf-8")
        cls.probe_def = PROBE_DEF_PATH.read_text(encoding="utf-8")

    def assert_source_rejected(self, mutant: str, label: str) -> None:
        self.assertNotEqual(mutant, self.source, f"mutant did not apply: {label}")
        self.assertTrue(gate.inspect_source_text(mutant), label)

    def test_current_sources_build_and_exports_pass(self) -> None:
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_test_text(self.test_source), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])
        self.assertEqual(gate.inspect_exports_text(self.export_manifest), [])
        self.assertEqual(gate.inspect_exports_text(self.legacy_def), [])
        self.assertEqual(gate.inspect_exports_text(self.probe_def), [])

    def test_final_cmake_count_mutant_is_rejected(self) -> None:
        mutant = self.cmake + "\nadd_test(NAME empty_extra COMMAND false)\n"
        self.assertIn(
            "CMake add_test declaration count must remain 192",
            gate.inspect_cmake_text(mutant),
        )

    def test_runtime_oracle_and_delegate_shortcut_mutants_are_rejected(self) -> None:
        wrong_oracle = self.test_source.replace("    0x90, 0x40, 0xaf, 0x11", "    0x8a, 0x40, 0xaf, 0x11", 1)
        self.assertTrue(gate.inspect_test_text(wrong_oracle))
        delegate_shortcut = self.test_source.replace(
            "int main(void)",
            "void *forbidden_delegate = rome2_port_100f1c10_initialize_triplet;\n\n"
            "int main(void)",
            1,
        )
        self.assertTrue(gate.inspect_test_text(delegate_shortcut))

    def test_nonzero_acceptance_and_partial_count_mutants_are_rejected(self) -> None:
        accepts_nonzero = self.source.replace(
            "if (source_count != 0)", "if (source_count == 0)", 1
        )
        self.assert_source_rejected(accepts_nonzero, "accepts nonzero count")
        ignores_high_byte = self.source.replace(
            "        ((uint32_t)source_bytes[3] << 24);",
            "        ((uint32_t)source_bytes[3] << 0);",
            1,
        )
        self.assert_source_rejected(ignores_high_byte, "partial count decode")
        reads_payload = self.source.replace(
            "        ((uint32_t)source_bytes[3] << 24);",
            "        ((uint32_t)source_bytes[3] << 24) | source_bytes[8];",
            1,
        )
        self.assert_source_rejected(reads_payload, "reads guest pointer payload")

    def test_status_precedence_reorder_mutant_is_rejected_semantically(self) -> None:
        null_check = (
            "    if (guest_destination.value == 0 || guest_source.value == 0) {\n"
            "        return ROME2_GUEST_NULL_ADDRESS;\n"
            "    }\n"
        )
        below_base_check = (
            "    if (guest_destination.value < view->guest_base ||\n"
            "        guest_source.value < view->guest_base) {\n"
            "        return ROME2_GUEST_OUT_OF_RANGE;\n"
            "    }\n"
        )
        prefix, remainder = self.source.split(null_check, 1)
        between, suffix = remainder.split(below_base_check, 1)
        reordered = prefix + below_base_check + between + null_check + suffix
        reordered_code, sanitize_findings = gate.sanitize_c(reordered)
        self.assertEqual(sanitize_findings, [])
        reordered_digest = gate._token_digest(reordered_code)
        with mock.patch.object(
            gate, "EXPECTED_SOURCE_TOKEN_SHA256", reordered_digest
        ):
            findings = gate.inspect_source_text(reordered)
        self.assertIn(
            "validation, source read, and delegation order changed", findings
        )

    def test_direct_write_wrong_delegate_and_early_output_are_rejected(self) -> None:
        direct_write = self.source.replace(
            "    return rome2_port_100f1c10_initialize_triplet(\n"
            "        view, guest_destination, guest_return_out);",
            "    view->host_base[(size_t)destination_offset] = 0;\n"
            "    return ROME2_GUEST_OK;",
            1,
        )
        self.assert_source_rejected(direct_write, "direct destination write")
        wrong_delegate = self.source.replace(
            "rome2_port_100f1c10_initialize_triplet",
            "rome2_port_100f1aa0_copy_empty_source",
            1,
        )
        self.assert_source_rejected(wrong_delegate, "recursive wrong delegate")
        early_output = self.source.replace(
            "    if (view == NULL",
            "    guest_return_out->value = guest_destination.value;\n\n"
            "    if (view == NULL",
            1,
        )
        self.assert_source_rejected(early_output, "early output mutation")

    def test_guest_span_overlap_mutants_are_rejected(self) -> None:
        overlap_block = (
            "    if ((destination_offset >= source_offset &&\n"
            "         destination_offset - source_offset < ROME2_EMPTY_SEQUENCE_BYTES) ||\n"
            "        (source_offset > destination_offset &&\n"
            "         source_offset - destination_offset < ROME2_EMPTY_SEQUENCE_BYTES)) {\n"
            "        return ROME2_GUEST_BAD_ARGUMENT;\n"
            "    }\n"
        )
        missing_overlap = self.source.replace(overlap_block, "", 1)
        self.assert_source_rejected(missing_overlap, "missing overlap rejection")
        off_by_one = self.source.replace(
            "destination_offset - source_offset < ROME2_EMPTY_SEQUENCE_BYTES",
            "destination_offset - source_offset <= ROME2_EMPTY_SEQUENCE_BYTES",
            1,
        )
        self.assert_source_rejected(off_by_one, "overlap off by one")
        for width in (8, 16):
            mutant = self.source.replace(
                "#define ROME2_EMPTY_SEQUENCE_BYTES UINT64_C(12)",
                f"#define ROME2_EMPTY_SEQUENCE_BYTES UINT64_C({width})",
                1,
            )
            self.assert_source_rejected(mutant, f"{width}-byte spans")

    def test_native_alias_checks_cannot_be_removed(self) -> None:
        output_view_check = (
            "    if ((output_address >= view_address &&\n"
            "         output_address - view_address < sizeof(*view)) ||\n"
            "        (view_address > output_address &&\n"
            "         view_address - output_address < sizeof(*guest_return_out))) {\n"
            "        return ROME2_GUEST_BAD_ARGUMENT;\n"
            "    }\n"
        )
        self.assert_source_rejected(
            self.source.replace(output_view_check, "", 1),
            "output/descriptor alias",
        )
        descriptor_view_check = (
            "    if (view->byte_count != 0 &&\n"
            "        ((view_address >= host_address &&\n"
            "          (uint64_t)(view_address - host_address) < view->byte_count) ||\n"
            "         (host_address > view_address &&\n"
            "          host_address - view_address < sizeof(*view)))) {\n"
            "        return ROME2_GUEST_BAD_ARGUMENT;\n"
            "    }\n"
        )
        self.assert_source_rejected(
            self.source.replace(descriptor_view_check, "", 1),
            "descriptor/guest-view alias",
        )

    def test_overflow_and_range_mutants_are_rejected(self) -> None:
        host_check = (
            "    if (view->byte_count != 0 &&\n"
            "        view->byte_count - UINT64_C(1) >\n"
            "            (uint64_t)(UINTPTR_MAX - host_address)) {\n"
            "        return ROME2_GUEST_RANGE_OVERFLOW;\n"
            "    }\n"
        )
        self.assert_source_rejected(
            self.source.replace(host_check, "", 1), "unchecked host overflow"
        )
        source_bounds = self.source.replace(
            "        ROME2_EMPTY_SEQUENCE_BYTES > view->byte_count - source_offset ||",
            "        ROME2_EMPTY_SEQUENCE_BYTES < view->byte_count - source_offset ||",
            1,
        )
        self.assert_source_rejected(source_bounds, "reversed source bounds")

    def test_native_pointer_allocator_and_global_mutants_are_rejected(self) -> None:
        native_pointer = self.source.replace(
            "    uint32_t source_count;",
            "    uint32_t source_count;\n"
            "    uint8_t *bad = (uint8_t *)(uintptr_t)guest_source.value;",
            1,
        )
        self.assert_source_rejected(native_pointer, "guest/native pointer cast")
        allocation = self.source.replace(
            "    uint32_t source_count;",
            "    uint32_t source_count;\n    (void)malloc(12);",
            1,
        )
        self.assert_source_rejected(allocation, "allocator call")
        global_state = "uint8_t bad_empty_storage[12];\n" + self.source
        self.assert_source_rejected(global_state, "global writable storage")
        platform = self.source.replace(
            "    uint32_t source_count;",
            "    uint32_t source_count;\n    (void)VirtualAlloc(0, 12, 0, 0);",
            1,
        )
        self.assert_source_rejected(platform, "platform allocator")

    def test_header_widening_reordering_and_export_are_rejected(self) -> None:
        widened = self.header.replace(
            "rome2_guest_addr32 guest_source,", "uintptr_t guest_source,", 1
        )
        self.assertTrue(gate.inspect_header_text(widened))
        reordered = self.header.replace(
            "    rome2_guest_addr32 guest_destination,\n"
            "    rome2_guest_addr32 guest_source,",
            "    rome2_guest_addr32 guest_source,\n"
            "    rome2_guest_addr32 guest_destination,",
            1,
        )
        self.assertTrue(gate.inspect_header_text(reordered))
        exported = self.header.replace(
            "rome2_guest_status rome2_port_100f1aa0",
            "__declspec(dllexport) rome2_guest_status rome2_port_100f1aa0",
            1,
        )
        self.assertTrue(gate.inspect_header_text(exported))

    def test_cmake_shared_escape_and_delegate_mutants_are_rejected(self) -> None:
        shared = self.cmake.replace(
            "rome2_startup_100f1aa0_empty_runtime\n    STATIC",
            "rome2_startup_100f1aa0_empty_runtime\n    SHARED",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(shared))
        escaped = (
            "add_library(evil_empty STATIC "
            "port/x64_ported/ported_100f1aa0_empty.c)\n" + self.cmake
        )
        self.assertTrue(gate.inspect_cmake_text(escaped))
        no_delegate = self.cmake.replace(
            "  target_link_libraries(\n"
            "    rome2_startup_100f1aa0_empty_runtime\n"
            "    PRIVATE rome2_startup_100f1c10_runtime\n"
            "  )",
            "  target_link_libraries(\n"
            "    rome2_startup_100f1aa0_empty_runtime\n"
            "    PRIVATE rome2_guest32_runtime\n"
            "  )",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(no_delegate))
        shared_with_bootstrap = self.cmake.replace(
            "    rome2_startup_100f1aa0_empty_runtime\n"
            "    PRIVATE rome2_startup_100f1c10_runtime",
            "    rome2_startup_100f1aa0_empty_runtime\n"
            "    PRIVATE rome2_startup_100f1c10_runtime empire_retail_bootstrap",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(shared_with_bootstrap))
        headless_with_bootstrap = self.cmake.replace(
            "      rome2_startup_100f1aa0_empty_runtime\n"
            "      rome2_startup_safe_seams_runtime\n"
            "      rome2_startup_100df270_headless_runtime\n"
            "      rome2_startup_100f2750_nonalloc_runtime\n"
            "      rome2_startup_100e8240_fastpath_runtime\n"
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
            "  )\n"
            "  target_link_options(\n"
            "    rome2_headless64",
            "      rome2_startup_100f1aa0_empty_runtime\n"
            "      rome2_startup_safe_seams_runtime\n"
            "      rome2_startup_100df270_headless_runtime\n"
            "      rome2_startup_100f2750_nonalloc_runtime\n"
            "      rome2_startup_100e8240_fastpath_runtime\n"
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
            "      empire_retail_bootstrap\n"
            "  )\n"
            "  target_link_options(\n"
            "    rome2_headless64",
            1,
        )
        self.assertNotEqual(headless_with_bootstrap, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(headless_with_bootstrap))
        missing_parent_consumer = self.cmake.replace(
            "      rome2_startup_100f1aa0_empty_runtime\n"
            "      rome2_startup_safe_seams_runtime\n",
            "      rome2_startup_safe_seams_runtime\n",
            1,
        )
        self.assertNotEqual(missing_parent_consumer, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(missing_parent_consumer))
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
            'startup_100df270_platform_prefix_transcript_reload_verified"',
            1,
        )
        self.assertNotEqual(stale_terminal_fixture, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(stale_terminal_fixture))
        escaped_headless = self.cmake.replace(
            "  add_executable(\n"
            "    rome2_headless64",
            "endif()\n\nadd_executable(\n"
            "    rome2_headless64",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(escaped_headless))
        override = "set(BUILD_TESTING ON)\n" + self.cmake
        self.assertTrue(gate.inspect_cmake_text(override))

    def test_production_and_probe_export_mutants_are_rejected(self) -> None:
        for text, suffix in (
            (self.export_manifest, "\nrome2_port_100f1aa0_copy_empty_source\n"),
            (self.legacy_def, "\n    EmptyCopy=rome2_port_100f1aa0_copy_empty_source\n"),
            (self.probe_def, "\n    Rome2Probe100f1aa0\n"),
        ):
            self.assertTrue(gate.inspect_exports_text(text + suffix))


if __name__ == "__main__":
    unittest.main(verbosity=2)

from __future__ import annotations

import pathlib
import unittest

import x64_startup_100f1c10_static_gate as gate


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "port" / "x64_ported" / "ported_100f1c10_triplet.c"
HEADER_PATH = ROOT / "port" / "x64_ported" / "ported_100f1c10_triplet.h"
CMAKE_PATH = ROOT / "CMakeLists.txt"


class StartupTripletStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")
        cls.header = HEADER_PATH.read_text(encoding="utf-8")
        cls.cmake = CMAKE_PATH.read_text(encoding="utf-8")

    def assert_source_rejected(self, mutant: str, label: str) -> None:
        self.assertTrue(gate.inspect_source_text(mutant), label)

    def test_current_sources_and_build_contract_pass(self) -> None:
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_wrong_and_swapped_identity_bytes_are_rejected(self) -> None:
        wrong = self.source.replace("UINT8_C(0x90)", "UINT8_C(0x8a)", 1)
        self.assert_source_rejected(wrong, "wrong identity")
        swapped = self.source.replace("UINT8_C(0x90)", "UINT8_C(0xfe)", 1)
        swapped = swapped.replace("UINT8_C(0x40)", "UINT8_C(0x90)", 1)
        swapped = swapped.replace("UINT8_C(0xfe)", "UINT8_C(0x40)", 1)
        self.assert_source_rejected(swapped, "swapped identity bytes")

    def test_partial_wide_and_extra_stores_are_rejected(self) -> None:
        partial = self.source.replace("    destination[7] = 0;\n", "", 1)
        self.assert_source_rejected(partial, "partial write")
        wide = self.source.replace(
            "    destination[11] = UINT8_C(0x11);\n",
            "    destination[11] = UINT8_C(0x11);\n"
            "    destination[12] = 0;\n",
            1,
        )
        self.assert_source_rejected(wide, "extra write")

        aliased = self.source.replace(
            "    destination[11] = UINT8_C(0x11);",
            "    destination[11] = UINT8_C(0x11);\n"
            "    { uint8_t *alias = destination; alias[12] = 1; }",
            1,
        )
        self.assert_source_rejected(aliased, "aliased extra write")
        direct_view = self.source.replace(
            "    destination[11] = UINT8_C(0x11);",
            "    destination[11] = UINT8_C(0x11);\n"
            "    view->host_base[20] = 1;",
            1,
        )
        self.assert_source_rejected(direct_view, "direct view write")

    def test_write_before_validation_and_output_mutation_are_rejected(self) -> None:
        early_write = self.source.replace(
            "    if (view == NULL",
            "    destination[0] = 0;\n\n    if (view == NULL",
            1,
        )
        self.assert_source_rejected(early_write, "early write")
        early_output = self.source.replace(
            "    if (view == NULL",
            "    guest_return_out->value = guest_destination.value;\n\n"
            "    if (view == NULL",
            1,
        )
        self.assert_source_rejected(early_output, "failure output mutation")

    def test_wrong_return_and_span_mutants_are_rejected(self) -> None:
        wrong_return = self.source.replace(
            "guest_return_out->value = guest_destination.value;",
            "guest_return_out->value = guest_destination.value + 1;",
            1,
        )
        self.assert_source_rejected(wrong_return, "wrong guest return")
        for width in (8, 16):
            mutant = self.source.replace(
                "#define ROME2_STARTUP_TRIPLET_BYTES UINT64_C(12)",
                f"#define ROME2_STARTUP_TRIPLET_BYTES UINT64_C({width})",
                1,
            )
            self.assert_source_rejected(mutant, f"{width}-byte span")

    def test_range_and_host_overflow_mutants_are_rejected(self) -> None:
        off_by_one = self.source.replace(
            "if (offset > view->byte_count ||",
            "if (offset >= view->byte_count ||",
            1,
        )
        self.assert_source_rejected(off_by_one, "off-by-one range")
        unchecked_host = self.source.replace(
            "    if (view->byte_count != 0 &&\n"
            "        view->byte_count - UINT64_C(1) >\n"
            "            (uint64_t)(UINTPTR_MAX - host_address)) {\n"
            "        return ROME2_GUEST_RANGE_OVERFLOW;\n"
            "    }\n",
            "",
            1,
        )
        self.assert_source_rejected(unchecked_host, "unchecked host overflow")

    def test_native_pointer_global_and_helper_mutants_are_rejected(self) -> None:
        native_pointer = self.source.replace(
            "    uint64_t offset;",
            "    uint64_t offset;\n"
            "    uint8_t *bad = (uint8_t *)(uintptr_t)guest_destination.value;",
            1,
        )
        self.assert_source_rejected(native_pointer, "guest pointer cast")
        global_state = "static uint8_t bad_storage[12];\n" + self.source
        self.assert_source_rejected(global_state, "global state")
        ordinary_global = "uint8_t bad_storage[12];\n" + self.source
        self.assert_source_rejected(ordinary_global, "ordinary global state")
        allocation = self.source.replace(
            "    uint64_t offset;",
            "    uint64_t offset;\n    (void)malloc(12);",
            1,
        )
        self.assert_source_rejected(allocation, "allocation/helper call")

        pointer_identity = self.source.replace(
            "    destination[8] = UINT8_C(0x90);",
            "    destination[8] = (uint8_t)(uintptr_t)view->host_base;",
            1,
        )
        self.assert_source_rejected(pointer_identity, "native pointer identity")

    def test_store_order_and_extra_success_return_are_rejected(self) -> None:
        reordered = self.source.replace(
            "    destination[0] = 0;\n    destination[1] = 0;",
            "    destination[1] = 0;\n    destination[0] = 0;",
            1,
        )
        self.assert_source_rejected(reordered, "reordered stores")
        extra_return = self.source.replace(
            "    return ROME2_GUEST_OK;",
            "    if (offset == 99) { return ROME2_GUEST_OK; }\n"
            "    return ROME2_GUEST_OK;",
            1,
        )
        self.assert_source_rejected(extra_return, "extra success return")

    def test_header_width_and_dll_export_mutants_are_rejected(self) -> None:
        widened = self.header.replace("uint32_t guest_base;", "uintptr_t guest_base;", 1)
        self.assertTrue(gate.inspect_header_text(widened))
        exported = self.header.replace(
            "rome2_guest_status rome2_port_100f1c10",
            "__declspec(dllexport) rome2_guest_status rome2_port_100f1c10",
            1,
        )
        self.assertTrue(gate.inspect_header_text(exported))

    def test_cmake_shared_or_outside_testing_mutants_are_rejected(self) -> None:
        shared = self.cmake.replace(
            "rome2_startup_100f1c10_runtime\n    STATIC",
            "rome2_startup_100f1c10_runtime\n    SHARED",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(shared))
        escaped = (
            "add_library(evil_triplet STATIC "
            "port/x64_ported/ported_100f1c10_triplet.c)\n" + self.cmake
        )
        self.assertTrue(gate.inspect_cmake_text(escaped))

        injected = self.cmake.replace(
            "  add_executable(\n    rome2_guest32_probe_host",
            "  target_sources(empire_retail_bootstrap PRIVATE\n"
            "    port/x64_ported/ported_100f1c10_triplet.c)\n\n"
            "  add_executable(\n    rome2_guest32_probe_host",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(injected))
        override = "set(BUILD_TESTING ON)\n" + self.cmake
        self.assertTrue(gate.inspect_cmake_text(override))
        alternate = self.cmake.replace(
            "if(BUILD_TESTING)\n",
            "if(BUILD_TESTING)\nelse()\n",
            1,
        )
        self.assertTrue(gate.inspect_cmake_text(alternate))
        missing_parent_consumer = self.cmake.replace(
            "      rome2_startup_100f1c10_runtime\n"
            "      rome2_startup_100f1aa0_empty_runtime\n",
            "      rome2_startup_100f1aa0_empty_runtime\n",
            1,
        )
        self.assertNotEqual(missing_parent_consumer, self.cmake)
        self.assertTrue(gate.inspect_cmake_text(missing_parent_consumer))


if __name__ == "__main__":
    unittest.main(verbosity=2)

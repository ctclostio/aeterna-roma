#!/usr/bin/env python3
"""Reciprocal mutants for the 0x100e8580 handler-transcript gate."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
GATE_PATH = SCRIPTS / "x64_startup_100e8580_handler_transcript_static_gate.py"
SPEC = importlib.util.spec_from_file_location("handler_8580_static_gate", GATE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load 100e8580 handler-transcript static gate")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


def future_headless() -> str:
    text = read("port/x64_headless/headless_main.c")
    final_token = "initializer-100ea4d0=injected-complete;"
    if final_token not in text:
        marker = '        "initializer-handler-100e8580=injected-transcript-complete;"'
        replacement = marker + '\n        "initializer-100ea4d0=injected-complete;"'
        if text.count(marker) != 1:
            raise AssertionError("cannot construct future headless transcript fixture")
        text = text.replace(marker, replacement, 1)
    return text


def future_cmake() -> str:
    return read("CMakeLists.txt")
    links = "\n".join("      " + library for library in gate.HEADLESS_LINK_LIBRARIES)
    return f'''if(BUILD_TESTING)
  add_library(
    {gate.LIBRARY}
    STATIC
      "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e8580_handler_transcript.h"
      "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e8580_handler_transcript.c"
  )
  target_compile_features(
    {gate.LIBRARY} PUBLIC c_std_17
  )
  target_compile_options(
    {gate.LIBRARY}
    PRIVATE ${{ROME2_HARDENED_COMPILE_OPTIONS}}
  )
  target_include_directories(
    {gate.LIBRARY}
    PUBLIC
      "${{ROME2_GUEST32_RUNTIME_DIR}}"
      "${{ROME2_GUEST32_PORTED_DIR}}"
  )
  target_link_libraries(
    {gate.LIBRARY}
    PRIVATE {gate.GUEST32_LIBRARY}
  )
  set_property(
    TARGET {gate.LIBRARY}
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    {gate.TEST_TARGET}
    "${{ROME2_GUEST32_RUNTIME_DIR}}/test_startup_100e8580_handler_transcript.c"
  )
  rome2_configure_x64_target({gate.TEST_TARGET})
  target_link_libraries(
    {gate.TEST_TARGET}
    PRIVATE {gate.LIBRARY}
  )

  target_link_libraries(
    {gate.HEADLESS}
    PRIVATE
{links}
  )

  add_test(
    NAME startup_100e8580_handler_transcript_provenance
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e8580_handler_transcript_provenance.py"
  )
  add_test(
    NAME startup_100e8580_handler_transcript_static_gate_unit
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e8580_handler_transcript_static_gate.py"
  )
  add_test(
    NAME startup_100e8580_handler_transcript_static_gate
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/x64_startup_100e8580_handler_transcript_static_gate.py"
      --header "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e8580_handler_transcript.h"
      --source "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e8580_handler_transcript.c"
      --test "${{ROME2_GUEST32_RUNTIME_DIR}}/test_startup_100e8580_handler_transcript.c"
      --transcript-provenance "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e8580_handler_transcript_provenance.py"
      --headless "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_headless/headless_main.c"
      --cmake "${{CMAKE_CURRENT_SOURCE_DIR}}/CMakeLists.txt"
      --export-manifest "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e8580_handler_transcript_runtime
    COMMAND "$<TARGET_FILE:{gate.TEST_TARGET}>"
  )
  add_test(
    NAME startup_100e8580_handler_transcript_post_pe_gate
    COMMAND Python3::Interpreter post_pe.py
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e8580_handler_transcript
    COMMAND "$<TARGET_FILE:empire_bootstrap_smoke>"
  )

  set_tests_properties(
    startup_100e8580_handler_transcript_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e8580_handler_transcript_provenance_verified
  )
  set_tests_properties(
    startup_100e8580_handler_transcript_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e8580_handler_transcript_static_tool_verified
  )
  set_tests_properties(
    startup_100e8580_handler_transcript_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e8580_handler_transcript_static_tool_verified
      FIXTURES_SETUP startup_100e8580_handler_transcript_static_verified
  )
  set_tests_properties(
    startup_100e8580_handler_transcript_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e85d0_normal_adapter_reload_verified;startup_100e8580_handler_transcript_provenance_verified;startup_100e8580_handler_transcript_static_verified"
      FIXTURES_SETUP startup_100e8580_handler_transcript_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e8580_handler_transcript_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e8580_handler_transcript_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e8580_handler_transcript_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e8580_handler_transcript
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e8580_handler_transcript_post_verified"
      FIXTURES_SETUP startup_100e8580_handler_transcript_reload_verified
  )
  set_tests_properties(
    headless_bounded_lifecycle
    PROPERTIES
      FIXTURES_REQUIRED
        "entry_policy_provenance_verified;entry_policy_static_verified;startup_100ea4d0_injected_reload_verified"
      TIMEOUT 90
  )
endif()
'''


class Startup100e8580HandlerTranscriptStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read("port/x64_ported/ported_100e8580_handler_transcript.h")
        cls.source = read("port/x64_ported/ported_100e8580_handler_transcript.c")
        cls.test = read("port/x64_runtime/test_startup_100e8580_handler_transcript.c")
        cls.provenance = read_bytes(
            "scripts/test_x64_startup_100e8580_handler_transcript_provenance.py"
        )
        cls.headless = future_headless()
        cls.cmake = future_cmake()
        cls.export_manifest = read("port/x64_exports/export_manifest.tsv")
        cls.legacy_def = read("port/x64_exports/empire.retail.exports.def")
        cls.probe_def = read("port/x64_probe/probe_exports.def")

    def assert_finding(self, findings: list[str], fragment: str) -> None:
        self.assertTrue(
            any(fragment in finding for finding in findings),
            f"expected finding containing {fragment!r}; got {findings!r}",
        )

    def test_live_payloads_provenance_and_exports_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_test_text(self.test), [])
        self.assertEqual(gate.inspect_provenance_bytes(self.provenance), [])
        self.assertEqual(gate.inspect_exports_text(self.export_manifest), [])
        self.assertEqual(gate.inspect_exports_text(self.legacy_def), [])
        self.assertEqual(gate.inspect_exports_text(self.probe_def), [])

    def test_future_outer_integration_contract_passes(self):
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_header_result_displacement_and_order_mutants_fail(self):
        wrong_displacement = self.header.replace("UINT32_C(0x68)", "UINT32_C(0x67)", 1)
        self.assert_finding(
            gate.inspect_header_text(wrong_displacement), "displacement"
        )
        wrong_identity = self.header.replace("0x1173fb54", "0x1173fb55", 1)
        self.assert_finding(gate.inspect_header_text(wrong_identity), "identity")
        reordered = self.header.replace(
            "ROME2_100E8580_STEP_CALL_112D0510 = 2",
            "ROME2_100E8580_STEP_CALL_112D0510 = 3",
            1,
        )
        self.assert_finding(gate.inspect_header_text(reordered), "nine-step order")
        no_result = self.header.replace("rome2_guest_addr32 result_100e8240;", "", 1)
        self.assert_finding(gate.inspect_header_text(no_result), "explicitly inject")

    def test_source_typed_order_and_argument_mutants_fail(self):
        wrong_one = self.source.replace(
            "step.argument0 = UINT32_C(1);",
            "step.argument0 = UINT32_C(0);",
            1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_one), "step 3")
        reordered = self.source.replace(
            "step.kind = ROME2_100E8580_STEP_CALL_100D9810;",
            "step.kind = ROME2_100E8580_STEP_CALL_100DDF50;",
            1,
        )
        self.assert_finding(gate.inspect_source_text(reordered), "nine-step order")
        wrong_suffix_identity = self.source.replace(
            "ROME2_PORT_100E8580_FINISHED_RUN_VARS_IDENTITY",
            "UINT32_C(0x1173fb55)",
            1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_suffix_identity), "step 9")

    def test_source_snapshot_checked_dependency_and_prefix_mutants_fail(self):
        live_add = (
            "effects_snapshot.result_100e8240,\n"
            "        ROME2_PORT_100E8580_RESULT_DISPLACEMENT,"
        )
        unsnapshotted = self.source.replace(
            live_add,
            "effects->result_100e8240,\n"
            "        ROME2_PORT_100E8580_RESULT_DISPLACEMENT,",
            1,
        )
        self.assert_finding(gate.inspect_source_text(unsnapshotted), "snapshotted")
        unchecked = self.source.replace(
            "ROME2_PORT_100E8580_RESULT_DISPLACEMENT,",
            "UINT32_C(0x67),",
            1,
        )
        self.assert_finding(gate.inspect_source_text(unchecked), "checked snapshotted")

        step7 = '''    rome2_100e8580_clear_step(&step);
    step.kind = ROME2_100E8580_STEP_CALL_100E8240;
    step.argument_count = UINT32_C(1);
    step.argument0 = UINT32_C(0);
    step.has_guest_result = UINT32_C(1);
    step.returned_guest_identity = effects_snapshot.result_100e8240;
    effects_snapshot.emit_step(effects_snapshot.context, step);

'''
        checked = '''    status = rome2_guest_add_checked(
        effects_snapshot.result_100e8240,
        ROME2_PORT_100E8580_RESULT_DISPLACEMENT,
        &adjusted_identity);
    if (status != ROME2_GUEST_OK) {
        return status;
    }

'''
        moved = self.source.replace(step7 + checked, checked + step7, 1)
        self.assert_finding(gate.inspect_source_text(moved), "exactly seven prefix")

    def test_source_output_alias_opaque_and_native_mutants_fail(self):
        early_output = self.source.replace(
            "    *return_al_out = ROME2_PORT_100E8580_AL;\n",
            "",
            1,
        ).replace(
            "    rome2_100e8580_clear_step(&step);\n"
            "    step.kind = ROME2_100E8580_STEP_CALL_112DCAF0;",
            "    *return_al_out = ROME2_PORT_100E8580_AL;\n\n"
            "    rome2_100e8580_clear_step(&step);\n"
            "    step.kind = ROME2_100E8580_STEP_CALL_112DCAF0;",
            1,
        )
        self.assert_finding(gate.inspect_source_text(early_output), "after step nine")
        no_alias = self.source.replace(
            "    if (rome2_100e8580_ranges_overlap(\n"
            "            effects, sizeof(*effects),\n"
            "            return_al_out, sizeof(*return_al_out))) {\n"
            "        return ROME2_GUEST_BAD_ARGUMENT;\n"
            "    }",
            "    if (0) {\n"
            "        return ROME2_GUEST_BAD_ARGUMENT;\n"
            "    }",
            1,
        )
        self.assert_finding(gate.inspect_source_text(no_alias), "alias rejection")
        inspected_input = self.source.replace(
            "    (void)guest_receiver;",
            "    if (guest_receiver.value == 0) { return ROME2_GUEST_NULL_ADDRESS; }",
            1,
        )
        self.assert_finding(gate.inspect_source_text(inspected_input), "opaque")
        native = self.source.replace(
            "    (void)guest_argument;",
            "    (void)malloc(4);",
            1,
        )
        self.assert_finding(gate.inspect_source_text(native), "malloc")

    def test_runtime_result_boundary_prefix_and_snapshot_mutants_fail(self):
        six_prefix = self.test.replace(
            "#define ROME2_TEST_PREFIX_COUNT UINT32_C(7)",
            "#define ROME2_TEST_PREFIX_COUNT UINT32_C(6)",
            1,
        )
        self.assert_finding(gate.inspect_test_text(six_prefix), "seven-prefix")
        wrong_boundary = self.test.replace("UINT32_C(0xffffff98)", "UINT32_C(0xffffff99)", 1)
        self.assert_finding(gate.inspect_test_text(wrong_boundary), "overflow boundary")
        wrong_dependency = self.test.replace(
            "result_100e8240 + UINT32_C(0x68)",
            "result_100e8240 + UINT32_C(0x64)",
            1,
        )
        self.assert_finding(gate.inspect_test_text(wrong_dependency), "adjusted-result")
        no_snapshot_mutant = self.test.replace(
            "trace->effects.result_100e8240.value = UINT32_C(0);",
            "trace->effects.result_100e8240.value = trace->original_result;",
            1,
        )
        self.assert_finding(gate.inspect_test_text(no_snapshot_mutant), "snapshot mutant")

    def test_runtime_publication_alias_and_opaque_mutants_fail(self):
        early_al_allowed = self.test.replace(
            "*trace->return_al != ROME2_TEST_SENTINEL",
            "*trace->return_al == ROME2_TEST_SENTINEL",
            1,
        )
        self.assert_finding(gate.inspect_test_text(early_al_allowed), "unpublished AL")
        no_alias = self.test.replace(
            "(uint8_t *)(void *)&trace.effects",
            "&return_al",
            1,
        )
        self.assert_finding(gate.inspect_test_text(no_alias), "alias case")
        narrowed_inputs = self.test.replace(
            "rome2_test_guest(UINT32_C(0)),\n"
            "        rome2_test_guest(UINT32_MAX)",
            "rome2_test_guest(UINT32_C(1)),\n"
            "        rome2_test_guest(UINT32_C(2))",
        )
        self.assert_finding(gate.inspect_test_text(narrowed_inputs), "all-bit")

    def test_provenance_body_call_vtable_and_data_mutants_fail(self):
        text = self.provenance.decode("utf-8")
        wrong_body = text.replace(
            "baeed663cb3c273a7e4a6cceb6cd6976695f2226e321bb231e484758a2cf3dfe",
            "0" * 64,
            1,
        ).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_body), "authority marker")
        wrong_call = text.replace("0x112BFEE0", "0x112BFEE1", 1).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_call), "authority marker")
        wrong_vtable = text.replace("0x1173F21C", "0x1173F220", 1).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_vtable), "authority marker")
        executable = (text + "\nimport ctypes\n").encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(executable), "data-only")

    def test_headless_call_result_order_and_token_mutants_fail(self):
        wrong_call = self.headless.replace(
            "&context->handler_8580_effects,",
            "&context->handler_8d00_effects,",
            1,
        )
        self.assert_finding(gate.inspect_headless_text(wrong_call), "call arguments")
        first_call = self.headless.find(gate.FUNCTION)
        self.assertGreaterEqual(first_call, 0)
        no_router_call = (
            self.headless[:first_call]
            + "rome2_port_100e8580_router_call_removed"
            + self.headless[first_call + len(gate.FUNCTION):]
        )
        self.assert_finding(
            gate.inspect_headless_text(no_router_call), "standalone router dispatch"
        )
        last_call = self.headless.rfind(gate.FUNCTION)
        self.assertGreater(last_call, first_call)
        no_outer_call = (
            self.headless[:last_call]
            + "rome2_port_100e8580_outer_call_removed"
            + self.headless[last_call + len(gate.FUNCTION):]
        )
        self.assert_finding(
            gate.inspect_headless_text(no_outer_call), "injected outer dispatch"
        )
        wrong_result = self.headless.replace("UINT32_C(0x119f3a38)", "UINT32_C(0x119f3a39)", 1)
        self.assert_finding(gate.inspect_headless_text(wrong_result), "result oracle")
        wrong_final = self.headless.replace(
            "initializer-100ea4d0=injected-complete",
            "initializer-100ea4d0=native",
            1,
        )
        self.assert_finding(gate.inspect_headless_text(wrong_final), "truthful status token")
        reordered = self.headless.replace(
            "initializer-handler-100e85d0=effect-free-complete",
            "initializer-handler-100e85d0=late",
            1,
        )
        self.assert_finding(gate.inspect_headless_text(reordered), "100e85d0")
        missing_87a0 = self.headless.replace(
            "initializer-handler-100e87a0=injected-transcript-complete",
            "initializer-handler-100e87a0=not-linked", 1,
        )
        self.assert_finding(
            gate.inspect_headless_text(missing_87a0), "truthful status token"
        )
        stale_fallback = self.headless + (
            "\nstatic const unsigned stale_fallback = 0x600000b1;\n"
        )
        self.assert_finding(
            gate.inspect_headless_text(stale_fallback), "fail closed"
        )

    def test_cmake_dependency_link_ctest_and_fixture_mutants_fail(self):
        wrong_dependency = self.cmake.replace(
            f"    {gate.LIBRARY}\n    PRIVATE {gate.GUEST32_LIBRARY}",
            f"    {gate.LIBRARY}\n    PRIVATE {gate.ROUTER_LIBRARY}",
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(wrong_dependency), "guest32")
        swapped_tail = self.cmake.replace(
            f"      {gate.ADAPTER_85D0_LIBRARY}\n      {gate.LIBRARY}",
            f"      {gate.LIBRARY}\n      {gate.ADAPTER_85D0_LIBRARY}",
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(swapped_tail), "exact headless link tail")
        no_runtime = self.cmake.replace(
            "NAME startup_100e8580_handler_transcript_runtime",
            "NAME startup_100e8580_handler_transcript_runtime_missing",
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(no_runtime), "runtime")
        wrong_predecessor = self.cmake.replace(
            "startup_100e85d0_normal_adapter_reload_verified;"
            "startup_100e8580_handler_transcript_provenance_verified",
            "startup_100e8d00_handler_transcript_reload_verified;"
            "startup_100e8580_handler_transcript_provenance_verified",
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(wrong_predecessor), "fixture-chain")
        wrong_terminal = self.cmake.replace(
            "entry_policy_static_verified;"
            "startup_100ed471_ordinary_lifecycle_reload_verified",
            "entry_policy_static_verified;"
            "startup_100e8580_handler_transcript_reload_verified",
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(wrong_terminal), "headless_bounded")
        missing_87a0 = self.cmake.replace(
            "      " + gate.HANDLER_87A0_LIBRARY + "\n", "", 1
        )
        self.assert_finding(
            gate.inspect_cmake_text(missing_87a0), "outer, 9340, 92c0, 87a0"
        )

    def test_build_testing_escape_and_export_escape_are_rejected(self):
        escaped = self.cmake + f"\nadd_library({gate.LIBRARY} STATIC escaped.c)\n"
        self.assert_finding(gate.inspect_cmake_text(escaped), "escapes BUILD_TESTING")
        for payload in (self.export_manifest, self.legacy_def, self.probe_def):
            mutant = payload + "\n" + gate.FUNCTION + "\n"
            self.assert_finding(gate.inspect_exports_text(mutant), "escaped exports")


    def test_suffix_and_platform_prefix_terminal_composition_mutants_fail(self):
        suffix_token = "startup-100df270-suffix=injected-transcript-complete"
        prefix_token = (
            "startup-100df270-platform-prefix=injected-call-shape-complete"
        )
        ordered_tokens = (
            '        "' + suffix_token + ';"\n'
            '        "' + prefix_token + ';"'
        )
        reversed_tokens = (
            '        "' + prefix_token + ';"\n'
            '        "' + suffix_token + ';"'
        )
        ordered_links = (
            "      " + gate.SUFFIX_LIBRARY + "\n"
            "      " + gate.PREFIX_LIBRARY + "\n"
        )
        reversed_links = (
            "      " + gate.PREFIX_LIBRARY + "\n"
            "      " + gate.SUFFIX_LIBRARY + "\n"
        )
        def replace_last(text: str, old: str, new: str) -> str:
            before, separator, after = text.rpartition(old)
            self.assertEqual(separator, old)
            return before + new + after

        missing_prefix_link = replace_last(
            self.cmake, "      " + gate.PREFIX_LIBRARY + "\n", ""
        )
        missing_suffix_link = replace_last(
            self.cmake, "      " + gate.SUFFIX_LIBRARY + "\n", ""
        )
        reversed_headless_links = replace_last(
            self.cmake, ordered_links, reversed_links
        )
        cases = (
            (
                self.headless,
                self.headless.replace(
                    gate.PARENT_FUNCTION, gate.SUFFIX_FUNCTION, 1
                ),
                gate.inspect_headless_text,
                "suffix",
            ),
            (
                self.headless,
                self.headless.replace(
                    gate.PARENT_FUNCTION, gate.PREFIX_FUNCTION, 1
                ),
                gate.inspect_headless_text,
                "platform-prefix",
            ),
            (
                self.headless,
                self.headless.replace(
                    suffix_token, "startup-100df270-suffix=not-linked", 1
                ),
                gate.inspect_headless_text,
                suffix_token,
            ),
            (
                self.headless,
                self.headless.replace(
                    prefix_token,
                    "startup-100df270-platform-prefix=not-linked",
                    1,
                ),
                gate.inspect_headless_text,
                prefix_token,
            ),
            (
                self.headless,
                self.headless.replace(
                    '#include "ported_100df270_platform_prefix_transcript.h"',
                    '#include "removed_platform_prefix_transcript.h"',
                    1,
                ),
                gate.inspect_headless_text,
                "include",
            ),
            (
                self.headless,
                self.headless.replace(ordered_tokens, reversed_tokens, 1),
                gate.inspect_headless_text,
                "token",
            ),
            (
                self.cmake,
                missing_prefix_link,
                gate.inspect_cmake_text,
                "exact headless",
            ),
            (
                self.cmake,
                missing_suffix_link,
                gate.inspect_cmake_text,
                "exact headless",
            ),
            (
                self.cmake,
                reversed_headless_links,
                gate.inspect_cmake_text,
                "exact headless",
            ),
            (
                self.cmake,
                self.cmake.replace(
                    "entry_policy_static_verified;"
                    "startup_100ed471_ordinary_lifecycle_reload_verified",
                    "entry_policy_static_verified;"
                    "startup_100df270_suffix_transcript_reload_verified",
                    1,
                ),
                gate.inspect_cmake_text,
                "fixture",
            ),
            (
                self.cmake,
                self.cmake.replace("add_test(", "removed_test(", 1),
                gate.inspect_cmake_text,
                "194",
            ),
        )
        for original, mutant, inspector, fragment in cases:
            with self.subTest(fragment=fragment):
                self.assertNotEqual(mutant, original)
                self.assert_finding(inspector(mutant), fragment)

if __name__ == "__main__":
    unittest.main(verbosity=2)

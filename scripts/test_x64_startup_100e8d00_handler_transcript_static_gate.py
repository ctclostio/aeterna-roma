#!/usr/bin/env python3
"""Reciprocal mutants for the bounded 0x100e8d00 transcript gate."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
GATE_PATH = SCRIPTS / "x64_startup_100e8d00_handler_transcript_static_gate.py"
SPEC = importlib.util.spec_from_file_location(
    "handler_transcript_static_gate", GATE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load handler-transcript static gate")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


def future_headless() -> str:
    return read("port/x64_headless/headless_main.c")


def future_cmake() -> str:
    return read("CMakeLists.txt")
    links = "\n".join("      " + library for library in gate.HEADLESS_LINK_LIBRARIES)
    return f'''if(BUILD_TESTING)
  add_library(
    {gate.LIBRARY}
    STATIC
      "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e8d00_handler_transcript.h"
      "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e8d00_handler_transcript.c"
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
  set_property(
    TARGET {gate.LIBRARY}
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    {gate.TEST_TARGET}
    "${{ROME2_GUEST32_RUNTIME_DIR}}/test_startup_100e8d00_handler_transcript.c"
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
    NAME startup_100e8d00_handler_transcript_provenance
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e8d00_handler_transcript_provenance.py"
  )
  add_test(
    NAME startup_100e8d00_handler_transcript_static_gate_unit
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e8d00_handler_transcript_static_gate.py"
  )
  add_test(
    NAME startup_100e8d00_handler_transcript_static_gate
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/x64_startup_100e8d00_handler_transcript_static_gate.py"
      --header "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e8d00_handler_transcript.h"
      --source "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e8d00_handler_transcript.c"
      --test "${{ROME2_GUEST32_RUNTIME_DIR}}/test_startup_100e8d00_handler_transcript.c"
      --transcript-provenance "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e8d00_handler_transcript_provenance.py"
      --headless "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_headless/headless_main.c"
      --cmake "${{CMAKE_CURRENT_SOURCE_DIR}}/CMakeLists.txt"
      --export-manifest "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e8d00_handler_transcript_runtime
    COMMAND "$<TARGET_FILE:{gate.TEST_TARGET}>"
  )
  add_test(
    NAME startup_100e8d00_handler_transcript_post_pe_gate
    COMMAND Python3::Interpreter post_pe.py
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e8d00_handler_transcript
    COMMAND "$<TARGET_FILE:empire_bootstrap_smoke>"
  )

  set_tests_properties(
    startup_100e8d00_handler_transcript_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e8d00_handler_transcript_provenance_verified
  )
  set_tests_properties(
    startup_100e8d00_handler_transcript_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e8d00_handler_transcript_static_tool_verified
  )
  set_tests_properties(
    startup_100e8d00_handler_transcript_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e8d00_handler_transcript_static_tool_verified
      FIXTURES_SETUP startup_100e8d00_handler_transcript_static_verified
  )
  set_tests_properties(
    startup_100e8d00_handler_transcript_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e2460_router_reload_verified;startup_100e8d00_handler_transcript_provenance_verified;startup_100e8d00_handler_transcript_static_verified"
      FIXTURES_SETUP startup_100e8d00_handler_transcript_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e8d00_handler_transcript_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e8d00_handler_transcript_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e8d00_handler_transcript_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e8d00_handler_transcript
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e8d00_handler_transcript_post_verified"
      FIXTURES_SETUP startup_100e8d00_handler_transcript_reload_verified
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


class Startup100e8d00HandlerTranscriptStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read("port/x64_ported/ported_100e8d00_handler_transcript.h")
        cls.source = read("port/x64_ported/ported_100e8d00_handler_transcript.c")
        cls.test = read("port/x64_runtime/test_startup_100e8d00_handler_transcript.c")
        cls.provenance = read_bytes(
            "scripts/test_x64_startup_100e8d00_handler_transcript_provenance.py"
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

    def test_future_combined_containment_contract_passes(self):
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_header_constants_typed_order_and_api_mutants_fail(self):
        wrong_count = self.header.replace("UINT32_C(6)", "UINT32_C(5)", 1)
        self.assert_finding(gate.inspect_header_text(wrong_count), "step count")
        swapped_enum = self.header.replace(
            "ROME2_100E8D00_STEP_CALL_10115D40 = 2",
            "ROME2_100E8D00_STEP_CALL_10115D40 = 3",
            1,
        )
        self.assert_finding(gate.inspect_header_text(swapped_enum), "six-step order")
        pointer_step = self.header.replace(
            "rome2_100e8d00_step step);", "const rome2_100e8d00_step *step);", 1
        )
        self.assert_finding(
            gate.inspect_header_text(pointer_step), "by-value typed callback"
        )
        optional_output = self.header.replace(
            "uint8_t *return_al_out", "uint8_t return_al_out", 1
        )
        self.assert_finding(
            gate.inspect_header_text(optional_output), "public transcript API"
        )

    def test_header_total_snapshot_and_opaque_contract_mutants_fail(self):
        reentrant = self.header.replace(
            "total and nonreentrant", "partial and reentrant", 1
        )
        self.assert_finding(
            gate.inspect_header_text(reentrant), "safety/effect contract"
        )
        no_snapshot = self.header.replace(
            "snapshots both callback", "uses the live callback", 1
        )
        self.assert_finding(
            gate.inspect_header_text(no_snapshot), "safety/effect contract"
        )
        nonzero_only = self.header.replace(
            "32-bit pattern is accepted", "nonzero pattern is accepted", 1
        )
        self.assert_finding(
            gate.inspect_header_text(nonzero_only), "safety/effect contract"
        )

    def test_source_object_range_and_alias_mutants_fail(self):
        weak_overflow = self.source.replace(
            "size > UINTPTR_MAX - start", "size >= UINTPTR_MAX - start", 1
        )
        self.assert_finding(
            gate.inspect_source_text(weak_overflow), "numeric-span validation"
        )
        no_alias = self.source.replace(
            "if (rome2_100e8d00_ranges_overlap(",
            "if (!rome2_100e8d00_ranges_overlap(",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(no_alias), "validation/snapshot stage"
        )
        accepts_null_context = self.source.replace(
            "effects_snapshot.context == NULL",
            "effects_snapshot.context != NULL",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(accepts_null_context), "validation/snapshot stage"
        )

    def test_source_snapshot_before_effect_mutants_fail(self):
        line = "    effects_snapshot = *effects;\n"
        delayed = self.source.replace(line, "", 1).replace(
            "    step.kind = ROME2_100E8D00_STEP_CALL_10115D40;",
            line + "\n    step.kind = ROME2_100E8D00_STEP_CALL_10115D40;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(delayed), "snapshot must precede"
        )
        live_callback = self.source.replace(
            "effects_snapshot.emit_step(effects_snapshot.context, step);",
            "effects->emit_step(effects->context, step);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(live_callback), "typed effect 1"
        )

    def test_source_six_effect_order_and_argument_mutants_fail(self):
        wrong_first_argument = self.source.replace(
            "step.argument1 = UINT32_C(1);",
            "step.argument1 = UINT32_C(0);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_first_argument), "typed effect 1"
        )
        wrong_identity = self.source.replace(
            "ROME2_PORT_100E8D00_PRE_DB_APP_INIT_IDENTITY",
            "UINT32_C(0)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_identity), "typed effect 3"
        )
        missing_sixth = self.source.replace(
            "    effects_snapshot.emit_step(effects_snapshot.context, step);\n\n"
            "    *return_al_out = ROME2_PORT_100E8D00_AL;",
            "    *return_al_out = ROME2_PORT_100E8D00_AL;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(missing_sixth), "exactly six"
        )

    def test_source_al_order_and_opaque_inputs_mutants_fail(self):
        early_al = self.source.replace(
            "    step.kind = ROME2_100E8D00_STEP_CALL_10CB6160;",
            "    *return_al_out = ROME2_PORT_100E8D00_AL;\n\n"
            "    step.kind = ROME2_100E8D00_STEP_CALL_10CB6160;",
            1,
        ).replace(
            "\n    *return_al_out = ROME2_PORT_100E8D00_AL;\n"
            "    return ROME2_GUEST_OK;",
            "\n    return ROME2_GUEST_OK;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(early_al), "only after the sixth"
        )
        inspect_receiver = self.source.replace(
            "    (void)guest_receiver;",
            "    if (guest_receiver.value == 0) { return ROME2_GUEST_BAD_ARGUMENT; }",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(inspect_receiver), "must not be inspected"
        )

    def test_native_platform_allocation_and_guest_cast_mutants_fail(self):
        for identifier in ("malloc", "HeapAlloc", "PeekMessageW", "GetProcAddress"):
            with self.subTest(identifier=identifier):
                mutant = self.source + f"\nvoid bad(void) {{ {identifier}(0); }}\n"
                self.assert_finding(
                    gate.inspect_source_text(mutant),
                    f"forbidden allocation/platform identifier: {identifier}",
                )
        guest_cast = self.source.replace(
            "    (void)guest_argument;",
            "    void *native = (void *)guest_argument; (void)native;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(guest_cast), "native pointer"
        )

    def test_runtime_typed_order_and_arguments_mutants_fail(self):
        wrong_first = self.test.replace(
            "ROME2_100E8D00_STEP_CALL_10CB6160,\n        UINT32_C(2),",
            "ROME2_100E8D00_STEP_CALL_10CB6160,\n        UINT32_C(1),",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(wrong_first), "typed effect oracle 1"
        )
        swapped = self.test.replace(
            "ROME2_100E8D00_STEP_CALL_10115D40,",
            "ROME2_100E8D00_STEP_CALL_112DC9F0,",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(swapped), "typed effect oracle 2"
        )
        wrong_identity = self.test.replace(
            "ROME2_100E8D00_STEP_CALL_112DC9F0,\n"
            "        UINT32_C(2),\n"
            "        UINT32_C(0x1173fb44)",
            "ROME2_100E8D00_STEP_CALL_112DC9F0,\n"
            "        UINT32_C(2),\n"
            "        UINT32_C(0x1173fb40)",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(wrong_identity), "typed effect oracle 3"
        )

    def test_runtime_snapshot_al_and_validation_mutants_fail(self):
        no_decoy = self.test.replace(
            "trace->effects.context = &trace->decoy_context;", "", 1
        )
        self.assert_finding(
            gate.inspect_test_text(no_decoy), "snapshot oracle"
        )
        early_al_allowed = self.test.replace(
            "*trace->return_al != ROME2_TEST_SENTINEL",
            "*trace->return_al == ROME2_TEST_SENTINEL",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(early_al_allowed), "AL-after-sixth"
        )
        missing_alias = self.test.replace('"effects/output alias"', '"no alias"', 1)
        self.assert_finding(
            gate.inspect_test_text(missing_alias), "effects/output alias"
        )
        narrowed_inputs = self.test.replace(
            '        "zero/max opaque identities",\n'
            "        rome2_test_guest(UINT32_C(0)),\n"
            "        rome2_test_guest(UINT32_MAX));",
            '        "zero/max opaque identities",\n'
            "        rome2_test_guest(UINT32_C(1)),\n"
            "        rome2_test_guest(UINT32_C(2)));",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(narrowed_inputs), "opaque all-bit"
        )

    def test_provenance_body_calls_arguments_and_policy_mutants_fail(self):
        changed_body = self.provenance.replace(
            b"721c0a9b4df58497dd3362758ecbb2f73be24e5223bbad3faf01b3442811b3fe",
            b"021c0a9b4df58497dd3362758ecbb2f73be24e5223bbad3faf01b3442811b3fe",
            1,
        )
        findings = gate.inspect_provenance_bytes(changed_body)
        self.assert_finding(findings, "authority digest changed")
        self.assert_finding(findings, "machine/canonical authority changed")
        fewer_calls = self.provenance.replace(
            b"CALL_OFFSETS = (4, 11, 23, 30, 37, 45)",
            b"CALL_OFFSETS = (4, 11, 23, 30, 37)",
            1,
        )
        self.assert_finding(
            gate.inspect_provenance_bytes(fewer_calls), "authority digest changed"
        )
        false_policy = self.provenance.replace(
            b"Nothing here authorizes native linkage",
            b"Everything here authorizes native linkage",
            1,
        )
        self.assert_finding(
            gate.inspect_provenance_bytes(false_policy), "policy boundary"
        )

    def test_headless_combined_calls_checks_and_tokens_mutants_fail(self):
        no_transcript = self.headless.replace(gate.FUNCTION, "removed_transcript", 1)
        self.assert_finding(
            gate.inspect_headless_text(no_transcript), "call-site count changed"
        )
        no_adapter = self.headless.replace(
            gate.NORMAL_ADAPTER_FUNCTION, "removed_adapter", 1
        )
        self.assert_finding(
            gate.inspect_headless_text(no_adapter), "call-site count changed"
        )
        weak_count = self.headless.replace(
            "router_effect_context.handler_8d00_context.observed_steps !=\n"
            "            ROME2_PORT_100E8D00_STEP_COUNT",
            "router_effect_context.handler_8d00_context.observed_steps !=\n"
            "            UINT32_C(0)",
            1,
        ).replace(
            "outer_effect_context.handler_8d00_context.observed_steps !=\n"
            "            ROME2_PORT_100E8D00_STEP_COUNT",
            "outer_effect_context.handler_8d00_context.observed_steps !=\n"
            "            UINT32_C(0)",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(weak_count), "six-effect transcript count"
        )
        missing_final_token = self.headless.replace(
            "initializer-handler-100e8580=injected-transcript-complete",
            "initializer-handler-100e8580=not-linked",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(missing_final_token),
            "initializer-handler-100e8580=injected-transcript-complete",
        )
        missing_87a0_token = self.headless.replace(
            "initializer-handler-100e87a0=injected-transcript-complete",
            "initializer-handler-100e87a0=not-linked", 1,
        )
        self.assert_finding(
            gate.inspect_headless_text(missing_87a0_token),
            "initializer-handler-100e87a0=injected-transcript-complete",
        )
        stale_fallback = self.headless + (
            "\nstatic const unsigned stale_fallback = 0x600000b1;\n"
        )
        self.assert_finding(
            gate.inspect_headless_text(stale_fallback), "fail closed"
        )

    def test_cmake_static_no_dependency_and_consumers_mutants_fail(self):
        shared = self.cmake.replace(
            gate.LIBRARY + "\n    STATIC", gate.LIBRARY + "\n    SHARED", 1
        )
        self.assert_finding(gate.inspect_cmake_text(shared), "static library")
        dependency = self.cmake.replace(
            "  set_property(\n    TARGET " + gate.LIBRARY,
            "  target_link_libraries(\n    " + gate.LIBRARY
            + "\n    PRIVATE " + gate.ROUTER_LIBRARY + "\n  )\n"
            "  set_property(\n    TARGET " + gate.LIBRARY,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(dependency), "no link dependencies"
        )
        extra_consumer = self.cmake.replace(
            "  add_executable(\n    " + gate.TEST_TARGET,
            "  target_link_libraries(empire_retail_bootstrap PRIVATE "
            + gate.LIBRARY + ")\n  add_executable(\n    " + gate.TEST_TARGET,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(extra_consumer), "unexpected consumer"
        )

    def test_cmake_combined_link_tail_and_8580_mutants_fail(self):
        missing_8580 = self.cmake.replace(
            "      " + gate.FINAL_TRANSCRIPT_LIBRARY + "\n", "", 1
        )
        self.assert_finding(
            gate.inspect_cmake_text(missing_8580), "outer, 9340, 92c0, 87a0"
        )
        reordered_8580 = self.cmake.replace(
            "      " + gate.NORMAL_ADAPTER_LIBRARY + "\n"
            "      " + gate.FINAL_TRANSCRIPT_LIBRARY,
            "      " + gate.FINAL_TRANSCRIPT_LIBRARY + "\n"
            "      " + gate.NORMAL_ADAPTER_LIBRARY,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(reordered_8580), "outer, 9340, 92c0, 87a0"
        )
        missing_transcript = self.cmake.replace("      " + gate.LIBRARY + "\n", "", 1)
        findings = gate.inspect_cmake_text(missing_transcript)
        self.assert_finding(findings, "unexpected consumer")
        self.assert_finding(findings, "outer, 9340, 92c0, 87a0")
        missing_outer = self.cmake.replace(
            "      " + gate.OUTER_INITIALIZER_LIBRARY + "\n", "", 1
        )
        self.assert_finding(
            gate.inspect_cmake_text(missing_outer),
            "outer, 9340, 92c0, 87a0",
        )
        reordered_outer = self.cmake.replace(
            "      " + gate.FINAL_TRANSCRIPT_LIBRARY + "\n"
            "      " + gate.OUTER_INITIALIZER_LIBRARY,
            "      " + gate.OUTER_INITIALIZER_LIBRARY + "\n"
            "      " + gate.FINAL_TRANSCRIPT_LIBRARY,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(reordered_outer),
            "outer, 9340, 92c0, 87a0",
        )
        missing_87a0 = self.cmake.replace(
            "      " + gate.HANDLER_87A0_LIBRARY + "\n", "", 1
        )
        self.assert_finding(
            gate.inspect_cmake_text(missing_87a0), "outer, 9340, 92c0, 87a0"
        )
        stale_tail = self.cmake.replace(
            "      " + gate.HANDLER_92C0_LIBRARY + "\n"
            "      " + gate.HANDLER_87A0_LIBRARY,
            "      " + gate.HANDLER_87A0_LIBRARY + "\n"
            "      " + gate.HANDLER_92C0_LIBRARY,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(stale_tail), "outer, 9340, 92c0, 87a0"
        )

    def test_cmake_cli_ctest_and_fixture_mutants_fail(self):
        no_provenance_arg = self.cmake.replace(
            '      --transcript-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
            'test_x64_startup_100e8d00_handler_transcript_provenance.py"\n',
            "",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(no_provenance_arg), "static-gate argument"
        )
        missing_post = self.cmake.replace(
            "NAME startup_100e8d00_handler_transcript_post_pe_gate",
            "NAME removed_handler_post_pe_gate",
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(missing_post), "CTest missing")
        stale_predecessor = self.cmake.replace(
            "startup_100e2460_router_reload_verified;"
            "startup_100e8d00_handler_transcript_provenance_verified",
            "startup_100e2460_growth_branch_reload_verified;"
            "startup_100e8d00_handler_transcript_provenance_verified",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(stale_predecessor), "fixture-chain block"
        )
        stale_terminal = self.cmake.replace(
            "entry_policy_static_verified;"
            "startup_100ed471_ordinary_lifecycle_reload_verified\"",
            "entry_policy_static_verified;"
            "startup_100ea4d0_injected_reload_verified\"",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(stale_terminal), "fixture-chain block"
        )

    def test_export_escape_is_rejected(self):
        for token in (
            gate.FUNCTION, gate.LIBRARY,
            "ported_100e8d00_handler_transcript.h",
        ):
            with self.subTest(token=token):
                self.assertTrue(gate.inspect_exports_text("ordinal\t" + token + "\n"))
        self.assertEqual(gate.inspect_exports_text("ordinal\tentry_point\n"), [])


    def test_suffix_and_platform_prefix_terminal_composition_mutants_fail(self):
        suffix_token = "startup-100df270-suffix=injected-transcript-complete"
        prefix_token = (
            "startup-100df270-platform-prefix=injected-call-shape-complete"
        )
        lifecycle_token = (
            "startup-100ed471-ordinary-lifecycle=injected-bounded-complete"
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
        missing_lifecycle_link = replace_last(
            self.cmake,
            "      rome2_startup_100ed471_ordinary_lifecycle_runtime\n",
            "",
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
                "call-site count",
            ),
            (
                self.headless,
                self.headless.replace(
                    gate.LIFECYCLE_FUNCTION, gate.PREFIX_FUNCTION, 1
                ),
                gate.inspect_headless_text,
                "call-site count",
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
                    lifecycle_token,
                    "startup-100ed471-ordinary-lifecycle=not-linked",
                    1,
                ),
                gate.inspect_headless_text,
                lifecycle_token,
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
                missing_lifecycle_link,
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
                "192",
            ),
        )
        for original, mutant, inspector, fragment in cases:
            with self.subTest(fragment=fragment):
                self.assertNotEqual(mutant, original)
                self.assert_finding(inspector(mutant), fragment)

if __name__ == "__main__":
    unittest.main(verbosity=2)

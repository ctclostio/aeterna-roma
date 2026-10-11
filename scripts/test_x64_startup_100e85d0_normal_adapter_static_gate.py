#!/usr/bin/env python3
"""Reciprocal mutants for the effect-free 0x100e85d0 static gate."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
GATE_PATH = SCRIPTS / "x64_startup_100e85d0_normal_adapter_static_gate.py"
SPEC = importlib.util.spec_from_file_location("normal_adapter_static_gate", GATE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load normal-adapter static gate")
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
      "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e85d0_normal_adapter.h"
      "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e85d0_normal_adapter.c"
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
    "${{ROME2_GUEST32_RUNTIME_DIR}}/test_startup_100e85d0_normal_adapter.c"
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
    NAME startup_100e85d0_normal_adapter_provenance
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e85d0_normal_adapter_provenance.py"
  )
  add_test(
    NAME startup_100e85d0_normal_adapter_static_gate_unit
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e85d0_normal_adapter_static_gate.py"
  )
  add_test(
    NAME startup_100e85d0_normal_adapter_static_gate
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/x64_startup_100e85d0_normal_adapter_static_gate.py"
      --header "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e85d0_normal_adapter.h"
      --source "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e85d0_normal_adapter.c"
      --test "${{ROME2_GUEST32_RUNTIME_DIR}}/test_startup_100e85d0_normal_adapter.c"
      --adapter-provenance "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e85d0_normal_adapter_provenance.py"
      --headless "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_headless/headless_main.c"
      --cmake "${{CMAKE_CURRENT_SOURCE_DIR}}/CMakeLists.txt"
      --export-manifest "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e85d0_normal_adapter_runtime
    COMMAND "$<TARGET_FILE:{gate.TEST_TARGET}>"
  )
  add_test(
    NAME startup_100e85d0_normal_adapter_post_pe_gate
    COMMAND Python3::Interpreter post_pe.py
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e85d0_normal_adapter
    COMMAND "$<TARGET_FILE:empire_bootstrap_smoke>"
  )

  set_tests_properties(
    startup_100e85d0_normal_adapter_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e85d0_normal_adapter_provenance_verified
  )
  set_tests_properties(
    startup_100e85d0_normal_adapter_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e85d0_normal_adapter_static_tool_verified
  )
  set_tests_properties(
    startup_100e85d0_normal_adapter_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e85d0_normal_adapter_static_tool_verified
      FIXTURES_SETUP startup_100e85d0_normal_adapter_static_verified
  )
  set_tests_properties(
    startup_100e85d0_normal_adapter_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e8d00_handler_transcript_reload_verified;startup_100e85d0_normal_adapter_provenance_verified;startup_100e85d0_normal_adapter_static_verified"
      FIXTURES_SETUP startup_100e85d0_normal_adapter_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e85d0_normal_adapter_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e85d0_normal_adapter_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e85d0_normal_adapter_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e85d0_normal_adapter
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e85d0_normal_adapter_post_verified"
      FIXTURES_SETUP startup_100e85d0_normal_adapter_reload_verified
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


class Startup100e85d0NormalAdapterStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read("port/x64_ported/ported_100e85d0_normal_adapter.h")
        cls.source = read("port/x64_ported/ported_100e85d0_normal_adapter.c")
        cls.test = read("port/x64_runtime/test_startup_100e85d0_normal_adapter.c")
        cls.provenance = read_bytes(
            "scripts/test_x64_startup_100e85d0_normal_adapter_provenance.py"
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

    def test_future_containment_contract_passes(self):
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_header_api_al_and_opaque_contract_mutants_fail(self):
        wrong_al = self.header.replace("UINT8_C(1)", "UINT8_C(0)", 1)
        self.assert_finding(gate.inspect_header_text(wrong_al), "exactly one")
        optional_output = self.header.replace(
            "uint8_t *return_al_out", "uint8_t return_al_out", 1
        )
        self.assert_finding(
            gate.inspect_header_text(optional_output), "public adapter API"
        )
        narrowed_identity = self.header.replace(
            "every guest32 bit", "every nonzero guest32 bit", 1
        )
        self.assert_finding(
            gate.inspect_header_text(narrowed_identity), "identity contract"
        )

    def test_source_null_failure_and_al_commit_mutants_fail(self):
        no_null_guard = self.source.replace(
            "if (return_al_out == NULL)", "if (return_al_out != NULL)", 1
        )
        self.assert_finding(
            gate.inspect_source_text(no_null_guard), "null-fail-closed"
        )
        wrong_status = self.source.replace(
            "return ROME2_GUEST_BAD_ARGUMENT;", "return ROME2_GUEST_OK;", 1
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_status), "effect-free adapter body"
        )
        wrong_al = self.source.replace(
            "ROME2_PORT_100E85D0_NORMAL_AL", "UINT8_C(0)", 1
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_al), "adapter body changed"
        )

    def test_source_identity_inspection_and_effect_mutants_fail(self):
        identity_check = self.source.replace(
            "    (void)guest_receiver;",
            "    if (guest_receiver.value == 0) { return ROME2_GUEST_BAD_ARGUMENT; }",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(identity_check), "must not be inspected"
        )
        state_effect = self.source + "\nstatic void callback(void *context) { (void)context; }\n"
        findings = gate.inspect_source_text(state_effect)
        self.assert_finding(findings, "effect/callback state")
        helper_link = self.source + "\nstatic int recovered_100d6560;\n"
        self.assert_finding(
            gate.inspect_source_text(helper_link), "helper must be elided"
        )

    def test_native_platform_and_guest_cast_mutants_fail(self):
        for identifier in ("malloc", "HeapAlloc", "PeekMessageW", "GetProcAddress"):
            with self.subTest(identifier=identifier):
                mutant = self.source + f"\nvoid bad(void) {{ {identifier}(0); }}\n"
                self.assert_finding(
                    gate.inspect_source_text(mutant),
                    f"forbidden allocation/platform identifier: {identifier}",
                )
        guest_cast = self.source.replace(
            "    (void)guest_receiver;",
            "    void *native = (void *)guest_receiver; (void)native;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(guest_cast), "native pointer"
        )

    def test_runtime_all_bit_identity_mutants_fail(self):
        missing_zero = self.test.replace(
            '{"both identities null", UINT32_C(0), UINT32_C(0)},', "", 1
        )
        self.assert_finding(
            gate.inspect_test_text(missing_zero), "both identities null"
        )
        signed_high = self.test.replace(
            "UINT32_C(0x80000000)", "UINT32_C(0x7fffffff)", 1
        )
        self.assert_finding(
            gate.inspect_test_text(signed_high), "receiver high-bit"
        )
        no_all_bits = self.test.replace("UINT32_MAX, UINT32_MAX", "1, 1", 1)
        self.assert_finding(
            gate.inspect_test_text(no_all_bits), "all-bit identity oracle"
        )

    def test_runtime_output_failure_and_bounded_mutants_fail(self):
        weak_al = self.test.replace(
            "guard.output != UINT8_C(1)", "guard.output == UINT8_C(0)", 1
        )
        self.assert_finding(gate.inspect_test_text(weak_al), "exact AL=1")
        no_guard = self.test.replace(
            "guard.before != UINT8_C(0x3c)", "guard.before == UINT8_C(0x3c)", 1
        )
        self.assert_finding(gate.inspect_test_text(no_guard), "output guard")
        accepts_null = self.test.replace(
            "status == ROME2_GUEST_BAD_ARGUMENT", "status == ROME2_GUEST_OK", 1
        )
        self.assert_finding(
            gate.inspect_test_text(accepts_null), "null-output fail-closed"
        )
        unbounded = self.test.replace(
            "iteration < UINT32_C(65536)", "iteration != UINT32_MAX", 1
        )
        self.assert_finding(
            gate.inspect_test_text(unbounded), "bounded repeatability"
        )

    def test_provenance_body_noop_and_policy_mutants_fail(self):
        changed_body = self.provenance.replace(
            b"6a00e889dffeff83c404b001c20400",
            b"6a00e889dffeff83c404b000c20400",
            1,
        )
        findings = gate.inspect_provenance_bytes(changed_body)
        self.assert_finding(findings, "authority digest changed")
        self.assert_finding(findings, "machine/canonical authority changed")
        changed_noop = self.provenance.replace(
            b'NOOP_BYTES = bytes.fromhex("c3")',
            b'NOOP_BYTES = bytes.fromhex("90")',
            1,
        )
        self.assert_finding(
            gate.inspect_provenance_bytes(changed_noop), "authority digest changed"
        )
        false_link_policy = self.provenance.replace(
            b"or authorize linking either recovered address into the port",
            b"and authorize linking either recovered address into the port",
            1,
        )
        self.assert_finding(
            gate.inspect_provenance_bytes(false_link_policy), "policy boundary"
        )

    def test_headless_call_check_and_token_mutants_fail(self):
        wrong_include = self.headless.replace(
            '#include "ported_100e85d0_normal_adapter.h"',
            '#include "ported_100e2460_router.h"',
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(wrong_include), "include order"
        )
        dropped_capture = self.headless.replace(
            "handler_status = " + gate.FUNCTION,
            gate.FUNCTION,
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(dropped_capture), "captured twice"
        )
        weak_check = self.headless.replace(
            "handler_al != ROME2_PORT_100E85D0_NORMAL_AL",
            "handler_al == UINT8_C(0)",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(weak_check), "status and exact AL"
        )
        false_token = self.headless.replace(
            "initializer-handler-100e85d0=effect-free-complete",
            "initializer-handler-100e85d0=not-linked",
            1,
        )
        findings = gate.inspect_headless_text(false_token)
        self.assert_finding(findings, "effect-free-complete")
        self.assert_finding(findings, "falsely claims")
        missing_87a0 = self.headless.replace(
            "initializer-handler-100e87a0=injected-transcript-complete",
            "initializer-handler-100e87a0=not-linked", 1,
        )
        self.assert_finding(
            gate.inspect_headless_text(missing_87a0),
            "initializer-handler-100e87a0=injected-transcript-complete",
        )
        stale_fallback = self.headless + (
            "\nstatic const unsigned stale_fallback = 0x600000b1;\n"
        )
        self.assert_finding(
            gate.inspect_headless_text(stale_fallback), "fail closed"
        )

    def test_cmake_static_no_dependency_and_consumer_mutants_fail(self):
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
            gate.inspect_cmake_text(dependency), "must have no link dependencies"
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

    def test_cmake_link_order_and_build_testing_escape_mutants_fail(self):
        reversed_tail = self.cmake.replace(
            "      " + gate.TRANSCRIPT_LIBRARY + "\n      " + gate.LIBRARY,
            "      " + gate.LIBRARY + "\n      " + gate.TRANSCRIPT_LIBRARY,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(reversed_tail), "outer, 9340, 92c0, 87a0"
        )
        missing_headless = self.cmake.replace("      " + gate.LIBRARY + "\n", "", 1)
        findings = gate.inspect_cmake_text(missing_headless)
        self.assert_finding(findings, "unexpected consumer")
        self.assert_finding(findings, "outer, 9340, 92c0, 87a0")
        missing_final = self.cmake.replace(
            "      " + gate.FINAL_TRANSCRIPT_LIBRARY + "\n", "", 1
        )
        self.assert_finding(
            gate.inspect_cmake_text(missing_final), "outer, 9340, 92c0, 87a0"
        )
        reordered_final = self.cmake.replace(
            "      " + gate.LIBRARY + "\n      " + gate.FINAL_TRANSCRIPT_LIBRARY,
            "      " + gate.FINAL_TRANSCRIPT_LIBRARY + "\n      " + gate.LIBRARY,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(reordered_final), "outer, 9340, 92c0, 87a0"
        )
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
        escaped = self.cmake + "\n# " + gate.LIBRARY + "\n"
        self.assert_finding(
            gate.inspect_cmake_text(escaped), "escapes BUILD_TESTING"
        )

    def test_cmake_cli_ctest_and_fixture_mutants_fail(self):
        no_provenance_arg = self.cmake.replace(
            '      --adapter-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
            'test_x64_startup_100e85d0_normal_adapter_provenance.py"\n',
            "",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(no_provenance_arg), "static-gate argument"
        )
        missing_post = self.cmake.replace(
            "NAME startup_100e85d0_normal_adapter_post_pe_gate",
            "NAME removed_adapter_post_pe_gate",
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(missing_post), "CTest missing")
        stale_predecessor = self.cmake.replace(
            "startup_100e8d00_handler_transcript_reload_verified;"
            "startup_100e85d0_normal_adapter_provenance_verified",
            "startup_100e2460_router_reload_verified;"
            "startup_100e85d0_normal_adapter_provenance_verified",
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
            gate.FUNCTION, gate.LIBRARY, "ported_100e85d0_normal_adapter.h"
        ):
            with self.subTest(token=token):
                self.assertTrue(gate.inspect_exports_text("ordinal\t" + token + "\n"))
        self.assertEqual(gate.inspect_exports_text("ordinal\tentry_point\n"), [])


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
                "192",
            ),
        )
        for original, mutant, inspector, fragment in cases:
            with self.subTest(fragment=fragment):
                self.assertNotEqual(mutant, original)
                self.assert_finding(inspector(mutant), fragment)

if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Reciprocal mutants for the injected 0x100ea4d0 static gate."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
GATE_PATH = SCRIPTS / "x64_startup_100ea4d0_injected_static_gate.py"
SPEC = importlib.util.spec_from_file_location("outer_injected_static_gate", GATE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load injected outer static gate")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


def future_headless() -> str:
    return read("port/x64_headless/headless_main.c")
    tokens = ";".join(
        gate.HEADLESS_COMPLETION_TOKENS + gate.HEADLESS_SAFETY_TOKENS
    )
    return f'''#include "ported_100e2460_router.h"
#include "ported_100e8d00_handler_transcript.h"
#include "ported_100e85d0_normal_adapter.h"
#include "ported_100e8580_handler_transcript.h"
#include "ported_100ea4d0_injected.h"
#include <stdint.h>
#include <stdio.h>

int main(void)
{{
    rome2_guest_write_view state_view;
    rome2_guest_read_view vtable_view;
    rome2_guest_addr32 receiver = {{UINT32_C(1)}};
    rome2_100e2460_growth_effects router_effects;
    rome2_100e8d00_transcript_effects effects_8d00;
    rome2_100e8580_transcript_effects effects_8580;
    rome2_100ea4d0_effects outer_effects;
    rome2_guest_status handler_status;
    rome2_100e2460_branch_status router_status;
    rome2_100ea4d0_status outer_status;
    uint8_t al = UINT8_C(1);

    router_status = {gate.ROUTER_FUNCTION}(
        &state_view, &vtable_view, receiver, receiver, receiver,
        &router_effects, UINT32_C(1), &al);
    handler_status = {gate.HANDLER_8D00_FUNCTION}(
        receiver, receiver, &effects_8d00, &al);
    handler_status = {gate.HANDLER_85D0_FUNCTION}(receiver, receiver, &al);
    handler_status = {gate.HANDLER_8580_FUNCTION}(
        receiver, receiver, &effects_8580, &al);
    handler_status = {gate.HANDLER_8D00_FUNCTION}(
        receiver, receiver, &effects_8d00, &al);
    handler_status = {gate.HANDLER_85D0_FUNCTION}(receiver, receiver, &al);
    handler_status = {gate.HANDLER_8580_FUNCTION}(
        receiver, receiver, &effects_8580, &al);
    outer_status = {gate.FUNCTION}(
        &state_view, &vtable_view, receiver, &outer_effects, UINT32_C(1));
    if (outer_status != ROME2_100EA4D0_OK) {{
        return 1;
    }}
    (void)router_status;
    (void)handler_status;
    puts("{tokens}");
    return 0;
}}
'''


def future_cmake() -> str:
    return read("CMakeLists.txt")
    links = "\n".join("      " + library for library in gate.HEADLESS_LINK_LIBRARIES)
    return f'''if(BUILD_TESTING)
  add_library(
    {gate.LIBRARY}
    STATIC
      "${{ROME2_GUEST32_PORTED_DIR}}/ported_100ea4d0_injected.h"
      "${{ROME2_GUEST32_PORTED_DIR}}/ported_100ea4d0_injected.c"
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
    PRIVATE {gate.ROUTER_LIBRARY}
  )
  set_property(
    TARGET {gate.LIBRARY}
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    {gate.TEST_TARGET}
    "${{ROME2_GUEST32_RUNTIME_DIR}}/test_startup_100ea4d0_injected.c"
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
    NAME startup_100ea4d0_executable_provenance
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100ea4d0_executable_provenance.py"
  )
  add_test(
    NAME startup_100ea4d0_injected_static_gate_unit
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100ea4d0_injected_static_gate.py"
  )
  add_test(
    NAME startup_100ea4d0_injected_static_gate
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/x64_startup_100ea4d0_injected_static_gate.py"
      --header "${{ROME2_GUEST32_PORTED_DIR}}/ported_100ea4d0_injected.h"
      --source "${{ROME2_GUEST32_PORTED_DIR}}/ported_100ea4d0_injected.c"
      --test "${{ROME2_GUEST32_RUNTIME_DIR}}/test_startup_100ea4d0_injected.c"
      --executable-provenance "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100ea4d0_executable_provenance.py"
      --evidence-provenance "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100ea4d0_evidence_provenance.py"
      --headless "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_headless/headless_main.c"
      --cmake "${{CMAKE_CURRENT_SOURCE_DIR}}/CMakeLists.txt"
      --export-manifest "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100ea4d0_injected_runtime
    COMMAND "$<TARGET_FILE:{gate.TEST_TARGET}>"
  )
  add_test(
    NAME startup_100ea4d0_injected_post_pe_gate
    COMMAND Python3::Interpreter post_pe.py
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100ea4d0_injected
    COMMAND "$<TARGET_FILE:empire_bootstrap_smoke>"
  )

  set_tests_properties(
    startup_100ea4d0_executable_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100ea4d0_executable_provenance_verified
  )
  set_tests_properties(
    startup_100ea4d0_injected_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100ea4d0_injected_static_tool_verified
  )
  set_tests_properties(
    startup_100ea4d0_injected_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100ea4d0_injected_static_tool_verified
      FIXTURES_SETUP startup_100ea4d0_injected_static_verified
  )
  set_tests_properties(
    startup_100ea4d0_injected_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e8580_handler_transcript_reload_verified;startup_100ea4d0_executable_provenance_verified;startup_100ea4d0_injected_static_verified"
      FIXTURES_SETUP startup_100ea4d0_injected_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100ea4d0_injected_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100ea4d0_injected_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100ea4d0_injected_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100ea4d0_injected
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100ea4d0_injected_post_verified"
      FIXTURES_SETUP startup_100ea4d0_injected_reload_verified
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


class Startup100ea4d0InjectedStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read("port/x64_ported/ported_100ea4d0_injected.h")
        cls.source = read("port/x64_ported/ported_100ea4d0_injected.c")
        cls.test = read("port/x64_runtime/test_startup_100ea4d0_injected.c")
        cls.executable_provenance = read_bytes(
            "scripts/test_x64_startup_100ea4d0_executable_provenance.py"
        )
        cls.evidence_provenance = read_bytes(
            "scripts/test_x64_startup_100ea4d0_evidence_provenance.py"
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
        self.assertEqual(
            gate.inspect_executable_provenance_bytes(self.executable_provenance), []
        )
        self.assertEqual(
            gate.inspect_evidence_provenance_bytes(self.evidence_provenance), []
        )
        self.assertEqual(gate.inspect_exports_text(self.export_manifest), [])
        self.assertEqual(gate.inspect_exports_text(self.legacy_def), [])
        self.assertEqual(gate.inspect_exports_text(self.probe_def), [])

    def test_future_final_containment_contract_passes(self):
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_header_counts_offsets_status_and_api_mutants_fail(self):
        five = self.header.replace("REGISTRATION_COUNT UINT32_C(6)",
                                   "REGISTRATION_COUNT UINT32_C(5)", 1)
        self.assert_finding(gate.inspect_header_text(five), "registration count")
        wrong_offset = self.header.replace("UINT32_C(0x854)", "UINT32_C(0x850)", 1)
        self.assert_finding(gate.inspect_header_text(wrong_offset), "vector offset")
        no_graph_status = self.header.replace(
            "ROME2_100EA4D0_HANDLER_GRAPH_CORRUPTED = 8",
            "ROME2_100EA4D0_HANDLER_GRAPH_CORRUPTED = 7",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(no_graph_status), "status/commit contract"
        )
        no_budget = self.header.replace(
            "uint32_t max_peek_calls);", "void);", 1
        )
        self.assert_finding(gate.inspect_header_text(no_budget), "public outer API")

    def test_header_effects_snapshot_alias_and_commit_contract_mutants_fail(self):
        smaller_effects = self.header.replace(
            "rome2_100e2460_growth_effects router_effects;",
            "rome2_100e2460_effects router_effects;",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(smaller_effects), "effects layout"
        )
        live_effects = self.header.replace(
            "complete effects object is snapshotted",
            "complete effects object remains live",
            1,
        )
        self.assert_finding(
            gate.inspect_header_text(live_effects), "safety/commit contract"
        )
        rollback = self.header.replace(
            "Effects are prefix-committing", "Effects are rolled back", 1
        )
        self.assert_finding(
            gate.inspect_header_text(rollback), "safety/commit contract"
        )

    def test_source_validation_derivation_and_snapshot_mutants_fail(self):
        accepts_zero_budget = self.source.replace(
            "if (max_peek_calls == 0)", "if (max_peek_calls == UINT32_MAX)", 1
        )
        self.assert_finding(
            gate.inspect_source_text(accepts_zero_budget), "validation/derivation stage"
        )
        unchecked_vector = self.source.replace(
            "UINT32_MAX - ROME2_PORT_100EA4D0_VECTOR_OFFSET",
            "UINT32_MAX",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(unchecked_vector), "validation/derivation stage"
        )
        live_allocator = self.source.replace(
            "allocate_handler = effects_snapshot.allocate_handler;",
            "allocate_handler = effects->allocate_handler;",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(live_allocator), "validation/derivation stage"
        )
        check_before_snapshot = self.source.replace(
            "    effects_snapshot = *effects;\n"
            "    allocate_handler = effects_snapshot.allocate_handler;\n"
            "    allocation_context = effects_snapshot.allocation_context;\n"
            "    if (allocate_handler == NULL) {",
            "    if (effects->allocate_handler == NULL) {",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(check_before_snapshot), "snapshot order"
        )

    def test_source_allocation_backing_and_alias_mutants_fail(self):
        wrong_size = self.source.replace(
            "ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_BYTES,\n"
            "            ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_CLASS);",
            "UINT32_C(8),\n            ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_CLASS);",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_size), "handler allocation call"
        )
        narrow_backing = self.source.replace(
            "(uint64_t)capacity * UINT64_C(4)", "UINT64_C(4)", 1
        )
        self.assert_finding(
            gate.inspect_source_text(narrow_backing), "capacity-sized backing"
        )
        no_argument_alias = self.source.replace(
            "rome2_100ea4d0_mapped_spans_alias(handler, argument) ||", "0 ||", 1
        )
        self.assert_finding(
            gate.inspect_source_text(no_argument_alias), "alias envelope"
        )
        no_earlier_alias = self.source.replace(
            "for (index = 0; index < earlier_count; ++index)",
            "for (index = earlier_count; index < earlier_count; ++index)",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(no_earlier_alias), "earlier-handler alias"
        )

    def test_source_store_router_audit_and_status_order_mutants_fail(self):
        wrong_vtable = self.source.replace(
            "UINT32_C(0x1173f214)", "UINT32_C(0x1173f20c)", 1
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_vtable), "six-vtable order"
        )
        live_router_effects = self.source.replace(
            "&effects_snapshot.router_effects", "&effects->router_effects", 1
        )
        self.assert_finding(
            gate.inspect_source_text(live_router_effects), "pre-effect snapshot"
        )
        no_graph_audit = self.source.replace(
            "if (!rome2_100ea4d0_handler_graph_is_exact(",
            "if (rome2_100ea4d0_handler_graph_is_exact(",
            1,
        )
        self.assert_finding(
            gate.inspect_source_text(no_graph_audit), "handler graph audit"
        )
        accepts_zero = self.source.replace("if (router_al == 0)",
                                           "if (router_al != 0)", 1)
        self.assert_finding(
            gate.inspect_source_text(accepts_zero), "zero-AL failure"
        )

    def test_native_allocator_platform_original_and_guest_cast_mutants_fail(self):
        for identifier in ("malloc", "HeapAlloc", "PeekMessageW", "GetProcAddress"):
            with self.subTest(identifier=identifier):
                mutant = self.source + f"\nvoid bad(void) {{ {identifier}(0); }}\n"
                self.assert_finding(
                    gate.inspect_source_text(mutant),
                    f"forbidden native allocation/platform identifier: {identifier}",
                )
        original = self.source + "\nstatic int recovered_100d12b0;\n"
        self.assert_finding(
            gate.inspect_source_text(original), "original allocator address"
        )
        guest_cast = self.source.replace(
            "    if (guest_receiver.value == 0) {",
            "    void *native = (void *)guest_receiver;\n"
            "    if (guest_receiver.value == 0) {",
            1,
        )
        self.assert_finding(gate.inspect_source_text(guest_cast), "native pointer")

    def test_runtime_success_trace_and_six_registration_mutants_fail(self):
        five_handlers = self.test.replace("#define ROME2_TEST_HANDLER_COUNT 6",
                                          "#define ROME2_TEST_HANDLER_COUNT 5", 1)
        self.assert_finding(
            gate.inspect_test_text(five_handlers), "six-handler count"
        )
        wrong_trace = self.test.replace(
            "1, 2, 4, 5,\n        1, 2, 3, 4, 5,",
            "1, 2, 4, 5,\n        1, 2, 4, 4, 5,",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(wrong_trace), "effect trace"
        )
        five_dispatches = self.test.replace(
            "fixture.context.dispatch_calls != 6",
            "fixture.context.dispatch_calls != 5",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(five_dispatches), "dispatch count"
        )

    def test_runtime_precommit_and_alias_mutants_fail(self):
        no_null_allocator = self.test.replace(
            '"null outer allocator is precommit"', '"outer allocator accepted"', 1
        )
        self.assert_finding(
            gate.inspect_test_text(no_null_allocator), "null outer allocator"
        )
        no_argument_alias = self.test.replace(
            '"handler allocation aliases argument cell"',
            '"handler allocation misses argument cell"',
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(no_argument_alias), "aliases argument cell"
        )
        no_backing_alias = self.test.replace(
            '"handler allocation aliases active backing"',
            '"handler allocation misses active backing"',
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(no_backing_alias), "aliases active backing"
        )

    def test_runtime_partial_commit_graph_and_zero_al_mutants_fail(self):
        rollback = self.test.replace(
            '"duplicate allocation preserves prior prefix"',
            '"duplicate allocation rolls back prefix"',
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(rollback), "preserves prior prefix"
        )
        no_graph = self.test.replace(
            "ROME2_100EA4D0_HANDLER_GRAPH_CORRUPTED",
            "ROME2_100EA4D0_ROUTER_FAILED",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(no_graph), "handler graph audit coverage"
        )
        no_zero_al = self.test.replace(
            "ROME2_100EA4D0_ROUTER_RETURNED_ZERO",
            "ROME2_100EA4D0_ROUTER_FAILED",
            1,
        )
        self.assert_finding(
            gate.inspect_test_text(no_zero_al), "zero-router-AL coverage"
        )

    def test_executable_and_evidence_provenance_mutants_fail(self):
        changed_authority = self.executable_provenance.replace(
            gate.EXPECTED_EVIDENCE_PROVENANCE_SHA256.encode("ascii"),
            b"0" * 64,
            1,
        )
        findings = gate.inspect_executable_provenance_bytes(changed_authority)
        self.assert_finding(findings, "authority digest changed")
        self.assert_finding(findings, "provenance authority changed")
        false_policy = self.executable_provenance.replace(
            b"does not prove the x64 port's injected callbacks",
            b"fully proves the x64 port's injected callbacks",
            1,
        )
        self.assert_finding(
            gate.inspect_executable_provenance_bytes(false_policy), "policy boundary"
        )
        changed_body = self.evidence_provenance.replace(
            b"582b4c4324650b88f969c1af5fac0dce0d6ffd69e1043ee99d834e6b102c7af3",
            b"0" * 64,
            1,
        )
        self.assert_finding(
            gate.inspect_evidence_provenance_bytes(changed_body),
            "authority digest changed",
        )

    def test_headless_outer_call_four_tokens_and_status_mutants_fail(self):
        no_outer = self.headless.replace(gate.FUNCTION, "removed_outer", 1)
        self.assert_finding(
            gate.inspect_headless_text(no_outer), "call-site count changed"
        )
        unchecked = self.headless.replace(
            "outer_status != ROME2_100EA4D0_OK",
            "outer_status == ROME2_100EA4D0_OK",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(unchecked), "reject a non-OK"
        )
        for token in gate.HEADLESS_COMPLETION_TOKENS:
            with self.subTest(token=token):
                mutant = self.headless.replace(token, token.split("=")[0] + "=not-linked", 1)
                self.assert_finding(
                    gate.inspect_headless_text(mutant), token
                )
        stale_fallback = self.headless + (
            "\nstatic const unsigned stale_fallback = 0x600000b1;\n"
        )
        self.assert_finding(
            gate.inspect_headless_text(stale_fallback), "fail closed"
        )

    def test_cmake_static_router_dependency_and_consumers_mutants_fail(self):
        shared = self.cmake.replace(
            gate.LIBRARY + "\n    STATIC", gate.LIBRARY + "\n    SHARED", 1
        )
        self.assert_finding(gate.inspect_cmake_text(shared), "static library")
        wrong_dependency = self.cmake.replace(
            "    " + gate.LIBRARY + "\n    PRIVATE " + gate.ROUTER_LIBRARY,
            "    " + gate.LIBRARY + "\n    PRIVATE " + gate.HANDLER_8580_LIBRARY,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(wrong_dependency), "depend only on"
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

    def test_cmake_final_link_tail_missing_and_reordered_outer_fail(self):
        missing_outer = self.cmake.replace("      " + gate.LIBRARY + "\n", "", 1)
        findings = gate.inspect_cmake_text(missing_outer)
        self.assert_finding(findings, "unexpected consumer")
        self.assert_finding(findings, "outer, 9340, 92c0, 87a0")
        reordered = self.cmake.replace(
            "      " + gate.HANDLER_8580_LIBRARY + "\n      " + gate.LIBRARY,
            "      " + gate.LIBRARY + "\n      " + gate.HANDLER_8580_LIBRARY,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(reordered), "outer, 9340, 92c0, 87a0"
        )
        missing_handler = self.cmake.replace(
            "      " + gate.HANDLER_85D0_LIBRARY + "\n", "", 1
        )
        self.assert_finding(
            gate.inspect_cmake_text(missing_handler), "outer, 9340, 92c0, 87a0"
        )
        missing_87a0 = self.cmake.replace(
            "      " + gate.HANDLER_87A0_LIBRARY + "\n", "", 1
        )
        self.assert_finding(
            gate.inspect_cmake_text(missing_87a0), "outer, 9340, 92c0, 87a0"
        )
        reordered_successors = self.cmake.replace(
            "      " + gate.HANDLER_92C0_LIBRARY + "\n"
            "      " + gate.HANDLER_87A0_LIBRARY,
            "      " + gate.HANDLER_87A0_LIBRARY + "\n"
            "      " + gate.HANDLER_92C0_LIBRARY,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(reordered_successors),
            "outer, 9340, 92c0, 87a0",
        )

    def test_cmake_cli_ctest_and_final_fixture_mutants_fail(self):
        no_evidence_arg = self.cmake.replace(
            '      --evidence-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
            'test_x64_startup_100ea4d0_evidence_provenance.py"\n',
            "",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(no_evidence_arg), "static-gate argument"
        )
        missing_post = self.cmake.replace(
            "NAME startup_100ea4d0_injected_post_pe_gate",
            "NAME removed_outer_post_pe_gate",
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(missing_post), "CTest missing")
        stale_predecessor = self.cmake.replace(
            "startup_100e8580_handler_transcript_reload_verified;"
            "startup_100ea4d0_executable_provenance_verified",
            "startup_100e85d0_normal_adapter_reload_verified;"
            "startup_100ea4d0_executable_provenance_verified",
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
            gate.FUNCTION, gate.LIBRARY, "ported_100ea4d0_injected.h"
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

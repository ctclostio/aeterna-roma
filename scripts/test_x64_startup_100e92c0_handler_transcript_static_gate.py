#!/usr/bin/env python3
"""Reciprocal mutants for the bounded 0x100e92c0 transcript gate."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import x64_startup_100e92c0_handler_transcript_static_gate as gate  # noqa: E402


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


def future_headless() -> str:
    return read("port/x64_headless/headless_main.c")
    return r'''
#include "ported_100e2460_router.h"
#include "ported_100e8d00_handler_transcript.h"
#include "ported_100e85d0_normal_adapter.h"
#include "ported_100e8580_handler_transcript.h"
#include "ported_100e9340_handler_transcript.h"
#include "ported_100e92c0_handler_transcript.h"
#include "ported_100e87a0_handler_transcript.h"
#include "ported_100ea4d0_injected.h"

#define ROME2_HEADLESS_92C0_FIRST_LOW UINT32_C(0x11223344)
#define ROME2_HEADLESS_92C0_SECOND_LOW UINT32_C(0x55667788)
#define ROME2_HEADLESS_92C0_SECOND_HIGH UINT32_C(0x99aabbcc)

typedef struct rome2_headless_92c0_effect_context {
    uint8_t *return_al;
    uint32_t observed_steps;
    uint32_t bad_observations;
} rome2_headless_92c0_effect_context;

typedef struct rome2_headless_composed_context {
    uint32_t handler_92c0_calls;
    uint32_t bad_observations;
    rome2_100e92c0_transcript_effects handler_92c0_effects;
    rome2_headless_92c0_effect_context handler_92c0_context;
} rome2_headless_composed_context;

static const rome2_100e92c0_step rome2_headless_92c0_steps[
    ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT] = {
    {
        ROME2_100E92C0_STEP_CALL_100D6970,
        0, 0, 0, 0, 0,
        0, 0, 0,
        0, 0, 0, 0
    },
    {
        ROME2_100E92C0_STEP_CALL_10FDE370,
        0, 0, 0, 0, 0,
        1, 1, 0,
        0, 0, 0, 0
    },
    {
        ROME2_100E92C0_STEP_CALL_10FDE9D0,
        0, 0, 0, 0, 0,
        1, 1, 0,
        0, 0, 0, 0
    },
    {
        ROME2_100E92C0_STEP_CALL_10FDE270,
        0, 0, 0, 0, 0,
        2, ROME2_HEADLESS_92C0_FIRST_LOW, 0,
        0, 0, ROME2_HEADLESS_92C0_FIRST_LOW, 0
    },
    {
        ROME2_100E92C0_STEP_CALL_10FDE990,
        0, 0, 0, 0, 0,
        2,
        ROME2_HEADLESS_92C0_SECOND_LOW,
        ROME2_HEADLESS_92C0_SECOND_HIGH,
        ROME2_HEADLESS_92C0_FIRST_LOW,
        0,
        ROME2_HEADLESS_92C0_SECOND_LOW,
        ROME2_HEADLESS_92C0_SECOND_HIGH
    },
    {
        ROME2_100E92C0_STEP_CALL_100D5150,
        4,
        ROME2_HEADLESS_92C0_FIRST_LOW,
        0,
        ROME2_HEADLESS_92C0_SECOND_LOW,
        ROME2_HEADLESS_92C0_SECOND_HIGH,
        0, 0, 0,
        0, 0, 0, 0
    },
};

static void rome2_headless_92c0_emit(
    void *opaque_context,
    rome2_100e92c0_step step)
{
    rome2_headless_92c0_effect_context *context =
        (rome2_headless_92c0_effect_context *)opaque_context;
    const rome2_100e92c0_step *expected;
    uint32_t index = context->observed_steps;
    if (index >= ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT ||
        context->return_al == NULL ||
        *context->return_al != UINT8_C(0xcc)) {
        ++context->bad_observations;
        return;
    }
    expected = &rome2_headless_92c0_steps[index];
    if (step.kind != expected->kind) {
        ++context->bad_observations;
    }
    ++context->observed_steps;
}

static uint8_t rome2_headless_router_dispatch(
    void *opaque_context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 argument)
{
    rome2_headless_composed_context *context =
        (rome2_headless_composed_context *)opaque_context;
    rome2_guest_status handler_status;
    uint8_t handler_al = UINT8_C(0xcc);
    ++context->handler_92c0_calls;
    context->handler_92c0_context.return_al = &handler_al;
    handler_status = rome2_port_100e92c0_run_handler_transcript(
        receiver,
        argument,
        &context->handler_92c0_effects,
        &handler_al);
    context->handler_92c0_context.return_al = NULL;
    if (handler_status != ROME2_GUEST_OK ||
        handler_al != ROME2_PORT_100E92C0_AL ||
        context->handler_92c0_calls != UINT32_C(1)) {
        ++context->bad_observations;
    }
    return handler_al;
}

static uint8_t rome2_headless_outer_dispatch(
    void *opaque_context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 argument)
{
    rome2_headless_composed_context *context =
        (rome2_headless_composed_context *)opaque_context;
    rome2_guest_status handler_status;
    uint8_t handler_al = UINT8_C(0xcc);
    ++context->handler_92c0_calls;
    context->handler_92c0_context.return_al = &handler_al;
    handler_status = rome2_port_100e92c0_run_handler_transcript(
        receiver,
        argument,
        &context->handler_92c0_effects,
        &handler_al);
    context->handler_92c0_context.return_al = NULL;
    if (handler_status != ROME2_GUEST_OK ||
        handler_al != ROME2_PORT_100E92C0_AL ||
        context->handler_92c0_calls != UINT32_C(1)) {
        ++context->bad_observations;
    }
    return handler_al;
}

int main(void)
{
    rome2_headless_composed_context router_effect_context = {0};
    rome2_headless_composed_context outer_effect_context = {0};
    router_effect_context.handler_92c0_effects.emit_step =
        rome2_headless_92c0_emit;
    router_effect_context.handler_92c0_effects.context =
        &router_effect_context.handler_92c0_context;
    router_effect_context.handler_92c0_effects.predicate_10fde370 = UINT32_C(1);
    router_effect_context.handler_92c0_effects.predicate_10fde9d0 = UINT32_C(1);
    router_effect_context.handler_92c0_effects.result_10fde270_low =
        ROME2_HEADLESS_92C0_FIRST_LOW;
    router_effect_context.handler_92c0_effects.result_10fde990_low =
        ROME2_HEADLESS_92C0_SECOND_LOW;
    router_effect_context.handler_92c0_effects.result_10fde990_high =
        ROME2_HEADLESS_92C0_SECOND_HIGH;
    outer_effect_context.handler_92c0_effects.emit_step =
        rome2_headless_92c0_emit;
    outer_effect_context.handler_92c0_effects.context =
        &outer_effect_context.handler_92c0_context;
    outer_effect_context.handler_92c0_effects.predicate_10fde370 = UINT32_C(1);
    outer_effect_context.handler_92c0_effects.predicate_10fde9d0 = UINT32_C(1);
    outer_effect_context.handler_92c0_effects.result_10fde270_low =
        ROME2_HEADLESS_92C0_FIRST_LOW;
    outer_effect_context.handler_92c0_effects.result_10fde990_low =
        ROME2_HEADLESS_92C0_SECOND_LOW;
    outer_effect_context.handler_92c0_effects.result_10fde990_high =
        ROME2_HEADLESS_92C0_SECOND_HIGH;
    if (router_effect_context.handler_92c0_context.observed_steps !=
            ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT ||
        outer_effect_context.handler_92c0_context.observed_steps !=
            ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT) {
        return 1;
    }
    return 0;
}

static const char rome2_headless_status[] =
    "initializer-handler-100e8d00=injected-transcript-complete;"
    "initializer-handler-100e85d0=effect-free-complete;"
    "initializer-handler-100e8580=injected-transcript-complete;"
    "initializer-100ea4d0=injected-complete;"
    "initializer-handler-100e9340=injected-transcript-complete;"
    "initializer-handler-100e92c0=injected-transcript-complete;"
    "initializer-handler-100e87a0=injected-transcript-complete;";
'''


def future_cmake() -> str:
    return read("CMakeLists.txt")
    links = "\n".join("      " + library for library in gate.HEADLESS_LINK_LIBRARIES)
    return f'''if(BUILD_TESTING)
  add_library(
    {gate.LIBRARY}
    STATIC
      "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e92c0_handler_transcript.h"
      "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e92c0_handler_transcript.c"
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
    "${{ROME2_GUEST32_RUNTIME_DIR}}/test_startup_100e92c0_handler_transcript.c"
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
    NAME startup_100e92c0_handler_transcript_provenance
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e92c0_handler_transcript_provenance.py"
  )
  add_test(
    NAME startup_100e92c0_handler_transcript_static_gate_unit
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e92c0_handler_transcript_static_gate.py"
  )
  add_test(
    NAME startup_100e92c0_handler_transcript_static_gate
    COMMAND Python3::Interpreter -B
      "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/x64_startup_100e92c0_handler_transcript_static_gate.py"
      --header "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e92c0_handler_transcript.h"
      --source "${{ROME2_GUEST32_PORTED_DIR}}/ported_100e92c0_handler_transcript.c"
      --test "${{ROME2_GUEST32_RUNTIME_DIR}}/test_startup_100e92c0_handler_transcript.c"
      --transcript-provenance "${{CMAKE_CURRENT_SOURCE_DIR}}/scripts/test_x64_startup_100e92c0_handler_transcript_provenance.py"
      --headless "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_headless/headless_main.c"
      --cmake "${{CMAKE_CURRENT_SOURCE_DIR}}/CMakeLists.txt"
      --export-manifest "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${{CMAKE_CURRENT_SOURCE_DIR}}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e92c0_handler_transcript_runtime
    COMMAND "$<TARGET_FILE:{gate.TEST_TARGET}>"
  )
  add_test(
    NAME startup_100e92c0_handler_transcript_post_pe_gate
    COMMAND Python3::Interpreter post_pe.py
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e92c0_handler_transcript
    COMMAND "$<TARGET_FILE:empire_bootstrap_smoke>"
  )

  set_tests_properties(
    startup_100e92c0_handler_transcript_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e92c0_handler_transcript_provenance_verified
  )
  set_tests_properties(
    startup_100e92c0_handler_transcript_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e92c0_handler_transcript_static_tool_verified
  )
  set_tests_properties(
    startup_100e92c0_handler_transcript_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e92c0_handler_transcript_static_tool_verified
      FIXTURES_SETUP startup_100e92c0_handler_transcript_static_verified
  )
  set_tests_properties(
    startup_100e92c0_handler_transcript_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "{gate.PREDECESSOR_RELOAD_FIXTURE};startup_100e92c0_handler_transcript_provenance_verified;startup_100e92c0_handler_transcript_static_verified"
      FIXTURES_SETUP startup_100e92c0_handler_transcript_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e92c0_handler_transcript_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e92c0_handler_transcript_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e92c0_handler_transcript_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e92c0_handler_transcript
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e92c0_handler_transcript_post_verified"
      FIXTURES_SETUP startup_100e92c0_handler_transcript_reload_verified
  )
  set_tests_properties(
    startup_100e9340_handler_transcript_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100ea4d0_injected_reload_verified;startup_100e9340_handler_transcript_provenance_verified;startup_100e9340_handler_transcript_static_verified"
      FIXTURES_SETUP startup_100e9340_handler_transcript_runtime_verified
      TIMEOUT 90
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
    headless_bounded_lifecycle
    PROPERTIES
      FIXTURES_REQUIRED
        "entry_policy_provenance_verified;entry_policy_static_verified;{gate.TERMINAL_RELOAD_FIXTURE}"
      TIMEOUT 90
  )
endif()
'''


class Startup100e92c0HandlerTranscriptStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read("port/x64_ported/ported_100e92c0_handler_transcript.h")
        cls.source = read("port/x64_ported/ported_100e92c0_handler_transcript.c")
        cls.test = read("port/x64_runtime/test_startup_100e92c0_handler_transcript.c")
        cls.provenance = read_bytes(
            "scripts/test_x64_startup_100e92c0_handler_transcript_provenance.py"
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

    def test_future_chronological_integration_contract_passes(self):
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])

    def test_header_route_counts_order_and_dependency_layout_mutants_fail(self):
        wrong_count = self.header.replace(
            "ROME2_PORT_100E92C0_SECOND_FALSE_STEP_COUNT UINT32_C(4)",
            "ROME2_PORT_100E92C0_SECOND_FALSE_STEP_COUNT UINT32_C(5)",
            1,
        )
        self.assert_finding(gate.inspect_header_text(wrong_count), "four-step")
        wrong_order = self.header.replace(
            "ROME2_100E92C0_STEP_CALL_10FDE270 = 4",
            "ROME2_100E92C0_STEP_CALL_10FDE270 = 5",
            1,
        )
        self.assert_finding(gate.inspect_header_text(wrong_order), "six-kind order")
        no_local = self.header.replace("uint32_t local_before0;", "", 1)
        self.assert_finding(gate.inspect_header_text(no_local), "local-dependency")
        no_result = self.header.replace("uint32_t result_10fde270_low;", "", 1)
        self.assert_finding(gate.inspect_header_text(no_result), "getter-result effects")
        pointer_step = self.header.replace(
            "rome2_100e92c0_step step", "const rome2_100e92c0_step *step", 1
        )
        self.assert_finding(gate.inspect_header_text(pointer_step), "by-value")

    def test_source_branch_result_dependency_and_publication_mutants_fail(self):
        wrong_first = self.source.replace(
            "effects_snapshot.predicate_10fde370 == UINT32_C(0)",
            "effects_snapshot.predicate_10fde370 != UINT32_C(0)",
            1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_first), "first-false")
        wrong_zero_high = self.source.replace(
            "step.result1 = UINT32_C(0);",
            "step.result1 = effects_snapshot.result_10fde990_high;",
            1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_zero_high), "step 4")
        wrong_dependency = self.source.replace(
            "step.local_before0 = effects_snapshot.result_10fde270_low;",
            "step.local_before0 = UINT32_C(0);",
            1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_dependency), "step 5")
        wrong_final = self.source.replace(
            "effects_snapshot.result_10fde270_low,\n        UINT32_C(0),",
            "UINT32_C(0),\n        effects_snapshot.result_10fde270_low,",
            1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_final), "dependent-result")
        early_output = self.source.replace(
            "    rome2_100e92c0_clear_step(&step);\n"
            "    step.kind = ROME2_100E92C0_STEP_CALL_10FDE990;",
            "    *return_al_out = ROME2_PORT_100E92C0_AL;\n"
            "    rome2_100e92c0_clear_step(&step);\n"
            "    step.kind = ROME2_100E92C0_STEP_CALL_10FDE990;",
            1,
        )
        self.assert_finding(gate.inspect_source_text(early_output), "publish")

    def test_source_snapshot_alias_containment_and_recovered_calls_fail(self):
        live_effect = self.source.replace(
            "step.result0 = effects_snapshot.result_10fde990_low;",
            "step.result0 = effects->result_10fde990_low;",
            1,
        )
        self.assert_finding(gate.inspect_source_text(live_effect), "snapshot")
        no_alignment = self.source.replace(
            "(uintptr_t)effects % _Alignof(rome2_100e92c0_transcript_effects) != 0U ||",
            "0 ||",
            1,
        )
        self.assert_finding(gate.inspect_source_text(no_alignment), "alignment")
        no_alias = self.source.replace(
            "        rome2_100e92c0_ranges_overlap(\n"
            "            effects, sizeof(*effects),",
            "        rome2_100e92c0_ranges_disjoint(\n"
            "            effects, sizeof(*effects),",
            1,
        )
        self.assert_finding(gate.inspect_source_text(no_alias), "alias")
        for identifier in (
            "malloc", "SteamInternal_ContextInit", "TlsSetValue",
            "CoCreateGuid", "GlobalMemoryStatusEx", "GetProcAddress",
        ):
            with self.subTest(identifier=identifier):
                mutant = self.source + f"\nvoid bad(void) {{ {identifier}(0); }}\n"
                self.assert_finding(
                    gate.inspect_source_text(mutant),
                    "forbidden native/Steam/TLS/global/platform",
                )
        original_global = self.source + "\nstatic unsigned DAT_119ef8d7;\n"
        self.assert_finding(gate.inspect_source_text(original_global), "global identifier")
        recovered = self.source + "\nvoid bad(void) { decomp_fn_100d5150(); }\n"
        self.assert_finding(gate.inspect_source_text(recovered), "recovered/native")

    def test_runtime_routes_snapshot_validation_and_alias_mutants_fail(self):
        missing_first = self.test.replace(
            '"first predicate false"', '"first route removed"', 1
        )
        self.assert_finding(gate.inspect_test_text(missing_first), "first-false")
        missing_second = self.test.replace(
            '"second predicate false"', '"second route removed"', 1
        )
        self.assert_finding(gate.inspect_test_text(missing_second), "second-false")
        wrong_local = self.test.replace(
            "trace->expected[index].local_before0 = first_low;",
            "trace->expected[index].local_before0 = UINT32_C(0);",
            1,
        )
        self.assert_finding(gate.inspect_test_text(wrong_local), "shared-local")
        weak_snapshot = self.test.replace(
            "trace->effects.predicate_10fde9d0 = UINT32_C(0);",
            "trace->effects.predicate_10fde9d0 = UINT32_C(1);",
            1,
        )
        self.assert_finding(gate.inspect_test_text(weak_snapshot), "snapshot mutant")
        no_alias = self.test.replace(
            "(uint8_t *)(void *)&trace.effects.result_10fde270_low",
            "&return_al",
            1,
        )
        self.assert_finding(gate.inspect_test_text(no_alias), "alias case")
        no_inactive_invalid = self.test.replace(
            '"wide inactive second predicate"', '"inactive accepted"', 1
        )
        self.assert_finding(
            gate.inspect_test_text(no_inactive_invalid), "inactive malformed"
        )

    def test_provenance_body_branches_getters_vtable_and_data_only_mutants_fail(self):
        text = self.provenance.decode("utf-8")
        wrong_body = text.replace(
            "6a667df2e872494bc91549ca47c5fe87664bfe94737a065b8bd7018154715e6d",
            "0" * 64,
            1,
        ).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_body), "authority marker")
        wrong_branch = text.replace(
            "SECOND_FALSE_BRANCH_OFFSET = 41",
            "SECOND_FALSE_BRANCH_OFFSET = 42",
            1,
        ).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_branch), "authority marker")
        wrong_getter = text.replace(
            "e2e45622dc3e817af4ec90e4af9df774f9d9e3553cee5e1f6dc6a12236d6146a",
            "1" * 64,
            1,
        ).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_getter), "authority marker")
        wrong_vtable = text.replace("0x1173F2EC", "0x1173F2E8", 1).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_vtable), "authority marker")
        executable = (text + "\nimport ctypes\n").encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(executable), "data-only")

    def test_headless_two_calls_results_steps_and_token_mutants_fail(self):
        first_call = self.headless.find(gate.FUNCTION)
        self.assertGreaterEqual(first_call, 0)
        no_router = (
            self.headless[:first_call] + "rome2_port_100e92c0_router_removed" +
            self.headless[first_call + len(gate.FUNCTION):]
        )
        self.assert_finding(
            gate.inspect_headless_text(no_router), "standalone router dispatch"
        )
        last_call = self.headless.rfind(gate.FUNCTION)
        no_outer = (
            self.headless[:last_call] + "rome2_port_100e92c0_outer_removed" +
            self.headless[last_call + len(gate.FUNCTION):]
        )
        self.assert_finding(
            gate.inspect_headless_text(no_outer), "injected outer dispatch"
        )
        wrong_predicate = self.headless.replace(
            "handler_92c0_effects.predicate_10fde9d0 =\n        UINT32_C(1)",
            "handler_92c0_effects.predicate_10fde9d0 =\n        UINT32_C(0)",
            1,
        )
        self.assertNotEqual(wrong_predicate, self.headless)
        self.assert_finding(gate.inspect_headless_text(wrong_predicate), "second-predicate")
        wrong_result = self.headless.replace("0x99aabbcc", "0x99aabbcd", 1)
        self.assert_finding(gate.inspect_headless_text(wrong_result), "second-high")
        wrong_step = self.headless.replace(
            "ROME2_HEADLESS_92C0_FIRST_LOW, 0,\n"
            "        0, 0, ROME2_HEADLESS_92C0_FIRST_LOW, 0",
            "ROME2_HEADLESS_92C0_FIRST_LOW, 1,\n"
            "        0, 0, ROME2_HEADLESS_92C0_FIRST_LOW, 0",
            1,
        )
        self.assert_finding(gate.inspect_headless_text(wrong_step), "zero-high")
        false_token = self.headless.replace(
            "initializer-handler-100e92c0=injected-transcript-complete",
            "initializer-handler-100e92c0=native",
            1,
        )
        self.assert_finding(gate.inspect_headless_text(false_token), "truthful status")

    def test_finalized_87a0_successor_mutants_fail(self):
        missing_include = self.headless.replace(
            '#include "ported_100e87a0_handler_transcript.h"\n', "", 1
        )
        self.assert_finding(
            gate.inspect_headless_text(missing_include), "include order"
        )
        reversed_includes = self.headless.replace(
            '#include "ported_100e92c0_handler_transcript.h"\n'
            '#include "ported_100e87a0_handler_transcript.h"',
            '#include "ported_100e87a0_handler_transcript.h"\n'
            '#include "ported_100e92c0_handler_transcript.h"',
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(reversed_includes), "include order"
        )
        false_successor_token = self.headless.replace(
            "initializer-handler-100e87a0=injected-transcript-complete",
            "initializer-handler-100e87a0=native",
            1,
        )
        self.assert_finding(
            gate.inspect_headless_text(false_successor_token), "truthful status"
        )
        reversed_tokens = self.headless.replace(
            '        "initializer-handler-100e92c0=injected-transcript-complete;"\n'
            '        "initializer-handler-100e87a0=injected-transcript-complete;"',
            '        "initializer-handler-100e87a0=injected-transcript-complete;"\n'
            '        "initializer-handler-100e92c0=injected-transcript-complete;"',
            1,
        )
        self.assertNotEqual(reversed_tokens, self.headless)
        self.assert_finding(
            gate.inspect_headless_text(reversed_tokens),
            "original-order handler/outer token sequence",
        )

        missing_link = self.cmake.replace(
            "      " + gate.HANDLER_87A0_LIBRARY + "\n", "", 1
        )
        self.assert_finding(
            gate.inspect_cmake_text(missing_link), "exact headless tail"
        )
        reversed_links = self.cmake.replace(
            "      " + gate.LIBRARY + "\n      " + gate.HANDLER_87A0_LIBRARY,
            "      " + gate.HANDLER_87A0_LIBRARY + "\n      " + gate.LIBRARY,
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(reversed_links), "exact headless tail"
        )
        stale_terminal = self.cmake.replace(
            "entry_policy_static_verified;" + gate.TERMINAL_RELOAD_FIXTURE,
            "entry_policy_static_verified;"
            "startup_100e92c0_handler_transcript_reload_verified",
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(stale_terminal), "fixture-chain"
        )

    def test_cmake_target_dependency_consumer_and_final_tail_mutants_fail(self):
        shared = self.cmake.replace(
            gate.LIBRARY + "\n    STATIC", gate.LIBRARY + "\n    SHARED", 1
        )
        self.assert_finding(gate.inspect_cmake_text(shared), "static library")
        dependency = self.cmake.replace(
            "  set_property(\n    TARGET " + gate.LIBRARY,
            "  target_link_libraries(\n    " + gate.LIBRARY +
            "\n    PRIVATE " + gate.PREDECESSOR_LIBRARY +
            "\n  )\n  set_property(\n    TARGET " + gate.LIBRARY,
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(dependency), "no link dependencies")
        extra_consumer = self.cmake.replace(
            "  add_executable(\n    " + gate.TEST_TARGET,
            "  target_link_libraries(empire_retail_bootstrap PRIVATE " +
            gate.LIBRARY + ")\n  add_executable(\n    " + gate.TEST_TARGET,
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(extra_consumer), "unexpected consumer")
        reversed_tail = self.cmake.replace(
            "      " + gate.PREDECESSOR_LIBRARY + "\n      " + gate.LIBRARY,
            "      " + gate.LIBRARY + "\n      " + gate.PREDECESSOR_LIBRARY,
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(reversed_tail), "outer, 9340, 92c0")

    def test_cmake_cli_fixture_predecessor_terminal_and_ctest_mutants_fail(self):
        no_provenance_arg = self.cmake.replace(
            '      --transcript-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
            'test_x64_startup_100e92c0_handler_transcript_provenance.py"\n',
            "",
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(no_provenance_arg), "static-gate argument")
        stale_predecessor = self.cmake.replace(
            gate.PREDECESSOR_RELOAD_FIXTURE +
            ";startup_100e92c0_handler_transcript_provenance_verified",
            "startup_100ea4d0_injected_reload_verified;"
            "startup_100e92c0_handler_transcript_provenance_verified",
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(stale_predecessor), "fixture-chain")
        wrong_terminal = self.cmake.replace(
            "entry_policy_static_verified;" + gate.TERMINAL_RELOAD_FIXTURE,
            "entry_policy_static_verified;" + gate.PREDECESSOR_RELOAD_FIXTURE,
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(wrong_terminal), "fixture-chain")
        missing_runtime = self.cmake.replace(
            "NAME startup_100e92c0_handler_transcript_runtime",
            "NAME startup_100e92c0_handler_transcript_runtime_missing",
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(missing_runtime), "runtime")

    def test_build_testing_and_export_escapes_are_rejected(self):
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
                "platform-prefix",
            ),
            (
                self.headless,
                self.headless.replace(
                    gate.LIFECYCLE_FUNCTION, gate.PREFIX_FUNCTION, 1
                ),
                gate.inspect_headless_text,
                "ordinary lifecycle",
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

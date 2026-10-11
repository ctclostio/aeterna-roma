#!/usr/bin/env python3
"""Reciprocal mutants for the 0x100e87a0 transcript containment gate."""

from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import x64_startup_100e87a0_handler_transcript_static_gate as gate


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_bytes(relative: str) -> bytes:
    return (ROOT / relative).read_bytes()


class Startup100e87a0HandlerTranscriptStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read(
            "port/x64_ported/ported_100e87a0_handler_transcript.h"
        )
        cls.source = read(
            "port/x64_ported/ported_100e87a0_handler_transcript.c"
        )
        cls.test = read(
            "port/x64_runtime/test_startup_100e87a0_handler_transcript.c"
        )
        cls.provenance = read_bytes(
            "scripts/test_x64_startup_100e87a0_handler_transcript_provenance.py"
        )
        cls.headless = read("port/x64_headless/headless_main.c")
        cls.cmake = read("CMakeLists.txt")
        cls.export_manifest = read("port/x64_exports/export_manifest.tsv")
        cls.legacy_def = read("port/x64_exports/empire.retail.exports.def")
        cls.probe_def = read("port/x64_probe/probe_exports.def")

    def assert_finding(self, findings: list[str], fragment: str) -> None:
        self.assertTrue(
            any(fragment in finding for finding in findings),
            f"expected finding containing {fragment!r}; got {findings!r}",
        )

    def test_live_payloads_integration_and_export_isolation_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_test_text(self.test), [])
        self.assertEqual(gate.inspect_provenance_bytes(self.provenance), [])
        self.assertEqual(gate.inspect_headless_text(self.headless), [])
        self.assertEqual(gate.inspect_cmake_text(self.cmake), [])
        self.assertEqual(gate.inspect_exports_text(self.export_manifest), [])
        self.assertEqual(gate.inspect_exports_text(self.legacy_def), [])
        self.assertEqual(gate.inspect_exports_text(self.probe_def), [])

    def test_header_identity_status_policy_and_api_mutants_fail(self):
        wrong_size = self.header.replace(
            "ROME2_PORT_100E87A0_LISTENER_BYTES UINT32_C(4)",
            "ROME2_PORT_100E87A0_LISTENER_BYTES UINT32_C(8)", 1,
        )
        self.assert_finding(gate.inspect_header_text(wrong_size), "four-byte")
        wrong_vtable = self.header.replace("0x1173ff28", "0x1173ff2c", 1)
        self.assert_finding(gate.inspect_header_text(wrong_vtable), "vtable identity")
        wrong_status = self.header.replace(
            "ROME2_100E87A0_ALLOCATION_RESULT_INVALID = 5",
            "ROME2_100E87A0_ALLOCATION_RESULT_INVALID = 6", 1,
        )
        self.assert_finding(gate.inspect_header_text(wrong_status), "status mapping")
        missing_policy = self.header.replace("    uint32_t free_identity;\n", "", 1)
        self.assert_finding(gate.inspect_header_text(missing_policy), "five-field policy")
        pointer_policy = self.header.replace(
            "    rome2_100e87a0_memory_policy policy,",
            "    const rome2_100e87a0_memory_policy *policy,", 1,
        )
        self.assert_finding(gate.inspect_header_text(pointer_policy), "callback 3")
        no_view = self.header.replace(
            "    const rome2_guest_write_view *state_view,\n", "", 1,
        )
        self.assert_finding(gate.inspect_header_text(no_view), "public bounded")

    def test_source_effect_order_null_route_and_prefix_mutants_fail(self):
        wrong_class = self.source.replace(
            "ROME2_PORT_100E87A0_ALLOCATION_CLASS);",
            "UINT32_C(1));", 1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_class), "prefix-commit route")
        reversed_null = self.source.replace(
            "if (listener.value != 0)", "if (listener.value == 0)", 1,
        )
        self.assert_finding(gate.inspect_source_text(reversed_null), "prefix-commit route")
        leaked_status = self.source.replace(
            "return ROME2_100E87A0_ALLOCATION_RESULT_INVALID;",
            "return status;", 1,
        )
        self.assert_finding(gate.inspect_source_text(leaked_status), "prefix-commit route")
        early_al = self.source.replace(
            "    effects_snapshot.publish_listener(effects_snapshot.context, listener);",
            "    *return_al_out = ROME2_PORT_100E87A0_AL;\n"
            "    effects_snapshot.publish_listener(effects_snapshot.context, listener);",
            1,
        )
        self.assert_finding(gate.inspect_source_text(early_al), "AL publication count")
        live_effects = self.source.replace(
            "effects_snapshot.publish_listener(effects_snapshot.context, listener);",
            "effects->publish_listener(effects->context, listener);", 1,
        )
        self.assert_finding(gate.inspect_source_text(live_effects), "snapshots")
        no_store = self.source.replace(
            "            ROME2_PORT_100E87A0_LISTENER_VTABLE);",
            "            UINT32_C(0));", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_store), "prefix-commit route")

    def test_source_validation_alias_and_native_escape_mutants_fail(self):
        no_alignment = self.source.replace(
            "(uintptr_t)state_view % _Alignof(rome2_guest_write_view) != 0U ||",
            "0 ||", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_alignment), "alignment")
        no_host_alias = self.source.replace(
            "if (rome2_100e87a0_host_interval_overlaps_controls(\n"
            "            &state_snapshot",
            "if (rome2_100e87a0_host_interval_is_disjoint(\n"
            "            &state_snapshot", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_host_alias), "physical-alias")
        no_overflow = self.source.replace(
            "offset > (uint64_t)SIZE_MAX", "0", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_overflow), "span validation")
        guest_cast = self.source + (
            "\nvoid *bad(rome2_guest_addr32 listener) { return (void *)listener; }\n"
        )
        self.assert_finding(gate.inspect_source_text(guest_cast), "guest identities")
        for identifier in (
            "malloc", "HeapAlloc", "RegOpenKeyExW", "TlsSetValue",
            "GetProcAddress", "CoCreateGuid",
        ):
            with self.subTest(identifier=identifier):
                mutant = self.source + f"\nvoid bad(void) {{ {identifier}(0); }}\n"
                self.assert_finding(
                    gate.inspect_source_text(mutant),
                    "forbidden native/allocator/platform",
                )
        global_escape = self.source + "\nstatic unsigned DAT_119f3858;\n"
        self.assert_finding(gate.inspect_source_text(global_escape), "process-global")
        recovered = self.source + "\nvoid bad(void) { decomp_fn_10ed67a0(); }\n"
        self.assert_finding(gate.inspect_source_text(recovered), "recovered/native")

    def test_runtime_success_null_boundary_snapshot_and_prefix_mutants_fail(self):
        weak_null = self.test.replace(
            "fixture.view.byte_count = UINT64_C(0);",
            "fixture.view.byte_count = UINT64_C(1);", 1,
        )
        self.assert_finding(gate.inspect_test_text(weak_null), "null-allocation")
        weak_boundary = self.test.replace("0xfffffffc", "0xfffffff8", 1)
        self.assert_finding(gate.inspect_test_text(weak_boundary), "address-space end")
        weak_snapshot = self.test.replace(
            "fixture.context.mutate_caller_effects = 1;",
            "fixture.context.mutate_caller_effects = 0;", 1,
        )
        self.assert_finding(gate.inspect_test_text(weak_snapshot), "snapshot mutant")
        weak_result = self.test.replace("UINT32_C(0xfffffffe)", "UINT32_C(0)", 1)
        self.assert_finding(gate.inspect_test_text(weak_result), "four invalid")
        weak_prefix = self.test.replace(
            "fixture.context.publication_calls == UINT32_C(0)",
            "fixture.context.publication_calls == UINT32_C(1)", 1,
        )
        self.assert_finding(gate.inspect_test_text(weak_prefix), "allocation-only prefix")
        no_alias = self.test.replace(
            "(uint8_t *)&fixture.effects", "&fixture.return_al", 1,
        )
        self.assert_finding(gate.inspect_test_text(no_alias), "effects/output alias")
        wrong_marker = self.test.replace("9/9 cases passed", "8/8 cases passed", 1)
        self.assert_finding(gate.inspect_test_text(wrong_marker), "success marker")

    def test_provenance_body_vtables_effects_and_data_only_mutants_fail(self):
        text = self.provenance.decode("utf-8")
        wrong_body = text.replace(
            "0917917b3f65047b219059555acfb913b8cd9f91ccf6908e8295619d0dea710d",
            "0" * 64, 1,
        ).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_body), "authority marker")
        wrong_pair = text.replace("0x1173F2DC", "0x1173F2D8", 1).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_pair), "authority marker")
        wrong_listener = text.replace("0x1173FF28", "0x1173FF2C", 1).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_listener), "authority marker")
        wrong_global = text.replace("0x119F3858", "0x119F385C", 1).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_global), "authority marker")
        wrong_calls = text.replace(
            "DIRECT_CALL_OFFSETS = (6, 50, 85, 96)",
            "DIRECT_CALL_OFFSETS = (6, 50, 84, 96)", 1,
        ).encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(wrong_calls), "authority marker")
        executable = (text + "\nimport ctypes\n").encode("utf-8")
        self.assert_finding(gate.inspect_provenance_bytes(executable), "data-only")

    def test_headless_two_calls_effect_order_wiring_and_tokens_mutants_fail(self):
        first = self.headless.find(gate.FUNCTION)
        no_router = (
            self.headless[:first] + "rome2_port_100e87a0_router_removed" +
            self.headless[first + len(gate.FUNCTION):]
        )
        self.assert_finding(gate.inspect_headless_text(no_router), "standalone router")
        last = self.headless.rfind(gate.FUNCTION)
        no_outer = (
            self.headless[:last] + "rome2_port_100e87a0_outer_removed" +
            self.headless[last + len(gate.FUNCTION):]
        )
        self.assert_finding(gate.inspect_headless_text(no_outer), "injected outer")
        wrong_allocator = self.headless.replace(
            "rome2_headless_87a0_allocate;", "rome2_headless_87a0_publish;", 1,
        )
        self.assert_finding(gate.inspect_headless_text(wrong_allocator), "wiring")
        wrong_order = self.headless.replace(
            "context->startup_calls != UINT32_C(1) ||\n"
            "        context->publish_calls != UINT32_C(1) ||\n"
            "        context->effect_order != UINT32_C(3)",
            "context->startup_calls != UINT32_C(1) ||\n"
            "        context->publish_calls != UINT32_C(1) ||\n"
            "        context->effect_order != UINT32_C(2)", 1,
        )
        self.assert_finding(gate.inspect_headless_text(wrong_order), "FaceFX order")
        wrong_policy = self.headless.replace(
            "ROME2_PORT_100E87A0_POLICY_FREE_IDENTITY",
            "ROME2_PORT_100E87A0_POLICY_ALLOCATE_IDENTITY", 1,
        )
        self.assert_finding(gate.inspect_headless_text(wrong_policy), "typed policy")
        false_token = self.headless.replace(
            "initializer-handler-100e87a0=injected-transcript-complete",
            "initializer-handler-100e87a0=native", 1,
        )
        self.assert_finding(gate.inspect_headless_text(false_token), "truthful status")
        stale_fallback = self.headless + (
            "\nstatic const unsigned bad_fallback = 0x600000b1;\n"
        )
        self.assert_finding(gate.inspect_headless_text(stale_fallback), "fail closed")

    def test_cmake_target_consumers_final_link_and_cli_mutants_fail(self):
        shared = self.cmake.replace(
            gate.LIBRARY + "\n    STATIC", gate.LIBRARY + "\n    SHARED", 1,
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
        self.assert_finding(gate.inspect_cmake_text(reversed_tail), "final link")
        no_argument = self.cmake.replace(
            '      --transcript-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
            'test_x64_startup_100e87a0_handler_transcript_provenance.py"\n',
            "", 1,
        )
        self.assert_finding(gate.inspect_cmake_text(no_argument), "static-gate argument")

    def test_cmake_fixture_terminal_build_testing_and_exports_mutants_fail(self):
        stale_predecessor = self.cmake.replace(
            gate.PREDECESSOR_RELOAD_FIXTURE +
            ";startup_100e87a0_handler_transcript_provenance_verified",
            "startup_100e9340_handler_transcript_reload_verified;"
            "startup_100e87a0_handler_transcript_provenance_verified", 1,
        )
        self.assert_finding(gate.inspect_cmake_text(stale_predecessor), "fixture-chain")
        stale_terminal = self.cmake.replace(
            "entry_policy_static_verified;" + gate.TERMINAL_RELOAD_FIXTURE,
            "entry_policy_static_verified;" + gate.PREDECESSOR_RELOAD_FIXTURE,
            1,
        )
        self.assert_finding(gate.inspect_cmake_text(stale_terminal), "fixture-chain")
        missing_runtime = self.cmake.replace(
            "NAME startup_100e87a0_handler_transcript_runtime",
            "NAME startup_100e87a0_handler_transcript_runtime_missing", 1,
        )
        self.assert_finding(gate.inspect_cmake_text(missing_runtime), "runtime")
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

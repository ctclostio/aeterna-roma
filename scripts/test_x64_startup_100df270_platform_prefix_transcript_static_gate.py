#!/usr/bin/env python3
"""Reciprocal mutants for the 0x100df270 platform-prefix static gate."""

from __future__ import annotations

import pathlib
import re
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import x64_startup_100df270_platform_prefix_transcript_static_gate as gate


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class Startup100df270PlatformPrefixTranscriptStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read(
            "port/x64_ported/ported_100df270_platform_prefix_transcript.h"
        )
        cls.source = read(
            "port/x64_ported/ported_100df270_platform_prefix_transcript.c"
        )
        cls.cmake = read("CMakeLists.txt")
        cls.headless = read("port/x64_headless/headless_main.c")
        cls.export_manifest = read("port/x64_exports/export_manifest.tsv")
        cls.export_contract = read("docs/x64_export_contract.md")
        cls.legacy_def = read("port/x64_exports/empire.retail.exports.def")
        cls.bootstrap_def = read("port/x64_bootstrap/empire_bootstrap.def")
        cls.probe_def = read("port/x64_probe/probe_exports.def")

    def assert_finding(self, findings: list[str], fragment: str) -> None:
        self.assertTrue(
            any(fragment in finding for finding in findings),
            f"expected finding containing {fragment!r}; got {findings!r}",
        )

    def integration_landed(self) -> bool:
        gate_command = (
            "scripts/x64_startup_100df270_platform_prefix_transcript_static_gate.py"
        )
        start = self.cmake.find(gate_command)
        end = self.cmake.find("add_test(", start + len(gate_command))
        invocation = self.cmake[start:end] if start >= 0 and end > start else ""
        return (
            gate.LIBRARY in self.cmake
            and gate.HEADLESS_TOKEN in self.headless
            and "--export-contract" in invocation
            and "--bootstrap-def" in invocation
        )

    def test_live_core_and_all_export_surfaces_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        for payload in (
            self.export_manifest,
            self.export_contract,
            self.legacy_def,
            self.bootstrap_def,
            self.probe_def,
        ):
            self.assertEqual(gate.inspect_exports_text(payload), [])

    def test_live_integration_passes_or_is_explicitly_fail_closed(self):
        cmake_findings = gate.inspect_cmake_text(self.cmake)
        headless_findings = gate.inspect_headless_text(self.headless)
        if self.integration_landed():
            self.assertEqual(cmake_findings, [])
            self.assertEqual(headless_findings, [])
        else:
            self.assert_finding(cmake_findings, "token is missing")
            self.assert_finding(headless_findings, "include is missing")
            self.assert_finding(headless_findings, "completion token")

    def test_header_counts_spans_offsets_and_identity_mutants_fail(self):
        mutants = (
            (self.header.replace(
                "NORMAL_STEP_COUNT UINT32_C(7)",
                "NORMAL_STEP_COUNT UINT32_C(8)", 1,
            ), "seven-step"),
            (self.header.replace(
                "DUPLICATE_STEP_COUNT UINT32_C(10)",
                "DUPLICATE_STEP_COUNT UINT32_C(9)", 1,
            ), "ten-step"),
            (self.header.replace("UINT32_C(0x80c)", "UINT32_C(0x808)", 1),
             "receiver 0x80c"),
            (self.header.replace("UINT32_C(0x2d)", "UINT32_C(0x2c)", 1),
             "packet 0x2d"),
            (self.header.replace("UINT32_C(0x808)", "UINT32_C(0x804)", 1),
             "mutex +0x808"),
            (self.header.replace("UINT32_C(0x1173f208)",
                                 "UINT32_C(0x1173f20c)", 1), "vtable"),
            (self.header.replace("UINT32_C(0x119f3854)",
                                 "UINT32_C(0x119f3858)", 1), "mouse-trails"),
            (self.header.replace("UINT32_C(0xb7)", "UINT32_C(0xb8)", 1),
             "ALREADY_EXISTS"),
        )
        for mutant, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_finding(gate.inspect_header_text(mutant), expected)

    def test_header_typed_values_steps_effects_and_api_mutants_fail(self):
        reversed_steps = self.header.replace(
            "ROME2_100DF270_PREFIX_STEP_LOAD_TITLE = 1,\n"
            "    ROME2_100DF270_PREFIX_STEP_LOAD_NAME = 2,",
            "ROME2_100DF270_PREFIX_STEP_LOAD_NAME = 1,\n"
            "    ROME2_100DF270_PREFIX_STEP_LOAD_TITLE = 2,", 1,
        )
        self.assert_finding(gate.inspect_header_text(reversed_steps), "ten-kind")
        changed_kind = self.header.replace(
            "ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER = 4",
            "ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER = 5", 1,
        )
        self.assert_finding(gate.inspect_header_text(changed_kind), "six-kind")
        pointer_step = self.header.replace(
            "    rome2_100df270_prefix_step step);",
            "    const rome2_100df270_prefix_step *step);", 1,
        )
        self.assert_finding(gate.inspect_header_text(pointer_step), "by-value")
        no_last_error = self.header.replace("    uint32_t last_error;\n", "", 1)
        self.assert_finding(gate.inspect_header_text(no_last_error), "effects layout")
        no_packet = self.header.replace(
            "    rome2_guest_addr32 guest_packet,\n", "", 1
        )
        self.assert_finding(gate.inspect_header_text(no_packet), "public bounded")
        wrong_iat = self.header.replace("0x1172f66c", "0x1172f670", 1)
        self.assert_finding(gate.inspect_header_text(wrong_iat), "iat_loadstringw")

    def test_source_prevalidation_snapshot_checked_add_and_alias_mutants_fail(self):
        mutants = (
            (self.source.replace("    effects_snapshot = *effects;\n", "", 1),
             "effects snapshot"),
            (self.source.replace("    state_snapshot = *state_view;\n", "", 1),
             "state-view snapshot"),
            (self.source.replace(
                "if (rome2_100df270_prefix_backing_overlaps_controls(\n",
                "if (0 && rome2_100df270_prefix_backing_overlaps_controls(\n", 1,
            ), "physical disjointness"),
            (self.source.replace(
                "receiver_span.guest_start,\n            receiver_span.byte_count,\n"
                "            packet_span.guest_start,",
                "receiver_span.guest_start,\n            UINT64_C(0),\n"
                "            packet_span.guest_start,", 1,
            ), "logical disjointness"),
            (self.source.replace(
                "ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET,\n        &guest_title);",
                "ROME2_PORT_100DF270_PREFIX_NAME_OFFSET,\n        &guest_title);", 1,
            ), "+0x408"),
            (self.source.replace(
                "ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET,\n        &guest_mutex);",
                "ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET,\n        &guest_mutex);", 1,
            ), "+0x808"),
            (self.source.replace(
                "effects_snapshot.last_error ==",
                "effects->last_error ==", 1,
            ), "live effects"),
        )
        for mutant, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_finding(gate.inspect_source_text(mutant), expected)

    def test_source_normal_and_duplicate_step_payload_mutants_fail(self):
        wrong_title = self.source.replace(
            "ROME2_PORT_100DF270_PREFIX_RESOURCE_TITLE);",
            "ROME2_PORT_100DF270_PREFIX_RESOURCE_NAME);", 1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_title), "normal-route step payload"
        )
        wrong_kind = self.source.replace(
            "ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY, guest_title.value",
            "ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY, guest_title.value", 1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_kind), "normal-route step payload"
        )
        wrong_create = self.source.replace(
            "ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(1)",
            "ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0)", 1,
        )
        self.assert_finding(
            gate.inspect_source_text(wrong_create), "normal-route step payload"
        )
        weak_branch = self.source.replace(
            "allow_duplicate == UINT8_C(0)",
            "allow_duplicate != UINT8_C(0)", 1,
        )
        self.assert_finding(gate.inspect_source_text(weak_branch), "three-step")
        wrong_caption = self.source.replace(
            "ROME2_PORT_100DF270_PREFIX_MUTEX_CAPTION);",
            "ROME2_PORT_100DF270_PREFIX_MUTEX_FORMAT);", 1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_caption), "three-step")

    def test_source_state_callback_and_output_order_mutants_fail(self):
        initial_block = (
            "    rome2_100df270_prefix_write_u32_le(\n"
            "        state_snapshot.host_base + (size_t)receiver_span.view_offset +\n"
            "            (size_t)ROME2_PORT_100DF270_PREFIX_INSTANCE_OFFSET,\n"
            "        instance_value);\n"
        )
        moved_initial = self.source.replace(initial_block, "", 1).replace(
            "    effects_snapshot.emit_step(effects_snapshot.context, step);\n\n",
            "    effects_snapshot.emit_step(effects_snapshot.context, step);\n\n"
            + initial_block, 1,
        )
        self.assert_finding(
            gate.inspect_source_text(moved_initial), "precede the first callback"
        )

        mutex_block = (
            "    rome2_100df270_prefix_write_u32_le(\n"
            "        state_snapshot.host_base + (size_t)receiver_span.view_offset +\n"
            "            (size_t)ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET,\n"
            "        effects_snapshot.created_mutex);\n\n"
        )
        late_mutex = self.source.replace(mutex_block, "", 1).replace(
            "        effects_snapshot.last_error);\n",
            "        effects_snapshot.last_error);\n" + mutex_block, 1,
        )
        self.assert_finding(
            gate.inspect_source_text(late_mutex), "last-error order"
        )

        final = (
            "    effects_snapshot.emit_step(effects_snapshot.context, step);\n\n"
            "    return_receiver_out->value = guest_receiver.value;"
        )
        early_output = self.source.replace(
            final,
            "    return_receiver_out->value = guest_receiver.value;\n"
            "    effects_snapshot.emit_step(effects_snapshot.context, step);", 1,
        )
        self.assert_finding(gate.inspect_source_text(early_output), "output")

    def test_source_native_string_global_recovered_and_pointer_mutants_fail(self):
        payloads = (
            ("\nvoid bad(void) { LoadStringW(0,0,0,0); }\n", "forbidden native"),
            ("\nvoid bad(void) { malloc(4); }\n", "forbidden native"),
            ("\nstatic const wchar_t bad[] = L\"fabricated\";\n", "strings"),
            ("\nstatic uint32_t bad_process_global;\n", "file-scope"),
            ("\nvoid bad(void) { decomp_fn_100edfe0(); }\n", "recovered/native"),
            ("\nvoid bad(void) { ((void (*)(void))(uintptr_t)0x100edfe0)(); }\n",
             "raw original"),
            ("\nvoid *bad(rome2_guest_addr32 guest) { return (void *)guest.value; }\n",
             "native pointers"),
            ("\nstatic uint32_t DAT_119f3854;\n", "process-global"),
        )
        for payload, expected in payloads:
            with self.subTest(expected=expected):
                self.assert_finding(
                    gate.inspect_source_text(self.source + payload), expected
                )

    def test_cmake_fail_closed_and_post_integration_mutants_fail(self):
        absent = self.cmake.replace(gate.LIBRARY, "removed_prefix_library")
        self.assert_finding(gate.inspect_cmake_text(absent), "token is missing")
        if not self.integration_landed():
            self.skipTest("platform-prefix integration has not landed")

        escaped = self.cmake + f"\nadd_library({gate.LIBRARY} STATIC escaped.c)\n"
        self.assert_finding(gate.inspect_cmake_text(escaped), "BUILD_TESTING")

        dependency = re.compile(
            r"target_link_libraries\s*\(\s*" + re.escape(gate.LIBRARY)
            + r"\s+PUBLIC\s+rome2_guest32_runtime\s*\)", flags=re.S,
        ).search(self.cmake)
        self.assertIsNotNone(dependency)
        assert dependency is not None
        block = dependency.group(0)
        private = (
            self.cmake[:dependency.start()]
            + block.replace("PUBLIC", "PRIVATE", 1)
            + self.cmake[dependency.end():]
        )
        self.assert_finding(gate.inspect_cmake_text(private), "exactly PUBLIC")

        headless_link = next(
            command for command in re.finditer(
                r"target_link_libraries\s*\(\s*rome2_headless64.*?\)",
                self.cmake, flags=re.S,
            ) if gate.LIBRARY in command.group(0)
        )
        link_block = headless_link.group(0)
        wrong_tail = link_block.replace(
            "rome2_startup_100df270_suffix_transcript_runtime\n"
            "      " + gate.LIBRARY,
            gate.LIBRARY + "\n"
            "      rome2_startup_100df270_suffix_transcript_runtime", 1,
        )
        mutant = (
            self.cmake[:headless_link.start()] + wrong_tail
            + self.cmake[headless_link.end():]
        )
        self.assert_finding(gate.inspect_cmake_text(mutant), "final lifecycle")
        missing_parent_consumer = self.cmake.replace(
            "      rome2_startup_100df270_platform_prefix_transcript_runtime\n"
            "  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100ed3c0_empty_preloop_runtime",
            "  )\n"
            "  set_property(\n"
            "    TARGET rome2_startup_100ed3c0_empty_preloop_runtime",
            1,
        )
        self.assertNotEqual(missing_parent_consumer, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(missing_parent_consumer), "empty-preloop parent"
        )

    def test_cmake_fixture_mutants_fail_after_integration(self):
        if not self.integration_landed():
            self.skipTest("platform-prefix integration has not landed")
        runtime_chain = (
            '"' + gate.PREDECESSOR_FIXTURE + ';'
            "startup_100df270_platform_prefix_transcript_provenance_verified;"
            'startup_100df270_platform_prefix_transcript_static_verified"'
        )
        wrong_predecessor = self.cmake.replace(
            runtime_chain,
            runtime_chain.replace(
                gate.PREDECESSOR_FIXTURE,
                "startup_100e87a0_handler_transcript_reload_verified",
            ),
            1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(wrong_predecessor), "follow suffix reload"
        )
        wrong_terminal = self.cmake.replace(
            gate.TERMINAL_FIXTURE,
            "startup_100df270_platform_prefix_transcript_wrong_verified", 1,
        )
        self.assert_finding(
            gate.inspect_cmake_text(wrong_terminal), "terminal reload"
        )
        before, separator, after = self.cmake.rpartition(
            gate.COMPOSED_TERMINAL_FIXTURE
        )
        self.assertEqual(separator, gate.COMPOSED_TERMINAL_FIXTURE)
        stale_composed_terminal = before + gate.TERMINAL_FIXTURE + after
        self.assertNotEqual(stale_composed_terminal, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(stale_composed_terminal), "parent terminal"
        )

    def test_headless_call_token_counts_and_step_oracle_mutants_fail(self):
        if self.integration_landed():
            baseline = self.headless
            self.assertEqual(gate.inspect_headless_text(baseline), [])
        else:
            kinds = "\n".join(f"int x_{index} = {kind};" for index, kind in enumerate(
                gate.STEP_KINDS
            ))
            baseline = (
                '#include "ported_100df270_platform_prefix_transcript.h"\n'
                "void synthetic(void) {\n"
                "  (void)ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT;\n"
                "  (void)ROME2_PORT_100DF270_PREFIX_DUPLICATE_STEP_COUNT;\n"
                f"  {gate.PARENT_FUNCTION}(0, (rome2_guest_addr32){{0}}, "
                "(rome2_guest_addr32){0}, 0, 0);\n"
                f"  {kinds}\n"
                "}\n"
                'const char *tokens = "startup-100df270-suffix='
                'injected-transcript-complete;'
                + gate.HEADLESS_TOKEN + ';'
                'startup-100ed3c0-empty-preloop='
                'injected-composition-complete;";\n'
            )
            self.assertEqual(gate.inspect_headless_text(baseline), [])

        no_call = baseline.replace(gate.PARENT_FUNCTION, "removed_parent_call", 1)
        self.assert_finding(gate.inspect_headless_text(no_call), "parent exactly once")
        direct_child = baseline.replace(
            gate.PARENT_FUNCTION, gate.FUNCTION, 1
        )
        self.assert_finding(gate.inspect_headless_text(direct_child), "child directly")
        wrong_token = baseline.replace(
            gate.HEADLESS_TOKEN,
            "startup-100df270-platform-prefix=wrong", 1,
        )
        self.assert_finding(gate.inspect_headless_text(wrong_token), "completion token")
        no_count = baseline.replace(
            "ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT",
            "REMOVED_NORMAL_COUNT",
        )
        self.assert_finding(gate.inspect_headless_text(no_count), "seven-step")
        no_kind = baseline.replace(gate.STEP_KINDS[9], "REMOVED_SET_KIND")
        self.assert_finding(gate.inspect_headless_text(no_kind), "typed-step")

    def test_final_cmake_count_mutant_fails(self):
        mutant = self.cmake + "\nadd_test(NAME prefix_extra COMMAND false)\n"
        self.assert_finding(gate.inspect_cmake_text(mutant), "must remain 192")

    def test_every_export_surface_rejects_slice_tokens(self):
        for label, payload in (
            ("manifest", self.export_manifest),
            ("contract", self.export_contract),
            ("legacy", self.legacy_def),
            ("bootstrap", self.bootstrap_def),
            ("probe", self.probe_def),
        ):
            with self.subTest(label=label):
                mutant = payload + "\n" + gate.FUNCTION + "\n"
                self.assert_finding(
                    gate.inspect_exports_text(mutant), "escaped exports"
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)

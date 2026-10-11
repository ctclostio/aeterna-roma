#!/usr/bin/env python3
"""Reciprocal mutants for the 0x100ed3c0 empty-preloop static gate."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import x64_startup_100ed3c0_empty_preloop_static_gate as gate


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class Startup100ed3c0EmptyPreloopStaticGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.header = read("port/x64_ported/ported_100ed3c0_empty_preloop.h")
        cls.source = read("port/x64_ported/ported_100ed3c0_empty_preloop.c")
        cls.provenance = read(
            "scripts/test_x64_startup_100ed3c0_preloop_transcript_provenance.py"
        )
        cls.cmake = read("CMakeLists.txt")
        cls.headless = read("port/x64_headless/headless_main.c")
        cls.export_manifest = read("port/x64_exports/export_manifest.tsv")
        cls.export_contract = read("docs/x64_export_contract.md")
        cls.legacy_def = read("port/x64_exports/empire.retail.exports.def")
        cls.bootstrap_def = read("port/x64_bootstrap/empire_bootstrap.def")
        cls.probe_def = read("port/x64_probe/probe_exports.def")
        cls.repro_manifest = read(
            "scripts/x64_reproducible_build_v2_manifest.json"
        )
        cls.repro_verifier = read("scripts/test_x64_reproducible_build_v2.py")

    def assert_finding(self, findings: list[str], fragment: str) -> None:
        self.assertTrue(
            any(fragment in finding for finding in findings),
            f"expected finding containing {fragment!r}; got {findings!r}",
        )

    def integration_landed(self) -> bool:
        command = "scripts/x64_startup_100ed3c0_empty_preloop_static_gate.py"
        start = self.cmake.find(command)
        end = self.cmake.find("add_test(", start + len(command))
        invocation = self.cmake[start:end] if start >= 0 and end > start else ""
        return (
            gate.LIBRARY in self.cmake
            and gate.LIFECYCLE_LIBRARY in self.cmake
            and gate.HEADLESS_TOKEN in self.headless
            and gate.LIFECYCLE_TOKEN in self.headless
            and "--preloop-provenance" in invocation
            and "--repro-manifest" in invocation
            and gate.REPRO_ON in self.repro_manifest
            and gate.REPRO_ON in self.repro_verifier
        )

    def test_live_core_provenance_and_all_export_surfaces_pass(self):
        self.assertEqual(gate.inspect_header_text(self.header), [])
        self.assertEqual(gate.inspect_source_text(self.source), [])
        self.assertEqual(gate.inspect_provenance_text(self.provenance), [])
        for payload in (
            self.export_manifest,
            self.export_contract,
            self.legacy_def,
            self.bootstrap_def,
            self.probe_def,
        ):
            self.assertEqual(gate.inspect_exports_text(payload), [])

    def test_live_integration_and_repro_pass_or_fail_closed(self):
        cmake_findings = gate.inspect_cmake_text(self.cmake)
        headless_findings = gate.inspect_headless_text(self.headless)
        manifest_findings = gate.inspect_repro_manifest_text(self.repro_manifest)
        verifier_findings = gate.inspect_repro_verifier_text(self.repro_verifier)
        if self.integration_landed():
            self.assertEqual(cmake_findings, [])
            self.assertEqual(headless_findings, [])
            self.assertEqual(manifest_findings, [])
            self.assertEqual(verifier_findings, [])
            self.assertEqual(
                gate.inspect_repro_cmake_pin(
                    self.repro_manifest, self.repro_verifier, self.cmake
                ),
                [],
            )
        else:
            self.assertTrue(
                cmake_findings or headless_findings
                or manifest_findings or verifier_findings,
                "partial integration must remain visibly fail closed",
            )

    def test_header_boundary_frame_text_offsets_and_callee_mutants_fail(self):
        mutants = (
            (self.header.replace("UINT32_C(0x100ed3c0)",
                                 "UINT32_C(0x100ed3c4)", 1), "start boundary"),
            (self.header.replace("UINT32_C(0x100ed471)",
                                 "UINT32_C(0x100ed472)", 1), "hard-stop"),
            (self.header.replace("UINT32_C(0x90c)",
                                 "UINT32_C(0x908)", 1), "0x90c"),
            (self.header.replace("PRELOOP_TEXT_UNITS UINT32_C(1)",
                                 "PRELOOP_TEXT_UNITS UINT32_C(2)", 1),
             "max_units=1"),
            (self.header.replace("PRELOOP_STEP_COUNT UINT32_C(9)",
                                 "PRELOOP_STEP_COUNT UINT32_C(8)", 1),
             "nine-operation"),
            (self.header.replace("UINT32_C(0x28)",
                                 "UINT32_C(0x2c)", 1), "descriptor +0x28"),
            (self.header.replace("UINT32_C(0x64)",
                                 "UINT32_C(0x60)", 1), "receiver +0x64"),
            (self.header.replace("UINT32_C(0x100f1bb0)",
                                 "UINT32_C(0x100f1bb4)", 1), "100f1bb0"),
        )
        for mutant, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_finding(gate.inspect_header_text(mutant), expected)

    def test_header_step_effect_result_and_separate_selector_api_mutants_fail(self):
        reversed_steps = self.header.replace(
            "ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET0 = 3,\n"
            "    ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET1 = 4,",
            "ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET1 = 3,\n"
            "    ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET0 = 4,",
            1,
        )
        self.assert_finding(gate.inspect_header_text(reversed_steps), "nine-kind")
        wrong_value = self.header.replace(
            "ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY = 2",
            "ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY = 3",
            1,
        )
        self.assert_finding(gate.inspect_header_text(wrong_value), "six-kind")
        no_prefix = self.header.replace(
            "    rome2_100df270_prefix_effects child_prefix;\n", "", 1
        )
        self.assert_finding(gate.inspect_header_text(no_prefix), "effects layout")
        no_next = self.header.replace("    uint32_t next_original_pc;\n", "", 1)
        self.assert_finding(gate.inspect_header_text(no_next), "result layout")
        no_selector = self.header.replace(
            "    const rome2_guest_write_view *selector_view,\n", "", 1
        )
        self.assert_finding(gate.inspect_header_text(no_selector), "public bounded")

    def test_provenance_boundary_hash_operation_and_exclusion_mutants_fail(self):
        mutants = (
            (self.provenance.replace("PRELOOP_END_VA = 0x100ED471",
                                     "PRELOOP_END_VA = 0x100ED472", 1),
             "hard stop"),
            (self.provenance + "\n", "exact digest"),
            (self.provenance.replace(
                "b9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626",
                "a9f107e7f54c3896399c1a4692ca17580ef266963522a744a3010ddf14a75626",
                1,
            ), "177-byte"),
            (self.provenance.replace('"copy_empty_b_100f1aa0",', "", 1),
             "copy_empty_b"),
            (self.provenance.replace(
                'self.assertNotIn(bytes.fromhex("ff5254"), PRELOOP_BYTES)',
                'self.assertIn(bytes.fromhex("ff5254"), PRELOOP_BYTES)', 1,
            ), "indirect-call exclusion"),
        )
        for mutant, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_finding(gate.inspect_provenance_text(mutant), expected)

    def test_source_exact_frame_text_measure_and_snapshot_mutants_fail(self):
        mutants = (
            (self.source.replace(
                "frame_snapshot.guest_base != guest_frame.value ||",
                "frame_snapshot.guest_base == guest_frame.value ||", 1,
            ), "exact-base"),
            (self.source.replace(
                "text_max_units != ROME2_PORT_100ED3C0_PRELOOP_TEXT_UNITS",
                "text_max_units > ROME2_PORT_100ED3C0_PRELOOP_TEXT_UNITS", 1,
            ), "exactly one"),
            (self.source.replace("    effects_snapshot = *effects;\n", "", 1),
             "source exact digest"),
            (self.source.replace("text_length != UINT32_C(0)",
                                 "text_length == UINT32_C(0)", 1), "nonempty"),
            (self.source.replace(
                "argument_position3_text,\n        text_max_units,",
                "argument_position3_text,\n        ROME2_PORT_100F1BB0_MAX_UNITS,",
                1,
            ), "measurement"),
        )
        for mutant, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_finding(gate.inspect_source_text(mutant), expected)

    def test_source_backing_control_checked_offset_and_selector_mutants_fail(self):
        mutants = (
            (self.source.replace(
                "rome2_100ed3c0_backings_overlap(backings, 3U) ||",
                "0 && rome2_100ed3c0_backings_overlap(backings, 3U) ||", 1,
            ), "pairwise backing"),
            (self.source.replace(
                "private_controls[8].start = (uint64_t)(uintptr_t)&preview_return;",
                "private_controls[8].start = UINT64_C(0);", 1,
            ), "preview output"),
            (self.source.replace(
                "ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET,\n"
                "        &guest_descriptor);",
                "ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET,\n"
                "        &guest_descriptor);", 1,
            ), "source exact digest"),
            (self.source.replace(
                "&selector_snapshot,\n        guest_receiver,",
                "&frame_snapshot,\n        guest_receiver,", 1,
            ), "separate selector"),
            (self.source.replace(
                "&second_selector_span)) {",
                "&first_selector_span)) {", 1,
            ), "disjointness"),
        )
        for mutant, expected in mutants:
            with self.subTest(expected=expected):
                self.assert_finding(gate.inspect_source_text(mutant), expected)

    def test_source_unified_preflight_and_admitted_api_count_mutants_fail(self):
        removed_preview_suffix = self.source.replace(
            "        &selector_preview_view,\n        guest_receiver,",
            "        &frame_preview_view,\n        guest_receiver,", 1,
        )
        self.assert_finding(
            gate.inspect_source_text(removed_preview_suffix), "unified"
        )
        no_triplet = self.source.replace(
            "rome2_port_100f1c10_initialize_triplet(",
            "removed_100f1c10_initialize_triplet(", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_triplet), "triplet")
        no_copy = self.source.replace(
            "rome2_port_100f1aa0_copy_empty_source(",
            "removed_100f1aa0_copy_empty_source(", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_copy), "empty copies")
        no_middle = self.source.replace(
            "rome2_port_100df270_project_headless_empty_state(",
            "removed_100df270_project_headless_empty_state(", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_middle), "child middle")
        no_cleanup = self.source.replace(
            "rome2_port_100f1cc0_accept_nonowning_noop(",
            "removed_100f1cc0_accept_nonowning_noop(", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_cleanup), "cleanup")

    def test_source_nine_parent_step_order_commit_and_hard_stop_mutants_fail(self):
        no_step = self.source.replace(
            "    effects_snapshot.emit_step(effects_snapshot.context, step);\n",
            "", 1,
        )
        self.assert_finding(gate.inspect_source_text(no_step), "nine parent")
        reversed_kinds = self.source.replace(
            "&step, ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY0);",
            "&step, ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY1);", 1,
        )
        self.assert_finding(gate.inspect_source_text(reversed_kinds), "operation")
        early_result = self.source.replace(
            "    result_out->child_receiver = guest_receiver;\n", "", 1
        ).replace(
            "    frame_bytes = (uint8_t *)frame_span.host_start;\n",
            "    result_out->child_receiver = guest_receiver;\n"
            "    frame_bytes = (uint8_t *)frame_span.host_start;\n",
            1,
        )
        self.assert_finding(gate.inspect_source_text(early_result), "commit sequence")
        loop = self.source.replace(
            "    result_out->next_original_pc = ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC;\n"
            "    return ROME2_GUEST_OK;\n}",
            "    result_out->next_original_pc = ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC;\n"
            "    while (0) { }\n"
            "    return ROME2_GUEST_OK;\n}", 1,
        )
        self.assert_finding(gate.inspect_source_text(loop), "straight-line")
        wrong_stop = self.source.replace(
            "ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC;",
            "ROME2_PORT_100ED3C0_PRELOOP_START_PC;", 1,
        )
        self.assert_finding(gate.inspect_source_text(wrong_stop), "hard stop")

    def test_source_native_allocator_recovered_pointer_and_address_mutants_fail(self):
        payloads = (
            ("\nvoid bad(void) { LoadStringW(0,0,0,0); }\n", "forbidden native"),
            ("\nvoid bad(void) { malloc(4); }\n", "forbidden native"),
            ("\nvoid bad(void) { decomp_fn_100ed3c0(); }\n", "recovered/native"),
            ("\nstatic uint32_t DAT_119f31c8;\n", "process-global"),
            ("\nvoid *bad(rome2_guest_addr32 guest) { return (void *)guest.value; }\n",
             "native pointers"),
            ("\nint bad = 0x100ed471;\n", "raw original address"),
        )
        for payload, expected in payloads:
            with self.subTest(expected=expected):
                self.assert_finding(
                    gate.inspect_source_text(self.source + payload), expected
                )

    def test_headless_call_token_oracles_and_no_duplicate_children_mutants_fail(self):
        if self.integration_landed():
            baseline = self.headless
            self.assertEqual(gate.inspect_headless_text(baseline), [])
        else:
            kinds = "\n".join(f"int k_{i} = {kind};" for i, kind in enumerate(
                gate.STEP_KINDS
            ))
            baseline = (
                '#include "ported_100ed3c0_empty_preloop.h"\n'
                '#include "ported_100ed471_ordinary_lifecycle.h"\n'
                "void synthetic(void) {\n"
                " (void)ROME2_PORT_100ED3C0_PRELOOP_STEP_COUNT;\n"
                " (void)ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES;\n"
                " (void)ROME2_PORT_100ED3C0_PRELOOP_TEXT_UNITS;\n"
                " (void)ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC;\n"
                f" {gate.FUNCTION}(0,(rome2_guest_addr32){{0}},0,0,"
                "(rome2_guest_addr32){0},1,0,0,0);\n"
                f" {gate.LIFECYCLE_FUNCTION}(0,(rome2_guest_addr32){{0}},0,"
                "(rome2_guest_addr32){0},1,0,0);\n"
                f" {kinds}\n"
                "}\n"
                'const char *t = "startup-100df270-platform-prefix='
                'injected-call-shape-complete;'
                + gate.HEADLESS_TOKEN + ';' + gate.LIFECYCLE_TOKEN + ';";\n'
            )
            self.assertEqual(gate.inspect_headless_text(baseline), [])
        self.assert_finding(
            gate.inspect_headless_text(baseline.replace(
                gate.FUNCTION, "removed_empty_preloop", 1
            )),
            "exactly once",
        )
        self.assert_finding(
            gate.inspect_headless_text(baseline.replace(
                gate.HEADLESS_TOKEN, "startup-100ed3c0-empty-preloop=wrong", 1
            )),
            "completion token",
        )
        self.assert_finding(
            gate.inspect_headless_text(baseline.replace(
                gate.LIFECYCLE_FUNCTION, "removed_ordinary_lifecycle", 1
            )),
            "ordinary lifecycle exactly once",
        )
        self.assert_finding(
            gate.inspect_headless_text(baseline.replace(
                gate.LIFECYCLE_TOKEN,
                "startup-100ed471-ordinary-lifecycle=wrong",
                1,
            )),
            "lifecycle completion token",
        )
        self.assert_finding(
            gate.inspect_headless_text(baseline.replace(
                gate.STEP_KINDS[-1], "REMOVED_CLEANUP_KIND", 1
            )),
            "typed parent-step",
        )
        duplicate = baseline + "\nvoid bad(void) { " \
            "rome2_port_100df270_run_suffix_transcript(0,0,0,0,0); }\n"
        self.assert_finding(
            gate.inspect_headless_text(duplicate), "must not duplicate"
        )

    def test_repro_manifest_verifier_and_live_cmake_pin_mutants_fail(self):
        cmake = "project(synthetic)\n"
        digest = hashlib.sha256(cmake.encode("utf-8")).hexdigest()
        manifest = json.dumps({
            "build_contract": {"testing_matrix": [
                {"path": "out/x64-bootstrap", "build_testing": True,
                 "external_flag_overrides": False, "verified_hash_pair": True},
                {"path": gate.REPRO_ON, "build_testing": True,
                 "external_flag_overrides": False, "verified_hash_pair": True},
                {"path": gate.REPRO_OFF, "build_testing": False,
                 "external_flag_overrides": False, "verified_hash_pair": True},
            ]},
            "reproducible_v2": {"artifacts": [
                {"role": "dll", "sha256":
                 "ea6eabe0e510ac9593bb4aeac8ae6123dfe050ac08c9f2067115dbef9fd63930",
                 "byte_count": 107520},
                {"role": "host", "sha256":
                 "fdcdb90111cbc0cc5301bccd6f96f15566cefd9be93f9a2714c73d9c02afa320",
                 "byte_count": 144384},
            ]},
            "inputs": [{"path": "CMakeLists.txt", "sha256": digest,
                        "byte_count": len(cmake.encode("utf-8"))}],
        })
        verifier = (
            f'EXPECTED_MATRIX=[("{gate.REPRO_ON}", True, False, True),'
            f'("{gate.REPRO_OFF}", False, False, True)]\n'
            'EXPECTED_V2_CMAKE_TESTS={"startup_100ed3c0_empty_preloop_post_pe_gate"}\n'
            'current_slice_targets=("rome2_startup_100ed3c0_empty_preloop_runtime",'
            '"rome2_startup_100ed3c0_empty_preloop_tests",'
            '"startup_100ed471_ordinary_lifecycle_post_pe_gate",'
            '"rome2_startup_100ed471_ordinary_lifecycle_runtime",'
            '"rome2_startup_100ed471_ordinary_lifecycle_tests")\n'
            f'EXPECTED_INPUTS={{"CMakeLists.txt": ("{digest}", {len(cmake.encode())},)}}\n'
        )
        with (
            mock.patch.object(
                gate, "EXPECTED_REPRO_MANIFEST_BYTES", len(manifest.encode("utf-8"))
            ),
            mock.patch.object(
                gate,
                "EXPECTED_REPRO_MANIFEST_SHA256",
                hashlib.sha256(manifest.encode("utf-8")).hexdigest(),
            ),
        ):
            self.assertEqual(gate.inspect_repro_manifest_text(manifest), [])
            wrong_on = manifest.replace(gate.REPRO_ON, "out/repro-wrong-on", 1)
            self.assert_finding(gate.inspect_repro_manifest_text(wrong_on), "matrix")
            wrong_artifact = manifest.replace("107520", "107521", 1)
            self.assert_finding(
                gate.inspect_repro_manifest_text(wrong_artifact), "production DLL"
            )
        with (
            mock.patch.object(
                gate, "EXPECTED_REPRO_VERIFIER_BYTES", len(verifier.encode("utf-8"))
            ),
            mock.patch.object(
                gate,
                "EXPECTED_REPRO_VERIFIER_SHA256",
                hashlib.sha256(verifier.encode("utf-8")).hexdigest(),
            ),
        ):
            self.assertEqual(gate.inspect_repro_verifier_text(verifier), [])
            wrong_verifier = verifier.replace(
                gate.REPRO_OFF, "out/repro-wrong-off", 1
            )
            self.assert_finding(
                gate.inspect_repro_verifier_text(wrong_verifier), "OFF matrix"
            )
        self.assertEqual(gate.inspect_repro_cmake_pin(manifest, verifier, cmake), [])
        self.assert_finding(
            gate.inspect_repro_cmake_pin(manifest, verifier, cmake + "#mutant\n"),
            "manifest CMake pin",
        )

    def test_cmake_fail_closed_and_integrated_dependency_mutants_fail(self):
        absent = self.cmake.replace(gate.LIBRARY, "removed_empty_preloop_library")
        self.assert_finding(gate.inspect_cmake_text(absent), "token is missing")
        if not self.integration_landed():
            self.skipTest("empty-preloop integration has not fully landed")
        escaped = self.cmake + f"\nadd_library({gate.LIBRARY} STATIC escaped.c)\n"
        self.assert_finding(gate.inspect_cmake_text(escaped), "BUILD_TESTING")
        dependency = next(
            command for command in re.finditer(
                r"target_link_libraries\s*\(\s*" + re.escape(gate.LIBRARY)
                + r".*?\)", self.cmake, flags=re.S,
            )
        )
        private = dependency.group(0).replace("PUBLIC", "PRIVATE", 1)
        mutant = (
            self.cmake[:dependency.start()] + private
            + self.cmake[dependency.end():]
        )
        self.assert_finding(gate.inspect_cmake_text(mutant), "guest32/public")
        dependency_text = dependency.group(0)
        missing_child_block = dependency_text.replace(
            gate.CHILD_LIBRARIES[-1], "removed_prefix_child", 1
        )
        missing_child = (
            self.cmake[:dependency.start()] + missing_child_block
            + self.cmake[dependency.end():]
        )
        self.assert_finding(gate.inspect_cmake_text(missing_child), "child/private")
        wrong_total = self.cmake.replace("add_test(", "removed_test(", 1)
        self.assert_finding(gate.inspect_cmake_text(wrong_total), "192 CTests")
        missing_lifecycle_link = self.cmake.replace(
            f"      {gate.LIBRARY}\n      {gate.LIFECYCLE_LIBRARY}\n",
            f"      {gate.LIBRARY}\n",
            1,
        )
        self.assertNotEqual(missing_lifecycle_link, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(missing_lifecycle_link), "final direct headless links"
        )
        stale_terminal = self.cmake.replace(
            "entry_policy_static_verified;" + gate.TERMINAL_FIXTURE,
            "entry_policy_static_verified;" + gate.PARENT_RELOAD_FIXTURE,
            1,
        )
        self.assertNotEqual(stale_terminal, self.cmake)
        self.assert_finding(
            gate.inspect_cmake_text(stale_terminal), "composed lifecycle"
        )

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

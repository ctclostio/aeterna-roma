#!/usr/bin/env python3
"""Focused synthetic tests for gen_compile_island.py."""

from __future__ import annotations

import contextlib
import csv
import dataclasses
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Sequence
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_compile_island as island


FINGERPRINT = "a" * 64
SIMPLE_SOURCE = b"int decomp_fn_10000000(void)\n{\n  return 0;\n}\n"
STRICT_MARKER = "WARNING_CLEAN_VERIFIED"
ALL_MARKERS = ("COMPILE_VERIFIED", STRICT_MARKER, "STRUCTURALLY_VALIDATED", "QUARANTINED")
# compile/compile_commands.tsv of the published historical baseline (policy
# 8afc796a...) records this SHA-256 for decomp_fn_102df760.rsp.
HISTORICAL_102DF760_RESPONSE_SHA256 = (
    "e78d5ab29b6e506e23b9a94ac1cda56ac4fbd48adda456f86a453eac80ac2d93"
)


def make_compile_config(
    root: Path, *, target: str = "x64", base: bytes = b"#pragma once\n"
) -> island.CompileConfig:
    base_path = root / "toolchain" / "base_compat.h"
    base_path.parent.mkdir(parents=True, exist_ok=True)
    base_path.write_bytes(base)
    return island.CompileConfig(
        compiler_path=root / "toolchain" / "cl.exe",
        compiler_sha256="c" * 64,
        compiler_version="19.51.36256",
        compiler_target=target,
        compiler_version_text="compiler version\n",
        compiler_version_sha256="d" * 64,
        base_compat_path=base_path,
        base_compat_sha256=hashlib.sha256(base).hexdigest(),
    )


class FakeCompiler:
    """Replaces subprocess.run; honors /Fo like cl.exe but ignores /WX."""

    def __init__(
        self,
        *,
        exit_code: int = 0,
        extra_lines: Sequence[str] = (),
        write_object: bool = True,
    ) -> None:
        self.exit_code = exit_code
        self.extra_lines = tuple(extra_lines)
        self.write_object = write_object
        self.calls: list[dict[str, object]] = []

    def __call__(self, args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        cwd = Path(str(kwargs["cwd"]))
        response = (cwd / args[1][1:]).read_text(encoding="utf-8").splitlines()
        self.calls.append({"args": list(args), "env": kwargs.get("env"), "response": response})
        for line in response:
            if line.startswith("/Fo") and self.write_object and self.exit_code == 0:
                (cwd / line[3:].strip('"').replace("\\", "/")).write_bytes(b"object")
        source_echo = response[-1].strip('"').split("\\")[-1]
        stdout = "\r\n".join((source_echo, *self.extra_lines)) + "\r\n"
        return subprocess.CompletedProcess(args, self.exit_code, stdout=stdout)


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def read_header(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()[0].split("\t")


def present_markers(path: Path) -> set[str]:
    return {name for name in ALL_MARKERS if (path / name).exists()}


def function_row(address: str, source: bytes, declaration: str) -> dict[str, str]:
    name = f"decomp_fn_{address}"
    row = {key: "" for key in island.JOINED_HEADER}
    row.update(
        {
            "record_type": "function",
            "mapping_fingerprint": FINGERPRINT,
            "address": address,
            "canonical_name": name,
            "source_file": f"{name}.c",
            "source_status": "success",
            "parse_status": "parsed",
            "file_sha256": hashlib.sha256(source).hexdigest(),
            "definition_sha256": "b" * 64,
            "definition_start_line": "1",
            "definition_end_line": "4",
            "declaration": declaration,
            "outgoing_function_targets": "0",
            "outgoing_function_occurrences": "0",
            "outgoing_data_targets": "0",
            "outgoing_data_occurrences": "0",
            "incoming_reference_sources": "0",
            "incoming_reference_occurrences": "0",
            "original_name": f"FUN_{address}",
            "original_qualified_name": f"FUN_{address}",
            "symbol_id": "1",
            "namespace_id": "0",
            "source_type": "DEFAULT",
            "signature": f"int FUN_{address}(void)",
            "size": "4",
            "kind": "func",
            "body_ranges": f"{address}-{address}",
        }
    )
    return row


def data_row(address: str, path: str, length: int, code_length: int) -> dict[str, str]:
    row = {key: "" for key in island.JOINED_HEADER}
    row.update(
        {
            "record_type": "data",
            "mapping_fingerprint": FINGERPRINT,
            "address": address,
            "canonical_name": f"decomp_g_{address}",
            "source_status": "indexed",
            "parse_status": "not_applicable",
            "symbol_id": "2",
            "namespace_id": "0",
            "source_type": "DEFAULT",
            "symbol_type": "LABEL",
            "data_type_path": path,
            "data_type_length": str(length),
            "code_unit_length": str(code_length),
        }
    )
    return row


def reference_row(source: str, kind: str, target: str, occurrences: int = 1) -> dict[str, str]:
    return {
        "source_canonical_name": f"decomp_fn_{source}",
        "source_entry": source,
        "source_status": "success",
        "target_kind": kind,
        "target_canonical_name": f"decomp_{'fn' if kind == 'function' else 'g'}_{target}",
        "target_indexed": "yes",
        "target_address": target,
        "target_source_status": "success" if kind == "function" else "indexed",
        "occurrences": str(occurrences),
    }


class Fixture:
    def __init__(self, root: Path, source: bytes, declaration: str = "int decomp_fn_10000000(void)"):
        self.stage = root / "stage"
        self.sources = self.stage / "sources"
        self.sources.mkdir(parents=True)
        self.rows = [function_row("10000000", source, declaration)]
        self.refs: list[dict[str, str]] = []
        self.source_map = {"10000000": source}

    def add_function(self, address: str, declaration: str, source: bytes | None = None) -> None:
        if source is None:
            source = f"int decomp_fn_{address}(void) {{ return 0; }}\n".encode()
        self.rows.append(function_row(address, source, declaration))
        self.source_map[address] = source

    def add_data(self, address: str, path: str, length: int, code_length: int) -> None:
        self.rows.append(data_row(address, path, length, code_length))

    def write(self) -> None:
        summary = {
            "mapping_fingerprint": FINGERPRINT,
            "complete": True,
            "source_success": sum(row["record_type"] == "function" for row in self.rows),
            "expected_functions": sum(row["record_type"] == "function" for row in self.rows),
        }
        (self.stage / island.SUMMARY_FILE).write_text(json.dumps(summary), encoding="utf-8")
        for address, source in self.source_map.items():
            (self.sources / f"decomp_fn_{address}.c").write_bytes(source)
        with (self.stage / island.MANIFEST_FILE).open("w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=island.JOINED_HEADER, delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(self.rows)
        with (self.stage / island.REFERENCES_FILE).open("w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=island.REFERENCES_HEADER, delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(self.refs)


class CompileIslandTests(unittest.TestCase):
    def test_exact_sorted_per_tu_declarations_and_atomic_structural_output(self) -> None:
        source = b"""int decomp_fn_10000000(void)\n{\n  return decomp_fn_10000020() + decomp_fn_10000010();\n}\n"""
        with tempfile.TemporaryDirectory() as raw:
            # publish_plan resolves Windows 8.3 aliases used by hosted runners.
            root = Path(raw).resolve()
            fixture = Fixture(root, source)
            fixture.add_function("10000020", "int decomp_fn_10000020(void)")
            fixture.add_function("10000010", "int decomp_fn_10000010(void)")
            fixture.refs.extend(
                [
                    reference_row("10000000", "function", "10000020"),
                    reference_row("10000000", "function", "10000010"),
                ]
            )
            fixture.write()
            plan = island.load_plan(fixture.stage, ["0x10000000"])
            self.assertTrue(plan.structurally_clean)
            output = island.publish_plan(plan, root / "output")
            self.assertEqual(
                output,
                root / "output" / FINGERPRINT / "_structural" / plan.policy_sha256,
            )
            self.assertEqual((output / "sources" / "decomp_fn_10000000.c").read_bytes(), source)
            deps = (output / "include" / "decomp_fn_10000000.deps.h").read_text()
            first = deps.index("int decomp_fn_10000010(void);")
            second = deps.index("int decomp_fn_10000020(void);")
            self.assertLess(first, second)
            self.assertNotIn("decomp_fn_10000000(void);", deps)
            self.assertTrue((output / "STRUCTURALLY_VALIDATED").is_file())
            self.assertFalse((output / "COMPILE_VERIFIED").exists())
            self.assertEqual(island.publish_plan(plan, root / "output"), output)

    def test_comments_strings_and_character_literals_are_ignored(self) -> None:
        source = b'''int decomp_fn_10000000(void)\n{\n  /* DAT_deadbeef PTR_bad LAB_1000 */\n  const char *s = "_DAT_feedface decomp_fn_10000010";\n  char c = 'x'; // UNK_1234\n  return c + (s != 0);\n}\n'''
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw), source)
            fixture.write()
            plan = island.load_plan(fixture.stage, ["10000000"])
            self.assertTrue(plan.structurally_clean, plan.findings)
            self.assertFalse(plan.units[0].inventory)

    def test_legacy_storage_is_inventory_and_quarantine_not_ready(self) -> None:
        source = b"int decomp_fn_10000000(void)\n{\n  return DAT_12345678 + DAT_12345678;\n}\n"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = Fixture(root, source)
            fixture.write()
            plan = island.load_plan(fixture.stage, ["10000000"])
            self.assertFalse(plan.structurally_clean)
            item = plan.units[0].inventory[0]
            self.assertEqual((item.category, item.symbol, item.occurrences), ("legacy_data", "DAT_12345678", 2))
            output = island.publish_plan(plan, root / "output")
            self.assertEqual(output.parent.name, "_quarantine")
            self.assertTrue((output / "QUARANTINED").is_file())
            self.assertFalse((output / "COMPILE_VERIFIED").exists())

    def test_local_labels_are_allowed_but_address_values_are_quarantined(self) -> None:
        safe = b"void decomp_fn_10000000(void)\n{\n  goto LAB_10000001;\nLAB_10000001:\n  return;\n}\n"
        unsafe = b"void *decomp_fn_10000000(void)\n{\n  return LAB_10000001;\nLAB_10000001:\n  return 0;\n}\n"
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw), safe, "void decomp_fn_10000000(void)")
            fixture.write()
            self.assertTrue(
                island.load_plan(fixture.stage, ["10000000"]).structurally_clean
            )
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw), unsafe, "void *decomp_fn_10000000(void)")
            fixture.write()
            plan = island.load_plan(fixture.stage, ["10000000"])
            self.assertIn("address_valued_label", {item.category for item in plan.findings})

    def test_fixed_width_data_registry_never_widens_guest_pointer(self) -> None:
        source = b"uint32_t decomp_fn_10000000(void)\n{\n  return decomp_g_20000000;\n}\n"
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw), source, "uint32_t decomp_fn_10000000(void)")
            fixture.add_data("20000000", "/pointer", 4, 4)
            fixture.refs.append(reference_row("10000000", "data", "20000000"))
            fixture.write()
            plan = island.load_plan(fixture.stage, ["10000000"])
            self.assertTrue(plan.structurally_clean, plan.findings)
            deps = plan.units[0].deps_bytes.decode()
            self.assertIn("extern uint32_t decomp_g_20000000;", deps)
            self.assertNotIn("intptr", deps)
            self.assertNotIn("void *", deps)

    def test_unknown_data_type_is_quarantined_without_blanket_declaration(self) -> None:
        source = b"int decomp_fn_10000000(void)\n{\n  return decomp_g_20000000;\n}\n"
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw), source)
            fixture.add_data("20000000", "/Mystery", 12, 12)
            fixture.refs.append(reference_row("10000000", "data", "20000000"))
            fixture.write()
            plan = island.load_plan(fixture.stage, ["10000000"])
            self.assertFalse(plan.structurally_clean)
            self.assertIn("unresolved_data_type", {item.category for item in plan.findings})
            self.assertNotIn("decomp_g_20000000;", plan.units[0].deps_bytes.decode())

    def test_unknown_prototype_type_and_old_style_prototype_are_quarantined(self) -> None:
        source = b"int decomp_fn_10000000(void)\n{\n  decomp_fn_10000010(0);\n  decomp_fn_10000020();\n  return 0;\n}\n"
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw), source)
            fixture.add_function("10000010", "void decomp_fn_10000010(_func_77 *param_1)")
            fixture.add_function("10000020", "void decomp_fn_10000020()")
            fixture.refs.extend(
                [
                    reference_row("10000000", "function", "10000010"),
                    reference_row("10000000", "function", "10000020"),
                ]
            )
            fixture.write()
            plan = island.load_plan(fixture.stage, ["10000000"])
            categories = {item.category for item in plan.findings}
            self.assertIn("unresolved_type", categories)
            self.assertIn("old_style_declaration", categories)

    def test_reference_inventory_mismatch_is_quarantined(self) -> None:
        source = b"int decomp_fn_10000000(void)\n{\n  return decomp_fn_10000010();\n}\n"
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw), source)
            fixture.add_function("10000010", "int decomp_fn_10000010(void)")
            fixture.write()
            plan = island.load_plan(fixture.stage, ["10000000"])
            self.assertIn("function_reference_contract", {item.category for item in plan.findings})

    def test_source_hash_mismatch_is_fatal(self) -> None:
        source = b"int decomp_fn_10000000(void) { return 0; }\n"
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw), source)
            fixture.write()
            path = fixture.sources / "decomp_fn_10000000.c"
            path.write_bytes(source + b"/* changed */\n")
            with self.assertRaisesRegex(island.IslandError, "source hash mismatch"):
                island.load_plan(fixture.stage, ["10000000"])

    def test_output_cannot_overlap_immutable_stage(self) -> None:
        source = b"int decomp_fn_10000000(void) { return 0; }\n"
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw), source)
            fixture.write()
            plan = island.load_plan(fixture.stage, ["10000000"])
            with self.assertRaisesRegex(island.IslandError, "disjoint"):
                island.publish_plan(plan, fixture.stage / "output")

    def test_policy_hash_is_deterministic_and_root_scoped(self) -> None:
        source = b"int decomp_fn_10000000(void) { return 0; }\n"
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw), source)
            fixture.add_function("10000010", "int decomp_fn_10000010(void)")
            fixture.write()
            one = island.load_plan(fixture.stage, ["10000000"])
            same = island.load_plan(fixture.stage, ["0x10000000", "10000000"])
            other = island.load_plan(fixture.stage, ["10000010"])
            self.assertEqual(one.policy_sha256, same.policy_sha256)
            self.assertNotEqual(one.policy_sha256, other.policy_sha256)

    def test_policy_pins_generator_x64_gate_and_relocatable_compile_inputs(self) -> None:
        source = b"int decomp_fn_10000000(void) { return 0; }\n"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = Fixture(root, source)
            fixture.write()
            base = root / "elsewhere" / "base.h"
            config = island.CompileConfig(
                compiler_path=root / "toolchain" / "cl.exe",
                compiler_sha256="c" * 64,
                compiler_version="19.51.36256",
                compiler_target="x64",
                compiler_version_text="compiler version\n",
                compiler_version_sha256="d" * 64,
                base_compat_path=base,
                base_compat_sha256="e" * 64,
            )
            plan = island.load_plan(fixture.stage, ["10000000"], config)
            self.assertEqual(plan.policy["policy_revision"], island.POLICY_REVISION)
            self.assertEqual(
                plan.policy["generator_sha256"],
                island.sha256_file(Path(island.__file__).resolve()),
            )
            gate = plan.policy["rules"]["compiler_gate"]
            self.assertEqual(gate["target_pointer_bits"], 64)
            self.assertEqual(gate["compiler_family"], "msvc")
            self.assertEqual(gate["compiler_target"], "x64")
            response = island.response_file_bytes(plan.units[0], config).decode()
            self.assertIn('/FI"..\\include\\pointer_width_gate.h"', response)
            self.assertIn('/FI"..\\include\\base_compat.h"', response)
            self.assertNotIn(str(base), response)

    def test_compiler_output_removes_random_atomic_root(self) -> None:
        root = Path("X:/output/.policy.tmp-random")
        raw = (
            "X:\\output\\.policy.tmp-random\\sources\\unit.c(3): error C9999\r\n"
            "X:/output/.policy.tmp-random/include/gate.h(1): note\r\n"
        )
        normalized = island.normalize_compile_output(raw, root)
        self.assertEqual(
            normalized,
            "<ISLAND_ROOT>\\sources\\unit.c(3): error C9999\n"
            "<ISLAND_ROOT>/include/gate.h(1): note\n",
        )
        self.assertNotIn("tmp-random", normalized)

    def test_msvc_banner_requires_inventory_and_records_target(self) -> None:
        x64 = (
            "Microsoft (R) C/C++ Optimizing Compiler Version 19.51.36256 for x64\n"
            "Compiler Passes:\n cl.exe: Version 19.51.36256.0\n"
        )
        x86 = x64.replace("for x64", "for x86")
        self.assertEqual(island.parse_msvc_banner(x64), ("19.51.36256", "x64"))
        self.assertEqual(island.parse_msvc_banner(x86), ("19.51.36256", "x86"))
        with self.assertRaisesRegex(island.IslandError, "MSVC compiler inventory"):
            island.parse_msvc_banner("compiler version\n")

    def test_default_and_original_audit_roots_remain_distinct_evidence(self) -> None:
        self.assertEqual(len(island.DEFAULT_ROOTS), 16)
        self.assertEqual(len(island.AUDITED_ROOTS), 16)
        self.assertNotEqual(island.DEFAULT_ROOTS, island.AUDITED_ROOTS)


class WarningCleanProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()

    def strict_plan(
        self, source: bytes = SIMPLE_SOURCE, *, target: str = "x64", base: bytes = b"#pragma once\n"
    ) -> island.IslandPlan:
        fixture = Fixture(self.root, source)
        fixture.write()
        config = make_compile_config(self.root, target=target, base=base)
        return island.load_plan(
            fixture.stage, ["10000000"], config, profile=island.WARNING_CLEAN_PROFILE
        )

    def publish(self, plan: island.IslandPlan, fake: FakeCompiler, output: str = "output") -> Path:
        with mock.patch.object(island.subprocess, "run", fake):
            return island.publish_plan(plan, self.root / output)

    def assert_no_staging_left(self, output: str = "output") -> None:
        fingerprint_dir = self.root / output / FINGERPRINT
        leftovers = [path.name for path in fingerprint_dir.iterdir() if ".tmp-" in path.name]
        self.assertEqual(leftovers, [])

    def test_default_response_is_byte_identical_to_historical_baseline(self) -> None:
        unit = island.TranslationUnit(
            entry="102df760",
            canonical_name="decomp_fn_102df760",
            source_file="decomp_fn_102df760.c",
            source_bytes=b"",
            source_sha256="",
            declaration="",
        )
        config = make_compile_config(self.root)
        response = island.response_file_bytes(unit, config)
        self.assertEqual(hashlib.sha256(response).hexdigest(), HISTORICAL_102DF760_RESPONSE_SHA256)
        self.assertEqual(island.response_file_bytes(unit, config, island.SYNTAX_PROFILE), response)
        self.assertEqual(island.COMPILE_FLAGS, ("/nologo", "/TC", "/Zs", "/W3", "/we4013"))
        self.assertIs(island.parse_args(["stage"]).warning_clean, False)
        self.assertIs(island.parse_args(["stage", "--warning-clean"]).warning_clean, True)

    def test_profile_is_part_of_policy_identity_and_strict_response(self) -> None:
        fixture = Fixture(self.root, SIMPLE_SOURCE)
        fixture.write()
        config = make_compile_config(self.root)
        for compile_config in (None, config):
            with self.subTest(compiler_configured=compile_config is not None):
                default = island.load_plan(fixture.stage, ["10000000"], compile_config)
                strict = island.load_plan(
                    fixture.stage,
                    ["10000000"],
                    compile_config,
                    profile=island.WARNING_CLEAN_PROFILE,
                )
                self.assertIs(default.profile, island.SYNTAX_PROFILE)
                self.assertNotEqual(default.policy_sha256, strict.policy_sha256)
                self.assertIn(strict.policy_sha256.encode(), strict.units[0].deps_bytes)
                default_gate = default.policy["rules"]["compiler_gate"]
                strict_gate = strict.policy["rules"]["compiler_gate"]
                self.assertEqual(default_gate["arguments"], list(island.COMPILE_FLAGS))
                self.assertEqual(default_gate["profile"]["success_marker"], "COMPILE_VERIFIED")
                self.assertEqual(strict_gate["arguments"], list(island.WARNING_CLEAN_COMPILE_FLAGS))
                self.assertEqual(strict_gate["profile"]["name"], island.WARNING_CLEAN_PROFILE.name)
                self.assertEqual(strict_gate["profile"]["success_marker"], STRICT_MARKER)
                self.assertEqual(strict_gate["profile"]["removed_environment"], ["CL", "_CL_"])
                self.assertEqual(strict_gate["target_pointer_bits"], 64)
                for gate in (default_gate, strict_gate):
                    claims = gate["profile"]["success_claims"]
                    self.assertIs(claims["abi_equivalence"], False)
                    self.assertIs(claims["behavior_equivalence"], False)
                self.assertIs(default_gate["profile"]["success_claims"]["warning_clean"], False)
                self.assertIs(strict_gate["profile"]["success_claims"]["warning_clean"], True)

        response = island.response_file_bytes(
            strict.units[0], config, island.WARNING_CLEAN_PROFILE
        ).decode().splitlines()
        self.assertEqual(response[:6], ["/nologo", "/TC", "/c", "/W4", "/WX", "/we4013"])
        self.assertEqual(response[-2], '/Fo"compile\\objects\\decomp_fn_10000000.obj"')
        self.assertEqual(response[-1], '"sources\\decomp_fn_10000000.c"')
        self.assertEqual(island.warning_clean_argument_violations(response), [])

    def test_strict_argument_guard_rejects_suppression_and_syntax_only_flags(self) -> None:
        self.assertEqual(
            set(island.warning_clean_argument_violations(island.COMPILE_FLAGS)),
            {
                "/Zs suppresses or hides diagnostics",
                "/W3 suppresses or hides diagnostics",
                "/c is required",
                "/W4 is required",
                "/WX is required",
            },
        )
        base = ["/c", "/W4", "/WX"]
        for flag in ("/w", "/W0", "/wd4312", "/wo4312", "/WX-", "/Wv:18", "/external:W0", "-wd4047"):
            with self.subTest(flag=flag):
                self.assertEqual(
                    island.warning_clean_argument_violations(base + [flag]),
                    [f"{flag} suppresses or hides diagnostics"],
                )
        self.assertEqual(island.warning_clean_argument_violations(base + ["/we4013"]), [])

        weakened = dataclasses.replace(
            island.WARNING_CLEAN_PROFILE,
            arguments=island.WARNING_CLEAN_COMPILE_FLAGS + ("/wd4312",),
        )
        fixture = Fixture(self.root, SIMPLE_SOURCE)
        fixture.write()
        with self.assertRaisesRegex(island.IslandError, "unknown compile profile"):
            island.load_plan(fixture.stage, ["10000000"], profile=weakened)
        with mock.patch.dict(island.COMPILE_PROFILES, {weakened.name: weakened}):
            with self.assertRaisesRegex(island.IslandError, "cannot claim warning cleanliness"):
                island.load_plan(fixture.stage, ["10000000"], profile=weakened)

    def test_compile_output_diagnostics_is_an_allow_list(self) -> None:
        self.assertEqual(
            island.compile_output_diagnostics("decomp_fn_1.c\n\n", "decomp_fn_1.c"), ((), ())
        )
        lines, codes = island.compile_output_diagnostics(
            "decomp_fn_1.c\n"
            "cl : Command line warning D9025 : overriding '/W4' with '/W3'\n"
            "sources\\decomp_fn_1.c(3): warning C4312: cast\n"
            "sources\\decomp_fn_1.c(4): warning C4312: cast\n",
            "decomp_fn_1.c",
        )
        self.assertEqual(len(lines), 3)
        self.assertEqual(codes, (("C4312", 2), ("D9025", 1)))
        lines, codes = island.compile_output_diagnostics("Warnung C4312: lokalisiert\n", "x.c")
        self.assertEqual((lines, codes), (("Warnung C4312: lokalisiert",), ()))

    def test_fake_success_with_warning_output_is_quarantined(self) -> None:
        plan = self.strict_plan()
        cases = {
            "front_end": ["sources\\decomp_fn_10000000.c(3): warning C4312: 'type cast'"],
            "command_line": ["cl : Command line warning D9025 : overriding '/W4' with '/W0'"],
            "unrecognized": ["note: something the gate does not understand"],
        }
        for name, lines in cases.items():
            with self.subTest(case=name):
                fake = FakeCompiler(extra_lines=lines)
                environment = {"CL": "/w", "_CL_": "/W0", "ISLAND_TEST_SENTINEL": "kept"}
                with mock.patch.dict(os.environ, environment):
                    output = self.publish(plan, fake, output=name)
                self.assertEqual(
                    output, self.root / name / FINGERPRINT / "_quarantine" / plan.policy_sha256
                )
                self.assertEqual(present_markers(output), {"QUARANTINED"})
                self.assertFalse((self.root / name / FINGERPRINT / plan.policy_sha256).exists())
                self.assert_no_staging_left(name)
                self.assertEqual(list((output / "compile" / "objects").iterdir()), [])

                passed_env = fake.calls[0]["env"]
                self.assertIsInstance(passed_env, dict)
                upper_keys = {key.upper() for key in passed_env}
                self.assertNotIn("CL", upper_keys)
                self.assertNotIn("_CL_", upper_keys)
                self.assertIn("ISLAND_TEST_SENTINEL", upper_keys)

                summary = json.loads((output / "island_summary.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["status"], "quarantined")
                self.assertEqual(summary["compile_profile"], island.WARNING_CLEAN_PROFILE.name)
                self.assertEqual(summary["compiler_gate"]["passed"], 1)
                self.assertEqual(summary["compiler_gate"]["warning_clean"], 0)
                self.assertIs(summary["compiler_gate"]["verified"], False)
                self.assertIs(summary["provenance"]["established"]["warning_clean"], False)
                quarantine = read_rows(output / "quarantine.tsv")
                self.assertEqual({row["category"] for row in quarantine}, {"compiler_diagnostics"})
                result = read_rows(output / "compile" / "compile_results.tsv")[0]
                self.assertEqual(
                    (result["exit_code"], result["passed"], result["warning_clean"]),
                    ("0", "yes", "no"),
                )
                self.assertEqual(result["object_produced"], "yes")

        front_end = json.loads(
            (
                self.root / "front_end" / FINGERPRINT / "_quarantine" / plan.policy_sha256
                / "island_summary.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(front_end["compiler_gate"]["warning_codes"], {"C4312": 1})

    def test_strict_clean_success_receives_only_the_warning_clean_marker(self) -> None:
        plan = self.strict_plan()
        output = self.publish(plan, FakeCompiler())
        self.assertEqual(output, self.root / "output" / FINGERPRINT / plan.policy_sha256)
        self.assertEqual(present_markers(output), {STRICT_MARKER})
        self.assertEqual((output / STRICT_MARKER).read_text(), "warning_clean_verified\n")
        self.assertEqual(list((output / "compile" / "objects").iterdir()), [])
        self.assert_no_staging_left()

        summary = json.loads((output / "island_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], "warning_clean_verified")
        self.assertEqual(summary["compile_profile"], island.WARNING_CLEAN_PROFILE.name)
        self.assertEqual(summary["provenance"]["evidence"], "warning_clean_compile")
        self.assertEqual(
            summary["provenance"]["established"],
            {
                "x64_compiler_gate": True,
                "warning_clean": True,
                "abi_equivalence": False,
                "behavior_equivalence": False,
            },
        )
        self.assertEqual(summary["compiler_gate"]["objects_produced"], 1)
        self.assertEqual(summary["compiler_gate"]["warning_codes"], {})
        policy = json.loads((output / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(
            policy["rules"]["compiler_gate"]["profile"]["name"], island.WARNING_CLEAN_PROFILE.name
        )
        command = read_rows(output / "compile" / "compile_commands.tsv")[0]
        self.assertEqual(command["compile_profile"], island.WARNING_CLEAN_PROFILE.name)
        self.assertEqual(command["removed_environment"], "CL,_CL_")
        response = (output / command["response_file"]).read_bytes()
        self.assertEqual(hashlib.sha256(response).hexdigest(), command["response_sha256"])
        self.assertIn(b"/W4\n/WX\n", response)
        self.assertEqual(read_rows(output / "compile" / "compile_results.tsv")[0]["warning_clean"], "yes")
        # Immutable republication of the same evidence is idempotent.
        self.assertEqual(self.publish(plan, FakeCompiler()), output)

    def test_strict_admission_requires_generated_object(self) -> None:
        plan = self.strict_plan()
        output = self.publish(plan, FakeCompiler(write_object=False))
        self.assertEqual(output.parent.name, "_quarantine")
        self.assertEqual(present_markers(output), {"QUARANTINED"})
        categories = {row["category"] for row in read_rows(output / "quarantine.tsv")}
        self.assertEqual(categories, {"compiler_object_missing"})

    def test_strict_compiler_target_must_remain_x64(self) -> None:
        plan = self.strict_plan(target="x86")
        output = self.publish(plan, FakeCompiler())
        self.assertEqual(output.parent.name, "_quarantine")
        self.assertEqual(present_markers(output), {"QUARANTINED"})
        categories = {row["category"] for row in read_rows(output / "quarantine.tsv")}
        self.assertEqual(categories, {"compiler_target"})

    def test_default_profile_behavior_and_records_are_unchanged(self) -> None:
        fixture = Fixture(self.root, SIMPLE_SOURCE)
        fixture.write()
        plan = island.load_plan(fixture.stage, ["10000000"], make_compile_config(self.root))
        fake = FakeCompiler(extra_lines=["sources\\decomp_fn_10000000.c(3): warning C4312: cast"])
        with mock.patch.dict(os.environ, {"CL": "/DSENTINEL"}):
            output = self.publish(plan, fake)
        self.assertEqual(output, self.root / "output" / FINGERPRINT / plan.policy_sha256)
        self.assertEqual(present_markers(output), {"COMPILE_VERIFIED"})
        self.assertIsNone(fake.calls[0]["env"])
        self.assertIn("/Zs", fake.calls[0]["response"])
        self.assertFalse((output / "compile" / "objects").exists())
        self.assertEqual(
            read_header(output / "compile" / "compile_commands.tsv"),
            [
                "entry",
                "canonical_name",
                "compiler",
                "response_file",
                "response_sha256",
                "command_from_island_root",
            ],
        )
        self.assertEqual(
            read_header(output / "compile" / "compile_results.tsv"),
            ["entry", "response_file", "exit_code", "passed", "output_sha256", "log_file"],
        )
        summary = json.loads((output / "island_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], "compile_verified")
        self.assertEqual(summary["compile_profile"], island.SYNTAX_PROFILE.name)
        self.assertEqual(summary["provenance"]["evidence"], "historical_syntax_compile")
        self.assertIs(summary["provenance"]["established"]["x64_compiler_gate"], True)
        self.assertIs(summary["provenance"]["established"]["warning_clean"], False)
        self.assertNotIn("warning_clean", summary["compiler_gate"])

    def test_compiler_invocation_failure_leaves_no_marker_or_staging(self) -> None:
        plan = self.strict_plan()
        failing = mock.Mock(side_effect=OSError("compiler vanished"))
        with mock.patch.object(island.subprocess, "run", failing):
            with self.assertRaisesRegex(island.IslandError, "compiler invocation failed"):
                island.publish_plan(plan, self.root / "output")
        self.assertEqual(list((self.root / "output" / FINGERPRINT).iterdir()), [])

    def test_contradictory_outcomes_for_one_policy_fail_closed(self) -> None:
        plan = self.strict_plan()
        verified = self.publish(plan, FakeCompiler(), output="first")
        with self.assertRaisesRegex(island.IslandError, "contradictory publication"):
            self.publish(plan, FakeCompiler(extra_lines=["warning C4312: x"]), output="first")
        quarantine = self.root / "first" / FINGERPRINT / "_quarantine" / plan.policy_sha256
        self.assertEqual(present_markers(quarantine), {"QUARANTINED"})
        self.assertEqual(present_markers(verified), {STRICT_MARKER})
        self.assert_no_staging_left("first")

        self.publish(plan, FakeCompiler(exit_code=2), output="second")
        with self.assertRaisesRegex(island.IslandError, "refusing warning_clean_verified"):
            self.publish(plan, FakeCompiler(), output="second")
        self.assertFalse((self.root / "second" / FINGERPRINT / plan.policy_sha256).exists())
        self.assert_no_staging_left("second")

    def test_strict_profile_quarantines_warning_control_directives(self) -> None:
        pragma = (
            b"int decomp_fn_10000000(void)\n{\n#pragma warning(disable: 4312)\n  return 0;\n}\n"
        )
        inline = b"int decomp_fn_10000000(void)\n{\n  __pragma(warning(push, 0))\n  return 0;\n}\n"
        masked = (
            b"int decomp_fn_10000000(void)\n{\n  /* #pragma warning(disable: 4312) */\n"
            b'  const char *s = "_Pragma(\\"warning\\")";\n  return s != 0;\n}\n'
        )
        for name, source, blocked in (("pragma", pragma, True), ("inline", inline, True), ("masked", masked, False)):
            with self.subTest(case=name), tempfile.TemporaryDirectory() as raw:
                fixture = Fixture(Path(raw), source)
                fixture.write()
                default = island.load_plan(fixture.stage, ["10000000"])
                strict = island.load_plan(
                    fixture.stage, ["10000000"], profile=island.WARNING_CLEAN_PROFILE
                )
                self.assertNotIn(
                    "warning_control_directive", {item.category for item in default.findings}
                )
                self.assertEqual(
                    "warning_control_directive" in {item.category for item in strict.findings},
                    blocked,
                )

        plan = self.strict_plan(base=b"#pragma once\n#pragma warning(push, 0)\n")
        self.assertEqual(
            [(item.category, item.symbol) for item in plan.findings],
            [("warning_control_directive", "base_compat.h")],
        )

    def test_cli_dry_run_never_publishes_or_verifies(self) -> None:
        fixture = Fixture(self.root, SIMPLE_SOURCE)
        fixture.write()
        output_root = self.root / "cli-output"
        common = [str(fixture.stage), "--address", "10000000", "--output-root", str(output_root)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            dry_run = island.main(common + ["--warning-clean", "--dry-run"])
            no_compiler = island.main(common + ["--warning-clean"])
        self.assertEqual(dry_run, 0)
        self.assertIn(f"profile={island.WARNING_CLEAN_PROFILE.name}", stdout.getvalue())
        self.assertNotIn("result=", stdout.getvalue())
        self.assertEqual(no_compiler, 1)
        self.assertIn("requires --compiler", stderr.getvalue())
        self.assertFalse(output_root.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)

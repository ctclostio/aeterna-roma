#!/usr/bin/env python3
"""Focused synthetic tests for gen_compile_island.py."""

from __future__ import annotations

import csv
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_compile_island as island


FINGERPRINT = "a" * 64


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
            root = Path(raw)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)

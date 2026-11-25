#!/usr/bin/env python3
"""Public CI-safe validation & fail-closed mutation tests for `work/binary_contracts/`."""
from __future__ import annotations

import ast
import copy
import csv
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import validate_whole_binary_contracts as vwc

MAX_FILE_BYTES = 25 * 1024 * 1024


def _rehash_temp_manifest(tmp_dir: Path, filename: str) -> None:
    manifest_p = tmp_dir / "manifest.json"
    manifest = json.loads(manifest_p.read_text(encoding="utf-8"))
    raw = (tmp_dir / filename).read_bytes()
    manifest["files"][filename]["bytes"] = len(raw)
    manifest["files"][filename]["sha256"] = hashlib.sha256(raw).hexdigest()
    manifest_p.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _edit_tsv_row(path: Path, row_index: int, mutate_fn) -> None:
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        fieldnames = reader.fieldnames or []
        rows = list(reader)
    mutate_fn(rows[row_index])
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


class PublicWholeBinaryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base_copy = Path(cls._tmp.name) / "base"
        shutil.copytree(vwc.CONTRACTS_DIR, cls.base_copy)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _fresh_copy(self, tag: str) -> Path:
        dst = Path(self._tmp.name) / tag
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(self.base_copy, dst)
        return dst

    def test_public_validation_passes_and_sizes_under_25mb(self) -> None:
        res = vwc.validate_all(vwc.CONTRACTS_DIR, image_bytes_data=None)
        self.assertTrue(res["verified"])
        self.assertFalse(res["pe_verified"])
        self.assertEqual(res["canonical_functions"], 81280)
        self.assertEqual(res["non_proc_curated_slots"], 31)
        self.assertEqual(res["vtables"], 9639)
        self.assertEqual(res["rtti_type_descriptors"], 181)
        self.assertEqual(res["globals"], 11141)

        for p in vwc.CONTRACTS_DIR.iterdir():
            self.assertLess(p.stat().st_size, MAX_FILE_BYTES, msg=p.name)

    def test_validator_uses_pure_stdlib_only(self) -> None:
        src = (SCRIPTS_DIR / "validate_whole_binary_contracts.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertNotIn("capstone", imported)
        self.assertNotIn("resolve_indirect_calls", imported)

    def test_rejects_tampered_manifest_hash(self) -> None:
        d = self._fresh_copy("tamper_manifest")
        m_p = d / "manifest.json"
        m = json.loads(m_p.read_text(encoding="utf-8"))
        m["files"]["rtti_contracts.tsv"]["sha256"] = "0" * 64
        m_p.write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "artifact sha256 mismatch"):
            vwc.validate_all(d, image_bytes_data=None)

    def test_rejects_duplicate_function_and_bad_cdecl_pop_and_range_sum(self) -> None:
        # 1. Duplicate function address
        d1 = self._fresh_copy("dup_fn")
        with open(d1 / "function_contracts_part1.tsv", "r", encoding="utf-8", newline="") as f:
            r1 = csv.DictReader(f, delimiter="\t")
            fns1 = list(r1)
        dup_addr = fns1[0]["address"]
        _edit_tsv_row(d1 / "function_contracts_part1.tsv", 1, lambda r: r.__setitem__("address", dup_addr))
        _rehash_temp_manifest(d1, "function_contracts_part1.tsv")
        with self.assertRaisesRegex(ValueError, "unsorted or duplicate function address"):
            vwc.validate_all(d1, image_bytes_data=None)

        # 2. cdecl with non-zero callee_pop_bytes
        d2 = self._fresh_copy("bad_cdecl")
        def _set_bad_cdecl(r: dict) -> None:
            r["calling_convention"] = "cdecl"
            r["receiver_register"] = "none"
            r["callee_pop_bytes"] = "4"
            if int(r["stack_argument_bytes"]) < 4:
                r["stack_argument_bytes"] = "4"
        _edit_tsv_row(d2 / "function_contracts_part1.tsv", 0, _set_bad_cdecl)
        _rehash_temp_manifest(d2, "function_contracts_part1.tsv")
        with self.assertRaisesRegex(ValueError, "cdecl callee must not pop caller args"):
            vwc.validate_all(d2, image_bytes_data=None)

        # 3. Mismatched body_ranges size sum
        d3 = self._fresh_copy("bad_range_sum")
        _edit_tsv_row(
            d3 / "function_contracts_part1.tsv",
            0,
            lambda r: r.__setitem__("bytes", str(int(r["bytes"]) + 4)),
        )
        _rehash_temp_manifest(d3, "function_contracts_part1.tsv")
        with self.assertRaisesRegex(ValueError, "body_ranges size sum"):
            vwc.validate_all(d3, image_bytes_data=None)

    def test_rejects_missing_vptr0_and_curated_global_mismatch(self) -> None:
        # 1. Missing +0x0 vptr
        d1 = self._fresh_copy("missing_vptr")
        _edit_tsv_row(d1 / "class_field_layouts.tsv", 0, lambda r: r.__setitem__("access_kind", "read"))
        _rehash_temp_manifest(d1, "class_field_layouts.tsv")
        with self.assertRaisesRegex(ValueError, "missing \\+0x0 vptr"):
            vwc.validate_all(d1, image_bytes_data=None)

        # 2. Curated global reconciliation failure (first curated global row flipped)
        d2 = self._fresh_copy("bad_curated_global")
        with open(d2 / "global_contracts.tsv", "r", encoding="utf-8", newline="") as f:
            grows = list(csv.DictReader(f, delimiter="\t"))
        cur_idx = next(i for i, r in enumerate(grows) if r["curated_global_pinned"] == "true")
        _edit_tsv_row(
            d2 / "global_contracts.tsv",
            cur_idx,
            lambda r: r.__setitem__("initial_hex_le", ("ff" if r["initial_hex_le"][:2] != "ff" else "00") + r["initial_hex_le"][2:]),
        )
        _rehash_temp_manifest(d2, "global_contracts.tsv")
        with self.assertRaisesRegex(ValueError, "curated global reconciliation failed"):
            vwc.validate_all(d2, image_bytes_data=None)


@unittest.skipUnless(vwc.DLL_PATH.is_file(), "original game image is absent")
class WholeBinaryContractPEProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.image = vwc.DLL_PATH.read_bytes()
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base_copy = Path(cls._tmp.name) / "base"
        shutil.copytree(vwc.CONTRACTS_DIR, cls.base_copy)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _fresh_copy(self, tag: str) -> Path:
        dst = Path(self._tmp.name) / tag
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(self.base_copy, dst)
        return dst

    def test_full_pe_validation_all_81280_functions_9639_vtables_181_rtti_11141_globals(self) -> None:
        res = vwc.validate_all(vwc.CONTRACTS_DIR, image_bytes_data=self.image)
        self.assertTrue(res["verified"])
        self.assertTrue(res["pe_verified"])
        self.assertEqual(res["canonical_functions"], 81280)
        self.assertEqual(res["vtables"], 9639)

    def test_pe_fail_closed_mutations(self) -> None:
        # 1. 1-bit PE image tamper fails pinned image SHA check
        bad_img = bytearray(self.image)
        bad_img[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "original image differs from pinned target"):
            vwc.validate_all(self.base_copy, image_bytes_data=bytes(bad_img))

        # 2. Tampered function SHA fails PE body SHA check
        d_fn = self._fresh_copy("pe_bad_fn_sha")
        _edit_tsv_row(d_fn / "function_contracts_part1.tsv", 0, lambda r: r.__setitem__("sha256", "0" * 64))
        _rehash_temp_manifest(d_fn, "function_contracts_part1.tsv")
        with self.assertRaisesRegex(ValueError, "PE body SHA-256 mismatch"):
            vwc.validate_all(d_fn, image_bytes_data=self.image)

        # 3. Wrong RET pop on first `ret` function fails PE return opcode check
        d_ret = self._fresh_copy("pe_bad_ret")
        with open(d_ret / "function_contracts_part1.tsv", "r", encoding="utf-8", newline="") as f:
            rlist = list(csv.DictReader(f, delimiter="\t"))
        ret_idx = next(i for i, r in enumerate(rlist) if r["exit_kind"] == "ret" and int(r["callee_pop_bytes"]) == 0)
        def _flip_ret(r: dict) -> None:
            r["calling_convention"] = "thiscall"
            r["receiver_register"] = "ECX"
            r["callee_pop_bytes"] = "4"
            if int(r["stack_argument_bytes"]) < 4:
                r["stack_argument_bytes"] = "4"
        _edit_tsv_row(d_ret / "function_contracts_part1.tsv", ret_idx, _flip_ret)
        _rehash_temp_manifest(d_ret, "function_contracts_part1.tsv")
        with self.assertRaisesRegex(ValueError, "PE return bytes disagree"):
            vwc.validate_all(d_ret, image_bytes_data=self.image)

        # 4. Tampered vtable SHA fails PE vtable check
        d_vt = self._fresh_copy("pe_bad_vt")
        _edit_tsv_row(d_vt / "vtable_class_contracts.tsv", 0, lambda r: r.__setitem__("vtable_bytes_sha256", "0" * 64))
        _rehash_temp_manifest(d_vt, "vtable_class_contracts.tsv")
        with self.assertRaisesRegex(ValueError, "PE vtable bytes sha256 mismatch"):
            vwc.validate_all(d_vt, image_bytes_data=self.image)

        # 5. Tampered non-curated global initial byte fails PE global check
        d_gl = self._fresh_copy("pe_bad_gl")
        with open(d_gl / "global_contracts.tsv", "r", encoding="utf-8", newline="") as f:
            glist = list(csv.DictReader(f, delimiter="\t"))
        noncur_idx = next(i for i, r in enumerate(glist) if r["curated_global_pinned"] == "false")
        _edit_tsv_row(
            d_gl / "global_contracts.tsv",
            noncur_idx,
            lambda r: r.__setitem__("initial_hex_le", ("aa" if r["initial_hex_le"][:2] != "aa" else "bb") + r["initial_hex_le"][2:]),
        )
        _rehash_temp_manifest(d_gl, "global_contracts.tsv")
        with self.assertRaisesRegex(ValueError, "PE global bytes disagree"):
            vwc.validate_all(d_gl, image_bytes_data=self.image)


if __name__ == "__main__":
    unittest.main()

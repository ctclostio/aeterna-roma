#!/usr/bin/env python3
"""Tests for gen_startup_audit.py (docs/startup_audit_spec.md contract).

Real-corpus tests run against the pinned production inputs; synthetic
fixtures exercise low-level module APIs without weakening the pins.
"""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path


def hex8(value):
    return format(value, "08x")

HERE = Path(__file__).resolve().parent


def _find_repo_root() -> Path:
    cur = HERE
    for _ in range(8):
        if (cur / "docs" / "startup_audit_spec.md").is_file():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    raise RuntimeError("repository root not found above " + str(HERE))


ROOT = _find_repo_root()
DLL_PATH = ROOT / "Total War Rome II" / "empire.retail.dll"
INDEX_PATH = ROOT / "src_canonical_out" / "empire.retail.dll" / \
    "canonical_function_index.tsv"

_spec = importlib.util.spec_from_file_location(
    "gen_startup_audit", HERE / "gen_startup_audit.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

_DLL_BYTES = None


def dll_bytes() -> bytes:
    global _DLL_BYTES
    if _DLL_BYTES is None:
        _DLL_BYTES = DLL_PATH.read_bytes()
    return _DLL_BYTES


def run_main(out_dir, check=False):
    argv = ["--dll", str(DLL_PATH), "--function-index", str(INDEX_PATH),
            "--output-dir", str(out_dir)]
    if check:
        argv.append("--check")
    return gen.main(argv)


class TempDirTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="w04_audit_test_")
        self.addCleanup(self._tmp.cleanup)
        self.out_dir = Path(self._tmp.name)


@unittest.skipUnless(DLL_PATH.is_file() and INDEX_PATH.is_file(),
                     "production corpus not present")
class RealCorpusTests(TempDirTestCase):

    # ---- generation -------------------------------------------------

    def test_generation_succeeds_and_outputs_match_contract(self):
        rc = run_main(self.out_dir)
        self.assertEqual(rc, 0)
        slots = self.out_dir / gen.SLOTS_NAME
        summary_path = self.out_dir / gen.SUMMARY_NAME
        self.assertTrue(slots.is_file())
        self.assertTrue(summary_path.is_file())

        raw = slots.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "BOM not allowed")
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b"\r\n", raw)

        lines = raw.decode("utf-8").split("\n")[:-1]
        self.assertEqual(lines[0], gen.TSV_HEADER)
        # 8 + 9866 data rows + header.
        self.assertEqual(len(lines), 9875)
        self.assertEqual(len(raw), 660_926)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "453de546bbbd64e858aa80cd2ce09552904098e02cb0861689c24bd21e67ff6b",
        )

        first = lines[1].split("\t")
        self.assertEqual(first[0], "initterm_e_int")
        self.assertEqual(first[1], "0")
        self.assertEqual(first[2], "11739430")
        self.assertEqual(first[3], "00000000")
        self.assertEqual(first[4], "yes")
        self.assertEqual(first[10], "no")

        second = lines[2].split("\t")
        self.assertEqual(second[0], "initterm_e_int")
        self.assertEqual(second[1], "1")
        self.assertEqual(second[4], "no")
        # exact_join must agree with presence of a canonical entry.
        self.assertEqual(second[10] == "yes", bool(second[8]))

        # Invocation order: all initterm_e_int rows precede initterm_void.
        order_seen = [ln.split("\t")[0] for ln in lines[1:]]
        self.assertEqual(order_seen[:8], ["initterm_e_int"] * 8)
        self.assertEqual(set(order_seen[8:]), {"initterm_void"})
        self.assertEqual(order_seen[-1], "initterm_void")

    def test_summary_facts_match_acceptance_table(self):
        self.assertEqual(run_main(self.out_dir), 0)
        text = (self.out_dir / gen.SUMMARY_NAME).read_text("utf-8")
        obj = json.loads(text)
        self.assertEqual(
            set(obj),
            {"generator", "inputs", "invocation_order", "schema",
             "startup_slots", "tables", "totals"},
        )
        self.assertEqual(set(obj["generator"]), {"sha256"})
        self.assertEqual(set(obj["inputs"]), {"dll", "function_index"})
        self.assertEqual(set(obj["inputs"]["dll"]), {"byte_count", "sha256"})
        self.assertEqual(
            set(obj["inputs"]["function_index"]), {"byte_count", "sha256"}
        )
        self.assertEqual(
            set(obj["startup_slots"]), {"data_row_count", "sha256"}
        )
        table_keys = {
            "id", "start_va", "end_va", "signature", "slot_count",
            "null_count", "nonzero_count", "unique_nonzero_count",
            "exact_join_count", "unresolved_exact_count", "null_indices",
            "first_raw_value", "last_raw_value",
        }
        self.assertTrue(all(set(table) == table_keys for table in obj["tables"]))
        self.assertEqual(
            set(obj["totals"]),
            {"slot_count", "null_count", "nonzero_count",
             "exact_join_count", "unresolved_exact_count"},
        )
        self.assertEqual(obj["schema"], "rome2-startup-audit-v1")
        self.assertEqual(obj["invocation_order"],
                         ["initterm_e_int", "initterm_void"])

        ids = [t["id"] for t in obj["tables"]]
        self.assertEqual(ids, ["initterm_e_int", "initterm_void"])
        e, v = obj["tables"]
        self.assertEqual(e["start_va"], "11739430")
        self.assertEqual(e["end_va"], "11739450")
        self.assertEqual(e["first_raw_value"], "00000000")
        self.assertEqual(e["last_raw_value"], "116bd4c4")
        self.assertEqual((e["slot_count"], e["null_count"],
                          e["unique_nonzero_count"], e["exact_join_count"],
                          e["unresolved_exact_count"]), (8, 1, 7, 1, 6))
        self.assertEqual(e["signature"], "int __cdecl(void)")
        self.assertEqual(v["signature"], "void __cdecl(void)")
        self.assertEqual(v["first_raw_value"], "00000000")
        self.assertEqual(v["last_raw_value"], "100d1290")
        self.assertEqual((v["slot_count"], v["null_count"],
                          v["unique_nonzero_count"], v["exact_join_count"],
                          v["unresolved_exact_count"]),
                         (9866, 1, 9865, 1110, 8755))
        for t in obj["tables"]:
            self.assertEqual(t["null_indices"], [0])
            self.assertNotEqual(t["last_raw_value"], "00000000")
            self.assertEqual(len(t["first_raw_value"]), 8)

        totals = obj["totals"]
        self.assertEqual((totals["slot_count"], totals["null_count"],
                          totals["nonzero_count"], totals["exact_join_count"],
                          totals["unresolved_exact_count"]),
                         (9874, 2, 9872, 1111, 8761))

        # Input facts recorded without absolute paths.
        self.assertEqual(obj["inputs"]["dll"]["byte_count"],
                         DLL_PATH.stat().st_size)
        self.assertEqual(obj["inputs"]["dll"]["byte_count"], 28_278_272)
        self.assertEqual(
            obj["inputs"]["dll"]["sha256"],
            "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528",
        )
        self.assertEqual(
            obj["inputs"]["function_index"]["byte_count"], 8_344_450
        )
        self.assertEqual(obj["inputs"]["function_index"]["sha256"],
                         "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5")
        # No absolute repository paths may appear anywhere in the evidence.
        flat = json.dumps(obj)
        self.assertNotIn(str(ROOT), flat)

        # Generator hash matches the actual script on disk.
        self.assertEqual(obj["generator"]["sha256"],
                         hashlib.sha256((HERE / "gen_startup_audit.py")
                                        .read_bytes()).hexdigest())

        # No forbidden classification vocabulary anywhere in the evidence.
        for bad in ("pure", "portable", "supported", "safe"):
            self.assertNotIn(bad, text.lower())

    def test_generation_is_deterministic(self):
        rc1 = run_main(self.out_dir)
        other = Path(tempfile.mkdtemp(prefix="w04_det_"))
        self.addCleanup(lambda: __import__("shutil").rmtree(other,
                                                             ignore_errors=True))
        rc2 = run_main(other)
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)
        for name in gen.OWNED_NAMES:
            a = (self.out_dir / name).read_bytes()
            b = (other / name).read_bytes()
            self.assertEqual(a, b, f"{name} is not deterministic")

    def test_unpinned_input_hard_fails_before_writing(self):
        bogus = self.out_dir / "bogus.bin"
        bogus.write_bytes(b"MZ not the real DLL")
        rc = gen.main(["--dll", str(bogus), "--function-index",
                       str(INDEX_PATH), "--output-dir", str(self.out_dir)])
        self.assertEqual(rc, 1)
        self.assertEqual(list(self.out_dir.glob("startup_*")), [])

    def test_failure_leaves_existing_outputs_unchanged(self):
        self.assertEqual(run_main(self.out_dir), 0)
        before_slots = (self.out_dir / gen.SLOTS_NAME).read_bytes()
        before_sum = (self.out_dir / gen.SUMMARY_NAME).read_bytes()
        broken_dll = self.out_dir / "trunc.bin"
        broken_dll.write_bytes(dll_bytes()[: len(dll_bytes()) // 3])
        argv = ["--dll", str(broken_dll), "--function-index", str(INDEX_PATH),
                "--output-dir", str(self.out_dir)]
        err_ctx = _capture_stderr()
        with err_ctx:
            rc = gen.main(argv)
        self.assertEqual(rc, 1)
        self.assertTrue(err_ctx.getvalue().strip(), "expected stderr diagnostic")
        self.assertEqual((self.out_dir / gen.SLOTS_NAME).read_bytes(), before_slots)
        self.assertEqual((self.out_dir / gen.SUMMARY_NAME).read_bytes(), before_sum)

    # ---- check mode --------------------------------------------------

    def test_check_mode_passes_after_generation(self):
        self.assertEqual(run_main(self.out_dir), 0)
        self.assertEqual(run_main(self.out_dir, check=True), 0)

    def test_check_mode_detects_output_mutation(self):
        self.assertEqual(run_main(self.out_dir), 0)
        slots = self.out_dir / gen.SLOTS_NAME
        data = bytearray(slots.read_bytes())
        data[-3] = ord("9") if data[-3] != ord("9") else ord("8")
        slots.write_bytes(bytes(data))
        ctx = _capture_stderr()
        with ctx:
            rc = run_main(self.out_dir, check=True)
        self.assertEqual(rc, 1)
        self.assertIn("changed output", ctx.getvalue())

    def test_check_mode_detects_missing_output(self):
        self.assertEqual(run_main(self.out_dir), 0)
        (self.out_dir / gen.SUMMARY_NAME).unlink()
        ctx = _capture_stderr()
        with ctx:
            rc = run_main(self.out_dir, check=True)
        self.assertEqual(rc, 1)
        self.assertIn("missing output", ctx.getvalue())

    def test_check_mode_preserves_timestamps_and_is_read_only(self):
        self.assertEqual(run_main(self.out_dir), 0)
        paths = [self.out_dir / n for n in gen.OWNED_NAMES]
        before = {p: os.stat(p) for p in paths}
        listing_before = sorted(os.listdir(self.out_dir))
        self.assertEqual(run_main(self.out_dir, check=True), 0)
        for p in paths:
            st_after = os.stat(p)
            self.assertEqual(st_after.st_mtime_ns, before[p].st_mtime_ns,
                             f"{p.name} timestamp changed during --check")
            self.assertEqual(st_after.st_size, before[p].st_size)
        self.assertEqual(sorted(os.listdir(self.out_dir)), listing_before)

    def test_check_mode_ignores_unrelated_files(self):
        self.assertEqual(run_main(self.out_dir), 0)
        stray = self.out_dir / "startup_legacy.tsv"
        stray.write_bytes(b"stale\n")
        self.assertEqual(run_main(self.out_dir, check=True), 0)
        self.assertEqual(stray.read_bytes(), b"stale\n")

    def test_unknown_option_is_rejected(self):
        with self.assertRaises(SystemExit) as cm:
            gen.main(["--dll", str(DLL_PATH), "--function-index",
                      str(INDEX_PATH), "--output-dir", str(self.out_dir),
                      "--bogus"])
        self.assertEqual(cm.exception.code, 2)


@unittest.skipUnless(DLL_PATH.is_file(), "production corpus not present")
class PeParsingNegativeTests(unittest.TestCase):

    def test_truncated_pe_fails(self):
        data = dll_bytes()
        with self.assertRaises(gen.AuditError):
            gen.parse_pe(data[: len(data) // 2])
        with self.assertRaises(gen.AuditError):
            gen.parse_pe(data[:0x30])

    def test_wrong_machine_fails(self):
        data = bytearray(dll_bytes())
        off = struct.unpack_from("<I", data, 0x3C)[0] + 4
        struct.pack_into("<H", data, off, 0x8664)
        with self.assertRaises(gen.AuditError) as cm:
            gen.parse_pe(bytes(data))
        self.assertIn("machine", str(cm.exception))

    def test_wrong_optional_header_magic_fails(self):
        data = bytearray(dll_bytes())
        off = struct.unpack_from("<I", data, 0x3C)[0] + 4 + 20
        struct.pack_into("<H", data, off, 0x020B)
        with self.assertRaises(gen.AuditError) as cm:
            gen.parse_pe(bytes(data))
        self.assertIn("magic", str(cm.exception))

    def test_wrong_image_base_fails(self):
        data = bytearray(dll_bytes())
        off = struct.unpack_from("<I", data, 0x3C)[0] + 4 + 20 + 28
        struct.pack_into("<I", data, off, 0x00400000)
        with self.assertRaises(gen.AuditError) as cm:
            gen.parse_pe(bytes(data))
        self.assertIn("image base", str(cm.exception))


class IndexNegativeTests(TempDirTestCase):

    @staticmethod
    def _minimal_index():
        return ("entry\tcanonical_name\tsignature\n"
                "10002070\tdecomp_fn_10002070\tundefined FUN_10002070(void)\n")

    def test_duplicate_entries_fail(self):
        text = self._minimal_index()
        dup_line = "10002092\tdecomp_fn_10002092\t-\n"
        text += dup_line + dup_line
        p = self.out_dir / "idx.tsv"
        p.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(gen.AuditError, "duplicate entry"):
            gen.parse_index(p.read_bytes())

    def test_malformed_entry_digits_fail(self):
        for bad in ("1000207", "100020700", "10002O70", "1000207A"):
            line = bad + "\tname\tx\n"
            p = self.out_dir / "idx.tsv"
            p.write_text(self._minimal_index() + line, encoding="utf-8")
            with self.assertRaises(gen.AuditError):
                gen.parse_index(p.read_bytes())

    def test_missing_required_columns_fail(self):
        p = self.out_dir / "idx.tsv"
        p.write_text("entry\tsignature\n10002070\tf(void)\n", encoding="utf-8")
        with self.assertRaisesRegex(gen.AuditError, "canonical_name"):
            gen.parse_index(p.read_bytes())


class SyntheticPeTests(unittest.TestCase):
    """Minimal hand-built PE32 images exercising mapping/characteristic rules."""

    HDRS_SIZE = 0x40 + 4 + 20 + 224  # DOS + PE sig + COFF + opt32
    SEC_HDR = 40
    EXEC_CHARS = 0x60000020   # CODE | MEM_EXECUTE | MEM_READ
    DATA_CHARS = 0x40000040   # INITIALIZED_DATA | READ (no execute)

    @classmethod
    def build_pe(cls, sections, image_base=0x10000000, machine=0x014C):
        """sections: list of dicts name/vaddr/vsize/rawptr/rawsize/chars.

        Returns (bytes, table_va) where table_va is base+0x1000 laid out to
        hold four DWORD slots inside the first section.
        """
        file_len = max(s["rawptr"] + s["rawsize"] for s in sections) + 16
        buf = bytearray(file_len)
        buf[0:2] = b"MZ"
        pe_off = 0x40
        struct.pack_into("<I", buf, 0x3C, pe_off)
        buf[pe_off:pe_off + 4] = b"PE\x00\x00"
        coff = pe_off + 4
        opt_size = 224
        struct.pack_into("<HHIIIHH", buf, coff, machine, len(sections),
                         0, 0, 0, opt_size, 0x2102)
        opt = coff + 20
        struct.pack_into("<H", buf, opt, 0x010B)
        struct.pack_into("<I", buf, opt + 28, image_base)
        highest_rva = max(
            s["vaddr"] + max(s.get("vsize", 0x1000), s["rawsize"])
            for s in sections
        )
        # SizeOfImage need not be alignment-perfect for these parser-focused
        # fixtures, but it must encompass every mapped section.
        struct.pack_into("<I", buf, opt + 56, highest_rva)
        sect_off = opt + opt_size
        for i, s in enumerate(sections):
            h = sect_off + i * cls.SEC_HDR
            name = s["name"].encode("ascii")[:8]
            buf[h:h + len(name)] = name
            struct.pack_into("<IIII", buf, h + 8, s.get("vsize", 0x1000),
                             s["vaddr"], s["rawsize"], s["rawptr"])
            struct.pack_into("<I", buf, h + 36, s["chars"])
        table_rva = sections[0]["vaddr"]
        # Table slots [sentinel, t1, t2, t3]; targets map inside section 0.
        t1 = image_base + table_rva + 0x800
        struct.pack_into("<4I", buf, sections[0]["rawptr"], 0, t1, t1 + 0x10,
                         t1 + 0x20)
        data = bytes(buf)
        pe = gen.parse_pe(data)
        return pe, data, image_base + table_rva

    def _base_section(self, chars):
        return {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000,
                "rawptr": 0x200, "rawsize": 0x1000, "chars": chars}

    def test_executable_target_passes(self):
        _, data, table_va = self.build_pe([self._base_section(self.EXEC_CHARS)])
        pe = gen.parse_pe(data)
        tdef = {"id": "synth", "start": table_va, "end": table_va + 16,
                "signature": "int(void)"}
        rows, info = gen.evaluate_table(pe, {}, tdef)
        self.assertEqual(info["slot_count"], 4)
        self.assertEqual(info["nonzero_count"], 3)
        self.assertEqual(info["exact_join_count"], 0)
        self.assertEqual(rows[0][4], "yes")
        self.assertTrue(all(r[7] == "yes" for r in rows[1:]))

    def test_non_executable_target_fails(self):
        _, data, table_va = self.build_pe([self._base_section(self.DATA_CHARS)])
        pe = gen.parse_pe(data)
        tdef = {"id": "synth", "start": table_va, "end": table_va + 16,
                "signature": "int(void)"}
        with self.assertRaisesRegex(gen.AuditError, "non-executable"):
            gen.evaluate_table(pe, {}, tdef)

    def test_unmappable_target_fails(self):
        """A target VA outside all section virtual ranges must hard-fail."""
        _, data, table_va = self.build_pe([self._base_section(self.EXEC_CHARS)])
        buf = bytearray(data)
        # Overwrite slot 1's target with a bogus absolute VA.
        struct.pack_into("<I", buf, 0x200 + 4, 0xDEADBEEF)
        pe = gen.parse_pe(bytes(buf))
        tdef = {"id": "synth", "start": table_va, "end": table_va + 16,
                "signature": "int(void)"}
        with self.assertRaisesRegex(
            gen.AuditError, "exceeds SizeOfImage|does not map"
        ):
            gen.evaluate_table(pe, {}, tdef)

    def test_overlapping_raw_ranges_fail(self):
        s1 = self._base_section(self.EXEC_CHARS)
        s2 = {"name": ".data", "vaddr": 0x2000, "vsize": 0x1000,
              "rawptr": 0x300, "rawsize": 0x1000, "chars": self.DATA_CHARS}
        with self.assertRaisesRegex(gen.AuditError, "overlapping raw"):
            self.build_pe([s1, s2])

    def test_raw_range_past_eof_fails(self):
        _, data, _ = self.build_pe([self._base_section(self.EXEC_CHARS)])
        buf = bytearray(data)
        sect_hdr = 0x40 + 4 + 20 + 224  # first section header offset
        struct.pack_into("<I", buf, sect_hdr + 16, 0x100000)  # SizeOfRawData
        with self.assertRaisesRegex(gen.AuditError, "past end of file"):
            gen.parse_pe(bytes(buf))

    def test_exact_join_requires_full_equality_not_nearest(self):
        _, data, table_va = self.build_pe([self._base_section(self.EXEC_CHARS)])
        pe = gen.parse_pe(data)
        t1 = table_va + 0x800  # matches the value written by build_pe
        index = {hex8(t1 + 0x10): "nearby_but_not_equal_fn"}  # exact-match decoy
        tdef = {"id": "synth", "start": table_va, "end": table_va + 16,
                "signature": "int(void)"}
        rows, info = gen.evaluate_table(pe, index, tdef)
        self.assertEqual(info["exact_join_count"], 1)
        joined = [r for r in rows if r[10] == "yes"][0]
        self.assertEqual(joined[3], hex8(t1 + 0x10))
        self.assertEqual(joined[9], "nearby_but_not_equal_fn")


def _capture_stderr():
    import io
    import contextlib

    class _ErrCapture:
        def __init__(self):
            self._buf = io.StringIO()

        def __enter__(self):
            self._ctx = contextlib.redirect_stderr(self._buf)
            self._ctx.__enter__()
            return self

        def __exit__(self, *exc):
            return self._ctx.__exit__(*exc)

        def getvalue(self):
            return self._buf.getvalue()

    return _ErrCapture()


class PublicationTransactionTests(unittest.TestCase):
    """Fault-injection gates for pair publication and read-only checking."""

    NEW_SLOTS = b"new startup slots\n"
    NEW_SUMMARY = b'{"new": true}\n'
    OLD_SLOTS = b"old startup slots\n"
    OLD_SUMMARY = b'{"old": true}\n'
    UNRELATED = b"unrelated user data\n"
    FIXED_MTIME_NS = 1_600_000_000_000_000_000

    @classmethod
    def _write_with_fixed_mtime(cls, path, payload):
        path.write_bytes(payload)
        os.utime(path, ns=(cls.FIXED_MTIME_NS, cls.FIXED_MTIME_NS))

    @staticmethod
    def _tree_snapshot(root):
        """Capture file bytes/mtime and directory presence, not dir mtimes."""
        root = Path(root)
        if not root.exists():
            return None
        snapshot = {}
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            relative = path.relative_to(root).as_posix()
            if path.is_dir():
                snapshot[relative] = ("directory",)
            else:
                status = path.stat()
                snapshot[relative] = ("file", path.read_bytes(), status.st_mtime_ns)
        return snapshot

    @classmethod
    def _seed_prior_state(cls, output_dir, owned):
        output_dir.mkdir(parents=True)
        for name, payload in owned.items():
            cls._write_with_fixed_mtime(output_dir / name, payload)
        cls._write_with_fixed_mtime(output_dir / "unrelated.keep", cls.UNRELATED)

    def test_first_and_second_replace_failures_restore_every_presence_state(self):
        from unittest import mock

        prior_states = {
            "fresh": {},
            "both": {
                gen.SLOTS_NAME: self.OLD_SLOTS,
                gen.SUMMARY_NAME: self.OLD_SUMMARY,
            },
            "slots_only": {gen.SLOTS_NAME: self.OLD_SLOTS},
            "summary_only": {gen.SUMMARY_NAME: self.OLD_SUMMARY},
        }

        with tempfile.TemporaryDirectory(prefix="startup_publish_failures_") as td:
            root = Path(td)
            for state_name, owned in prior_states.items():
                for fail_at in (1, 2):
                    with self.subTest(prior=state_name, replace=fail_at):
                        output_dir = root / f"{state_name}-{fail_at}"
                        self._seed_prior_state(output_dir, owned)
                        before = self._tree_snapshot(output_dir)
                        real_replace = gen.os.replace
                        calls = {"forward": 0, "failed": False}

                        def flaky_replace(source, destination):
                            source_name = Path(source).name
                            if source_name.startswith("new-"):
                                calls["forward"] += 1
                                if calls["forward"] == fail_at and not calls["failed"]:
                                    calls["failed"] = True
                                    raise OSError(5, f"injected forward replace {fail_at}")
                            return real_replace(source, destination)

                        with mock.patch.object(
                            gen.os, "replace", side_effect=flaky_replace
                        ):
                            with self.assertRaisesRegex(
                                gen.AuditError, "prior outputs were restored"
                            ):
                                gen.write_outputs(
                                    output_dir, self.NEW_SLOTS, self.NEW_SUMMARY
                                )

                        self.assertTrue(calls["failed"])
                        self.assertEqual(calls["forward"], fail_at)
                        self.assertEqual(self._tree_snapshot(output_dir), before)
                        self.assertEqual(gen._reserved_entries(output_dir), [])

    def test_rollback_failure_preserves_lock_transaction_and_old_bytes(self):
        from unittest import mock

        with tempfile.TemporaryDirectory(prefix="startup_recovery_required_") as td:
            output_dir = Path(td) / "out"
            self._seed_prior_state(
                output_dir,
                {
                    gen.SLOTS_NAME: self.OLD_SLOTS,
                    gen.SUMMARY_NAME: self.OLD_SUMMARY,
                },
            )
            real_replace = gen.os.replace
            injected = {"primary": False, "rollback": False}

            def broken_publish_and_rollback(source, destination):
                source_name = Path(source).name
                if source_name.startswith("new-1-") and not injected["primary"]:
                    injected["primary"] = True
                    raise OSError(5, "injected second publication failure")
                if (
                    injected["primary"]
                    and source_name.startswith("old-0-")
                    and not injected["rollback"]
                ):
                    injected["rollback"] = True
                    raise OSError(5, "injected slots rollback failure")
                return real_replace(source, destination)

            with mock.patch.object(
                gen.os, "replace", side_effect=broken_publish_and_rollback
            ):
                with self.assertRaises(gen.RecoveryRequired) as caught:
                    gen.write_outputs(output_dir, self.NEW_SLOTS, self.NEW_SUMMARY)

            self.assertTrue(injected["primary"])
            self.assertTrue(injected["rollback"])
            self.assertIn("preserved", str(caught.exception))
            self.assertTrue((output_dir / gen.LOCK_NAME).is_file())
            transaction_dirs = [
                path
                for path in output_dir.iterdir()
                if path.is_dir() and path.name.startswith(gen.TRANSACTION_PREFIX)
            ]
            self.assertEqual(len(transaction_dirs), 1)
            transaction_dir = transaction_dirs[0]
            self.assertEqual(
                (transaction_dir / f"old-0-{gen.SLOTS_NAME}").read_bytes(),
                self.OLD_SLOTS,
            )
            self.assertEqual(
                (transaction_dir / f"new-1-{gen.SUMMARY_NAME}").read_bytes(),
                self.NEW_SUMMARY,
            )
            self.assertEqual((output_dir / gen.SLOTS_NAME).read_bytes(), self.NEW_SLOTS)
            self.assertEqual(
                (output_dir / gen.SUMMARY_NAME).read_bytes(), self.OLD_SUMMARY
            )
            self.assertEqual(
                (output_dir / "unrelated.keep").read_bytes(), self.UNRELATED
            )
            self.assertEqual(
                set(gen._reserved_entries(output_dir)),
                {gen.LOCK_NAME, transaction_dir.name},
            )

    def test_reserved_artifacts_block_publication_without_touching_tree(self):
        from unittest import mock

        with tempfile.TemporaryDirectory(prefix="startup_reserved_artifacts_") as td:
            root = Path(td)
            for artifact_kind in ("lock", "transaction"):
                with self.subTest(artifact=artifact_kind):
                    output_dir = root / artifact_kind
                    self._seed_prior_state(
                        output_dir,
                        {
                            gen.SLOTS_NAME: self.OLD_SLOTS,
                            gen.SUMMARY_NAME: self.OLD_SUMMARY,
                        },
                    )
                    if artifact_kind == "lock":
                        self._write_with_fixed_mtime(
                            output_dir / gen.LOCK_NAME, b"stale lock\n"
                        )
                    else:
                        transaction = output_dir / (gen.TRANSACTION_PREFIX + "stale")
                        transaction.mkdir()
                        self._write_with_fixed_mtime(
                            transaction / "recovery-evidence", b"preserve me\n"
                        )
                    before = self._tree_snapshot(output_dir)

                    with mock.patch.object(
                        gen, "_acquire_lock", side_effect=AssertionError("lock acquired")
                    ), mock.patch.object(
                        gen, "_write_fsynced", side_effect=AssertionError("file staged")
                    ), mock.patch.object(
                        gen.os, "replace", side_effect=AssertionError("file replaced")
                    ):
                        with self.assertRaisesRegex(
                            gen.AuditError, "reserved publication artifact"
                        ):
                            gen.write_outputs(
                                output_dir, self.NEW_SLOTS, self.NEW_SUMMARY
                            )

                    self.assertEqual(self._tree_snapshot(output_dir), before)

    def test_successful_publication_preserves_unrelated_file_and_cleans_state(self):
        with tempfile.TemporaryDirectory(prefix="startup_publish_success_") as td:
            output_dir = Path(td) / "out"
            self._seed_prior_state(
                output_dir,
                {
                    gen.SLOTS_NAME: self.OLD_SLOTS,
                    gen.SUMMARY_NAME: self.OLD_SUMMARY,
                },
            )
            unrelated = output_dir / "unrelated.keep"
            unrelated_before = (unrelated.read_bytes(), unrelated.stat().st_mtime_ns)

            gen.write_outputs(output_dir, self.NEW_SLOTS, self.NEW_SUMMARY)

            self.assertEqual((output_dir / gen.SLOTS_NAME).read_bytes(), self.NEW_SLOTS)
            self.assertEqual(
                (output_dir / gen.SUMMARY_NAME).read_bytes(), self.NEW_SUMMARY
            )
            self.assertEqual(
                (unrelated.read_bytes(), unrelated.stat().st_mtime_ns),
                unrelated_before,
            )
            self.assertEqual(
                {path.name for path in output_dir.iterdir()},
                {gen.SLOTS_NAME, gen.SUMMARY_NAME, "unrelated.keep"},
            )
            self.assertEqual(gen._reserved_entries(output_dir), [])

    def test_check_mode_never_calls_mutators_and_preserves_every_scenario(self):
        import contextlib
        from unittest import mock

        expected_slots, expected_summary = gen.compute_streams(
            DLL_PATH.read_bytes(),
            INDEX_PATH.read_bytes(),
            Path(gen.__file__).read_bytes(),
        )
        scenarios = {
            "matching": "success",
            "unrelated": "success",
            "mutated": "failure",
            "missing": "failure",
            "reserved": "failure",
            "absent_directory": "failure",
        }

        def forbidden(*_args, **_kwargs):
            raise AssertionError("--check invoked a filesystem mutator")

        mutators = (
            (gen, "write_outputs"),
            (gen, "_write_fsynced"),
            (gen, "_acquire_lock"),
            (gen, "_cleanup_transaction"),
            (gen.tempfile, "mkstemp"),
            (gen.tempfile, "mkdtemp"),
            (gen.shutil, "rmtree"),
            (gen.os, "replace"),
            (gen.os, "unlink"),
            (gen.os, "rmdir"),
            (gen.os, "mkdir"),
            (gen.os, "makedirs"),
            (gen.os, "utime"),
            (Path, "write_bytes"),
            (Path, "write_text"),
            (Path, "touch"),
            (Path, "mkdir"),
            (Path, "unlink"),
            (Path, "replace"),
            (Path, "rename"),
        )

        with tempfile.TemporaryDirectory(prefix="startup_check_read_only_") as td:
            root = Path(td)
            for scenario, outcome in scenarios.items():
                with self.subTest(scenario=scenario):
                    output_dir = root / scenario
                    if scenario != "absent_directory":
                        output_dir.mkdir()
                        (output_dir / gen.SLOTS_NAME).write_bytes(expected_slots)
                        if scenario != "missing":
                            (output_dir / gen.SUMMARY_NAME).write_bytes(expected_summary)
                        if scenario == "mutated":
                            (output_dir / gen.SLOTS_NAME).write_bytes(
                                expected_slots + b"mutated\n"
                            )
                        if scenario == "unrelated":
                            self._write_with_fixed_mtime(
                                output_dir / "unrelated.keep", self.UNRELATED
                            )
                        if scenario == "reserved":
                            self._write_with_fixed_mtime(
                                output_dir / gen.LOCK_NAME, b"stale lock\n"
                            )

                    before = self._tree_snapshot(output_dir)
                    with contextlib.ExitStack() as stack:
                        for owner, attribute in mutators:
                            stack.enter_context(
                                mock.patch.object(
                                    owner, attribute, side_effect=forbidden
                                )
                            )
                        if outcome == "success":
                            self.assertEqual(
                                gen.run_check(DLL_PATH, INDEX_PATH, output_dir), 0
                            )
                        else:
                            with self.assertRaises(gen.AuditError):
                                gen.run_check(DLL_PATH, INDEX_PATH, output_dir)
                    self.assertEqual(self._tree_snapshot(output_dir), before)


class StaticHardeningTests(unittest.TestCase):
    """Adversarial parser, mapping, publication, and CLI regression gates."""

    SECTION_TABLE_OFFSET = SyntheticPeTests.HDRS_SIZE

    @staticmethod
    def _section(
        name=".text",
        vaddr=0x1000,
        vsize=0x1000,
        rawptr=0x200,
        rawsize=0x1000,
        chars=SyntheticPeTests.EXEC_CHARS,
    ):
        return {
            "name": name,
            "vaddr": vaddr,
            "vsize": vsize,
            "rawptr": rawptr,
            "rawsize": rawsize,
            "chars": chars,
        }

    @classmethod
    def _valid_pe(cls):
        return SyntheticPeTests.build_pe([cls._section()])

    def test_declared_optional_headers_below_required_width_are_rejected(self):
        _, data, _ = self._valid_pe()
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        for declared_width in (68, 95):
            with self.subTest(declared_width=declared_width):
                malformed = bytearray(data)
                struct.pack_into("<H", malformed, e_lfanew + 20, declared_width)
                with self.assertRaisesRegex(
                    gen.AuditError, "optional header incomplete"
                ):
                    gen.parse_pe(bytes(malformed))

    def test_section_count_zero_and_over_policy_limit_are_rejected(self):
        _, data, _ = self._valid_pe()
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        for count in (0, 97):
            with self.subTest(count=count):
                malformed = bytearray(data)
                struct.pack_into("<H", malformed, e_lfanew + 6, count)
                with self.assertRaisesRegex(
                    gen.AuditError, f"invalid PE section count {count}"
                ):
                    gen.parse_pe(bytes(malformed))

    def test_overlapping_rva_mappings_with_disjoint_raw_ranges_are_rejected(self):
        sections = [
            self._section(
                name=".text",
                vaddr=0x1000,
                vsize=0x1000,
                rawptr=0x200,
                rawsize=0x1000,
            ),
            self._section(
                name=".data",
                vaddr=0x1800,
                vsize=0x400,
                rawptr=0x1400,
                rawsize=0x400,
                chars=SyntheticPeTests.DATA_CHARS,
            ),
        ]
        with self.assertRaisesRegex(gen.AuditError, "overlapping RVA"):
            SyntheticPeTests.build_pe(sections)

    def test_four_byte_slot_crossing_raw_extent_is_rejected(self):
        pe, _, table_va = SyntheticPeTests.build_pe(
            [self._section(vsize=0x1000, rawsize=0x22)]
        )
        table = {
            "id": "crosses_raw_boundary",
            "start": table_va + 0x20,
            "end": table_va + 0x24,
            "signature": "int __cdecl(void)",
        }
        with self.assertRaisesRegex(gen.AuditError, "not fully raw-backed"):
            gen.evaluate_table(pe, {}, table)

    def test_duplicate_section_names_do_not_alias_execute_flags(self):
        sections = [
            self._section(name=".same"),
            self._section(
                name=".same",
                vaddr=0x2000,
                rawptr=0x1200,
                chars=SyntheticPeTests.DATA_CHARS,
            ),
        ]
        _, data, table_va = SyntheticPeTests.build_pe(sections)
        malformed = bytearray(data)
        non_executable_target = gen.IMAGE_BASE + sections[1]["vaddr"] + 0x20
        struct.pack_into(
            "<I", malformed, sections[0]["rawptr"] + 4, non_executable_target
        )
        pe = gen.parse_pe(bytes(malformed))
        table = {
            "id": "duplicate_name_flags",
            "start": table_va,
            "end": table_va + 16,
            "signature": "int __cdecl(void)",
        }
        with self.assertRaisesRegex(gen.AuditError, "non-executable"):
            gen.evaluate_table(pe, {}, table)

    def test_empty_non_ascii_and_tab_section_names_are_rejected(self):
        _, data, _ = self._valid_pe()
        cases = (
            ("empty", b"\x00" * 8, "empty name"),
            ("non_ascii", b".\xffbad\x00\x00\x00", "not ASCII"),
            ("tab", b".te\txt\x00\x00", "TSV delimiter"),
        )
        for case, raw_name, diagnostic in cases:
            with self.subTest(case=case):
                malformed = bytearray(data)
                malformed[
                    self.SECTION_TABLE_OFFSET:self.SECTION_TABLE_OFFSET + 8
                ] = raw_name
                with self.assertRaisesRegex(gen.AuditError, diagnostic):
                    gen.parse_pe(bytes(malformed))

    def test_index_duplicate_header_and_row_width_mismatches_are_rejected(self):
        cases = (
            (
                "duplicate_header",
                b"entry\tcanonical_name\tentry\n10001000\tfn\t10001000\n",
                "duplicate columns",
            ),
            (
                "extra_field",
                b"entry\tcanonical_name\n10001000\tfn\textra\n",
                "3 fields, expected 2",
            ),
            (
                "missing_field",
                b"entry\tcanonical_name\n10001000\n",
                "1 fields, expected 2",
            ),
        )
        for case, payload, diagnostic in cases:
            with self.subTest(case=case):
                with self.assertRaisesRegex(gen.AuditError, diagnostic):
                    gen.parse_index(payload)

    def test_index_interior_blank_row_and_blank_name_are_rejected(self):
        cases = (
            (
                "interior_blank",
                (
                    b"entry\tcanonical_name\n"
                    b"10001000\tfirst\n"
                    b"\n"
                    b"10001010\tsecond\n"
                ),
                "blank row",
            ),
            (
                "blank_name",
                b"entry\tcanonical_name\n10001000\t\n",
                "blank canonical_name",
            ),
        )
        for case, payload, diagnostic in cases:
            with self.subTest(case=case):
                with self.assertRaisesRegex(gen.AuditError, diagnostic):
                    gen.parse_index(payload)

    def test_crlf_function_index_is_accepted(self):
        payload = (
            b"entry\tcanonical_name\r\n"
            b"10001000\tfirst\r\n"
            b"10001010\tsecond\r\n"
        )
        self.assertEqual(
            gen.parse_index(payload),
            {"10001000": "first", "10001010": "second"},
        )

    def test_utf8_canonical_name_round_trips_into_rendered_tsv(self):
        pe, _, table_va = self._valid_pe()
        target = table_va + 0x800
        canonical_name = "初期化_é"
        index = gen.parse_index(
            (
                "entry\tcanonical_name\r\n"
                f"{hex8(target)}\t{canonical_name}\r\n"
            ).encode("utf-8")
        )
        rows, info = gen.evaluate_table(
            pe,
            index,
            {
                "id": "utf8_name",
                "start": table_va,
                "end": table_va + 16,
                "signature": "void __cdecl(void)",
            },
        )
        matching_rows = [row for row in rows if row[10] == "yes"]
        self.assertEqual(info["exact_join_count"], 1)
        self.assertEqual(len(matching_rows), 1)
        self.assertEqual(matching_rows[0][9], canonical_name)

        rendered = gen.render_tsv(rows)
        self.assertFalse(rendered.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", rendered)
        self.assertIn(canonical_name.encode("utf-8"), rendered)
        self.assertEqual(rendered.decode("utf-8").count(canonical_name), 1)

    def test_owned_output_symlink_is_rejected_without_touching_targets(self):
        old_target = b"external target must remain unchanged\n"
        unrelated_payload = b"unrelated output-directory entry\n"
        with tempfile.TemporaryDirectory(prefix="startup_owned_symlink_") as td:
            root = Path(td)
            output_dir = root / "out"
            output_dir.mkdir()
            external_target = root / "external-slots.tsv"
            external_target.write_bytes(old_target)
            unrelated = output_dir / "unrelated.keep"
            unrelated.write_bytes(unrelated_payload)
            owned_link = output_dir / gen.SLOTS_NAME
            try:
                os.symlink(external_target, owned_link)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"file symlinks unavailable: {exc}")
            if not owned_link.is_symlink():
                self.skipTest("file symlink creation did not produce a symlink")

            with self.assertRaisesRegex(
                gen.AuditError, "owned output is not a regular file"
            ):
                gen.write_outputs(output_dir, b"new slots\n", b"{}\n")

            self.assertTrue(owned_link.is_symlink())
            self.assertEqual(external_target.read_bytes(), old_target)
            self.assertEqual(unrelated.read_bytes(), unrelated_payload)
            self.assertFalse((output_dir / gen.SUMMARY_NAME).exists())
            self.assertEqual(gen._reserved_entries(output_dir), [])

    def test_argparse_rejects_long_option_abbreviations(self):
        parser = gen.build_parser()
        self.assertFalse(parser.allow_abbrev)
        with _capture_stderr():
            with self.assertRaises(SystemExit) as caught:
                parser.parse_args(
                    [
                        "--dll",
                        "input.dll",
                        "--function-ind",
                        "index.tsv",
                        "--output-dir",
                        "audit",
                    ]
                )
        self.assertEqual(caught.exception.code, 2)


class PublicationEdgeCaseTests(unittest.TestCase):
    """Recovery-evidence and host-filesystem publication edge cases."""

    NEW_SLOTS = b"edge-case new startup slots\n"
    NEW_SUMMARY = b'{"edge_case": "new"}\n'
    OLD_SLOTS = b"edge-case old startup slots\n"
    OLD_SUMMARY = b'{"edge_case": "old"}\n'

    @classmethod
    def _seed_owned_pair(cls, output_dir):
        output_dir.mkdir(parents=True)
        (output_dir / gen.SLOTS_NAME).write_bytes(cls.OLD_SLOTS)
        (output_dir / gen.SUMMARY_NAME).write_bytes(cls.OLD_SUMMARY)

    def test_rollback_verification_io_errors_preserve_recovery_evidence(self):
        from unittest import mock

        with tempfile.TemporaryDirectory(
            prefix="startup_rollback_verify_errors_"
        ) as td:
            root = Path(td)
            for error_type in (OSError, PermissionError):
                with self.subTest(error_type=error_type.__name__):
                    output_dir = root / error_type.__name__
                    self._seed_owned_pair(output_dir)
                    slots_path = output_dir / gen.SLOTS_NAME
                    state = {
                        "forward_count": 0,
                        "primary_failed": False,
                        "rollback_completed": False,
                        "verification_failed": False,
                    }
                    real_replace = gen.os.replace
                    real_read_bytes = Path.read_bytes

                    def fail_second_forward_replace(source, destination):
                        source_name = Path(source).name
                        if source_name.startswith("new-"):
                            state["forward_count"] += 1
                            if state["forward_count"] == 2:
                                state["primary_failed"] = True
                                raise OSError(
                                    5, "injected second forward replace failure"
                                )
                        result = real_replace(source, destination)
                        if (
                            state["primary_failed"]
                            and source_name.startswith("old-0-")
                        ):
                            state["rollback_completed"] = True
                        return result

                    def fail_rollback_verification(path):
                        if (
                            state["rollback_completed"]
                            and Path(path) == slots_path
                            and not state["verification_failed"]
                        ):
                            state["verification_failed"] = True
                            raise error_type(
                                13, "injected rollback verification read failure"
                            )
                        return real_read_bytes(path)

                    with mock.patch.object(
                        gen.os,
                        "replace",
                        side_effect=fail_second_forward_replace,
                    ), mock.patch.object(
                        Path,
                        "read_bytes",
                        autospec=True,
                        side_effect=fail_rollback_verification,
                    ):
                        with self.assertRaises(gen.RecoveryRequired) as caught:
                            gen.write_outputs(
                                output_dir, self.NEW_SLOTS, self.NEW_SUMMARY
                            )

                    self.assertEqual(state["forward_count"], 2)
                    self.assertTrue(state["primary_failed"])
                    self.assertTrue(state["rollback_completed"])
                    self.assertTrue(state["verification_failed"])
                    self.assertIn(
                        "rollback could not be verified", str(caught.exception)
                    )
                    self.assertIn("preserved", str(caught.exception))
                    self.assertEqual(slots_path.read_bytes(), self.OLD_SLOTS)
                    self.assertEqual(
                        (output_dir / gen.SUMMARY_NAME).read_bytes(),
                        self.OLD_SUMMARY,
                    )
                    transaction_dirs = [
                        path
                        for path in output_dir.iterdir()
                        if path.is_dir()
                        and path.name.startswith(gen.TRANSACTION_PREFIX)
                    ]
                    self.assertEqual(len(transaction_dirs), 1)
                    self.assertTrue((output_dir / gen.LOCK_NAME).is_file())
                    self.assertEqual(
                        set(gen._reserved_entries(output_dir)),
                        {gen.LOCK_NAME, transaction_dirs[0].name},
                    )

    def test_cleanup_failure_after_commit_reports_installed_new_pair(self):
        from unittest import mock

        with tempfile.TemporaryDirectory(prefix="startup_commit_cleanup_fail_") as td:
            output_dir = Path(td) / "out"
            self._seed_owned_pair(output_dir)

            with mock.patch.object(
                gen.shutil,
                "rmtree",
                side_effect=PermissionError(
                    13, "injected transaction-directory cleanup failure"
                ),
            ) as remove_tree:
                with self.assertRaises(gen.AuditError) as caught:
                    gen.write_outputs(
                        output_dir, self.NEW_SLOTS, self.NEW_SUMMARY
                    )

            message = str(caught.exception)
            self.assertIn("publication committed and verified", message)
            self.assertIn("new output pair is installed", message)
            self.assertEqual(
                (output_dir / gen.SLOTS_NAME).read_bytes(), self.NEW_SLOTS
            )
            self.assertEqual(
                (output_dir / gen.SUMMARY_NAME).read_bytes(), self.NEW_SUMMARY
            )
            remove_tree.assert_called_once()
            self.assertFalse((output_dir / gen.LOCK_NAME).exists())
            remaining = gen._reserved_entries(output_dir)
            self.assertEqual(len(remaining), 1)
            self.assertTrue(remaining[0].startswith(gen.TRANSACTION_PREFIX))

    def test_read_only_prior_output_replace_failure_cleans_reserved_state(self):
        import stat
        from unittest import mock

        with tempfile.TemporaryDirectory(prefix="startup_read_only_replace_") as td:
            root = Path(td)
            probe_source = root / "probe-source"
            probe_destination = root / "probe-destination"
            probe_source.write_bytes(b"new probe\n")
            probe_destination.write_bytes(b"old probe\n")
            probe_destination.chmod(stat.S_IREAD)
            host_rejects_replace = False
            try:
                try:
                    os.replace(probe_source, probe_destination)
                except OSError:
                    host_rejects_replace = True
            finally:
                for path in (probe_source, probe_destination):
                    if os.path.lexists(path):
                        try:
                            path.chmod(stat.S_IREAD | stat.S_IWRITE)
                        except OSError:
                            pass
                        try:
                            path.unlink()
                        except OSError:
                            pass
            if not host_rejects_replace:
                self.skipTest(
                    "host os.replace permits replacement of a read-only file"
                )

            output_dir = root / "out"
            self._seed_owned_pair(output_dir)
            slots_path = output_dir / gen.SLOTS_NAME
            summary_path = output_dir / gen.SUMMARY_NAME
            slots_path.chmod(stat.S_IREAD)
            real_replace = gen.os.replace
            replace_destinations = []

            def track_real_replace(source, destination):
                replace_destinations.append(Path(destination))
                return real_replace(source, destination)

            try:
                with mock.patch.object(
                    gen.os, "replace", side_effect=track_real_replace
                ):
                    with self.assertRaisesRegex(
                        gen.AuditError, "prior outputs were restored"
                    ):
                        gen.write_outputs(
                            output_dir, self.NEW_SLOTS, self.NEW_SUMMARY
                        )

                self.assertEqual(replace_destinations, [slots_path])
                self.assertEqual(slots_path.read_bytes(), self.OLD_SLOTS)
                self.assertEqual(summary_path.read_bytes(), self.OLD_SUMMARY)
                self.assertEqual(gen._reserved_entries(output_dir), [])
            finally:
                for path in (slots_path, summary_path):
                    if os.path.lexists(path):
                        try:
                            path.chmod(stat.S_IREAD | stat.S_IWRITE)
                        except OSError:
                            pass

    @unittest.skipUnless(DLL_PATH.is_file() and INDEX_PATH.is_file(),
                         "production corpus not present")
    def test_broken_success_stream_is_nonfatal_after_commit(self):
        from unittest import mock

        with tempfile.TemporaryDirectory(prefix="startup_broken_stdout_") as td:
            with mock.patch.object(gen, "write_outputs") as publish, \
                    mock.patch(
                        "builtins.print",
                        side_effect=[OSError(22, "injected stdout failure"), None],
                    ) as status:
                self.assertEqual(
                    gen.run_generate(DLL_PATH, INDEX_PATH, Path(td)), 0
                )

            publish.assert_called_once()
            self.assertEqual(status.call_count, 2)
            self.assertIs(status.call_args_list[1].kwargs["file"], sys.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

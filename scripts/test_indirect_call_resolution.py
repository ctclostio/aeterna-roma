#!/usr/bin/env python3
"""Public CI-safe validation and unit tests for indirect-call resolution artifacts & passes."""
from __future__ import annotations

import csv
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import extract_indirect_call_ir as eir
import resolve_indirect_calls as ric

TEXT_LO = 0x10001000
TEXT_HI = 0x1172E4EA
HEX_RE = re.compile(r"^0x[0-9a-f]{8}$")

ALLOWED_CONF = {"high", "medium", "low"}
ALLOWED_KINDS = {
    "monomorphic_internal",
    "external_import",
    "external_interface",
    "polymorphic_virtual",
    "callback_dispatch",
    "null_optional_hook",
    "non_call_trap",
}


class TrackedArtifactIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        csv.field_size_limit(max(csv.field_size_limit(), 10 * 1024 * 1024))
        cls.work = ROOT / "work"
        with open(cls.work / "indirect_calls_after.tsv", encoding="utf-8") as f:
            cls.input_rows = list(csv.DictReader(f, delimiter="\t"))
        with open(cls.work / "indirect_call_resolutions_after.tsv", encoding="utf-8") as f:
            cls.res_rows = list(csv.DictReader(f, delimiter="\t"))
        with open(cls.work / "indirect_call_target_sets_after.tsv", encoding="utf-8") as f:
            cls.ts_rows = list(csv.DictReader(f, delimiter="\t"))
        with open(cls.work / "indirect_call_vtables_after.tsv", encoding="utf-8") as f:
            cls.vt_rows = list(csv.DictReader(f, delimiter="\t"))
        with open(cls.work / "indirect_call_hierarchy_after.tsv", encoding="utf-8") as f:
            cls.hi_rows = list(csv.DictReader(f, delimiter="\t"))

    def test_exact_site_bijection_and_zero_unresolved(self) -> None:
        self.assertEqual(len(self.input_rows), 59079)
        self.assertEqual(len(self.res_rows), 59079)
        in_sites = [r["site"] for r in self.input_rows]
        res_sites = [r["site"] for r in self.res_rows]
        self.assertEqual(in_sites, res_sites)

        for row in self.res_rows:
            conf = row["confidence"]
            rkind = row["resolution_kind"]
            self.assertIn(conf, ALLOWED_CONF, msg=f"bad confidence at {row['site']}: {conf}")
            self.assertIn(rkind, ALLOWED_KINDS, msg=f"bad resolution_kind at {row['site']}: {rkind}")

    def test_target_consistency_and_text_bounds(self) -> None:
        ts_map = {r["target_set_id"]: r for r in self.ts_rows}
        self.assertEqual(len(ts_map), len(self.ts_rows))

        for row in self.res_rows:
            rkind = row["resolution_kind"]
            cnt = int(row["target_count"])
            tgt = row["resolved_target"]
            ts_id = row["target_set_id"]

            if rkind == "monomorphic_internal":
                self.assertEqual(cnt, 1, msg=row["site"])
                self.assertRegex(tgt, HEX_RE, msg=row["site"])
                va = int(tgt, 16)
                self.assertTrue(TEXT_LO <= va < TEXT_HI, msg=f"target out of .text: {tgt}")
                self.assertTrue(row["resolved_function"], msg=row["site"])
            elif rkind in ("external_import", "external_interface"):
                self.assertEqual(cnt, 1, msg=row["site"])
                self.assertTrue(tgt, msg=row["site"])
                self.assertTrue(row["resolved_function"], msg=row["site"])
            elif rkind in ("polymorphic_virtual", "callback_dispatch"):
                self.assertGreaterEqual(cnt, 2, msg=row["site"])
                self.assertEqual(tgt, "", msg=row["site"])
                self.assertIn(ts_id, ts_map, msg=row["site"])
                ts_row = ts_map[ts_id]
                self.assertEqual(int(ts_row["target_count"]), cnt)
            elif rkind in ("non_call_trap", "null_optional_hook"):
                self.assertEqual(cnt, 0, msg=row["site"])
                self.assertEqual(tgt, "", msg=row["site"])

    def test_target_sets_contain_only_valid_text_addresses(self) -> None:
        for ts in self.ts_rows:
            tgts = ts["targets"].split(";")
            self.assertEqual(len(tgts), int(ts["target_count"]))
            self.assertEqual(len(set(tgts)), len(tgts))
            for t in tgts:
                self.assertRegex(t, HEX_RE)
                va = int(t, 16)
                self.assertTrue(TEXT_LO <= va < TEXT_HI, msg=f"bad target in {ts['target_set_id']}: {t}")

    def test_vtables_and_hierarchy_integrity(self) -> None:
        seen_slots = set()
        vt_set = set()
        for r in self.vt_rows:
            vt = r["vtable"]
            off = r["slot_offset"]
            tgt = r["target"]
            self.assertRegex(vt, HEX_RE)
            self.assertRegex(tgt, HEX_RE)
            va = int(tgt, 16)
            self.assertTrue(TEXT_LO <= va < TEXT_HI, msg=f"bad vtable slot {vt}+{off}: {tgt}")
            key = (vt, off)
            self.assertNotIn(key, seen_slots)
            seen_slots.add(key)
            vt_set.add(vt)
        hi_vts = {r["vtable"] for r in self.hi_rows}
        self.assertEqual(hi_vts, vt_set)

    def test_external_imports_high_and_artifact_sizes(self) -> None:
        narrowed = 0
        for row in self.res_rows:
            if row["confidence"] in ("high", "medium"):
                narrowed += 1
            if row["resolution_kind"] == "external_import":
                self.assertEqual(
                    row["confidence"],
                    "high",
                    msg=f"non-high external_import leak at {row['site']}: {row['resolved_target']}",
                )
        self.assertGreaterEqual(narrowed, 29540)

        for fname in (
            "indirect_call_resolutions_after.tsv",
            "indirect_call_target_sets_after.tsv",
            "indirect_call_vtables_after.tsv",
            "indirect_call_hierarchy_after.tsv",
            "indirect_call_summary_after.md",
        ):
            self.assertLess((self.work / fname).stat().st_size, 25 * 1024 * 1024, msg=fname)


class IRExtractionUnitTests(unittest.TestCase):
    def test_balanced_paren_icall_and_pointer_stride(self) -> None:
        sample_c = """\
// Entry: 0x10123450
void __thiscall decomp_fn_10123450(int *param_1, float *param_2)

{
  int *piVar1;
  code *pcVar2;

  *param_1 = (int)&PTR_decomp_fn_10120000_11800000;
  piVar1 = (int *)param_1[6];
  (**(code **)(*piVar1 + 0x18))(param_2 + 2);
  pcVar2 = *(code **)(*(int *)((int)param_2 + 0x10) + 0x4);
  (*pcVar2)();
  piVar1 = (int *)(**(code **)(*piVar1 + 0xc4))();
  (**(code **)(*piVar1 + 0x20))();
  return;
}
"""
        ir = eir.extract_function_ir(sample_c, "10123450")
        self.assertEqual(ir["cc"], "__thiscall")
        self.assertEqual(len(ir["vtable_stores"]), 1)
        self.assertEqual(ir["vtable_stores"][0][2], "11800000")
        self.assertEqual(len(ir["icalls"]), 4)
        self.assertEqual(ir["icalls"][0]["slot_offset"], 0x18)
        self.assertIsNone(ir["icalls"][1]["slot_offset"])
        self.assertEqual(ir["icalls"][2]["slot_offset"], 0xC4)
        self.assertEqual(ir["icalls"][2]["lhs_var"], "piVar1")
        self.assertEqual(ir["icalls"][3]["slot_offset"], 0x20)

        # Verify pointer-stride scaling: param_1[6] -> offset 24 (6*4)
        assigns = [op for op in ir["ops"] if op[0] == "assign" and op[2] == "piVar1"]
        self.assertEqual(assigns[0][3], ("deref", ("add", ("var", "param_1"), ("const", 24))))
        # Verify `(int)param_2 + 0x10` did NOT multiply 0x10 by 4
        assigns_pc = [op for op in ir["ops"] if op[0] == "assign" and op[2] == "pcVar2"]
        self.assertEqual(
            assigns_pc[0][3],
            ("deref", ("add", ("deref", ("add", ("var", "param_2"), ("const", 16))), ("const", 4))),
        )

    def test_mi_adjust_and_alloc_implicit_this(self) -> None:
        sample_c = """\
undefined4 decomp_fn_10500000(int param_1)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;

  piVar1 = (int *)(-(uint)(param_1 != 0) & param_1 - 0x18U);
  (**(code **)(*piVar1 + 0x1c))();
  iVar2 = decomp_fn_100d12b0(0x40);
  if (iVar2 != 0) {
    uVar3 = decomp_fn_10500100();
    return uVar3;
  }
  return 0;
}
"""
        ir = eir.extract_function_ir(sample_c, "10500000")
        mi_ops = [op for op in ir["ops"] if op[0] == "assign" and op[2] == "piVar1"]
        self.assertEqual(mi_ops[0][3], ("mi_adjust", "param_1", 0x18))
        dcalls = [op for op in ir["ops"] if op[0] == "dcall" and op[2] == "10500100"]
        self.assertEqual(dcalls[0][5], "iVar2")


class AlignmentAndLatticeUnitTests(unittest.TestCase):
    def test_absval_join_and_external_peeling_alignment(self) -> None:
        a = ric.AbsVal(vts=frozenset(["11700000"]), origin="ctor_ret")
        b = ric.AbsVal(vts=frozenset(["11700010"]), origin="param_prop")
        j = a.join(b)
        self.assertEqual(j.vts, frozenset(["11700000", "11700010"]))

        class _FakePE:
            iat_map: dict[int, str] = {}

        asm_rows = [
            {"site": "10000010", "mnemonic": "CALL", "operands": "CALL ESI", "kind": "register", "offset": ""},
            {"site": "10000020", "mnemonic": "CALL", "operands": "CALL dword ptr [EAX + 0x18]", "kind": "register_offset", "offset": "0x18"},
            {"site": "10000030", "mnemonic": "INT3", "operands": "INT3", "kind": "other", "offset": ""},
        ]
        ctx_rows = [
            {"external_targets": "KERNEL32.DLL!Sleep", "reg_def_chain": ""},
            {"external_targets": "", "reg_def_chain": ""},
            {"external_targets": "", "reg_def_chain": ""},
        ]
        c_icalls = [
            {"expr": "**(code **)(*piVar1 + 0x18)", "slot_offset": 0x18, "base": "piVar1"},
        ]
        aligned = ric.align_function_sites(asm_rows, ctx_rows, c_icalls, _FakePE())  # type: ignore[arg-type]
        self.assertEqual(aligned[0][3], "external")
        self.assertIsNone(aligned[0][2])
        self.assertEqual(aligned[1][3], "exact_1to1")
        self.assertEqual(aligned[1][2]["slot_offset"], 0x18)
        self.assertEqual(aligned[2][3], "trap")


class PropagationUnitTests(unittest.TestCase):
    def test_normalize_ir_globals(self) -> None:
        ir_map = {
            "10010000": {
                "ops": [
                    ("assign", 0, "_DAT_12100000", ("const", 1)),
                    ("assign", 1, "local_4", ("const", 2)),
                ],
                "vtable_stores": [
                    (2, ("var", "DAT_12100004"), "11800000"),
                    (3, ("var", "local_8"), "11800000"),
                ],
            }
        }
        converted = ric.normalize_ir_globals(ir_map)
        self.assertEqual(converted, 2)
        self.assertEqual(ir_map["10010000"]["ops"][0], ("store", 0, ("global", "12100000"), ("const", 1)))
        self.assertEqual(ir_map["10010000"]["ops"][1], ("assign", 1, "local_4", ("const", 2)))
        self.assertEqual(ir_map["10010000"]["vtable_stores"][0], (2, ("global", "12100004"), "11800000"))

    def test_cap_join_freezes_at_limit(self) -> None:
        a = frozenset(["11700000", "11700004"])
        b = frozenset(["11700008"])
        self.assertEqual(ric._cap_join(a, b, ric.MAX_VTS_PER_VAL), a | b)

        full = frozenset(f"{0x11700000 + i * 4:08x}" for i in range(ric.MAX_VTS_PER_VAL))
        self.assertEqual(len(full), ric.MAX_VTS_PER_VAL)
        self.assertEqual(ric._cap_join(full, frozenset(["11999999"]), ric.MAX_VTS_PER_VAL), full)
        self.assertEqual(ric._cap_join(frozenset(["11999999"]), full, ric.MAX_VTS_PER_VAL), full)

    def test_propagation_stack_vstore_ptr_vts_glob_addrs_and_exref_isolation(self) -> None:
        class _FakePE:
            reloc_vas: set[int] = set()
            data_to_rdata_ptrs: dict[int, int] = {}
            data_to_text_raw: dict[int, int] = {}
            jmp_iat_thunks: dict[str, str] = {}

            def in_text(self, va: int) -> bool:
                return TEXT_LO <= va < TEXT_HI

            def read_u32(self, va: int) -> int | None:
                return None

        c_stack = """\
// Entry: 0x10020000
void decomp_fn_10020000(void)

{
  int local_60;

  local_60 = (int)&PTR_decomp_fn_10010000_11800000;
  (**(code **)(local_60 + 4))();
  decomp_fn_10020010(&local_60);
  return;
}
"""
        c_callee = """\
// Entry: 0x10020010
void decomp_fn_10020010(int *param_1)

{
  (**(code **)(*param_1 + 0))();
  return;
}
"""
        c_getter = """\
// Entry: 0x10020020
void * decomp_fn_10020020(void)

{
  return &DAT_12100100;
}
"""
        c_writer = """\
// Entry: 0x10020030
void decomp_fn_10020030(void)

{
  int *piVar1;
  int *piVar2;

  piVar1 = (int *)decomp_fn_10020020();
  piVar2 = (int *)decomp_fn_10020025();
  piVar1[2] = (int)piVar2;
  return;
}
"""
        c_reader = """\
// Entry: 0x10020040
void decomp_fn_10020040(void)

{
  int *piVar1;
  int *piVar2;

  piVar1 = (int *)decomp_fn_10020020();
  piVar2 = (int *)piVar1[2];
  (**(code **)(*piVar2 + 4))();
  return;
}
"""
        c_ptr = """\
// Entry: 0x10020050
void decomp_fn_10020050(void)

{
  int *local_4;
  int *piVar1;
  int *piVar2;

  piVar1 = (int *)decomp_fn_10020025();
  *local_4 = (int)piVar1;
  piVar2 = (int *)*local_4;
  (**(code **)(*piVar2 + 4))();
  return;
}
"""
        ir_map = {
            "10020000": eir.extract_function_ir(c_stack, "10020000"),
            "10020010": eir.extract_function_ir(c_callee, "10020010"),
            "10020020": eir.extract_function_ir(c_getter, "10020020"),
            "10020025": {
                "entry": "10020025",
                "cc": "__thiscall",
                "ret_type": "int *",
                "params": [("param_1", "int *", 4, 0)],
                "var_sizes": {},
                "icalls": [],
                "ops": [("vstore", 0, ("deref", ("var", "param_1")), "11800040"), ("ret", 1, ("var", "param_1"))],
                "vtable_stores": [(0, ("deref", ("var", "param_1")), "11800040")],
                "has_delete": False,
                "idiom_tags": [],
            },
            "10020030": eir.extract_function_ir(c_writer, "10020030"),
            "10020040": eir.extract_function_ir(c_reader, "10020040"),
            "10020050": eir.extract_function_ir(c_ptr, "10020050"),
            "10020070": {
                "entry": "10020070",
                "cc": "__thiscall",
                "ret_type": "void *",
                "params": [("param_1", "int *", 4, 0)],
                "var_sizes": {},
                "icalls": [],
                "ops": [
                    ("assign", 0, "pcVar1", ("exref", "EnterCriticalSection")),
                    ("assign", 1, "pcVar1", ("dcall", "10020025", (), None, None)),
                    ("dcall", 2, "10020080", (("var", "pcVar1"),), None, None),
                    ("store", 3, ("deref", ("add", ("var", "param_1"), ("const", 12))), ("var", "pcVar1")),
                    ("ret", 4, ("var", "pcVar1")),
                ],
                "vtable_stores": [],
                "has_delete": False,
                "idiom_tags": [],
            },
            "10020080": {
                "entry": "10020080",
                "cc": "__cdecl",
                "ret_type": "void",
                "params": [("param_1", "void *", 4, 0)],
                "var_sizes": {},
                "icalls": [],
                "ops": [],
                "vtable_stores": [],
                "has_delete": False,
                "idiom_tags": [],
            },
        }
        vt_slots = {
            "11800000": {0: "10010000", 4: "10010010"},
            "11800040": {0: "10010020", 4: "10010030"},
        }
        hier = {
            "fn_to_vts": {"10020070": [("11800000", 0)]},
            "subobj_of": {},
            "primary_of": {},
            "ancestors": {},
            "descendants": {},
            "vt_to_family": {"11800000": "11800000", "11800040": "11800040"},
            "family_members": {"11800000": {"11800000"}, "11800040": {"11800040"}},
            "ctor_vtable": {"10020025": "11800040"},
            "icf_stubs": set(),
            "fn_is_dtor": set(),
        }
        res = ric.run_propagation(_FakePE(), ir_map, vt_slots, hier, {})  # type: ignore[arg-type]

        # Stack object direct dispatch & &local_60 propagation
        fnptr_s, recv_s = res["icall_results"]["10020000"][0]
        self.assertEqual(recv_s.vts, frozenset(["11800000"]))
        self.assertEqual(fnptr_s.fn_ptrs, frozenset(["10010010"]))
        fnptr_c, recv_c = res["icall_results"]["10020010"][0]
        self.assertEqual(recv_c.vts, frozenset(["11800000"]))
        self.assertEqual(fnptr_c.fn_ptrs, frozenset(["10010000"]))

        # Singleton getter glob_addrs + field store/read propagation
        fnptr_g, recv_g = res["icall_results"]["10020040"][0]
        self.assertEqual(recv_g.vts, frozenset(["11800040"]))
        self.assertEqual(fnptr_g.fn_ptrs, frozenset(["10010030"]))

        # Pointer-to-pointer ptr_vts propagation through deref
        fnptr_p, recv_p = res["icall_results"]["10020050"][0]
        self.assertEqual(recv_p.vts, frozenset(["11800040"]))
        self.assertEqual(fnptr_p.fn_ptrs, frozenset(["10010030"]))

        # Unqualified exref isolation (must not leak via return, param, or field)
        ret_70 = res["fn_return_types"].get("10020070", ric.EMPTY_VAL)
        self.assertEqual(ret_70.ext_fns, frozenset())
        self.assertEqual(ret_70.vts, frozenset(["11800040"]))
        p_80 = res["fn_param_types"].get("10020080", {}).get(0, ric.EMPTY_VAL)
        self.assertEqual(p_80.ext_fns, frozenset())
        self.assertEqual(p_80.vts, frozenset(["11800040"]))
        fld_12 = res["field_types"].get(("11800000", 12), ric.EMPTY_VAL)
        self.assertEqual(fld_12.ext_fns, frozenset())
        self.assertEqual(fld_12.vts, frozenset(["11800040"]))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Independent, inert instruction/field evidence for the normal terminal seam.

No candidate module is read or imported. The unchanged entry-tail oracle supplies
only PE/corpus readers; expected fields below come from instruction encodings and
are cross-checked against the pinned design report. No DLL is loaded/executed,
no guest memory is dereferenced, and opaque value=0 is NOT a recovered value.
Widths are record vocabulary: data bytes, branch encoding bytes, or zero for
call-shape/RETURN. They are not a universal instruction-size/stack-effect field.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, replace
import hashlib
import struct
import unittest
from pathlib import Path

import test_x64_startup_100edd70_entry_tail_provenance as corpus

ROOT = Path(__file__).resolve().parent.parent
ORACLE = ROOT / "scripts/test_x64_startup_100edd70_entry_tail_provenance.py"
DESIGN = ROOT / "out/pi-swarm/20260901-entry-tail-design/transcript/report.md"
ORACLE_PIN = (14903, "b272dc06372698d9dc73ef85da8c6351927a1f29c0d4c375def5d6a6331d1e86")
DESIGN_PIN = (10114, "28661c05406ca60145047fb96a1d40f29ce2e284f8f67d36a1c70e405e429c4f")


@dataclass(frozen=True)
class Fields:
    kind: str
    pc: int
    target: int = 0
    source: int = 0
    displacement: int = 0
    destination: str = "none"
    value: int = 0  # unused/opaque unless value_known
    width: int = 0
    source_register: str = "none"  # explicit instruction evidence, not API ordinal
    value_known: bool = False


# Each row is a separate physical instruction. String identities intentionally do
# not import or freeze candidate enums. FS_ZERO_STORE means OFFSET zero, not a
# store of the immediate zero. The source is ECX and its contents are unknown.
SITES = (
    ("c745fcffffffff", Fields("TAIL_FRAME_STORE", 0x100EDF41,
        displacement=-4, destination="frame", value=0xFFFFFFFF, width=4, value_known=True)),
    ("eb4a", Fields("BRANCH", 0x100EDF48, target=0x100EDF94, width=2)),
    ("ff1534f97211", Fields("IMPORTED_CALL_SHAPE", 0x100EDF94, target=0x1172F934)),
    ("a044319f11", Fields("GLOBAL_BYTE_LOAD", 0x100EDF9A,
        source=0x119F3144, destination="AL", width=1)),
    ("8b4df0", Fields("SEH_SLOT_LOAD", 0x100EDF9F,
        displacement=-16, destination="ECX", width=4, source_register="EBP")),
    ("64890d00000000", Fields("FS_ZERO_STORE", 0x100EDFA2,
        destination="fs:[0]", width=4, source_register="ECX")),
    ("5f", Fields("POP_EDI", 0x100EDFA9, destination="EDI", width=4)),
    ("5e", Fields("POP_ESI", 0x100EDFAA, destination="ESI", width=4)),
    ("5b", Fields("POP_EBX", 0x100EDFAB, destination="EBX", width=4)),
    ("8be5", Fields("TEARDOWN_MOV_ESP_EBP", 0x100EDFAC,
        destination="ESP", width=4, source_register="EBP")),
    ("5d", Fields("TEARDOWN_POP_EBP", 0x100EDFAE, destination="EBP", width=4)),
    ("c3", Fields("RETURN", 0x100EDFAF)),
)
REG32 = ("EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI")


def decode(pc: int, code: bytes) -> Fields:
    """Bounded PE32 syntax decoder; not an emulator or general disassembler."""
    if len(code) == 7 and code[:2] == b"\xc7\x45":
        return Fields("TAIL_FRAME_STORE", pc, displacement=struct.unpack("b", code[2:3])[0],
                      destination="frame", value=int.from_bytes(code[3:], "little"),
                      width=4, value_known=True)
    if len(code) == 2 and code[0] == 0xEB:
        return Fields("BRANCH", pc, target=pc + 2 + struct.unpack("b", code[1:])[0], width=2)
    if len(code) == 6 and code[:2] == b"\xff\x15":
        return Fields("IMPORTED_CALL_SHAPE", pc, target=int.from_bytes(code[2:], "little"))
    if len(code) == 5 and code[0] == 0xA0:
        return Fields("GLOBAL_BYTE_LOAD", pc, source=int.from_bytes(code[1:], "little"),
                      destination="AL", width=1)
    if len(code) == 3 and code[0] == 0x8B and code[1] & 0xC7 == 0x45:
        return Fields("SEH_SLOT_LOAD", pc, displacement=struct.unpack("b", code[2:])[0],
                      destination=REG32[(code[1] >> 3) & 7], width=4, source_register="EBP")
    if len(code) == 7 and code[:2] == b"\x64\x89" and code[2] & 0xC7 == 5:
        address = int.from_bytes(code[3:], "little")
        return Fields("FS_ZERO_STORE", pc, destination=f"fs:[{address}]", width=4,
                      source_register=REG32[(code[2] >> 3) & 7])
    if len(code) == 1 and 0x58 <= code[0] <= 0x5F:
        register = REG32[code[0] - 0x58]
        kind = "TEARDOWN_POP_EBP" if register == "EBP" else "POP_" + register
        return Fields(kind, pc, destination=register, width=4)
    if len(code) == 2 and code[0] == 0x8B and code[1] & 0xC0 == 0xC0:
        return Fields("TEARDOWN_MOV_ESP_EBP", pc, destination=REG32[(code[1] >> 3) & 7],
                      width=4, source_register=REG32[code[1] & 7])
    if code == b"\xc3":
        return Fields("RETURN", pc)
    raise ValueError("outside bounded instruction vocabulary")


def authenticate_site(pc: int, code: bytes, fields: Fields) -> None:
    matches = [(encoding, expected) for encoding, expected in SITES if expected.pc == pc]
    if len(matches) != 1:
        raise ValueError("not a terminal instruction PC")
    encoding, expected = matches[0]
    if code != bytes.fromhex(encoding) or fields != expected or decode(pc, code) != fields:
        raise ValueError("instruction bytes or field semantics differ")


def pinned(path: Path, size: int, digest: str) -> bytes:
    data = path.read_bytes()
    if (len(data), hashlib.sha256(data).hexdigest()) != (size, digest):
        raise AssertionError(f"pinned input differs: {path}")
    return data


class TerminalTranscriptProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.oracle = pinned(ORACLE, *ORACLE_PIN)
        cls.design = pinned(DESIGN, *DESIGN_PIN).decode("utf-8")
        cls.dll = pinned(corpus.DLL, corpus.DLL_SIZE, corpus.DLL_SHA256)
        cls.index = pinned(corpus.INDEX, corpus.INDEX_SIZE, corpus.INDEX_SHA256)
        cls.canonical = pinned(corpus.CANONICAL_ENTRY, corpus.CANONICAL_ENTRY_SIZE,
                               corpus.CANONICAL_ENTRY_SHA256).decode("utf-8")
        cls.optional, cls.sections = corpus.parse_pe32(cls.dll)

    def read_site(self, pc, size):
        body, section, raw, flags = corpus.read_va(self.dll, self.sections, pc, size)
        self.assertEqual((section, raw), (".text", pc - 0x10000C00))
        self.assertTrue(flags & 0x20000000)
        return body

    def test_every_exact_site_decodes_to_independent_fields(self):
        for encoding, fields in SITES:
            with self.subTest(pc=hex(fields.pc), kind=fields.kind):
                code = self.read_site(fields.pc, len(bytes.fromhex(encoding)))
                self.assertEqual(code.hex(), encoding)
                self.assertEqual(decode(fields.pc, code), fields)
                authenticate_site(fields.pc, code, fields)

    def test_two_install_ten_common_no_folding_or_extra_sites(self):
        self.assertEqual((len(SITES[:2]), len(SITES[2:])), (2, 10))
        self.assertEqual(len({f.kind for _, f in SITES}), 12)
        for subset, end in ((SITES[:2], 0x100EDF4A), (SITES[2:], 0x100EDFB0)):
            for (code, current), (_, following) in zip(subset, subset[1:]):
                self.assertEqual(current.pc + len(bytes.fromhex(code)), following.pc)
            code, last = subset[-1]
            self.assertEqual(last.pc + len(bytes.fromhex(code)), end)
        # Neither cleanup is a terminal record; skip has no synthetic branch.
        for pc, end in ((0x100EDF3E, 0x100EDF41), (0x100EDF91, 0x100EDF94)):
            self.assertEqual(self.read_site(pc, 3), bytes.fromhex("83c418"))
            self.assertEqual(pc + 3, end)
            self.assertNotIn(pc, [f.pc for _, f in SITES])
        self.assertIn("**10 records (skip terminal)**", self.design)
        for encoding, fields in SITES:
            self.assertIn(f"`0x{fields.pc:08x}`", self.design)
            self.assertIn(" ".join(encoding[i:i+2] for i in range(0, len(encoding), 2)), self.design)
            self.assertIn(f"`{fields.kind}`", self.design)

    def test_signed_frame_displacements_immediate_and_rel8(self):
        store = decode(0x100EDF41, self.read_site(0x100EDF41, 7))
        branch = decode(0x100EDF48, self.read_site(0x100EDF48, 2))
        self.assertEqual((store.displacement, store.value, store.width), (-4, 0xFFFFFFFF, 4))
        self.assertEqual(branch.target, 0x100EDF48 + 2 + 74)
        self.assertEqual(branch.target, SITES[2][1].pc)
        self.assertEqual(decode(0x100EDF48, bytes.fromhex("ebfe")).target, 0x100EDF48)
        self.assertEqual(SITES[4][1].displacement, -16)

    def test_iat_identity_is_not_a_direct_function_address_or_execution(self):
        call = decode(0x100EDF94, self.read_site(0x100EDF94, 6))
        self.assertEqual(call.target, 0x1172F934)
        self.assertEqual(corpus.imported_name_at_iat(self.dll, self.optional, self.sections,
                                                   call.target), ("ole32.dll", "CoUninitialize"))
        self.assertEqual((call.width, call.source, call.value_known), (0, 0, False))
        # Width zero is the design's argument/cleanup shape, not x86 CALL's
        # encoded length (6), pointer width (4), or a denial of its stack effect.
        self.assertIn("zero args, zero cleanup; nothing to fold", self.design)

    def test_register_directions_widths_and_fs_offset_not_value(self):
        decoded = [decode(f.pc, self.read_site(f.pc, len(bytes.fromhex(c)))) for c, f in SITES]
        self.assertEqual([(f.destination, f.source_register, f.width) for f in decoded[3:]], [
            ("AL", "none", 1), ("ECX", "EBP", 4), ("fs:[0]", "ECX", 4),
            ("EDI", "none", 4), ("ESI", "none", 4), ("EBX", "none", 4),
            ("ESP", "EBP", 4), ("EBP", "none", 4), ("none", "none", 0)])
        self.assertTrue(all(not f.value_known for f in decoded[1:]))
        self.assertIn("source ECX, width 4", self.design)

    def test_unknown_return_byte_and_target_not_early_zero_or_next_function(self):
        self.assertEqual(self.canonical.count("return DAT_119f3144;"), 1)
        self.assertEqual(self.canonical.count("return 0;"), 1)
        self.assertLess(self.canonical.index("return 0;"), self.canonical.index("pwVar4 ="))
        self.assertGreater(self.canonical.index("return DAT_119f3144;"), self.canonical.index("pwVar4 ="))
        self.assertEqual(self.read_site(0x100EDEB6, 2), bytes.fromhex("32c0"))
        self.assertEqual(self.read_site(0x100EDF9A, 5), bytes.fromhex("a044319f11"))
        returned = SITES[-1][1]
        self.assertEqual((returned.target, returned.value_known, returned.width), (0, False, 0))
        self.assertNotEqual(returned.target, returned.pc + 1)
        self.assertIn("never claims the byte value", self.design)
        self.assertIn("caller/ret target unevidenced", self.design)
        # Deliberately do NOT read 0x119f3144's file contents as a runtime value.

    def test_canonical_ranges_and_excluded_gap_are_not_admitted(self):
        rows = corpus.index_rows(self.index, "100edd70")
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["size"], rows[0]["body_ranges"]),
                         ("535", "100edd70-100edf49,100edf73-100edfaf"))
        for _, fields in SITES:
            self.assertFalse(0x100EDF4A <= fields.pc < 0x100EDF73)
            self.assertFalse(0x100EDEB0 <= fields.pc < 0x100EDEC7)
        for pc in (0x100EDF4A, 0x100EDF67, 0x100EDF71, 0x100EDEB0, 0x100EDFB0):
            with self.assertRaises(ValueError):
                authenticate_site(pc, b"\xc3", Fields("RETURN", pc))

    def test_every_instruction_byte_mutant_and_wrong_pc_rejected(self):
        for encoding, fields in SITES:
            code = bytes.fromhex(encoding)
            for i in range(len(code)):
                for bit in range(8):
                    mutant = bytearray(code)
                    mutant[i] ^= 1 << bit
                    with self.subTest(pc=hex(fields.pc), byte=i, bit=bit), self.assertRaises(ValueError):
                        authenticate_site(fields.pc, bytes(mutant), fields)
            with self.assertRaises(ValueError):
                authenticate_site(fields.pc + 1, code, replace(fields, pc=fields.pc + 1))

    def test_every_field_mutant_rejected_including_opaque_value_claims(self):
        for encoding, fields in SITES:
            for name, value in vars(fields).items():
                changed = not value if isinstance(value, bool) else value + 1 if isinstance(value, int) else value + "?"
                with self.subTest(pc=hex(fields.pc), field=name), self.assertRaises(ValueError):
                    authenticate_site(fields.pc, bytes.fromhex(encoding), replace(fields, **{name: changed}))

    def test_oracle_unchanged_and_this_suite_has_no_execution_dependency(self):
        self.assertEqual(pinned(ORACLE, *ORACLE_PIN), self.oracle)
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
        self.assertEqual(imports, {"__future__", "ast", "dataclasses", "hashlib", "struct",
                                  "unittest", "pathlib", "test_x64_startup_100edd70_entry_tail_provenance"})
        # No production/candidate import, subprocess, ctypes, DLL loading, or writes.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, {"write_bytes", "write_text", "unlink", "rename",
                                                 "mkdir", "rmdir", "touch", "open"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

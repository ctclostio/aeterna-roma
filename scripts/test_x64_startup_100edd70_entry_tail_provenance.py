#!/usr/bin/env python3
"""Freeze inert evidence for the 0x100edd70 normal-route convergence tail."""

from __future__ import annotations

import ast
import hashlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
DLL_SIZE = 28_278_272
DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
IMAGE_BASE = 0x10000000
INDEX = ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_function_index.tsv"
INDEX_SIZE = 8_344_450
INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"

INTERVALS = {
    "installed_tail": (
        0x100EDF41,
        0x0ED341,
        bytes.fromhex("c745fcffffffffeb4a"),
        "ebcf3ccb829383d74c54f505a857df1ea3fb5913165c50c70fecf6a987b67f02",
    ),
    "exception_gap": (
        0x100EDF4A,
        0x0ED34A,
        bytes.fromhex(
            "8b4dec8b018b008945dc894de08b45e050ff75dce86d02000083c408c3"
            "8b65e8c745fcffffffffeb21"
        ),
        "48fa1bded5911a24a9980288ef3a9470d56277c0a3636946cae77a4bb327ff77",
    ),
    "common_epilogue": (
        0x100EDF94,
        0x0ED394,
        bytes.fromhex(
            "ff1534f97211a044319f118b4df064890d000000005f5e5b8be55dc3"
        ),
        "490afcdfb5d7f9ee30342e409c8b657875d504f7fe6ce7c29822bcb204795f1c",
    ),
    "excluded_early_epilogue": (
        0x100EDEB0,
        0x0ED2B0,
        bytes.fromhex(
            "ff1534f9721132c08b4df064890d000000005f5e5b8be55dc3"
        ),
        "863eb0e844888cc718d5bb9b2ad3fbf4b8e318fe4f20c56934eb68dab61bf5bc",
    ),
}

ADMITTED_ENTRY_DECISION = {
    "port/x64_ported/ported_100edd70_entry_decision.h": (
        5_103,
        "64b9204fbe3bc11d81c5a15c8faec5b3e3e737e5c926cd40bf9b309bd472995d",
    ),
    "port/x64_ported/ported_100edd70_entry_decision.c": (
        27_463,
        "d4cd6f3633cee6ef3584787bf8e609fb6dcf4a1156d957924d49076788f419db",
    ),
    "port/x64_runtime/test_startup_100edd70_entry_decision.c": (
        35_819,
        "edb849e2fa7d1a4e2acc5d89b2a65a57d6200fa4bcb193403fddb523486e7a60",
    ),
    "scripts/test_x64_startup_100edd70_entry_decision_provenance.py": (
        18_153,
        "a66591732ebc3a354c8295df06ea4d95ce64861ad664f89e76c68d1031f00744",
    ),
    "docs/x64_startup_100edd70_entry_decision.md": (
        6_849,
        "361f6c369f6540a46b0d0ef5be4d30f5c9b44b9a13533c8bfd7fbd04210f0045",
    ),
}

CANONICAL_ENTRY = (
    ROOT
    / "src_canonical_out"
    / "empire.retail.dll"
    / "canonical_decomp"
    / "decomp_fn_100edd70.c"
)
CANONICAL_ENTRY_SIZE = 3_717
CANONICAL_ENTRY_SHA256 = (
    "ec93da6e0523b5558068cc6cc2cb7acfe686cbb201f3d35bf4f0168e0e1e3c34"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"{label} is outside the pinned input")


def parse_pe32(data: bytes):
    require_range(data, 0, 0x40, "DOS header")
    if data[:2] != b"MZ":
        raise ValueError("missing MZ signature")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe, 24, "PE header")
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    coff = pe + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    require_range(data, optional, optional_size, "optional header")
    if (
        machine != 0x014C
        or not 1 <= section_count <= 96
        or optional_size < 112
        or struct.unpack_from("<H", data, optional)[0] != 0x010B
        or struct.unpack_from("<I", data, optional + 28)[0] != IMAGE_BASE
    ):
        raise ValueError("input is not the pinned PE32 shape")
    table = optional + optional_size
    require_range(data, table, section_count * 40, "section table")
    sections = []
    for index in range(section_count):
        entry = table + index * 40
        name = data[entry:entry + 8].split(b"\0", 1)[0].decode("ascii")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, entry + 8
        )
        characteristics = struct.unpack_from("<I", data, entry + 36)[0]
        require_range(data, raw_offset, raw_size, f"section {name}")
        sections.append(
            (name, rva, virtual_size, raw_offset, raw_size, characteristics)
        )
    return optional, tuple(sections)


def read_rva(data: bytes, sections, rva: int, size: int):
    matches = []
    for section in sections:
        name, section_rva, _virtual_size, raw_offset, raw_size, flags = section
        delta = rva - section_rva
        if delta >= 0 and delta <= raw_size and size <= raw_size - delta:
            matches.append((name, raw_offset + delta, flags))
    if len(matches) != 1:
        raise ValueError(f"RVA 0x{rva:08x} has {len(matches)} raw mappings")
    name, offset, flags = matches[0]
    require_range(data, offset, size, f"RVA 0x{rva:08x}")
    return data[offset:offset + size], name, offset, flags


def read_va(data: bytes, sections, va: int, size: int):
    if va < IMAGE_BASE:
        raise ValueError("VA precedes the image base")
    return read_rva(data, sections, va - IMAGE_BASE, size)


def read_c_string(data: bytes, sections, rva: int) -> str:
    _unit, _name, offset, _flags = read_rva(data, sections, rva, 1)
    end = data.find(b"\0", offset)
    if end < 0 or end - offset > 4096:
        raise ValueError(f"unterminated string at RVA 0x{rva:08x}")
    return data[offset:end].decode("ascii")


def imported_name_at_iat(data: bytes, optional: int, sections, iat_va: int):
    import_rva, import_size = struct.unpack_from("<II", data, optional + 104)
    if import_rva == 0 or import_size < 20:
        raise ValueError("import directory is absent")
    for descriptor_index in range(import_size // 20):
        descriptor, _name, _offset, _flags = read_rva(
            data, sections, import_rva + descriptor_index * 20, 20
        )
        values = struct.unpack("<IIIII", descriptor)
        if values == (0, 0, 0, 0, 0):
            break
        original_thunk, _stamp, _chain, name_rva, first_thunk = values
        module = read_c_string(data, sections, name_rva)
        lookup_rva = original_thunk or first_thunk
        for thunk_index in range(65536):
            thunk_bytes, _name, _offset, _flags = read_rva(
                data, sections, lookup_rva + thunk_index * 4, 4
            )
            thunk = struct.unpack("<I", thunk_bytes)[0]
            if thunk == 0:
                break
            if IMAGE_BASE + first_thunk + thunk_index * 4 != iat_va:
                continue
            if thunk & 0x80000000:
                return module, f"ordinal-{thunk & 0xffff}"
            return module, read_c_string(data, sections, thunk + 2)
    raise ValueError(f"IAT cell 0x{iat_va:08x} is absent")


def rel8_target(instruction_va: int, instruction: bytes) -> int:
    if len(instruction) != 2 or instruction[0] != 0xEB:
        raise ValueError("instruction is not an EB rel8 jump")
    return instruction_va + 2 + struct.unpack_from("<b", instruction, 1)[0]


def rel32_call_target(instruction_va: int, instruction: bytes) -> int:
    if len(instruction) != 5 or instruction[0] != 0xE8:
        raise ValueError("instruction is not an E8 rel32 call")
    return instruction_va + 5 + struct.unpack_from("<i", instruction, 1)[0]


def index_rows(index_data: bytes, entry: str):
    lines = index_data.decode("utf-8").splitlines()
    header = lines[0].split("\t")
    return [
        dict(zip(header, line.split("\t"), strict=True))
        for line in lines[1:]
        if line.split("\t", 1)[0] == entry
    ]


class Startup100edd70EntryTailEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != DLL_SIZE or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.optional, cls.sections = parse_pe32(cls.dll)
        cls.index = INDEX.read_bytes()
        if len(cls.index) != INDEX_SIZE or sha256(cls.index) != INDEX_SHA256:
            raise AssertionError("canonical function index differs")

    def test_convergence_and_excluded_intervals_are_exact(self) -> None:
        for role, (va, raw_offset, expected, expected_hash) in INTERVALS.items():
            with self.subTest(role=role):
                body, section, actual_offset, flags = read_va(
                    self.dll, self.sections, va, len(expected)
                )
                self.assertEqual((section, actual_offset), (".text", raw_offset))
                self.assertNotEqual(flags & 0x20000000, 0)
                self.assertEqual(body, expected)
                self.assertEqual(sha256(body), expected_hash)
        install_cleanup = read_va(self.dll, self.sections, 0x100EDF3E, 3)[0]
        skip_cleanup = read_va(self.dll, self.sections, 0x100EDF91, 3)[0]
        self.assertEqual(install_cleanup, bytes.fromhex("83c418"))
        self.assertEqual(skip_cleanup, bytes.fromhex("83c418"))
        self.assertEqual(0x100EDF3E + len(install_cleanup), 0x100EDF41)
        self.assertEqual(0x100EDF91 + len(skip_cleanup), 0x100EDF94)

    def test_installed_tail_store_and_jump_are_exact(self) -> None:
        body = INTERVALS["installed_tail"][2]
        self.assertEqual(body[:7], bytes.fromhex("c745fcffffffff"))
        self.assertEqual(struct.unpack_from("<b", body, 2)[0], -4)
        self.assertEqual(struct.unpack_from("<I", body, 3)[0], 0xFFFFFFFF)
        self.assertEqual(rel8_target(0x100EDF48, body[7:9]), 0x100EDF94)

    def test_exception_gap_is_dispatch_only_and_converges(self) -> None:
        body = INTERVALS["exception_gap"][2]
        filter_block = body[:29]
        handler_block = body[29:]
        self.assertEqual(filter_block[:3], bytes.fromhex("8b4dec"))
        self.assertEqual(
            rel32_call_target(0x100EDF5E, filter_block[20:25]),
            0x100EE1D0,
        )
        self.assertEqual(filter_block[-4:], bytes.fromhex("83c408c3"))
        self.assertEqual(handler_block[:3], bytes.fromhex("8b65e8"))
        self.assertEqual(handler_block[3:10], bytes.fromhex("c745fcffffffff"))
        self.assertEqual(rel8_target(0x100EDF71, handler_block[10:]), 0x100EDF94)
        self.assertEqual(index_rows(self.index, "100ee1d0"), [])

    def test_common_epilogue_instruction_sites_and_import_are_exact(self) -> None:
        body = INTERVALS["common_epilogue"][2]
        self.assertEqual(body[:2], bytes.fromhex("ff15"))
        self.assertEqual(struct.unpack_from("<I", body, 2)[0], 0x1172F934)
        self.assertEqual(
            imported_name_at_iat(self.dll, self.optional, self.sections, 0x1172F934),
            ("ole32.dll", "CoUninitialize"),
        )
        self.assertEqual(body[6:11], bytes.fromhex("a044319f11"))
        self.assertEqual(struct.unpack_from("<I", body, 7)[0], 0x119F3144)
        self.assertEqual(body[11:14], bytes.fromhex("8b4df0"))
        self.assertEqual(body[14:21], bytes.fromhex("64890d00000000"))
        self.assertEqual(body[21:24], bytes.fromhex("5f5e5b"))
        self.assertEqual(body[24:26], bytes.fromhex("8be5"))
        self.assertEqual(body[26:], bytes.fromhex("5dc3"))

    def test_early_return_zero_epilogue_is_distinct_and_excluded(self) -> None:
        early = INTERVALS["excluded_early_epilogue"][2]
        common = INTERVALS["common_epilogue"][2]
        self.assertEqual(early[:6], common[:6])
        self.assertEqual(early[6:8], bytes.fromhex("32c0"))
        self.assertEqual(common[6:11], bytes.fromhex("a044319f11"))
        self.assertEqual(early[8:], common[11:])
        canonical = CANONICAL_ENTRY.read_bytes()
        self.assertEqual(len(canonical), CANONICAL_ENTRY_SIZE)
        self.assertEqual(sha256(canonical), CANONICAL_ENTRY_SHA256)
        text = canonical.decode("utf-8")
        self.assertEqual(text.count("return 0;"), 1)
        self.assertEqual(text.count("return DAT_119f3144;"), 1)
        self.assertLess(text.index("return 0;"), text.index("pwVar4 ="))
        self.assertGreater(text.index("return DAT_119f3144;"), text.index("pwVar4 ="))

    def test_canonical_boundary_and_admitted_child_are_exact(self) -> None:
        rows = index_rows(self.index, "100edd70")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["canonical_name"], "decomp_fn_100edd70")
        self.assertEqual(rows[0]["original_name"], "entry_point")
        self.assertEqual(rows[0]["size"], "535")
        self.assertEqual(
            rows[0]["body_ranges"],
            "100edd70-100edf49,100edf73-100edfaf",
        )
        self.assertNotIn("100edf4a", rows[0]["body_ranges"])
        for relative, (expected_size, expected_hash) in ADMITTED_ENTRY_DECISION.items():
            data = (ROOT / relative).read_bytes()
            self.assertEqual(len(data), expected_size, relative)
            self.assertEqual(sha256(data), expected_hash, relative)

    def test_reciprocal_mutants_fail_and_oracle_is_read_only(self) -> None:
        for role, (_va, _raw, expected, expected_hash) in INTERVALS.items():
            for offset in (0, len(expected) // 2, len(expected) - 1):
                mutant = bytearray(expected)
                mutant[offset] ^= 1
                self.assertNotEqual(sha256(bytes(mutant)), expected_hash, role)

        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        imports = set()
        forbidden = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {
                    "write_bytes", "write_text", "unlink", "rename", "replace",
                    "mkdir", "rmdir", "touch",
                }:
                    forbidden.add(node.func.attr)
        self.assertEqual(
            imports,
            {"__future__", "ast", "hashlib", "struct", "unittest", "pathlib"},
        )
        self.assertEqual(forbidden, set())


if __name__ == "__main__":
    unittest.main(verbosity=2)

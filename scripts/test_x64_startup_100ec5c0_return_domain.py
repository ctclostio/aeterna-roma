#!/usr/bin/env python3
"""Authenticate the ordinary 0/2 returns and INT3 stop in x86 0x100ec5c0."""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
CANONICAL = (
    ROOT
    / "src_canonical_out"
    / "empire.retail.dll"
    / "canonical_decomp"
    / "decomp_fn_100ec5c0.c"
)
PARENT_FIXTURE = ROOT / "scripts" / "x64_startup_100ed3c0_abi_fixture.json"

DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
CANONICAL_SHA256 = "c4362bfb508004284f0f079a3367a8f2e8bb63c0b0610d94906d7eeac7f7689c"
PARENT_SHA256 = "b606895706a18f44d27babaef870efc60b362733d01af389b96a10e7c0e5d206"

IMAGE_BASE = 0x10000000
FUNCTION_VA = 0x100EC5C0
FUNCTION_SIZE = 1199
FUNCTION_SHA256 = "bf1adcefe07251e80f2711a590dcc479071d845c00535ec57d5b0f7385e25e5e"

RETURN2_VA = 0x100EC68D
RETURN2_BYTES = bytes.fromhex("5f5e5db8020000005b81c4c4000000c3")
RETURN2_SHA256 = "6bafa6d887a759d262d93e0a373dcbb4d301346e8be85f55621b8a97e667606f"

FINAL_RETURN_VA = 0x100ECA35
FINAL_RETURN_BYTES = bytes.fromhex(
    "e8e6341d010fb6c05ff7d85e1bc05d83e0025b81c4c4000000c3"
)
FINAL_RETURN_SHA256 = "ed1c1041ab6570ae5cc61e6cedc8c4518eac6a49ccbba47d9e9f0b0becaa5edc"

TRAP_VA = 0x100ECA4F
TRAP_BYTES = bytes.fromhex(
    "8d44241450e857611f0183c4048bc8e89d601f01e89873590150e862120000cc"
)
TRAP_SHA256 = "0756cbe584a461d314d996199fe3c7dbb1635088e18718aaf4cd6ce6f60d544a"

PARENT_WINDOW_VA = 0x100ED4C1
PARENT_WINDOW_BYTES = bytes.fromhex(
    "8d4c2468e8f6f0ffff83f802744c83f80175ed"
)
PARENT_WINDOW_SHA256 = "cbec5f0803aee5e4667fae58f23b30896440fae3bfbf06ad4fa97b359032c7bd"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise ValueError(f"{label} lies outside the {len(data)}-byte input")


def parse_pe32(data: bytes):
    require_range(data, 0, 0x40, "DOS header")
    if data[:2] != b"MZ":
        raise ValueError("missing MZ signature")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe_offset, 24, "PE header")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    coff = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    require_range(data, optional, optional_size, "optional header")
    if (
        machine != 0x014C
        or not 1 <= section_count <= 96
        or optional_size < 96
        or struct.unpack_from("<H", data, optional)[0] != 0x010B
        or struct.unpack_from("<I", data, optional + 28)[0] != IMAGE_BASE
    ):
        raise ValueError("original image is not the expected PE32 image")
    table = optional + optional_size
    require_range(data, table, section_count * 40, "section table")
    sections = []
    for index in range(section_count):
        offset = table + index * 40
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        require_range(data, raw_offset, raw_size, f"section {name}")
        sections.append((name, rva, virtual_size, raw_offset, raw_size))
    return tuple(sections)


def read_va(data: bytes, sections, va: int, size: int):
    rva = va - IMAGE_BASE
    matches = []
    for name, section_rva, _virtual_size, raw_offset, raw_size in sections:
        delta = rva - section_rva
        if delta >= 0 and size <= raw_size - delta:
            matches.append((name, raw_offset + delta))
    if len(matches) != 1:
        raise ValueError(f"VA 0x{va:08x} has {len(matches)} raw mappings")
    name, offset = matches[0]
    require_range(data, offset, size, f"VA 0x{va:08x}")
    return data[offset : offset + size], name, offset


def rel32_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    opcode = body[offset : offset + 2]
    if body[offset] == 0xE8:
        displacement_offset = offset + 1
        next_va = instruction_va + 5
    elif opcode in (b"\x0f\x84", b"\x0f\x85"):
        displacement_offset = offset + 2
        next_va = instruction_va + 6
    else:
        raise ValueError(f"unsupported rel32 opcode at 0x{instruction_va:08x}")
    displacement = struct.unpack_from("<i", body, displacement_offset)[0]
    return next_va + displacement


def rel8_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    displacement = struct.unpack_from("<b", body, offset + 1)[0]
    return instruction_va + 2 + displacement


class Startup100ec5c0ReturnDomainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != 28_278_272 or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32(cls.dll)
        cls.body, section, offset = read_va(
            cls.dll, cls.sections, FUNCTION_VA, FUNCTION_SIZE
        )
        if (section, offset, sha256(cls.body)) != (
            ".text",
            0xEB9C0,
            FUNCTION_SHA256,
        ):
            raise AssertionError("0x100ec5c0 body or mapping changed")

    def test_all_constant_two_branches_share_exact_epilogue(self):
        window, section, offset = read_va(
            self.dll, self.sections, RETURN2_VA, len(RETURN2_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0xEBA8D))
        self.assertEqual(window, RETURN2_BYTES)
        self.assertEqual(sha256(window), RETURN2_SHA256)
        self.assertEqual(struct.unpack_from("<I", window, 4)[0], 2)
        self.assertEqual(window[-1], 0xC3)

        for branch_va in (0x100EC5D3, 0x100EC5EE, 0x100EC946, 0x100EC96B):
            self.assertEqual(
                rel32_target(self.body, FUNCTION_VA, branch_va), RETURN2_VA
            )
        self.assertEqual(rel8_target(self.body, FUNCTION_VA, 0x100EC6DE), RETURN2_VA)

    def test_final_ordinary_return_is_boolean_masked_to_zero_or_two(self):
        window, section, offset = read_va(
            self.dll, self.sections, FINAL_RETURN_VA, len(FINAL_RETURN_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0xEBE35))
        self.assertEqual(window, FINAL_RETURN_BYTES)
        self.assertEqual(sha256(window), FINAL_RETURN_SHA256)
        self.assertEqual(rel32_target(window, FINAL_RETURN_VA, FINAL_RETURN_VA), 0x112BFF20)
        self.assertIn(bytes.fromhex("0fb6c0"), window)
        self.assertIn(bytes.fromhex("f7d8"), window)
        self.assertIn(bytes.fromhex("1bc0"), window)
        self.assertIn(bytes.fromhex("83e002"), window)
        self.assertEqual(window[-1], 0xC3)

    def test_debug_branch_ends_in_int3_and_is_not_an_indirect_return(self):
        window, section, offset = read_va(
            self.dll, self.sections, TRAP_VA, len(TRAP_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0xEBE4F))
        self.assertEqual(window, TRAP_BYTES)
        self.assertEqual(sha256(window), TRAP_SHA256)
        self.assertEqual(window[-1], 0xCC)
        self.assertNotIn(b"\xff\xd0", window)
        self.assertNotIn(b"\xc3", window)
        self.assertEqual(rel32_target(window, TRAP_VA, 0x100ECA69), 0x100EDCD0)

        self.assertEqual(
            rel32_target(self.body, FUNCTION_VA, 0x100EC978), FINAL_RETURN_VA
        )
        self.assertEqual(
            rel32_target(self.body, FUNCTION_VA, 0x100EC991), TRAP_VA
        )

    def test_parent_call_and_zero_one_two_branching_are_exact(self):
        window, section, offset = read_va(
            self.dll, self.sections, PARENT_WINDOW_VA, len(PARENT_WINDOW_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0xEC8C1))
        self.assertEqual(window, PARENT_WINDOW_BYTES)
        self.assertEqual(sha256(window), PARENT_WINDOW_SHA256)
        self.assertEqual(rel32_target(window, PARENT_WINDOW_VA, 0x100ED4C5), FUNCTION_VA)
        self.assertEqual(window[9:14], bytes.fromhex("83f802744c"))
        self.assertEqual(window[14:19], bytes.fromhex("83f80175ed"))
        self.assertEqual(rel8_target(window, PARENT_WINDOW_VA, 0x100ED4CD), 0x100ED51B)
        self.assertEqual(rel8_target(window, PARENT_WINDOW_VA, 0x100ED4D2), PARENT_WINDOW_VA)

    def test_canonical_and_parent_fixture_are_pinned_cross_checks(self):
        self.assertEqual(sha256(CANONICAL.read_bytes()), CANONICAL_SHA256)
        fixture = json.loads(PARENT_FIXTURE.read_text(encoding="utf-8"))
        callee = fixture["callee"]
        self.assertEqual(
            (callee["va_start"], callee["size"], callee["sha256"]),
            ("0x100ed3c0", 400, PARENT_SHA256),
        )
        parent, section, offset = read_va(
            self.dll, self.sections, 0x100ED3C0, callee["size"]
        )
        self.assertEqual((section, offset), (".text", 0xEC7C0))
        self.assertEqual(parent, bytes.fromhex(callee["hex"]))
        self.assertEqual(sha256(parent), PARENT_SHA256)


if __name__ == "__main__":
    unittest.main(verbosity=2)

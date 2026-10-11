#!/usr/bin/env python3
"""Independent provenance gates for the guest32 entry-policy selector."""

from __future__ import annotations

import csv
import hashlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
LAUNCHER = ROOT / "Total War Rome II" / "Rome2.exe"
CANONICAL = (
    ROOT
    / "src_canonical_out"
    / "empire.retail.dll"
    / "canonical_decomp"
    / "decomp_fn_100edd70.c"
)
FUNCTION_INDEX = (
    ROOT
    / "src_canonical_out"
    / "empire.retail.dll"
    / "canonical_function_index.tsv"
)
STARTUP_SLOTS = ROOT / "port" / "startup_audit" / "startup_slots.tsv"

DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
LAUNCHER_SHA256 = "332de1aac9303ce71dbee82fe2f8fcb9d2f82766ebd2e6943db6fe9dac30519d"
CANONICAL_SHA256 = "ec93da6e0523b5558068cc6cc2cb7acfe686cbb201f3d35bf4f0168e0e1e3c34"
INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
STARTUP_SLOTS_SHA256 = (
    "453de546bbbd64e858aa80cd2ce09552904098e02cb0861689c24bd21e67ff6b"
)

SELECTOR_VA = 0x100EDECC
SELECTOR_BYTES = bytes.fromhex(
    "8b7d108bcfb894f87311668b10663b11751e6685d27415668b5002663b5102750f"
    "83c00483c1046685d275de33c0eb051bc083c80185c0746e"
)
SELECTOR_SHA256 = "11bc65f6b73602d0b4a7c974728793ca5d817cc974a5c8ff91ab1e98b64e7ebc"
LITERAL_VA = 0x1173F894
LITERAL_BYTES = bytes.fromhex(
    "2d006e006f005f0065007800630065007000740069006f006e005f0068006100"
    "6e0064006c00650072000000"
)
LITERAL_SHA256 = "158c0c7b39632eaab540612eb67ded95089a82894e7a91edbff93866b072c86e"
HANDLER_FALLTHROUGH_VA = 0x100EDF05
HANDLER_FALLTHROUGH_BYTES = bytes.fromhex("68d0e50e10e83b9b590183c404")
HANDLER_FALLTHROUGH_SHA256 = (
    "b97e64e8d36cbd7686e184a44bb45b692638d34e805b897c8088d614e7e3c485"
)
LAUNCH_CALL_VA = 0x00402492
LAUNCH_CALL_INSTRUCTIONS = (
    ("lea_arg9", bytes.fromhex("8d442428")),
    ("push_arg9", bytes.fromhex("50")),
    ("push_arg8", bytes.fromhex("6a00")),
    ("push_arg7", bytes.fromhex("ff742418")),
    ("lea_arg5", bytes.fromhex("8d442438")),
    ("push_arg6", bytes.fromhex("53")),
    ("push_arg5", bytes.fromhex("50")),
    ("load_arg4", bytes.fromhex("8b442428")),
    ("increment_arg4", bytes.fromhex("40")),
    ("push_arg4", bytes.fromhex("50")),
    ("push_arg3", bytes.fromhex("ffb4242c010000")),
    ("push_arg2", bytes.fromhex("ffb4242c010000")),
    ("push_arg1", bytes.fromhex("ffb4242c010000")),
    ("call_entry", bytes.fromhex("ffd1")),
    ("discard_36_bytes", bytes.fromhex("83c424")),
)
LAUNCH_CALL_BYTES = b"".join(body for _, body in LAUNCH_CALL_INSTRUCTIONS)
LAUNCH_CALL_SHA256 = "0a37a289d5e49348f28d6aea2970f9b7ce1345ce5080d5cbfbe4a30a0d7d8cd6"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"{label} is outside the {len(data)}-byte file")


def parse_pe_sections(data: bytes, expected_machine: int, expected_base: int):
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("missing MZ signature")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe_offset, 24, "PE/COFF header")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")

    coff = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    if machine != expected_machine:
        raise ValueError(f"machine 0x{machine:04x} is not expected x86")
    if not 1 <= section_count <= 96:
        raise ValueError("implausible section count")
    require_range(data, optional, optional_size, "optional header")
    if optional_size < 96 or struct.unpack_from("<H", data, optional)[0] != 0x010B:
        raise ValueError("image is not PE32")
    image_base = struct.unpack_from("<I", data, optional + 28)[0]
    if image_base != expected_base:
        raise ValueError(f"unexpected image base 0x{image_base:08x}")

    table = optional + optional_size
    require_range(data, table, section_count * 40, "section table")
    sections = []
    for index in range(section_count):
        offset = table + index * 40
        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII section name") from exc
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        require_range(data, raw_offset, raw_size, f"section {name} raw data")
        sections.append((name, rva, virtual_size, raw_offset, raw_size))
    return image_base, tuple(sections)


def read_va(data: bytes, image_base: int, sections, va: int, size: int):
    rva = va - image_base
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


class EntryPolicyProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for path in (DLL, LAUNCHER, CANONICAL, FUNCTION_INDEX, STARTUP_SLOTS):
            if not path.is_file():
                raise AssertionError(f"required pinned input is missing: {path}")
        cls.dll = DLL.read_bytes()
        cls.launcher = LAUNCHER.read_bytes()
        cls.startup_slots = STARTUP_SLOTS.read_bytes()
        if sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        if sha256(cls.launcher) != LAUNCHER_SHA256:
            raise AssertionError("original launcher differs from the pinned corpus")
        if sha256(cls.startup_slots) != STARTUP_SLOTS_SHA256:
            raise AssertionError("startup slot table differs from the pinned corpus")
        cls.dll_base, cls.dll_sections = parse_pe_sections(
            cls.dll, expected_machine=0x014C, expected_base=0x10000000
        )
        cls.launcher_base, cls.launcher_sections = parse_pe_sections(
            cls.launcher, expected_machine=0x014C, expected_base=0x00400000
        )

    def test_selector_bytes_literal_and_control_flow(self):
        body, section, offset = read_va(
            self.dll,
            self.dll_base,
            self.dll_sections,
            SELECTOR_VA,
            len(SELECTOR_BYTES),
        )
        self.assertEqual((section, offset), (".text", 0xED2CC))
        self.assertEqual(body, SELECTOR_BYTES)
        self.assertEqual(sha256(body), SELECTOR_SHA256)
        self.assertEqual(body[5:10], b"\xb8\x94\xf8\x73\x11")
        self.assertEqual(struct.unpack_from("<I", body, 6)[0], LITERAL_VA)
        self.assertEqual(body[-2], 0x74)
        branch_va = SELECTOR_VA + len(body) + struct.unpack_from("<b", body, len(body) - 1)[0]
        self.assertEqual(branch_va, 0x100EDF73)

        literal, literal_section, literal_offset = read_va(
            self.dll,
            self.dll_base,
            self.dll_sections,
            LITERAL_VA,
            len(LITERAL_BYTES),
        )
        self.assertEqual((literal_section, literal_offset), (".rdata", 0x173E294))
        self.assertEqual(literal, LITERAL_BYTES)
        self.assertEqual(sha256(literal), LITERAL_SHA256)
        self.assertEqual(literal.decode("utf-16le"), "-no_exception_handler\0")

    def test_nonmatch_falls_through_to_handler_registration(self):
        body, section, offset = read_va(
            self.dll,
            self.dll_base,
            self.dll_sections,
            HANDLER_FALLTHROUGH_VA,
            len(HANDLER_FALLTHROUGH_BYTES),
        )
        self.assertEqual((section, offset), (".text", 0xED305))
        self.assertEqual(body, HANDLER_FALLTHROUGH_BYTES)
        self.assertEqual(sha256(body), HANDLER_FALLTHROUGH_SHA256)
        self.assertEqual(body[0], 0x68)
        self.assertEqual(struct.unpack_from("<I", body, 1)[0], 0x100EE5D0)
        self.assertEqual(body[5], 0xE8)
        displacement = struct.unpack_from("<i", body, 6)[0]
        self.assertEqual(HANDLER_FALLTHROUGH_VA + 10 + displacement, 0x11687A4A)
        self.assertEqual(body[10:], b"\x83\xc4\x04")

    def test_launcher_supplies_nine_positions_and_discards_36_bytes(self):
        body, section, offset = read_va(
            self.launcher,
            self.launcher_base,
            self.launcher_sections,
            LAUNCH_CALL_VA,
            len(LAUNCH_CALL_BYTES),
        )
        self.assertEqual((section, offset), (".text", 0x1892))
        self.assertEqual(body, LAUNCH_CALL_BYTES)
        self.assertEqual(sha256(body), LAUNCH_CALL_SHA256)
        self.assertEqual(sum(name.startswith("push_arg") for name, _ in LAUNCH_CALL_INSTRUCTIONS), 9)
        self.assertEqual(LAUNCH_CALL_INSTRUCTIONS[-2], ("call_entry", b"\xff\xd1"))
        self.assertEqual(LAUNCH_CALL_INSTRUCTIONS[-1], ("discard_36_bytes", b"\x83\xc4\x24"))

    def test_canonical_identity_and_startup_absence(self):
        self.assertEqual(sha256(CANONICAL.read_bytes()), CANONICAL_SHA256)
        index_bytes = FUNCTION_INDEX.read_bytes()
        self.assertEqual(sha256(index_bytes), INDEX_SHA256)
        rows = list(
            csv.DictReader(index_bytes.decode("utf-8").splitlines(), delimiter="\t")
        )
        matches = [row for row in rows if row["entry"] == "100edd70"]
        self.assertEqual(len(matches), 1)
        row = matches[0]
        self.assertEqual(row["canonical_name"], "decomp_fn_100edd70")
        self.assertEqual(row["size"], "535")
        self.assertEqual(row["body_ranges"], "100edd70-100edf49,100edf73-100edfaf")

        startup_rows = list(
            csv.DictReader(
                self.startup_slots.decode("utf-8").splitlines(), delimiter="\t"
            )
        )
        startup_targets = {row["raw_target_va"] for row in startup_rows}
        self.assertFalse({"100edd70", "1093c450", "100e81a0"} & startup_targets)


if __name__ == "__main__":
    unittest.main(verbosity=2)

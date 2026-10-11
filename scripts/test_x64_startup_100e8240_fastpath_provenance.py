#!/usr/bin/env python3
"""Authenticate the bounded no-crash fast path of original 0x100e8240."""

from __future__ import annotations

import csv
import hashlib
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "Total War Rome II" / "empire.retail.dll"
INDEX = (
    ROOT / "src_canonical_out" / "empire.retail.dll" /
    "canonical_function_index.tsv"
)
CANONICAL = (
    ROOT / "src_canonical_out" / "empire.retail.dll" / "canonical_decomp"
)

DLL_SHA256 = "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
INDEX_SHA256 = "d6f066172d632800ec9c614afebfc8cf3bb88ca11ce243a47845071958a66de5"
CANONICAL_HASHES = {
    "100df270": "9309918694adc92b151210f40eeb1965a144d68b24967a9aa160ecdf8517de72",
    "100e8240": "aa030e847e3d0ab772c70c11a58d36c9a14680f3d5cf357f4b9066a9d53b551b",
    "100ea4d0": "122ca8ff594fb0becdc7c07999f235b64418efd18f0f08026a25ad9da066ce99",
    "100f2750": "16c0b2bd1980f7c8870b9a74720c17df25b4f8a883e56f3ba2a4a5eff68f706b",
}

IMAGE_BASE = 0x10000000

# 0x100e8240-0x100e8267: the admitted read-only fast path (40 bytes).
FASTPATH_VA = 0x100E8240
FASTPATH_BYTES = bytes.fromhex(
    "64a12c00000083ec0c8b0d445612128b0c88a1b03a9f11"
    "3b81040000007f09b8383a9f1183c40cc3"
)
FASTPATH_SHA256 = "cbc2db249bbf073aa791853d526ca1d6597f77906875020ae36a3a5d7a4be4c1"

# 0x100e8268-0x100e8375: the complete excluded window (270 bytes).
EXCLUDED_VA = 0x100E8268
EXCLUDED_BYTES = bytes.fromhex(
    "68b03a9f11e8c0b7590183c404833db03a9f11ff75e156b9"
    "4c3a9f11e88799000068440074118d4c2408e8199900006a"
    "118bf0e8f08a0300565068743a9f11e8a48dffff83c4108d"
    "4c2404e8089a0000685c0074118d4c2408e8ea9800006a11"
    "8bf0e8c18a0300565068803a9f11e8758dffff83c4108d4c"
    "2404e8d9990000b9a03a9f11e81f9900000f57c066c70538"
    "3a9f1100006880dc6d11c6053a3a9f11000f11053c3a9f11"
    "c705683a9f11000000000f1105583a9f11c7056c3a9f1100"
    "000000c605703a9f1100660f1305903a9f11c705983a9f11"
    "00000000c7059c3a9f110000000066c705ad3a9f110000c6"
    "05af3a9f1100e887b5590168b03a9f11e87bb6590183c408"
    "5ee9e9feffff"
)
EXCLUDED_SHA256 = "eeb4d55d5e4e4efdd3debf8d54dad445971b977b82697031de247bf4bd6b67fa"

# 0x100df47a-0x100df48f: the original 0x100df270 call sequence that reaches
# 0x100e8240, 0x100f2750, and 0x100ea4d0 (21 bytes).
PARENT_VA = 0x100DF47A
PARENT_BYTES = bytes.fromhex("e8c18d00008d4868e8c93201008bcfe842b000008b")
PARENT_SHA256 = "0c6026216d10621f29aa2fbb5ef9d2399b4a97e545cef108c68599b8ba6ebc3c"

# 0x100ea4d0: the adjacent suffix evidence entry (96 bytes).
EA4D0_VA = 0x100EA4D0
EA4D0_BYTES = bytes.fromhex(
    "56576a048bf9e8d56dfeff83c40485c07408c7000cf27311"
    "eb0233c08db72408000081c75408000056508bcfe85f7fff"
    "ff84c0750433c089006a04e8a06dfeff83c40485c07408c7"
    "0014f27311eb0233c056508bcfe8367fffff84c0750433c0"
)
EA4D0_SHA256 = "b0c23cef41978027ff45cba5761bc0f64f48a67d683355cbdff6f4e7d38c5c3a"

EXPECTED_INDEX_ROWS = {
    "100df270": ("decomp_fn_100df270", "640", "100df270-100df4ef"),
    "100e8240": ("decomp_fn_100e8240", "310", "100e8240-100e8375"),
    "100ea4d0": ("decomp_fn_100ea4d0", "265", "100ea4d0-100ea5d8"),
    "100f2750": ("decomp_fn_100f2750", "157", "100f2750-100f27ec"),
}



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
        raise ValueError("original image is not the expected bounded PE32 image")
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
    if body[offset] not in (0xE8, 0xE9):
        raise ValueError(f"0x{instruction_va:08x} is not an E8/E9 rel32")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    return instruction_va + 5 + displacement


class Startup100e8240FastpathProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = DLL.read_bytes()
        if len(cls.dll) != 28_278_272 or sha256(cls.dll) != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = parse_pe32(cls.dll)

    def test_canonical_corpus_identity(self):
        self.assertEqual(sha256(INDEX.read_bytes()), INDEX_SHA256)
        for name, expected in CANONICAL_HASHES.items():
            path = CANONICAL / f"decomp_fn_{name}.c"
            self.assertTrue(path.exists(), f"canonical {name} missing")
            self.assertEqual(sha256(path.read_bytes()), expected, name)

    def test_fastpath_window_is_exact_and_read_only(self):
        actual, section, offset = read_va(
            self.dll, self.sections, FASTPATH_VA, len(FASTPATH_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0x000E7640))
        self.assertEqual(actual, FASTPATH_BYTES)
        self.assertEqual(sha256(actual), FASTPATH_SHA256)
        # The fast path must end exactly where the excluded window begins.
        self.assertEqual(FASTPATH_VA + len(FASTPATH_BYTES), EXCLUDED_VA)
        self.assertEqual(
            len(FASTPATH_BYTES) + len(EXCLUDED_BYTES), 310,
            "the two windows must cover the full canonical function",
        )
        self.assertEqual(EXCLUDED_VA + len(EXCLUDED_BYTES), 0x100E8376)
        b = FASTPATH_BYTES
        self.assertEqual(
            b[0:6], bytes.fromhex("64a12c000000"),
            "load TEB.ThreadLocalStoragePointer from FS:[0x2c]")
        self.assertEqual(b[6:9], bytes.fromhex("83ec0c"), "frame setup")
        self.assertEqual(b[9:15], bytes.fromhex("8b0d44561212"),
                         "TLS index global 0x12125644")
        self.assertEqual(b[15:18], bytes.fromhex("8b0c88"),
                          "TLS-vector slot read [tls_vector + index*4]")
        self.assertEqual(b[18:23], bytes.fromhex("a1b03a9f11"),
                         "threshold global 0x119f3ab0")
        self.assertEqual(b[23:29], bytes.fromhex("3b8104000000"),
                         "cmp eax, [ecx+4] (threshold - tls value)")
        self.assertEqual(b[29:31], bytes.fromhex("7f09"), "jg +9 branch")
        self.assertEqual(b[31:36], bytes.fromhex("b8383a9f11"),
                         "crash-record identity 0x119f3a38")
        self.assertEqual(b[36:40], bytes.fromhex("83c40cc3"), "epilogue")
        # Every one of the 40 bytes is accounted for by the read-only
        # instructions above (6+3+6+3+5+6+2+5+4 == 40); the exact-byte pin
        # therefore proves the fast path performs no store.

    def test_excluded_window_is_crash_handler_only(self):
        actual, section, offset = read_va(
            self.dll, self.sections, EXCLUDED_VA, len(EXCLUDED_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0x000E7668))
        self.assertEqual(actual, EXCLUDED_BYTES)
        self.assertEqual(sha256(actual), EXCLUDED_SHA256)
        b = EXCLUDED_BYTES
        self.assertEqual(b[0:1], bytes.fromhex("68"), "push")
        self.assertEqual(b[1:5], bytes.fromhex("b03a9f11"),
                         "threshold global 0x119f3ab0")
        self.assertEqual(b[5:10], bytes.fromhex("e8c0b75901"),
                         "crash detector call 0x11683a32")
        self.assertEqual(b[13:15], bytes.fromhex("833d"),
                         "threshold compare opcode")
        self.assertEqual(b[15:19], bytes.fromhex("b03a9f11"),
                         "threshold compare address")
        self.assertEqual(b[19:20], bytes.fromhex("ff"),
                         "threshold compare immediate -1")
        self.assertEqual(b[20:22], bytes.fromhex("75e1"),
                         "early-return branch")
        self.assertEqual(b[-5:-4], bytes.fromhex("e9"), "final jmp opcode")
        self.assertEqual(
            rel32_target(b, EXCLUDED_VA, EXCLUDED_VA + len(b) - 5),
            0x100E825F,
            "final jmp must rejoin the crash-record return",
        )
        # The excluded window must contain the crash-record data cells.
        for cell in (0x119f3a38, 0x119f3a4c, 0x119f3a58, 0x119f3a68,
                     0x119f3a6c, 0x119f3a70, 0x119f3a90, 0x119f3a98,
                     0x119f3a9c, 0x119f3aad, 0x119f3aaf):
            self.assertIn(struct.pack("<I", cell), b,
                          f"crash-record cell {cell:#x} missing")

    def test_parent_call_sequence_targets_are_exact(self):
        actual, section, offset = read_va(
            self.dll, self.sections, PARENT_VA, len(PARENT_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0x000DE87A))
        self.assertEqual(actual, PARENT_BYTES)
        self.assertEqual(sha256(actual), PARENT_SHA256)
        self.assertEqual(
            rel32_target(actual, PARENT_VA, PARENT_VA + 0x00), 0x100E8240,
            "first call target is not 0x100e8240")
        self.assertEqual(
            rel32_target(actual, PARENT_VA, PARENT_VA + 0x08), 0x100F2750,
            "second call target is not 0x100f2750")
        self.assertEqual(
            rel32_target(actual, PARENT_VA, PARENT_VA + 0x0F), 0x100EA4D0,
            "third call target is not 0x100ea4d0")

    def test_ea4d0_evidence_entry_allocates_and_mutates(self):
        actual, section, offset = read_va(
            self.dll, self.sections, EA4D0_VA, len(EA4D0_BYTES)
        )
        self.assertEqual((section, offset), (".text", 0x000E98D0))
        self.assertEqual(actual, EA4D0_BYTES)
        self.assertEqual(sha256(actual), EA4D0_SHA256)
        b = EA4D0_BYTES
        self.assertEqual(b[0:2], bytes.fromhex("5657"), "prologue")
        self.assertEqual(rel32_target(b, EA4D0_VA, EA4D0_VA + 6), 0x100D12B0,
                         "first allocation call 0x100d12b0")
        self.assertEqual(b[18:24], bytes.fromhex("c7000cf27311"),
                          "first heap-object mutation mov [eax], 0x1173f20c")
        self.assertEqual(rel32_target(b, EA4D0_VA, EA4D0_VA + 0x2C), 0x100E2460,
                         "second initialization call 0x100e2460")
        self.assertEqual(rel32_target(b, EA4D0_VA, EA4D0_VA + 0x3B), 0x100D12B0,
                         "second allocation call 0x100d12b0")

    def test_canonical_index_rows_are_exact(self):
        index_bytes = INDEX.read_bytes()
        self.assertEqual(sha256(index_bytes), INDEX_SHA256)
        rows = list(
            csv.DictReader(index_bytes.decode("utf-8").splitlines(),
                           delimiter="\t")
        )
        by_entry = {row["entry"]: row for row in rows}
        for entry, (canonical, size, body) in EXPECTED_INDEX_ROWS.items():
            self.assertEqual(
                (
                    by_entry[entry]["canonical_name"],
                    by_entry[entry]["size"],
                    by_entry[entry]["body_ranges"],
                ),
                (canonical, size, body),
                entry,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

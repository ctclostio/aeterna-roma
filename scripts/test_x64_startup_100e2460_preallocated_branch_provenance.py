#!/usr/bin/env python3
"""Authenticate the complete preallocated branch of original 0x100e2460."""

from __future__ import annotations

import hashlib
import struct
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BASE_PROVENANCE = (
    ROOT / "scripts" /
    "test_x64_startup_100e2460_append_prefix_provenance.py"
)
BASE_PROVENANCE_SHA256 = (
    "b3d9dd5ca5e354e94fc06072e4e98c3d3312bde47a9399cd660f946fb6c2ef4c"
)

COUNT_DISPATCH_VA = 0x100E252D
COUNT_DISPATCH_BYTES = bytes.fromhex(
    "ff46088bcb8b03ff7424108b4004ffd0"
)
COUNT_DISPATCH_SHA256 = (
    "0c39615f1998cfdd8b5f272d6c1ec24c45c1dce68bdbb536d59546bee88b2839"
)

PUMP_SAVE_VA = 0x100E253D
PUMP_SAVE_BYTES = bytes.fromhex(
    "8b3570f672118ad86a016a006a006a006a00ffd685c075f0"
)
PUMP_SAVE_SHA256 = (
    "2a1304ba7973a578f0eee4d838043b456950a6a424f0d4258e06331bcd894d7a"
)

EPILOGUE_VA = 0x100E2555
EPILOGUE_BYTES = bytes.fromhex("5e8ac35bc20800")
EPILOGUE_SHA256 = (
    "cdcceb30543e9b5c00f4fcc7fc5ecf5ce7dece61c1fc34d3bfa6c9321ddbb9e9"
)
PREALLOCATED_BYTES_SHA256 = (
    "b95416d4dec58abb68351be21cab561948dd4090e8304fc39bd0222a0a6738bd"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_base_provenance():
    data = BASE_PROVENANCE.read_bytes()
    if sha256(data) != BASE_PROVENANCE_SHA256:
        raise AssertionError("append-prefix provenance authority changed")
    name = "rome2_100e2460_append_provenance_authority"
    module = types.ModuleType(name)
    module.__file__ = str(BASE_PROVENANCE)
    sys.modules[name] = module
    exec(
        compile(data.decode("utf-8"), str(BASE_PROVENANCE), "exec"),
        module.__dict__,
    )
    return module


class Startup100e2460PreallocatedBranchProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = load_base_provenance()
        cls.dll = cls.base.DLL.read_bytes()
        if (
            len(cls.dll) != 28_278_272
            or sha256(cls.dll) != cls.base.DLL_SHA256
        ):
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.optional, cls.sections = cls.base.parse_pe32(cls.dll)

    def test_full_function_and_branch_partition_are_exact(self):
        body, section, raw_offset = self.base.read_va(
            self.dll,
            self.sections,
            self.base.FUNCTION_VA,
            self.base.FUNCTION_SIZE,
        )
        self.assertEqual((section, raw_offset), (".text", 0x000E1860))
        self.assertEqual(sha256(body), self.base.FUNCTION_SHA256)
        self.assertEqual(
            body,
            self.base.CONTROL_BYTES
            + self.base.EXCLUDED_BYTES
            + self.base.TAIL_BYTES,
        )
        self.assertEqual(
            sha256(self.base.CONTROL_BYTES + self.base.TAIL_BYTES),
            PREALLOCATED_BYTES_SHA256,
        )
        self.assertEqual(
            (
                self.base.CONTROL_VA,
                self.base.EXCLUDED_VA,
                self.base.TAIL_VA,
            ),
            (0x100E2460, 0x100E247D, 0x100E252D),
        )

    def test_tail_subwindows_partition_every_byte_exactly(self):
        expected = (
            (COUNT_DISPATCH_VA, COUNT_DISPATCH_BYTES, COUNT_DISPATCH_SHA256),
            (PUMP_SAVE_VA, PUMP_SAVE_BYTES, PUMP_SAVE_SHA256),
            (EPILOGUE_VA, EPILOGUE_BYTES, EPILOGUE_SHA256),
        )
        concatenated = bytearray()
        for va, wanted, digest in expected:
            actual, section, raw_offset = self.base.read_va(
                self.dll, self.sections, va, len(wanted)
            )
            self.assertEqual(section, ".text")
            self.assertEqual(raw_offset, 0x000E192D + (va - COUNT_DISPATCH_VA))
            self.assertEqual(actual, wanted)
            self.assertEqual(sha256(actual), digest)
            concatenated.extend(actual)
        self.assertEqual(bytes(concatenated), self.base.TAIL_BYTES)
        self.assertEqual(sha256(concatenated), self.base.TAIL_SHA256)

    def test_dispatch_abi_slot_and_saved_al_are_exact(self):
        b = COUNT_DISPATCH_BYTES
        self.assertEqual(b[:3], bytes.fromhex("ff4608"), "count increment")
        self.assertEqual(b[3:5], bytes.fromhex("8bcb"), "ECX is handler")
        self.assertEqual(b[5:7], bytes.fromhex("8b03"), "load handler vtable")
        self.assertEqual(
            b[7:11], bytes.fromhex("ff742410"), "push sole dispatch argument"
        )
        self.assertEqual(b[11:14], bytes.fromhex("8b4004"), "vtable slot +4")
        self.assertEqual(b[14:16], bytes.fromhex("ffd0"), "indirect call EAX")
        self.assertEqual(PUMP_SAVE_BYTES[6:8], bytes.fromhex("8ad8"))
        self.assertEqual(EPILOGUE_BYTES[1:3], bytes.fromhex("8ac3"))
        self.assertEqual(EPILOGUE_BYTES[-3:], bytes.fromhex("c20800"))

    def test_peek_message_shape_import_and_loop_polarity_are_exact(self):
        b = PUMP_SAVE_BYTES
        self.assertEqual(b[:6], bytes.fromhex("8b3570f67211"))
        self.assertEqual(
            b[8:20], bytes.fromhex("6a016a006a006a006a00ffd6")
        )
        self.assertEqual(b[20:24], bytes.fromhex("85c075f0"))
        self.assertEqual(
            PUMP_SAVE_VA + len(b) + struct.unpack("<b", b[-1:])[0],
            0x100E2545,
        )
        self.assertEqual(
            self.base.imported_name_at_iat(
                self.dll,
                self.optional,
                self.sections,
                self.base.PEEK_MESSAGE_IAT_VA,
            ),
            ("USER32.dll", "PeekMessageW"),
        )

    def test_callers_and_six_vtable_slot_pairs_remain_exact(self):
        for caller_va, caller_size, expected_offsets in (
            (
                self.base.EA4D0_VA,
                self.base.EA4D0_SIZE,
                self.base.EA4D0_CALL_OFFSETS,
            ),
            (
                self.base.EA060_VA,
                self.base.EA060_SIZE,
                self.base.EA060_CALL_OFFSETS,
            ),
        ):
            body, section, _raw_offset = self.base.read_va(
                self.dll, self.sections, caller_va, caller_size
            )
            self.assertEqual(section, ".text")
            actual_offsets = tuple(
                offset
                for offset in range(len(body) - 4)
                if body[offset] == 0xE8
                and self.base.rel32_target(
                    body, caller_va, caller_va + offset
                ) == self.base.FUNCTION_VA
            )
            self.assertEqual(actual_offsets, expected_offsets)

        for vtable, expected_pair in self.base.VTABLE_PAIRS.items():
            pair, section, _raw_offset = self.base.read_va(
                self.dll, self.sections, vtable, 8
            )
            self.assertEqual(section, ".rdata")
            self.assertEqual(struct.unpack("<II", pair), expected_pair)


if __name__ == "__main__":
    unittest.main(verbosity=2)

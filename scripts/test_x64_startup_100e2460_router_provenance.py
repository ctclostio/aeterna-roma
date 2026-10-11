#!/usr/bin/env python3
"""Authenticate the original three-way selection CFG of 0x100e2460.

This suite records machine and canonical-corpus facts only.  It source-loads
and pins the existing preallocated, capacity-zero, and growth authorities so
the router evidence cannot silently drift from any admitted branch.  The x64
router's validation envelope, callback adapters, finite Peek budget, alias
rules, failure statuses, and commit policy are port decisions; none is claimed
to be proved by these x86 bytes.
"""

from __future__ import annotations

import csv
import hashlib
import struct
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

AUTHORITY_PATHS = {
    "base": ROOT / "scripts" /
        "test_x64_startup_100e2460_append_prefix_provenance.py",
    "preallocated": ROOT / "scripts" /
        "test_x64_startup_100e2460_preallocated_branch_provenance.py",
    "capacity_zero": ROOT / "scripts" /
        "test_x64_startup_100e2460_capacity_zero_branch_provenance.py",
    "growth": ROOT / "scripts" /
        "test_x64_startup_100e2460_growth_branch_provenance.py",
}
AUTHORITY_SHA256 = {
    "base": "b3d9dd5ca5e354e94fc06072e4e98c3d3312bde47a9399cd660f946fb6c2ef4c",
    "preallocated": "1d4d94bd1c5980f0beaae91bd9afce9a5886ee1e6761feed3bae37b66665988f",
    "capacity_zero": "810aa11e28e2eb90dda9af231f5335b9f74dac868baa57b1e3c197d949e20441",
    "growth": "eaffd54cc6a4ef00daddf63b4d6ce8ac4f6cb49807976bb0a0e5f94d09f73b0e",
}

ENTRY_VA = 0x100E2460
ENTRY_BYTES = bytes.fromhex("53568bf18b4e088b46043bc8730f")
ENTRY_SHA256 = (
    "78860a504081ae472b75dd5a30aed09a70613b93d4579739303b997c26430551"
)

PREALLOCATED_VA = 0x100E246E
PREALLOCATED_BYTES = bytes.fromhex(
    "8b460c8b5c240c891c88e9b0000000"
)
PREALLOCATED_SHA256 = (
    "2e1493212a3d722ff90d9f73cd12052ac438e484bb6f3eea59764203ed95d45c"
)

CAPACITY_DISCRIMINATOR_VA = 0x100E247D
CAPACITY_DISCRIMINATOR_BYTES = bytes.fromhex("85c07524")
CAPACITY_DISCRIMINATOR_SHA256 = (
    "3ca7f0113f08d0e3b578001a9aa08008678880f4c657d2e1355fea67a05a0a0d"
)

CAPACITY_ZERO_VA = 0x100E2481
CAPACITY_ZERO_BYTES = bytes.fromhex(
    "506a04c7460401000000e8f0a701008b4e0883c4088b5c240c"
    "89460c891c88e988000000"
)
CAPACITY_ZERO_SHA256 = (
    "8a5172516788b3886df02503207f131d8ca25958df0e25ef73cae3be99a331a7"
)

GROWTH_VA = 0x100E24A5
GROWTH_SHA256 = (
    "9b618022f138033d8b71b5d256bf66d70c15a11de0829515fb8e59aec8e77b22"
)

TAIL_VA = 0x100E252D
TAIL_SHA256 = (
    "fb4f572129c1d66b60be22c9f9ca6d9698be8a95281df72c232787f279c354c0"
)

PRE_TAIL_SHA256 = (
    "9f9524f4cad04f338c1c849dcc033c1159550c0aafc3c9f1978e20e6df73efb2"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_pinned_source(label: str):
    """Load an authority from authenticated source, never an import pyc."""
    path = AUTHORITY_PATHS[label]
    data = path.read_bytes()
    if sha256(data) != AUTHORITY_SHA256[label]:
        raise AssertionError(f"{label} provenance authority changed")
    name = f"rome2_100e2460_router_{label}_authority"
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(data.decode("utf-8"), str(path), "exec"), module.__dict__)
    return module


def rel8_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    opcode = body[offset]
    if opcode not in range(0x70, 0x80) and opcode != 0xEB:
        raise ValueError(f"0x{instruction_va:08x} is not a short Jcc/JMP")
    displacement = struct.unpack_from("<b", body, offset + 1)[0]
    return instruction_va + 2 + displacement


def rel32_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    if body[offset] not in (0xE8, 0xE9):
        raise ValueError(f"0x{instruction_va:08x} is not CALL/JMP rel32")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    return instruction_va + 5 + displacement


def recovered_original_route(capacity: int, count: int) -> str:
    """Interpret only the pinned unsigned CMP/JAE and TEST/JNE selector."""
    if not 0 <= capacity <= 0xFFFFFFFF:
        raise ValueError("capacity is not an unsigned guest32 value")
    if not 0 <= count <= 0xFFFFFFFF:
        raise ValueError("count is not an unsigned guest32 value")
    if count < capacity:
        return "preallocated"
    if capacity == 0:
        return "capacity_zero"
    return "growth"


class Startup100e2460RouterProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authorities = {
            label: load_pinned_source(label) for label in AUTHORITY_PATHS
        }
        cls.base = cls.authorities["base"]
        cls.dll = cls.base.DLL.read_bytes()
        if len(cls.dll) != 28_278_272 or sha256(cls.dll) != cls.base.DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.optional, cls.sections = cls.base.parse_pe32(cls.dll)
        cls.function, section, cls.function_raw_offset = cls.base.read_va(
            cls.dll,
            cls.sections,
            cls.base.FUNCTION_VA,
            cls.base.FUNCTION_SIZE,
        )
        if section != ".text":
            raise AssertionError("0x100e2460 is no longer in .text")

    def test_all_three_branch_authorities_are_source_pinned_and_consistent(self):
        preallocated = self.authorities["preallocated"]
        capacity_zero = self.authorities["capacity_zero"]
        growth = self.authorities["growth"]

        for label, path in AUTHORITY_PATHS.items():
            with self.subTest(authority=label):
                self.assertEqual(sha256(path.read_bytes()), AUTHORITY_SHA256[label])

        self.assertEqual(
            {
                preallocated.BASE_PROVENANCE_SHA256,
                capacity_zero.BASE_PROVENANCE_SHA256,
                growth.BASE_PROVENANCE_SHA256,
            },
            {AUTHORITY_SHA256["base"]},
        )
        self.assertEqual(capacity_zero.ENTRY_PREDICATE_BYTES, ENTRY_BYTES)
        self.assertEqual(growth.ENTRY_PREDICATE_BYTES, ENTRY_BYTES)
        self.assertEqual(
            capacity_zero.ZERO_DISCRIMINATOR_BYTES,
            CAPACITY_DISCRIMINATOR_BYTES,
        )
        self.assertEqual(
            growth.GROWTH_DISCRIMINATOR_BYTES,
            CAPACITY_DISCRIMINATOR_BYTES,
        )
        self.assertEqual(capacity_zero.ZERO_BODY_BYTES, CAPACITY_ZERO_BYTES)
        self.assertEqual(sha256(growth.GROWTH_BODY_BYTES), GROWTH_SHA256)
        self.assertEqual(preallocated.COUNT_DISPATCH_VA, TAIL_VA)
        self.assertEqual(
            preallocated.COUNT_DISPATCH_BYTES
            + preallocated.PUMP_SAVE_BYTES
            + preallocated.EPILOGUE_BYTES,
            self.base.TAIL_BYTES,
        )

    def test_exact_original_function_partition_and_raw_offsets(self):
        growth = self.authorities["growth"]
        expected = (
            (ENTRY_VA, ENTRY_BYTES, ENTRY_SHA256, 0x000E1860),
            (
                PREALLOCATED_VA,
                PREALLOCATED_BYTES,
                PREALLOCATED_SHA256,
                0x000E186E,
            ),
            (
                CAPACITY_DISCRIMINATOR_VA,
                CAPACITY_DISCRIMINATOR_BYTES,
                CAPACITY_DISCRIMINATOR_SHA256,
                0x000E187D,
            ),
            (
                CAPACITY_ZERO_VA,
                CAPACITY_ZERO_BYTES,
                CAPACITY_ZERO_SHA256,
                0x000E1881,
            ),
            (GROWTH_VA, growth.GROWTH_BODY_BYTES, GROWTH_SHA256, 0x000E18A5),
            (TAIL_VA, self.base.TAIL_BYTES, TAIL_SHA256, 0x000E192D),
        )
        concatenated = bytearray()
        for va, wanted, digest, wanted_raw_offset in expected:
            with self.subTest(va=f"0x{va:08x}"):
                actual, section, raw_offset = self.base.read_va(
                    self.dll, self.sections, va, len(wanted)
                )
                self.assertEqual((section, raw_offset), (".text", wanted_raw_offset))
                self.assertEqual(actual, wanted)
                self.assertEqual(sha256(actual), digest)
                concatenated.extend(actual)

        self.assertEqual(self.function_raw_offset, 0x000E1860)
        self.assertEqual(len(concatenated), self.base.FUNCTION_SIZE)
        self.assertEqual(bytes(concatenated), self.function)
        self.assertEqual(sha256(self.function), self.base.FUNCTION_SHA256)
        self.assertEqual(sha256(self.function[:0xCD]), PRE_TAIL_SHA256)
        self.assertEqual(
            (
                ENTRY_VA + len(ENTRY_BYTES),
                PREALLOCATED_VA + len(PREALLOCATED_BYTES),
                CAPACITY_DISCRIMINATOR_VA + len(CAPACITY_DISCRIMINATOR_BYTES),
                CAPACITY_ZERO_VA + len(CAPACITY_ZERO_BYTES),
                GROWTH_VA + len(growth.GROWTH_BODY_BYTES),
                TAIL_VA + len(self.base.TAIL_BYTES),
            ),
            (
                PREALLOCATED_VA,
                CAPACITY_DISCRIMINATOR_VA,
                CAPACITY_ZERO_VA,
                GROWTH_VA,
                TAIL_VA,
                0x100E255C,
            ),
        )

    def test_selection_cfg_edges_and_common_tail_convergence_are_exact(self):
        # mov ecx,[esi+8]; mov eax,[esi+4]; cmp ecx,eax; jae discriminator
        self.assertEqual(ENTRY_BYTES[4:14], bytes.fromhex("8b4e088b46043bc8730f"))
        self.assertEqual(
            rel8_target(ENTRY_BYTES, ENTRY_VA, 0x100E246C),
            CAPACITY_DISCRIMINATOR_VA,
        )
        self.assertEqual(0x100E246E, PREALLOCATED_VA)

        # The short path appends, then bypasses both allocating bodies.
        self.assertEqual(PREALLOCATED_BYTES[:10], bytes.fromhex(
            "8b460c8b5c240c891c88"
        ))
        self.assertEqual(PREALLOCATED_BYTES[10], 0xE9)
        self.assertEqual(
            rel32_target(PREALLOCATED_BYTES, PREALLOCATED_VA, 0x100E2478),
            TAIL_VA,
        )

        # test capacity; nonzero branches to growth, zero falls through.
        self.assertEqual(CAPACITY_DISCRIMINATOR_BYTES, bytes.fromhex("85c07524"))
        self.assertEqual(
            rel8_target(
                CAPACITY_DISCRIMINATOR_BYTES,
                CAPACITY_DISCRIMINATOR_VA,
                0x100E247F,
            ),
            GROWTH_VA,
        )
        self.assertEqual(0x100E2481, CAPACITY_ZERO_VA)

        self.assertEqual(CAPACITY_ZERO_BYTES[-5], 0xE9)
        self.assertEqual(
            rel32_target(CAPACITY_ZERO_BYTES, CAPACITY_ZERO_VA, 0x100E24A0),
            TAIL_VA,
        )
        self.assertEqual(
            GROWTH_VA + len(self.authorities["growth"].GROWTH_BODY_BYTES),
            TAIL_VA,
            "growth falls through to the same dispatch/Peek tail",
        )

    def test_unsigned_selection_truth_table_is_exact(self):
        cases = (
            (0x00000000, 0x00000000, "capacity_zero"),
            (0x00000000, 0x00000001, "capacity_zero"),
            (0x00000001, 0x00000000, "preallocated"),
            (0x00000001, 0x00000001, "growth"),
            (0x00000001, 0x00000002, "growth"),
            (0x7FFFFFFF, 0x7FFFFFFE, "preallocated"),
            (0x7FFFFFFF, 0x7FFFFFFF, "growth"),
            (0x80000000, 0x7FFFFFFF, "preallocated"),
            (0x80000000, 0x80000000, "growth"),
            (0xFFFFFFFF, 0xFFFFFFFE, "preallocated"),
            (0xFFFFFFFF, 0xFFFFFFFF, "growth"),
        )
        for capacity, count, wanted in cases:
            with self.subTest(capacity=capacity, count=count):
                self.assertEqual(recovered_original_route(capacity, count), wanted)

        for capacity, count in ((-1, 0), (0, -1), (0x100000000, 0), (0, 0x100000000)):
            with self.subTest(rejected=(capacity, count)):
                with self.assertRaises(ValueError):
                    recovered_original_route(capacity, count)

    def test_canonical_main_authority_is_exact(self):
        self.assertEqual(sha256(self.base.INDEX.read_bytes()), self.base.INDEX_SHA256)
        canonical = self.base.CANONICAL / "decomp_fn_100e2460.c"
        self.assertTrue(canonical.exists())
        self.assertEqual(sha256(canonical.read_bytes()), self.base.CANONICAL_SHA256)

        rows = {
            row["entry"]: row
            for row in csv.DictReader(
                self.base.INDEX.read_text(encoding="utf-8").splitlines(),
                delimiter="\t",
            )
        }
        row = rows["100e2460"]
        self.assertEqual(
            (
                row["canonical_name"],
                row["original_name"],
                row["signature"],
                row["size"],
                row["body_ranges"],
            ),
            (
                "decomp_fn_100e2460",
                "FUN_100e2460",
                "undefined FUN_100e2460(void)",
                "252",
                "100e2460-100e255b",
            ),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

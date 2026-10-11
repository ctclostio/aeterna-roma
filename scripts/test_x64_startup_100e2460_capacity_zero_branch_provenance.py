#!/usr/bin/env python3
"""Authenticate the capacity-zero return route of original 0x100e2460."""

from __future__ import annotations

import csv
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

ENTRY_PREDICATE_VA = 0x100E2460
ENTRY_PREDICATE_BYTES = bytes.fromhex(
    "53568bf18b4e088b46043bc8730f"
)
ENTRY_PREDICATE_SHA256 = (
    "78860a504081ae472b75dd5a30aed09a70613b93d4579739303b997c26430551"
)

ZERO_DISCRIMINATOR_VA = 0x100E247D
ZERO_DISCRIMINATOR_BYTES = bytes.fromhex("85c07524")
ZERO_DISCRIMINATOR_SHA256 = (
    "3ca7f0113f08d0e3b578001a9aa08008678880f4c657d2e1355fea67a05a0a0d"
)

ZERO_BODY_VA = 0x100E2481
ZERO_BODY_BYTES = bytes.fromhex(
    "506a04c7460401000000e8f0a701008b4e0883c4088b5c240c"
    "89460c891c88e988000000"
)
ZERO_BODY_SHA256 = (
    "8a5172516788b3886df02503207f131d8ca25958df0e25ef73cae3be99a331a7"
)
ZERO_WINDOW_SHA256 = (
    "030e64a45d9c01c867c01a24400d6c89a465c0bd2daf52baaf9665c365135189"
)
EXECUTED_ROUTE_SHA256 = (
    "11e40cca7cff6bed447043fcb10b29ddbc52b4a0951c6e880819edf91a088dc2"
)

ALLOCATOR_VA = 0x100FCC80
ALLOCATOR_SIZE = 380
ALLOCATOR_SHA256 = (
    "da50f0daf59ed3194f95fcb7c9df0198debdd7c8244497c026acb485100d44d8"
)
ALLOCATOR_CANONICAL_SHA256 = (
    "9dbd299240f648438f3e5a9e0a1d55707790af16b4d95c58f190c0475a034e6f"
)

ALLOCATOR_ARGUMENT_VA = 0x100FCCA2
ALLOCATOR_ARGUMENT_BYTES = bytes.fromhex(
    "8b44242c8b7c2428578b1c85b43e9f11e8e9870200"
)
ALLOCATOR_ARGUMENT_SHA256 = (
    "78778436a8a3cb26d687fb5194410f235024857743a62ceca0ba28eb7f57289b"
)

ALLOCATOR_RESULT_VA = 0x100FCCB7
ALLOCATOR_RESULT_BYTES = bytes.fromhex("8bf083c40485f6743f")
ALLOCATOR_RESULT_SHA256 = (
    "604b86e14ff4f8e4337467abdbda6d3f42fd1cadcb80856ea47f3e87e8b9c3f5"
)

ALLOCATOR_NORMAL_EPILOGUE_VA = 0x100FCCF6
ALLOCATOR_NORMAL_EPILOGUE_BYTES = bytes.fromhex(
    "5f8bc65e5b83c418c3"
)
ALLOCATOR_NORMAL_EPILOGUE_SHA256 = (
    "5905b49658f32cf791dfe9cc07a9bd30ee1b41a0864b6558e07cd5931a2fcc54"
)

ALLOCATOR_NULL_PATH_VA = 0x100FCCFF
ALLOCATOR_NULL_PATH_BYTES = bytes.fromhex(
    "8d4c241ce8484fffff68e83d92118d44242050e8da1e5c01"
)
ALLOCATOR_NULL_PATH_SHA256 = (
    "45100b02408c5367aee59bddde0c482df4f5ba0fcbcea2675ee2c30aaac3929b"
)

LOW_LEVEL_ALLOCATOR_VA = 0x101254A0
ALLOC_FAILURE_HELPER_VA = 0x100F1C50
CXX_THROW_VA = 0x116BEBF1


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_base_provenance():
    data = BASE_PROVENANCE.read_bytes()
    if sha256(data) != BASE_PROVENANCE_SHA256:
        raise AssertionError("append-prefix provenance authority changed")
    name = "rome2_100e2460_capacity_zero_provenance_authority"
    module = types.ModuleType(name)
    module.__file__ = str(BASE_PROVENANCE)
    sys.modules[name] = module
    exec(
        compile(data.decode("utf-8"), str(BASE_PROVENANCE), "exec"),
        module.__dict__,
    )
    return module


def rel8_target(body: bytes, body_va: int, instruction_va: int) -> int:
    offset = instruction_va - body_va
    if body[offset] not in range(0x70, 0x80):
        raise ValueError(f"0x{instruction_va:08x} is not a short Jcc")
    displacement = struct.unpack_from("<b", body, offset + 1)[0]
    return instruction_va + 2 + displacement


class Startup100e2460CapacityZeroProvenanceTests(unittest.TestCase):
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

    def test_entry_discriminator_zero_body_and_tail_are_exact(self):
        expected = (
            (
                ENTRY_PREDICATE_VA,
                ENTRY_PREDICATE_BYTES,
                ENTRY_PREDICATE_SHA256,
                0x000E1860,
            ),
            (
                ZERO_DISCRIMINATOR_VA,
                ZERO_DISCRIMINATOR_BYTES,
                ZERO_DISCRIMINATOR_SHA256,
                0x000E187D,
            ),
            (ZERO_BODY_VA, ZERO_BODY_BYTES, ZERO_BODY_SHA256, 0x000E1881),
            (
                self.base.TAIL_VA,
                self.base.TAIL_BYTES,
                self.base.TAIL_SHA256,
                0x000E192D,
            ),
        )
        for va, wanted, digest, wanted_raw_offset in expected:
            actual, section, raw_offset = self.base.read_va(
                self.dll, self.sections, va, len(wanted)
            )
            self.assertEqual((section, raw_offset), (".text", wanted_raw_offset))
            self.assertEqual(actual, wanted)
            self.assertEqual(sha256(actual), digest)

        self.assertEqual(
            sha256(ZERO_DISCRIMINATOR_BYTES + ZERO_BODY_BYTES),
            ZERO_WINDOW_SHA256,
        )
        self.assertEqual(
            (
                ENTRY_PREDICATE_VA + len(ENTRY_PREDICATE_BYTES),
                ZERO_DISCRIMINATOR_VA + len(ZERO_DISCRIMINATOR_BYTES),
                ZERO_BODY_VA + len(ZERO_BODY_BYTES),
                self.base.TAIL_VA + len(self.base.TAIL_BYTES),
            ),
            (0x100E246E, ZERO_BODY_VA, 0x100E24A5, 0x100E255C),
        )

    def test_executed_route_concatenation_is_exact(self):
        executed = (
            ENTRY_PREDICATE_BYTES
            + ZERO_DISCRIMINATOR_BYTES
            + ZERO_BODY_BYTES
            + self.base.TAIL_BYTES
        )
        self.assertEqual(len(executed), 101)
        self.assertEqual(sha256(executed), EXECUTED_ROUTE_SHA256)

        body, section, raw_offset = self.base.read_va(
            self.dll,
            self.sections,
            self.base.FUNCTION_VA,
            self.base.FUNCTION_SIZE,
        )
        self.assertEqual((section, raw_offset), (".text", 0x000E1860))
        self.assertEqual(sha256(body), self.base.FUNCTION_SHA256)
        self.assertEqual(
            executed,
            body[0x00:0x0E]
            + body[0x1D:0x45]
            + body[0xCD:0xFC],
        )

    def test_branch_targets_allocator_call_and_tail_jump_are_exact(self):
        self.assertEqual(
            rel8_target(ENTRY_PREDICATE_BYTES, ENTRY_PREDICATE_VA, 0x100E246C),
            ZERO_DISCRIMINATOR_VA,
        )
        self.assertEqual(
            rel8_target(
                ZERO_DISCRIMINATOR_BYTES,
                ZERO_DISCRIMINATOR_VA,
                0x100E247F,
            ),
            0x100E24A5,
        )
        self.assertEqual(
            self.base.rel32_target(ZERO_BODY_BYTES, ZERO_BODY_VA, 0x100E248B),
            ALLOCATOR_VA,
        )
        self.assertEqual(
            self.base.rel32_target(ZERO_BODY_BYTES, ZERO_BODY_VA, 0x100E24A0),
            self.base.TAIL_VA,
        )

    def test_allocator_arguments_cdecl_cleanup_and_mutation_order_are_exact(self):
        b = ZERO_BODY_BYTES
        self.assertEqual(b[0:3], bytes.fromhex("506a04"), "push zero, then size 4")
        self.assertEqual(
            b[3:10],
            bytes.fromhex("c7460401000000"),
            "capacity=1 must precede allocator",
        )
        self.assertEqual(b[10:15], bytes.fromhex("e8f0a70100"))
        self.assertEqual(b[15:18], bytes.fromhex("8b4e08"), "reload count")
        self.assertEqual(
            b[18:21], bytes.fromhex("83c408"), "cdecl two-argument cleanup"
        )
        self.assertEqual(b[21:25], bytes.fromhex("8b5c240c"), "load handler")
        self.assertEqual(b[25:28], bytes.fromhex("89460c"), "publish backing")
        self.assertEqual(b[28:31], bytes.fromhex("891c88"), "publish element")
        self.assertEqual(b[31:36], bytes.fromhex("e988000000"))
        self.assertEqual(
            self.base.TAIL_BYTES[:3], bytes.fromhex("ff4608"), "count increment"
        )

    def test_main_and_allocator_canonical_authorities_are_exact(self):
        self.assertEqual(sha256(self.base.INDEX.read_bytes()), self.base.INDEX_SHA256)
        main_canonical = self.base.CANONICAL / "decomp_fn_100e2460.c"
        allocator_canonical = self.base.CANONICAL / "decomp_fn_100fcc80.c"
        self.assertEqual(
            sha256(main_canonical.read_bytes()), self.base.CANONICAL_SHA256
        )
        self.assertEqual(
            sha256(allocator_canonical.read_bytes()),
            ALLOCATOR_CANONICAL_SHA256,
        )

        rows = {
            row["entry"]: row
            for row in csv.DictReader(
                self.base.INDEX.read_text(encoding="utf-8").splitlines(),
                delimiter="\t",
            )
        }
        self.assertEqual(
            (
                rows["100e2460"]["canonical_name"],
                rows["100e2460"]["size"],
                rows["100e2460"]["body_ranges"],
            ),
            ("decomp_fn_100e2460", "252", "100e2460-100e255b"),
        )
        self.assertEqual(
            (
                rows["100fcc80"]["canonical_name"],
                rows["100fcc80"]["size"],
                rows["100fcc80"]["body_ranges"],
            ),
            ("decomp_fn_100fcc80", "380", "100fcc80-100fcdfb"),
        )
        self.assertEqual(
            (
                rows["116bebf1"]["original_name"],
                rows["116bebf1"]["signature"],
                rows["116bebf1"]["body_ranges"],
            ),
            (
                "__CxxThrowException@8",
                "noreturn undefined __CxxThrowException@8(void)",
                "116bebf1-116bec5d",
            ),
        )

    def test_allocator_normal_return_and_null_throw_boundary_are_exact(self):
        allocator, section, raw_offset = self.base.read_va(
            self.dll, self.sections, ALLOCATOR_VA, ALLOCATOR_SIZE
        )
        self.assertEqual((section, raw_offset), (".text", 0x000FC080))
        self.assertEqual(sha256(allocator), ALLOCATOR_SHA256)

        expected = (
            (
                ALLOCATOR_ARGUMENT_VA,
                ALLOCATOR_ARGUMENT_BYTES,
                ALLOCATOR_ARGUMENT_SHA256,
            ),
            (
                ALLOCATOR_RESULT_VA,
                ALLOCATOR_RESULT_BYTES,
                ALLOCATOR_RESULT_SHA256,
            ),
            (
                ALLOCATOR_NORMAL_EPILOGUE_VA,
                ALLOCATOR_NORMAL_EPILOGUE_BYTES,
                ALLOCATOR_NORMAL_EPILOGUE_SHA256,
            ),
            (
                ALLOCATOR_NULL_PATH_VA,
                ALLOCATOR_NULL_PATH_BYTES,
                ALLOCATOR_NULL_PATH_SHA256,
            ),
        )
        for va, wanted, digest in expected:
            actual, actual_section, _actual_raw_offset = self.base.read_va(
                self.dll, self.sections, va, len(wanted)
            )
            self.assertEqual(actual_section, ".text")
            self.assertEqual(actual, wanted)
            self.assertEqual(sha256(actual), digest)

        self.assertEqual(
            self.base.rel32_target(
                ALLOCATOR_ARGUMENT_BYTES,
                ALLOCATOR_ARGUMENT_VA,
                0x100FCCB2,
            ),
            LOW_LEVEL_ALLOCATOR_VA,
        )
        self.assertEqual(
            rel8_target(
                ALLOCATOR_RESULT_BYTES,
                ALLOCATOR_RESULT_VA,
                0x100FCCBE,
            ),
            ALLOCATOR_NULL_PATH_VA,
        )
        self.assertEqual(
            ALLOCATOR_NORMAL_EPILOGUE_BYTES,
            bytes.fromhex("5f8bc65e5b83c418c3"),
            "normal path returns the nonzero ESI result in EAX",
        )
        self.assertEqual(
            self.base.rel32_target(
                ALLOCATOR_NULL_PATH_BYTES,
                ALLOCATOR_NULL_PATH_VA,
                0x100FCD03,
            ),
            ALLOC_FAILURE_HELPER_VA,
        )
        self.assertEqual(
            self.base.rel32_target(
                ALLOCATOR_NULL_PATH_BYTES,
                ALLOCATOR_NULL_PATH_VA,
                0x100FCD12,
            ),
            CXX_THROW_VA,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

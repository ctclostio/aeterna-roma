#!/usr/bin/env python3
"""Authenticate the remaining count >= capacity growth route of 0x100e2460.

This suite records facts from the pinned x86 image and canonical corpus only.
It does not declare the recovered growth route safe or choose an x64 allocator,
alias, overflow, failure, or ownership policy.  Those are port decisions and
must be reviewed separately from this evidence.
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

GROWTH_DISCRIMINATOR_VA = 0x100E247D
GROWTH_DISCRIMINATOR_BYTES = bytes.fromhex("85c07524")
GROWTH_DISCRIMINATOR_SHA256 = (
    "3ca7f0113f08d0e3b578001a9aa08008678880f4c657d2e1355fea67a05a0a0d"
)

GROWTH_RESIZE_VA = 0x100E24A5
GROWTH_RESIZE_BYTES = bytes.fromhex(
    "578b7e0c03c0894604741633c985c0510f48c1c1e00250"
    "e8bfa7010083c408eb0233c0"
)
GROWTH_RESIZE_SHA256 = (
    "770139608101bd65e63c6a3f285369175377f000ca9de3a89b9403d3dd9fd721"
)

GROWTH_COPY_VA = 0x100E24C8
GROWTH_COPY_BYTES = bytes.fromhex(
    "8b4e0833d289460c85c974118b4e0c8b0497890491428b4e083bd172ef"
)
GROWTH_COPY_SHA256 = (
    "889b1531d96e444b57a8d3a299cbd37340d197b55f0d2482da79bc31b27485cc"
)

GROWTH_SOURCE_ALIAS_VA = 0x100E24E5
GROWTH_SOURCE_ALIAS_BYTES = bytes.fromhex(
    "8b5c24108d4424103bc77228558d148d000000008d6c2414"
    "8d043a3be85d73148b4e0c8d4424102bc7c1f8028b0481"
    "89040aeb068b460c891c88"
)
GROWTH_SOURCE_ALIAS_SHA256 = (
    "2d30707bfc46a8940ee0c408c44b90890e8c6dd718ad8ddc60ba7796aa5dac2d"
)

GROWTH_FREE_VA = 0x100E251F
GROWTH_FREE_BYTES = bytes.fromhex("85ff740957e827a7010083c4045f")
GROWTH_FREE_SHA256 = (
    "3806e3a4d3d56813bbfc3d2f35dafc83a1608d7da50d4670648f8b532be6a5d1"
)

GROWTH_BODY_VA = GROWTH_RESIZE_VA
GROWTH_BODY_BYTES = (
    GROWTH_RESIZE_BYTES
    + GROWTH_COPY_BYTES
    + GROWTH_SOURCE_ALIAS_BYTES
    + GROWTH_FREE_BYTES
)
GROWTH_BODY_SHA256 = (
    "9b618022f138033d8b71b5d256bf66d70c15a11de0829515fb8e59aec8e77b22"
)
GROWTH_CONTROL_SHA256 = (
    "14c1178ddabeb5c9d2724e7edeb1235672ab64c10c2a3e827ddf67b94a795983"
)
EXECUTED_GROWTH_ROUTE_SHA256 = (
    "8e337476fa1159b17fa6faa04d98da4eddd0f4e0f917f278a13d561cc0c10caf"
)

ALLOCATOR_VA = 0x100FCC80
ALLOCATOR_SIZE = 380
ALLOCATOR_SHA256 = (
    "da50f0daf59ed3194f95fcb7c9df0198debdd7c8244497c026acb485100d44d8"
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
ALLOCATOR_NORMAL_EPILOGUE_BYTES = bytes.fromhex("5f8bc65e5b83c418c3")
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

FREE_VA = 0x100FCC50
FREE_SIZE = 37
FREE_BYTES = bytes.fromhex(
    "568b74240885f6741a56e8f1810200a1b03e9f1183c404"
    "85c074086a0056ffd083c4085ec3"
)
FREE_SHA256 = (
    "3c9eb430ade389d3f31098476cad63aa88c0ce9f130e7b4781897129d65c1cb4"
)
LOW_LEVEL_FREE_VA = 0x10124E50

ALLOC_FAILURE_HELPER_SIZE = 16
ALLOC_FAILURE_HELPER_BYTES = bytes.fromhex(
    "c74104841d74118bc1c701781d7411c3"
)
ALLOC_FAILURE_HELPER_SHA256 = (
    "4a6020de840331f31b19bf89452940f531ef1c808993ef14b50cb99f999f2991"
)
CXX_THROW_SIZE = 109
CXX_THROW_SHA256 = (
    "ee8234e0abd2474b5ded468c67803c4c7e69bb321afd503c024e6dee23a0443d"
)

CANONICAL_SHA256 = {
    "100e2460": "38aa07ab66bd4e551a830131c500a76a9a37a3c67c7f97fbf8fdc6c20bc67451",
    "100fcc80": "9dbd299240f648438f3e5a9e0a1d55707790af16b4d95c58f190c0475a034e6f",
    "100fcc50": "05c04f3a86ed0ffff6869efab3c1a654fddf39ff43c7488f348e311b73fad6ab",
    "101254a0": "b48b43d6ffe2ce7a35c634551463d9a5796ff4968d9dd2c4b97adbcfdd276e73",
    "10124e50": "e866eb4e0e99eaa548d8c8d41e47a07defd1e0e5c594b7d6fa2c1cd2cd456225",
    "100f1c50": "669b510bfc94b1a2d6b024279992a4bd7da5482ce095ba4ae391cbc76c26f786",
    "116bebf1": "48cbc01e514344ccd6433ff3897e3c15c1162aadee9d589a2ad9b6f6fa04530f",
}

CANONICAL_ROWS = {
    "100e2460": (
        "decomp_fn_100e2460", "FUN_100e2460",
        "undefined FUN_100e2460(void)", "252", "100e2460-100e255b",
    ),
    "100fcc80": (
        "decomp_fn_100fcc80", "FUN_100fcc80",
        "undefined FUN_100fcc80(void)", "380", "100fcc80-100fcdfb",
    ),
    "100fcc50": (
        "decomp_fn_100fcc50", "FUN_100fcc50",
        "undefined FUN_100fcc50(void)", "37", "100fcc50-100fcc74",
    ),
    "101254a0": (
        "decomp_fn_101254a0", "FUN_101254a0",
        "undefined FUN_101254a0(void)", "724", "101254a0-10125773",
    ),
    "10124e50": (
        "decomp_fn_10124e50", "FUN_10124e50",
        "undefined FUN_10124e50(void)", "1613", "10124e50-1012549c",
    ),
    "100f1c50": (
        "decomp_fn_100f1c50", "FUN_100f1c50",
        "undefined FUN_100f1c50(void)", "16", "100f1c50-100f1c5f",
    ),
    "116bebf1": (
        "decomp_fn_116bebf1", "__CxxThrowException@8",
        "noreturn undefined __CxxThrowException@8(void)",
        "109", "116bebf1-116bec5d",
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_base_provenance():
    """Source-load the pinned authority; never accept an import-cache pyc."""
    data = BASE_PROVENANCE.read_bytes()
    if sha256(data) != BASE_PROVENANCE_SHA256:
        raise AssertionError("append-prefix provenance authority changed")
    name = "rome2_100e2460_growth_provenance_authority"
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
    opcode = body[offset]
    if opcode not in range(0x70, 0x80) and opcode != 0xEB:
        raise ValueError(f"0x{instruction_va:08x} is not a short Jcc/JMP")
    displacement = struct.unpack_from("<b", body, offset + 1)[0]
    return instruction_va + 2 + displacement


def recovered_resize_machine_semantics(capacity: int) -> tuple[int, bool, int]:
    """Interpret only the pinned add/test/cmovs/shl instruction sequence."""
    if not 0 < capacity <= 0xFFFFFFFF:
        raise ValueError("the authenticated growth discriminator requires capacity != 0")
    doubled = (capacity << 1) & 0xFFFFFFFF
    if doubled == 0:
        return doubled, False, 0
    nonnegative = 0 if doubled & 0x80000000 else doubled
    byte_count = (nonnegative << 2) & 0xFFFFFFFF
    return doubled, True, byte_count


class Startup100e2460GrowthBranchProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = load_base_provenance()
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

    def test_entry_predicates_and_growth_branch_targets_are_exact(self):
        expected = (
            (
                ENTRY_PREDICATE_VA,
                ENTRY_PREDICATE_BYTES,
                ENTRY_PREDICATE_SHA256,
                0x000E1860,
            ),
            (
                GROWTH_DISCRIMINATOR_VA,
                GROWTH_DISCRIMINATOR_BYTES,
                GROWTH_DISCRIMINATOR_SHA256,
                0x000E187D,
            ),
        )
        for va, wanted, digest, raw_offset in expected:
            actual, section, actual_raw_offset = self.base.read_va(
                self.dll, self.sections, va, len(wanted)
            )
            self.assertEqual((section, actual_raw_offset), (".text", raw_offset))
            self.assertEqual(actual, wanted)
            self.assertEqual(sha256(actual), digest)

        self.assertEqual(
            ENTRY_PREDICATE_BYTES[4:14],
            bytes.fromhex("8b4e088b46043bc8730f"),
            "load count/capacity, unsigned count >= capacity discriminator",
        )
        self.assertEqual(
            rel8_target(ENTRY_PREDICATE_BYTES, ENTRY_PREDICATE_VA, 0x100E246C),
            GROWTH_DISCRIMINATOR_VA,
        )
        self.assertEqual(
            GROWTH_DISCRIMINATOR_BYTES,
            bytes.fromhex("85c07524"),
            "test capacity, take growth only when capacity != 0",
        )
        self.assertEqual(
            rel8_target(
                GROWTH_DISCRIMINATOR_BYTES,
                GROWTH_DISCRIMINATOR_VA,
                0x100E247F,
            ),
            GROWTH_BODY_VA,
        )

    def test_full_growth_windows_and_executed_route_are_exact(self):
        expected = (
            (GROWTH_RESIZE_VA, GROWTH_RESIZE_BYTES, GROWTH_RESIZE_SHA256, 0x000E18A5),
            (GROWTH_COPY_VA, GROWTH_COPY_BYTES, GROWTH_COPY_SHA256, 0x000E18C8),
            (
                GROWTH_SOURCE_ALIAS_VA,
                GROWTH_SOURCE_ALIAS_BYTES,
                GROWTH_SOURCE_ALIAS_SHA256,
                0x000E18E5,
            ),
            (GROWTH_FREE_VA, GROWTH_FREE_BYTES, GROWTH_FREE_SHA256, 0x000E191F),
            (
                self.base.TAIL_VA,
                self.base.TAIL_BYTES,
                self.base.TAIL_SHA256,
                0x000E192D,
            ),
        )
        for va, wanted, digest, raw_offset in expected:
            actual, section, actual_raw_offset = self.base.read_va(
                self.dll, self.sections, va, len(wanted)
            )
            self.assertEqual((section, actual_raw_offset), (".text", raw_offset))
            self.assertEqual(actual, wanted)
            self.assertEqual(sha256(actual), digest)

        self.assertEqual(len(GROWTH_BODY_BYTES), 136)
        self.assertEqual(sha256(GROWTH_BODY_BYTES), GROWTH_BODY_SHA256)
        self.assertEqual(
            sha256(GROWTH_DISCRIMINATOR_BYTES + GROWTH_BODY_BYTES),
            GROWTH_CONTROL_SHA256,
        )
        self.assertEqual(
            (
                GROWTH_RESIZE_VA + len(GROWTH_RESIZE_BYTES),
                GROWTH_COPY_VA + len(GROWTH_COPY_BYTES),
                GROWTH_SOURCE_ALIAS_VA + len(GROWTH_SOURCE_ALIAS_BYTES),
                GROWTH_FREE_VA + len(GROWTH_FREE_BYTES),
            ),
            (GROWTH_COPY_VA, GROWTH_SOURCE_ALIAS_VA, GROWTH_FREE_VA, self.base.TAIL_VA),
        )

        executed = (
            ENTRY_PREDICATE_BYTES
            + GROWTH_DISCRIMINATOR_BYTES
            + GROWTH_BODY_BYTES
            + self.base.TAIL_BYTES
        )
        self.assertEqual(len(executed), 201)
        self.assertEqual(sha256(executed), EXECUTED_GROWTH_ROUTE_SHA256)
        self.assertEqual(self.function_raw_offset, 0x000E1860)
        self.assertEqual(sha256(self.function), self.base.FUNCTION_SHA256)
        self.assertEqual(
            executed,
            self.function[0x00:0x0E]
            + self.function[0x1D:0x21]
            + self.function[0x45:0xFC],
        )

    def test_all_growth_control_flow_targets_are_exact(self):
        targets = (
            (GROWTH_RESIZE_BYTES, GROWTH_RESIZE_VA, 0x100E24AE, 0x100E24C6),
            (GROWTH_RESIZE_BYTES, GROWTH_RESIZE_VA, 0x100E24C4, 0x100E24C8),
            (GROWTH_COPY_BYTES, GROWTH_COPY_VA, 0x100E24D2, 0x100E24E5),
            (GROWTH_COPY_BYTES, GROWTH_COPY_VA, 0x100E24E3, 0x100E24D4),
            (
                GROWTH_SOURCE_ALIAS_BYTES,
                GROWTH_SOURCE_ALIAS_VA,
                0x100E24EF,
                0x100E2519,
            ),
            (
                GROWTH_SOURCE_ALIAS_BYTES,
                GROWTH_SOURCE_ALIAS_VA,
                0x100E2503,
                0x100E2519,
            ),
            (
                GROWTH_SOURCE_ALIAS_BYTES,
                GROWTH_SOURCE_ALIAS_VA,
                0x100E2517,
                0x100E251F,
            ),
            (GROWTH_FREE_BYTES, GROWTH_FREE_VA, 0x100E2521, 0x100E252C),
            (self.base.TAIL_BYTES, self.base.TAIL_VA, 0x100E2553, 0x100E2545),
        )
        for body, body_va, instruction_va, wanted_target in targets:
            self.assertEqual(
                rel8_target(body, body_va, instruction_va), wanted_target
            )

        self.assertEqual(
            self.base.rel32_target(
                GROWTH_RESIZE_BYTES, GROWTH_RESIZE_VA, 0x100E24BC
            ),
            ALLOCATOR_VA,
        )
        self.assertEqual(
            self.base.rel32_target(
                GROWTH_FREE_BYTES, GROWTH_FREE_VA, 0x100E2524
            ),
            FREE_VA,
        )

    def test_doubled_capacity_signed_and_overflow_behavior_is_exact(self):
        b = GROWTH_RESIZE_BYTES
        self.assertEqual(b[0:4], bytes.fromhex("578b7e0c"), "save old backing")
        self.assertEqual(b[4:9], bytes.fromhex("03c0894604"),
                         "32-bit add eax,eax, then publish wrapped capacity")
        self.assertEqual(b[9:11], bytes.fromhex("7416"),
                         "wrapped-zero skips the allocator call")
        self.assertEqual(b[11:19], bytes.fromhex("33c985c0510f48c1"),
                         "zero class, signed test, push class, cmovs size to zero")
        self.assertEqual(b[19:23], bytes.fromhex("c1e00250"),
                         "32-bit byte-count shift then push size")
        self.assertEqual(b[28:35], bytes.fromhex("83c408eb0233c0"),
                         "cdecl cleanup, converge, or synthesize null result")

        cases = {
            0x00000001: (0x00000002, True, 0x00000008),
            0x1FFFFFFF: (0x3FFFFFFE, True, 0xFFFFFFF8),
            0x20000000: (0x40000000, True, 0x00000000),
            0x3FFFFFFF: (0x7FFFFFFE, True, 0xFFFFFFF8),
            0x40000000: (0x80000000, True, 0x00000000),
            0x7FFFFFFF: (0xFFFFFFFE, True, 0x00000000),
            0x80000000: (0x00000000, False, 0x00000000),
            0x80000001: (0x00000002, True, 0x00000008),
            0xA0000000: (0x40000000, True, 0x00000000),
            0xFFFFFFFF: (0xFFFFFFFE, True, 0x00000000),
        }
        for capacity, expected in cases.items():
            with self.subTest(capacity=f"0x{capacity:08x}"):
                self.assertEqual(
                    recovered_resize_machine_semantics(capacity), expected
                )
        with self.assertRaises(ValueError):
            recovered_resize_machine_semantics(0)

    def test_allocator_arguments_order_and_failure_boundary_are_exact(self):
        # In the growth call site, cdecl right-to-left order is class zero first,
        # then the computed byte count.  Capacity was already published.
        self.assertEqual(GROWTH_RESIZE_BYTES[6:9], bytes.fromhex("894604"))
        self.assertEqual(GROWTH_RESIZE_BYTES[11:16], bytes.fromhex("33c985c051"))
        self.assertEqual(GROWTH_RESIZE_BYTES[19:28],
                         bytes.fromhex("c1e00250e8bfa70100"))
        self.assertEqual(GROWTH_RESIZE_BYTES[28:31], bytes.fromhex("83c408"))

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
                0x000FC0A2,
            ),
            (
                ALLOCATOR_RESULT_VA,
                ALLOCATOR_RESULT_BYTES,
                ALLOCATOR_RESULT_SHA256,
                0x000FC0B7,
            ),
            (
                ALLOCATOR_NORMAL_EPILOGUE_VA,
                ALLOCATOR_NORMAL_EPILOGUE_BYTES,
                ALLOCATOR_NORMAL_EPILOGUE_SHA256,
                0x000FC0F6,
            ),
            (
                ALLOCATOR_NULL_PATH_VA,
                ALLOCATOR_NULL_PATH_BYTES,
                ALLOCATOR_NULL_PATH_SHA256,
                0x000FC0FF,
            ),
        )
        for va, wanted, digest, wanted_raw_offset in expected:
            actual, actual_section, actual_raw_offset = self.base.read_va(
                self.dll, self.sections, va, len(wanted)
            )
            self.assertEqual(
                (actual_section, actual_raw_offset),
                (".text", wanted_raw_offset),
            )
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
            rel8_target(ALLOCATOR_RESULT_BYTES, ALLOCATOR_RESULT_VA, 0x100FCCBE),
            ALLOCATOR_NULL_PATH_VA,
        )
        self.assertEqual(
            ALLOCATOR_NORMAL_EPILOGUE_BYTES,
            bytes.fromhex("5f8bc65e5b83c418c3"),
            "normal boundary returns the nonzero ESI result in EAX",
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
        throw_prep, section, raw_offset = self.base.read_va(
            self.dll,
            self.sections,
            ALLOC_FAILURE_HELPER_VA,
            ALLOC_FAILURE_HELPER_SIZE,
        )
        self.assertEqual((section, raw_offset), (".text", 0x000F1050))
        self.assertEqual(throw_prep, ALLOC_FAILURE_HELPER_BYTES)
        self.assertEqual(sha256(throw_prep), ALLOC_FAILURE_HELPER_SHA256)
        cxx_throw, section, raw_offset = self.base.read_va(
            self.dll, self.sections, CXX_THROW_VA, CXX_THROW_SIZE
        )
        self.assertEqual((section, raw_offset), (".text", 0x016BDFF1))
        self.assertEqual(sha256(cxx_throw), CXX_THROW_SHA256)

    def test_old_buffer_copy_loop_and_reloaded_count_are_exact(self):
        b = GROWTH_COPY_BYTES
        self.assertEqual(b[0:8], bytes.fromhex("8b4e0833d289460c"),
                         "load count, zero index, publish new backing")
        self.assertEqual(b[8:12], bytes.fromhex("85c97411"),
                         "zero count skips the copy loop")
        self.assertEqual(b[12:21], bytes.fromhex("8b4e0c8b0497890491"),
                         "reload new backing and copy old[index] to new[index]")
        self.assertEqual(b[21:29], bytes.fromhex("428b4e083bd172ef"),
                         "increment index, reload count, unsigned loop back edge")
        self.assertEqual(
            rel8_target(b, GROWTH_COPY_VA, 0x100E24D2),
            GROWTH_SOURCE_ALIAS_VA,
        )
        self.assertEqual(
            rel8_target(b, GROWTH_COPY_VA, 0x100E24E3), 0x100E24D4
        )

    def test_source_alias_branch_and_old_buffer_free_are_exact(self):
        b = GROWTH_SOURCE_ALIAS_BYTES
        self.assertEqual(b[0:12], bytes.fromhex("8b5c24108d4424103bc77228"),
                         "load source value, compare source-cell address to old base")
        self.assertEqual(b[12:32],
                         bytes.fromhex("558d148d000000008d6c24148d043a3be85d7314"),
                         "form old end and branch direct when source is outside")
        self.assertEqual(b[32:52],
                         bytes.fromhex("8b4e0c8d4424102bc7c1f8028b048189040aeb06"),
                         "map old-relative source index through new backing")
        self.assertEqual(b[52:58], bytes.fromhex("8b460c891c88"),
                         "direct source-value append path")
        self.assertEqual(
            rel8_target(b, GROWTH_SOURCE_ALIAS_VA, 0x100E24EF), 0x100E2519
        )
        self.assertEqual(
            rel8_target(b, GROWTH_SOURCE_ALIAS_VA, 0x100E2503), 0x100E2519
        )
        self.assertEqual(
            rel8_target(b, GROWTH_SOURCE_ALIAS_VA, 0x100E2517), GROWTH_FREE_VA
        )

        self.assertEqual(GROWTH_FREE_BYTES[0:4], bytes.fromhex("85ff7409"),
                         "null old backing skips free")
        self.assertEqual(GROWTH_FREE_BYTES[4:13],
                         bytes.fromhex("57e827a7010083c404"),
                         "push old backing, call free, cdecl cleanup")
        self.assertEqual(GROWTH_FREE_BYTES[-1:], bytes.fromhex("5f"),
                         "restore EDI before the common tail")
        self.assertEqual(
            self.base.rel32_target(
                GROWTH_FREE_BYTES, GROWTH_FREE_VA, 0x100E2524
            ),
            FREE_VA,
        )

        free_body, section, raw_offset = self.base.read_va(
            self.dll, self.sections, FREE_VA, FREE_SIZE
        )
        self.assertEqual((section, raw_offset), (".text", 0x000FC050))
        self.assertEqual(free_body, FREE_BYTES)
        self.assertEqual(sha256(free_body), FREE_SHA256)
        self.assertEqual(
            rel8_target(FREE_BYTES, FREE_VA, 0x100FCC57), 0x100FCC73
        )
        self.assertEqual(
            self.base.rel32_target(FREE_BYTES, FREE_VA, 0x100FCC5A),
            LOW_LEVEL_FREE_VA,
        )

    def test_common_dispatch_and_peek_tail_is_exact(self):
        b = self.base.TAIL_BYTES
        self.assertEqual(sha256(b), self.base.TAIL_SHA256)
        self.assertEqual(b[0:3], bytes.fromhex("ff4608"), "count increment")
        self.assertEqual(
            b[3:16], bytes.fromhex("8bcb8b03ff7424108b4004ffd0"),
            "vtable-slot-4 thiscall dispatch",
        )
        self.assertEqual(b[16:22], bytes.fromhex("8b3570f67211"),
                         "PeekMessageW IAT-cell load")
        self.assertEqual(b[24:36], bytes.fromhex("6a016a006a006a006a00ffd6"),
                         "PeekMessageW(NULL,NULL,0,0,PM_REMOVE)")
        self.assertEqual(b[36:40], bytes.fromhex("85c075f0"),
                         "nonzero BOOL drains again")
        self.assertEqual(
            rel8_target(b, self.base.TAIL_VA, 0x100E2553), 0x100E2545
        )
        self.assertEqual(b[-7:], bytes.fromhex("5e8ac35bc20800"),
                         "saved AL and ret 8 epilogue")
        self.assertEqual(
            self.base.imported_name_at_iat(
                self.dll,
                self.optional,
                self.sections,
                self.base.PEEK_MESSAGE_IAT_VA,
            ),
            ("USER32.dll", "PeekMessageW"),
        )

    def test_canonical_rows_and_files_for_relied_boundaries_are_exact(self):
        self.assertEqual(
            sha256(self.base.INDEX.read_bytes()), self.base.INDEX_SHA256
        )
        rows = {
            row["entry"]: row
            for row in csv.DictReader(
                self.base.INDEX.read_text(encoding="utf-8").splitlines(),
                delimiter="\t",
            )
        }
        for entry, expected in CANONICAL_ROWS.items():
            with self.subTest(entry=entry):
                row = rows[entry]
                self.assertEqual(
                    (
                        row["canonical_name"],
                        row["original_name"],
                        row["signature"],
                        row["size"],
                        row["body_ranges"],
                    ),
                    expected,
                )
                canonical = self.base.CANONICAL / f"decomp_fn_{entry}.c"
                self.assertTrue(canonical.exists())
                self.assertEqual(
                    sha256(canonical.read_bytes()), CANONICAL_SHA256[entry]
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Authenticate dependencies for the injected executable port of 0x100ea4d0.

This suite source-pins the earlier evidence-only authority and reuses its
authenticated PE parser and exact 265-byte body.  It proves the six original
allocator calls, vtable identities, receiver-derived argument/vector values,
router-call order, slot-plus-four method identities, and canonical row.  It
does not prove the x64 port's injected callbacks, argument/backing alias
envelope, post-router handler-graph audit, finite Peek budget, explicit
statuses, or prefix-commit policy; those are documented port decisions
replacing original native allocation and null-write traps.
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
AUTHORITY = ROOT / "scripts" / "test_x64_startup_100ea4d0_evidence_provenance.py"
AUTHORITY_SHA256 = (
    "8cb4a70f52f3afb45a2fbf3ed60eee45548fa35ba2c7f113871e5bc1c0444b63"
)

ARGUMENT_OFFSET = 0x824
VECTOR_OFFSET = 0x854
DERIVATION_OFFSET = 0x1C
DERIVATION_BYTES = bytes.fromhex("8db72408000081c754080000")
ROUTER_PRELUDE_BYTES = bytes.fromhex("56508bcf")

VTABLE_SLOT4_TARGETS = (
    0x100E8D00,
    0x100E85D0,
    0x100E8580,
    0x100E9340,
    0x100E92C0,
    0x100E87A0,
)
VTABLE_RECORD_BYTES = (
    bytes.fromhex("20170e10008d0e10"),
    bytes.fromhex("b0380d10d0850e10"),
    bytes.fromhex("50120e1080850e10"),
    bytes.fromhex("00190e1040930e10"),
    bytes.fromhex("c0180e10c0920e10"),
    bytes.fromhex("70140e10a0870e10"),
)
VTABLE_RECORD_RAW_OFFSETS = (
    0x0173DC0C,
    0x0173DC14,
    0x0173DC1C,
    0x0173DC24,
    0x0173DCEC,
    0x0173DCDC,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_pinned_authority():
    data = AUTHORITY.read_bytes()
    if sha256(data) != AUTHORITY_SHA256:
        raise AssertionError("100ea4d0 evidence authority changed")
    name = "rome2_100ea4d0_executable_evidence_authority"
    module = types.ModuleType(name)
    module.__file__ = str(AUTHORITY)
    sys.modules[name] = module
    exec(compile(data.decode("utf-8"), str(AUTHORITY), "exec"), module.__dict__)
    return module


class Startup100ea4d0ExecutableProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = load_pinned_authority()
        cls.dll = cls.authority.DLL.read_bytes()
        if (
            len(cls.dll) != 28_278_272
            or sha256(cls.dll) != cls.authority.DLL_SHA256
        ):
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.sections = cls.authority.parse_pe32(cls.dll)
        cls.body, cls.section, cls.raw_offset = cls.authority.read_va(
            cls.dll,
            cls.sections,
            cls.authority.EA4D0_VA,
            cls.authority.EA4D0_SIZE,
        )

    def test_evidence_authority_is_source_pinned(self):
        self.assertEqual(sha256(AUTHORITY.read_bytes()), AUTHORITY_SHA256)
        self.assertEqual(self.authority.EA4D0_SIZE, 265)
        self.assertEqual(
            self.authority.EA4D0_SHA256,
            "582b4c4324650b88f969c1af5fac0dce0d6ffd69e1043ee99d834e6b102c7af3",
        )
        self.assertEqual(self.authority.ALLOCATOR_VA, 0x100D12B0)
        self.assertEqual(self.authority.INITIALIZER_VA, 0x100E2460)

    def test_exact_body_and_checked_receiver_derivations_are_pinned(self):
        self.assertEqual((self.section, self.raw_offset), (".text", 0x000E98D0))
        self.assertEqual(len(self.body), self.authority.EA4D0_SIZE)
        self.assertEqual(sha256(self.body), self.authority.EA4D0_SHA256)
        self.assertEqual(
            self.body[DERIVATION_OFFSET : DERIVATION_OFFSET + len(DERIVATION_BYTES)],
            DERIVATION_BYTES,
        )
        self.assertEqual(
            struct.unpack_from("<I", self.body, DERIVATION_OFFSET + 2)[0],
            ARGUMENT_OFFSET,
        )
        self.assertEqual(
            struct.unpack_from("<I", self.body, DERIVATION_OFFSET + 8)[0],
            VECTOR_OFFSET,
        )

    def test_six_allocate_store_router_sequences_are_exact(self):
        self.assertEqual(len(self.authority.ALLOC_CALL_OFFSETS), 6)
        self.assertEqual(len(self.authority.INITIALIZER_CALL_OFFSETS), 6)
        self.assertEqual(len(self.authority.VTABLE_IMMEDIATES), 6)
        for index in range(6):
            allocate_offset = self.authority.ALLOC_CALL_OFFSETS[index]
            store_offset = self.authority.VTABLE_STORE_OFFSETS[index]
            router_offset = self.authority.INITIALIZER_CALL_OFFSETS[index]
            with self.subTest(registration=index):
                self.assertLess(allocate_offset, store_offset)
                self.assertLess(store_offset, router_offset)
                self.assertEqual(
                    self.authority.rel32_target(
                        self.body,
                        self.authority.EA4D0_VA,
                        self.authority.EA4D0_VA + allocate_offset,
                    ),
                    self.authority.ALLOCATOR_VA,
                )
                self.assertEqual(
                    self.body[store_offset : store_offset + 6],
                    b"\xc7\x00" + struct.pack(
                        "<I", self.authority.VTABLE_IMMEDIATES[index]
                    ),
                )
                self.assertEqual(
                    self.body[router_offset - 4 : router_offset],
                    ROUTER_PRELUDE_BYTES,
                )
                self.assertEqual(
                    self.authority.rel32_target(
                        self.body,
                        self.authority.EA4D0_VA,
                        self.authority.EA4D0_VA + router_offset,
                    ),
                    self.authority.INITIALIZER_VA,
                )
        self.assertEqual(self.body[-1:], b"\xc3")

    def test_vtable_slot_plus_four_targets_are_exact(self):
        for vtable, wanted, wanted_bytes, wanted_raw in zip(
            self.authority.VTABLE_IMMEDIATES,
            VTABLE_SLOT4_TARGETS,
            VTABLE_RECORD_BYTES,
            VTABLE_RECORD_RAW_OFFSETS,
        ):
            with self.subTest(vtable=f"0x{vtable:08x}"):
                record, section, raw_offset = self.authority.read_va(
                    self.dll, self.sections, vtable, 8
                )
                self.assertEqual((section, raw_offset), (".rdata", wanted_raw))
                self.assertEqual(record, wanted_bytes)
                self.assertEqual(struct.unpack_from("<I", record, 4)[0], wanted)

    def test_canonical_entry_and_policy_boundary_are_exact(self):
        canonical = self.authority.CANONICAL / "decomp_fn_100ea4d0.c"
        self.assertEqual(
            sha256(canonical.read_bytes()),
            self.authority.CANONICAL_100EA4D0_SHA256,
        )
        rows = {
            row["entry"]: row
            for row in csv.DictReader(
                self.authority.INDEX.read_text(encoding="utf-8").splitlines(),
                delimiter="\t",
            )
        }
        row = rows["100ea4d0"]
        self.assertEqual(
            (
                row["canonical_name"],
                row["original_name"],
                row["signature"],
                row["size"],
                row["body_ranges"],
            ),
            (
                "decomp_fn_100ea4d0",
                "FUN_100ea4d0",
                "undefined FUN_100ea4d0(void)",
                "265",
                "100ea4d0-100ea5d8",
            ),
        )
        normalized_doc = " ".join((__doc__ or "").split())
        self.assertIn("does not prove the x64 port's injected callbacks", normalized_doc)
        self.assertIn("port decisions", normalized_doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)

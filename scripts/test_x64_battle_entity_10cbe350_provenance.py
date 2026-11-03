"""Pin the original entity constructor and its corrected stack-word sources."""
from __future__ import annotations

import hashlib
import struct
import unittest
from pathlib import Path

from test_x64_startup_100edd70_caller_closure_provenance import (
    DLL_SHA256, DLL_SIZE, parse_pe32, read_va,
)


DLL = Path(__file__).resolve().parents[1] / "Total War Rome II/empire.retail.dll"
BODIES = {
    0x10CBE350: (512, "1a9cdb6c8d2dbeafae459afa588c05fc2f3ca2361bcde655da5183e241e55525"),
    0x10CC1A10: (127, "2c717aad747c2446ea358488d2d4b9c0c7ddcde3c482398ced48ac23b816227c"),
    0x100F1700: (32, "b914ce9c4151eda34ea7777f588df95d50c9b94093c4ee3d3513192c6e5c517d"),
    0x100EF2C0: (111, "12af44082fcc9372e2f8a1e93544777c847dfba294763d08b2d7b672c8712c07"),
}

# PC, instruction bytes, live stack depth below entry ESP, argument index.
# The two three-word pushes and the by-value climate string account for the
# temporary depth changes; RET 0x18 restores the ordinary 0x18-byte frame.
STACK_READS = (
    (0x10CBE3B3, "8b4c2440", 0x18, 9),
    (0x10CBE3FF, "8a442458", 0x24, 12),
    (0x10CBE409, "8b44246c", 0x30, 14),
    (0x10CBE453, "8b5c2444", 0x18, 10),
    (0x10CBE4F6, "ff742460", 0x18, 17),
    (0x10CBE505, "8a442464", 0x18, 18),
    (0x10CBE50F, "ff742448", 0x18, 11),
    (0x10CBE51E, "8a442450", 0x18, 13),
    (0x10CBE52C, "8b442458", 0x18, 15),
    (0x10CBE536, "8a44245c", 0x18, 16),
)


@unittest.skipUnless(DLL.is_file(), "original game image is absent")
class BattleEntityProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = DLL.read_bytes()
        if len(cls.image) != DLL_SIZE or hashlib.sha256(cls.image).hexdigest() != DLL_SHA256:
            raise AssertionError("original DLL differs from the pinned corpus")
        cls.base, cls.sections = parse_pe32(cls.image)

    def read(self, address, size):
        return read_va(self.image, self.base, self.sections, address, size)

    def test_complete_original_bodies(self):
        for address, (size, digest) in BODIES.items():
            with self.subTest(address=hex(address)):
                self.assertEqual(hashlib.sha256(self.read(address, size)).hexdigest(), digest)

    def test_independent_origin_vector_and_suffix_stack_sources(self):
        self.assertEqual(self.read(0x10CBE350, 6).hex(), "83ec0c535657")
        for address, instruction, depth, index in STACK_READS:
            with self.subTest(address=hex(address), argument=index):
                body = bytes.fromhex(instruction)
                self.assertEqual(self.read(address, len(body)), body)
                self.assertEqual(body[-1] - depth, 4 + 4 * index)

    def test_by_value_climate_string_and_incoming_destructor(self):
        self.assertEqual(self.read(0x10CBE403, 3).hex(), "83ec0c")
        for address, target in ((0x10CBE433, 0x100F1800), (0x10CBE43B, 0x10CC1A10)):
            call = self.read(address, 5)
            self.assertEqual(call[0], 0xE8)
            self.assertEqual(address + 5 + struct.unpack_from("<i", call, 1)[0], target)
        self.assertEqual(self.read(0x10CC1A8C, 3).hex(), "c21800")
        # Final destructor addresses arg06 at entry ESP+0x1c, not arg03.
        self.assertEqual(self.read(0x10CBE522, 4).hex(), "8d4c2434")
        self.assertEqual(0x34 - 0x18, 4 + 4 * 6)
        self.assertEqual(self.read(0x10CBE54D, 3).hex(), "c24c00")

    def test_allocation_clamp_does_not_clamp_vector_count(self):
        self.assertEqual(self.read(0x10CBE486, 3).hex(), "8b4b04")
        self.assertEqual(self.read(0x10CBE4A1, 9).hex(), "0f48c88d0449c1e002")
        # The copy loop reloads the unchanged destination count at this+0xb8.
        self.assertEqual(self.read(0x10CBE4DA, 6).hex(), "8b87b8000000")
        self.assertEqual(self.read(0x10CBE4E0, 6).hex(), "83c60c83c30c")


if __name__ == "__main__":
    unittest.main(verbosity=2)

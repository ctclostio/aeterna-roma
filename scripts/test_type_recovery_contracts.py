from __future__ import annotations

import copy
import json
import struct
import unittest
from pathlib import Path

import type_recovery_contracts as contracts


class ImageMappingTests(unittest.TestCase):
    def test_file_and_virtual_tail_are_distinct(self):
        data = bytes(range(32))
        sections = [(0x1000, 16, 8, 8)]
        self.assertEqual(contracts.image_bytes(data, 0x10000000, sections, 0x10001002, 3),
                         (data[10:13], "file"))
        self.assertEqual(contracts.image_bytes(data, 0x10000000, sections, 0x10001008, 4,
                                               allow_zero_fill=True), (bytes(4), "zero_fill"))
        self.assertEqual(contracts.image_bytes(data, 0x10000000, sections, 0x10001006, 4,
                                               allow_zero_fill=True), (data[14:16] + bytes(2),
                                                                       "file_and_zero_fill"))
        with self.assertRaises(ValueError):
            contracts.image_bytes(data, 0x10000000, sections, 0x10001008, 4)
        with self.assertRaises(ValueError):
            contracts.image_bytes(data, 0x10000000, sections, 0x10001010, 1, allow_zero_fill=True)

    def test_ambiguous_mapping_rejected(self):
        with self.assertRaises(ValueError):
            contracts.image_bytes(bytes(32), 0x10000000,
                [(0x1000, 8, 0, 8), (0x1000, 8, 8, 8)], 0x10001000, 4)

    def test_invalid_images_rejected(self):
        for data in (b"", bytes(64), b"MZ" + bytes(100)):
            with self.subTest(size=len(data)), self.assertRaises((ValueError, struct.error)):
                contracts.parse_pe32(data)


@unittest.skipUnless((contracts.ROOT / "Total War Rome II/empire.retail.dll").is_file(),
                     "original game image is absent")
class TypeContractProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = (contracts.ROOT / "Total War Rome II/empire.retail.dll").read_bytes()
        cls.registry = json.loads(contracts.CONTRACT.read_text("utf-8"))

    def test_original_functions_globals_and_vtables(self):
        result = contracts.validate_contracts(self.image, self.registry)
        self.assertTrue(result["verified"])
        self.assertEqual(result["functions"], 46)

    def test_cdecl_stack_arity_is_separate_from_return_pop(self):
        helper = next(f for f in self.registry["functions"] if f["address"] == "10102bc0")
        self.assertEqual(helper["calling_convention"], "cdecl")
        self.assertEqual(helper["receiver_register"], "none")
        self.assertEqual(helper["stack_argument_bytes"], 16)
        self.assertEqual(helper["callee_pop_bytes"], 0)
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_wrong_cdecl_return_pop_is_rejected(self):
        registry = copy.deepcopy(self.registry)
        helper = next(f for f in registry["functions"] if f["address"] == "10102bc0")
        helper["callee_pop_bytes"] = 8
        with self.assertRaisesRegex(ValueError, "cdecl callee"):
            contracts.validate_contracts(self.image, registry)

    def test_nonterminal_return_instruction_is_checked(self):
        registry = copy.deepcopy(self.registry)
        helper = next(f for f in registry["functions"] if f["address"] == "11347ed0")
        self.assertEqual(helper["return_instruction_addresses"], ["11348bc9"])
        helper["return_instruction_addresses"] = ["11348bca"]
        with self.assertRaisesRegex(ValueError, "stack return"):
            contracts.validate_contracts(self.image, registry)

    def test_probability_scales_are_binary32_instructions(self):
        registry = copy.deepcopy(self.registry)
        witness = next(w for w in registry["instruction_witnesses"] if w["address"] == "11347550")
        self.assertEqual(witness["hex"], "f30f59c1f30f59c2")
        witness["hex"] = witness["hex"].replace("f30f59", "f20f59", 1)
        with self.assertRaisesRegex(ValueError, "instruction witness"):
            contracts.validate_contracts(self.image, registry)

    def test_probability_scaling_constant_is_pinned(self):
        registry = copy.deepcopy(self.registry)
        constant = next(g for g in registry["globals"] if g["address"] == "1173e2bc")
        self.assertEqual(constant["initial_hex_le"], "cdcccc3d")
        constant["initial_hex_le"] = "cccccc3d"
        with self.assertRaisesRegex(ValueError, "global initial"):
            contracts.validate_contracts(self.image, registry)

    def test_uint_parser_multiply_add_is_pinned(self):
        registry = copy.deepcopy(self.registry)
        witness = next(w for w in registry["instruction_witnesses"] if w["address"] == "10105419")
        witness["hex"] = "00" + witness["hex"][2:]
        with self.assertRaisesRegex(ValueError, "instruction witness"):
            contracts.validate_contracts(self.image, registry)

    def test_original_peasant_literal_is_pinned(self):
        registry = copy.deepcopy(self.registry)
        literal = next(g for g in registry["globals"] if g["address"] == "1174e31c")
        self.assertEqual(bytes.fromhex(literal["initial_hex_le"]), b"peasant\0")
        literal["initial_hex_le"] = "00" + literal["initial_hex_le"][2:]
        with self.assertRaisesRegex(ValueError, "global initial"):
            contracts.validate_contracts(self.image, registry)

    def test_xml_first_named_item_load_is_pinned(self):
        registry = copy.deepcopy(self.registry)
        witness = next(w for w in registry["instruction_witnesses"] if w["address"] == "112b518c")
        self.assertIn("8b00", witness["hex"])
        witness["hex"] = witness["hex"].replace("8b00", "8b08", 1)
        with self.assertRaisesRegex(ValueError, "instruction witness"):
            contracts.validate_contracts(self.image, registry)

    def test_wrong_tag_source_offset_is_rejected(self):
        registry = copy.deepcopy(self.registry)
        witness = next(w for w in registry["instruction_witnesses"]
                       if w["address"] == "10145f4a")
        # Change ADD ECX,4 to ADD ECX,8 in the original instruction window.
        witness["hex"] = witness["hex"].replace("83c104", "83c108", 1)
        with self.assertRaisesRegex(ValueError, "instruction witness"):
            contracts.validate_contracts(self.image, registry)

    def test_attachment_receiver_instruction_is_pinned(self):
        registry = copy.deepcopy(self.registry)
        witness = next(w for w in registry["instruction_witnesses"]
                       if w["address"] == "10145f80")
        # MOV ECX,EAX is the allocated receiver, not MOV ECX,EDI (source).
        witness["hex"] = witness["hex"].replace("8bc8", "8bcf", 1)
        with self.assertRaisesRegex(ValueError, "instruction witness"):
            contracts.validate_contracts(self.image, registry)

    def test_setup_receiver_is_a_holder(self):
        registry = copy.deepcopy(self.registry)
        witness = next(w for w in registry["instruction_witnesses"]
                       if w["address"] == "1015e2b2")
        # MOV ECX,[EDI] cannot be replaced by MOV ECX,EDI.
        witness["hex"] = witness["hex"].replace("8b0f", "8bcf", 1)
        with self.assertRaisesRegex(ValueError, "instruction witness"):
            contracts.validate_contracts(self.image, registry)

    def test_coordinate_vector_receiver_offset_is_pinned(self):
        registry = copy.deepcopy(self.registry)
        witness = next(w for w in registry["instruction_witnesses"]
                       if w["address"] == "1016ee3b")
        witness["hex"] = witness["hex"].replace("8d4f68", "8d4f5c", 1)
        with self.assertRaisesRegex(ValueError, "instruction witness"):
            contracts.validate_contracts(self.image, registry)

    def test_default_setup_clears_fauna_before_resource_load(self):
        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        self.assertEqual(witnesses["101a9860"], bytes.fromhex("c7866001000000000000"))
        call = witnesses["101a989b"]
        self.assertEqual(call[0], 0xE8)
        self.assertEqual(0x101A989B + 5 + struct.unpack_from("<i", call, 1)[0], 0x112AAB60)
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_changed_image_rejected(self):
        changed = bytearray(self.image)
        changed[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "pinned target"):
            contracts.validate_contracts(bytes(changed), self.registry)

    def test_wrong_stack_abi_rejected(self):
        registry = copy.deepcopy(self.registry)
        registry["functions"][0]["stack_argument_bytes"] += 4
        with self.assertRaisesRegex(ValueError, "stack return"):
            contracts.validate_contracts(self.image, registry)

    def test_zero_fill_cannot_be_reported_as_file_bytes(self):
        registry = copy.deepcopy(self.registry)
        bss = next(item for item in registry["globals"] if item["storage"] == "zero_fill")
        bss["storage"] = "file"
        with self.assertRaisesRegex(ValueError, "global initial storage"):
            contracts.validate_contracts(self.image, registry)

    def test_vtable_is_identity_only(self):
        registry = copy.deepcopy(self.registry)
        registry["vtables"][0]["first_slot_code_identity"] = "00000000"
        with self.assertRaisesRegex(ValueError, "vtable identity"):
            contracts.validate_contracts(self.image, registry)

    def test_dropped_registry_category_rejected(self):
        registry = copy.deepcopy(self.registry)
        registry["functions"] = []
        with self.assertRaisesRegex(ValueError, "empty or invalid"):
            contracts.validate_contracts(self.image, registry)


if __name__ == "__main__":
    unittest.main()

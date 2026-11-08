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

    def test_disjoint_body_reads_exclude_gap_bytes(self):
        data = bytes(range(32)); sections = [(0x1000, 24, 4, 24)]
        function = {"address": "10001000", "bytes": 7, "body_ranges": [
            {"start": "10001000", "end": "10001002"},
            {"start": "10001008", "end": "1000100b"}]}
        self.assertEqual(contracts.function_body_parts(data, 0x10000000, sections, function),
                         [(0x10001000, data[4:7]), (0x10001008, data[12:16])])
        function = {"address": "10001000", "bytes": 3}
        self.assertEqual(contracts.function_body_parts(data, 0x10000000, sections, function),
                         [(0x10001000, data[4:7])])

    def test_invalid_body_range_sets_are_rejected(self):
        data = bytes(range(32)); sections = [(0x1000, 24, 4, 24)]
        good = {"address": "10001000", "bytes": 7, "body_ranges": [
            {"start": "10001000", "end": "10001002"},
            {"start": "10001008", "end": "1000100b"}]}
        cases = []
        for ranges in ([], list(reversed(good["body_ranges"])),
                       [{"start": "10001000", "end": "10001004"},
                        {"start": "10001004", "end": "10001005"}],
                       [{"start": "10001002", "end": "10001000"}]):
            mutant = copy.deepcopy(good); mutant["body_ranges"] = ranges; cases.append(mutant)
        for field, value in (("bytes", 6), ("bytes", 0), ("bytes", True), ("address", "10001005")):
            mutant = copy.deepcopy(good); mutant[field] = value; cases.append(mutant)
        for mutant in cases:
            with self.subTest(mutant=mutant), self.assertRaises(ValueError):
                contracts.function_body_parts(data, 0x10000000, sections, mutant)


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
        self.assertEqual(result["functions"], 72)

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

    def test_explicit_setup_node_bypasses_resource_lookup(self):
        witness = next(w for w in self.registry["instruction_witnesses"]
                       if w["address"] == "101a986a")
        branch = bytes.fromhex(witness["hex"])
        # TEST EAX,EAX / JZ default path; nonzero node is pushed for the
        # child decoder, whose receiver is the local card-pointer holder.
        self.assertEqual(branch[:9], bytes.fromhex("85c07415508d4c240c"))
        self.assertEqual(branch[9], 0xE8)
        self.assertEqual(0x101A9873 + 5 + struct.unpack_from("<i", branch, 10)[0], 0x1015E280)
        self.assertEqual(0x101A986C + 2 + branch[3], 0x101A9883)
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_xml_root_state_initialization_and_raw_flag_read(self):
        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        self.assertEqual(witnesses["112aab6b"], bytes.fromhex("c7060000000066c746040100"))
        self.assertEqual(witnesses["101b927d"], bytes.fromhex("8a4104c3"))
        base, sections = contracts.parse_pe32(self.image)
        walk, _ = contracts.image_bytes(self.image, base, sections, 0x101B9270, 17)
        self.assertEqual(walk, bytes.fromhex("8b0185c074078bc8e9f3ffffff8a4104c3"))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_loader_callback_adapts_two_stack_arguments(self):
        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        adapter = witnesses["112b5110"]
        self.assertEqual(len(adapter), 20)
        self.assertEqual(adapter[:14], bytes.fromhex("51ff74240c8d4c2407ff74240ce8"))
        self.assertEqual(0x112B511D + 5 + struct.unpack_from("<i", adapter, 14)[0], 0x112A7B60)
        self.assertEqual(adapter[18:], bytes.fromhex("59c3"))
        self.assertEqual(witnesses["112aacc9"], bytes.fromhex("ff54243083c408"))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_drive_rooted_predicate_is_a_byte_prefix_test(self):
        base, sections = contracts.parse_pe32(self.image)
        body, _ = contracts.image_bytes(self.image, base, sections, 0x100F3B20, 27)
        # No existence/drive-letter check: byte +1 is ':', byte +2 is '/' or
        # '\\'. Only AL is assigned 0/1; upper EAX is not an integer boolean.
        self.assertEqual(body, bytes.fromhex("8b4424048078013a750e8a40023c5c74043c2f7503b001c332c0c3"))

    def test_vfs_secondary_dispatch_and_selected_targets(self):
        globals_ = {g["address"]: bytes.fromhex(g["initial_hex_le"]) for g in self.registry["globals"]}
        self.assertEqual(struct.unpack("<II", globals_["119e1004"]), (0x1189791C, 0x11897994))
        self.assertEqual(struct.unpack("<II", globals_["118978e8"]), (0x112BD130, 0x112BD3B0))
        self.assertEqual(struct.unpack("<II", globals_["11897994"]), (0x112BD0C0, 0x112BD0C0))
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["112a7c63"], bytes.fromhex("8d58048b03"))
        self.assertEqual(w["112a7c7d"], bytes.fromhex("8b7804"))
        self.assertEqual(w["112a7cab"], bytes.fromhex("ffd7"))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_vfs_active_hit_branches_are_present(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        first, second = w["112bd49f"], w["112bd5a3"]
        self.assertEqual(first[9:11], bytes.fromhex("0f84"))
        self.assertEqual(0x112BD4A8 + 6 + struct.unpack_from("<i", first, 11)[0], 0x112BD5A3)
        self.assertEqual(second[6:8], bytes.fromhex("0f84"))
        self.assertEqual(0x112BD5A9 + 6 + struct.unpack_from("<i", second, 8)[0], 0x112BD64C)
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_vfs_hash_uses_signed_independent_halfword_sums(self):
        registry = copy.deepcopy(self.registry)
        w = {w["address"]: w for w in registry["instruction_witnesses"]}
        self.assertEqual(w["100f3061"]["hex"], "660fbec26603f8")
        self.assertEqual(w["100f306f"]["hex"], "660fbec26603f0")
        helper = next(f for f in registry["functions"] if f["address"] == "100f3040")
        self.assertEqual((helper["stack_argument_bytes"], helper["callee_pop_bytes"]), (4, 4))
        w["100f3061"]["hex"] = w["100f3061"]["hex"].replace("0fbe", "0fb6", 1)
        with self.assertRaisesRegex(ValueError, "instruction witness"):
            contracts.validate_contracts(self.image, registry)

    def test_vfs_name_match_precedes_empty_and_returns_value_cell(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["101206e0"], bytes.fromhex("8b013b4424040f94c0c20400"))
        self.assertEqual(w["112c1191"], bytes.fromhex("84c0756c"))
        self.assertEqual(w["112c119e"][:3], bytes.fromhex("8d4b08"))
        self.assertEqual(w["112c1204"], bytes.fromhex("8d4204"))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_vfs_empty_wrapper_slots_and_counter_call_arity(self):
        table = next(g for g in self.registry["globals"] if g["address"] == "11897be0")
        words = struct.unpack("<12I", bytes.fromhex(table["initial_hex_le"]))
        self.assertEqual((words[4], words[11]), (0x100DBC00, 0x100DBC00))
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["112bd66e"], bytes.fromhex("c707e07b8911"))
        self.assertEqual(w["112d0c80"], bytes.fromhex("ff4108c20800"))
        helper = next(f for f in self.registry["functions"] if f["address"] == "112d0c80")
        self.assertEqual((helper["stack_argument_bytes"], helper["callee_pop_bytes"]), (8, 8))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_disjoint_original_bodies_exclude_reported_gaps(self):
        helpers = {f["address"]: f for f in self.registry["functions"] if "body_ranges" in f}
        self.assertEqual(set(helpers), {"112a8ff0", "112bbd10"})
        base, sections = contracts.parse_pe32(self.image)
        for address, gap in (("112a8ff0", 9), ("112bbd10", 3)):
            helper = helpers[address]
            parts = contracts.function_body_parts(self.image, base, sections, helper)
            self.assertEqual(len(parts), 2)
            self.assertEqual(sum(len(data) for _, data in parts), helper["bytes"])
            self.assertEqual(parts[-1][0] + len(parts[-1][1]) - parts[0][0] - helper["bytes"], gap)
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_stack_return_cannot_be_in_a_body_gap(self):
        registry = copy.deepcopy(self.registry)
        helper = next(f for f in registry["functions"] if f["address"] == "112a8ff0")
        gap = int(helper["body_ranges"][0]["end"], 16) + 1
        helper["return_instruction_addresses"] = [f"{gap:08x}"]
        with self.assertRaisesRegex(ValueError, "stack return"):
            contracts.validate_contracts(self.image, registry)

    def test_legacy_bom_filter_advances_by_bytes(self):
        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        # INC ECX, not a UTF-16 stride. Zero bytes are skipped; retained bytes
        # are copied without transcoding, then a NUL terminator is written.
        self.assertEqual(witnesses["112a7d80"], bytes.fromhex("8a0184c0740388024246413bf372f1c60200"))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_read_and_parse_failures_do_not_imply_empty_output(self):
        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        for address in (0x112A7C40, 0x112A7C57):
            jump = witnesses[f"{address:08x}"]
            self.assertEqual(jump[0], 0xE9)
            self.assertEqual(address + 5 + struct.unpack_from("<i", jump, 1)[0], 0x112A7D4B)
        self.assertEqual(witnesses["112a7de7"], bytes.fromhex("84c07529"))
        self.assertEqual(0x112A7DE9 + 2 + witnesses["112a7de7"][3], 0x112A7E14)
        initial_import = witnesses["112a7e31"]
        self.assertEqual(initial_import[:6], bytes.fromhex("566a00538bcd"))
        self.assertEqual(0x112A7E37 + 5 + struct.unpack_from("<i", initial_import, 7)[0], 0x112CE6B0)
        self.assertEqual(witnesses["10127b9d"], bytes.fromhex("8d4201894304"))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

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

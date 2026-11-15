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
        self.assertEqual(result["functions"], 290)
        self.assertEqual(result["globals"], 145)
        self.assertEqual(result["vtables"], 29)
        self.assertEqual(result["instruction_witnesses"], 286)

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
        self.assertEqual(helper["stack_argument_bytes"], 8)
        self.assertEqual(helper["callee_pop_bytes"], 8)
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_vfs_assignment_precedence_and_full_table_growth(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["112ddf17"], bytes.fromhex("8b4e0433d2f7f1"))
        self.assertEqual(0x112DDF53 + 6 + struct.unpack_from("<i", w["112ddf51"], 4)[0], 0x112DE0A0)
        self.assertEqual(0x112DDF6E + 6 + struct.unpack_from("<i", w["112ddf6c"], 4)[0], 0x112DE073)
        self.assertEqual(0x112DDFB3 + 6 + struct.unpack_from("<i", w["112ddfb1"], 4)[0], 0x112DE0A0)
        self.assertEqual(0x112DDFCB + 6 + struct.unpack_from("<i", w["112ddfc9"], 4)[0], 0x112DE073)
        self.assertEqual(w["112ddfea"], bytes.fromhex("8d044501000000"))
        self.assertEqual(w["112ddff5"], bytes.fromhex("894604c1e003"))
        self.assertEqual(w["112de010"][:6], bytes.fromhex("8b06558d0cd8"))
        self.assertEqual(w["112de040"][:4], bytes.fromhex("84c0750c"))
        self.assertEqual(w["112de073"][-4:], bytes.fromhex("8b098908"))
        self.assertEqual(w["112de0a0"], bytes.fromhex("8b4424285f8b00894204"))
        helper = next(f for f in self.registry["functions"] if f["address"] == "112ddee0")
        self.assertEqual((helper["receiver_register"], helper["stack_argument_bytes"], helper["callee_pop_bytes"]), ("ECX", 8, 8))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_loose_cache_replacement_destroys_old_and_assigns_zero_on_null(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["112b8848"], bytes.fromhex("8b0885c974068b016a01ff10"))
        self.assertEqual(w["112b8861"], bytes.fromhex("85ff7451"))
        self.assertEqual(0x112B8863 + 2 + w["112b8861"][3], 0x112B88B6)
        self.assertEqual(w["112b88b6"][:6], bytes.fromhex("33ff897c2408"))
        self.assertEqual(0x112B88CD + 5 + struct.unpack_from("<i", w["112b88b6"], 24)[0], 0x112DDEE0)
        vtable = next(v for v in self.registry["vtables"] if v["address"] == "11897710")
        self.assertEqual(vtable["first_slot_code_identity"], "112acf40")
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_archive_local_table_retains_first_equal_key(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["112a957c"][:3], bytes.fromhex("8d5804"))
        self.assertEqual(w["112a957c"][-7:], bytes.fromhex("c7430408000000"))
        self.assertEqual(0x112A98A7 + 2 + w["112a98a5"][3], 0x112A9913)
        self.assertEqual(0x112A98F3 + 2 + w["112a98f1"][3], 0x112A9913)
        self.assertEqual(w["112a9913"][:3], bytes.fromhex("83c104"))
        self.assertEqual(0x112A9916 + 6 + struct.unpack_from("<i", w["112a9913"], 5)[0], 0x112A9AE2)
        self.assertEqual(0x112A99BE + 5 + struct.unpack_from("<i", w["112a99b2"], 13)[0], 0x112DDEE0)
        vtable = next(v for v in self.registry["vtables"] if v["address"] == "118976c0")
        self.assertEqual(vtable["first_slot_code_identity"], "112ad1b0")
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_archive_tree_and_comparator_predicates_are_distinct(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["112c020c"], bytes.fromhex("b8342a0312c3"))
        self.assertEqual(0x112CE105 + 5 + struct.unpack_from("<i", w["112ce0f2"], 20)[0], 0x112C1130)
        self.assertEqual(w["112d03ee"][:8], bytes.fromhex("c744241000152e11"))
        self.assertEqual(0x112E151B + 5 + struct.unpack_from("<i", w["112e1513"], 9)[0], 0x112D59F0)
        self.assertEqual(0x112E1534 + 5 + struct.unpack_from("<i", w["112e1530"], 5)[0], 0x112D59F0)
        self.assertEqual(w["112e1553"], bytes.fromhex("8b401c83e00f3ac80f97c0"))
        self.assertEqual(w["112d5a21"], bytes.fromhex("3b461c7428"))
        self.assertEqual(w["112d5a36"], bytes.fromhex("3b461c7413"))
        self.assertEqual(w["112d5a50"], bytes.fromhex("32c05dc20800"))
        globals_ = {g["address"]: g for g in self.registry["globals"]}
        for addr, width in (("120329b4", 12), ("12032a34", 8), ("12032a7c", 12)):
            self.assertEqual((globals_[addr]["width"], globals_[addr]["storage"]), (width, "zero_fill"))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_name_entry_comparator_chain_and_signed_byte_order(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["101206f0"], bytes.fromhex("8b0985c97505b001c20400"))
        self.assertEqual(w["101206fb"], bytes.fromhex("8b44240485c0750532c0c20400"))
        self.assertEqual(0x1012070A + 5 + struct.unpack_from("<i", w["10120708"], 3)[0], 0x100F2FE0)
        self.assertEqual(0x100F2FE8 + 5 + struct.unpack_from("<i", w["100f2fe0"], 9)[0], 0x100F7040)
        self.assertEqual(w["100f2fe0"][13:], bytes.fromhex("c1e81fc3"))
        self.assertEqual(w["100f7040"], bytes.fromhex("8b5424048b4108568b31578b3a8b5208"))
        self.assertEqual(w["100f7070"][:6], bytes.fromhex("0fbe0a0fbe00"))
        self.assertEqual(w["100f70a0"][:6], bytes.fromhex("0fbe0a0fbe00"))
        self.assertEqual(w["100f70d0"][7:13], bytes.fromhex("0fbe000fbe0a"))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_archive_tree_search_and_sentinel_initializers(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["112c025f"], bytes.fromhex("8b388bdf8b7704807e0d00"))
        self.assertEqual(0x112C027C + 5 + struct.unpack_from("<i", w["112c0279"], 4)[0], 0x101206F0)
        self.assertEqual(0x112C02AC + 5 + struct.unpack_from("<i", w["112c02aa"], 3)[0], 0x101206F0)
        self.assertIn(bytes.fromhex("66c7420c0101"), w["112a7599"])
        self.assertEqual(w["112a7698"], bytes.fromhex("8b008903c7430400000000c7430800000000"))
        self.assertIn(bytes.fromhex("66c7410c0101"), w["112a76e2"])
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_archive_dependency_graph_singleton_and_recursive_walk(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["112d503e"][:5], bytes.fromhex("b9582a0312"))
        self.assertEqual(0x112D5056 + 5 + struct.unpack_from("<i", w["112d503e"], 25)[0], 0x112A77B0)
        self.assertEqual(w["112a783b"][:20], bytes.fromhex("c7471807000000c7471c08000000c7070000803f"))
        self.assertEqual(w["112b000b"][:3], bytes.fromhex("8b5718"))
        self.assertEqual(w["112b5098"][:5], bytes.fromhex("8b308bd957"))
        self.assertEqual(0x112B50B5 + 5 + struct.unpack_from("<i", w["112b50b0"], 6)[0], 0x100F28A0)
        self.assertEqual(0x112B50E2 + 5 + struct.unpack_from("<i", w["112b50da"], 9)[0], 0x112B5090)
        globals_ = {g["address"]: g for g in self.registry["globals"]}
        for addr, width in (("12032950", 12), ("12032a40", 24), ("12032a58", 32)):
            self.assertEqual((globals_[addr]["width"], globals_[addr]["storage"]), (width, "zero_fill"))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_dependency_tree_increment_and_registration_callees(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["10101a40"], bytes.fromhex("8b4108c3"))
        self.assertEqual(w["112ac2d6"], bytes.fromhex("8b7a08807f0d007422"))
        self.assertEqual(w["112ac2df"], bytes.fromhex("8b420480780d0075123b5008750d8906"))
        self.assertEqual(w["112ac310"], bytes.fromhex("8b018bf98bc880780d0074f4"))
        self.assertEqual(0x112A4C18 + 5 + struct.unpack_from("<i", w["112a4c13"], 6)[0], 0x100F28A0)
        self.assertEqual(0x112BB76F + 5 + struct.unpack_from("<i", w["112bb76b"], 5)[0], 0x112AC2D0)
        self.assertEqual(w["112a432e"], bytes.fromhex("8b730457894c241488442410807e0d007549"))
        self.assertEqual(0x112A4438 + 5 + struct.unpack_from("<i", w["112a4434"], 5)[0], 0x112A37B0)
        self.assertEqual(w["112a32e5"][:12], bytes.fromhex("890e8971048b4a0480790c00"))
        self.assertEqual(w["112d4ce3"], bytes.fromhex("b81c2a03125ec3"))
        self.assertEqual(w["112d4e03"], bytes.fromhex("b8e02903125ec3"))
        self.assertEqual(0x112C13FB + 5 + struct.unpack_from("<i", w["112c13fb"], 1)[0], 0x10101A40)
        self.assertEqual(0x112C1405 + 5 + struct.unpack_from("<i", w["112c13fb"], 11)[0], 0x100F3040)
        self.assertEqual(w["112c149c"], bytes.fromhex("5f5e5d8d410c5b59c20400"))
        self.assertEqual(0x112DD6D8 + 5 + struct.unpack_from("<i", w["112dd6cd"], 12)[0], 0x10101A40)
        self.assertEqual(w["112dd8c5"][-3:], bytes.fromhex("c20800"))
        globals_ = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((globals_["12032944"]["width"], globals_["12032944"]["storage"]), (8, "zero_fill"))
        self.assertEqual((globals_["12032960"]["width"], globals_["12032960"]["storage"]), (12, "zero_fill"))
        self.assertEqual((globals_["1173dfac"]["width"], globals_["1173dfac"]["storage"]), (8, "file"))
        self.assertEqual(bytes.fromhex(globals_["1173dfac"]["initial_hex_le"]), b"\\\x00\x00\x001.21")
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_registration_preconditions_and_layer11_callees(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["101028f0"], bytes.fromhex("8b01c3"))
        self.assertEqual(0x10121696 + 5 + struct.unpack_from("<i", w["10121690"], 7)[0], 0x101028F0)
        self.assertEqual(w["112c0b20"][-9:], bytes.fromhex("8b41048d04808d0482"))
        self.assertEqual(w["112c0bb0"][-6:], bytes.fromhex("8b41048d04c2"))
        self.assertEqual(w["112a37b6"][:7], bytes.fromhex("817b0448922409"))
        self.assertEqual(0x112A3CD2 + 5 + struct.unpack_from("<i", w["112a3cd2"], 1)[0], 0x100F2FE0)
        self.assertEqual(0x112A425E + 5 + struct.unpack_from("<i", w["112a425e"], 1)[0], 0x100F2FE0)
        self.assertEqual(0x112A44A7 + 5 + struct.unpack_from("<i", w["112a44a7"], 1)[0], 0x101206F0)
        self.assertEqual(0x112CFC65 + 5 + struct.unpack_from("<i", w["112cfc5e"], 8)[0], 0x112A4C00)
        self.assertEqual(0x112CFC84 + 5 + struct.unpack_from("<i", w["112cfc84"], 1)[0], 0x112D4DE0)
        self.assertEqual(0x112CFC8C + 5 + struct.unpack_from("<i", w["112cfc84"], 9)[0], 0x112C13F0)
        self.assertEqual(w["112d0156"], bytes.fromhex("807c246000754f80bc24b000000000"))
        self.assertEqual(w["112d016b"], bytes.fromhex("8b44245c8b40148b40048b00894424108b40103b442414"))
        globals_ = {g["address"]: g for g in self.registry["globals"]}
        for addr, width in (("120329e0", 24), ("12032a1c", 24), ("12032a8c", 12)):
            self.assertEqual((globals_[addr]["width"], globals_[addr]["storage"]), (width, "zero_fill"))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_mount_step_and_layer12_callees(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(0x1011FE0A + 5 + struct.unpack_from("<i", w["1011fe02"], 9)[0], 0x10120B30)
        self.assertEqual(0x1011FE74 + 5 + struct.unpack_from("<i", w["1011fe73"], 2)[0], 0x10120B30)
        self.assertEqual(struct.unpack_from("<I", w["10cb8f15"], 1)[0], 0x117DF544)
        self.assertEqual(0x10CB8F1E + 5 + struct.unpack_from("<i", w["10cb8f15"], 10)[0], 0x100F1BB0)
        self.assertEqual(0x10CB8F28 + 5 + struct.unpack_from("<i", w["10cb8f15"], 20)[0], 0x112C02E0)
        self.assertEqual(0x112A95E6 + 5 + struct.unpack_from("<i", w["112a95df"], 8)[0], 0x101141F0)
        self.assertEqual(w["112a9b22"], bytes.fromhex("8b75008b461c240f3c047415"))
        self.assertEqual(struct.unpack_from("<I", w["112a2e86"], 1)[0], 0x09249248)
        self.assertEqual(struct.unpack_from("<I", w["112a3574"], 3)[0], 0x09249248)
        self.assertEqual(struct.unpack_from("<I", w["112a3a54"], 3)[0], 0x0CCCCCCB)
        self.assertEqual(0x112D01DC + 5 + struct.unpack_from("<i", w["112d01d8"], 5)[0], 0x101141F0)
        self.assertEqual(struct.unpack_from("<I", w["112d020a"], 1)[0], 0x12032960)
        self.assertEqual(0x112D0219 + 5 + struct.unpack_from("<i", w["112d020a"], 16)[0], 0x100F2610)
        self.assertEqual(0x112D0232 + 5 + struct.unpack_from("<i", w["112d022d"], 6)[0], 0x10113C10)
        globals_ = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((globals_["117df544"]["width"], globals_["117df544"]["storage"]), (28, "file"))
        self.assertEqual(bytes.fromhex(globals_["117df544"]["initial_hex_le"]), "vfs_log_level\0".encode("utf-16-le"))
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_pack_entry_vtable_and_stream_callees(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(struct.unpack_from("<I", w["112a9963"], 2)[0], 0x118976C0)
        self.assertEqual(w["112a999d"], bytes.fromhex("c7462000000000c6462400"))
        self.assertEqual(w["112d01a5"][4:7], bytes.fromhex("ff5034"))
        self.assertEqual(w["112d0224"][4:7], bytes.fromhex("ff5034"))
        self.assertEqual(w["112d2900"], bytes.fromhex("c6412401c3"))
        self.assertEqual(0x112D3278 + 5 + struct.unpack_from("<i", w["112d3270"], 9)[0], 0x1011FE30)
        self.assertEqual(w["103282bb"], bytes.fromhex("8d04ad0000000003c5c1e003"))
        self.assertEqual(struct.unpack_from("<I", w["1010613c"], 1)[0], 0x11934518)
        self.assertEqual(struct.unpack_from("<I", w["112e157c"], 1)[0], 0x12032A7C)
        globals_ = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((globals_["11934518"]["width"], globals_["11934518"]["storage"]), (12, "file"))
        self.assertEqual(globals_["11934518"]["initial_hex_le"], "000000000000000060100000")
        vtables_ = {v["address"]: v for v in self.registry["vtables"]}
        self.assertEqual(vtables_["118976c0"]["first_slot_code_identity"], "112ad1b0")
        self.assertEqual(vtables_["1189a434"]["first_slot_code_identity"], "112afd00")
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_pack_entry_stream_and_full_vtable(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        self.assertEqual(w["100f3880"][:2], bytes.fromhex("ff25"))
        self.assertEqual(struct.unpack_from("<I", w["100f3880"], 2)[0], 0x1172F1D8)
        self.assertEqual(w["10102f5a"][:5], bytes.fromhex("bf04000000"))
        self.assertEqual(w["10171400"], bytes.fromhex("8b4118c3"))
        self.assertEqual(w["10269610"], bytes.fromhex("8b4120c3"))
        self.assertEqual(w["112c9540"], bytes.fromhex("8b411c8b008b401cc1e8062401c3"))
        self.assertEqual(w["112baf20"], bytes.fromhex("8b49208b01ff601c"))
        self.assertEqual(0x112E0D8B + 5 + struct.unpack_from("<i", w["112e0d80"], 12)[0], 0x1011FDD0)
        self.assertEqual(w["112d0d90"][-3:], bytes.fromhex("0f43c7"))
        self.assertEqual(w["112c0dd3"][-3:], bytes.fromhex("3b4608"))
        self.assertEqual(w["112d9890"][-4:], bytes.fromhex("0f95c0c3"))
        self.assertEqual(w["112d0bd0"][:5], bytes.fromhex("8b492085c9"))
        self.assertEqual(struct.unpack_from("<I", w["112ad1b0"], 10)[0], 0x11849278)
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_pool_slab_disposer_mutex_and_global_map(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        g = {item["address"]: item for item in self.registry["globals"]}
        self.assertEqual(w["1032825b"][:7], bytes.fromhex("8d04ed00000000"))
        self.assertEqual(w["112e333a"], bytes.fromhex("c1e0046a0450"))
        self.assertEqual(struct.unpack_from("<I", w["112bffb8"], 1)[0], 0x12032B14)
        self.assertEqual(struct.unpack_from("<I", w["112bffb8"], 7)[0], 0x1172F1EC)
        self.assertEqual(w["113465cb"], bytes.fromhex("83e10f894c3204"))
        self.assertEqual(w["112afd00"][:3], bytes.fromhex("8b4110"))
        self.assertEqual(w["112acd70"][10:12], bytes.fromhex("6a18"))
        self.assertEqual(w["112acd30"][10:12], bytes.fromhex("6a2c"))
        for pool in ("119344f4", "11934500", "1193450c"):
            self.assertEqual(g[pool]["width"], 12)
        base_vt = bytes.fromhex(g["11849278"]["initial_hex_le"])
        self.assertEqual(struct.unpack_from("<15I", base_vt, 0)[:11], (0x116BD8AF,) * 11)
        self.assertEqual(g["12032b10"]["storage"], "zero_fill")
        self.assertEqual(g["12032bf4"]["storage"], "zero_fill")
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_quota_global_map_and_pack_wire_header(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        g = {item["address"]: item for item in self.registry["globals"]}
        v = {item["address"]: item for item in self.registry["vtables"]}
        self.assertEqual(struct.unpack_from("<I", w["100d79c6"], 1)[0], 0xF73A51C9)
        self.assertEqual(w["10cf4d43"][5:], bytes.fromhex("8b08890f8938"))
        self.assertEqual(w["112a4674"], bytes.fromhex("80780c007406017e18ff461c"))
        self.assertEqual(w["112a9cec"], bytes.fromhex("c7470426000000"))
        self.assertEqual(w["112e3ee8"][:2], bytes.fromhex("6a14"))
        self.assertEqual(w["112e3ee8"][-2:], bytes.fromhex("0101"))
        self.assertEqual(w["112b59be"], bytes.fromhex("c605881a031201"))
        self.assertEqual(w["10fa1340"][-3:], bytes.fromhex("c20400"))
        self.assertEqual(w["10f9faa0"][-3:], bytes.fromhex("c20400"))
        self.assertEqual(w["10f9fae0"][:2], bytes.fromhex("558b"))
        self.assertEqual(w["112afca0"][:3], bytes.fromhex("568d71"))
        self.assertEqual(g["119e11e8"]["storage"], "file")
        self.assertEqual(g["1172f224"]["storage"], "file")
        for flag in ("12032738", "12031ace", "120326e0", "12032290"):
            self.assertEqual(g[flag]["storage"], "zero_fill")
            self.assertEqual(g[flag]["width"], 1)
        self.assertEqual(v["1189a454"]["first_slot_code_identity"], "112afca0")
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_scan_mount_thread_buckets_and_stream_wrappers(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        g = {item["address"]: item for item in self.registry["globals"]}
        v = {item["address"]: item for item in self.registry["vtables"]}
        self.assertEqual(struct.unpack_from("<I", w["101f4f9f"], 1)[0], 0x4A545EED)
        self.assertEqual(w["112cbed6"][:3], bytes.fromhex("0f2f49"))
        self.assertEqual(struct.unpack_from("<I", w["112d4192"], 16)[0], 0x1189A424)
        self.assertEqual(struct.unpack_from("<I", w["112bafd1"], 2)[0], 0x120329CC)
        self.assertEqual(struct.unpack_from("<I", w["112bafd1"], 6)[0], 0x3CB)
        self.assertEqual(struct.unpack_from("<I", w["112a7aeb"], 9)[0], 0x118977EC)
        self.assertEqual(struct.unpack_from("<I", w["112a94dc"], 9)[0], 0x11897790)
        self.assertEqual(w["112b5462"][:3], bytes.fromhex("8d1cf5"))
        self.assertEqual(bytes.fromhex(g["1173dad0"]["initial_hex_le"])[4:8], b"true")
        self.assertEqual(bytes.fromhex(g["1173f1f0"]["initial_hex_le"])[12:14], b"%s")
        for z in ("12032a14", "120329c8", "120329d8", "12032af4"):
            self.assertEqual(g[z]["storage"], "zero_fill")
        self.assertEqual(v["1189a424"]["first_slot_code_identity"], "112afce0")
        self.assertEqual(v["118977ec"]["first_slot_code_identity"], "112acde0")
        self.assertEqual(v["11897790"]["first_slot_code_identity"], "112ad0f0")
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_dep_rb_rehash_and_stream_dtor_contracts(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        g = {item["address"]: item for item in self.registry["globals"]}
        ev = self.registry["rea_layer18_evidence"]
        self.assertEqual(ev["closed_evidence_records"], 231)
        self.assertEqual(ev["new_evidence_records"], 23)
        self.assertEqual(ev["reused_layer17_evidence_records"], 208)
        self.assertEqual(len(ev["records"]), 23)
        self.assertEqual(w["112acd50"][10:12], bytes.fromhex("6a50"))
        self.assertEqual(w["112ace05"][:2], bytes.fromhex("6a38"))
        self.assertEqual(struct.unpack_from("<I", w["112ad107"], 3)[0], 0x1172F24C)
        self.assertEqual(struct.unpack_from("<I", w["112d9e84"], 1)[0], 0x800)
        self.assertEqual(struct.unpack_from("<H", w["112a7728"], 7)[0], 0x0101)
        self.assertEqual(w["112be330"][:2], bytes.fromhex("6a28"))
        self.assertEqual(w["112ddb65"], bytes.fromhex("8d3c80c1e702"))
        self.assertEqual(struct.unpack_from("<H", w["112e3b04"], 7)[0], 0x0101)
        self.assertEqual(struct.unpack_from("<I", w["112af2a8"], 1)[0], 0x11897BC8)
        self.assertEqual(struct.unpack_from("<I", w["112af2a8"], 6)[0], 0x12032960)
        self.assertEqual(bytes.fromhex(g["11897bc8"]["initial_hex_le"]), b"<root>\x00")
        self.assertEqual(bytes.fromhex(g["11897c70"]["initial_hex_le"]), b"normals\\normal_\x00")
        self.assertEqual(g["1172f24c"]["storage"], "file")
        for z in ("12032964", "12125644"):
            self.assertEqual(g[z]["storage"], "zero_fill")
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_rb_bucket_ops_and_handle_box_contracts(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        g = {item["address"]: item for item in self.registry["globals"]}
        ev = self.registry["rea_layer19_evidence"]
        self.assertEqual(ev["closed_evidence_records"], 246)
        self.assertEqual(ev["new_evidence_records"], 15)
        self.assertEqual(ev["reused_layer18_evidence_records"], 231)
        self.assertEqual(len(ev["records"]), 15)
        self.assertEqual(struct.unpack_from("<I", w["112a3324"], 3)[0], 0x06666665)
        self.assertEqual(struct.unpack_from("<I", w["112b0077"], 1)[0], 0x1FFFFFFF)
        self.assertEqual(struct.unpack_from("<I", w["112b039b"], 1)[0], 0x11745C98)
        self.assertEqual(struct.unpack_from("<I", w["112ac44a"], 2)[0], 0x1172F1F0)
        self.assertEqual(w["112ac4b0"][:2], bytes.fromhex("6a14"))
        self.assertEqual(struct.unpack_from("<I", w["112ab432"], 2)[0], 0x1000)
        self.assertEqual(w["112dbe36"], bytes.fromhex("8d0440c1e002"))
        self.assertEqual(struct.unpack_from("<I", w["112afc6f"], 2)[0], 0x200)
        self.assertEqual(bytes.fromhex(g["11745c98"]["initial_hex_le"]), b"invalid hash bucket count\x00")
        self.assertEqual(bytes.fromhex(g["1177ddbc"]["initial_hex_le"]), b"map/set<T> too long\x00")
        self.assertEqual(g["1172f1f0"]["storage"], "file")
        self.assertEqual(g["1172f1f4"]["storage"], "file")
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_stream_wrap_slots_and_rb_rotate_contracts(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        fmap = {f["address"]: f for f in self.registry["functions"]}
        ev = self.registry["rea_layer20_evidence"]
        self.assertEqual(ev["closed_evidence_records"], 267)
        self.assertEqual(ev["new_evidence_records"], 21)
        self.assertEqual(ev["reused_layer19_evidence_records"], 246)
        self.assertEqual(len(ev["records"]), 21)
        self.assertEqual(w["10369160"], bytes.fromhex("837920000f95c0c3"))
        self.assertEqual(w["112c8b80"], bytes.fromhex("837930000f95c0c3"))
        self.assertEqual(w["112baef0"], bytes.fromhex("8b41208b4004c3"))
        self.assertEqual(w["112d9860"][:4], bytes.fromhex("8b413085"))
        self.assertEqual(w["112badf0"][-8:], bytes.fromhex("01ff600833c05ec3"))
        self.assertEqual(w["112c8bc0"][:6], bytes.fromhex("837920007417"))
        self.assertEqual(struct.unpack_from("<I", w["112dab21"], 3)[0], 0x1172F24C)
        self.assertEqual(w["112da9f6"], bytes.fromhex("83462cff"))
        self.assertEqual(w["112a2483"][0], 0xE8)
        self.assertEqual(0x112A2483 + 5 + struct.unpack_from("<i", w["112a2483"], 1)[0], 0x112A2660)
        self.assertEqual(fmap["10190580"]["callee_pop_bytes"], 12)
        self.assertEqual(fmap["100e22c0"]["callee_pop_bytes"], 8)
        self.assertEqual(fmap["112b0760"]["calling_convention"], "cdecl")
        self.assertEqual(fmap["112b0780"]["calling_convention"], "cdecl")
        self.assertEqual(fmap["112b0710"]["callee_pop_bytes"], 4)
        self.assertEqual(fmap["112b07a0"]["callee_pop_bytes"], 4)
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_adj_hash_stream_open_and_ref_dtor_contracts(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        fmap = {f["address"]: f for f in self.registry["functions"]}
        g = {item["address"]: item for item in self.registry["globals"]}
        ev = self.registry["rea_layer21_evidence"]
        self.assertEqual(ev["closed_evidence_records"], 281)
        self.assertEqual(ev["new_evidence_records"], 14)
        self.assertEqual(ev["reused_layer20_evidence_records"], 267)
        self.assertEqual(len(ev["records"]), 18)
        self.assertEqual(bytes.fromhex(g["11745c7c"]["initial_hex_le"]), b"unordered_map/set too long\x00")
        self.assertEqual(g["1172f670"]["storage"], "file")
        self.assertEqual(g["1172f670"]["initial_hex_le"], "b8149301")
        self.assertEqual(g["12031a8a"]["storage"], "zero_fill")
        self.assertEqual(g["12031a8a"]["initial_hex_le"], "00")
        self.assertEqual(w["112accd0"][:6], bytes.fromhex("f64424040156"))
        self.assertEqual(struct.unpack_from("<I", w["112a2954"], 2)[0], 0x071C71C7)
        self.assertEqual(w["112a2b95"][0], 0x68)
        self.assertEqual(struct.unpack_from("<I", w["112a2b95"], 1)[0], 0x11745C7C)
        self.assertEqual(w["112ac1c5"], bytes.fromhex("6a24"))
        self.assertEqual(w["112c0cb0"], bytes.fromhex("807f0d00750790807f0c0074f3"))
        self.assertEqual(w["112cd4c0"], bytes.fromhex("568bf18b0e85c97405e8f2ffffffc64604005ec3"))
        self.assertEqual(struct.unpack_from("<I", w["112d8c7f"], 2)[0], 0x3FFFFFFF)
        self.assertEqual(w["112d8e6d"][:2], bytes.fromhex("803d"))
        self.assertEqual(struct.unpack_from("<I", w["112d8e6d"], 2)[0], 0x12031A8A)
        for addr, pop in [
            ("112a2660", 12),
            ("112a2910", 12),
            ("112a3ee0", 12),
            ("112ac1a0", 4),
            ("112accd0", 4),
            ("112acd50", 4),
            ("112acd70", 4),
            ("112be350", 4),
            ("112c0c60", 0),
            ("112cd4c0", 0),
            ("112d8c50", 4),
            ("112d8d30", 12),
            ("112d8e20", 12),
        ]:
            self.assertEqual(fmap[addr]["calling_convention"], "thiscall")
            self.assertEqual(fmap[addr]["callee_pop_bytes"], pop)
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_view_map_handle_ctor_and_76c0_vtable_contracts(self):
        w = {w["address"]: bytes.fromhex(w["hex"]) for w in self.registry["instruction_witnesses"]}
        fmap = {f["address"]: f for f in self.registry["functions"]}
        g = {item["address"]: item for item in self.registry["globals"]}
        v = {item["address"]: item["first_slot_code_identity"] for item in self.registry["vtables"]}
        ev = self.registry["rea_layer22_evidence"]
        self.assertEqual(ev["closed_evidence_records"], 302)
        self.assertEqual(ev["new_evidence_records"], 18)
        self.assertEqual(ev["reused_layer21_evidence_records"], 281)
        self.assertEqual(ev["reused_layer18_resolve_records"], 6)
        self.assertEqual(ev["extra_evidence_views_count"], 3)
        self.assertEqual(len(ev["records"]), 24)
        for zaddr in ("12032e68", "11af4268"):
            self.assertEqual(g[zaddr]["storage"], "zero_fill")
            self.assertEqual(g[zaddr]["initial_hex_le"], "00000000")
        for iat_addr, iat_le in (
            ("1172f23c", "dc0a9301"),
            ("1172f184", "62079301"),
            ("1172f244", "020b9301"),
            ("1172f248", "120b9301"),
        ):
            self.assertEqual(g[iat_addr]["storage"], "file")
            self.assertEqual(g[iat_addr]["initial_hex_le"], iat_le)
        self.assertEqual(v["1189a444"], "112afcd0")
        self.assertEqual(v["118976a4"], "112d36f0")
        self.assertEqual(v["118977bc"], "112acd90")
        self.assertEqual(v["118977d4"], "112ad140")
        self.assertEqual(w["112afb9e"], bytes.fromhex("83e1fc81f900100000"))
        self.assertEqual(w["101d991b"], bytes.fromhex("3dffffff3f760583c9ffeb08"))
        self.assertEqual(w["112a7901"], bytes.fromhex("6a2c"))
        self.assertEqual(w["112a794d"], bytes.fromhex("c7450044a48911"))
        self.assertEqual(w["1010301e"], bytes.fromhex("4b8bebf7d58d041f23c5"))
        self.assertEqual(w["112e183e"], bytes.fromhex("6a6c"))
        self.assertEqual(w["112e1894"], bytes.fromhex("c74744e5030000"))
        self.assertEqual(w["10e13a80"], bytes.fromhex("8a0c06403aca750c8a1084d275f2"))
        self.assertEqual(w["10115920"], bytes.fromhex("0fb60203f703c803d73bf372f3"))
        self.assertEqual(w["116835d7"], bytes.fromhex("558becff7508e8dedca4fe595dc3"))
        self.assertEqual(w["112accf0"], bytes.fromhex("f644240401568bf1740b6a2056e8d5683d0083c4088bc65ec20400"))
        self.assertEqual(w["112acd10"], bytes.fromhex("f644240401568bf1740b6a1c56e8b5683d0083c4088bc65ec20400"))
        self.assertEqual(w["112acd30"], bytes.fromhex("f644240401568bf1740b6a2c56e895683d0083c4088bc65ec20400"))
        self.assertEqual(w["112ad1b0"][:14], bytes.fromhex("f644240401568bf1c70678928411"))
        self.assertEqual(w["112d3270"], bytes.fromhex("8d41048b4c240450e8b3cbe4fe8b442404c20400"))
        self.assertEqual(w["112e0d80"], bytes.fromhex("8b411c8b4c240483c01450e840f0e3fe8b442404c20400"))
        self.assertEqual(w["112c9540"], bytes.fromhex("8b411c8b008b401cc1e8062401c3"))
        self.assertEqual(w["112afd00"], bytes.fromhex("8b4110568d71108bceff700456e80e50a4ff8b36e8e762e5fe8b08890e89305ec3"))
        for addr, cc, pop in [
            ("112afb90", "thiscall", 12),
            ("101d9910", "stdcall", 4),
            ("116835d7", "cdecl", 0),
            ("112a7860", "thiscall", 36),
            ("10102f90", "thiscall", 16),
            ("112e1830", "cdecl", 0),
            ("10e13a60", "cdecl", 0),
            ("10115900", "cdecl", 0),
            ("112ad1b0", "thiscall", 4),
            ("112d3270", "thiscall", 4),
            ("112e0d80", "thiscall", 4),
            ("112c9540", "thiscall", 0),
            ("112afd00", "thiscall", 0),
            ("112accf0", "thiscall", 4),
            ("112acd10", "thiscall", 4),
            ("112acd30", "thiscall", 4),
        ]:
            self.assertEqual(fmap[addr]["calling_convention"], cc)
            self.assertEqual(fmap[addr]["callee_pop_bytes"], pop)
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_state_inner_vtables_async_view_and_telemetry_contracts(self):
        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        gmap = {g["address"]: g for g in self.registry["globals"]}
        vmap = {v["address"]: v["first_slot_code_identity"] for v in self.registry["vtables"]}
        fmap = {f["address"]: f for f in self.registry["functions"]}

        for vaddr, slot0 in [
            ("118977c8", "112acfe0"),
            ("118977e0", "112acd90"),
            ("1189a464", "112afcc0"),
            ("1189a474", "112afcd0"),
        ]:
            self.assertEqual(vmap[vaddr], slot0)

        for addr, width in [
            ("11af4104", 1),
            ("11af40e0", 36),
            ("11af426c", 4),
            ("12031ac0", 4),
            ("12031ac4", 4),
            ("12031ad0", 4),
            ("12031ad4", 4),
            ("119f3ed8", 4),
            ("119f3edc", 4),
        ]:
            self.assertEqual(gmap[addr]["storage"], "zero_fill")
            self.assertEqual(gmap[addr]["width"], width)
            self.assertEqual(gmap[addr]["initial_hex_le"], "00" * width)

        for iat, hex_le in [
            ("1172f2c8", "6c0d9301"),
            ("1172f2cc", "7a0d9301"),
            ("1172f208", "e0099301"),
        ]:
            self.assertEqual(gmap[iat]["storage"], "file")
            self.assertEqual(gmap[iat]["initial_hex_le"], hex_le)

        self.assertEqual(witnesses["112bade0"], bytes.fromhex("8b41048b4004c3"))
        self.assertEqual(witnesses["112d36f0"], bytes.fromhex("8b410440c3"))
        self.assertEqual(witnesses["100e80b0"], bytes.fromhex("8b412cc3"))
        self.assertEqual(witnesses["10299640"], bytes.fromhex("8d413cc3"))
        self.assertEqual(witnesses["10497c50"], bytes.fromhex("8d4150c3"))
        self.assertEqual(witnesses["112c03d9"], bytes.fromhex("6a20"))
        self.assertEqual(witnesses["112d91fc"], bytes.fromhex("6a1c"))
        d9640 = witnesses["112d9640"]
        self.assertEqual(d9640[13], 0xE8)
        self.assertEqual(0x112D964D + 5 + struct.unpack_from("<i", d9640, 14)[0], 0x10115940)
        d97fc = witnesses["112d97fc"]
        self.assertEqual(d97fc[:3], bytes.fromhex("f64614"))
        self.assertEqual(d97fc[3], 0x01)
        fcc59 = witnesses["100fcc59"]
        self.assertEqual(fcc59[1], 0xE8)
        self.assertEqual(0x100FCC5A + 5 + struct.unpack_from("<i", fcc59, 2)[0], 0x10124E50)

        for addr, cc, stack, pop in [
            ("112acd90", "thiscall", 4, 4),
            ("112ad140", "thiscall", 4, 4),
            ("112acfe0", "thiscall", 4, 4),
            ("112bade0", "thiscall", 0, 0),
            ("112baf00", "thiscall", 0, 0),
            ("112d9640", "thiscall", 0, 0),
            ("112d97f0", "thiscall", 0, 0),
            ("112c0300", "cdecl", 16, 0),
            ("112d91c0", "thiscall", 24, 24),
            ("10115730", "cdecl", 0, 0),
            ("10115940", "cdecl", 12, 0),
            ("100fcc50", "cdecl", 4, 0),
            ("112d36f0", "thiscall", 0, 0),
            ("100e80b0", "thiscall", 0, 0),
            ("112badd0", "thiscall", 0, 0),
            ("10299640", "thiscall", 0, 0),
            ("10497c50", "thiscall", 0, 0),
            ("112e1780", "thiscall", 4, 4),
            ("112e17e0", "thiscall", 4, 4),
            ("112e1960", "cdecl", 0, 0),
            ("112e19b0", "cdecl", 0, 0),
        ]:
            self.assertEqual(fmap[addr]["calling_convention"], cc)
            self.assertEqual(fmap[addr]["stack_argument_bytes"], stack)
            self.assertEqual(fmap[addr]["callee_pop_bytes"], pop)
        self.assertTrue(contracts.validate_contracts(self.image, self.registry)["verified"])

    def test_disjoint_original_bodies_exclude_reported_gaps(self):
        helpers = {f["address"]: f for f in self.registry["functions"] if "body_ranges" in f}
        self.assertEqual(
            set(helpers),
            {"112a2910", "112a8ff0", "112b5730", "112baf90", "112bbd10", "112d4cc0", "112d4de0", "112e32b0", "112e3db0"},
        )
        base, sections = contracts.parse_pe32(self.image)
        expected_gaps = {
            "112a2910": [1],
            "112a8ff0": [9],
            "112b5730": [10, 21, 30],
            "112baf90": [3],
            "112bbd10": [3],
            "112d4cc0": [4],
            "112d4de0": [7],
            "112e32b0": [4],
            "112e3db0": [13],
        }
        for address, gaps in expected_gaps.items():
            helper = helpers[address]
            parts = contracts.function_body_parts(self.image, base, sections, helper)
            self.assertEqual(len(parts), len(gaps) + 1)
            self.assertEqual(sum(len(data) for _, data in parts), helper["bytes"])
            observed_gaps = [parts[i + 1][0] - (parts[i][0] + len(parts[i][1])) for i in range(len(gaps))]
            self.assertEqual(observed_gaps, gaps)
            self.assertEqual(parts[-1][0] + len(parts[-1][1]) - parts[0][0] - helper["bytes"], sum(gaps))
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

    def test_stream_completion_cache_crt_math_and_vtables(self):
        evidence = self.registry["rea_layer24_evidence"]
        self.assertEqual(evidence["closed_evidence_records"], 367)
        self.assertEqual(evidence["new_evidence_records"], 31)
        self.assertEqual(evidence["reused_layer23_evidence_records"], 336)
        self.assertEqual(evidence["reused_prior_resolve_records"], 3)
        self.assertEqual(evidence["extra_evidence_views_count"], 3)
        self.assertEqual(len(evidence["records"]), 31)
        self.assertEqual(
            evidence["closed_snapshot_sha256"],
            "bea46f1d05869d5e02e02e21df781e1c9a62a4e904aaf1849924f797a32c62db",
        )
        self.assertEqual(
            evidence["validated_bundle_sha256"],
            "475ab7199d42e3cb2a866a007302f7868344303e3bfda6f975c2e19ae2040a0e",
        )

        by_vt = {entry["address"]: entry for entry in self.registry["vtables"]}
        self.assertEqual(by_vt["1189a414"]["first_slot_code_identity"], "112afcd0")

        by_global = {entry["address"]: entry for entry in self.registry["globals"]}
        expected_globals = {
            "12032b38": (4, "zero_fill", "00000000"),
            "119e1230": (28, "file", "34129e11000000000000000000000000000000000000000000000000"),
            "12032b0c": (4, "zero_fill", "00000000"),
            "12032b04": (4, "zero_fill", "00000000"),
            "12032b08": (4, "zero_fill", "00000000"),
            "119e1010": (4, "file", "ffffff7f"),
            "1172f1ec": (4, "file", "3a099301"),
            "119f3eb4": (4, "zero_fill", "00000000"),
            "119f3f68": (4, "zero_fill", "00000000"),
            "11af4288": (4, "zero_fill", "00000000"),
            "11af4284": (4, "zero_fill", "00000000"),
            "11af4285": (1, "zero_fill", "00"),
            "119f3f57": (1, "zero_fill", "00"),
            "11934484": (4, "file", "ca000000"),
        }
        for addr, (width, storage, initial_hex) in expected_globals.items():
            self.assertEqual(by_global[addr]["width"], width)
            self.assertEqual(by_global[addr]["storage"], storage)
            self.assertEqual(by_global[addr]["initial_hex_le"], initial_hex)

        by_iw = {w["address"]: w["hex"] for w in self.registry["instruction_witnesses"]}
        for addr in (
            "112dd2f0",
            "112c0090",
            "112c0c40",
            "112b3190",
            "112b30b0",
            "1090b600",
            "100fa6f1",
            "100fd020",
            "100f19fb",
            "100ff8c0",
            "112b328c",
            "112b2fa4",
            "100fccd9",
            "11684210",
            "1168427a",
            "108b2600",
        ):
            self.assertIn(addr, by_iw)

        by_fn = {entry["address"]: entry for entry in self.registry["functions"]}
        expected_fns = {
            "100fa6d0": (88, "cdecl", "none", 16, 0, ["100fa727"]),
            "100fcfd0": (158, "cdecl", "none", 16, 0, ["100fd06d"]),
            "100f19f0": (57, "thiscall", "ECX", 12, 12, ["100f1a26"]),
            "100ff8c0": (18, "thiscall", "ECX", 4, 4, ["100ff8cf"]),
            "112b3270": (81, "cdecl", "none", 0, 0, ["112b3291"]),
            "112b2f40": (242, "cdecl", "none", 4, 0, ["112b2f8c"]),
            "100fcc80": (380, "cdecl", "none", 8, 0, ["100fccfe"]),
            "11684200": (52, "stdcall", "none", 16, 16, ["11684216", "11684231"]),
            "11684270": (104, "stdcall", "none", 16, 16, ["116842d5"]),
            "112d9890": (16, "thiscall", "ECX", 0, 0, ["112d989f"]),
            "112d2900": (5, "thiscall", "ECX", 0, 0, ["112d2904"]),
            "112d0bd0": (24, "thiscall", "ECX", 0, 0, ["112d0be4", "112d0be7"]),
            "112dd2f0": (15, "thiscall", "ECX", 0, 0, ["112dd2fe"]),
            "112c0090": (24, "thiscall", "ECX", 4, 4, ["112c00a5"]),
            "112c0c40": (28, "thiscall", "ECX", 0, 0, ["112c0c5b"]),
            "1018ad20": (4, "thiscall", "ECX", 0, 0, ["1018ad23"]),
            "108b2600": (8, "thiscall", "ECX", 0, 0, ["108b2607"]),
            "112b3190": (35, "thiscall", "ECX", 4, 4, ["112b31ab", "112b31b0"]),
            "101a0430": (4, "thiscall", "ECX", 0, 0, ["101a0433"]),
            "105cd140": (8, "thiscall", "ECX", 0, 0, ["105cd147"]),
            "112b30b0": (35, "thiscall", "ECX", 4, 4, ["112b30cb", "112b30d0"]),
            "1090b600": (27, "thiscall", "ECX", 4, 4, ["1090b618"]),
        }
        for addr, (size, cc, rx, stack, pop, rets) in expected_fns.items():
            fn = by_fn[addr]
            self.assertEqual(fn["bytes"], size)
            self.assertEqual(fn["calling_convention"], cc)
            self.assertEqual(fn["receiver_register"], rx)
            self.assertEqual(fn["stack_argument_bytes"], stack)
            self.assertEqual(fn["callee_pop_bytes"], pop)
            self.assertEqual(fn["return_instruction_addresses"], rets)

    def test_dropped_registry_category_rejected(self):
        registry = copy.deepcopy(self.registry)
        registry["functions"] = []
        with self.assertRaisesRegex(ValueError, "empty or invalid"):
            contracts.validate_contracts(self.image, registry)


if __name__ == "__main__":
    unittest.main()

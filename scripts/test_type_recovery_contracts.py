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
        self.assertEqual(result["functions"], 1763)
        self.assertEqual(result["globals"], 1000)
        self.assertEqual(result["vtables"], 85)
        self.assertEqual(result["instruction_witnesses"], 1560)

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
            {
                "100f38b0", "10123e40", "10fb2fb0", "10fd6d80",
                "112a2910", "112a8ff0", "112b5730", "112baf90", "112bbd10",
                "112cf920", "112d0720", "112d2e80", "112d4cc0", "112d4de0",
                "112e32b0", "112e3c60", "112e3db0", "116839e8", "11683e00",
                "1168bcc3", "11695540", "11696308", "11696528", "11699af7", "11699b02",
                "1169b820", "1169e653", "1169ecd8", "116a1729", "116a511c", "116a5864", "116a586f", "116ade23", "116ae58e", "116afb0a",
                "116b4b50", "116b56b1", "116b5f67", "116bd8d0", "116bde50",
            } | {"116b0517", "116aaee6", "1168d030", "116adaed"} | {"100edd70"} | {"116c0bf0", "116d7250"} | {"116c223f"},
        )
        base, sections = contracts.parse_pe32(self.image)
        expected_gaps = {
            "100edd70": [41],
            "100f38b0": [7],
            "10123e40": [4, 6],
            "10fb2fb0": [9],
            "10fd6d80": [18, 28],
            "112a2910": [1],
            "112a8ff0": [9],
            "112b5730": [10, 21, 30],
            "112baf90": [3],
            "112bbd10": [3],
            "112cf920": [18],
            "112d0720": [10],
            "112d2e80": [3],
            "112d4cc0": [4],
            "112d4de0": [7],
            "112e32b0": [4],
            "112e3c60": [3],
            "112e3db0": [13],
            "116839e8": [82],
            "11683e00": [36],
            "1168bcc3": [374],
            "1168d030": [5],
            "116adaed": [48],
            "11695540": [6],
            "11696308": [284, 311],
            "11696528": [1803],
            "11699af7": [1977],
            "11699b02": [1766],
            "1169b820": [86042],
            "1169e653": [17],
            "1169ecd8": [508],
            "116a1729": [1080],
            "116a511c": [14],
            "116a5864": [824],
            "116a586f": [554],
            "116ade23": [67],
            "116ae58e": [63],
            "116aaee6": [14],
            "116afb0a": [],
            "116b0517": [33],
            "116b4b50": [12],
            "116b56b1": [1187],
            "116b5f67": [12],
            "116bd8d0": [24, 1, 1, 3, 1, 17, 1, 3, 1, 5, 9],
            "116bde50": [24, 1, 1, 3, 1, 17, 1, 3, 1, 5, 9],
            "116c0bf0": [40, 8],
            "116d7250": [22],
            "116c223f": [24],
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

    def test_layer25_handle_lifecycle_and_pack_vtable_contracts(self):
        evidence = self.registry["rea_layer25_evidence"]
        self.assertEqual(evidence["closed_evidence_records"], 48)
        self.assertEqual(evidence["new_evidence_records"], 48)
        self.assertEqual(evidence["reused_layer24_evidence_records"], 0)
        self.assertEqual(evidence["extra_evidence_views_count"], 9)
        self.assertEqual(evidence["cumulative_validated_bundle_records"], 415)
        self.assertEqual(len(evidence["records"]), 39)
        self.assertEqual(
            evidence["closed_snapshot_sha256"],
            "5fd35cd44f3b6d550c7f1899ba247e844f365ae336470ea80580893c779fe404",
        )
        self.assertEqual(
            evidence["validated_bundle_sha256"],
            "5898b5658a7431b6171b1d16f11dfa9ee80bb9c385fc0816e34fe0a57bd71e1a",
        )
        self.assertEqual(
            evidence["cumulative_validated_bundle_sha256"],
            "9dd4c99ac96626498c41c5f4777742a83b40e87092f8d9879c67eef29c65c9be",
        )

        by_vt = {entry["address"]: entry for entry in self.registry["vtables"]}
        self.assertEqual(by_vt["11741d78"]["first_slot_code_identity"], "100f3820")
        self.assertEqual(by_vt["11897c44"]["first_slot_code_identity"], "112ad6d0")

        by_global = {entry["address"]: entry for entry in self.registry["globals"]}
        expected_globals = {
            "1172f1fc": (4, "file", "ae099301"),
            "1172f278": (4, "file", "ea0b9301"),
            "1172f178": (4, "file", "34079301"),
            "1172f1d8": (4, "file", "e0089301"),
            "1172f19c": (4, "file", "d8079301"),
            "1172f1b8": (4, "file", "50089301"),
            "1172f240": (4, "file", "ec0a9301"),
            "1172fa00": (4, "file", "60650d10"),
            "12126348": (4, "zero_fill", "00000000"),
            "11741d84": (15, "file", "62616420616c6c6f636174696f6e00"),
        }
        for addr, (width, storage, hex_le) in expected_globals.items():
            g = by_global[addr]
            self.assertEqual(g["width"], width)
            self.assertEqual(g["storage"], storage)
            self.assertEqual(g["initial_hex_le"], hex_le)

        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        expected_witnesses = {
            "112afcc0": "83c110e98826e4fe",
            "116bd8af": "568b354863121285f6740a8bceff1500fa7211ffd6e874e0fdff",
            "11724990": "b930129e11e9b669b8ff",
            "100d12c0": "e98bb90200",
            "11724950": "568b35082b031285f674255783cfff8bc7f00fc14604",
            "112acf80": "f644240401568bf1c70678928411740b6a0c56e83f663d0083c4088bc65ec20400",
            "112daae0": "8b410883c0ff89410875088b016a01ff1033c0c3",
            "112ad6d0": "f644240401568bf1c7069c8c8411740b6a2856e8ef5e3d0083c4088bc65ec20400",
            "112c8c60": "83791400740b8b411c3b41207303b001c332c0c3",
            "112c0d90": "8b44240485c0740801411c8bc1c20400c7411c000000008bc1c20400",
            "112dc250": "8b44240485c0740829411c8bc1c20400c7411c000000008bc1c20400",
            "112d32b0": "8d41188b4c240450e873cbe4fe8b442404c20400",
            "100f12df": "3db7000000750eff36ff1578f17211c70600000000",
            "10104bd8": "85c07506c7060300000033c033d25ec20400",
            "100fcb6b": "834e040233c08b54240803c75f83d2005e59c3",
            "112ab36e": "83c8fff00fc1460475178b068bceff10",
        }
        for addr, hex_bytes in expected_witnesses.items():
            self.assertEqual(witnesses[addr], bytes.fromhex(hex_bytes))

        by_fn = {entry["address"]: entry for entry in self.registry["functions"]}
        expected_fns = {
            "100f2230": (14, "thiscall", "ECX", 0, 0, ["100f223d"]),
            "100f12c0": (58, "thiscall", "ECX", 12, 12, ["100f12f7"]),
            "100f2170": (42, "thiscall", "ECX", 0, 0, ["100f2199"]),
            "100f1080": (16, "thiscall", "ECX", 0, 0, ["100f108f"]),
            "100f2350": (69, "thiscall", "ECX", 0, 0, ["100f2394"]),
            "100f1a30": (24, "thiscall", "ECX", 0, 0, ["100f1a47"]),
            "10104b60": (153, "thiscall", "ECX", 4, 4, ["10104be7", "10104bf6"]),
            "100fcb00": (126, "thiscall", "ECX", 0, 0, ["100fcb6a", "100fcb7d"]),
            "112ab350": (97, "thiscall", "ECX", 0, 0, ["112ab3b0"]),
            "100f1c50": (16, "thiscall", "ECX", 0, 0, ["100f1c5f"]),
            "100d6770": (3, "thiscall", "ECX", 0, 0, ["100d6772"]),
            "100d6900": (3, "thiscall", "ECX", 0, 0, ["100d6902"]),
            "100f3d00": (3, "thiscall", "ECX", 4, 4, ["100f3d00"]),
            "100d6560": (1, "thiscall", "ECX", 0, 0, ["100d6560"]),
            "112ad6a0": (47, "thiscall", "ECX", 4, 4, ["112ad6cc"]),
            "101e48d0": (5, "thiscall", "ECX", 8, 8, ["101e48d2"]),
            "11724950": (50, "cdecl", "none", 0, 0, ["11724981"]),
            "112acf80": (33, "thiscall", "ECX", 4, 4, ["112acf9e"]),
            "112daae0": (20, "thiscall", "ECX", 0, 0, ["112daaf3"]),
            "112ad6d0": (33, "thiscall", "ECX", 4, 4, ["112ad6ee"]),
            "112c8c60": (20, "thiscall", "ECX", 0, 0, ["112c8c70", "112c8c73"]),
            "112c0d90": (28, "thiscall", "ECX", 4, 4, ["112c0d9d", "112c0da9"]),
            "112dc250": (28, "thiscall", "ECX", 4, 4, ["112dc25d", "112dc269"]),
            "112d32b0": (20, "thiscall", "ECX", 4, 4, ["112d32c1"]),
        }
        for addr, (size, cc, rx, stack, pop, rets) in expected_fns.items():
            fn = by_fn[addr]
            self.assertEqual(fn["bytes"], size)
            self.assertEqual(fn["calling_convention"], cc)
            self.assertEqual(fn["receiver_register"], rx)
            self.assertEqual(fn["stack_argument_bytes"], stack)
            self.assertEqual(fn["callee_pop_bytes"], pop)
            self.assertEqual(fn["return_instruction_addresses"], rets)

    def test_layer26_loose_entry_substream_and_exception_vtable_contracts(self):
        evidence = self.registry["rea_layer26_evidence"]
        self.assertEqual(evidence["closed_evidence_records"], 95)
        self.assertEqual(evidence["new_evidence_records"], 47)
        self.assertEqual(evidence["reused_layer25_evidence_records"], 48)
        self.assertEqual(evidence["extra_evidence_views_count"], 0)
        self.assertEqual(evidence["cumulative_validated_bundle_records"], 462)
        self.assertEqual(len(evidence["records"]), 47)
        self.assertEqual(
            evidence["closed_snapshot_sha256"],
            "1d659d3db5d85bdeaeef587fa2d3896e998880a513343b6c1a193ffe7352de40",
        )
        self.assertEqual(
            evidence["validated_bundle_sha256"],
            "81668c38b2ea1209075c0866c4e20eac427ae4a52b628cf4f686adb41754ce25",
        )
        self.assertEqual(
            evidence["cumulative_validated_bundle_sha256"],
            "fed59b6c56268dfb7af471a10c318cd53fecf5471699ae85c150a64fb7d7ea27",
        )

        by_vt = {entry["address"]: entry for entry in self.registry["vtables"]}
        self.assertEqual(by_vt["11897760"]["first_slot_code_identity"], "112ace20")
        self.assertEqual(by_vt["11897c24"]["first_slot_code_identity"], "112ad6a0")
        self.assertEqual(by_vt["11741d58"]["first_slot_code_identity"], "100f3820")

        by_global = {entry["address"]: entry for entry in self.registry["globals"]}
        expected_globals = {
            "11741d58": (12, "file", "20380f10f05d111060650d10"),
            "11741d64": (18, "file", "756e6b6e6f776e20657863657074696f6e00"),
            "11741d78": (12, "file", "20380f10f05d1110103b0f10"),
            "11897718": (
                72,
                "file",
                "404ba3100014171000981d10908b2c1100690d10f00b2d11200d2d1140aa2d11"
                "f0971d10b0ae2b1180982d1160650d10b00b2d11b00d2c11e0d22d1170322d11e0ff2b1100bc0d10",
            ),
            "11897760": (
                48,
                "file",
                "20ce2a1170322d1170322d1100981d1030041a1090bfab1020952c11c0220e10"
                "003d0f1000bc0d1000bc0d10808c2c11",
            ),
            "11897c24": (
                32,
                "file",
                "a0d62a11408c2c11c0982d11f00c2c11a0c12d1190322d1190562d11d0572d11",
            ),
            "11897c44": (
                32,
                "file",
                "d0d62a11608c2c1100690d10900d2c1150c22d11b0322d11d0481e1060650d10",
            ),
            "11848c9c": (
                32,
                "file",
                "afd86b11afd86b11afd86b11afd86b11afd86b11afd86b11afd86b11afd86b11",
            ),
        }
        for addr, (width, storage, hex_le) in expected_globals.items():
            g = by_global[addr]
            self.assertEqual(g["width"], width)
            self.assertEqual(g["storage"], storage)
            self.assertEqual(g["initial_hex_le"], hex_le)

        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        expected_witnesses = {
            "112d98c0": "8b49148b018b4038ffe0",
            "100f3b10": "6a006a006a006a006a00e8f73e5901",
            "112acf43": "ff7610c70610778911ff760ce87ca0e4fe83c408c70678928411",
            "112daa9d": "ff7610c7461c00000000ff760ce821c5e1fe83c408c7460cffffffffc74610ffffffff",
            "112c001f": "e89c4ce4fe83c40889460cc74610ffffffff83f8ff7443",
            "112ace20": "f644240401568bf1c70678928411740b6a2056e89f673d0083c4088bc65ec20400",
            "112c9520": "8b411885c0740c8b008b401cc1e80683e001c3b001c3",
            "112c8c80": "8b4918ff7424048b0983c108e82f6ce3fe8b442404c20400",
            "112c8c40": "8079240075178079250075118b49148b018b4014ffd084c07403b001c332c0c3",
            "112c0cff": "8b460c03c73b4608723d8b4e148b01c744240800000000",
            "112dc1af": "8b460c3bc772122bc789460c8bc6297e105f5e83c40cc20400",
            "112d57a3": "8b038bcbff501c5f5e5db0015b83c40cc208005f5e5dc643250132c05b83c40cc20800",
            "112d57d0": "568bf18b4e148b01ff50103946100f93c08846245ec3",
            "100f3820": "f644240401568bf1c706581d7411740b6a0856e89ffd580183c4088bc65ec20400",
            "10115df0": "8b4904b8641d741185c90f45c1c3",
            "10104cc0": "807c240800b9010000686a00b8010000080f45c1506a036a006a036800000080ff74241cff159cf17211c3",
        }
        for addr, hex_bytes in expected_witnesses.items():
            self.assertEqual(witnesses[addr], bytes.fromhex(hex_bytes))

        by_fn = {entry["address"]: entry for entry in self.registry["functions"]}
        expected_fns = {
            "112acf40": (53, "thiscall", "ECX", 4, 4, ["112acf72"]),
            "10a34b40": (16, "thiscall", "ECX", 4, 4, ["10a34b4d"]),
            "101d9800": (4, "thiscall", "ECX", 0, 0, ["101d9803"]),
            "112c8b90": (24, "thiscall", "ECX", 0, 0, ["112c8ba4", "112c8ba7"]),
            "112d0bf0": (142, "thiscall", "ECX", 8, 8, ["112d0c7b"]),
            "112d0d20": (86, "thiscall", "ECX", 4, 4, ["112d0d73"]),
            "112daa40": (147, "thiscall", "ECX", 0, 0, ["112daa4f", "112daa82", "112daad2"]),
            "101d97f0": (4, "thiscall", "ECX", 0, 0, ["101d97f3"]),
            "112baeb0": (49, "thiscall", "ECX", 0, 0, ["112baee0"]),
            "112d9880": (16, "thiscall", "ECX", 0, 0, ["112d988f"]),
            "112d0bb0": (24, "thiscall", "ECX", 0, 0, ["112d0bc4", "112d0bc7"]),
            "112c0db0": (28, "thiscall", "ECX", 0, 0, ["112c0dc7", "112c0dcb"]),
            "112dd2e0": (15, "thiscall", "ECX", 0, 0, ["112dd2ee"]),
            "112bffe0": (175, "thiscall", "ECX", 4, 4, ["112c008c"]),
            "112ace20": (33, "thiscall", "ECX", 4, 4, ["112ace3e"]),
            "10abbf90": (8, "thiscall", "ECX", 0, 0, ["10abbf97"]),
            "112c9520": (22, "thiscall", "ECX", 0, 0, ["112c9532", "112c9535"]),
            "112c8c80": (24, "thiscall", "ECX", 4, 4, ["112c8c95"]),
            "112c8c40": (32, "thiscall", "ECX", 0, 0, ["112c8c5c", "112c8c5f"]),
            "112c0cf0": (159, "thiscall", "ECX", 4, 4, ["112c0d53", "112c0d8c"]),
            "112dc1a0": (174, "thiscall", "ECX", 4, 4, ["112dc1c5", "112dc212", "112dc24b"]),
            "112d3290": (19, "thiscall", "ECX", 4, 4, ["112d32a0"]),
            "112d5690": (310, "thiscall", "ECX", 8, 8, ["112d57b3", "112d57c3"]),
            "112d57d0": (22, "thiscall", "ECX", 0, 0, ["112d57e5"]),
            "100f3820": (33, "thiscall", "ECX", 4, 4, ["100f383e"]),
            "10115df0": (14, "thiscall", "ECX", 0, 0, ["10115dfd"]),
            "100f6fd0": (17, "cdecl", "none", 4, 0, ["100f6fe0"]),
            "10104cc0": (43, "cdecl", "none", 8, 0, ["10104cea"]),
            "1011fda0": (34, "thiscall", "ECX", 0, 0, ["1011fdc1"]),
            "112b43d0": (66, "cdecl", "none", 12, 0, ["112b43f4", "112b4411"]),
        }
        for addr, (size, cc, rx, stack, pop, rets) in expected_fns.items():
            fn = by_fn[addr]
            self.assertEqual(fn["bytes"], size)
            self.assertEqual(fn["calling_convention"], cc)
            self.assertEqual(fn["receiver_register"], rx)
            self.assertEqual(fn["stack_argument_bytes"], stack)
            self.assertEqual(fn["callee_pop_bytes"], pop)
            self.assertEqual(fn["return_instruction_addresses"], rets)

    def test_layer27_dual_slot_cipher_mem_and_delegate_adapter_contracts(self):
        evidence = self.registry["rea_layer27_evidence"]
        self.assertEqual(evidence["reused_layer26_evidence_records"], 95)
        self.assertEqual(evidence["new_evidence_records"], 61)
        self.assertEqual(evidence["retained_operation_envelopes"], 55)
        self.assertEqual(evidence["extra_evidence_views_count"], 6)
        self.assertEqual(evidence["closed_evidence_records"], 156)
        self.assertEqual(evidence["cumulative_validated_bundle_records"], 523)
        self.assertEqual(len(evidence["records"]), 55)
        self.assertEqual(
            evidence["non_proc_slots"],
            [
                "101d3b10", "112b31c0", "112bae20", "112bff30", "112c8c30",
                "112ce900", "112d8e10", "112d98a0", "112dd2b0", "112dd2c0",
            ],
        )
        self.assertEqual(evidence["resource_constrained_slots"], ["100f1720", "100f3090"])
        self.assertEqual(
            evidence["closed_snapshot_sha256"],
            "e8d16749766a006a89e149436ad409d96bcca96805bf9de3553458951603bdd1",
        )
        self.assertEqual(
            evidence["validated_bundle_sha256"],
            "d77f5c0aad2793ca14373572b467e7e5184c33c8d7bb27b7f58d93dc059599ad",
        )
        self.assertEqual(
            evidence["cumulative_validated_bundle_sha256"],
            "2d387473bbc4d3d351ef82b240b550c645936b84afb038adb658ffe2bad1f3d1",
        )

        by_vt = {entry["address"]: entry for entry in self.registry["vtables"]}
        self.assertEqual(by_vt["11897818"]["first_slot_code_identity"], "112ad210")
        self.assertEqual(by_vt["11897844"]["first_slot_code_identity"], "112ace20")
        self.assertEqual(by_vt["11897c90"]["first_slot_code_identity"], "112ad1e0")

        by_global = {entry["address"]: entry for entry in self.registry["globals"]}
        expected_globals = {
            "11897818": (
                44,
                "file",
                "10d22a11508f2d11c0d22d11c0220e10d0ab2d11308c2c11a0982d1130af2b11"
                "00e92c1130f65d10c0312b11",
            ),
            "11897844": (
                36,
                "file",
                "20ce2a11108e2d11b0d22d1130ff2b1130b47410300b5d1000125d1020ae2b11"
                "00141710",
            ),
            "11897c90": (
                60,
                "file",
                "e0d12a11103b1d1000bc0d10602e1810b09c031140508c1030508c1060602d11"
                "90be01111016031190fe2d1130412d11e0da2c11902f2c1160650d10",
            ),
            "1173db9c": (
                60,
                "file",
                "b0380d10afd86b11503b0d1000690d10afd86b1130700d1050380d1000b70d10"
                "80670d10e0380d10306e0d1010380d1010390d10205f0d10b0aa0d10",
            ),
            "11af406c": (4, "zero_fill", "00000000"),
            "11af407c": (4, "zero_fill", "00000000"),
        }
        for addr, (width, storage, hex_le) in expected_globals.items():
            g = by_global[addr]
            self.assertEqual(g["width"], width)
            self.assertEqual(g["storage"], storage)
            self.assertEqual(g["initial_hex_le"], hex_le)

        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        expected_witnesses = {
            "11039cb0": "8b49048b01ff6010",
            "108c5040": "8b49048b01ff6014",
            "108c5030": "8b49048b01ff6018",
            "112d6060": "8b49048b01ff601c",
            "1101be90": "8b49048b01ff6020",
            "11031610": "8b49048b01ff6024",
            "112dfe90": "8b49048b01ff6028",
            "112d4130": "8b49048b01ff602c",
            "112cdae0": "8b49048b018b4030ffe0",
            "112c2f90": "8b49048b01ff6034",
            "112ba9c5": "c70618788911",
            "112ad21a": "c70318788911",
            "112ad237": "c70378928411",
            "112d8fd5": "80f101",
            "112dabd3": "834624ff",
            "112dc8db": "c70744788911",
            "112bff4f": "e87cd0e3fe",
            "112c6b17": "c744240c907c8911",
            "112ad1f0": "c7069cdb7311",
            "1011541f": "f7c100810000",
        }
        for addr, hex_bytes in expected_witnesses.items():
            self.assertEqual(witnesses[addr], bytes.fromhex(hex_bytes))

        by_fn = {entry["address"]: entry for entry in self.registry["functions"]}
        expected_fns = {
            "112ad210": (66, "thiscall", "ECX", 4, 4, ["112ad24f"]),
            "112d8f50": (593, "thiscall", "ECX", 12, 12, ["112d8fb3", "112d8fce", "112d919e"]),
            "112dd2c0": (31, "thiscall", "ECX", 12, 12, ["112dd2dc"]),
            "112dabd0": (72, "thiscall", "ECX", 0, 0, ["112dac17"]),
            "112c8c30": (15, "thiscall", "ECX", 0, 0, ["112c8c3e"]),
            "112d98a0": (29, "thiscall", "ECX", 0, 0, ["112d98b9", "112d98bc"]),
            "112baf30": (61, "thiscall", "ECX", 0, 0, ["112baf67", "112baf6c"]),
            "112ce900": (26, "thiscall", "ECX", 0, 0, ["112ce916", "112ce919"]),
            "105df630": (8, "thiscall", "ECX", 0, 0, ["105df637"]),
            "112b31c0": (100, "thiscall", "ECX", 4, 4, ["112b321a", "112b3221"]),
            "112ba840": (564, "cdecl", "none", 8, 0, ["112ba869", "112ba8f4", "112ba8fc", "112ba94e", "112baa69", "112baa73"]),
            "112a2090": (27, "thiscall", "ECX", 0, 0, ["112a20aa"]),
            "112ab500": (13, "thiscall", "ECX", 0, 0, ["112ab50c"]),
            "112d8e10": (6, "thiscall", "ECX", 12, 12, ["112d8e13"]),
            "112dd2b0": (8, "thiscall", "ECX", 12, 12, ["112dd2b5"]),
            "112bff30": (66, "thiscall", "ECX", 8, 8, ["112bff64", "112bff6f"]),
            "1074b430": (12, "thiscall", "ECX", 0, 0, ["1074b43b"]),
            "105d0b30": (4, "thiscall", "ECX", 0, 0, ["105d0b33"]),
            "105d1200": (4, "thiscall", "ECX", 0, 0, ["105d1203"]),
            "112bae20": (140, "thiscall", "ECX", 0, 0, ["112baea5", "112baeab"]),
            "112ad1e0": (41, "thiscall", "ECX", 4, 4, ["112ad206"]),
            "101d3b10": (18, "thiscall", "ECX", 12, 12, ["101d3b1f"]),
            "112c6b10": (97, "cdecl", "none", 12, 0, ["112c6b70"]),
            "112a9550": (11, "thiscall", "ECX", 4, 4, ["112a9558"]),
            "101153f0": (176, "thiscall", "ECX", 4, 4, ["1011548f", "1011549d"]),
            "101154a0": (143, "thiscall", "ECX", 4, 4, ["10115523", "1011552c"]),
            "10115540": (37, "cdecl", "none", 8, 0, ["10115564"]),
            "101211b0": (157, "cdecl", "none", 16, 0, ["1012124c"]),
            "100f1720": (124, "thiscall", "ECX", 4, 4, ["100f1799"]),
            "100f3090": (192, "thiscall", "ECX", 4, 4, ["100f314d"]),
        }
        for addr, (size, cc, rx, stack, pop, rets) in expected_fns.items():
            fn = by_fn[addr]
            self.assertEqual(fn["bytes"], size)
            self.assertEqual(fn["calling_convention"], cc)
            self.assertEqual(fn["receiver_register"], rx)
            self.assertEqual(fn["stack_argument_bytes"], stack)
            self.assertEqual(fn["callee_pop_bytes"], pop)
            self.assertEqual(fn["return_instruction_addresses"], rets)

    def test_layer28_base_fs_shared_ctrl_and_secondary_fs_contracts(self):
        ev = self.registry["rea_layer28_evidence"]
        self.assertEqual(ev["closed_evidence_records"], 216)
        self.assertEqual(ev["new_evidence_records"], 60)
        self.assertEqual(ev["retained_operation_envelopes"], 57)
        self.assertEqual(ev["reused_layer27_evidence_records"], 156)
        self.assertEqual(ev["extra_evidence_views_count"], 3)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 583)
        self.assertEqual(len(ev["records"]), 57)
        self.assertEqual(
            ev["non_proc_slots"],
            [
                "10457110", "11002ca0", "1108d3b0", "112accb0", "112acfb0",
                "112b0810", "112bbaf0", "112c9550", "112d2980", "112d2a70",
                "112d2bb0", "112d5bd0", "112e14a0", "112e3480",
            ],
        )
        self.assertEqual(ev["resource_constrained_slots"], ["1018bd90"])

        by_vt = {entry["address"]: entry for entry in self.registry["vtables"]}
        self.assertEqual(by_vt["1189791c"]["first_slot_code_identity"], "100f3d00")
        self.assertEqual(by_vt["1189a520"]["first_slot_code_identity"], "112afc90")

        by_global = {entry["address"]: entry for entry in self.registry["globals"]}
        expected_globals = {
            "1189791c": (
                120,
                "file",
                "003d0f10003d0f1070670d10003d0f10003d0f1070670d1090bd181010082b11"
                "a0142e1190cc2f1090cc2f10f0ba2b11f0ba2b11d05b2d1100bc0d1090bd1810"
                "b0d30811a02c001170670d10003d0f1060650d10003d0f1070670d1000bc0d10"
                "50952c1150952c11508c1210003d0f1010714510b0cf2a11",
            ),
            "1189799c": (
                44,
                "file",
                "c0d02b11d00e2e11b0e32c11b0e32c11b0e32c1180292d11702a2d1100031810"
                "d0481e1090bd181090bd1810",
            ),
            "118978f0": (
                44,
                "file",
                "e0dd2c11e0102e11300f2e1110e42c1110e42c11602b2d11b02b2d1160962d11"
                "e0302b11c0f62c1180342e11",
            ),
            "1189a520": (16, "file", "90fc2a1110bb9010b0cc2a11508c1210"),
            "118979c8": (13, "file", "3c656d7074792066696c653e00"),
            "119e1000": (4, "file", "ffffffff"),
            "12032890": (12, "zero_fill", "00" * 12),
            "1203289c": (4, "zero_fill", "00000000"),
            "120328a0": (28, "zero_fill", "00" * 28),
            "120328c0": (4, "zero_fill", "00000000"),
            "120328c8": (28, "zero_fill", "00" * 28),
            "120328e8": (4, "zero_fill", "00000000"),
            "120328ec": (12, "zero_fill", "00" * 12),
            "120328f8": (4, "zero_fill", "00000000"),
            "12032af8": (1, "zero_fill", "00"),
            "12032afc": (4, "zero_fill", "00000000"),
            "120325e0": (1, "zero_fill", "00"),
        }
        for addr, (width, storage, hex_le) in expected_globals.items():
            g = by_global[addr]
            self.assertEqual(g["width"], width)
            self.assertEqual(g["storage"], storage)
            self.assertEqual(g["initial_hex_le"], hex_le)

        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        expected_witnesses = {
            "117240b0": "c70504109e111c798911",
            "117240ba": "c70508109e1194798911",
            "112b0848": "6820467211",
            "11724620": "538b1d98280312",
            "112acfb8": "c7061c798911c7460494798911",
            "112e0f01": "c70020a58911",
            "112d2a13": "c705c828031260778911",
            "112d2a35": "68d0467211",
            "117246d0": "c705c828031278928411c3",
            "112d2b03": "c705a028031260778911",
            "112d2c7f": "c70160778911",
            "112cde18": "c707e07b8911",
            "112e11a2": "c706447c8911",
            "112bd25f": "3b3d00109e11",
            "112bd26b": "81c7ffffff7f",
            "112e103a": "3b3d00109e11",
            "112d97c6": "e80538e2fe",
            "112d2da0": "803d3827031200",
            "112d2dad": "803dce1a031200",
            "112b3040": "64a12c000000",
            "112cf6c9": "e87239feff",
            "112e3487": "e8b4fbfcff",
        }
        for addr, hex_bytes in expected_witnesses.items():
            self.assertEqual(witnesses[addr], bytes.fromhex(hex_bytes))

        by_fn = {entry["address"]: entry for entry in self.registry["functions"]}
        expected_fns = {
            "117240b0": (21, "cdecl", "none", 0, 0, ["117240c4"]),
            "1018bd90": (5, "thiscall", "ECX", 4, 4, ["1018bd92"]),
            "112b0810": (81, "cdecl", "none", 0, 0, ["112b0831"]),
            "112e14a0": (8, "thiscall", "ECX", 4, 4, ["112e14a5"]),
            "102fcc90": (3, "thiscall", "ECX", 20, 20, ["102fcc90"]),
            "112bbaf0": (28, "thiscall", "ECX", 8, 8, ["112bbb09"]),
            "112d5bd0": (21, "thiscall", "ECX", 8, 8, ["112d5be2"]),
            "1108d3b0": (6, "thiscall", "ECX", 4, 4, ["1108d3b3"]),
            "11002ca0": (20, "thiscall", "ECX", 8, 8, ["11002cb1"]),
            "112c9550": (78, "thiscall", "ECX", 8, 8, ["112c959b"]),
            "10457110": (5, "thiscall", "ECX", 8, 8, ["10457112"]),
            "112acfb0": (40, "thiscall", "ECX", 4, 4, ["112acfd5"]),
            "112e0ed0": (87, "thiscall", "ECX", 20, 20, ["112e0f17", "112e0f24"]),
            "112ce3b0": (87, "thiscall", "ECX", 16, 16, ["112ce3f7", "112ce404"]),
            "112d2980": (237, "thiscall", "ECX", 8, 8, ["112d29e8"]),
            "112d2a70": (237, "thiscall", "ECX", 8, 8, ["112d2ad8"]),
            "10180300": (5, "thiscall", "ECX", 12, 12, ["10180302"]),
            "112afc90": (14, "thiscall", "ECX", 0, 0, ["112afc9d"]),
            "112accb0": (27, "thiscall", "ECX", 4, 4, ["112accc8"]),
            "112bd130": (628, "thiscall", "ECX", 16, 16, ["112bd250", "112bd337", "112bd3a1"]),
            "112cdde0": (721, "thiscall", "ECX", 16, 16, ["112cde88", "112cdf88", "112ce0ae"]),
            "112e10e0": (381, "thiscall", "ECX", 20, 20, ["112e113a", "112e114b", "112e125a"]),
            "112e0f30": (419, "thiscall", "ECX", 16, 16, ["112e102f", "112e10be", "112e10d0"]),
            "112ce410": (662, "thiscall", "ECX", 16, 16, ["112ce46e", "112ce481", "112ce58d", "112ce62d", "112ce6a3"]),
            "112d2b60": (79, "thiscall", "ECX", 8, 8, ["112d2bac"]),
            "112d2bb0": (711, "thiscall", "ECX", 8, 8, ["112d2d27", "112d2e74"]),
            "112d9660": (390, "thiscall", "ECX", 12, 12, ["112d9681", "112d9788", "112d97e3"]),
            "112b30e0": (165, "thiscall", "ECX", 8, 8, ["112b30fb", "112b3182"]),
            "112cf6c0": (451, "thiscall", "ECX", 4, 4, ["112cf6e8", "112cf880"]),
            "112e3480": (269, "thiscall", "ECX", 4, 4, ["112e3497", "112e34aa", "112e3518", "112e355c", "112e358a"]),
        }
        for addr, (size, cc, rx, stack, pop, rets) in expected_fns.items():
            fn = by_fn[addr]
            self.assertEqual(fn["bytes"], size)
            self.assertEqual(fn["calling_convention"], cc)
            self.assertEqual(fn["receiver_register"], rx)
            self.assertEqual(fn["stack_argument_bytes"], stack)
            self.assertEqual(fn["callee_pop_bytes"], pop)
            self.assertEqual(fn["return_instruction_addresses"], rets)

    def test_layer29_active_fs_primary_interface_contracts(self):
        ev = self.registry["rea_layer29_evidence"]
        self.assertEqual(ev["closed_evidence_records"], 279)
        self.assertEqual(ev["new_evidence_records"], 63)
        self.assertEqual(ev["retained_operation_envelopes"], 63)
        self.assertEqual(ev["reused_layer28_evidence_records"], 216)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 646)
        self.assertEqual(len(ev["records"]), 63)
        self.assertEqual(len(ev["non_proc_slots"]), 20)
        self.assertEqual(ev["resource_constrained_slots"], [])

        vtables = {v["address"]: v["first_slot_code_identity"]
                   for v in self.registry["vtables"]}
        self.assertEqual(vtables["11897870"], "112beac0")

        by_global = {entry["address"]: entry for entry in self.registry["globals"]}
        expected_globals = {
            "11897870": (
                120,
                "file",
                "c0ea2b11f0362e1120072d1140f02d11003d0f1020f92c1130322b1170082b11"
                "b0142e1150bb2b1110db2b1100402e1110bb2b11f05b2d1190ba2b11a0ba2b11"
                "004f2d11d04b2d1140ad0e1070f22d1160342e11d02c2e11b08b2c11d0dd2c11"
                "50952c11a0952c1130942c1150e32d11b0002c1170d02a11",
            ),
            "119e0fe8": (4, "file", "01000080"),
            "119e11b8": (12, "file", "100000000000000000000000"),
            "119e11c4": (12, "file", "100000000000000000000000"),
            "119e11d0": (12, "file", "cb0300000000000000000000"),
            "119e11ec": (16, "file", "00000000200000000000000000000000"),
            "12031ad8": (4, "zero_fill", "00000000"),
            "12031ae0": (4, "zero_fill", "00000000"),
            "12031ae7": (1, "zero_fill", "00"),
            "12032080": (1, "zero_fill", "00"),
            "12032435": (1, "zero_fill", "00"),
            "12032438": (12, "zero_fill", "000000000000000000000000"),
            "1203291c": (4, "zero_fill", "00000000"),
            "12032920": (16, "zero_fill", "00000000000000000000000000000000"),
            "12032930": (4, "zero_fill", "00000000"),
            "120329b0": (4, "zero_fill", "00000000"),
            "120329dc": (4, "zero_fill", "00000000"),
        }
        for addr, (width, storage, hex_le) in expected_globals.items():
            g = by_global[addr]
            self.assertEqual(g["width"], width)
            self.assertEqual(g["storage"], storage)
            self.assertEqual(g["initial_hex_le"], hex_le)

        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        expected_witnesses = {
            "112beac0": "e84b0000008bc8e964c8e2fe",
            "112b0870": "e94b280200",
            "112bbc57": "68203f2e11",
            "112df043": "e87840ffff",
            "112ad073": "c70670788911",
            "112ad079": "c74604e8788911",
            "112ad088": "c705101f031200000000",
            "112e39eb": "a3e8119e11",
            "112e3468": "ff5074",
            "112e346b": "c705101f031200000000",
            "112c00ff": "e8ec8efeff",
            "112c0108": "a3101f0312",
            "112c0118": "884124",
            "112c01cb": "ff05e80f9e11",
            "112c94cf": "a3e80f9e11",
            "112d4c1e": "f0ff4604",
            "112e14be": "e83dbafdff",
            "112beb4a": "68c0000000",
            "112beb54": "68b04a7211",
            "112d3104": "68e04b7211",
            "112bbce4": "68104a7211",
            "112e3cf9": "68c04e7211",
            "112e3ca1": "c705242903121b3b0200",
        }
        for addr, hex_bytes in expected_witnesses.items():
            self.assertEqual(witnesses[addr], bytes.fromhex(hex_bytes))

        by_fn = {entry["address"]: entry for entry in self.registry["functions"]}
        expected_fns = {
            "112e36f0": (882, "thiscall", "ECX", 4, 4, ["112e3993"]),
            "112d0720": (1151, "thiscall", "ECX", 0, 0, ["112d0a7c"]),
            "112df040": (246, "thiscall", "ECX", 4, 4, ["112df133"]),
            "112cf920": (723, "thiscall", "ECX", 0, 0, ["112cfad9"]),
            "112b3230": (56, "thiscall", "ECX", 4, 4, ["112b3243", "112b3265"]),
            "112e14b0": (80, "thiscall", "ECX", 4, 4, ["112e14c6", "112e14fd"]),
            "112bbb50": (326, "thiscall", "ECX", 20, 20, ["112bbc93"]),
            "112bdb10": (239, "thiscall", "ECX", 20, 20, ["112bdbfc"]),
            "112e4000": (77, "thiscall", "ECX", 8, 8, ["112e4038", "112e404a"]),
            "112bbb10": (63, "thiscall", "ECX", 8, 8, ["112bbb27", "112bbb4c"]),
            "112d5bf0": (99, "thiscall", "ECX", 8, 8, ["112d5c13", "112d5c50"]),
            "112bba90": (9, "thiscall", "ECX", 0, 0, ["112bba98"]),
            "112bbaa0": (68, "thiscall", "ECX", 4, 4, ["112bbadb", "112bbae1"]),
            "112d4f00": (37, "thiscall", "ECX", 4, 4, ["112d4f1c", "112d4f22"]),
            "112d4bd0": (119, "thiscall", "ECX", 8, 8, ["112d4c2f", "112d4c44"]),
            "100ead40": (4, "thiscall", "ECX", 0, 0, ["100ead43"]),
            "112df270": (24, "thiscall", "ECX", 4, 4, ["112df285"]),
            "112e3460": (22, "thiscall", "ECX", 0, 0, ["112e3475"]),
            "112e2cd0": (12, "thiscall", "ECX", 4, 4, ["112e2cd9"]),
            "112c8bb0": (6, "thiscall", "ECX", 0, 0, ["112c8bb5"]),
            "112cddd0": (6, "thiscall", "ECX", 0, 0, ["112cddd5"]),
            "112c95a0": (635, "thiscall", "ECX", 8, 8, ["112c9600", "112c9715", "112c97bc", "112c9818"]),
            "112c9430": (225, "thiscall", "ECX", 4, 4, ["112c9442", "112c94e2", "112c94fa", "112c950e"]),
            "112de350": (12, "thiscall", "ECX", 4, 4, ["112de359"]),
            "112c00b0": (313, "thiscall", "ECX", 8, 8, ["112c014c", "112c01a1", "112c01e6"]),
            "112ad070": (65, "thiscall", "ECX", 4, 4, ["112ad0ae"]),
            "112beb10": (98, "cdecl", "none", 0, 0, ["112beb31"]),
            "100eb330": (290, "thiscall", "ECX", 4, 4, ["100eb352", "100eb383", "100eb44f"]),
            "112d30c0": (98, "cdecl", "none", 0, 0, ["112d30e1"]),
            "112bcf00": (81, "cdecl", "none", 0, 0, ["112bcf21"]),
            "112bbca0": (98, "cdecl", "none", 0, 0, ["112bbcc1"]),
            "112e3c60": (180, "cdecl", "none", 0, 0, ["112e3c81"]),
        }
        for addr, (size, cc, rx, stack, pop, rets) in expected_fns.items():
            fn = by_fn[addr]
            self.assertEqual(fn["bytes"], size)
            self.assertEqual(fn["calling_convention"], cc)
            self.assertEqual(fn["receiver_register"], rx)
            self.assertEqual(fn["stack_argument_bytes"], stack)
            self.assertEqual(fn["callee_pop_bytes"], pop)
            self.assertEqual(fn["return_instruction_addresses"], rets)
        self.assertEqual(by_fn["112d0720"]["body_ranges"], [
            {"start": "112d0720", "end": "112d0a7d"},
            {"start": "112d0a88", "end": "112d0ba8"},
        ])
        self.assertEqual(by_fn["112cf920"]["body_ranges"], [
            {"start": "112cf920", "end": "112cfada"},
            {"start": "112cfaed", "end": "112cfc04"},
        ])
        self.assertEqual(by_fn["112e3c60"]["body_ranges"], [
            {"start": "112e3c60", "end": "112e3cdc"},
            {"start": "112e3ce0", "end": "112e3d16"},
        ])

    def test_layer30_fs_mount_rebuild_hash_and_teardown_contracts(self):
        ev = self.registry["rea_layer30_evidence"]
        self.assertEqual(ev["closed_evidence_records"], 324)
        self.assertEqual(ev["new_evidence_records"], 45)
        self.assertEqual(ev["retained_operation_envelopes"], 45)
        self.assertEqual(ev["reused_layer29_evidence_records"], 279)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 691)
        self.assertEqual(len(ev["records"]), 45)
        self.assertEqual(ev["non_proc_slots"], ["112e3f20"])
        self.assertEqual(ev["resource_constrained_slots"], [])

        by_global = {entry["address"]: entry for entry in self.registry["globals"]}
        expected_globals = {
            "1172f20c": (4, "file", "f4099301"),
            "1172f2d8": (4, "file", "a40d9301"),
            "117402c0": (16, "file", "0000000000000000000000002ece2f35"),
            "1189a6c0": (16, "file", "0000000000000000000000002fce2f35"),
            "119e11dc": (12, "file", "e0119e110000000000000000"),
            "119e1224": (12, "file", "f82401000000000000000000"),
            "119f387c": (16, "zero_fill", "00000000000000000000000000000000"),
            "119f388c": (4, "zero_fill", "00000000"),
            "12031f14": (1, "zero_fill", "00"),
            "12032934": (12, "zero_fill", "000000000000000000000000"),
            "12032940": (4, "zero_fill", "00000000"),
            "120329fc": (16, "zero_fill", "00000000000000000000000000000000"),
            "12032a0c": (4, "zero_fill", "00000000"),
            "12032a10": (4, "zero_fill", "00000000"),
            "12032a3c": (4, "zero_fill", "00000000"),
            "12032a88": (4, "zero_fill", "00000000"),
            "12032b00": (4, "zero_fill", "00000000"),
            "12032b2c": (12, "zero_fill", "000000000000000000000000"),
            "12032b8c": (16, "zero_fill", "00000000000000000000000000000000"),
            "12032b9c": (4, "zero_fill", "00000000"),
            "12035150": (1, "zero_fill", "00"),
            "12035151": (1, "zero_fill", "00"),
        }
        for addr, (width, storage, hex_le) in expected_globals.items():
            g = by_global[addr]
            self.assertEqual(g["width"], width)
            self.assertEqual(g["storage"], storage)
            self.assertEqual(g["initial_hex_le"], hex_le)

        witnesses = {w["address"]: bytes.fromhex(w["hex"])
                     for w in self.registry["instruction_witnesses"]}
        expected_witnesses = {
            "112d5d10": "3b35342a0312",
            "112d5f00": "e84b82feff",
            "112e2068": "c605881a031200",
            "112e257a": "68142b0312",
            "112e2581": "ff05102b0312",
            "112e2655": "ff35302b0312ff150cf27211",
            "112e2a89": "c705302b031200000000",
            "112d2ec1": "c705002a031299010000",
            "112d2f19": "68904b7211",
            "112c097d": "e82ebafeff",
            "112ac3b3": "830608",
            "112da7b2": "803d141f031200",
            "112d294a": "68804f1200",
            "112d2954": "68704b7211",
            "112de43c": "e8efdbffff",
            "112dc0ac": "e8bf1c0000",
            "112d8a19": "c70601000000",
            "112e3f36": "b9a4207411",
            "112e3fcc": "e81f4affff",
            "112a2c00": "81fa55555505",
            "112b3078": "803de025031201",
            "11302c49": "ff15d8f27211",
            "112c8f3d": "0f2805c0a68911",
            "112c8f77": "0f2805c0027411",
        }
        for addr, hex_bytes in expected_witnesses.items():
            self.assertEqual(witnesses[addr], bytes.fromhex(hex_bytes))

        by_fn = {entry["address"]: entry for entry in self.registry["functions"]}
        expected_fns = {
            "112d5cc0": (737, "cdecl", "none", 0, 0, ["112d5f20"]),
            "112be150": (428, "thiscall", "ECX", 4, 4, ["112be290", "112be2f9"]),
            "112e1a00": (4350, "cdecl", "none", 0, 0, ["112e26b1"]),
            "112d2e80": (180, "cdecl", "none", 0, 0, ["112d2ea1"]),
            "112c0940": (123, "thiscall", "ECX", 4, 4, ["112c09b8"]),
            "112ac3b0": (60, "thiscall", "ECX", 0, 0, ["112ac3eb"]),
            "112c91d0": (593, "thiscall", "ECX", 4, 4, ["112c941e"]),
            "112da500": (1260, "cdecl", "none", 0, 0, ["112da8fc"]),
            "112d2910": (98, "cdecl", "none", 0, 0, ["112d2931"]),
            "112de360": (308, "thiscall", "ECX", 8, 8, ["112de457", "112de484", "112de491"]),
            "112dc030": (165, "thiscall", "ECX", 4, 4, ["112dc0d2"]),
            "112ddd70": (356, "thiscall", "ECX", 8, 8, ["112dde96", "112ddeb1", "112dded1"]),
            "112d89f0": (229, "thiscall", "ECX", 4, 4, ["112d8a0f", "112d8a3d", "112d8ad2"]),
            "112d7dc0": (395, "thiscall", "ECX", 4, 4, ["112d7dfe", "112d7e48", "112d7f48"]),
            "112d7f50": (536, "thiscall", "ECX", 4, 4, ["112d7fbb", "112d7ff6", "112d8165"]),
            "112e3f20": (200, "cdecl", "none", 20, 0, ["112e3fe7"]),
            "112a51b0": (520, "cdecl", "none", 20, 0, ["112a53ad", "112a53b7"]),
            "112a4c80": (397, "cdecl", "none", 24, 0, ["112a4d68", "112a4e0c"]),
            "112c06c0": (491, "cdecl", "none", 16, 0, ["112c08aa"]),
            "112c14b0": (2621, "cdecl", "none", 4, 0, ["112c154d", "112c1e6c"]),
            "112a75b0": (217, "thiscall", "ECX", 4, 4, ["112a7675", "112a7686"]),
            "112a74d0": (121, "thiscall", "ECX", 4, 4, ["112a7546"]),
            "112a7440": (134, "thiscall", "ECX", 4, 4, ["112a74c3"]),
            "112a2ba0": (726, "thiscall", "ECX", 12, 12, ["112a2df2", "112a2e39", "112a2e57", "112a2e69"]),
            "112d28a0": (81, "cdecl", "none", 0, 0, ["112d28c1"]),
            "112b3040": (106, "cdecl", "none", 0, 0, ["112b3061"]),
            "11302c40": (71, "cdecl", "none", 0, 0, ["11302c71", "11302c80", "11302c86"]),
            "112c8ca0": (759, "cdecl", "none", 12, 0, ["112c8da4", "112c8e11", "112c8ebc", "112c8f22"]),
            "112b5670": (83, "stdcall", "none", 8, 8, ["112b56c0"]),
            "112a8540": (157, "thiscall", "ECX", 4, 4, ["112a85da"]),
        }
        for addr, (size, cc, rx, stack, pop, rets) in expected_fns.items():
            fn = by_fn[addr]
            self.assertEqual(fn["bytes"], size)
            self.assertEqual(fn["calling_convention"], cc)
            self.assertEqual(fn["receiver_register"], rx)
            self.assertEqual(fn["stack_argument_bytes"], stack)
            self.assertEqual(fn["callee_pop_bytes"], pop)
            self.assertEqual(fn["return_instruction_addresses"], rets)
        self.assertEqual(by_fn["112d2e80"]["body_ranges"], [
            {"start": "112d2e80", "end": "112d2efc"},
            {"start": "112d2f00", "end": "112d2f36"},
        ])

    def test_layer31_vfs_index_traverse_rehash_and_atexit_evidence(self):
        ev31 = self.registry["rea_layer31_evidence"]
        self.assertEqual(len(ev31["records"]), 50)
        self.assertEqual(ev31["closed_evidence_records"], 376)
        self.assertEqual(ev31["new_evidence_records"], 52)
        self.assertEqual(ev31["reused_layer30_evidence_records"], 324)
        self.assertEqual(ev31["extra_evidence_views_count"], 3)
        self.assertEqual(ev31["cumulative_validated_bundle_records"], 743)
        self.assertEqual(ev31["resource_constrained_slots"], ["100eaf40"])
        self.assertEqual(ev31["non_proc_slots"], [
            "11724a10", "11724a80", "11724ab0", "11724b00", "11724b30",
            "11724b70", "11724b90", "11724be0", "11724e30", "11724e50",
        ])

        by_fn = {fn["address"]: fn for fn in self.registry["functions"]}
        expected = [
            ("10122cb0", "cdecl", "none", 0, 0, ["10122cf7"]),
            ("10122640", "cdecl", "none", 0, 0, ["10122689"]),
            ("101217e0", "thiscall", "ECX", 4, 4, ["10121863", "10121907", "10121921"]),
            ("10121c40", "thiscall", "ECX", 8, 8, ["10121c91", "10121d4f", "10121d7d"]),
            ("10122260", "thiscall", "ECX", 8, 8, ["10122364"]),
            ("10122380", "cdecl", "none", 8, 0, ["10122396"]),
            ("10122d70", "cdecl", "none", 8, 0, ["10122db9"]),
            ("10121d80", "cdecl", "none", 8, 0, ["10121e6d", "10121e92"]),
            ("10121250", "cdecl", "none", 12, 0, ["10121320"]),
            ("100fec00", "cdecl", "none", 20, 0, ["100feeea"]),
            ("112ab1f0", "thiscall", "ECX", 0, 0, ["112ab230"]),
            ("112a26f0", "thiscall", "ECX", 8, 8, ["112a274f"]),
            ("112a28a0", "cdecl", "none", 8, 0, ["112a290a"]),
            ("112b03b0", "thiscall", "ECX", 4, 4, ["112b06c0"]),
            ("112b5420", "thiscall", "ECX", 0, 0, ["112b5445"]),
            ("112d7b40", "thiscall", "ECX", 4, 4, ["112d7b68", "112d7b9c", "112d7c4b"]),
            ("100eaf40", "thiscall", "ECX", 4, 4, ["100eaf5e", "100eaf8a", "100eb014"]),
            ("112c2370", "cdecl", "none", 0, 0, ["112c2391"]),
            ("112a5530", "cdecl", "none", 4, 0, ["112a5557", "112a555b"]),
            ("112a56d0", "cdecl", "none", 12, 0, ["112a57f3", "112a57fc"]),
            ("112f0b90", "cdecl", "none", 12, 0, ["112f0c9e"]),
            ("11724e50", "cdecl", "none", 0, 0, ["11724e60"]),
        ]
        for addr, cc, rx, stack, pop, rets in expected:
            fn = by_fn[addr]
            self.assertEqual(fn["calling_convention"], cc, addr)
            self.assertEqual(fn["receiver_register"], rx, addr)
            self.assertEqual(fn["stack_argument_bytes"], stack, addr)
            self.assertEqual(fn["callee_pop_bytes"], pop, addr)
            self.assertEqual(fn["return_instruction_addresses"], rets, addr)

    def test_layer32_vfs_init_intern_xml_and_string_evidence(self):
        ev32 = self.registry["rea_layer32_evidence"]
        self.assertEqual(len(ev32["records"]), 44)
        self.assertEqual(ev32["closed_evidence_records"], 423)
        self.assertEqual(ev32["new_evidence_records"], 47)
        self.assertEqual(ev32["reused_layer31_evidence_records"], 376)
        self.assertEqual(ev32["extra_evidence_views_count"], 3)
        self.assertEqual(ev32["cumulative_validated_bundle_records"], 790)
        self.assertEqual(ev32["non_proc_slots"], [])
        self.assertEqual(ev32["resource_constrained_slots"], ["100f2530"])

        by_fn = {fn["address"]: fn for fn in self.registry["functions"]}
        expected = [
            ("112a4690", "cdecl", "none", 8, 0, ["112a4759"]),
            ("112a85e0", "thiscall", "ECX", 4, 4, ["112a8600"]),
            ("112aa610", "thiscall", "ECX", 16, 16, ["112aa63b"]),
            ("112aa670", "thiscall", "ECX", 12, 12, ["112aa705"]),
            ("112aa710", "thiscall", "ECX", 4, 4, ["112aa751", "112aa75e"]),
            ("112acec0", "thiscall", "ECX", 4, 4, ["112acf36"]),
            ("112b0880", "thiscall", "ECX", 8, 8, ["112b0945", "112b0971", "112b09fc"]),
            ("112c2190", "cdecl", "none", 0, 0, ["112c21b1"]),
            ("112c21f0", "cdecl", "none", 0, 0, ["112c2211"]),
            ("112cc200", "thiscall", "ECX", 8, 8, ["112cc386", "112cc3ae"]),
            ("112ce950", "thiscall", "ECX", 0, 0, ["112cee20"]),
            ("112d3640", "cdecl", "none", 0, 0, ["112d3663"]),
            ("11300140", "cdecl", "none", 4, 0, ["113001fb", "11300211"]),
            ("100ff880", "cdecl", "none", 4, 0, ["100ff897", "100ff89a"]),
            ("100ff8e0", "cdecl", "none", 4, 0, ["100ff8ef"]),
            ("100ff8f0", "thiscall", "ECX", 8, 8, ["100ffa08"]),
            ("1011fef0", "thiscall", "ECX", 0, 0, ["1011ffad", "101204d6"]),
            ("10120b30", "cdecl", "none", 4, 0, ["10120b6b", "10120c0b"]),
            ("10120c10", "cdecl", "none", 8, 0, ["10120c56", "10120d8c"]),
            ("10121930", "cdecl", "none", 0, 0, ["10121977"]),
            ("101225a0", "cdecl", "none", 0, 0, ["101225e9"]),
            ("10122dc0", "cdecl", "none", 0, 0, ["10122de1"]),
            ("100f1a50", "thiscall", "ECX", 4, 4, ["100f1a90"]),
            ("100f2530", "thiscall", "ECX", 4, 4, ["100f255c"]),
            ("100f2ad0", "thiscall", "ECX", 4, 4, ["100f2add", "100f2ae5"]),
            ("100f2c40", "cdecl", "none", 12, 0, ["100f2cb9"]),
            ("100f2de0", "cdecl", "none", 12, 0, ["100f2e5c"]),
            ("100f6ea0", "thiscall", "ECX", 0, 0, ["100f6eb0"]),
            ("100f6ee0", "thiscall", "ECX", 0, 0, ["100f6eed", "100f6f0a", "100f6f20"]),
            ("100f70f0", "thiscall", "ECX", 12, 12, ["100f7142", "100f7175", "100f7195", "100f71a3"]),
            ("1017fc90", "stdcall", "none", 12, 12, ["1017fcd9"]),
        ]
        for addr, cc, rx, stack, pop, rets in expected:
            fn = by_fn[addr]
            self.assertEqual(fn["calling_convention"], cc, addr)
            self.assertEqual(fn["receiver_register"], rx, addr)
            self.assertEqual(fn["stack_argument_bytes"], stack, addr)
            self.assertEqual(fn["callee_pop_bytes"], pop, addr)
            self.assertEqual(fn["return_instruction_addresses"], rets, addr)

        fn_xml = by_fn["112c5460"]
        self.assertEqual(fn_xml["bytes"], 5491)
        self.assertEqual(len(fn_xml["return_instruction_addresses"]), 19)
        self.assertIn("112c5807", fn_xml["return_instruction_addresses"])
        self.assertIn("112c69d2", fn_xml["return_instruction_addresses"])

    def test_layer33_folder_tree_and_switch_contracts(self):
        ev33 = self.registry["rea_layer33_evidence"]
        self.assertEqual(ev33["closed_evidence_records"], 455)
        self.assertEqual(ev33["new_evidence_records"], 32)
        self.assertEqual(ev33["retained_operation_envelopes"], 32)
        self.assertEqual(ev33["reused_layer32_evidence_records"], 423)
        self.assertEqual(ev33["cumulative_validated_bundle_records"], 822)
        self.assertEqual(ev33["non_proc_slots"], [])
        self.assertEqual(ev33["resource_constrained_slots"], [])

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        by_g = {item["address"]: item for item in self.registry["globals"]}
        for addr in [
            "112aa800", "112cbff0", "112d6a10", "112da2d0", "112dc5e0", "112e4050",
            "1011f7c0", "1011fd40", "1011fea0", "10120e10", "10122760", "10122830",
            "10126e50", "10126f40", "10126f60", "10126fa0", "10127010", "10127390",
            "10127510", "10127900", "10127c00", "1012db60", "10103ec0", "1011f6e0",
            "100fce00", "100f0a80", "100f26b0", "100f2750",
        ]:
            self.assertIn(addr, by_fn)

        fn_sw = by_fn["112e4050"]
        self.assertEqual(fn_sw["bytes"], 311)
        self.assertEqual(fn_sw["calling_convention"], "cdecl")
        self.assertEqual(fn_sw["stack_argument_bytes"], 8)
        self.assertEqual(fn_sw["return_instruction_addresses"], ["112e4186"])
        self.assertEqual(by_fn["10126e50"]["bytes"], 234)
        self.assertEqual(by_fn["10127390"]["bytes"], 377)
        self.assertEqual(by_fn["10120e10"]["bytes"], 855)
        self.assertEqual(by_fn["10122830"]["bytes"], 790)
        self.assertEqual(by_fn["10103ec0"]["bytes"], 380)
        self.assertEqual(by_fn["100fce00"]["bytes"], 76)
        self.assertEqual(by_fn["100f0a80"]["bytes"], 987)
        self.assertEqual(by_g["1172f198"]["width"], 4)
        self.assertEqual(by_g["112e4188"]["width"], 52)
        self.assertEqual(by_g["11745c54"]["width"], 4)

    def test_layer34_leaf_codec_and_dlmalloc_contracts(self):
        ev34 = self.registry["rea_layer34_evidence"]
        self.assertEqual(ev34["closed_evidence_records"], 481)
        self.assertEqual(ev34["new_evidence_records"], 26)
        self.assertEqual(ev34["retained_operation_envelopes"], 26)
        self.assertEqual(ev34["reused_layer33_evidence_records"], 455)
        self.assertEqual(ev34["cumulative_validated_bundle_records"], 848)
        self.assertEqual(ev34["non_proc_slots"], [])
        self.assertEqual(ev34["resource_constrained_slots"], [])

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        by_g = {item["address"]: item for item in self.registry["globals"]}
        for addr in [
            "100f11b0", "100f1b40", "100f21c0", "100f27f0", "100f29b0",
            "100f2b20", "100f31e0", "100f3260", "101021b0", "10102310",
            "101030d0", "10103450", "10113760", "10114290", "10114420",
            "101145e0", "10115050", "101153c0", "10124e50", "101254a0",
        ]:
            self.assertIn(addr, by_fn)

        self.assertEqual(by_fn["10124e50"]["bytes"], 1613)
        self.assertEqual(by_fn["101254a0"]["bytes"], 724)
        fn_e1 = by_fn["101021b0"]
        self.assertEqual(fn_e1["bytes"], 120)
        self.assertEqual(len(fn_e1["return_instruction_addresses"]), 12)
        self.assertIn("101021d4", fn_e1["return_instruction_addresses"])
        self.assertIn("10102227", fn_e1["return_instruction_addresses"])
        fn_e2 = by_fn["101030d0"]
        self.assertEqual(fn_e2["bytes"], 111)
        self.assertEqual(len(fn_e2["return_instruction_addresses"]), 11)
        self.assertIn("101030f4", fn_e2["return_instruction_addresses"])
        self.assertIn("1010313e", fn_e2["return_instruction_addresses"])
        self.assertEqual(by_fn["10114420"]["stack_argument_bytes"], 28)
        self.assertEqual(by_fn["101145e0"]["stack_argument_bytes"], 12)
        self.assertEqual(by_fn["10115050"]["stack_argument_bytes"], 16)
        self.assertEqual(by_fn["10103450"]["stack_argument_bytes"], 4)
        self.assertEqual(by_g["11afa700"]["width"], 448)
        self.assertEqual(by_g["1172f1c8"]["width"], 4)
        self.assertEqual(by_g["1172f284"]["width"], 4)
        self.assertEqual(by_g["1172f760"]["width"], 4)
        self.assertEqual(by_g["10102228"]["width"], 44)

    def test_layer35_codec_vec_and_math_contracts(self):
        ev35 = self.registry["rea_layer35_evidence"]
        self.assertEqual(ev35["closed_evidence_records"], 527)
        self.assertEqual(ev35["new_evidence_records"], 46)
        self.assertEqual(ev35["retained_operation_envelopes"], 46)
        self.assertEqual(ev35["reused_layer34_evidence_records"], 481)
        self.assertEqual(ev35["cumulative_validated_bundle_records"], 894)
        self.assertEqual(ev35["non_proc_slots"], [])
        self.assertEqual(ev35["resource_constrained_slots"], [])

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        by_g = {item["address"]: item for item in self.registry["globals"]}
        for addr in [
            "100ef8f0", "100f1ac0", "100f2ac0", "100f2e60", "100f3330", "100f33b0",
            "100f60b0", "100f6130", "100f61b0", "100fcb80", "10100620", "101007b0",
            "101015c0", "10103220", "101034b0", "10113820", "101207a0", "101216b0",
            "10121bf0", "10122b50", "101278d0", "1016f190", "10179470", "1017ff40",
            "112a53c0", "112ac330", "112bed30", "112bef10", "112d8ae0", "112da050",
            "112e41c0", "112e43f0", "112e4510", "112e4610", "112e47c0", "112e49b0",
        ]:
            self.assertIn(addr, by_fn)

        self.assertEqual(by_fn["100ef8f0"]["bytes"], 140)
        self.assertEqual(by_fn["100f61b0"]["bytes"], 21)
        self.assertEqual(by_fn["100f61b0"]["return_instruction_addresses"], ["100f61be", "100f61c4"])
        self.assertEqual(by_fn["100fcb80"]["stack_argument_bytes"], 28)
        self.assertEqual(by_fn["10100620"]["return_instruction_addresses"], ["10100667", "101006f0"])
        self.assertEqual(by_fn["101007b0"]["bytes"], 484)
        self.assertEqual(by_fn["10103220"]["bytes"], 116)
        self.assertEqual(by_fn["101207a0"]["bytes"], 889)
        self.assertEqual(by_fn["1017ff40"]["bytes"], 98)
        self.assertEqual(by_fn["112bed30"]["bytes"], 473)
        self.assertEqual(by_fn["112d8ae0"]["bytes"], 353)
        self.assertEqual(by_fn["112d8ae0"]["return_instruction_addresses"], ["112d8b2b", "112d8c3e"])
        self.assertEqual(by_fn["112da050"]["bytes"], 626)
        self.assertEqual(by_fn["112e41c0"]["bytes"], 555)
        self.assertEqual(by_fn["112e49b0"]["bytes"], 515)
        self.assertEqual(by_g["1172f158"]["width"], 4)
        self.assertEqual(by_g["1174108c"]["width"], 28)
        self.assertEqual(by_g["11898044"]["width"], 14)
        self.assertEqual(by_g["11898118"]["width"], 16)
        self.assertEqual(by_g["11af4098"]["width"], 64)
        self.assertEqual(by_g["11af40dc"]["width"], 4)

    def test_layer36_dlmalloc_and_stream_contracts(self):
        ev36 = self.registry["rea_layer36_evidence"]
        self.assertEqual(ev36["closed_evidence_records"], 569)
        self.assertEqual(ev36["new_evidence_records"], 42)
        self.assertEqual(ev36["retained_operation_envelopes"], 39)
        self.assertEqual(ev36["reused_layer35_evidence_records"], 527)
        self.assertEqual(ev36["extra_evidence_views_count"], 3)
        self.assertEqual(ev36["cumulative_validated_bundle_records"], 936)
        self.assertEqual(ev36["non_proc_slots"], [])
        self.assertEqual(ev36["resource_constrained_slots"], ["100e10c0"])

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        by_g = {item["address"]: item for item in self.registry["globals"]}
        for addr in [
            "100d1790", "100d2740", "100d3790", "100db960", "100de5e0", "100e10c0",
            "100e3950", "100e77a0", "100eb8a0", "100ec210", "100ec450", "100edd60",
            "100f3150", "100f6f30", "100ffbb0", "10105fa0", "1011f6b0", "10120720",
            "10123640", "10123a90", "10123e00", "10124180", "101242e0", "101246f0",
            "112bb9a0", "112d87a0", "112dbf20", "11346070", "11346d60", "11347190",
            "11348d50", "11349790", "11349f00", "113682d0",
        ]:
            self.assertIn(addr, by_fn)

        self.assertEqual(by_fn["100d1790"]["bytes"], 216)
        self.assertEqual(by_fn["100d1790"]["stack_argument_bytes"], 20)
        self.assertEqual(by_fn["100d2740"]["bytes"], 273)
        self.assertEqual(by_fn["100db960"]["bytes"], 546)
        self.assertEqual(by_fn["100e10c0"]["bytes"], 82)
        self.assertEqual(by_fn["100edd60"]["bytes"], 6)
        self.assertEqual(by_fn["100f6f30"]["bytes"], 146)
        self.assertEqual(by_fn["10123640"]["bytes"], 174)
        self.assertEqual(by_fn["10123a90"]["bytes"], 827)
        self.assertEqual(by_fn["10124180"]["bytes"], 338)
        self.assertEqual(by_fn["101242e0"]["bytes"], 1039)
        self.assertEqual(len(by_fn["101242e0"]["return_instruction_addresses"]), 7)
        self.assertEqual(by_fn["101246f0"]["bytes"], 490)
        self.assertEqual(by_fn["112d87a0"]["bytes"], 581)
        self.assertEqual(by_fn["11348d50"]["bytes"], 842)
        self.assertEqual(by_fn["113682d0"]["bytes"], 215)
        self.assertEqual(by_g["1172f154"]["width"], 4)
        self.assertEqual(by_g["1172f230"]["width"], 4)
        self.assertEqual(by_g["1173dadc"]["width"], 48)
        self.assertEqual(by_g["1173db88"]["width"], 20)
        self.assertEqual(by_g["118a12c4"]["width"], 24)
        self.assertEqual(by_g["119344e8"]["width"], 12)
        self.assertEqual(by_g["11afa6e0"]["width"], 4)
        self.assertEqual(by_g["11afa6e8"]["width"], 20)

    def test_layer37_engine_channel_contracts(self):
        ev37 = self.registry["rea_layer37_evidence"]
        self.assertEqual(ev37["closed_evidence_records"], 592)
        self.assertEqual(ev37["new_evidence_records"], 23)
        self.assertEqual(ev37["retained_operation_envelopes"], 23)
        self.assertEqual(ev37["reused_layer36_evidence_records"], 569)
        self.assertEqual(ev37["extra_evidence_views_count"], 0)
        self.assertEqual(ev37["cumulative_validated_bundle_records"], 959)
        self.assertEqual(ev37["non_proc_slots"], [])
        self.assertEqual(ev37["resource_constrained_slots"], [])

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        by_g = {item["address"]: item for item in self.registry["globals"]}
        for addr in [
            "10238c90", "1036a710", "1039db80", "10524c30", "1075c5a0", "107c9080",
            "107e0650", "108bfc70", "108c0510", "10ca9010", "10cb03c0", "10d82640",
            "10f78370", "10f89bf0", "10fa5da0", "10fd6c90", "10fd74d0", "10fd77f0",
            "10fd7a70", "10fd7b10", "10fd9660", "1103d530",
        ]:
            self.assertIn(addr, by_fn)

        self.assertEqual(by_fn["10238c90"]["bytes"], 232)
        self.assertEqual(by_fn["10238c90"]["stack_argument_bytes"], 16)
        self.assertEqual(by_fn["1039db80"]["bytes"], 47)
        self.assertEqual(by_fn["10524c30"]["bytes"], 80)
        self.assertEqual(by_fn["107c9080"]["bytes"], 116)
        self.assertEqual(by_fn["10cb03c0"]["bytes"], 125)
        self.assertEqual(by_fn["10cb03c0"]["stack_argument_bytes"], 8)
        self.assertEqual(by_fn["10d82640"]["bytes"], 657)
        self.assertEqual(by_fn["10f89bf0"]["bytes"], 264)
        self.assertEqual(by_fn["10fa5da0"]["bytes"], 253)
        self.assertEqual(by_fn["10fa5da0"]["callee_pop_bytes"], 20)
        self.assertEqual(by_fn["10fd6c90"]["bytes"], 232)
        self.assertEqual(by_fn["10fd7b10"]["bytes"], 152)
        self.assertEqual(by_fn["1103d530"]["bytes"], 395)
        self.assertEqual(by_g["1184926c"]["width"], 12)

    def test_layer38_engine_codec_contracts(self):
        ev38 = self.registry["rea_layer38_evidence"]
        self.assertEqual(ev38["closed_evidence_records"], 624)
        self.assertEqual(ev38["new_evidence_records"], 32)
        self.assertEqual(ev38["retained_operation_envelopes"], 32)
        self.assertEqual(ev38["reused_layer37_evidence_records"], 592)
        self.assertEqual(ev38["extra_evidence_views_count"], 0)
        self.assertEqual(ev38["cumulative_validated_bundle_records"], 991)
        self.assertEqual(ev38["non_proc_slots"], [])
        self.assertEqual(ev38["resource_constrained_slots"], [])

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        by_g = {item["address"]: item for item in self.registry["globals"]}
        for addr in [
            "100d26e0", "100de0d0", "100de340", "100f2af0", "100f2b00", "100f5860",
            "101056d0", "10105850", "10114f00", "10114f60", "1011fcf0", "101236f0",
            "10123dd0", "101e3c50", "1055bff0", "10f5f5c0", "10f71eb0", "10f78290",
            "10f80f40", "10fd6850", "10fd7df0", "10fe4780", "113490a0", "11349180",
            "1134a060",
        ]:
            self.assertIn(addr, by_fn)

        self.assertEqual(by_fn["100d26e0"]["bytes"], 96)
        self.assertEqual(by_fn["100de0d0"]["bytes"], 6)
        self.assertEqual(by_fn["100de340"]["bytes"], 216)
        self.assertEqual(by_fn["100de340"]["stack_argument_bytes"], 20)
        self.assertEqual(by_fn["100f5860"]["bytes"], 1243)
        self.assertEqual(by_fn["100f5860"]["stack_argument_bytes"], 32)
        self.assertEqual(by_fn["101056d0"]["bytes"], 375)
        self.assertEqual(by_fn["10105850"]["bytes"], 455)
        self.assertEqual(by_fn["10114f60"]["bytes"], 71)
        self.assertEqual(by_fn["101236f0"]["bytes"], 61)
        self.assertEqual(by_fn["1055bff0"]["bytes"], 125)
        self.assertEqual(by_fn["10f71eb0"]["bytes"], 182)
        self.assertEqual(by_fn["10f78290"]["bytes"], 177)
        self.assertEqual(by_fn["10fd6850"]["bytes"], 180)
        self.assertEqual(by_fn["113490a0"]["bytes"], 54)
        self.assertEqual(by_fn["11349180"]["bytes"], 197)
        self.assertEqual(by_fn["1134a060"]["bytes"], 89)
        self.assertEqual(by_g["1172f94c"]["width"], 4)
        self.assertEqual(by_g["11741dcc"]["width"], 8)
        self.assertEqual(by_g["11745250"]["width"], 82)
        self.assertEqual(by_g["117453c0"]["width"], 16)
        self.assertEqual(by_g["11756480"]["width"], 24)
        self.assertEqual(by_g["11923db4"]["width"], 16)
        self.assertEqual(by_g["119da098"]["width"], 4)
        self.assertEqual(by_g["11af408c"]["width"], 2)

    def test_layer39_engine_net_sys_contracts(self):
        ev = self.registry["rea_layer39_evidence"]
        self.assertEqual(ev["closed_evidence_records"], 655)
        self.assertEqual(ev["new_evidence_records"], 31)
        self.assertEqual(ev["retained_operation_envelopes"], 31)
        self.assertEqual(ev["reused_layer38_evidence_records"], 624)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 1022)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 31)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 24)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 7)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual(by_fn["100e7ff0"]["calling_convention"], "cdecl")
        self.assertEqual(by_fn["10115640"]["calling_convention"], "thiscall")
        self.assertEqual(by_fn["10115640"]["callee_pop_bytes"], 12)
        self.assertEqual(by_fn["100f38b0"]["calling_convention"], "cdecl")
        self.assertEqual(len(by_fn["100f38b0"]["body_ranges"]), 2)
        self.assertEqual(len(by_fn["10123e40"]["body_ranges"]), 3)
        self.assertEqual(len(by_fn["10fb2fb0"]["body_ranges"]), 2)
        self.assertEqual(by_fn["10fb2fb0"]["callee_pop_bytes"], 16)
        self.assertEqual(len(by_fn["10fd6d80"]["body_ranges"]), 3)
        self.assertIn("10fd6e9c", by_fn["10fd6d80"]["return_instruction_addresses"])
        self.assertEqual(by_fn["10fd9500"]["callee_pop_bytes"], 12)
        self.assertEqual(by_fn["10fdf080"]["stack_argument_bytes"], 8)
        self.assertEqual(by_fn["10fe45f0"]["stack_argument_bytes"], 12)
        self.assertEqual(by_g["1172f190"]["width"], 4)
        self.assertEqual(by_g["11744d14"]["width"], 37)
        self.assertEqual(by_g["11744d90"]["width"], 52)
        self.assertEqual(by_g["11745080"]["width"], 44)
        self.assertEqual(by_g["117450ac"]["width"], 45)
        self.assertEqual(by_g["11745cbc"]["width"], 41)
        self.assertEqual(by_g["11923da8"]["width"], 12)
        self.assertEqual(by_g["11924804"]["width"], 16)
        self.assertEqual(by_g["1193447c"]["width"], 4)
        self.assertEqual((by_g["119f3b04"]["width"], by_g["119f3b04"]["storage"]), (16, "zero_fill"))
        self.assertEqual((by_g["119f3b14"]["width"], by_g["119f3b14"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["1201ae48"]["width"], by_g["1201ae48"]["storage"]), (4, "zero_fill"))

    def test_layer40_engine_crt_contracts(self):
        ev = self.registry["rea_layer40_evidence"]
        self.assertEqual(ev["closed_evidence_records"], 695)
        self.assertEqual(ev["new_evidence_records"], 40)
        self.assertEqual(ev["retained_operation_envelopes"], 34)
        self.assertEqual(ev["reused_layer39_evidence_records"], 655)
        self.assertEqual(ev["extra_evidence_views_count"], 6)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 1062)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], ["116838ea", "11683a32"])
        self.assertEqual(len(ev["records"]), 34)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 26)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 8)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual(by_fn["100ee990"]["stack_argument_bytes"], 16)
        self.assertEqual(by_fn["10114740"]["callee_pop_bytes"], 12)
        self.assertEqual(by_fn["10f7c1a0"]["callee_pop_bytes"], 4)
        self.assertEqual(by_fn["10fa7230"]["callee_pop_bytes"], 28)
        self.assertEqual(by_fn["10fdad30"]["calling_convention"], "thiscall")
        self.assertEqual(by_fn["10fdebc0"]["calling_convention"], "thiscall")
        self.assertEqual(by_fn["10fe4980"]["stack_argument_bytes"], 24)
        self.assertEqual(by_fn["1168e713"]["stack_argument_bytes"], 28)
        self.assertEqual(by_fn["1169764e"]["stack_argument_bytes"], 28)
        self.assertEqual(by_fn["1169b63d"]["stack_argument_bytes"], 24)
        self.assertEqual(len(by_fn["1169b820"]["body_ranges"]), 2)
        self.assertEqual(by_fn["116bebf1"]["calling_convention"], "stdcall")
        self.assertEqual(by_fn["116bebf1"]["callee_pop_bytes"], 8)
        self.assertEqual(by_g["1172f304"]["width"], 4)
        self.assertEqual(by_g["1172f7c0"]["width"], 4)
        self.assertEqual(by_g["117452a4"]["width"], 5)
        self.assertEqual(by_g["1190bb30"]["width"], 4)
        self.assertEqual(by_g["11910b10"]["width"], 16)
        self.assertEqual(by_g["11910b50"]["width"], 8)
        self.assertEqual(by_g["1191fd50"]["width"], 32)
        self.assertEqual(by_g["119ebd78"]["width"], 4)
        self.assertEqual(by_g["119ebd90"]["width"], 4)
        self.assertEqual(by_g["119ebda4"]["width"], 4)
        self.assertEqual(by_g["119ebe18"]["width"], 168)
        self.assertEqual((by_g["12125624"]["width"], by_g["12125624"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["1212564c"]["width"], by_g["1212564c"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12125650"]["width"], by_g["12125650"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12125f10"]["width"], by_g["12125f10"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12126c3c"]["width"], by_g["12126c3c"]["storage"]), (4, "zero_fill"))

    def test_layer41_engine_crt_fmt_contracts(self):
        ev = self.registry["rea_layer41_evidence"]
        self.assertEqual(ev["closed_evidence_records"], 743)
        self.assertEqual(ev["new_evidence_records"], 48)
        self.assertEqual(ev["retained_operation_envelopes"], 42)
        self.assertEqual(ev["reused_layer40_evidence_records"], 695)
        self.assertEqual(ev["extra_evidence_views_count"], 6)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 743)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1110)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], ["116839e8", "116bd8d0"])
        self.assertEqual(len(ev["records"]), 42)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 26)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 16)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual(by_fn["100ee800"]["stack_argument_bytes"], 20)
        self.assertEqual(by_fn["100f5d40"]["stack_argument_bytes"], 32)
        self.assertEqual(by_fn["10fba190"]["calling_convention"], "thiscall")
        self.assertEqual(by_fn["10fdec30"]["stack_argument_bytes"], 4)
        self.assertEqual(len(by_fn["116839e8"]["body_ranges"]), 2)
        self.assertEqual(by_fn["116880f7"]["callee_pop_bytes"], 12)
        self.assertEqual(by_fn["1168e69c"]["stack_argument_bytes"], 24)
        self.assertEqual(by_fn["1168f167"]["stack_argument_bytes"], 28)
        self.assertEqual(by_fn["1169b55f"]["calling_convention"], "thiscall")
        self.assertEqual(by_fn["116a8e6d"]["stack_argument_bytes"], 28)
        self.assertEqual(len(by_fn["11699af7"]["body_ranges"]), 2)
        self.assertEqual(len(by_fn["11699b02"]["body_ranges"]), 2)
        self.assertEqual(len(by_fn["116bd8d0"]["body_ranges"]), 12)
        self.assertEqual(len(by_fn["116bde50"]["body_ranges"]), 12)
        self.assertEqual(by_g["117410d4"]["width"], 2)
        self.assertEqual(by_g["11745168"]["width"], 43)
        self.assertEqual(by_g["117452c0"]["width"], 12)
        self.assertEqual(by_g["119152d8"]["width"], 6)
        self.assertEqual(by_g["119ebe10"]["width"], 8)
        self.assertEqual((by_g["12125604"]["width"], by_g["12125604"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12126c38"]["width"], by_g["12126c38"]["storage"]), (4, "zero_fill"))

    def test_layer42_engine_crt_io_contracts(self):
        ev = self.registry["rea_layer42_evidence"]
        self.assertEqual(ev["snapshot_mode"], "fresh_partition_p3")
        self.assertEqual(ev["closed_evidence_records"], 36)
        self.assertEqual(ev["new_evidence_records"], 36)
        self.assertEqual(ev["retained_operation_envelopes"], 36)
        self.assertEqual(ev["reused_layer41_evidence_records"], 0)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 36)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["prior_partitions_validated_records"], 1110)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1146)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 36)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 25)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 11)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["100f17a0"]["calling_convention"], by_fn["100f17a0"]["callee_pop_bytes"]), ("thiscall", 8))
        self.assertEqual(by_fn["11684800"]["bytes"], 31)
        self.assertEqual((by_fn["116849b0"]["bytes"], by_fn["116849b0"]["return_instruction_addresses"]), (70, ["116849f5"]))
        self.assertEqual(by_fn["11687985"]["bytes"], 99)
        self.assertEqual((by_fn["11688f63"]["calling_convention"], by_fn["11688f63"]["callee_pop_bytes"]), ("thiscall", 4))
        self.assertEqual((by_fn["11692dc6"]["stack_argument_bytes"], by_fn["11692dc6"]["callee_pop_bytes"]), (24, 24))
        self.assertEqual(by_fn["11698a9d"]["bytes"], 67)
        self.assertEqual(by_fn["1169941c"]["stack_argument_bytes"], 8)
        self.assertEqual(by_fn["116994a6"]["stack_argument_bytes"], 16)
        self.assertEqual(by_fn["116a1c5d"]["stack_argument_bytes"], 28)
        self.assertEqual(by_fn["116a3ece"]["bytes"], 290)
        self.assertEqual(by_fn["116a4789"]["bytes"], 181)
        self.assertEqual(by_g["1172f320"]["width"], 4)
        self.assertEqual(by_g["119108c8"]["width"], 360)
        self.assertEqual(by_g["119ebf38"]["width"], 4)
        self.assertEqual(by_g["119ebff8"]["width"], 8)
        self.assertEqual((by_g["12125c24"]["width"], by_g["12125c24"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12125d90"]["width"], by_g["12125d90"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12125f14"]["width"], by_g["12125f14"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12126328"]["width"], by_g["12126328"]["storage"]), (4, "zero_fill"))

    def test_layer43_engine_crt_sec_contracts(self):
        ev = self.registry["rea_layer43_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer42")
        self.assertEqual(ev["closed_evidence_records"], 71)
        self.assertEqual(ev["new_evidence_records"], 35)
        self.assertEqual(ev["retained_operation_envelopes"], 35)
        self.assertEqual(ev["reused_layer42_evidence_records"], 36)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 71)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["prior_partitions_validated_records"], 1110)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1181)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 35)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 25)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 10)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["11683dd0"]["bytes"], by_fn["11683dd0"]["return_instruction_addresses"]), (45, ["11683df3"]))
        self.assertEqual((by_fn["11684b3c"]["bytes"], by_fn["11684b3c"]["return_instruction_addresses"]), (17, ["11684b46"]))
        self.assertEqual((by_fn["1168783d"]["bytes"], by_fn["1168783d"]["stack_argument_bytes"]), (313, 12))
        self.assertEqual((by_fn["11688f27"]["calling_convention"], by_fn["11688f27"]["callee_pop_bytes"]), ("thiscall", 24))
        self.assertEqual(by_fn["1168c5c8"]["stack_argument_bytes"], 16)
        self.assertEqual((by_fn["11692cc4"]["calling_convention"], by_fn["11692cc4"]["callee_pop_bytes"]), ("thiscall", 12))
        self.assertEqual(by_fn["11692f4e"]["bytes"], 280)
        self.assertEqual(by_fn["116997f6"]["bytes"], 174)
        self.assertEqual((by_fn["116a17ca"]["calling_convention"], by_fn["116a17ca"]["callee_pop_bytes"]), ("stdcall", 12))
        self.assertEqual(by_fn["116a2028"]["stack_argument_bytes"], 28)
        self.assertEqual(by_fn["116a234d"]["stack_argument_bytes"], 36)
        self.assertEqual(by_fn["116a4434"]["stack_argument_bytes"], 8)
        self.assertEqual(by_g["11910528"]["width"], 120)
        self.assertEqual(by_g["11913748"]["width"], 232)
        self.assertEqual(by_g["11915f18"]["width"], 8)
        self.assertEqual(by_g["119ec210"]["width"], 4)

    def test_layer44_engine_crt_flt_contracts(self):
        ev = self.registry["rea_layer44_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer43")
        self.assertEqual(ev["closed_evidence_records"], 102)
        self.assertEqual(ev["new_evidence_records"], 31)
        self.assertEqual(ev["retained_operation_envelopes"], 31)
        self.assertEqual(ev["reused_layer43_evidence_records"], 71)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 102)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["prior_partitions_validated_records"], 1110)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1212)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 31)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 26)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 5)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["1168499d"]["bytes"], by_fn["1168499d"]["return_instruction_addresses"]), (8, ["116849a4"]))
        self.assertEqual((by_fn["11688ea1"]["calling_convention"], by_fn["11688ea1"]["callee_pop_bytes"]), ("thiscall", 0))
        self.assertEqual((by_fn["1168c7bc"]["calling_convention"], by_fn["1168c7bc"]["callee_pop_bytes"]), ("thiscall", 4))
        self.assertEqual(by_fn["116996a1"]["stack_argument_bytes"], 28)
        self.assertEqual((by_fn["116a4632"]["bytes"], by_fn["116a4632"]["return_instruction_addresses"]), (188, ["116a46e8"]))
        self.assertEqual(by_fn["116a587a"]["bytes"], 179)
        self.assertEqual(by_fn["116a80f2"]["stack_argument_bytes"], 24)
        self.assertEqual((by_fn["116a8723"]["calling_convention"], by_fn["116a8723"]["callee_pop_bytes"]), ("stdcall", 4))
        self.assertEqual((by_fn["116a8762"]["calling_convention"], by_fn["116a8762"]["callee_pop_bytes"]), ("stdcall", 8))
        self.assertEqual(by_fn["116a8dad"]["stack_argument_bytes"], 20)
        self.assertEqual(by_fn["116ab734"]["bytes"], 93)
        self.assertEqual(len(by_fn["116ada8f"]["return_instruction_addresses"]), 3)
        self.assertEqual(by_fn["116b82f0"]["bytes"], 79)
        self.assertEqual((by_fn["116bcc58"]["bytes"], by_fn["116bcc58"]["return_instruction_addresses"]), (20, ["116bcc6b"]))
        self.assertEqual(by_g["1172f0e8"]["width"], 4)
        self.assertEqual(by_g["1172f2b8"]["width"], 4)
        self.assertEqual(by_g["1190c774"]["width"], 12)
        self.assertEqual(by_g["11914c88"]["width"], 8)
        self.assertEqual(by_g["119ec1f0"]["width"], 4)
        self.assertEqual((by_g["12125efc"]["width"], by_g["12125efc"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12126330"]["width"], by_g["12126330"]["storage"]), (4, "zero_fill"))

    def test_layer45_engine_crt_env_contracts(self):
        ev = self.registry["rea_layer45_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer44")
        self.assertEqual(ev["closed_evidence_records"], 134)
        self.assertEqual(ev["new_evidence_records"], 32)
        self.assertEqual(ev["retained_operation_envelopes"], 32)
        self.assertEqual(ev["reused_layer44_evidence_records"], 102)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 134)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["prior_partitions_validated_records"], 1110)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1244)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 32)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 25)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 7)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual(by_fn["11687d0f"]["bytes"], 101)
        self.assertEqual(by_fn["1168c7fb"]["stack_argument_bytes"], 8)
        self.assertEqual((by_fn["116967fd"]["calling_convention"], by_fn["116967fd"]["receiver_register"]), ("thiscall", "ECX"))
        self.assertEqual(len(by_fn["11696ac0"]["return_instruction_addresses"]), 3)
        self.assertEqual((by_fn["11696d09"]["calling_convention"], by_fn["11696d09"]["callee_pop_bytes"]), ("thiscall", 4))
        self.assertEqual(by_fn["11699953"]["bytes"], 211)
        self.assertEqual(by_fn["11699b38"]["bytes"], 164)
        self.assertEqual(by_fn["1169af6a"]["bytes"], 222)
        self.assertEqual(by_fn["116a1825"]["bytes"], 297)
        self.assertEqual((by_fn["116a42c8"]["calling_convention"], by_fn["116a42c8"]["callee_pop_bytes"]), ("stdcall", 12))
        self.assertEqual((by_fn["116a43da"]["calling_convention"], by_fn["116a43da"]["callee_pop_bytes"]), ("stdcall", 12))
        self.assertEqual(by_fn["116a84d2"]["stack_argument_bytes"], 16)
        self.assertEqual(by_fn["116ad990"]["stack_argument_bytes"], 12)
        self.assertEqual((by_fn["116adc01"]["bytes"], by_fn["116adc01"]["return_instruction_addresses"]), (16, ["116adc10"]))
        self.assertEqual(by_g["1172f164"]["width"], 4)
        self.assertEqual(by_g["1172f318"]["width"], 4)
        self.assertEqual(by_g["11914c40"]["width"], 4)
        self.assertEqual(by_g["11914c44"]["width"], 16)
        self.assertEqual(by_g["11915f38"]["width"], 10)
        self.assertEqual(by_g["119ebf40"]["width"], 4)
        self.assertEqual((by_g["12125da8"]["width"], by_g["12125da8"]["storage"]), (24, "zero_fill"))
        self.assertEqual((by_g["12126170"]["width"], by_g["12126170"]["storage"]), (4, "zero_fill"))

    def test_layer46_engine_crt_fenv_contracts(self):
        ev = self.registry["rea_layer46_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer45")
        self.assertEqual(ev["closed_evidence_records"], 169)
        self.assertEqual(ev["new_evidence_records"], 35)
        self.assertEqual(ev["retained_operation_envelopes"], 35)
        self.assertEqual(ev["reused_layer45_evidence_records"], 134)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 169)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["prior_partitions_validated_records"], 1110)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1279)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 35)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 28)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 7)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["1168781e"]["bytes"], by_fn["1168781e"]["calling_convention"]), (31, "cdecl"))
        self.assertEqual((by_fn["1168bf06"]["stack_argument_bytes"], len(by_fn["1168bf06"]["return_instruction_addresses"])), (12, 2))
        self.assertEqual(len(by_fn["11699a26"]["return_instruction_addresses"]), 2)
        self.assertEqual(len(by_fn["11699b0d"]["return_instruction_addresses"]), 2)
        self.assertEqual(by_fn["1169dedd"]["stack_argument_bytes"], 12)
        self.assertEqual(by_fn["1169e117"]["bytes"], 54)
        self.assertEqual(by_fn["116a2525"]["bytes"], 23)
        self.assertEqual(by_fn["116a2553"]["bytes"], 36)
        self.assertEqual(by_fn["116a45bb"]["bytes"], 75)
        self.assertEqual(by_fn["116a840b"]["bytes"], 199)
        self.assertEqual(by_fn["116ada62"]["stack_argument_bytes"], 12)
        self.assertEqual(by_fn["116ae4c4"]["bytes"], 78)
        self.assertEqual(by_fn["116b56c7"]["bytes"], 109)
        self.assertEqual((by_fn["116b6038"]["bytes"], len(by_fn["116b6038"]["return_instruction_addresses"])), (86, 2))
        self.assertEqual(by_fn["116b8348"]["bytes"], 184)
        self.assertEqual(
            (by_fn["116b89d3"]["bytes"], by_fn["116b8a53"]["bytes"], by_fn["116b8b0b"]["bytes"], by_fn["116b8b73"]["bytes"]),
            (128, 184, 104, 247),
        )
        self.assertEqual((by_fn["116be8d3"]["bytes"], by_fn["116be8d3"]["return_instruction_addresses"]), (162, ["116be974"]))
        self.assertEqual(by_g["1172f0e4"]["width"], 4)
        self.assertEqual(by_g["11914720"]["width"], 4)
        self.assertEqual(by_g["11914c20"]["width"], 16)
        self.assertEqual(by_g["11916390"]["width"], 10)
        self.assertEqual(by_g["1191b38a"]["width"], 10)
        self.assertEqual(by_g["1191b3e8"]["width"], 2)
        self.assertEqual((by_g["12125f18"]["width"], by_g["12125f18"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12126118"]["width"], by_g["12126118"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12126120"]["width"], by_g["12126120"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12126334"]["width"], by_g["12126334"]["storage"]), (4, "zero_fill"))

    def test_layer47_engine_crt_strtox_contracts(self):
        ev = self.registry["rea_layer47_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer46")
        self.assertEqual(ev["closed_evidence_records"], 206)
        self.assertEqual(ev["new_evidence_records"], 37)
        self.assertEqual(ev["retained_operation_envelopes"], 37)
        self.assertEqual(ev["reused_layer46_evidence_records"], 169)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 206)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["prior_partitions_validated_records"], 1110)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1316)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 37)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 27)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 10)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["1168dc34"]["bytes"], by_fn["1168dc34"]["stack_argument_bytes"]), (678, 20))
        self.assertEqual(by_fn["1169de44"]["bytes"], 27)
        self.assertEqual(by_fn["116b1986"]["bytes"], 105)
        self.assertEqual(by_fn["116b5824"]["bytes"], 80)
        self.assertEqual(by_fn["116b5d1b"]["bytes"], 328)
        self.assertEqual(
            (by_fn["116b86a4"]["bytes"], by_fn["116b8760"]["bytes"], by_fn["116b8819"]["bytes"], by_fn["116b88e6"]["bytes"]),
            (188, 185, 205, 203),
        )
        self.assertEqual((by_fn["11683e00"]["bytes"], len(by_fn["11683e00"]["body_ranges"])), (145, 2))
        self.assertEqual((by_fn["11689985"]["bytes"], by_fn["11689985"]["calling_convention"], by_fn["11689985"]["receiver_register"]), (249, "thiscall", "ECX"))
        self.assertEqual((by_fn["11695540"]["bytes"], len(by_fn["11695540"]["body_ranges"]), len(by_fn["11695540"]["return_instruction_addresses"])), (1170, 2, 5))
        self.assertEqual((by_fn["11696308"]["bytes"], len(by_fn["11696308"]["body_ranges"])), (149, 3))
        self.assertEqual((by_fn["11696528"]["bytes"], len(by_fn["11696528"]["body_ranges"])), (680, 2))
        self.assertEqual((by_fn["116a511c"]["bytes"], len(by_fn["116a511c"]["body_ranges"])), (228, 2))
        self.assertEqual((by_fn["116ade23"]["bytes"], len(by_fn["116ade23"]["body_ranges"]), by_fn["116ade23"]["return_instruction_addresses"]), (474, 2, ["116addd2"]))
        self.assertEqual((by_fn["116ae58e"]["bytes"], len(by_fn["116ae58e"]["body_ranges"]), len(by_fn["116ae58e"]["return_instruction_addresses"])), (134, 2, 3))
        self.assertEqual((by_fn["116b4b50"]["bytes"], len(by_fn["116b4b50"]["body_ranges"]), by_fn["116b4b50"]["return_instruction_addresses"]), (148, 2, ["116b4be9"]))
        self.assertEqual((by_fn["116b5f67"]["bytes"], len(by_fn["116b5f67"]["body_ranges"]), by_fn["116b5f67"]["return_instruction_addresses"]), (117, 2, ["116b5fe1"]))
        self.assertEqual(by_g["1172f0ac"]["width"], 4)
        self.assertEqual(by_g["1172f10c"]["width"], 4)
        self.assertEqual(by_g["119146b0"]["width"], 52)
        self.assertEqual(by_g["1191b3e0"]["width"], 8)
        self.assertEqual(by_g["119258d0"]["width"], 16)
        self.assertEqual(by_g["119ebed0"]["width"], 4)
        self.assertEqual(by_g["119ec000"]["width"], 4)
        self.assertEqual((by_g["1212632c"]["width"], by_g["1212632c"]["storage"]), (4, "zero_fill"))

    def test_layer48_engine_crt_printf_contracts(self):
        ev = self.registry["rea_layer48_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer47")
        self.assertEqual(ev["closed_evidence_records"], 234)
        self.assertEqual(ev["new_evidence_records"], 28)
        self.assertEqual(ev["retained_operation_envelopes"], 28)
        self.assertEqual(ev["reused_layer47_evidence_records"], 206)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 234)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["prior_partitions_validated_records"], 1110)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1344)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 28)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 26)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 2)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["116842e0"]["bytes"], by_fn["116842e0"]["calling_convention"], by_fn["116842e0"]["callee_pop_bytes"]), (149, "stdcall", 16))
        self.assertEqual((by_fn["1168934e"]["bytes"], by_fn["1168934e"]["calling_convention"], by_fn["1168934e"]["callee_pop_bytes"]), (63, "stdcall", 8))
        self.assertEqual((by_fn["11689d22"]["bytes"], by_fn["11689d22"]["calling_convention"], by_fn["11689d22"]["receiver_register"]), (61, "thiscall", "ECX"))
        self.assertEqual((by_fn["1168e5ab"]["bytes"], by_fn["1168e5ab"]["callee_pop_bytes"]), (41, 4))
        self.assertEqual((by_fn["11696278"]["bytes"], by_fn["11696278"]["callee_pop_bytes"]), (78, 4))
        self.assertEqual(by_fn["116a51db"]["bytes"], 8)
        self.assertEqual(by_fn["116a8ce2"]["bytes"], 203)
        self.assertEqual(by_fn["116adde0"]["bytes"], 67)
        self.assertEqual(by_fn["116ae1c9"]["bytes"], 105)
        self.assertEqual(by_fn["116ae232"]["bytes"], 105)
        self.assertEqual((by_fn["116ae454"]["bytes"], by_fn["116ae454"]["receiver_register"]), (82, "ECX"))
        self.assertEqual(by_fn["116ae5d7"]["bytes"], 184)
        self.assertEqual(
            (by_fn["116afb58"]["bytes"], by_fn["116afb84"]["bytes"], by_fn["116afbb0"]["bytes"]),
            (44, 44, 44),
        )
        self.assertEqual(by_g["1172f0c0"]["width"], 4)
        self.assertEqual(by_g["1190ec70"]["width"], 91)
        self.assertEqual((by_g["12126200"]["width"], by_g["12126200"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12126204"]["width"], by_g["12126204"]["storage"]), (4, "zero_fill"))
        self.assertEqual((by_g["12126208"]["width"], by_g["12126208"]["storage"]), (4, "zero_fill"))

    def test_layer49_crt_lconv_time_write_and_matherr_contracts(self) -> None:
        ev = self.registry["rea_layer49_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer48")
        self.assertEqual(ev["closed_evidence_records"], 264)
        self.assertEqual(ev["new_evidence_records"], 30)
        self.assertEqual(ev["retained_operation_envelopes"], 30)
        self.assertEqual(ev["reused_layer48_evidence_records"], 234)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 264)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["prior_partitions_validated_records"], 1110)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1374)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 30)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 22)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 8)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["1168949f"]["bytes"], by_fn["1168949f"]["calling_convention"], by_fn["1168949f"]["callee_pop_bytes"]), (118, "thiscall", 4))
        self.assertEqual((by_fn["11689e3f"]["bytes"], by_fn["11689e3f"]["receiver_register"]), (42, "ECX"))
        self.assertEqual(by_fn["1168a992"]["bytes"], 613)
        self.assertEqual((by_fn["1168c795"]["bytes"], by_fn["1168c795"]["callee_pop_bytes"]), (39, 4))
        self.assertEqual((by_fn["116a520e"]["bytes"], by_fn["116a520e"]["stack_argument_bytes"]), (482, 12))
        self.assertEqual((by_fn["116ae3a6"]["bytes"], by_fn["116ae3a6"]["callee_pop_bytes"]), (63, 4))
        self.assertEqual(by_fn["116ae54f"]["bytes"], 63)
        self.assertEqual(by_fn["116ae892"]["bytes"], 35)
        self.assertEqual((by_fn["116b034a"]["bytes"], by_fn["116b03a7"]["bytes"]), (84, 72))
        self.assertEqual((by_fn["116b4bcf"]["bytes"], by_fn["116b5877"]["bytes"], by_fn["116b5fc7"]["bytes"]), (9, 9, 9))
        self.assertEqual((by_fn["116b5b9b"]["bytes"], by_fn["116b5b9b"]["stack_argument_bytes"]), (259, 28))
        self.assertEqual((by_fn["116b5e63"]["bytes"], by_fn["116b5e8c"]["bytes"], by_fn["116b5ebd"]["bytes"]), (41, 49, 41))
        self.assertEqual(by_fn["116b5fe8"]["bytes"], 80)
        self.assertEqual((by_fn["116b60c7"]["bytes"], by_fn["116b657c"]["bytes"]), (254, 105))
        self.assertEqual(by_fn["116bc61a"]["bytes"], 28)
        self.assertEqual((by_fn["116bcfc0"]["bytes"], by_fn["116bcfc0"]["stack_argument_bytes"]), (266, 12))
        self.assertEqual((by_g["1172f2dc"]["width"], by_g["1172f33c"]["width"]), (4, 4))
        self.assertEqual((by_g["11913ef2"]["width"], by_g["119142f8"]["width"]), (512, 180))
        self.assertEqual((by_g["119ebed4"]["width"], by_g["119ebf1c"]["width"]), (4, 4))
        self.assertEqual((by_g["121262cc"]["width"], by_g["121262cc"]["storage"]), (4, "zero_fill"))

    def test_layer50_crt_wprintf_types_lowio_text_and_dst_contracts(self) -> None:
        ev = self.registry["rea_layer50_evidence"]
        self.assertEqual(ev["snapshot_mode"], "fresh_partition_p4")
        self.assertEqual(ev["closed_evidence_records"], 38)
        self.assertEqual(ev["new_evidence_records"], 38)
        self.assertEqual(ev["retained_operation_envelopes"], 38)
        self.assertEqual(ev["reused_layer49_evidence_records"], 0)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 38)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["prior_partitions_validated_records"], 1374)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1412)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 38)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 30)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 8)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["1168750e"]["bytes"], by_fn["11688dbf"]["bytes"]), (30, 64))
        self.assertEqual((by_fn["1168af61"]["bytes"], by_fn["1168b10a"]["bytes"]), (90, 357))
        self.assertEqual((by_fn["1168b2ff"]["bytes"], by_fn["1168b2ff"]["callee_pop_bytes"]), (150, 4))
        self.assertEqual((by_fn["1168b4e6"]["bytes"], by_fn["1168b4e6"]["callee_pop_bytes"]), (341, 8))
        self.assertEqual((by_fn["1168b63b"]["bytes"], by_fn["1168b6ce"]["bytes"], by_fn["1168b705"]["bytes"]), (116, 31, 24))
        self.assertEqual((by_fn["1168b78e"]["bytes"], by_fn["1168b9ea"]["callee_pop_bytes"], by_fn["1168bb71"]["callee_pop_bytes"]), (115, 4, 4))
        self.assertEqual((by_fn["1169df07"]["bytes"], by_fn["1169e7f6"]["bytes"], by_fn["116a2005"]["bytes"]), (42, 27, 35))
        self.assertEqual((by_fn["116a49a3"]["bytes"], by_fn["116a4d4d"]["bytes"], by_fn["116a4db5"]["bytes"]), (938, 104, 113))
        self.assertEqual((by_fn["116a4e26"]["bytes"], by_fn["116a4f01"]["bytes"], by_fn["116a4fea"]["bytes"]), (219, 233, 306))
        self.assertEqual((by_fn["116ae350"]["bytes"], by_fn["116ae3e5"]["bytes"]), (26, 31))
        self.assertEqual((by_fn["116afbdc"]["bytes"], by_fn["116b026c"]["bytes"]), (537, 222))
        self.assertEqual((by_fn["116b039e"]["bytes"], by_fn["116b03f2"]["bytes"], by_fn["116b6aa8"]["bytes"]), (9, 9, 228))
        self.assertEqual((by_fn["116bc428"]["bytes"], by_fn["116bc636"]["bytes"]), (346, 162))
        self.assertEqual((by_g["1172f0f0"]["width"], by_g["1172f0f4"]["width"]), (4, 4))
        self.assertEqual((by_g["11846d30"]["width"], by_g["1190ed2c"]["width"], by_g["11915f50"]["width"]), (7, 14, 3))
        self.assertEqual((by_g["119ec040"]["width"], by_g["119ec1d0"]["width"], by_g["119ec1dc"]["width"]), (256, 12, 12))
        self.assertEqual((by_g["12126218"]["storage"], by_g["12126264"]["width"], by_g["121262b8"]["width"]), ("zero_fill", 16, 16))

    def test_layer51_crt_fpfmt_utf8_and_tz_contracts(self) -> None:
        ev = self.registry["rea_layer51_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer50")
        self.assertEqual(ev["closed_evidence_records"], 69)
        self.assertEqual(ev["new_evidence_records"], 31)
        self.assertEqual(ev["retained_operation_envelopes"], 31)
        self.assertEqual(ev["reused_layer50_evidence_records"], 38)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 69)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["prior_partitions_validated_records"], 1374)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1443)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 31)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 27)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 4)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["11688991"]["bytes"], by_fn["116889c2"]["callee_pop_bytes"], by_fn["11688a3f"]["callee_pop_bytes"]), (24, 4, 4))
        self.assertEqual((by_fn["11688aee"]["bytes"], by_fn["11688b3c"]["bytes"]), (78, 30))
        self.assertEqual((by_fn["11688bcd"]["callee_pop_bytes"], by_fn["11688ce2"]["callee_pop_bytes"]), (12, 16))
        self.assertEqual((by_fn["11689271"]["bytes"], by_fn["116893cf"]["bytes"], by_fn["1168b801"]["callee_pop_bytes"]), (96, 92, 8))
        self.assertEqual((by_fn["1168d62c"]["bytes"], by_fn["1169d3f9"]["bytes"], by_fn["1169e75f"]["bytes"]), (1544, 251, 124))
        self.assertEqual((by_fn["116a4118"]["bytes"], by_fn["116a59ef"]["bytes"], by_fn["116a5b31"]["bytes"]), (432, 322, 26))
        self.assertEqual((by_fn["116a6568"]["bytes"], by_fn["116a66d3"]["bytes"], by_fn["116a67fc"]["bytes"]), (315, 297, 21))
        self.assertEqual((by_fn["116a816e"]["bytes"], by_fn["116afdf6"]["bytes"]), (173, 319))
        self.assertEqual((by_fn["116aff36"]["bytes"], by_fn["116b0111"]["bytes"]), (474, 346))
        self.assertEqual((by_fn["116b608e"]["bytes"], by_fn["116b67f4"]["bytes"], by_fn["116bc582"]["bytes"], by_fn["116bd871"]["bytes"]), (50, 56, 124, 62))
        self.assertEqual((by_g["1172f0b4"]["width"], by_g["1172f2bc"]["width"]), (4, 4))
        self.assertEqual((by_g["119146e4"]["width"], by_g["119ec008"]["width"]), (56, 56))
        self.assertEqual((by_g["12125f04"]["storage"], by_g["12125f08"]["storage"], by_g["12125f0c"]["storage"]), ("zero_fill", "zero_fill", "zero_fill"))
        self.assertEqual((by_g["12126210"]["width"], by_g["12126220"]["width"], by_g["12126224"]["width"]), (4, 4, 64))
        self.assertEqual((by_g["12126274"]["width"], by_g["12126278"]["width"], by_g["121262c8"]["width"]), (4, 64, 4))

    def test_layer52_crt_utf8_fp_and_lowio_contracts(self) -> None:
        ev = self.registry["rea_layer52_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer51")
        self.assertEqual(ev["closed_evidence_records"], 102)
        self.assertEqual(ev["new_evidence_records"], 33)
        self.assertEqual(ev["retained_operation_envelopes"], 33)
        self.assertEqual(ev["reused_layer51_evidence_records"], 69)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 102)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["prior_partitions_validated_records"], 1374)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1476)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 33)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 28)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 5)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["116889a9"]["bytes"], by_fn["11689010"]["callee_pop_bytes"], by_fn["1168d395"]["bytes"]), (25, 4, 49))
        self.assertEqual((by_fn["1168e5d4"]["callee_pop_bytes"], by_fn["1168e679"]["bytes"]), (4, 35))
        self.assertEqual((by_fn["1169d38d"]["callee_pop_bytes"], by_fn["1169d3b9"]["bytes"], by_fn["1169e514"]["bytes"]), (4, 64, 41))
        self.assertEqual((by_fn["116a25d6"]["bytes"], by_fn["116a5ca6"]["bytes"]), (37, 29))
        self.assertEqual((by_fn["116a5d7f"]["bytes"], by_fn["116a6098"]["bytes"], by_fn["116a6282"]["bytes"], by_fn["116a63de"]["bytes"], by_fn["116a649f"]["bytes"]), (793, 162, 139, 193, 148))
        self.assertEqual((by_fn["116a66a3"]["bytes"], by_fn["116a8a30"]["callee_pop_bytes"], by_fn["116a8c79"]["bytes"]), (48, 36, 105))
        self.assertEqual((by_fn["116aea59"]["bytes"], by_fn["116afb0a"]["bytes"], by_fn["116afb0a"]["body_ranges"]), (106, 190, [{"start": "116afa57", "end": "116afb14"}]))
        self.assertEqual((by_fn["116afb40"]["bytes"], by_fn["116afb46"]["bytes"], by_fn["116afb4c"]["bytes"], by_fn["116afb52"]["bytes"]), (6, 6, 6, 6))
        self.assertEqual((by_fn["116b1572"]["bytes"], by_fn["116b15ac"]["bytes"], by_fn["116bd4f2"]["bytes"], by_fn["116bd528"]["bytes"]), (58, 423, 31, 85))
        self.assertEqual((by_g["1172f114"]["width"], by_g["1172f344"]["width"]), (4, 4))
        self.assertEqual((by_g["11914110"]["width"], by_g["119ebf34"]["width"], by_g["119ec730"]["width"]), (64, 4, 4))
        self.assertEqual((by_g["1212620c"]["width"], by_g["1212620c"]["storage"], by_g["121262ec"]["width"], by_g["121262ec"]["storage"]), (4, "zero_fill", 8, "zero_fill"))

    def test_layer53_crt_fls_switch_and_div_contracts(self) -> None:
        ev = self.registry["rea_layer53_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer52")
        self.assertEqual(ev["closed_evidence_records"], 127)
        self.assertEqual(ev["new_evidence_records"], 25)
        self.assertEqual(ev["retained_operation_envelopes"], 25)
        self.assertEqual(ev["reused_layer52_evidence_records"], 102)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 127)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["prior_partitions_validated_records"], 1374)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1501)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 25)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 19)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 6)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["116847e0"]["bytes"], by_fn["1168aeb3"]["bytes"], by_fn["1168d407"]["bytes"]), (31, 49, 549))
        self.assertEqual((by_fn["1168bcc3"]["bytes"], by_fn["1168bcc3"]["callee_pop_bytes"], by_fn["1168bcc3"]["body_ranges"]), (205, 16, [{"start": "1168bcc3", "end": "1168bcee"}, {"start": "1168be65", "end": "1168bf05"}]))
        self.assertEqual((by_fn["11695ee2"]["bytes"], by_fn["11695ee2"]["calling_convention"]), (76, "thiscall"))
        self.assertEqual((by_fn["1169ecd8"]["bytes"], by_fn["1169ecd8"]["body_ranges"]), (94, [{"start": "1169ea89", "end": "1169eadb"}, {"start": "1169ecd8", "end": "1169ece2"}]))
        self.assertEqual((by_fn["116a5864"]["bytes"], by_fn["116a5864"]["body_ranges"]), (288, [{"start": "116a5417", "end": "116a552b"}, {"start": "116a5864", "end": "116a586e"}]))
        self.assertEqual((by_fn["116a586f"]["bytes"], by_fn["116a586f"]["body_ranges"]), (292, [{"start": "116a552c", "end": "116a5644"}, {"start": "116a586f", "end": "116a5879"}]))
        self.assertEqual((by_fn["116a5b4b"]["bytes"], by_fn["116a613a"]["bytes"], by_fn["116a630d"]["bytes"]), (347, 327, 209))
        self.assertEqual((by_fn["116a83bd"]["bytes"], by_fn["116a8a8d"]["callee_pop_bytes"], by_fn["116a8a8d"]["bytes"]), (26, 8, 49))
        self.assertEqual((by_fn["116b149d"]["bytes"], by_fn["116b8215"]["bytes"], by_fn["116bd4d3"]["bytes"], by_fn["116bd511"]["bytes"]), (31, 25, 31, 23))
        self.assertEqual((by_fn["116bf330"]["bytes"], by_fn["116d7120"]["bytes"], by_fn["116d7120"]["callee_pop_bytes"]), (311, 223, 16))
        self.assertEqual((by_g["1190ca98"]["width"], by_g["11914190"]["width"]), (14, 6))
        self.assertEqual((by_g["11914d60"]["width"], by_g["11914d68"]["width"], by_g["1191ec20"]["width"], by_g["119256b0"]["width"]), (8, 8, 16, 16))

    def test_layer54_crt_scanf_stdio_and_c32rtomb_contracts(self) -> None:
        ev = self.registry["rea_layer54_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer53")
        self.assertEqual(ev["closed_evidence_records"], 153)
        self.assertEqual(ev["new_evidence_records"], 26)
        self.assertEqual(ev["retained_operation_envelopes"], 26)
        self.assertEqual(ev["reused_layer53_evidence_records"], 127)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 153)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["prior_partitions_validated_records"], 1374)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1527)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 26)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 21)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 5)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["1168f338"]["bytes"], by_fn["11691750"]["bytes"], by_fn["11695bf3"]["bytes"]), (30, 702, 65))
        self.assertEqual((by_fn["116923d9"]["callee_pop_bytes"], by_fn["116923d9"]["bytes"], by_fn["11692817"]["callee_pop_bytes"], by_fn["11692817"]["bytes"]), (8, 349, 8, 359))
        self.assertEqual((by_fn["116960bc"]["callee_pop_bytes"], by_fn["116960bc"]["bytes"], by_fn["116963d4"]["callee_pop_bytes"], by_fn["116963d4"]["bytes"]), (8, 98, 4, 72))
        self.assertEqual((by_fn["116974ef"]["callee_pop_bytes"], by_fn["116974ef"]["bytes"], by_fn["1169e7db"]["bytes"]), (8, 110, 27))
        self.assertEqual((by_fn["1169e998"]["bytes"], by_fn["1169eadf"]["bytes"], by_fn["1169eb47"]["bytes"]), (109, 9, 165))
        self.assertEqual((by_fn["116a5645"]["bytes"], by_fn["116a5711"]["bytes"], by_fn["116a57df"]["bytes"], by_fn["116a6534"]["bytes"]), (204, 206, 133, 52))
        self.assertEqual((by_fn["116a83d7"]["bytes"], by_fn["116b14bc"]["bytes"], by_fn["116b1c0d"]["bytes"]), (26, 171, 89))
        self.assertEqual((by_fn["116b80ef"]["bytes"], by_fn["116b81e9"]["bytes"]), (80, 44))
        self.assertEqual((by_g["1172f1bc"]["width"], by_g["11914d84"]["width"], by_g["11914d8c"]["width"]), (4, 8, 17))
        self.assertEqual((by_g["1191c408"]["width"], by_g["1191cb28"]["width"]), (64, 64))

    def test_layer55_crt_envinit_lseek_and_scanf_helper_contracts(self) -> None:
        ev = self.registry["rea_layer55_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer54")
        self.assertEqual(ev["closed_evidence_records"], 181)
        self.assertEqual(ev["new_evidence_records"], 28)
        self.assertEqual(ev["retained_operation_envelopes"], 28)
        self.assertEqual(ev["reused_layer54_evidence_records"], 153)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 181)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["prior_partitions_validated_records"], 1374)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1555)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 28)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 23)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 5)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["11692d4c"]["callee_pop_bytes"], by_fn["11692d4c"]["bytes"], by_fn["11695a17"]["bytes"]), (16, 49, 55))
        self.assertEqual((by_fn["11695b59"]["callee_pop_bytes"], by_fn["11695b59"]["bytes"], by_fn["11696503"]["callee_pop_bytes"], by_fn["11696503"]["bytes"]), (8, 80, 8, 37))
        self.assertEqual((by_fn["11697107"]["bytes"], by_fn["1169712a"]["bytes"]), (35, 49))
        self.assertEqual((by_fn["116971c4"]["callee_pop_bytes"], by_fn["116971c4"]["bytes"], by_fn["116972d5"]["bytes"]), (4, 71, 33))
        self.assertEqual((by_fn["1169738e"]["callee_pop_bytes"], by_fn["1169738e"]["bytes"]), (20, 109))
        self.assertEqual((by_fn["1169e653"]["bytes"], by_fn["1169e653"]["body_ranges"], by_fn["1169e728"]["bytes"]), (251, [{"start": "1169e653", "end": "1169e71e"}, {"start": "1169e730", "end": "1169e75e"}], 8))
        self.assertEqual((by_fn["116a131d"]["bytes"], by_fn["116a13be"]["bytes"], by_fn["116a159b"]["bytes"], by_fn["116a15ca"]["bytes"]), (83, 207, 47, 131))
        self.assertEqual((by_fn["116a1729"]["bytes"], by_fn["116a1729"]["body_ranges"]), (49, [{"start": "116a12c5", "end": "116a12f0"}, {"start": "116a1729", "end": "116a172d"}]))
        self.assertEqual((by_fn["116b1b1c"]["bytes"], by_fn["116b1b45"]["bytes"], by_fn["116b1ef1"]["bytes"]), (41, 200, 70))
        self.assertEqual((by_fn["116b4bf0"]["bytes"], by_fn["116b4ec6"]["bytes"], by_fn["116b4efd"]["bytes"], by_fn["116b8400"]["bytes"]), (72, 55, 132, 79))
        self.assertEqual((by_g["1172f104"]["width"], by_g["1172f108"]["width"], by_g["11925670"]["width"]), (4, 4, 16))
        self.assertEqual((by_g["119ec430"]["width"], by_g["119ec538"]["width"], by_g["1212630c"]["width"]), (257, 256, 1))
        self.assertEqual((by_g["12125d80"]["width"], by_g["12125d84"]["width"], by_g["12125d8c"]["width"], by_g["121262fc"]["width"], by_g["12126300"]["width"]), (4, 4, 4, 4, 4))

    def test_layer56_crt_mbcp_setenv_and_closure_contracts(self) -> None:
        ev = self.registry["rea_layer56_evidence"]
        self.assertEqual(ev["snapshot_mode"], "fresh_partition_p5")
        self.assertEqual(ev["closed_evidence_records"], 36)
        self.assertEqual(ev["new_evidence_records"], 36)
        self.assertEqual(ev["retained_operation_envelopes"], 36)
        self.assertEqual(ev["reused_layer55_evidence_records"], 0)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 36)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["partition4_validated_bundle_records"], 181)
        self.assertEqual(ev["prior_partitions_validated_records"], 1555)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1591)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 36)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 23)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 13)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["116a2c97"]["bytes"], by_fn["116a46ef"]["bytes"], by_fn["116a6bcc"]["bytes"], by_fn["116a82ed"]["bytes"]), (28, 153, 11, 26))
        self.assertEqual((by_fn["116a85f4"]["callee_pop_bytes"], by_fn["116a85f4"]["bytes"], by_fn["116af5f5"]["bytes"]), (36, 93, 149))
        self.assertEqual((by_fn["116b1753"]["bytes"], by_fn["116b193d"]["bytes"], by_fn["116b1c66"]["bytes"]), (490, 73, 651))
        self.assertEqual((by_fn["116b46d2"]["callee_pop_bytes"], by_fn["116b46d2"]["bytes"], by_fn["116b4713"]["bytes"], by_fn["116b471f"]["bytes"]), (12, 65, 12, 131))
        self.assertEqual((by_fn["116b47a2"]["bytes"], by_fn["116b47e0"]["bytes"], by_fn["116b4851"]["bytes"], by_fn["116b48b6"]["bytes"]), (62, 113, 101, 385))
        self.assertEqual((by_fn["116b4a37"]["bytes"], by_fn["116b4c4b"]["bytes"], by_fn["116b5462"]["bytes"], by_fn["116b55d0"]["bytes"]), (281, 499, 175, 26))
        self.assertEqual((by_fn["116b5604"]["bytes"], by_fn["116b56b1"]["bytes"], by_fn["116b56b1"]["body_ranges"], by_fn["116bf200"]["bytes"]), (85, 584, [{"start": "116b4fd1", "end": "116b520d"}, {"start": "116b56b1", "end": "116b56bb"}], 299))
        self.assertEqual((by_g["1172f0a4"]["width"], by_g["1172f0a8"]["width"], by_g["1172f0b0"]["width"], by_g["1172f314"]["width"], by_g["1172f338"]["width"], by_g["1172f348"]["width"]), (4, 4, 4, 4, 4, 4))
        self.assertEqual((by_g["1190ca78"]["width"], by_g["11914c54"]["width"], by_g["11914c5c"]["width"], by_g["1191b630"]["width"], by_g["11925be8"]["width"]), (16, 8, 8, 16, 16))
        self.assertEqual((by_g["119ec638"]["width"], by_g["119ec640"]["width"], by_g["12126308"]["width"]), (4, 240, 4))

    def test_tail_exit_direct_jmp_mutations_rejected(self) -> None:
        with self.subTest("conflict_with_return_instruction_addresses"):
            reg = copy.deepcopy(self.registry)
            fn = next(f for f in reg["functions"] if f["address"] == "100d12c0")
            fn["return_instruction_addresses"] = ["100d12c0"]
            with self.assertRaisesRegex(ValueError, "tail_exit"):
                contracts.validate_contracts(self.image, reg)

        with self.subTest("invalid_kind"):
            reg = copy.deepcopy(self.registry)
            fn = next(f for f in reg["functions"] if f["address"] == "100d12c0")
            fn["tail_exit"]["kind"] = "indirect_reg"
            with self.assertRaisesRegex(ValueError, "tail_exit"):
                contracts.validate_contracts(self.image, reg)

        with self.subTest("non_terminal_direct_jmp_address"):
            reg = copy.deepcopy(self.registry)
            fn = next(f for f in reg["functions"] if f["address"] == "1011fc50")
            fn["tail_exit"]["address"] = "1011fc50"
            with self.assertRaisesRegex(ValueError, "tail_exit direct_jmp"):
                contracts.validate_contracts(self.image, reg)

        with self.subTest("wrong_direct_jmp_target"):
            reg = copy.deepcopy(self.registry)
            fn = next(f for f in reg["functions"] if f["address"] == "100d12c0")
            fn["tail_exit"]["target"] = "100f1700"
            with self.assertRaisesRegex(ValueError, "tail_exit direct_jmp"):
                contracts.validate_contracts(self.image, reg)

        with self.subTest("mismatched_direct_jmp_callee_pop"):
            reg = copy.deepcopy(self.registry)
            fn = next(f for f in reg["functions"] if f["address"] == "1011fc50")
            fn["callee_pop_bytes"] = 0
            with self.assertRaisesRegex(ValueError, "tail_exit stack pop"):
                contracts.validate_contracts(self.image, reg)

    def test_tail_exit_iat_jmp_mutations_rejected(self) -> None:
        with self.subTest("non_terminal_iat_jmp_address"):
            reg = copy.deepcopy(self.registry)
            fn = next(f for f in reg["functions"] if f["address"] == "116c80c5")
            fn["tail_exit"]["address"] = "116c80c6"
            with self.assertRaisesRegex(ValueError, "tail_exit iat_jmp"):
                contracts.validate_contracts(self.image, reg)

        with self.subTest("wrong_iat_jmp_slot"):
            reg = copy.deepcopy(self.registry)
            fn = next(f for f in reg["functions"] if f["address"] == "116c80c5")
            fn["tail_exit"]["iat_slot"] = "1172f1d8"
            with self.assertRaisesRegex(ValueError, "tail_exit iat_jmp"):
                contracts.validate_contracts(self.image, reg)

        with self.subTest("missing_iat_global"):
            reg = copy.deepcopy(self.registry)
            reg["globals"] = [g for g in reg["globals"] if g["address"] != "1172f880"]
            with self.assertRaisesRegex(ValueError, "tail_exit iat_jmp"):
                contracts.validate_contracts(self.image, reg)

    def test_layer57_tail_jump_and_iat_thunk_closure_contracts(self) -> None:
        ev = self.registry["rea_layer57_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer56")
        self.assertEqual(ev["closed_evidence_records"], 65)
        self.assertEqual(ev["new_evidence_records"], 29)
        self.assertEqual(ev["retained_operation_envelopes"], 65)
        self.assertEqual(ev["reused_layer56_evidence_records"], 36)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 65)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["partition4_validated_bundle_records"], 181)
        self.assertEqual(ev["prior_partitions_validated_records"], 1555)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1620)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["new_records"]), 29)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "analyze_function"), 22)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "read_bytes"), 7)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["100d12c0"]["bytes"], by_fn["100d12c0"]["tail_exit"]), (5, {"kind": "direct_jmp", "address": "100d12c0", "target": "100fcc50"}))
        self.assertEqual((by_fn["100f2a70"]["bytes"], by_fn["100f2a70"]["return_instruction_addresses"]), (69, ["100f2aaf", "100f2ab4"]))
        self.assertEqual((by_fn["100f3880"]["bytes"], by_fn["100f3880"]["tail_exit"]), (6, {"kind": "iat_jmp", "address": "100f3880", "iat_slot": "1172f1d8"}))
        self.assertEqual((by_fn["100f3890"]["bytes"], by_fn["100f3890"]["tail_exit"]), (6, {"kind": "iat_jmp", "address": "100f3890", "iat_slot": "1172f234"}))
        self.assertEqual((by_fn["1011fc50"]["bytes"], by_fn["1011fc50"]["callee_pop_bytes"], by_fn["1011fc50"]["tail_exit"]), (150, 4, {"kind": "direct_jmp", "address": "1011fce1", "target": "100f1700"}))
        self.assertEqual((by_fn["101cfaf0"]["bytes"], by_fn["101cfaf0"]["return_instruction_addresses"]), (309, ["101cfc24"]))
        self.assertEqual((by_fn["10f69830"]["bytes"], by_fn["10f69830"]["tail_exit"]), (172, {"kind": "direct_jmp", "address": "10f698d7", "target": "101cfaf0"}))
        self.assertEqual((by_fn["10f71f70"]["bytes"], by_fn["10f71f70"]["return_instruction_addresses"]), (48, ["10f71f9f"]))
        self.assertEqual((by_fn["112ab060"]["bytes"], by_fn["112ab060"]["tail_exit"]), (108, {"kind": "direct_jmp", "address": "112ab0c7", "target": "100f1cc0"}))
        self.assertEqual((by_fn["112ab150"]["bytes"], by_fn["112ab150"]["tail_exit"]), (147, {"kind": "direct_jmp", "address": "112ab1de", "target": "100f1cc0"}))
        self.assertEqual((by_fn["112ab6b0"]["bytes"], by_fn["112ab6b0"]["tail_exit"]), (313, {"kind": "direct_jmp", "address": "112ab7e4", "target": "112ab1f0"}))
        self.assertEqual((by_fn["112ab8b0"]["bytes"], by_fn["112ab8b0"]["tail_exit"]), (730, {"kind": "direct_jmp", "address": "112abb85", "target": "100f1cc0"}))
        self.assertEqual((by_fn["11684240"]["bytes"], by_fn["11684240"]["tail_exit"]), (22, {"kind": "direct_jmp", "address": "11684251", "target": "11683dd0"}))
        self.assertEqual((by_fn["1168a23e"]["bytes"], by_fn["1168a23e"]["return_instruction_addresses"]), (376, ["1168a290", "1168a3b5"]))
        self.assertEqual((by_fn["1168d0c3"]["bytes"], by_fn["1168d0c3"]["tail_exit"]), (11, {"kind": "direct_jmp", "address": "1168d0c9", "target": "116a59a1"}))
        for addr, pop, slot in [
            ("116c80c5", 4, "1172f880"), ("116c80d1", 12, "1172f81c"), ("116c80d7", 4, "1172f820"),
            ("116c80ef", 16, "1172f830"), ("116c80fb", 16, "1172f838"), ("116c810d", 12, "1172f844"),
            ("116c8125", 0, "1172f854"),
        ]:
            self.assertEqual((by_fn[addr]["bytes"], by_fn[addr]["callee_pop_bytes"], by_fn[addr]["tail_exit"]), (6, pop, {"kind": "iat_jmp", "address": addr, "iat_slot": slot}))
            self.assertEqual(by_g[slot]["width"], 4)

    def test_tail_exit_noreturn_call_mutations_rejected(self) -> None:
        with self.subTest("non_terminal_noreturn_call_address"):
            reg = copy.deepcopy(self.registry)
            fn = next(f for f in reg["functions"] if f["address"] == "10120b20")
            fn["tail_exit"]["address"] = "10120b20"
            with self.assertRaisesRegex(ValueError, "tail_exit noreturn_call"):
                contracts.validate_contracts(self.image, reg)

        with self.subTest("wrong_noreturn_call_target"):
            reg = copy.deepcopy(self.registry)
            fn = next(f for f in reg["functions"] if f["address"] == "11686192")
            fn["tail_exit"]["target"] = "1168d362"
            with self.assertRaisesRegex(ValueError, "tail_exit noreturn_call"):
                contracts.validate_contracts(self.image, reg)

    def test_tail_exit_noreturn_iat_call_mutations_rejected(self) -> None:
        with self.subTest("non_terminal_noreturn_iat_call_address"):
            reg = copy.deepcopy(self.registry)
            fn = next(f for f in reg["functions"] if f["address"] == "1168d26c")
            fn["tail_exit"]["address"] = "1168d28e"
            with self.assertRaisesRegex(ValueError, "tail_exit noreturn_iat_call"):
                contracts.validate_contracts(self.image, reg)

        with self.subTest("wrong_noreturn_iat_call_slot"):
            reg = copy.deepcopy(self.registry)
            fn = next(f for f in reg["functions"] if f["address"] == "1168d26c")
            fn["tail_exit"]["iat_slot"] = "1172f21c"
            with self.assertRaisesRegex(ValueError, "tail_exit noreturn_iat_call"):
                contracts.validate_contracts(self.image, reg)

        with self.subTest("missing_noreturn_iat_global"):
            reg = copy.deepcopy(self.registry)
            reg["globals"] = [g for g in reg["globals"] if g["address"] != "1172f2fc"]
            with self.assertRaisesRegex(ValueError, "tail_exit noreturn_iat_call"):
                contracts.validate_contracts(self.image, reg)

    def test_layer58_crt_exit_abort_raise_exception_closure_contracts(self) -> None:
        ev = self.registry["rea_layer58_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer57")
        self.assertEqual(ev["closed_evidence_records"], 118)
        self.assertEqual(ev["new_evidence_records"], 53)
        self.assertEqual(ev["retained_operation_envelopes"], 118)
        self.assertEqual(ev["reused_layer57_evidence_records"], 65)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 118)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["partition4_validated_bundle_records"], 181)
        self.assertEqual(ev["prior_partitions_validated_records"], 1555)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1673)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["new_records"]), 53)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "analyze_function"), 30)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "read_bytes"), 23)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual((by_fn["10120b20"]["bytes"], by_fn["10120b20"]["tail_exit"]), (10, {"kind": "noreturn_call", "address": "10120b25", "target": "11686192"}))
        self.assertEqual((by_fn["1168601c"]["bytes"], by_fn["1168601c"]["callee_pop_bytes"]), (53, 4))
        self.assertEqual((by_fn["1168606c"]["bytes"], by_fn["1168606c"]["callee_pop_bytes"]), (31, 4))
        self.assertEqual((by_fn["11686192"]["bytes"], by_fn["11686192"]["tail_exit"]), (31, {"kind": "noreturn_call", "address": "116861ac", "target": "116bebf1"}))
        self.assertEqual((by_fn["116879f9"]["bytes"], by_fn["116879f9"]["tail_exit"]), (28, {"kind": "noreturn_call", "address": "11687a10", "target": "11687a16"}))
        self.assertEqual((by_fn["1168d0ce"]["bytes"], by_fn["1168d0ce"]["callee_pop_bytes"], by_fn["1168d10f"]["bytes"], by_fn["1168d11b"]["bytes"]), (65, 12, 12, 193))
        self.assertEqual((by_fn["1168d208"]["bytes"], by_fn["1168d208"]["return_instruction_addresses"]), (100, ["1168d262"]))
        self.assertEqual((by_fn["1168d26c"]["bytes"], by_fn["1168d26c"]["tail_exit"]), (65, {"kind": "noreturn_iat_call", "address": "1168d2a7", "iat_slot": "1172f2fc"}))
        self.assertEqual((by_fn["1168d2ae"]["bytes"], by_fn["1168d2f1"]["bytes"], by_fn["1168d362"]["bytes"]), (67, 83, 22))
        self.assertEqual((by_fn["1169b93d"]["bytes"], by_fn["1169b93d"]["tail_exit"]), (67, {"kind": "noreturn_call", "address": "1169b97b", "target": "1168d362"}))
        self.assertEqual((by_fn["116a176f"]["bytes"], by_fn["116a17be"]["bytes"], by_fn["116a194e"]["bytes"], by_fn["116a1a3e"]["bytes"], by_fn["116a23ed"]["bytes"]), (76, 12, 218, 45, 69))
        self.assertEqual((by_fn["116a8555"]["bytes"], by_fn["116a8555"]["callee_pop_bytes"], by_fn["116a8c48"]["bytes"]), (64, 4, 49))
        self.assertEqual((by_fn["116b03fb"]["bytes"], by_fn["116b03fb"]["callee_pop_bytes"], by_fn["116b0453"]["bytes"], by_fn["116b045f"]["bytes"]), (85, 12, 12, 66))
        self.assertEqual((by_fn["116b04a1"]["bytes"], by_fn["116b04c9"]["bytes"], by_fn["116b050e"]["bytes"], by_fn["116b06aa"]["bytes"], by_fn["116bf74d"]["bytes"]), (40, 39, 9, 18, 99))
        self.assertEqual((by_fn["116b0517"]["bytes"], by_fn["116b0517"]["body_ranges"], by_fn["116b0517"]["return_instruction_addresses"]), (473, [{"start": "116b0517", "end": "116b069a"}, {"start": "116b06bc", "end": "116b0710"}], ["116b06fd"]))
        for addr, width in [
            ("1172f254", 4), ("1172f2fc", 4), ("1173945c", 20), ("11739470", 4), ("11739474", 4), ("11739478", 4),
            ("11745c68", 19), ("1190bbd0", 8), ("1190bbf4", 8), ("1190f9dc", 24), ("1190f9f4", 15),
            ("119136b8", 4), ("119136bc", 4), ("119136c0", 4), ("11914de4", 4), ("11914de8", 37),
            ("11925254", 16), ("11925448", 16), ("11925468", 16), ("119257f0", 16), ("11925b38", 16), ("11925b58", 16),
            ("119ebec0", 4), ("12125c28", 4), ("12125c2c", 4), ("12125c30", 1), ("12125d9c", 12),
            ("121262d0", 4), ("121262d4", 4), ("121262d8", 4), ("121262dc", 4),
        ]:
            self.assertEqual(by_g[addr]["width"], width)

    def test_layer59_mod_options_exports_and_startup_bootstrap_contracts(self) -> None:
        ev = self.registry["rea_layer59_evidence"]
        self.assertEqual(ev["snapshot_mode"], "fresh_partition_p6")
        self.assertEqual(ev["closed_evidence_records"], 99)
        self.assertEqual(ev["new_evidence_records"], 99)
        self.assertEqual(ev["retained_operation_envelopes"], 99)
        self.assertEqual(ev["reused_layer58_evidence_records"], 0)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 99)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["partition4_validated_bundle_records"], 181)
        self.assertEqual(ev["partition5_validated_bundle_records"], 118)
        self.assertEqual(ev["prior_partitions_validated_records"], 1673)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1772)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 99)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 25)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 74)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        by_vt = {v["address"]: v for v in self.registry["vtables"]}
        for addr, size, cc, pop in [
            ("100d24c0", 455, "thiscall", 0),
            ("100de500", 216, "cdecl", 0),
            ("100e1050", 106, "cdecl", 0),
            ("100e3360", 1512, "cdecl", 0),
            ("100e8240", 310, "cdecl", 0),
            ("100ea060", 1123, "thiscall", 0),
            ("100ea4d0", 265, "thiscall", 0),
            ("100ea5e0", 566, "thiscall", 16),
            ("100f3000", 17, "cdecl", 0),
            ("100f4920", 226, "cdecl", 0),
            ("100f71b0", 172, "thiscall", 4),
            ("100fcc30", 26, "cdecl", 0),
            ("101016c0", 704, "cdecl", 0),
            ("10102c10", 75, "cdecl", 0),
            ("101136d0", 10, "cdecl", 0),
            ("101150f0", 10, "cdecl", 0),
            ("10120d90", 123, "cdecl", 0),
            ("10122e30", 15, "cdecl", 0),
            ("101c89e0", 108, "cdecl", 0),
            ("112dc9f0", 244, "cdecl", 0),
            ("11302cc0", 168, "cdecl", 0),
            ("11303db0", 187, "cdecl", 0),
            ("113048b0", 208, "cdecl", 0),
            ("11304980", 90, "cdecl", 0),
            ("116be670", 611, "cdecl", 0),
        ]:
            self.assertEqual(
                (by_fn[addr]["bytes"], by_fn[addr]["calling_convention"], by_fn[addr]["callee_pop_bytes"]),
                (size, cc, pop),
            )
            self.assertNotIn("tail_exit", by_fn[addr])
            self.assertTrue(by_fn[addr]["return_instruction_addresses"])
        for vt_addr, slot0 in [
            ("1173f20c", "100e1720"), ("1173f214", "100d38b0"), ("1173f21c", "100e1250"),
            ("1173f224", "100e1900"), ("1173f22c", "100e1820"), ("1173f234", "100d38b0"),
            ("1173f23c", "100e1af0"), ("1173f244", "100d38b0"), ("1173f24c", "100e1210"),
            ("1173f254", "100e17c0"), ("1173f25c", "100e1760"), ("1173f264", "100d38b0"),
            ("1173f26c", "100e1610"), ("1173f274", "100e1280"), ("1173f27c", "100e1180"),
            ("1173f284", "100e13b0"), ("1173f28c", "100e1860"), ("1173f294", "100e1640"),
            ("1173f29c", "100d38b0"), ("1173f2a4", "100d38b0"), ("1173f2ac", "100e12e0"),
            ("1173f2b4", "100e1340"), ("1173f2bc", "100e1a70"), ("1173f2c4", "100e1550"),
            ("1173f2cc", "100d38b0"), ("1173f2d4", "100e16a0"), ("1173f2dc", "100e1470"),
            ("1173f2e4", "100e14d0"), ("1173f2ec", "100e18c0"),
        ]:
            self.assertEqual(by_vt[vt_addr]["first_slot_code_identity"], slot0)
        for addr, width in [
            ("1172f004", 4), ("1172f008", 4), ("1172f01c", 4), ("1172f024", 4),
            ("1172f170", 4), ("1172f174", 4), ("1172f194", 4), ("1172f558", 4),
            ("1172f55c", 4), ("1172f56c", 4), ("11740044", 24), ("1174005c", 20),
            ("1174202c", 15), ("11742050", 8), ("11745194", 50), ("11745b64", 14),
            ("117e2e7c", 47), ("117e2eac", 37), ("1189893c", 33), ("1189bc28", 26),
            ("1189bc44", 24), ("1189bc5c", 30), ("1193452c", 588), ("11934780", 4),
            ("119e0ff0", 4), ("119f3a38", 120), ("119f3ab0", 4), ("119f3d8e", 1),
            ("119f3f04", 4), ("119f3f5c", 4), ("11af4290", 512), ("12031af0", 4),
            ("12031af4", 4), ("12031af8", 4), ("12031f00", 4), ("120321e8", 4),
            ("120321ec", 4), ("120321f0", 4), ("1203514c", 4),
        ]:
            self.assertEqual(by_g[addr]["width"], width)

    def test_layer60_startup_app_ctor_wprintf_and_timing_contracts(self) -> None:
        ev = self.registry["rea_layer60_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer59")
        self.assertEqual(ev["closed_evidence_records"], 152)
        self.assertEqual(ev["new_evidence_records"], 53)
        self.assertEqual(ev["retained_operation_envelopes"], 152)
        self.assertEqual(ev["reused_layer59_evidence_records"], 99)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 152)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["partition4_validated_bundle_records"], 181)
        self.assertEqual(ev["partition5_validated_bundle_records"], 118)
        self.assertEqual(ev["prior_partitions_validated_records"], 1673)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1825)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["new_records"]), 53)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "analyze_function"), 29)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "read_bytes"), 24)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        by_vt = {v["address"]: v for v in self.registry["vtables"]}
        for addr, size, cc, pop in [
            ("100de6d0", 369, "cdecl", 0),
            ("100df270", 640, "thiscall", 8),
            ("100edfe0", 46, "cdecl", 0),
            ("100f0eb0", 25, "thiscall", 4),
            ("100f4a10", 679, "cdecl", 0),
            ("100fe770", 1161, "cdecl", 0),
            ("10102850", 16, "cdecl", 0),
            ("101032a0", 426, "cdecl", 0),
            ("101046d0", 370, "cdecl", 0),
            ("10115800", 11, "cdecl", 0),
            ("10115810", 11, "cdecl", 0),
            ("10122e40", 15, "cdecl", 0),
            ("1014d170", 16, "thiscall", 0),
            ("106b91a0", 138, "cdecl", 0),
            ("112b2d40", 447, "cdecl", 0),
            ("112dcaf0", 996, "cdecl", 0),
            ("112e2bb0", 63, "cdecl", 0),
            ("11687a4a", 48, "cdecl", 0),
            ("11688718", 391, "cdecl", 0),
            ("11688e2b", 49, "cdecl", 0),
            ("11689bc9", 249, "thiscall", 0),
            ("11689dbc", 31, "thiscall", 0),
            ("11689e69", 27, "thiscall", 0),
            ("1168a3b6", 376, "thiscall", 0),
            ("1168abf7", 613, "thiscall", 0),
            ("1168b96f", 69, "thiscall", 8),
            ("1168bc04", 147, "thiscall", 4),
            ("1168bd56", 113, "thiscall", 16),
            ("1168c120", 36, "cdecl", 0),
        ]:
            self.assertEqual(
                (by_fn[addr]["bytes"], by_fn[addr]["calling_convention"], by_fn[addr]["callee_pop_bytes"]),
                (size, cc, pop),
            )
            self.assertNotIn("tail_exit", by_fn[addr])
            self.assertTrue(by_fn[addr]["return_instruction_addresses"])
        for vt_addr, slot0 in [
            ("1173dc18", "100d7cd0"),
            ("1173f208", "100e1a20"),
            ("1173f2f4", "100e1380"),
            ("11741e08", "101015a0"),
        ]:
            self.assertEqual(by_vt[vt_addr]["first_slot_code_identity"], slot0)
        for addr, width in [
            ("1172f17c", 4), ("1172f66c", 4), ("1172f69c", 4), ("1172f6a8", 4),
            ("1172f714", 4), ("1172f798", 4), ("1172f79c", 4), ("1173f440", 24),
            ("1173f460", 62), ("1173f4a0", 130), ("11741e28", 30), ("11741e48", 88),
            ("117420a0", 4), ("11745058", 17), ("1174506c", 17), ("1174510c", 44),
            ("11898960", 12), ("11898970", 94), ("118989d0", 107), ("11934528", 4),
            ("119f3140", 4), ("119f3854", 4), ("119f3f50", 4), ("11af4058", 4),
            ("12031ae8", 4), ("12031aec", 4),
        ]:
            self.assertEqual(by_g[addr]["width"], width)

    def test_layer61_startup_handlers_and_crt_stdio_close_contracts(self) -> None:
        ev = self.registry["rea_layer61_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer60")
        self.assertEqual(ev["closed_evidence_records"], 196)
        self.assertEqual(ev["new_evidence_records"], 44)
        self.assertEqual(ev["retained_operation_envelopes"], 196)
        self.assertEqual(ev["reused_layer60_evidence_records"], 152)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 196)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["partition4_validated_bundle_records"], 181)
        self.assertEqual(ev["partition5_validated_bundle_records"], 118)
        self.assertEqual(ev["prior_partitions_validated_records"], 1673)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1869)
        self.assertEqual(
            ev["non_proc_slots"],
            ["100d38b0", "100e85d0", "100e8be0", "100e8e50", "100e9230", "100ea040"],
        )
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["new_records"]), 44)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "analyze_function"), 25)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "resolve_containing_procedure"), 6)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "read_bytes"), 13)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        for addr, size, cc, pop in [
            ("100d3620", 98, "thiscall", 0),
            ("100d38b0", 33, "thiscall", 4),
            ("100e14d0", 65, "thiscall", 4),
            ("100e16a0", 68, "thiscall", 4),
            ("100e1820", 51, "thiscall", 4),
            ("100e1a70", 122, "thiscall", 4),
            ("100e32e0", 121, "thiscall", 0),
            ("100e7690", 60, "thiscall", 0),
            ("100e85d0", 15, "thiscall", 4),
            ("100e8be0", 28, "thiscall", 4),
            ("100e8e50", 43, "thiscall", 4),
            ("100e9230", 57, "thiscall", 4),
            ("100ea040", 21, "thiscall", 4),
            ("10121170", 63, "thiscall", 0),
            ("11687a7a", 44, "cdecl", 0),
            ("11687e1a", 76, "thiscall", 12),
            ("11687e69", 12, "cdecl", 0),
            ("11687e75", 67, "thiscall", 0),
            ("11687eb8", 385, "cdecl", 0),
            ("11688039", 99, "cdecl", 0),
            ("1168ed21", 119, "cdecl", 0),
            ("1168ed98", 119, "cdecl", 0),
            ("1168ee12", 10, "cdecl", 0),
            ("116aa220", 59, "cdecl", 0),
            ("116ab53f", 125, "thiscall", 12),
            ("116ab5bf", 12, "cdecl", 0),
            ("116ab5cb", 141, "cdecl", 0),
            ("116ab658", 156, "cdecl", 0),
            ("116ab6f4", 64, "cdecl", 0),
            ("116ae9c8", 145, "cdecl", 0),
            ("116bc6d8", 6, "cdecl", 0),
        ]:
            self.assertEqual(
                (by_fn[addr]["bytes"], by_fn[addr]["calling_convention"], by_fn[addr]["callee_pop_bytes"]),
                (size, cc, pop),
            )
            self.assertNotIn("tail_exit", by_fn[addr])
            self.assertTrue(by_fn[addr]["return_instruction_addresses"])
        for addr, width in [
            ("1172f0bc", 4), ("1173fb68", 12), ("1173fb74", 26), ("117401dc", 14),
            ("119253c8", 16), ("119254e8", 16), ("119259d0", 16), ("119f385c", 4),
            ("12126338", 4),
        ]:
            self.assertEqual(by_g[addr]["width"], width)

    def test_layer62_startup_input_msg_console_contracts(self) -> None:
        ev = self.registry["rea_layer62_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer61")
        self.assertEqual(ev["closed_evidence_records"], 252)
        self.assertEqual(ev["new_evidence_records"], 56)
        self.assertEqual(ev["retained_operation_envelopes"], 252)
        self.assertEqual(ev["reused_layer61_evidence_records"], 196)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 252)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["partition4_validated_bundle_records"], 181)
        self.assertEqual(ev["partition5_validated_bundle_records"], 118)
        self.assertEqual(ev["prior_partitions_validated_records"], 1673)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1925)
        self.assertEqual(ev["non_proc_slots"], ["100e8660"])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["new_records"]), 56)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "analyze_function"), 32)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "resolve_containing_procedure"), 1)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "read_bytes"), 23)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        by_vt = {v["address"]: v for v in self.registry["vtables"]}
        for addr, size, cc, pop in [
            ("100d1e30", 23, "thiscall", 0),
            ("100d2860", 963, "thiscall", 0),
            ("100d32b0", 55, "thiscall", 0),
            ("100d3690", 108, "thiscall", 0),
            ("100ddfc0", 24, "cdecl", 0),
            ("100e0ff0", 88, "thiscall", 0),
            ("100e12e0", 96, "thiscall", 4),
            ("100e7920", 60, "thiscall", 4),
            ("100e7960", 698, "thiscall", 8),
            ("100e8660", 97, "thiscall", 4),
            ("100eaba0", 80, "thiscall", 4),
            ("100eabf0", 30, "cdecl", 0),
            ("100eac10", 31, "cdecl", 0),
            ("100ec560", 84, "thiscall", 4),
            ("100f0fd0", 117, "thiscall", 4),
            ("100f2d60", 122, "cdecl", 0),
            ("100f5f20", 136, "cdecl", 0),
            ("100f7260", 204, "thiscall", 12),
            ("100fc8f0", 176, "cdecl", 0),
            ("100fd130", 54, "cdecl", 0),
            ("10101980", 147, "cdecl", 0),
            ("101061b0", 115, "cdecl", 0),
            ("1010eda0", 430, "cdecl", 0),
            ("10114380", 66, "thiscall", 8),
            ("1011fb70", 221, "cdecl", 0),
            ("10121350", 441, "cdecl", 0),
            ("112ac3f0", 28, "cdecl", 0),
            ("112bff20", 6, "cdecl", 0),
            ("112e2b00", 165, "thiscall", 0),
            ("112e2c20", 135, "thiscall", 0),
            ("11347290", 149, "thiscall", 0),
            ("11349100", 120, "thiscall", 8),
            ("11683d60", 55, "cdecl", 0),
        ]:
            self.assertEqual(
                (by_fn[addr]["bytes"], by_fn[addr]["calling_convention"], by_fn[addr]["callee_pop_bytes"]),
                (size, cc, pop),
            )
            self.assertNotIn("tail_exit", by_fn[addr])
            self.assertTrue(by_fn[addr]["return_instruction_addresses"])
        for vt_addr, slot0 in [
            ("1173deb0", "100d3850"),
            ("11744dd8", "100f37b0"),
            ("11744de4", "100f37d0"),
        ]:
            self.assertEqual(by_vt[vt_addr]["first_slot_code_identity"], slot0)
        for addr, width in [
            ("1172f280", 4), ("1172f6b4", 4), ("1172f6b8", 4), ("1173de98", 10),
            ("1173debc", 17), ("1173ded0", 23), ("1173dee8", 3), ("1173deec", 9),
            ("1173def8", 29), ("1173df18", 17), ("1173df2c", 19), ("1173df40", 18),
            ("1173df54", 22), ("1173e2b8", 4), ("117452ac", 17), ("117452f4", 10),
            ("11745c44", 14), ("1190bb38", 16), ("119344d8", 16), ("119f3b6c", 4),
            ("119f3b70", 4), ("119f3b78", 256), ("119f3c78", 256), ("119f3d78", 16),
            ("119f3dc8", 4), ("12031ae5", 1), ("120351cc", 4),
        ]:
            self.assertEqual(by_g[addr]["width"], width)

    def test_layer63_startup_sysinfo_vsprintf_contracts(self) -> None:
        ev = self.registry["rea_layer63_evidence"]
        self.assertEqual(ev["snapshot_mode"], "fresh_partition_p7")
        self.assertEqual(ev["closed_evidence_records"], 40)
        self.assertEqual(ev["new_evidence_records"], 40)
        self.assertEqual(ev["retained_operation_envelopes"], 40)
        self.assertEqual(ev["reused_layer62_evidence_records"], 0)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 40)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["partition4_validated_bundle_records"], 181)
        self.assertEqual(ev["partition5_validated_bundle_records"], 118)
        self.assertEqual(ev["partition6_validated_bundle_records"], 252)
        self.assertEqual(ev["prior_partitions_validated_records"], 1925)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1965)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["records"]), 40)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "analyze_function"), 32)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "resolve_containing_procedure"), 0)
        self.assertEqual(sum(1 for r in ev["records"] if r["operation"] == "read_bytes"), 8)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        for addr, size, cc, pop in [
            ("10126cd0", 48, "cdecl", 0),
            ("112f6190", 576, "cdecl", 0),
            ("1168859a", 382, "cdecl", 0),
            ("11688abd", 49, "cdecl", 0),
            ("11688b5a", 115, "thiscall", 12),
            ("11688c54", 142, "thiscall", 16),
            ("11688dff", 44, "cdecl", 0),
            ("11688e5c", 69, "thiscall", 0),
            ("11688eeb", 60, "thiscall", 24),
            ("11689311", 61, "thiscall", 8),
            ("1168942b", 116, "thiscall", 4),
            ("11689871", 244, "thiscall", 0),
            ("11689ce5", 61, "thiscall", 0),
            ("11689d7e", 31, "thiscall", 0),
            ("11689e15", 42, "thiscall", 0),
            ("11689ef1", 100, "thiscall", 4),
            ("11689f55", 38, "thiscall", 0),
            ("1168a0f0", 334, "thiscall", 0),
            ("1168a760", 562, "thiscall", 0),
            ("1168ae5c", 43, "thiscall", 0),
            ("1168af07", 90, "thiscall", 0),
            ("1168afbb", 335, "thiscall", 0),
            ("1168b26f", 144, "thiscall", 4),
            ("1168b395", 337, "thiscall", 8),
            ("1168b6af", 31, "thiscall", 0),
            ("1168b6ed", 24, "thiscall", 0),
            ("1168b71d", 113, "thiscall", 0),
            ("1168b92d", 66, "thiscall", 8),
            ("1168baca", 167, "thiscall", 4),
            ("1168bcef", 103, "thiscall", 16),
            ("1168c0d8", 36, "cdecl", 0),
            ("1169de89", 42, "cdecl", 0),
        ]:
            self.assertEqual(
                (by_fn[addr]["bytes"], by_fn[addr]["calling_convention"], by_fn[addr]["callee_pop_bytes"]),
                (size, cc, pop),
            )
            self.assertNotIn("tail_exit", by_fn[addr])
            self.assertTrue(by_fn[addr]["return_instruction_addresses"])
        for addr, width in [
            ("1172f188", 4), ("1172f2d4", 4), ("117420a4", 2), ("117420a8", 3),
            ("1189af70", 61), ("1189afb4", 7), ("1189afbc", 15), ("1189afcc", 21),
            ("12033e68", 1024), ("12034268", 1024), ("12034b88", 256),
        ]:
            self.assertEqual(by_g[addr]["width"], width)

    def test_layer64_startup_vfprintf_read_contracts(self) -> None:
        ev = self.registry["rea_layer64_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer63_batched_p7")
        self.assertEqual(ev["closed_evidence_records"], 72)
        self.assertEqual(ev["new_evidence_records"], 32)
        self.assertEqual(ev["retained_operation_envelopes"], 72)
        self.assertEqual(ev["reused_layer63_evidence_records"], 40)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 72)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["partition4_validated_bundle_records"], 181)
        self.assertEqual(ev["partition5_validated_bundle_records"], 118)
        self.assertEqual(ev["partition6_validated_bundle_records"], 252)
        self.assertEqual(ev["prior_partitions_validated_records"], 1925)
        self.assertEqual(ev["cumulative_all_partitions_records"], 1997)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["new_records"]), 32)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "analyze_function"), 27)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "resolve_containing_procedure"), 0)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "read_bytes"), 5)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        for addr, size, cc, pop in [
            ("100edfb0", 34, "cdecl", 0),
            ("1168809c", 76, "thiscall", 12),
            ("116880eb", 12, "cdecl", 0),
            ("11688d84", 59, "cdecl", 0),
            ("116890f3", 191, "thiscall", 0),
            ("116892d1", 64, "stdcall", 8),
            ("11689515", 259, "thiscall", 0),
            ("11689d5f", 31, "thiscall", 0),
            ("11689ddb", 58, "thiscall", 0),
            ("11689e84", 109, "thiscall", 4),
            ("11689fa2", 334, "thiscall", 0),
            ("1168a52e", 562, "thiscall", 0),
            ("1168b848", 33, "thiscall", 0),
            ("1168b884", 34, "thiscall", 0),
            ("1168b8a6", 135, "cdecl", 0),
            ("1168b9b4", 54, "thiscall", 4),
            ("1168ba23", 167, "thiscall", 4),
            ("1168bc97", 44, "thiscall", 16),
            ("1168bdc7", 158, "thiscall", 16),
            ("1168bfab", 131, "cdecl", 0),
            ("116aa9e2", 353, "cdecl", 0),
            ("116aab43", 465, "cdecl", 0),
            ("116aad14", 343, "cdecl", 0),
            ("116aae6b", 123, "cdecl", 0),
            ("116aaee6", 262, "cdecl", 0),
            ("116aafc7", 8, "cdecl", 0),
            ("116aaffa", 944, "cdecl", 0),
        ]:
            self.assertEqual(
                (by_fn[addr]["bytes"], by_fn[addr]["calling_convention"], by_fn[addr]["callee_pop_bytes"]),
                (size, cc, pop),
            )
            self.assertNotIn("tail_exit", by_fn[addr])
            self.assertTrue(by_fn[addr]["return_instruction_addresses"])
        self.assertEqual(
            by_fn["116aaee6"]["body_ranges"],
            [{"start": "116aaee6", "end": "116aafc0"}, {"start": "116aafcf", "end": "116aaff9"}],
        )
        for addr, width in [
            ("1172f0cc", 4), ("1172f1c0", 4), ("1190ecd0", 91),
            ("11925428", 16), ("119259b0", 16),
        ]:
            self.assertEqual(by_g[addr]["width"], width)

    def test_layer65_startup_stdio_stream_contracts(self) -> None:
        ev = self.registry["rea_layer65_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer63_batched_p7")
        self.assertEqual(ev["closed_evidence_records"], 127)
        self.assertEqual(ev["new_evidence_records"], 55)
        self.assertEqual(ev["retained_operation_envelopes"], 127)
        self.assertEqual(ev["reused_layer64_evidence_records"], 72)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 127)
        self.assertEqual(ev["partition1_validated_bundle_records"], 367)
        self.assertEqual(ev["partition2_validated_bundle_records"], 743)
        self.assertEqual(ev["partition3_validated_bundle_records"], 264)
        self.assertEqual(ev["partition4_validated_bundle_records"], 181)
        self.assertEqual(ev["partition5_validated_bundle_records"], 118)
        self.assertEqual(ev["partition6_validated_bundle_records"], 252)
        self.assertEqual(ev["prior_partitions_validated_records"], 1925)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2052)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(len(ev["new_records"]), 55)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "analyze_function"), 37)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "resolve_containing_procedure"), 0)
        self.assertEqual(sum(1 for r in ev["new_records"] if r["operation"] == "read_bytes"), 18)

        by_fn = {f["address"]: f for f in self.registry["functions"]}
        by_g = {g["address"]: g for g in self.registry["globals"]}
        for addr, size, cc, pop in [
            ("1168d030", 115, "cdecl", 0),
            ("116a896e", 75, "stdcall", 12),
            ("116aa31d", 554, "cdecl", 0),
            ("116aa547", 619, "cdecl", 0),
            ("116aa7b2", 131, "cdecl", 0),
            ("116aa835", 131, "cdecl", 0),
            ("116aa8b8", 27, "cdecl", 0),
            ("116aa8d3", 31, "cdecl", 0),
            ("116aa8f2", 32, "cdecl", 0),
            ("116aa912", 34, "cdecl", 0),
            ("116aa934", 34, "cdecl", 0),
            ("116aa956", 54, "cdecl", 0),
            ("116aa98c", 32, "cdecl", 0),
            ("116aa9ac", 32, "cdecl", 0),
            ("116ae68f", 123, "cdecl", 0),
            ("116ae800", 146, "cdecl", 0),
            ("116ae8b5", 263, "cdecl", 0),
            ("116ae9bf", 9, "cdecl", 0),
            ("116aeb77", 143, "cdecl", 0),
            ("116aec0c", 44, "cdecl", 0),
            ("116aec38", 143, "cdecl", 0),
            ("116aeccd", 44, "cdecl", 0),
            ("116aecf9", 594, "cdecl", 0),
            ("116aef4c", 37, "cdecl", 0),
            ("116aef71", 112, "cdecl", 0),
            ("116aefe1", 377, "cdecl", 0),
            ("116af15b", 170, "cdecl", 0),
            ("116af21d", 110, "cdecl", 0),
            ("116af28b", 32, "cdecl", 0),
            ("116af2ab", 810, "cdecl", 0),
            ("116af5d5", 32, "cdecl", 0),
            ("116b844f", 76, "cdecl", 0),
            ("116b849b", 211, "cdecl", 0),
            ("116bc6de", 45, "cdecl", 0),
            ("116bc70b", 207, "cdecl", 0),
            ("116bc7da", 77, "thiscall", 12),
            ("116bc827", 368, "cdecl", 0),
        ]:
            self.assertEqual(
                (by_fn[addr]["bytes"], by_fn[addr]["calling_convention"], by_fn[addr]["callee_pop_bytes"]),
                (size, cc, pop),
            )
            self.assertNotIn("tail_exit", by_fn[addr])
            self.assertTrue(by_fn[addr]["return_instruction_addresses"])
        self.assertEqual(
            by_fn["1168d030"]["body_ranges"],
            [{"start": "1168d030", "end": "1168d09a"}, {"start": "1168d0a0", "end": "1168d0a7"}],
        )
        for addr, width in [
            ("1172f110", 4), ("1190c78c", 28), ("11914d3c", 8), ("11914d44", 8),
            ("119152f8", 4), ("119152fc", 6), ("11915304", 8), ("1191530c", 8),
            ("11915314", 8), ("1191531c", 12), ("11915328", 16), ("11915338", 16),
            ("11925a38", 16), ("11925a98", 16), ("11925ab8", 16),
            ("121262f4", 4), ("1212633c", 4), ("12126340", 4),
        ]:
            self.assertEqual(by_g[addr]["width"], width)

    def test_layer66_startup_fopen_fread_init_contracts(self):
        ev = self.registry["rea_layer66_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer63")
        self.assertEqual(ev["closed_evidence_records"], 193)
        self.assertEqual(ev["new_evidence_records"], 66)
        self.assertEqual(ev["reused_layer65_evidence_records"], 127)
        self.assertEqual(ev["retained_operation_envelopes"], 193)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(ev["cumulative_validated_bundle_records"], 193)
        self.assertEqual(ev["prior_partitions_validated_records"], 1925)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2118)
        self.assertEqual(
            ev["closed_snapshot_sha256"],
            "6d212336f17ee7c9e9e7b4a52bc0c075c5f0d114a1c0696fc2d7443f9f13c1fd",
        )
        self.assertEqual(
            ev["validated_bundle_sha256"],
            "de90311e12db70e6ac2aae91c0523ea76e8fbbaae414e652e6a2665aaff44741",
        )
        ops = {}
        for rec in ev["new_records"]:
            ops[rec["operation"]] = ops.get(rec["operation"], 0) + 1
        self.assertEqual(ops, {"analyze_function": 37, "read_bytes": 29})

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        layer66_addrs = [
            "100e2980", "100edc70", "100edcd0", "100f21a0", "10104a70",
            "1011fee0", "113471f0", "11684670", "1168d37f", "1168e7d7",
            "1168e877", "1168e88e", "1168e92d", "1168e95b", "1168e9a2",
            "1168e9b9", "1168ea00", "1168ec03", "1168ec98", "11699fb7",
            "1169a031", "1169a0b2", "1169a0bc", "1169a195", "1169a28e",
            "1169a3c5", "1169a549", "1169a708", "1169a8a1", "1169a92a",
            "116aa1b7", "116aa217", "116aa25b", "116aa9cc", "116aa9d7",
            "116ab3aa", "116ab534",
        ]
        for addr in layer66_addrs:
            self.assertIn(addr, by_fn)
        expected_tails = {
            "100edcd0": {"kind": "noreturn_call", "address": "100edd54", "target": "1168d37f"},
            "1169a92a": {"kind": "direct_jmp", "address": "1169a930", "target": "1169a3c5"},
            "116aa9cc": {"kind": "direct_jmp", "address": "116aa9d2", "target": "116aa7b2"},
            "116aa9d7": {"kind": "direct_jmp", "address": "116aa9dd", "target": "116aa835"},
            "116ab534": {"kind": "direct_jmp", "address": "116ab53a", "target": "116ab3aa"},
        }
        for addr, tail in expected_tails.items():
            self.assertEqual(by_fn[addr]["tail_exit"], tail)

        by_v = {item["address"]: item for item in self.registry["vtables"]}
        self.assertEqual(by_v["1173db1c"]["first_slot_code_identity"], "100d3970")
        self.assertEqual(by_v["1173db4c"]["first_slot_code_identity"], "100d39b0")

        by_g = {item["address"]: item for item in self.registry["globals"]}
        expected_globals = {
            "1173db1c": (48, "file"), "1173db4c": (12, "file"), "1173f204": (4, "file"),
            "1173f458": (4, "file"), "1173f6fc": (26, "file"), "1173f718": (12, "file"),
            "1173f724": (26, "file"), "1173f740": (28, "file"), "1173f75c": (56, "file"),
            "1173f794": (32, "file"), "1173f7b4": (50, "file"), "1173f7e8": (12, "file"),
            "1173f7f4": (18, "file"), "1173f808": (17, "file"), "1173f81c": (25, "file"),
            "11740124": (3, "file"), "117420ac": (4, "file"), "117420b0": (4, "file"),
            "118a13d8": (60, "file"), "11925488": (16, "file"), "119254a8": (16, "file"),
            "119254c8": (16, "file"), "11925588": (16, "file"), "11925990": (16, "file"),
            "119e255c": (60, "file"), "119f3174": (4, "zero_fill"),
            "12125c34": (4, "zero_fill"), "12125c38": (4, "zero_fill"),
        }
        for addr, (width, storage) in expected_globals.items():
            self.assertEqual(by_g[addr]["width"], width)
            self.assertEqual(by_g[addr]["storage"], storage)

    def test_layer67_startup_engine_db_fp_contracts(self):
        ev = self.registry["rea_layer67_evidence"]
        self.assertEqual(ev["snapshot_mode"], "fresh_partition_p8")
        self.assertEqual(ev["closed_evidence_records"], 41)
        self.assertEqual(ev["new_evidence_records"], 41)
        self.assertEqual(ev["reused_layer66_evidence_records"], 0)
        self.assertEqual(ev["retained_operation_envelopes"], 41)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(ev["cumulative_validated_bundle_records"], 41)
        self.assertEqual(ev["partition7_validated_bundle_records"], 193)
        self.assertEqual(ev["prior_partitions_validated_records"], 2118)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2159)
        self.assertEqual(
            ev["closed_snapshot_sha256"],
            "19261c2e0ae8d1f75f5328bd2bcf364117e470e8f7e892ae29496af406936e00",
        )
        self.assertEqual(
            ev["validated_bundle_sha256"],
            "fb254cb2760656d5ae0f175bca375e52a518b4c486c82a1865ffe86f030f9883",
        )
        ops = {}
        for rec in ev["records"]:
            ops[rec["operation"]] = ops.get(rec["operation"], 0) + 1
        self.assertEqual(ops, {"analyze_function": 24, "read_bytes": 17})

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        layer67_addrs = [
            "100d2c80", "100d6db0", "100d81c0", "100e0650", "101150a0", "106d1a90",
            "106d2a40", "106d2e80", "106d2f20", "10c84e40", "10c8f760", "10c8f8c0",
            "10ca3740", "10ca37d0", "10ca3810", "10cad6e0", "10cb8f90", "112bb3f0",
            "11698a7c", "1169aec3", "1169b048", "1169b349", "1169b482", "116adaed",
        ]
        for addr in layer67_addrs:
            self.assertIn(addr, by_fn)
        self.assertEqual(
            by_fn["10ca3810"]["tail_exit"],
            {"kind": "direct_jmp", "address": "10ca38e6", "target": "10ca3740"},
        )
        self.assertEqual(by_fn["106d2a40"]["callee_pop_bytes"], 8)
        self.assertEqual(by_fn["106d2e80"]["callee_pop_bytes"], 4)
        self.assertEqual(by_fn["106d2f20"]["callee_pop_bytes"], 8)
        self.assertEqual(by_fn["10cad6e0"]["callee_pop_bytes"], 4)
        self.assertEqual(
            by_fn["116adaed"]["body_ranges"],
            [
                {"start": "116adaed", "end": "116adb22"},
                {"start": "116adb53", "end": "116adb6c"},
            ],
        )

        by_v = {item["address"]: item for item in self.registry["vtables"]}
        self.assertEqual(by_v["1173f200"]["first_slot_code_identity"], "100e11e0")

        by_g = {item["address"]: item for item in self.registry["globals"]}
        expected_globals = {
            "1173dd44": 25, "1173dd60": 28, "1173dd7c": 27, "1173dd98": 22,
            "1173ddb0": 21, "1173ddc8": 20, "1173dddc": 19, "1173ddf0": 32,
            "1173de10": 19, "1173de80": 24, "1173f200": 4, "1175612c": 12,
            "11925a18": 16, "119e1254": 8, "119e125c": 4, "119e1260": 4,
            "119ec140": 4,
        }
        for addr, width in expected_globals.items():
            self.assertEqual(by_g[addr]["width"], width)
            self.assertEqual(by_g[addr]["storage"], "file")

    def test_layer68_startup_video_device_cfg_contracts(self):
        ev = self.registry["rea_layer68_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer67_batched_p8")
        self.assertEqual(ev["closed_evidence_records"], 112)
        self.assertEqual(ev["new_evidence_records"], 71)
        self.assertEqual(ev["reused_layer67_evidence_records"], 41)
        self.assertEqual(ev["retained_operation_envelopes"], 112)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(ev["cumulative_validated_bundle_records"], 112)
        self.assertEqual(ev["prior_partitions_validated_records"], 2118)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2230)
        self.assertEqual(
            ev["closed_snapshot_sha256"],
            "19261c2e0ae8d1f75f5328bd2bcf364117e470e8f7e892ae29496af406936e00",
        )
        self.assertEqual(
            ev["validated_bundle_sha256"],
            "98bab55dd163c0e8a6d9dcf1ac0f9d286fd082a88baae01a87c685b619a1c8eb",
        )
        ops = {}
        for rec in ev["new_records"]:
            ops[rec["operation"]] = ops.get(rec["operation"], 0) + 1
        self.assertEqual(ops, {"analyze_function": 30, "read_bytes": 41})

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        layer68_addrs = [
            "100dd4c0", "100efd80", "100f2960", "10115370", "101223e0", "102b4f20",
            "10c84040", "10c8a0b0", "10c8b3a0", "10c99c60", "10ca63f0", "10cc18c0",
            "10cc4b50", "10cc9090", "10ce6120", "10d33170", "10d33280", "10d39b50",
            "10dd83c0", "10ddb580", "10de06e0", "110e2700", "112a4ae0", "112a58b0",
            "112a5af0", "112ab5e0", "112bb070", "112bdc00", "112d9900", "112d9960",
        ]
        for addr in layer68_addrs:
            self.assertIn(addr, by_fn)
        self.assertEqual(by_fn["10cc4b50"]["callee_pop_bytes"], 16)
        self.assertEqual(by_fn["10cc9090"]["callee_pop_bytes"], 16)
        self.assertEqual(by_fn["10ddb580"]["callee_pop_bytes"], 16)
        self.assertEqual(by_fn["10de06e0"]["callee_pop_bytes"], 16)
        self.assertEqual(by_fn["112d9960"]["callee_pop_bytes"], 12)

        by_v = {item["address"]: item for item in self.registry["vtables"]}
        expected_vtables = {
            "11768574": "1033d400", "117e2588": "10c9fd40", "117e29fc": "10ccb320",
            "117e2a04": "10c9fd40", "117ee52c": "10c9fd40", "117ff0d0": "10de3460",
        }
        for va, slot0 in expected_vtables.items():
            self.assertEqual(by_v[va]["first_slot_code_identity"], slot0)

        by_g = {item["address"]: item for item in self.registry["globals"]}
        self.assertEqual(by_g["11899d90"]["width"], 106)
        self.assertEqual(by_g["11970645"]["width"], 1)
        self.assertEqual(by_g["11970646"]["width"], 1)
        self.assertEqual(by_g["1172f764"]["width"], 4)

    def test_layer69_startup_remote_socket_net_contracts(self):
        ev = self.registry["rea_layer69_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer68_batched_p8")
        self.assertEqual(ev["closed_evidence_records"], 158)
        self.assertEqual(ev["new_evidence_records"], 46)
        self.assertEqual(ev["reused_layer68_evidence_records"], 112)
        self.assertEqual(ev["retained_operation_envelopes"], 158)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(ev["cumulative_validated_bundle_records"], 158)
        self.assertEqual(ev["prior_partitions_validated_records"], 2118)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2276)
        self.assertEqual(
            ev["closed_snapshot_sha256"],
            "19261c2e0ae8d1f75f5328bd2bcf364117e470e8f7e892ae29496af406936e00",
        )
        self.assertEqual(
            ev["validated_bundle_sha256"],
            "d54a59fa912eb685d07f4c5152b1f56598b8331be8424b7d623019942803994a",
        )
        ops = {}
        for rec in ev["new_records"]:
            ops[rec["operation"]] = ops.get(rec["operation"], 0) + 1
        self.assertEqual(ops, {"analyze_function": 23, "read_bytes": 23})

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        layer69_addrs = [
            "100eeb50", "100f1bf0", "100f3b40", "100f5630", "100f6220", "100ffa10",
            "10100700", "10100e20", "10101e30", "10106230", "10113510", "10115e10",
            "10924df0", "10c93c00", "10cba480", "10cba4c0", "10cba590", "10cba7a0",
            "10cbae00", "10cbaf70", "11370160", "116c80b9", "116c80e9",
        ]
        for addr in layer69_addrs:
            self.assertIn(addr, by_fn)
        self.assertEqual(
            by_fn["10cba590"]["tail_exit"],
            {"kind": "direct_jmp_short", "address": "10cba780", "target": "10cba7a0"},
        )
        self.assertEqual(
            by_fn["116c80b9"]["tail_exit"],
            {"kind": "iat_jmp", "address": "116c80b9", "iat_slot": "1172f878"},
        )
        self.assertEqual(
            by_fn["116c80e9"]["tail_exit"],
            {"kind": "iat_jmp", "address": "116c80e9", "iat_slot": "1172f82c"},
        )
        self.assertEqual(by_fn["10113510"]["callee_pop_bytes"], 12)
        self.assertEqual(by_fn["10cba480"]["callee_pop_bytes"], 12)

        by_g = {item["address"]: item for item in self.registry["globals"]}
        expected_globals = {
            "1172f6f0": 4, "1172f82c": 4, "1172f878": 4, "11741db0": 7,
            "11741ea0": 14, "11741eb0": 20, "11741ec4": 12, "11741ed0": 12,
            "11741edc": 14, "11741eec": 22, "11753f98": 3, "117e19e0": 17,
            "117e1a08": 76, "119247b0": 16,
        }
        for addr, width in expected_globals.items():
            self.assertEqual(by_g[addr]["width"], width)
            self.assertEqual(by_g[addr]["storage"], "file")

    def test_layer70_startup_touch_gesture_input_contracts(self):
        ev = self.registry["rea_layer70_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer69_batched_p8")
        self.assertEqual(ev["closed_evidence_records"], 198)
        self.assertEqual(ev["new_evidence_records"], 40)
        self.assertEqual(ev["reused_layer69_evidence_records"], 158)
        self.assertEqual(ev["retained_operation_envelopes"], 198)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(ev["cumulative_validated_bundle_records"], 198)
        self.assertEqual(ev["prior_partitions_validated_records"], 2118)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2316)
        self.assertEqual(
            ev["closed_snapshot_sha256"],
            "19261c2e0ae8d1f75f5328bd2bcf364117e470e8f7e892ae29496af406936e00",
        )
        self.assertEqual(
            ev["validated_bundle_sha256"],
            "78b04418c2eff5f57bcf8efc40d0643df1fbd9cf6556dbba5a2662bda1ef1b63",
        )
        ops = {}
        for rec in ev["new_records"]:
            ops[rec["operation"]] = ops.get(rec["operation"], 0) + 1
        self.assertEqual(ops, {"analyze_function": 21, "read_bytes": 19})

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        layer70_thiscall = {
            "100d2690": 4, "100d8430": 4, "100d89a0": 4, "100d9880": 0,
            "100d9e40": 4, "100d9f80": 4, "100da2b0": 4, "100da3f0": 4,
            "100da620": 4, "100dcfe0": 4, "100dd280": 4, "100dd7a0": 4,
            "100ddcd0": 4, "100f1090": 4, "100f1100": 4, "100f1160": 0,
            "10103c50": 0,
        }
        for addr, pop in layer70_thiscall.items():
            self.assertEqual(by_fn[addr]["calling_convention"], "thiscall")
            self.assertEqual(by_fn[addr]["receiver_register"], "ECX")
            self.assertEqual(by_fn[addr]["callee_pop_bytes"], pop)
        for addr, pop in {"100d6910": 8, "100d7b80": 96, "100d7f30": 96}.items():
            self.assertEqual(by_fn[addr]["calling_convention"], "stdcall")
            self.assertEqual(by_fn[addr]["callee_pop_bytes"], pop)
        self.assertEqual(by_fn["1168cad5"]["calling_convention"], "cdecl")
        self.assertEqual(by_fn["1168cad5"]["callee_pop_bytes"], 0)

        by_g = {item["address"]: item for item in self.registry["globals"]}
        expected_globals = {
            "1173e2b4": "00000000", "1173e2c0": "0000803e", "1173e2c4": "0000003f",
            "1173e2f0": "46276542", "1173e2f8": "462765c2", "119331d8": "cdccccbd",
            "119331dc": "0000c842", "119331e0": "00000041", "11933c7c": "01",
            "119344c0": "000000000000000000000000ffff7f7f", "119344d0": "0000000000000000",
        }
        for addr, initial in expected_globals.items():
            self.assertEqual(by_g[addr]["initial_hex_le"], initial)
            self.assertEqual(by_g[addr]["storage"], "file")
        for addr, width in {
            "1190ed40": 64, "1190f540": 16, "1190f550": 16, "1190f560": 16, "11914e40": 64,
        }.items():
            self.assertEqual(by_g[addr]["width"], width)
            self.assertEqual(by_g[addr]["storage"], "file")

    def test_layer71_startup_entry_frame_loop_contracts(self):
        ev = self.registry["rea_layer71_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer70_batched_p8")
        self.assertEqual(ev["closed_evidence_records"], 257)
        self.assertEqual(ev["new_evidence_records"], 59)
        self.assertEqual(ev["reused_layer70_evidence_records"], 198)
        self.assertEqual(ev["retained_operation_envelopes"], 257)
        self.assertEqual(ev["extra_evidence_views_count"], 0)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(ev["cumulative_validated_bundle_records"], 257)
        self.assertEqual(ev["prior_partitions_validated_records"], 2118)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2375)
        self.assertEqual(
            ev["closed_snapshot_sha256"],
            "19261c2e0ae8d1f75f5328bd2bcf364117e470e8f7e892ae29496af406936e00",
        )
        self.assertEqual(
            ev["validated_bundle_sha256"],
            "d1e0cc84583aad43fe0757bc525b609c1558a1bb786b80d4c599b26d386e2541",
        )
        ops = {}
        for rec in ev["new_records"]:
            ops[rec["operation"]] = ops.get(rec["operation"], 0) + 1
        self.assertEqual(ops, {"analyze_function": 17, "read_bytes": 42})
        self.assertEqual(len(ev["limitations"]), 10)

        by_fn = {item["address"]: item for item in self.registry["functions"]}
        layer71_thiscall = {
            "100d6cc0": 4, "100d9d90": 4, "100dbf80": 0, "100ec5c0": 0,
            "104274b0": 8, "10c8fff0": 0, "10c914d0": 0, "10cb8420": 8,
            "10cb8450": 8, "10cb8480": 8, "112e2bf0": 4,
        }
        for addr, pop in layer71_thiscall.items():
            self.assertEqual(by_fn[addr]["calling_convention"], "thiscall")
            self.assertEqual(by_fn[addr]["receiver_register"], "ECX")
            self.assertEqual(by_fn[addr]["callee_pop_bytes"], pop)
            self.assertEqual(by_fn[addr]["stack_argument_bytes"], pop)
        layer71_cdecl = {
            "100ed3c0": 12, "100edd70": 32, "100f6940": 0, "10114ee0": 8,
            "10cb0440": 4, "112ac410": 12,
        }
        for addr, stack in layer71_cdecl.items():
            self.assertEqual(by_fn[addr]["calling_convention"], "cdecl")
            self.assertEqual(by_fn[addr]["callee_pop_bytes"], 0)
            self.assertEqual(by_fn[addr]["stack_argument_bytes"], stack)

        entry = by_fn["100edd70"]
        self.assertEqual(entry["bytes"], 535)
        self.assertEqual(entry["body_ranges"], [
            {"start": "100edd70", "end": "100edf49"},
            {"start": "100edf73", "end": "100edfaf"},
        ])
        self.assertEqual(entry["return_instruction_addresses"], ["100edec8", "100edfaf"])

        by_g = {item["address"]: item for item in self.registry["globals"]}
        expected_globals = {
            "1173dd3c": "5549732f00", "1173f838": "90a95e9a34306f4d912801f3c61022bc",
            "1173f848": "72fbb2e728d7b349a5f218ebf5f1349e", "11740128": "0d0a00",
            "11923d98": "ffffffff4adf0e1067df0e10", "11933190": "00000100",
            "11933ad0": "01", "11934468": "10270000", "119ef0c8": "00000000",
        }
        for addr, initial in expected_globals.items():
            self.assertEqual(by_g[addr]["initial_hex_le"], initial)
            self.assertEqual(by_g[addr]["storage"], "file")
        scope = bytes.fromhex(by_g["11923d98"]["initial_hex_le"])
        filt, handler = struct.unpack_from("<II", scope, 4)
        gap = (int(entry["body_ranges"][0]["end"], 16), int(entry["body_ranges"][1]["start"], 16))
        self.assertTrue(gap[0] < filt < handler < gap[1])

        by_w = {item["address"]: item for item in self.registry["instruction_witnesses"]}
        self.assertEqual(by_w["10cb045e"]["hex"], "0f85bc600000")
        self.assertEqual(by_w["100edd7a"]["hex"], "68d8e36b11")
        self.assertEqual(by_w["100edf05"]["hex"], "68d0e50e10")

        # Independent decode of every audited jump edge that left the Layer 71 recovered bodies.
        base, sections = contracts.parse_pe32(self.image)[:2]
        l71_fns = self.registry["functions"][:1563]
        l71_by_fn = {fn["address"]: fn for fn in l71_fns}
        ranges = []
        for fn in l71_fns:
            if "body_ranges" in fn:
                ranges.extend((int(r["start"], 16), int(r["end"], 16)) for r in fn["body_ranges"])
            else:
                start = int(fn["address"], 16)
                ranges.append((start, start + fn["bytes"] - 1))

        def recovered(address):
            return any(start <= address <= end for start, end in ranges)

        audit = ev["closure_audit"]
        self.assertEqual(audit["recovered_functions"], 1563)
        self.assertEqual(audit["open_direct_call_edges"], 0)
        edges = audit["direct_jump_edges_leaving_recovered_bodies"]
        self.assertEqual(len(edges), 12)
        self.assertEqual(len({edge["target"] for edge in edges}), 9)
        self.assertEqual([edge["instruction"] for edge in edges if edge["layer"] == "layer71"], ["10cb045e"])
        for edge in edges:
            at = int(edge["instruction"], 16)
            raw = contracts.image_bytes(self.image, base, sections, at, 6)[0]
            if raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f:
                target = at + 2 + struct.unpack_from("<b", raw, 1)[0]
            elif raw[0] == 0xe9:
                target = at + 5 + struct.unpack_from("<i", raw, 1)[0]
            else:
                self.assertEqual(raw[0], 0x0f)
                self.assertTrue(0x80 <= raw[1] <= 0x8f)
                target = at + 6 + struct.unpack_from("<i", raw, 2)[0]
            self.assertEqual(target, int(edge["target"], 16))
            self.assertTrue(recovered(at))
            self.assertFalse(recovered(target))
            self.assertNotIn(edge["target"], l71_by_fn)

    def test_layer72_startup_prefs_seh_tail_contracts(self):
        by_fn = {f["address"]: f for f in self.registry["functions"]}
        layer72_addrs = [
            "100d12d0",
            "100d14d0",
            "100d6570",
            "100dacb0",
            "10104ac0",
            "10fd964a",
            "11346aa0",
            "11349f80",
            "1168e944",
            "116b326e",
            "116b327b",
            "116bd580",
            "116bd59e",
            "116bd810",
            "116c09ae",
            "116c09f0",
            "116c0a56",
            "116c0b0c",
            "116c0b2b",
            "116c0b30",
            "116c0bf0",
            "116c0f9d",
            "116d7200",
            "116d7250",
            "116d7310",
        ]
        for addr in layer72_addrs:
            self.assertIn(addr, by_fn)
        self.assertEqual(
            [(r["start"], r["end"]) for r in by_fn["116c0bf0"]["body_ranges"]],
            [("116c0bf0", "116c0ed6"), ("116c0eff", "116c0f17"), ("116c0f20", "116c0f9c")],
        )
        self.assertEqual(
            [(r["start"], r["end"]) for r in by_fn["116d7250"]["body_ranges"]],
            [("116d7250", "116d72d8"), ("116d72ef", "116d7309")],
        )
        by_g = {g["address"]: g for g in self.registry["globals"]}
        for gaddr in (
            "1172f118", "1173e288", "1173e28c", "1173e294", "1173e298", "1173e2b0",
            "117420b4", "117420bc", "1191ec30", "1191fd70", "11925c68", "119264a0", "119ec740",
        ):
            self.assertIn(gaddr, by_g)
        ev = self.registry["rea_layer72_evidence"]
        self.assertEqual(ev["snapshot_mode"], "fresh_partition_p9")
        self.assertEqual(ev["closed_evidence_records"], 42)
        self.assertEqual(ev["prior_partitions_validated_records"], 2375)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2417)
        self.assertEqual(ev["non_proc_slots"], ["100ee5d0", "116be3d8"])
        self.assertEqual(ev["resource_constrained_slots"], [])
        self.assertEqual(ev["closure_audit"]["recovered_functions"], 1588)
        self.assertEqual(ev["closure_audit"]["open_direct_call_edges"], 0)
        self.assertEqual(
            [(e["source"], e["target"]) for e in ev["closure_audit"]["direct_jump_edges_leaving_recovered_bodies"]],
            [("11695ee2", "11695ffa"), ("11695ee2", "11695e3c"), ("10cb0440", "10cb6520")],
        )

    def test_layer73_startup_crt_strtox_fp_contracts(self):
        by_fn = {f["address"]: f for f in self.registry["functions"]}
        layer73_addrs = [
            "1168f0d4", "1168f0f5", "1168f125", "1168f2b4", "1168f2d5", "1168f2f6", "1168f317",
            "1168f448", "1168f4c1", "1168fa89", "11690ba7", "11690e4e", "116910d4", "11691188",
            "11691202", "1169136e", "1169206a", "1169219c", "11692bae", "11692c50", "11692f24",
            "1169316a", "1169318f", "116931b4", "116931f4", "1169353d", "116936d1", "11693706",
            "11695445", "11695c75", "11695524", "11695ffa", "11696481", "116ab791", "116b89b1",
        ]
        for addr in layer73_addrs:
            self.assertIn(addr, by_fn)
        self.assertEqual(by_fn["11693706"]["bytes"], 7487)
        by_g = {g["address"]: g for g in self.registry["globals"]}
        for gaddr in ("119103d0", "11910438", "11910494", "119104b0", "1191050c"):
            self.assertIn(gaddr, by_g)
        ev = self.registry["rea_layer73_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer72_batched_p9")
        self.assertEqual(ev["new_evidence_records"], 42)
        self.assertEqual(ev["reused_layer72_evidence_records"], 42)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 84)
        self.assertEqual(ev["prior_partitions_validated_records"], 2375)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2459)
        self.assertEqual(ev["non_proc_slots"], ["11695e3c"])
        self.assertEqual(ev["resource_constrained_slots"], ["11693706"])
        self.assertEqual(ev["closure_audit"]["recovered_functions"], 1623)
        self.assertEqual(ev["closure_audit"]["open_direct_call_edges"], 0)
        self.assertEqual(
            [(e["source"], e["target"]) for e in ev["closure_audit"]["direct_jump_edges_leaving_recovered_bodies"]],
            [("11695ee2", "11695e3c"), ("10cb0440", "10cb6520")],
        )

    def test_layer74_startup_crt_strtod_setjmp_contracts(self):
        by_fn = {f["address"]: f for f in self.registry["functions"]}
        layer74_addrs = [
            "116982e7", "1169835b", "11698744", "116987e5", "116988f4", "11698930", "1169896c",
            "1169b981", "1169deb3", "1169e3f0", "1169efaa", "1169f033", "1169f050", "1169f0a0",
            "1169f1d5", "1169f284", "1169f29b", "116bf467", "116bf480", "116c0fcd", "116c1eb0",
            "116c223f", "116d7042",
        ]
        for addr in layer74_addrs:
            self.assertIn(addr, by_fn)
        self.assertEqual(by_fn["116bf467"]["tail_exit"], {"kind": "direct_jmp", "address": "116bf474", "target": "116c1eb0"})
        self.assertEqual(by_fn["116c1eb0"]["tail_exit"], {"kind": "indirect_jmp", "address": "116c1f5a", "hex": "ff6214"})
        self.assertEqual(by_fn["116d7042"]["tail_exit"], {"kind": "iat_jmp", "address": "116d7042", "iat_slot": "1172f118"})
        self.assertEqual([(r["start"], r["end"]) for r in by_fn["116c223f"]["body_ranges"]], [("116c223f", "116c2258"), ("116c2271", "116c228c")])
        by_g = {g["address"]: g for g in self.registry["globals"]}
        for gaddr in ("11910d70", "11911080", "119134e0", "1191aa30", "11925da8"):
            self.assertIn(gaddr, by_g)
        ev = self.registry["rea_layer74_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer73_batched_p9")
        self.assertEqual(ev["new_evidence_records"], 28)
        self.assertEqual(ev["reused_layer73_evidence_records"], 84)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 112)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2487)
        self.assertEqual(ev["closure_audit"]["recovered_functions"], 1646)
        self.assertEqual(ev["closure_audit"]["open_direct_call_edges"], 0)
        self.assertEqual([(e["source"], e["target"]) for e in ev["closure_audit"]["direct_jump_edges_leaving_recovered_bodies"]], [("11695ee2", "11695e3c"), ("10cb0440", "10cb6520")])

    def test_layer75_lua_core_leaf_contracts(self):
        ev = self.registry["rea_layer75_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer74_batched_p9")
        self.assertEqual(ev["closed_evidence_records"], 172)
        self.assertEqual(ev["new_evidence_records"], 60)
        self.assertEqual(ev["reused_layer74_evidence_records"], 112)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 172)
        self.assertEqual(ev["prior_partitions_validated_records"], 2375)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2547)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        fns = {f["address"]: f for f in self.registry["functions"]}
        for addr in ("10f43cb0", "10f460e0", "10f46d50", "10f47870", "10f49920", "10f4a340", "10f4df10"):
            self.assertIn(addr, fns)
            self.assertEqual(fns[addr]["calling_convention"], "cdecl")
        globs = {g["address"]: g for g in self.registry["globals"]}
        self.assertEqual(globs["11846c28"]["width"], 256)
        self.assertEqual(globs["11846ee0"]["width"], 32)
        self.assertNotIn("1183b666", globs)
        self.assertNotIn("11846d44", globs)
        self.assertEqual(ev["closure_audit"]["recovered_functions"], 1685)
        self.assertEqual(ev["closure_audit"]["open_direct_call_edges"], 0)
        self.assertEqual([(e["source"], e["target"]) for e in ev["closure_audit"]["direct_jump_edges_leaving_recovered_bodies"]], [("11695ee2", "11695e3c"), ("10cb0440", "10cb6520")])

    def test_layer76_lua_stack_api_contracts(self):
        ev = self.registry["rea_layer76_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer75_batched_p9")
        self.assertEqual(ev["closed_evidence_records"], 202)
        self.assertEqual(ev["new_evidence_records"], 30)
        self.assertEqual(ev["reused_layer75_evidence_records"], 172)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 202)
        self.assertEqual(ev["prior_partitions_validated_records"], 2375)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2577)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], [])
        fns = {f["address"]: f for f in self.registry["functions"]}
        for addr in ("10f43c00", "10f440d0", "10f449f0", "10f44ad0", "10f44ef0", "10f44f10", "112a5480", "112c0df0"):
            self.assertIn(addr, fns)
            self.assertEqual(fns[addr]["calling_convention"], "cdecl")
        globs = {g["address"]: g for g in self.registry["globals"]}
        for addr in ("1173fb20", "117e0fac", "117e0fd8", "11846b04", "1189870c", "11898714"):
            self.assertIn(addr, globs)
        self.assertEqual(ev["closure_audit"]["recovered_functions"], 1709)
        self.assertEqual(ev["closure_audit"]["open_direct_call_edges"], 0)
        self.assertEqual([(e["source"], e["target"]) for e in ev["closure_audit"]["direct_jump_edges_leaving_recovered_bodies"]], [("11695ee2", "11695e3c"), ("10cb0440", "10cb6520")])

    def test_layer77_lua_vm_gc_table_contracts(self):
        ev = self.registry["rea_layer77_evidence"]
        self.assertEqual(ev["snapshot_mode"], "extending_layer76_batched_p9")
        self.assertEqual(ev["closed_evidence_records"], 286)
        self.assertEqual(ev["new_evidence_records"], 84)
        self.assertEqual(ev["reused_layer76_evidence_records"], 202)
        self.assertEqual(ev["cumulative_validated_bundle_records"], 286)
        self.assertEqual(ev["prior_partitions_validated_records"], 2375)
        self.assertEqual(ev["cumulative_all_partitions_records"], 2661)
        self.assertEqual(ev["non_proc_slots"], [])
        self.assertEqual(ev["resource_constrained_slots"], ["10f4c0f0"])
        fns = {f["address"]: f for f in self.registry["functions"]}
        for addr in ("10f462b0", "10f48850", "10f49630", "10f4a500", "10f4ab20", "10f4c0f0", "10f4e0d0"):
            self.assertIn(addr, fns)
            self.assertEqual(fns[addr]["calling_convention"], "cdecl")
        self.assertEqual(ev["closure_audit"]["recovered_functions"], 1763)
        self.assertEqual(ev["closure_audit"]["open_direct_call_edges"], 0)
        self.assertEqual([(e["source"], e["target"]) for e in ev["closure_audit"]["direct_jump_edges_leaving_recovered_bodies"]], [("11695ee2", "11695e3c"), ("10cb0440", "10cb6520")])

    def test_tail_exit_indirect_jmp_mutations_rejected(self):
        for mutator, pattern in (
            (lambda te: te.update({"address": "116c1f58"}), "tail_exit indirect_jmp address disagrees"),
            (lambda te: te.update({"hex": "ffe0"}), "tail_exit indirect_jmp address disagrees"),
            (lambda te: te.update({"hex": "eb00"}), "tail_exit indirect_jmp opcode disagrees"),
            (lambda te: te.update({"hex": "ff6218"}), "tail_exit indirect_jmp hex disagrees"),
        ):
            registry = copy.deepcopy(self.registry)
            for fn in registry["functions"]:
                if fn["address"] == "116c1eb0":
                    mutator(fn["tail_exit"])
                    break
            with self.assertRaisesRegex(ValueError, pattern):
                contracts.validate_contracts(self.image, registry)

    def test_direct_jmp_short_mismatch_rejected(self):
        registry = copy.deepcopy(self.registry)
        for fn in registry["functions"]:
            if fn["address"] == "10cba590":
                fn["tail_exit"]["target"] = "100f1bf0"
                break
        with self.assertRaisesRegex(ValueError, "target disagrees"):
            contracts.validate_contracts(self.image, registry)

    def test_dropped_registry_category_rejected(self):
        registry = copy.deepcopy(self.registry)
        registry["functions"] = []
        with self.assertRaisesRegex(ValueError, "empty or invalid"):
            contracts.validate_contracts(self.image, registry)


if __name__ == "__main__":
    unittest.main()

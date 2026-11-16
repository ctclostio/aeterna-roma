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
        self.assertEqual(result["functions"], 669)
        self.assertEqual(result["globals"], 325)
        self.assertEqual(result["vtables"], 40)
        self.assertEqual(result["instruction_witnesses"], 596)

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
                "112a2910", "112a8ff0", "112b5730", "112baf90", "112bbd10",
                "112cf920", "112d0720", "112d2e80", "112d4cc0", "112d4de0",
                "112e32b0", "112e3c60", "112e3db0",
            },
        )
        base, sections = contracts.parse_pe32(self.image)
        expected_gaps = {
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

    def test_dropped_registry_category_rejected(self):
        registry = copy.deepcopy(self.registry)
        registry["functions"] = []
        with self.assertRaisesRegex(ValueError, "empty or invalid"):
            contracts.validate_contracts(self.image, registry)


if __name__ == "__main__":
    unittest.main()

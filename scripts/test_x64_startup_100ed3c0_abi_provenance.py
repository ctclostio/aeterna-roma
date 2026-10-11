#!/usr/bin/env python3
"""Authenticate the read-only raw ABI fixture for original x86 0x100ed3c0.

This test parses PE32 bytes as data.  It never loads the image or executes any
recovered instruction.
"""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = ROOT / "scripts" / "x64_startup_100ed3c0_abi_fixture.json"

EXPECTED_PURPOSE = (
    "Read-only byte provenance for the original x86 0x100edd70 -> "
    "0x100ed3c0 boundary; this fixture does not authorize recovered-code "
    "execution or define a native ABI."
)
EXPECTED_DLL_SHA256 = (
    "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528"
)
EXPECTED_BODY_SHA256 = (
    "b606895706a18f44d27babaef870efc60b362733d01af389b96a10e7c0e5d206"
)
EXPECTED_PACKETS = {
    "handler_registered": (
        0x100EDF20,
        "262a2edbd145895bc99d265e80cefd88f94b44056e9b4824cc20bfac5f22f32e",
        "52227b99b8d956f8926eb0f02b0f3b8c62a229dee20653b5608dc81a96e41084",
    ),
    "no_exception_handler": (
        0x100EDF73,
        "fa01caa591667fe272ef633abfc90e01d240d674b6a71aa4adb370b09d914d58",
        "76a454a3f06c1c8de33f0b3b0ab432e059de9abca52b342b8cac0e9f50198d6a",
    ),
}
EXPECTED_SOURCE_LOADS = {
    0x100EDE68: (b"\x8b\x75\x08", "esi", 8),
    0x100EDEC9: (b"\x8b\x75\x08", "esi", 8),
    0x100EDECC: (b"\x8b\x7d\x10", "edi", 16),
}
EXPECTED_CRITICAL_VAS = (
    0x100ED3C0,
    0x100ED3ED,
    0x100ED434,
    0x100ED471,
    0x100ED4B0,
    0x100ED4BA,
    0x100ED4D4,
    0x100ED4DB,
    0x100ED500,
    0x100ED50B,
    0x100ED548,
    0x100ED549,
    0x100ED54F,
)
EXPECTED_ESP_BEFORE = {
    0x100ED3C0: 0,
    0x100ED3ED: -0x90C,
    0x100ED434: -0x90C,
    0x100ED471: -0x90C,
    0x100ED4B0: -0x910,
    0x100ED4BA: -0x910,
    0x100ED4D4: -0x910,
    0x100ED4DB: -0x910,
    0x100ED500: -0x910,
    0x100ED50B: -0x910,
    0x100ED548: -0x910,
    0x100ED549: -0x90C,
    0x100ED54F: 0,
}
EXPECTED_LIMITATIONS = [
    "The full body and selected instruction semantics are authenticated without "
    "executing x86; this is not a general-purpose x86 decoder.",
    "Canonical/decompiler variable names are not evidence for stack direction, "
    "argument type, exported name, or a native x64 calling convention.",
    "The ESI and EDI source loads are authenticated prior-load observations; "
    "this fixture does not prove an unclobbered register def/use path to each push.",
]
REGISTER_NAMES = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hex_int(value: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"expected canonical hex string, got {value!r}")
    return int(value, 16)


def require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"{label} is outside the {len(data)}-byte file")


def parse_pe32(data: bytes):
    require_range(data, 0, 0x40, "DOS header")
    if data[:2] != b"MZ":
        raise ValueError("missing MZ signature")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    require_range(data, pe_offset, 24, "PE/COFF header")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")

    coff = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    if not 1 <= section_count <= 96:
        raise ValueError("implausible section count")
    require_range(data, optional, optional_size, "optional header")
    if optional_size < 96:
        raise ValueError("truncated PE32 optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    image_base = struct.unpack_from("<I", data, optional + 28)[0]

    table = optional + optional_size
    require_range(data, table, section_count * 40, "section table")
    sections = []
    for index in range(section_count):
        offset = table + index * 40
        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("non-ASCII section name") from exc
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        require_range(data, raw_offset, raw_size, f"section {name}")
        sections.append(
            {
                "name": name,
                "rva": rva,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
            }
        )
    return machine, magic, image_base, tuple(sections)


def read_va(data: bytes, image_base: int, sections, va: int, size: int):
    if va < image_base:
        raise ValueError(f"VA 0x{va:08x} precedes image base")
    rva = va - image_base
    matches = []
    for section in sections:
        delta = rva - section["rva"]
        if delta >= 0 and size <= section["raw_size"] - delta:
            matches.append((section["name"], section["raw_offset"] + delta))
    if len(matches) != 1:
        raise ValueError(f"VA 0x{va:08x} has {len(matches)} raw mappings")
    section_name, offset = matches[0]
    require_range(data, offset, size, f"VA 0x{va:08x}")
    return data[offset : offset + size], section_name, offset


def decode_push(body: bytes, offset: int):
    opcode = body[offset]
    if opcode == 0xFF:
        require_range(body, offset, 3, "push [ebp+disp8]")
        if body[offset + 1] != 0x75:
            raise ValueError("unsupported FF push in authenticated packet")
        displacement = struct.unpack_from("<b", body, offset + 2)[0]
        return 3, f"dword [ebp+0x{displacement:02x}]"
    if 0x50 <= opcode <= 0x57:
        register = REGISTER_NAMES[opcode - 0x50]
        provenance = {
            "esi": (
                "esi (earlier authenticated load from dword [ebp+0x08]; "
                "no complete def/use proof)"
            ),
            "edi": (
                "edi (earlier authenticated load from dword [ebp+0x10]; "
                "no complete def/use proof)"
            ),
        }
        if register not in provenance:
            raise ValueError(f"unsupported packet push register {register}")
        return 1, provenance[register]
    raise ValueError(f"unsupported packet push opcode 0x{opcode:02x}")


def decode_rel32_call(body: bytes, offset: int, instruction_va: int):
    require_range(body, offset, 5, "rel32 call")
    if body[offset] != 0xE8:
        raise ValueError("expected E8 rel32 call")
    displacement = struct.unpack_from("<i", body, offset + 1)[0]
    next_va = instruction_va + 5
    return displacement, next_va, next_va + displacement


def scan_large_esp_disp32(body: bytes, base_va: int, minimum: int, maximum: int):
    """Find conservative mod=disp32/SIB=[esp] encodings near the frame boundary."""
    facts = []
    for modrm_index in range(1, len(body) - 5):
        modrm = body[modrm_index]
        if (modrm & 0xC7) != 0x84 or body[modrm_index + 1] != 0x24:
            continue
        displacement = struct.unpack_from("<I", body, modrm_index + 2)[0]
        if not minimum <= displacement <= maximum:
            continue
        opcode = body[modrm_index - 1]
        if opcode == 0x8B:
            access = "read"
        elif opcode == 0x89:
            access = "write"
        elif opcode == 0xFF and ((modrm >> 3) & 7) == 6:
            access = "read"
        else:
            raise ValueError(
                f"unsupported high ESP-reference opcode 0x{opcode:02x} "
                f"at 0x{base_va + modrm_index - 1:08x}"
            )
        facts.append(
            {
                "va": base_va + modrm_index - 1,
                "opcode": f"{opcode:02x}",
                "access": access,
                "displacement": displacement,
            }
        )
    return facts


class Startup100ed3c0AbiFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not FIXTURE_PATH.is_file():
            raise AssertionError(f"fixture is missing: {FIXTURE_PATH}")
        cls.fixture_bytes = FIXTURE_PATH.read_bytes()
        cls.fixture = json.loads(cls.fixture_bytes)
        cls.assert_fixture_keys(
            cls.fixture,
            {
                "schema_version",
                "purpose",
                "original_pe",
                "callee",
                "caller_source_loads",
                "caller_packets",
                "critical_instructions",
                "large_esp_disp32_scan",
                "entry_stack_positions",
                "limitations",
            },
            "fixture",
        )
        original = cls.fixture["original_pe"]
        pe_path = ROOT / original["path"]
        if not pe_path.is_file():
            raise AssertionError(f"pinned original PE is missing: {pe_path}")
        cls.pe = pe_path.read_bytes()
        cls.machine, cls.magic, cls.image_base, cls.sections = parse_pe32(cls.pe)

    @staticmethod
    def assert_fixture_keys(value, expected, label):
        actual = set(value)
        if actual != set(expected):
            raise AssertionError(
                f"{label} keys differ: missing={set(expected) - actual}, "
                f"extra={actual - set(expected)}"
            )

    def assert_keys(self, value, expected, label):
        self.assert_fixture_keys(value, expected, label)

    def fixture_bytes_at(self, fact, byte_key="bytes"):
        body = bytes.fromhex(fact[byte_key])
        actual, section, offset = read_va(
            self.pe, self.image_base, self.sections, hex_int(fact["va"]), len(body)
        )
        self.assertEqual(section, ".text")
        self.assertEqual(offset, hex_int(fact["file_offset"]))
        self.assertEqual(actual, body)
        return body

    def test_original_pe_and_text_mapping_are_exact(self):
        fixture = self.fixture
        self.assertEqual(fixture["schema_version"], 1)
        self.assertEqual(fixture["purpose"], EXPECTED_PURPOSE)
        self.assertEqual(fixture["limitations"], EXPECTED_LIMITATIONS)

        original = fixture["original_pe"]
        self.assert_keys(
            original,
            {
                "path",
                "size",
                "sha256",
                "machine",
                "optional_magic",
                "image_base",
                "text_section",
            },
            "original_pe",
        )
        self.assertEqual(original["path"], "Total War Rome II/empire.retail.dll")
        self.assertEqual(original["size"], len(self.pe))
        self.assertEqual(original["size"], 28_278_272)
        self.assertEqual(original["sha256"], EXPECTED_DLL_SHA256)
        self.assertEqual(sha256(self.pe), EXPECTED_DLL_SHA256)
        self.assertEqual(hex_int(original["machine"]), self.machine)
        self.assertEqual(self.machine, 0x014C)
        self.assertEqual(hex_int(original["optional_magic"]), self.magic)
        self.assertEqual(self.magic, 0x010B)
        self.assertEqual(hex_int(original["image_base"]), self.image_base)
        self.assertEqual(self.image_base, 0x10000000)

        text = original["text_section"]
        self.assert_keys(
            text, {"name", "rva", "virtual_size", "raw_offset", "raw_size"},
            "text_section",
        )
        matches = [section for section in self.sections if section["name"] == ".text"]
        self.assertEqual(len(matches), 1)
        actual = matches[0]
        self.assertEqual(text["name"], actual["name"])
        for key in ("rva", "virtual_size", "raw_offset", "raw_size"):
            self.assertEqual(hex_int(text[key]), actual[key])

    def test_full_400_byte_callee_is_exact(self):
        callee = self.fixture["callee"]
        self.assert_keys(
            callee,
            {
                "va_start",
                "va_end_exclusive",
                "file_offset",
                "size",
                "hex",
                "sha256",
            },
            "callee",
        )
        start = hex_int(callee["va_start"])
        end = hex_int(callee["va_end_exclusive"])
        self.assertEqual((start, end, callee["size"]), (0x100ED3C0, 0x100ED550, 400))
        self.assertEqual(end - start, callee["size"])
        fixture_body = bytes.fromhex(callee["hex"])
        self.assertEqual(len(fixture_body), 400)
        actual, section, offset = read_va(
            self.pe, self.image_base, self.sections, start, callee["size"]
        )
        self.assertEqual((section, offset), (".text", hex_int(callee["file_offset"])))
        self.assertEqual(actual, fixture_body)
        self.assertEqual(callee["sha256"], EXPECTED_BODY_SHA256)
        self.assertEqual(sha256(actual), EXPECTED_BODY_SHA256)

    def test_caller_source_loads_are_exact(self):
        loads = self.fixture["caller_source_loads"]
        self.assertEqual(len(loads), len(EXPECTED_SOURCE_LOADS))
        self.assertEqual({hex_int(load["va"]) for load in loads}, set(EXPECTED_SOURCE_LOADS))
        for load in loads:
            self.assert_keys(
                load,
                {
                    "va",
                    "file_offset",
                    "bytes",
                    "sha256",
                    "kind",
                    "destination",
                    "ebp_offset",
                },
                "caller_source_load",
            )
            va = hex_int(load["va"])
            expected_bytes, expected_register, expected_offset = EXPECTED_SOURCE_LOADS[va]
            body = self.fixture_bytes_at(load)
            self.assertEqual(body, expected_bytes)
            self.assertEqual(sha256(body), load["sha256"])
            self.assertEqual(load["kind"], "mov_reg_ebp_disp8")
            self.assertEqual(body[0], 0x8B)
            modrm = body[1]
            self.assertEqual((modrm >> 6, modrm & 7), (1, 5))
            destination = REGISTER_NAMES[(modrm >> 3) & 7]
            displacement = struct.unpack_from("<b", body, 2)[0]
            self.assertEqual((destination, displacement), (expected_register, expected_offset))
            self.assertEqual(load["destination"], destination)
            self.assertEqual(load["ebp_offset"], displacement)

    def test_caller_packets_rel32_and_grouped_cleanup_are_exact(self):
        packets = self.fixture["caller_packets"]
        self.assertEqual(len(packets), 2)
        self.assertEqual({packet["branch"] for packet in packets}, set(EXPECTED_PACKETS))
        for packet in packets:
            self.assert_keys(
                packet,
                {
                    "branch",
                    "va_start",
                    "va_end_exclusive",
                    "file_offset",
                    "size",
                    "hex",
                    "sha256",
                    "pushes",
                    "call",
                    "window_through_cleanup",
                    "grouped_cleanup",
                },
                "caller_packet",
            )
            expected_start, expected_hash, expected_window_hash = EXPECTED_PACKETS[
                packet["branch"]
            ]
            start = hex_int(packet["va_start"])
            self.assertEqual(start, expected_start)
            self.assertEqual(packet["size"], 13)
            self.assertEqual(hex_int(packet["va_end_exclusive"]), start + 13)
            packet_bytes = bytes.fromhex(packet["hex"])
            self.assertEqual(len(packet_bytes), 13)
            actual, section, offset = read_va(
                self.pe, self.image_base, self.sections, start, 13
            )
            self.assertEqual((section, offset), (".text", hex_int(packet["file_offset"])))
            self.assertEqual(actual, packet_bytes)
            self.assertEqual(packet["sha256"], expected_hash)
            self.assertEqual(sha256(actual), expected_hash)

            cursor = 0
            self.assertEqual(len(packet["pushes"]), 4)
            for order, push in enumerate(packet["pushes"], start=1):
                self.assert_keys(
                    push,
                    {
                        "va",
                        "bytes",
                        "source",
                        "machine_order",
                        "callee_position",
                    },
                    "packet_push",
                )
                length, source = decode_push(packet_bytes, cursor)
                instruction = packet_bytes[cursor : cursor + length]
                self.assertEqual(hex_int(push["va"]), start + cursor)
                self.assertEqual(bytes.fromhex(push["bytes"]), instruction)
                self.assertEqual(push["source"], source)
                self.assertEqual(push["machine_order"], order)
                self.assertEqual(push["callee_position"], 5 - order)
                cursor += length
            self.assertEqual(cursor, 8)

            call = packet["call"]
            self.assert_keys(
                call, {"va", "bytes", "next_va", "rel32", "target_va"},
                "packet_call",
            )
            call_va = start + cursor
            displacement, next_va, target_va = decode_rel32_call(
                packet_bytes, cursor, call_va
            )
            self.assertEqual(hex_int(call["va"]), call_va)
            self.assertEqual(bytes.fromhex(call["bytes"]), packet_bytes[cursor:])
            self.assertEqual(call["rel32"], displacement)
            self.assertEqual(hex_int(call["next_va"]), next_va)
            self.assertEqual(hex_int(call["target_va"]), target_va)
            self.assertEqual(target_va, 0x100ED3C0)

            window = packet["window_through_cleanup"]
            self.assert_keys(
                window,
                {
                    "va_start",
                    "va_end_exclusive",
                    "file_offset",
                    "size",
                    "hex",
                    "sha256",
                },
                "window_through_cleanup",
            )
            self.assertEqual(hex_int(window["va_start"]), start)
            self.assertEqual(window["size"], 33)
            self.assertEqual(hex_int(window["va_end_exclusive"]), start + 33)
            window_bytes = bytes.fromhex(window["hex"])
            actual_window, section, window_offset = read_va(
                self.pe, self.image_base, self.sections, start, 33
            )
            self.assertEqual(
                (section, window_offset), (".text", hex_int(window["file_offset"]))
            )
            self.assertEqual(actual_window, window_bytes)
            self.assertEqual(window["sha256"], expected_window_hash)
            self.assertEqual(sha256(actual_window), expected_window_hash)

            cleanup = packet["grouped_cleanup"]
            self.assert_keys(
                cleanup,
                {
                    "continuation_va",
                    "continuation_file_offset",
                    "continuation_size",
                    "continuation_hex",
                    "continuation_sha256",
                    "later_calls",
                    "cleanup",
                    "target_packet_bytes",
                    "later_push_bytes",
                    "total_cleanup_bytes",
                },
                "grouped_cleanup",
            )
            continuation_va = hex_int(cleanup["continuation_va"])
            self.assertEqual(continuation_va, next_va)
            self.assertEqual(cleanup["continuation_size"], 20)
            continuation = bytes.fromhex(cleanup["continuation_hex"])
            self.assertEqual(len(continuation), 20)
            actual_continuation, section, continuation_offset = read_va(
                self.pe, self.image_base, self.sections, continuation_va, 20
            )
            self.assertEqual(
                (section, continuation_offset),
                (".text", hex_int(cleanup["continuation_file_offset"])),
            )
            self.assertEqual(actual_continuation, continuation)
            self.assertEqual(sha256(continuation), cleanup["continuation_sha256"])
            self.assertEqual(window_bytes, packet_bytes + continuation)

            continuation_cursor = 0
            later_push_bytes = 0
            expected_later_targets = (0x101136D0, 0x101150F0)
            self.assertEqual(len(cleanup["later_calls"]), 2)
            for later, expected_target in zip(
                cleanup["later_calls"], expected_later_targets, strict=True
            ):
                self.assert_keys(
                    later,
                    {
                        "push_va",
                        "push_bytes",
                        "pushed_bytes",
                        "call_va",
                        "call_bytes",
                        "rel32",
                        "target_va",
                    },
                    "later_call",
                )
                push_opcode = continuation[continuation_cursor]
                if push_opcode == 0x6A:
                    push_length = 2
                elif push_opcode == 0x68:
                    push_length = 5
                else:
                    self.fail(f"unsupported later push opcode 0x{push_opcode:02x}")
                push_body = continuation[
                    continuation_cursor : continuation_cursor + push_length
                ]
                self.assertEqual(
                    hex_int(later["push_va"]), continuation_va + continuation_cursor
                )
                self.assertEqual(bytes.fromhex(later["push_bytes"]), push_body)
                self.assertEqual(later["pushed_bytes"], 4)
                later_push_bytes += later["pushed_bytes"]
                continuation_cursor += push_length

                later_call_va = continuation_va + continuation_cursor
                displacement, later_next, later_target = decode_rel32_call(
                    continuation, continuation_cursor, later_call_va
                )
                self.assertEqual(hex_int(later["call_va"]), later_call_va)
                self.assertEqual(
                    bytes.fromhex(later["call_bytes"]),
                    continuation[continuation_cursor : continuation_cursor + 5],
                )
                self.assertEqual(later["rel32"], displacement)
                self.assertEqual(hex_int(later["target_va"]), later_target)
                self.assertEqual(later_target, expected_target)
                self.assertEqual(later_next, later_call_va + 5)
                continuation_cursor += 5

            cleanup_instruction = cleanup["cleanup"]
            self.assert_keys(
                cleanup_instruction,
                {"va", "bytes", "operation", "immediate"},
                "cleanup_instruction",
            )
            cleanup_body = continuation[continuation_cursor:]
            self.assertEqual(cleanup_body[:2], b"\x83\xc4")
            self.assertEqual(len(cleanup_body), 3)
            self.assertEqual(
                hex_int(cleanup_instruction["va"]),
                continuation_va + continuation_cursor,
            )
            self.assertEqual(bytes.fromhex(cleanup_instruction["bytes"]), cleanup_body)
            self.assertEqual(cleanup_instruction["operation"], "add_esp_imm8")
            self.assertEqual(cleanup_instruction["immediate"], cleanup_body[2])
            self.assertEqual(cleanup["target_packet_bytes"], 4 * 4)
            self.assertEqual(cleanup["later_push_bytes"], later_push_bytes)
            self.assertEqual(cleanup["later_push_bytes"], 8)
            self.assertEqual(
                cleanup["total_cleanup_bytes"],
                cleanup["target_packet_bytes"] + cleanup["later_push_bytes"],
            )
            self.assertEqual(
                cleanup_instruction["immediate"], cleanup["total_cleanup_bytes"]
            )

    def test_critical_disassembly_and_entry_esp_normalization(self):
        facts = self.fixture["critical_instructions"]
        self.assertEqual(tuple(hex_int(fact["va"]) for fact in facts), EXPECTED_CRITICAL_VAS)
        callee_start = hex_int(self.fixture["callee"]["va_start"])
        callee_bytes = bytes.fromhex(self.fixture["callee"]["hex"])
        position_names = {
            4: "caller_position_1",
            8: "caller_position_2",
            12: "caller_position_3",
            16: "caller_position_4",
        }
        for fact in facts:
            va = hex_int(fact["va"])
            body = bytes.fromhex(fact["bytes"])
            actual, section, offset = read_va(
                self.pe, self.image_base, self.sections, va, len(body)
            )
            self.assertEqual(section, ".text")
            self.assertEqual(offset, hex_int(fact["file_offset"]))
            self.assertEqual(actual, body)
            relative = va - callee_start
            self.assertEqual(callee_bytes[relative : relative + len(body)], body)
            self.assertEqual(fact["esp_delta_before"], EXPECTED_ESP_BEFORE[va])

            kind = fact["kind"]
            common = {"va", "file_offset", "bytes", "kind", "esp_delta_before"}
            if kind in {"sub_esp_imm32", "add_esp_imm32"}:
                self.assert_keys(
                    fact,
                    common | {"immediate", "stack_effect", "esp_delta_after"},
                    kind,
                )
                expected_prefix = b"\x81\xec" if kind.startswith("sub") else b"\x81\xc4"
                self.assertEqual(body[:2], expected_prefix)
                immediate = struct.unpack_from("<I", body, 2)[0]
                effect = -immediate if kind.startswith("sub") else immediate
                self.assertEqual(fact["immediate"], immediate)
                self.assertEqual(fact["stack_effect"], effect)
                self.assertEqual(
                    fact["esp_delta_after"], fact["esp_delta_before"] + effect
                )
            elif kind in {"esp_disp32", "push_esp_disp32"}:
                extra = {
                    "access",
                    "displacement",
                    "entry_esp_offset",
                    "classification",
                }
                if kind == "push_esp_disp32":
                    extra.add("stack_effect")
                    self.assertEqual(body[:3], b"\xff\xb4\x24")
                    self.assertEqual(fact["stack_effect"], -4)
                else:
                    self.assertIn(body[:3], (b"\x8b\x84\x24", b"\x8b\x94\x24", b"\x89\x84\x24", b"\x89\x8c\x24"))
                self.assert_keys(fact, common | extra, kind)
                displacement = struct.unpack_from("<I", body, 3)[0]
                self.assertEqual(fact["displacement"], displacement)
                entry_offset = fact["esp_delta_before"] + displacement
                self.assertEqual(fact["entry_esp_offset"], entry_offset)
                expected_access = "write" if body[0] == 0x89 else "read"
                self.assertEqual(fact["access"], expected_access)
                expected_class = position_names.get(entry_offset, "local")
                self.assertEqual(fact["classification"], expected_class)
            elif kind == "esp_disp32_imm32":
                self.assert_keys(
                    fact,
                    common
                    | {
                        "access",
                        "displacement",
                        "immediate",
                        "entry_esp_offset",
                        "classification",
                    },
                    kind,
                )
                self.assertEqual(body[:3], b"\xc7\x84\x24")
                displacement, immediate = struct.unpack_from("<II", body, 3)
                self.assertEqual(fact["displacement"], displacement)
                self.assertEqual(fact["immediate"], immediate)
                self.assertEqual(fact["access"], "write")
                entry_offset = fact["esp_delta_before"] + displacement
                self.assertEqual(fact["entry_esp_offset"], entry_offset)
                self.assertEqual(fact["classification"], "local")
            elif kind in {"push_esi", "pop_esi"}:
                self.assert_keys(
                    fact,
                    common | {"stack_effect", "esp_delta_after", "classification"},
                    kind,
                )
                expected_body = b"\x56" if kind == "push_esi" else b"\x5e"
                expected_effect = -4 if kind == "push_esi" else 4
                expected_class = (
                    "delayed_saved_register"
                    if kind == "push_esi"
                    else "restore_saved_register"
                )
                self.assertEqual(body, expected_body)
                self.assertEqual(fact["stack_effect"], expected_effect)
                self.assertEqual(fact["classification"], expected_class)
                self.assertEqual(
                    fact["esp_delta_after"], fact["esp_delta_before"] + expected_effect
                )
            elif kind == "ret":
                self.assert_keys(
                    fact,
                    common | {"ret_immediate", "callee_cleanup_bytes"},
                    kind,
                )
                self.assertEqual(body, b"\xc3")
                self.assertEqual(fact["ret_immediate"], 0)
                self.assertEqual(fact["callee_cleanup_bytes"], 0)
            else:
                self.fail(f"unsupported critical instruction kind {kind!r}")

    def test_large_esp_reference_scan_and_position_summary_are_exact(self):
        scan = self.fixture["large_esp_disp32_scan"]
        self.assert_keys(
            scan, {"minimum_displacement", "maximum_displacement", "references"},
            "large_esp_disp32_scan",
        )
        self.assertEqual(scan["minimum_displacement"], 0x900)
        self.assertEqual(scan["maximum_displacement"], 0x1000)
        body = bytes.fromhex(self.fixture["callee"]["hex"])
        base = hex_int(self.fixture["callee"]["va_start"])
        actual = scan_large_esp_disp32(
            body, base, scan["minimum_displacement"], scan["maximum_displacement"]
        )
        expected = []
        for reference in scan["references"]:
            self.assert_keys(
                reference,
                {
                    "va",
                    "opcode",
                    "access",
                    "displacement",
                    "esp_delta_before",
                    "entry_esp_offset",
                },
                "large_esp_reference",
            )
            va = hex_int(reference["va"])
            self.assertEqual(reference["esp_delta_before"], EXPECTED_ESP_BEFORE[va])
            self.assertEqual(
                reference["entry_esp_offset"],
                reference["esp_delta_before"] + reference["displacement"],
            )
            expected.append(
                {
                    "va": va,
                    "opcode": reference["opcode"],
                    "access": reference["access"],
                    "displacement": reference["displacement"],
                }
            )
        self.assertEqual(actual, expected)

        reads_by_entry_offset = {}
        reference_by_va = {hex_int(item["va"]): item for item in scan["references"]}
        for item in actual:
            fixture_item = reference_by_va[item["va"]]
            if item["access"] == "read":
                reads_by_entry_offset.setdefault(
                    fixture_item["entry_esp_offset"], []
                ).append(item["va"])

        positions = self.fixture["entry_stack_positions"]
        self.assertEqual([position["position"] for position in positions], [1, 2, 3, 4])
        for position in positions:
            self.assert_keys(
                position, {"position", "entry_esp_offset", "read_vas"},
                "entry_stack_position",
            )
            expected_offset = position["position"] * 4
            self.assertEqual(position["entry_esp_offset"], expected_offset)
            self.assertEqual(
                [hex_int(va) for va in position["read_vas"]],
                reads_by_entry_offset.get(expected_offset, []),
            )
        self.assertEqual(positions[1]["read_vas"], [])
        self.assertEqual(positions[3]["read_vas"], [])


if __name__ == "__main__":
    unittest.main()

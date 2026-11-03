#!/usr/bin/env python3
"""Fail-closed source and integration gate for original handler 0x100e9340."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100e9340_run_handler_transcript"
LIBRARY = "rome2_startup_100e9340_handler_transcript_runtime"
TEST_TARGET = "rome2_startup_100e9340_handler_transcript_tests"
HEADLESS = "rome2_headless64"
PREDECESSOR_LIBRARY = "rome2_startup_100e8580_handler_transcript_runtime"
OUTER_INITIALIZER_LIBRARY = "rome2_startup_100ea4d0_injected_runtime"
HANDLER_92C0_LIBRARY = "rome2_startup_100e92c0_handler_transcript_runtime"
HANDLER_87A0_LIBRARY = "rome2_startup_100e87a0_handler_transcript_runtime"
SUFFIX_FUNCTION = "rome2_port_100df270_run_suffix_transcript"
SUFFIX_LIBRARY = "rome2_startup_100df270_suffix_transcript_runtime"
PREFIX_FUNCTION = "rome2_port_100df270_run_platform_prefix_transcript"
PARENT_FUNCTION = "rome2_port_100ed3c0_run_empty_preloop"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
PREFIX_LIBRARY = "rome2_startup_100df270_platform_prefix_transcript_runtime"

EXPECTED_HEADLESS_SIZE = 163368
EXPECTED_HEADLESS_SHA256 = (
    "083b4135c0d5bdd68a2485f917c051661da2f2230b0226c0935e657f9f0bf494"
)
EXPECTED_CMAKE_ADD_TEST_COUNT = 194
EXPECTED_CMAKE_SIZE = 185_731
EXPECTED_CMAKE_SHA256 = (
    "869669615b762f48b4eeaacabc157e58447e079d0ad379c490da9e95d298d56b"
)

EXPECTED_HEADER_SHA256 = (
    "03f7a477e4a5ee5b0aa2dc77b70ba0bc492dbe6531fd505f9c455ded3f8d75a9"
)
EXPECTED_SOURCE_SHA256 = (
    "ca6e27ef29f255795567784c354551c3dc114d223aea9611e62930433cd4aec5"
)
EXPECTED_TEST_SHA256 = (
    "eebc924d6f95e842a11756f7f0bc4e2bbec75186ad3fa38562d02f5c34528455"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "5921f15f2b14470d63dec8299f7eefc5ade7cb2d0726b1413a90921f56adef34"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "ffb6d5ef59624b36b1672a9e47e2bb9441977ce32dc171ced24c91e8d206cd8f"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "0dd1bb898e85c084b3233d7e233464c4b0231d97d8246e3586e77e0d86c67439"
)
EXPECTED_PROVENANCE_SHA256 = (
    "f17a82848edd7d02957dbd21a892faf6e6ba553a7d9ad26a5cef74e2e31757a2"
)

TRANSCRIPT_TEST_NAMES = (
    "startup_100e9340_handler_transcript_provenance",
    "startup_100e9340_handler_transcript_static_gate_unit",
    "startup_100e9340_handler_transcript_static_gate",
    "startup_100e9340_handler_transcript_runtime",
    "startup_100e9340_handler_transcript_post_pe_gate",
    "x64_bootstrap_load_after_startup_100e9340_handler_transcript",
)

# This prefix is historical and remains frozen.  Later 0x100e92c0/0x100e87a0
# milestones extend only SUCCESSOR_TAIL_LIBRARIES and TERMINAL_RELOAD_FIXTURE.
FROZEN_HEADLESS_LINK_PREFIX = (
    "rome2_guest32_runtime",
    "rome2_startup_100f1aa0_empty_runtime",
    "rome2_startup_safe_seams_runtime",
    "rome2_startup_100df270_headless_runtime",
    "rome2_startup_100f2750_nonalloc_runtime",
    "rome2_startup_100e8240_fastpath_runtime",
    "rome2_startup_100e2460_append_prefix_runtime",
    "rome2_startup_100e2460_preallocated_branch_runtime",
    "rome2_startup_100e2460_capacity_zero_branch_runtime",
    "rome2_startup_100e2460_growth_branch_runtime",
    "rome2_startup_100e2460_router_runtime",
    "rome2_startup_100e8d00_handler_transcript_runtime",
    "rome2_startup_100e85d0_normal_adapter_runtime",
    PREDECESSOR_LIBRARY,
)
SUCCESSOR_TAIL_LIBRARIES = (
    OUTER_INITIALIZER_LIBRARY,
    LIBRARY,
    HANDLER_92C0_LIBRARY,
    HANDLER_87A0_LIBRARY,
    SUFFIX_LIBRARY,
    PREFIX_LIBRARY,
    "rome2_startup_100ed3c0_empty_preloop_runtime",
    "rome2_startup_100ed471_ordinary_lifecycle_runtime",
)
HEADLESS_LINK_LIBRARIES = FROZEN_HEADLESS_LINK_PREFIX + SUCCESSOR_TAIL_LIBRARIES
PREDECESSOR_RELOAD_FIXTURE = (
    "startup_100ea4d0_injected_reload_verified"
)
TERMINAL_RELOAD_FIXTURE = (
    "startup_100ed471_ordinary_lifecycle_reload_verified"
)

FROZEN_HANDLER_TOKEN_PREFIX = (
    "initializer-handler-100e8d00=injected-transcript-complete",
    "initializer-handler-100e85d0=effect-free-complete",
    "initializer-handler-100e8580=injected-transcript-complete",
)
SUCCESSOR_HANDLER_TOKEN_TAIL = (
    "initializer-100ea4d0=injected-complete",
    "initializer-handler-100e9340=injected-transcript-complete",
    "initializer-handler-100e92c0=injected-transcript-complete",
    "initializer-handler-100e87a0=injected-transcript-complete",
    "startup-100df270-suffix=injected-transcript-complete",
    "startup-100df270-platform-prefix=injected-call-shape-complete",
    "startup-100ed3c0-empty-preloop=injected-composition-complete",
    "startup-100ed471-ordinary-lifecycle=injected-bounded-complete",
)

HEADLESS_SELECTED_DWORD = "0x89abcdef"
HEADLESS_SELECTED_BYTE = "0xa5"

BANNED_IDENTIFIERS = {
    "CreateProcessA", "CreateProcessW", "DispatchMessageA",
    "DispatchMessageW", "EnterCriticalSection", "FreeLibrary",
    "GetCurrentThreadId", "GetMessageA", "GetMessageW",
    "GetModuleHandleA", "GetModuleHandleW", "GetProcAddress", "HeapAlloc",
    "HeapFree", "InitializeCriticalSection", "InitializeCriticalSectionAndSpinCount",
    "LeaveCriticalSection", "LoadLibraryA", "LoadLibraryW", "PeekMessageA",
    "PeekMessageW", "PostMessageA", "PostMessageW", "SendMessageA",
    "SendMessageW", "TlsAlloc", "TlsFree", "TlsGetValue", "TlsSetValue",
    "TranslateMessage", "VirtualAlloc", "VirtualFree", "calloc", "dlopen",
    "dlsym", "free", "malloc", "realloc", "system",
}

STEP_KINDS = (
    "ROME2_100E9340_STEP_LOOKUP_DWORD_12",
    "ROME2_100E9340_STEP_LOOKUP_BYTE_49",
    "ROME2_100E9340_STEP_CALL_112E1830",
    "ROME2_100E9340_STEP_CALL_112CBBB0",
)

SOURCE_STEP_BLOCKS = (
    "rome2_100e9340_clear_step(&step);"
    "step.kind=ROME2_100E9340_STEP_LOOKUP_DWORD_12;"
    "step.argument_count=UINT32_C(1);"
    "step.argument0=ROME2_PORT_100E9340_SELECTOR_DWORD;"
    "step.result_width_bytes=UINT32_C(4);"
    "step.result_u32=effects_snapshot.selected_dword_12;"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
    "rome2_100e9340_clear_step(&step);"
    "step.kind=ROME2_100E9340_STEP_LOOKUP_BYTE_49;"
    "step.argument_count=UINT32_C(1);"
    "step.argument0=ROME2_PORT_100E9340_SELECTOR_BYTE;"
    "step.result_width_bytes=UINT32_C(1);"
    "step.result_u32=effects_snapshot.selected_byte_49;"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
    "rome2_100e9340_clear_step(&step);"
    "step.kind=ROME2_100E9340_STEP_CALL_112E1830;"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
    "rome2_100e9340_clear_step(&step);"
    "step.kind=ROME2_100E9340_STEP_CALL_112CBBB0;"
    "step.argument_count=UINT32_C(3);"
    "step.argument0=effects_snapshot.selected_dword_12;"
    "step.argument1=patched_receiver;"
    "step.argument2=UINT32_C(0);"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
)


def _decode_utf8(path: pathlib.Path) -> tuple[str | None, list[str]]:
    try:
        return path.read_bytes().decode("utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"cannot read strict UTF-8: {error}"]


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _token_digest(code: str) -> str:
    return _sha256(_compact(code).encode("utf-8"))


def _require_once(
    compact: str,
    fragment: str,
    findings: list[str],
    message: str,
) -> None:
    if compact.count(fragment) != 1:
        findings.append(message)


def _banned_findings(code: str) -> list[str]:
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    findings = [
        f"forbidden native/TLS/global/platform identifier: {identifier}"
        for identifier in sorted(BANNED_IDENTIFIERS & identifiers)
    ]
    if re.search(r"\b_?DAT_[0-9A-Fa-f]+\b", code):
        findings.append("original global identifier is forbidden")
    return findings


def _function_body(code: str, function: str) -> str | None:
    match = re.search(
        rf"\b{re.escape(function)}\s*\([^;]*?\)\s*\{{",
        code,
        flags=re.S,
    )
    if match is None:
        return None
    opening = code.find("{", match.start())
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return code[opening + 1:index]
    return None


def inspect_header_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _sha256(text.encode("utf-8")) != EXPECTED_HEADER_SHA256:
        findings.append("header exact digest changed")
    if _token_digest(code) != EXPECTED_HEADER_TOKEN_SHA256:
        findings.append("header executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != ["guest32.h"]:
        findings.append("transcript header must reuse only the guest32 contract")

    for fragment, message in (
        ("#defineROME2_PORT_100E9340_ALUINT8_C(1)", "AL constant changed"),
        ("#defineROME2_PORT_100E9340_STEP_COUNTUINT32_C(4)",
         "four-step count changed"),
        ("#defineROME2_PORT_100E9340_SELECTOR_DWORDUINT32_C(0x12)",
         "selector 0x12 changed"),
        ("#defineROME2_PORT_100E9340_SELECTOR_BYTEUINT32_C(0x49)",
         "selector 0x49 changed"),
        ("#defineROME2_PORT_100E9340_TARGET_112E1830UINT32_C(0x112e1830)",
         "getter evidence identity changed"),
        ("#defineROME2_PORT_100E9340_TARGET_112CBBB0UINT32_C(0x112cbbb0)",
         "helper evidence identity changed"),
    ):
        _require_once(compact, fragment, findings, message)

    enum_body = (
        "typedefenumrome2_100e9340_step_kind{"
        + ",".join(f"{kind}={index}" for index, kind in enumerate(STEP_KINDS, 1))
        + "}rome2_100e9340_step_kind;"
    )
    _require_once(compact, enum_body, findings, "typed four-step order changed")
    step_type = (
        "typedefstructrome2_100e9340_step{"
        "rome2_100e9340_step_kindkind;uint32_targument_count;"
        "uint32_targument0;uint32_targument1;uint32_targument2;"
        "uint32_tresult_width_bytes;uint32_tresult_u32;}"
        "rome2_100e9340_step;"
    )
    _require_once(compact, step_type, findings, "typed step/result layout changed")
    callback_type = (
        "typedefvoid(*rome2_100e9340_emit_step_fn)("
        "void*context,rome2_100e9340_stepstep);"
    )
    _require_once(compact, callback_type, findings, "by-value callback contract changed")
    effects_type = (
        "typedefstructrome2_100e9340_transcript_effects{"
        "rome2_100e9340_emit_step_fnemit_step;void*context;"
        "uint32_tselected_dword_12;uint32_tselected_byte_49;}"
        "rome2_100e9340_transcript_effects;"
    )
    _require_once(
        compact, effects_type, findings,
        "complete injected lookup-result effects layout changed",
    )
    declaration = (
        "rome2_guest_status" + FUNCTION + "("
        "rome2_guest_addr32guest_receiver,rome2_guest_addr32guest_argument,"
        "constrome2_100e9340_transcript_effects*effects,uint8_t*return_al_out);"
    )
    _require_once(compact, declaration, findings, "public transcript API changed")
    findings.extend(_banned_findings(code))
    return sorted(set(findings))


def inspect_source_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _sha256(text.encode("utf-8")) != EXPECTED_SOURCE_SHA256:
        findings.append("source exact digest changed")
    if _token_digest(code) != EXPECTED_SOURCE_TOKEN_SHA256:
        findings.append("source executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != [
        "ported_100e9340_handler_transcript.h", "stddef.h", "stdint.h"
    ]:
        findings.append("source include containment changed")
    findings.extend(_banned_findings(code))
    if "#pragmacomment(lib" in compact.lower():
        findings.append("native library autolinking is forbidden")

    for fragment, message in (
        ("status=rome2_100e9340_validate_object(effects,sizeof(*effects));",
         "effects borrowed-object validation changed"),
        ("status=rome2_100e9340_validate_object(return_al_out,"
         "sizeof(*return_al_out));", "AL borrowed-object validation changed"),
        ("(uintptr_t)effects%_Alignof(rome2_100e9340_transcript_effects)!=0U||"
         "rome2_100e9340_ranges_overlap(effects,sizeof(*effects),"
         "return_al_out,sizeof(*return_al_out))",
         "effects alignment/output-alias rejection changed"),
        ("effects_snapshot=*effects;", "complete effects snapshot changed"),
        ("effects_snapshot.emit_step==NULL||effects_snapshot.context==NULL||"
         "effects_snapshot.selected_byte_49>UINT32_C(0xff)",
         "callback/context/byte validation changed"),
        ("(void)guest_argument;", "ignored stack-argument contract changed"),
        ("patched_receiver=(guest_receiver.value&UINT32_C(0xffffff00))|"
         "effects_snapshot.selected_byte_49;",
         "receiver low-byte replacement changed"),
    ):
        if fragment not in compact:
            findings.append(message)

    kinds = tuple(re.findall(
        r"step\.kind\s*=\s*(ROME2_100E9340_STEP_[A-Z0-9_]+)", code
    ))
    if kinds != STEP_KINDS:
        findings.append("source four-step order changed")
    if compact.count(
        "effects_snapshot.emit_step(effects_snapshot.context,step);"
    ) != 4:
        findings.append("source must emit exactly four snapshotted steps")
    if compact.count("rome2_100e9340_clear_step(&step);") != 4:
        findings.append("every step must clear every unused field")

    positions = []
    previous = -1
    for index, block in enumerate(SOURCE_STEP_BLOCKS, 1):
        position = compact.find(block)
        positions.append(position)
        if position < 0:
            findings.append(f"typed step {index} arguments/result changed")
        elif position <= previous:
            findings.append("typed step blocks are not in original order")
        previous = position

    output = "*return_al_out=ROME2_PORT_100E9340_AL;"
    if compact.count(output) != 1:
        findings.append("AL must have exactly one publication")
    elif positions[-1] < 0 or compact.find(output) <= positions[-1]:
        findings.append("AL must publish only after helper step four")
    if compact.count(output + "returnROME2_GUEST_OK;") != 1:
        findings.append("success must immediately follow final AL publication")

    snapshot_position = compact.find("effects_snapshot=*effects;")
    first_emit = compact.find(
        "effects_snapshot.emit_step(effects_snapshot.context,step);"
    )
    alias_position = compact.find("rome2_100e9340_ranges_overlap(")
    if not (0 <= alias_position < snapshot_position < first_emit):
        findings.append("alias validation and snapshot must precede every effect")
    if "effects->" in code:
        findings.append("callbacks and results must be read only from the snapshot")
    if code.count("guest_argument") != 2:
        findings.append("stack argument must remain opaque and ignored")
    if re.search(
        r"\([^)]*\*[^)]*\)\s*(?:guest_receiver|guest_argument|patched_receiver)",
        code,
    ):
        findings.append("guest identities must never be cast to host pointers")
    for target in ("112e1830", "112cbbb0", "1136a220", "10113620"):
        if re.search(rf"\b(?:FUN_|decomp_fn_)?{target}\s*\(", code, flags=re.I):
            findings.append(f"recovered/native call is forbidden: {target}")
    return sorted(set(findings))


def inspect_test_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if _sha256(text.encode("utf-8")) != EXPECTED_TEST_SHA256:
        findings.append("runtime oracle exact digest changed")
    if _token_digest(code) != EXPECTED_TEST_TOKEN_SHA256:
        findings.append("runtime oracle executable-token digest changed")
    includes = re.findall(
        r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, flags=re.MULTILINE
    )
    if includes != [
        "ported_100e9340_handler_transcript.h", "stddef.h", "stdint.h",
        "stdio.h", "string.h",
    ]:
        findings.append("runtime oracle include containment changed")
    findings.extend(_banned_findings(code))

    required = (
        ("#defineROME2_TEST_STEP_COUNTUINT32_C(4)",
         "runtime four-step oracle changed"),
        ("#defineROME2_TEST_SENTINELUINT8_C(0xcc)",
         "runtime unpublished-AL sentinel changed"),
        ("*trace->return_al!=ROME2_TEST_SENTINEL",
         "callbacks must observe unpublished AL"),
        ("(receiver&UINT32_C(0xffffff00))|selected_byte",
         "runtime receiver-low-byte oracle changed"),
        ("UINT32_C(1),UINT32_C(1),UINT32_C(0x12)",
         "runtime selector-0x12 step changed"),
        ("UINT32_C(2),UINT32_C(1),UINT32_C(0x49)",
         "runtime selector-0x49 step changed"),
        ("UINT32_C(3),UINT32_C(0)", "runtime getter step changed"),
        ("UINT32_C(4),UINT32_C(3),selected_dword,patched_receiver",
         "runtime helper-argument step changed"),
        ("trace->effects.emit_step=rome2_test_unexpected_emit;"
         "trace->effects.context=&trace->unexpected_call_count;"
         "trace->effects.selected_dword_12=UINT32_C(0x01020304);"
         "trace->effects.selected_byte_49=UINT32_C(0x5a);",
         "runtime complete-effects snapshot mutant changed"),
        ("UINT32_C(0xffffffff),UINT32_C(0xffffffff),"
         "UINT32_C(0x80000000),UINT32_C(0)",
         "runtime all-bit/signed-dword boundary changed"),
        ("UINT32_C(0xabcdef00),UINT32_C(0x80000000),"
         "UINT32_C(0x7fffffff),UINT32_C(0xff)",
         "runtime maximum-byte boundary changed"),
        ("UINTPTR_MAX-(uintptr_t)sizeof(rome2_100e9340_transcript_effects)+"
         "(uintptr_t)2U", "runtime host-overflow case changed"),
        ("storage.bytes+1U", "runtime misalignment case changed"),
        ("(uint8_t*)(void*)&trace.effects.selected_byte_49",
         "runtime effects/output alias case changed"),
        ("trace.effects.emit_step=NULL", "runtime null-callback case changed"),
        ("trace.effects.context=NULL", "runtime null-context case changed"),
        ("trace.effects.selected_byte_49=UINT32_C(0x100)",
         "runtime wide-byte rejection changed"),
    )
    for fragment, message in required:
        if fragment not in compact:
            findings.append(message)
    for function in (
        "rome2_test_success_and_exact_order",
        "rome2_test_receiver_boundaries_and_ignored_argument",
        "rome2_test_effects_snapshot_is_complete",
        "rome2_test_invalid_borrowed_objects",
        "rome2_test_invalid_effect_values",
    ):
        if compact.count(function + "(") != 2:
            findings.append(f"runtime coverage function changed: {function}")
    if compact.count(FUNCTION + "(") != 2:
        findings.append("runtime must exercise success and precommit paths")
    if text.count("100e9340 handler transcript: ok") != 1:
        findings.append("runtime success marker changed")
    return sorted(set(findings))


def inspect_provenance_bytes(data: bytes) -> list[str]:
    findings: list[str] = []
    if _sha256(data) != EXPECTED_PROVENANCE_SHA256:
        findings.append("provenance exact digest changed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        return findings + [f"provenance is not strict UTF-8: {error}"]
    compact = _compact(text)
    required = (
        "FUNCTION_VA=0x100E9340",
        "FUNCTION_SHA256=\"52f130537cbe5ce500544e8f55fc50daa848c9202bd515f11cb173a6a602d1b6\"",
        "FUNCTION_RAW_OFFSET=0x000E8740",
        "DIRECT_CALL_OFFSETS=(48,62)",
        "DIRECT_CALL_TARGETS=(0x112E1830,0x112CBBB0)",
        "GLOBAL_ROOT_VA=0x119F3140",
        "GLOBAL_SERVICE_OFFSET=0x874",
        "LOOKUP_DWORD_SELECTOR=0x12",
        "LOOKUP_BYTE_SELECTOR=0x49",
        "VTABLE_PAIR_VA=0x1173F224",
        "VTABLE_PAIR_BYTES=bytes.fromhex(\"00190e1040930e10\")",
        "GETTER_SHA256=\"64d02765657eae86676a99593cc1783853cab51a531931597a30b2218ca4edd2\"",
        "HELPER_SHA256=\"8cac67abb474a5043787387b354a6ec3171a9e14a261137c30b9a392464a5d28\"",
        "HELPER_DIRECT_CALL_TARGETS=(0x1136A220,0x10113620)",
        "HELPER_CALLBACK_IDENTITY=0x112C6D60",
        "self.imports[0x1172F2C4][1],\"TlsAlloc\"",
        "self.imports[0x1172F2CC][1],\"TlsSetValue\"",
        "self.assertNotIn(\"100e9340\",rows)",
        "self.assertNotIn(\"112cbbb0\",rows)",
        "onlyAL,notfullEAX,isdefinedasone",
    )
    for fragment in required:
        if fragment not in compact:
            findings.append(f"provenance authority marker changed: {fragment[:72]}")
    if len(re.findall(r"^\s+def test_", text, flags=re.MULTILINE)) != 8:
        findings.append("provenance must retain eight independent assertions")
    for banned in ("ctypes", "subprocess", "WinDLL", "CDLL"):
        if banned in text:
            findings.append(f"provenance must remain data-only: {banned}")
    return sorted(set(findings))


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_HEADLESS_SIZE:
        findings.append("headless exact size changed")
    if _sha256(encoded) != EXPECTED_HEADLESS_SHA256:
        findings.append("headless exact digest changed")
    include_prefix = text.find(
        '#include "ported_100df270_platform_prefix_transcript.h"'
    )
    include_suffix = text.find('#include "ported_100df270_suffix_transcript.h"')
    include_router = text.find('#include "ported_100e2460_router.h"')
    include_8d00 = text.find('#include "ported_100e8d00_handler_transcript.h"')
    include_85d0 = text.find('#include "ported_100e85d0_normal_adapter.h"')
    include_8580 = text.find('#include "ported_100e8580_handler_transcript.h"')
    include_9340 = text.find('#include "ported_100e9340_handler_transcript.h"')
    include_92c0 = text.find('#include "ported_100e92c0_handler_transcript.h"')
    include_87a0 = text.find('#include "ported_100e87a0_handler_transcript.h"')
    include_outer = text.find('#include "ported_100ea4d0_injected.h"')
    if not (
        0 <= include_prefix < include_suffix < include_router < include_8d00 <
        include_85d0 < include_8580 < include_9340 < include_92c0 <
        include_87a0 < include_outer
    ):
        findings.append(
            "headless include order must be platform-prefix, suffix, router, "
            "8d00, 85d0, 8580, 9340, 92c0, 87a0, outer"
        )
    if compact.count(SUFFIX_FUNCTION + "(") != 0:
        findings.append("headless must not duplicate the composed suffix transcript")
    if compact.count(PREFIX_FUNCTION + "(") != 0:
        findings.append("headless must not duplicate the composed platform-prefix transcript")
    if compact.count(PARENT_FUNCTION + "(") != 1:
        findings.append("headless must execute the empty-preloop parent exactly once")
    if compact.count(LIFECYCLE_FUNCTION + "(") != 1:
        findings.append("headless must execute the ordinary lifecycle exactly once")
    if compact.count(FUNCTION + "(") != 2:
        findings.append("headless must execute the 100e9340 transcript exactly twice")
    call = (
        "handler_status=" + FUNCTION + "(receiver,argument,"
        "&context->handler_9340_effects,&handler_al);"
    )
    if compact.count(call) != 2:
        findings.append("headless two 100e9340 call arguments changed")
    router_dispatch = _function_body(code, "rome2_headless_router_dispatch")
    outer_dispatch = _function_body(code, "rome2_headless_outer_dispatch")
    if router_dispatch is None or _compact(router_dispatch).count(call) != 1:
        findings.append("standalone router dispatch must call 100e9340 exactly once")
    if outer_dispatch is None or _compact(outer_dispatch).count(call) != 1:
        findings.append("injected outer dispatch must call 100e9340 exactly once")

    required = (
        ("context->handler_9340_context.expected_receiver=receiver.value;",
         "composed calls must capture the receiver oracle"),
        ("context->handler_9340_context.return_al=&handler_al;",
         "composed calls must expose unpublished AL to the callback"),
        ("handler_status!=ROME2_GUEST_OK||"
         "handler_al!=ROME2_PORT_100E9340_AL||"
         "context->handler_9340_calls!=1",
         "headless status/AL/call oracle changed"),
        ("router_effect_context.handler_9340_effects.emit_step="
         "rome2_headless_9340_emit;",
         "router injected callback wiring changed"),
        ("outer_effect_context.handler_9340_effects.emit_step="
         "rome2_headless_9340_emit;",
         "outer injected callback wiring changed"),
        ("router_effect_context.handler_9340_effects.selected_dword_12="
         f"UINT32_C({HEADLESS_SELECTED_DWORD});",
         "router selected-dword injection changed"),
        ("outer_effect_context.handler_9340_effects.selected_dword_12="
         f"UINT32_C({HEADLESS_SELECTED_DWORD});",
         "outer selected-dword injection changed"),
        ("router_effect_context.handler_9340_effects.selected_byte_49="
         f"UINT32_C({HEADLESS_SELECTED_BYTE});",
         "router selected-byte injection changed"),
        ("outer_effect_context.handler_9340_effects.selected_byte_49="
         f"UINT32_C({HEADLESS_SELECTED_BYTE});",
         "outer selected-byte injection changed"),
        ("(context->expected_receiver&UINT32_C(0xffffff00))|"
         f"UINT32_C({HEADLESS_SELECTED_BYTE})",
         "headless receiver-low-byte oracle changed"),
        ("context->return_al==NULL||*context->return_al!=UINT8_C(0xcc)",
         "headless callback publication oracle changed"),
        ("router_effect_context.handler_9340_context.observed_steps!="
         "ROME2_PORT_100E9340_STEP_COUNT",
         "router four-step completion oracle changed"),
        ("outer_effect_context.handler_9340_context.observed_steps!="
         "ROME2_PORT_100E9340_STEP_COUNT",
         "outer four-step completion oracle changed"),
    )
    for fragment, message in required:
        if fragment not in compact:
            findings.append(message)

    positions = [compact.find(kind) for kind in STEP_KINDS]
    if any(position < 0 for position in positions):
        findings.append("headless typed four-step oracle is incomplete")
    elif any(left >= right for left, right in zip(positions, positions[1:])):
        findings.append("headless typed four-step oracle order changed")
    if compact.count("UINT32_C(0x12)") < 1 or compact.count("UINT32_C(0x49)") < 1:
        findings.append("headless lookup selectors changed")
    if compact.count(f"UINT32_C({HEADLESS_SELECTED_DWORD})") != 5:
        findings.append("headless selected dword must drive oracle and both contexts")
    if compact.count(f"UINT32_C({HEADLESS_SELECTED_BYTE})") != 4:
        findings.append("headless selected byte must drive oracle and both contexts")

    token_sequence = FROZEN_HANDLER_TOKEN_PREFIX + SUCCESSOR_HANDLER_TOKEN_TAIL
    token_positions = []
    for token in token_sequence:
        if text.count(token) != 1:
            findings.append(f"headless truthful status token changed: {token}")
        token_positions.append(text.find(token))
    if any(left >= right for left, right in zip(token_positions, token_positions[1:])):
        findings.append("headless original-order handler/outer token sequence changed")
    for forbidden in (
        "initializer-handler-100e9340=native",
        "initializer-handler-100e9340=not-linked",
        "initializer-handler-100e92c0=native",
        "initializer-handler-100e92c0=not-linked",
        "initializer-handler-100e87a0=native",
        "initializer-handler-100e87a0=not-linked",
        "startup-100df270-suffix=native",
        "startup-100df270-suffix=not-linked",
        "startup-100df270-platform-prefix=native",
        "startup-100df270-platform-prefix=not-linked",
        "initializer-100ea4d0=native",
    ):
        if forbidden in text:
            findings.append(f"headless reports forbidden native state: {forbidden}")
    return sorted(set(findings))


def _build_testing_bounds(lines: list[str]) -> tuple[int, int] | None:
    stack: list[tuple[int, bool]] = []
    found: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"if\s*\(", stripped, flags=re.I):
            stack.append((index, bool(re.match(
                r"if\s*\(\s*BUILD_TESTING\s*\)", stripped, flags=re.I
            ))))
        elif re.match(r"endif\s*(?:\([^)]*\))?\s*$", stripped, flags=re.I):
            if not stack:
                return None
            block_start, is_build_testing = stack.pop()
            if is_build_testing:
                found.append((block_start, index))
    if stack or len(found) != 1:
        return None
    return found[0]


def inspect_cmake_text(text: str) -> list[str]:
    findings: list[str] = []
    encoded = text.encode("utf-8")
    if len(encoded) != EXPECTED_CMAKE_SIZE:
        findings.append("CMake exact size changed")
    if hashlib.sha256(encoded).hexdigest() != EXPECTED_CMAKE_SHA256:
        findings.append("CMake exact digest changed")
    if len(re.findall(r"\badd_test\s*\(", text)) != EXPECTED_CMAKE_ADD_TEST_COUNT:
        findings.append("CMake add_test declaration count must remain 194")
    lines = text.splitlines()
    bounds = _build_testing_bounds(lines)
    if bounds is None:
        return ["one balanced if(BUILD_TESTING) block is required"]
    start, end = bounds
    scoped_tokens = (
        LIBRARY, TEST_TARGET,
        "ported_100e9340_handler_transcript.h",
        "ported_100e9340_handler_transcript.c",
        "test_startup_100e9340_handler_transcript.c",
        "test_x64_startup_100e9340_handler_transcript_provenance.py",
        "test_x64_startup_100e9340_handler_transcript_static_gate.py",
        "x64_startup_100e9340_handler_transcript_static_gate.py",
        *TRANSCRIPT_TEST_NAMES,
    )
    for token in scoped_tokens:
        positions = [index for index, line in enumerate(lines) if token in line]
        if not positions:
            findings.append(f"CMake transcript token is missing: {token}")
        elif any(index <= start or index >= end for index in positions):
            findings.append(f"CMake transcript token escapes BUILD_TESTING: {token}")
    scoped = "\n".join(lines[start + 1:end])
    compact = _compact(scoped)

    exact_library = (
        f"add_library({LIBRARY}STATIC"
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e9340_handler_transcript.h"'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e9340_handler_transcript.c")'
    )
    if compact.count(exact_library) != 1:
        findings.append("transcript must be an exact BUILD_TESTING-only static library")
    if f"add_library({LIBRARY}SHARED" in compact:
        findings.append("transcript library must not be shared")
    for fragment, message in (
        (f"target_compile_features({LIBRARY}PUBLICc_std_17)",
         "transcript C17 requirement changed"),
        (f"target_compile_options({LIBRARY}PRIVATE"
         "${ROME2_HARDENED_COMPILE_OPTIONS})",
         "transcript hardened compile options changed"),
        (f"target_include_directories({LIBRARY}PUBLIC"
         '"${ROME2_GUEST32_RUNTIME_DIR}"'
         '"${ROME2_GUEST32_PORTED_DIR}")',
         "transcript include containment changed"),
        (f"add_executable({TEST_TARGET}"
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e9340_handler_transcript.c")',
         "transcript runtime-test executable is missing"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "dedicated runtime test must link only its transcript library"),
    ):
        if compact.count(fragment) != 1:
            findings.append(message)

    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", text, flags=re.I | re.S
    )
    own_dependencies = [
        command for command in link_commands
        if re.split(r"\s+", command.strip(), maxsplit=1)[0] == LIBRARY
    ]
    if own_dependencies:
        findings.append("transcript core must have no link dependencies")
    consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in link_commands
        if LIBRARY in command
        and re.split(r"\s+", command.strip(), maxsplit=1)[0] != LIBRARY
    ]
    if sorted(consumers) != sorted((TEST_TARGET, HEADLESS)):
        findings.append("transcript library has an unexpected consumer/dependency")
    exact_headless_link = (
        "target_link_libraries(" + HEADLESS + "PRIVATE"
        + "".join(HEADLESS_LINK_LIBRARIES) + ")"
    )
    if compact.count(exact_headless_link) != 1:
        findings.append("exact headless link prefix/successor tail changed")

    gate_start = compact.find(
        "add_test(NAMEstartup_100e9340_handler_transcript_static_gateCOMMAND"
    )
    gate_end = compact.find("add_test(", gate_start + 1)
    gate_scope = compact[gate_start:gate_end] if gate_start >= 0 else ""
    for argument in (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100e9340_handler_transcript.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100e9340_handler_transcript.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e9340_handler_transcript.c"',
        '--transcript-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100e9340_handler_transcript_provenance.py"',
        '--headless"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"',
        '--cmake"${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"',
        '--export-manifest"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"',
        '--legacy-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"',
        '--probe-def"${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"',
    ):
        if gate_scope.count(argument) != 1:
            findings.append(f"transcript static-gate argument changed: {argument[:76]}")
    for test_name in TRANSCRIPT_TEST_NAMES:
        count = len(re.findall(
            r"NAME" + re.escape(test_name) + r"(?=COMMAND)", compact
        ))
        if count != 1:
            findings.append(f"transcript CTest missing or duplicated: {test_name}")

    fixture_blocks = (
        "set_tests_properties(startup_100e9340_handler_transcript_provenance"
        "PROPERTIESFIXTURES_SETUPstartup_100e9340_handler_transcript_provenance_verified)",
        "set_tests_properties(startup_100e9340_handler_transcript_static_gate_unit"
        "PROPERTIESFIXTURES_SETUPstartup_100e9340_handler_transcript_static_tool_verified)",
        "set_tests_properties(startup_100e9340_handler_transcript_static_gate"
        "PROPERTIESFIXTURES_REQUIREDstartup_100e9340_handler_transcript_static_tool_verified"
        "FIXTURES_SETUPstartup_100e9340_handler_transcript_static_verified)",
        "set_tests_properties(startup_100e9340_handler_transcript_runtimePROPERTIES"
        f"FIXTURES_REQUIRED\"{PREDECESSOR_RELOAD_FIXTURE};"
        "startup_100e9340_handler_transcript_provenance_verified;"
        "startup_100e9340_handler_transcript_static_verified\""
        "FIXTURES_SETUPstartup_100e9340_handler_transcript_runtime_verifiedTIMEOUT90)",
        "set_tests_properties(startup_100e9340_handler_transcript_post_pe_gate"
        "PROPERTIESFIXTURES_REQUIRED\""
        "startup_100e9340_handler_transcript_runtime_verified;"
        "entry_policy_probe_pe_tool_verified\""
        "FIXTURES_SETUPstartup_100e9340_handler_transcript_post_verified)",
        "set_tests_properties(x64_bootstrap_load_after_startup_100e9340_handler_transcript"
        "PROPERTIESFIXTURES_REQUIRED\"x64_bootstrap_pre_verified;"
        "startup_100e9340_handler_transcript_post_verified\""
        "FIXTURES_SETUPstartup_100e9340_handler_transcript_reload_verified)",
        "set_tests_properties(startup_100ea4d0_injected_runtimePROPERTIES"
        "FIXTURES_REQUIRED\"startup_100e8580_handler_transcript_reload_verified;"
        "startup_100ea4d0_executable_provenance_verified;"
        "startup_100ea4d0_injected_static_verified\""
        "FIXTURES_SETUPstartup_100ea4d0_injected_runtime_verifiedTIMEOUT90)",
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED\"entry_policy_provenance_verified;"
        f"entry_policy_static_verified;{TERMINAL_RELOAD_FIXTURE}\"TIMEOUT90)",
    )
    for block in fixture_blocks:
        if compact.count(block) != 1:
            findings.append(f"transcript fixture-chain block changed: {block[:82]}")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), "rome2_100e9340_handler_transcript",
        "ported_100e9340_handler_transcript", "100e9340_handler_transcript",
    ):
        if token in lowered:
            findings.append(f"test-only transcript token escaped exports: {token}")
    return sorted(set(findings))


def _inspect_path(path: pathlib.Path, inspector) -> list[str]:
    text, findings = _decode_utf8(path)
    if text is None:
        return findings
    return inspector(text)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--test", type=pathlib.Path, required=True)
    parser.add_argument("--transcript-provenance", type=pathlib.Path, required=True)
    parser.add_argument("--headless", type=pathlib.Path, required=True)
    parser.add_argument("--cmake", type=pathlib.Path, required=True)
    parser.add_argument("--export-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-def", type=pathlib.Path, required=True)
    parser.add_argument("--probe-def", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = {
        "header": args.header,
        "source": args.source,
        "test": args.test,
        "transcript_provenance": args.transcript_provenance,
        "headless": args.headless,
        "cmake": args.cmake,
        "export_manifest": args.export_manifest,
        "legacy_def": args.legacy_def,
        "probe_def": args.probe_def,
    }
    try:
        provenance = args.transcript_provenance.resolve(strict=True).read_bytes()
    except OSError as error:
        provenance_findings = [f"cannot read transcript provenance: {error}"]
    else:
        provenance_findings = inspect_provenance_bytes(provenance)
    checks = {
        "header": _inspect_path(args.header.resolve(strict=True), inspect_header_text),
        "source": _inspect_path(args.source.resolve(strict=True), inspect_source_text),
        "test": _inspect_path(args.test.resolve(strict=True), inspect_test_text),
        "transcript_provenance": provenance_findings,
        "headless": _inspect_path(args.headless.resolve(strict=True), inspect_headless_text),
        "cmake": _inspect_path(args.cmake.resolve(strict=True), inspect_cmake_text),
        "export_manifest": _inspect_path(
            args.export_manifest.resolve(strict=True), inspect_exports_text
        ),
        "legacy_def": _inspect_path(args.legacy_def.resolve(strict=True), inspect_exports_text),
        "probe_def": _inspect_path(args.probe_def.resolve(strict=True), inspect_exports_text),
    }
    report: dict[str, object] = {"status": "pass", "files": {}}
    total = 0
    for label, findings in checks.items():
        total += len(findings)
        report["files"][label] = {
            "path": str(paths[label].resolve(strict=True)),
            "findings": findings,
        }
    report["finding_count"] = total
    if total:
        report["status"] = "fail"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

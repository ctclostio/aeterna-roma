#!/usr/bin/env python3
"""Fail-closed source and containment gate for original 0x100e8580."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100e8580_run_handler_transcript"
LIBRARY = "rome2_startup_100e8580_handler_transcript_runtime"
TEST_TARGET = "rome2_startup_100e8580_handler_transcript_tests"
HEADLESS = "rome2_headless64"
GUEST32_LIBRARY = "rome2_guest32_runtime"
ROUTER_LIBRARY = "rome2_startup_100e2460_router_runtime"
TRANSCRIPT_8D00_LIBRARY = "rome2_startup_100e8d00_handler_transcript_runtime"
ADAPTER_85D0_LIBRARY = "rome2_startup_100e85d0_normal_adapter_runtime"
FINAL_INJECTED_LIBRARY = "rome2_startup_100ea4d0_injected_runtime"
HANDLER_9340_FUNCTION = "rome2_port_100e9340_run_handler_transcript"
HANDLER_92C0_FUNCTION = "rome2_port_100e92c0_run_handler_transcript"
HANDLER_87A0_FUNCTION = "rome2_port_100e87a0_run_handler_transcript"
SUFFIX_FUNCTION = "rome2_port_100df270_run_suffix_transcript"
PREFIX_FUNCTION = "rome2_port_100df270_run_platform_prefix_transcript"
PARENT_FUNCTION = "rome2_port_100ed3c0_run_empty_preloop"
LIFECYCLE_FUNCTION = "rome2_port_100ed471_run_ordinary_lifecycle"
HANDLER_9340_LIBRARY = "rome2_startup_100e9340_handler_transcript_runtime"
HANDLER_92C0_LIBRARY = "rome2_startup_100e92c0_handler_transcript_runtime"
HANDLER_87A0_LIBRARY = "rome2_startup_100e87a0_handler_transcript_runtime"
SUFFIX_LIBRARY = "rome2_startup_100df270_suffix_transcript_runtime"
PREFIX_LIBRARY = "rome2_startup_100df270_platform_prefix_transcript_runtime"
LIFECYCLE_LIBRARY = "rome2_startup_100ed471_ordinary_lifecycle_runtime"

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
    "bc445ddd811d1d219033c407693f207490e46ec3827b0b3827481422460a4ee0"
)
EXPECTED_SOURCE_SHA256 = (
    "3b2e6c09e344523289763c108b1d05cc15f6c34c2c08b0851916ecf969f41694"
)
EXPECTED_TEST_SHA256 = (
    "20edf096196b2069ef667960877eae712fdd5a099e31b59c6eabc8e0f76ac56e"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "7e82cb1039d0d1e3f67d32a7743db121d6a983080cc8c739f80df0fbf62c79de"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "398f7a3e1673a475479a1453af6c53a5d482992ccb8becda368d7a6eafd0a898"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "70755f917c3634ab3d7293c6318f489a4901afb94f3f482b29155a1021e60a86"
)
EXPECTED_PROVENANCE_SHA256 = (
    "19760944e339af4e6de8292e3400e3c25b84e05fc44e91624b00d89a255fa7e8"
)

TRANSCRIPT_TEST_NAMES = (
    "startup_100e8580_handler_transcript_provenance",
    "startup_100e8580_handler_transcript_static_gate_unit",
    "startup_100e8580_handler_transcript_static_gate",
    "startup_100e8580_handler_transcript_runtime",
    "startup_100e8580_handler_transcript_post_pe_gate",
    "x64_bootstrap_load_after_startup_100e8580_handler_transcript",
)

HEADLESS_LINK_LIBRARIES = (
    GUEST32_LIBRARY,
    "rome2_startup_100f1aa0_empty_runtime",
    "rome2_startup_safe_seams_runtime",
    "rome2_startup_100df270_headless_runtime",
    "rome2_startup_100f2750_nonalloc_runtime",
    "rome2_startup_100e8240_fastpath_runtime",
    "rome2_startup_100e2460_append_prefix_runtime",
    "rome2_startup_100e2460_preallocated_branch_runtime",
    "rome2_startup_100e2460_capacity_zero_branch_runtime",
    "rome2_startup_100e2460_growth_branch_runtime",
    ROUTER_LIBRARY,
    TRANSCRIPT_8D00_LIBRARY,
    ADAPTER_85D0_LIBRARY,
    LIBRARY,
    FINAL_INJECTED_LIBRARY,
    HANDLER_9340_LIBRARY,
    HANDLER_92C0_LIBRARY,
    HANDLER_87A0_LIBRARY,
    SUFFIX_LIBRARY,
    PREFIX_LIBRARY,
    "rome2_startup_100ed3c0_empty_preloop_runtime",
    LIFECYCLE_LIBRARY,
)

HEADLESS_REQUIRED_TOKENS = (
    "initializer-router=injected-complete",
    "initializer-handler-100e8d00=injected-transcript-complete",
    "initializer-handler-100e85d0=effect-free-complete",
    "initializer-handler-100e8580=injected-transcript-complete",
    "initializer-100ea4d0=injected-complete",
    "initializer-handler-100e9340=injected-transcript-complete",
    "initializer-handler-100e92c0=injected-transcript-complete",
    "initializer-handler-100e87a0=injected-transcript-complete",
    "startup-100df270-suffix=injected-transcript-complete",
    "startup-100df270-platform-prefix=injected-call-shape-complete",
    "startup-100ed3c0-empty-preloop=injected-composition-complete",
    "startup-100ed471-ordinary-lifecycle=injected-bounded-complete",
    "initializer-growth=injected-complete",
    "growth-allocator=injected-16-byte",
    "growth-release=injected-old-backing",
    "native-release=not-run",
    "platform-effects=not-run",
    "native-allocator=not-run",
    "initializer-dispatch=injected-complete",
    "queue-drain=injected-bounded-complete",
    "gameplay=not-linked",
)

BANNED_IDENTIFIERS = {
    "CreateProcessA", "CreateProcessW", "DispatchMessageA",
    "DispatchMessageW", "FreeLibrary", "GetMessageA", "GetMessageW",
    "GetModuleHandleA", "GetModuleHandleW", "GetProcAddress", "HeapAlloc",
    "HeapFree", "LoadLibraryA", "LoadLibraryW", "PeekMessageA",
    "PeekMessageW", "PostMessageA", "PostMessageW", "SendMessageA",
    "SendMessageW", "TranslateMessage", "VirtualAlloc", "VirtualFree",
    "calloc", "dlopen", "dlsym", "free", "malloc", "realloc", "system",
}

STEP_KINDS = (
    "ROME2_100E8580_STEP_CALL_100D6560",
    "ROME2_100E8580_STEP_CALL_112D0510",
    "ROME2_100E8580_STEP_CALL_112E0950_ONE",
    "ROME2_100E8580_STEP_CALL_100D9810",
    "ROME2_100E8580_STEP_CALL_100DDF50",
    "ROME2_100E8580_STEP_CALL_112E0950_ZERO",
    "ROME2_100E8580_STEP_CALL_100E8240",
    "ROME2_100E8580_STEP_CALL_112BFEE0",
    "ROME2_100E8580_STEP_CALL_112DCAF0",
)

SOURCE_STEP_BLOCKS = (
    "rome2_100e8580_clear_step(&step);"
    "step.kind=ROME2_100E8580_STEP_CALL_100D6560;"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
    "rome2_100e8580_clear_step(&step);"
    "step.kind=ROME2_100E8580_STEP_CALL_112D0510;"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
    "rome2_100e8580_clear_step(&step);"
    "step.kind=ROME2_100E8580_STEP_CALL_112E0950_ONE;"
    "step.argument_count=UINT32_C(1);step.argument0=UINT32_C(1);"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
    "rome2_100e8580_clear_step(&step);"
    "step.kind=ROME2_100E8580_STEP_CALL_100D9810;"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
    "rome2_100e8580_clear_step(&step);"
    "step.kind=ROME2_100E8580_STEP_CALL_100DDF50;"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
    "rome2_100e8580_clear_step(&step);"
    "step.kind=ROME2_100E8580_STEP_CALL_112E0950_ZERO;"
    "step.argument_count=UINT32_C(1);step.argument0=UINT32_C(0);"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
    "rome2_100e8580_clear_step(&step);"
    "step.kind=ROME2_100E8580_STEP_CALL_100E8240;"
    "step.argument_count=UINT32_C(1);step.argument0=UINT32_C(0);"
    "step.has_guest_result=UINT32_C(1);"
    "step.returned_guest_identity=effects_snapshot.result_100e8240;"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
    "rome2_100e8580_clear_step(&step);"
    "step.kind=ROME2_100E8580_STEP_CALL_112BFEE0;"
    "step.argument_count=UINT32_C(1);step.argument0=adjusted_identity.value;"
    "effects_snapshot.emit_step(effects_snapshot.context,step);",
    "rome2_100e8580_clear_step(&step);"
    "step.kind=ROME2_100E8580_STEP_CALL_112DCAF0;"
    "step.argument_count=UINT32_C(3);"
    "step.argument0=ROME2_PORT_100E8580_FINISHED_RUN_VARS_IDENTITY;"
    "step.argument1=UINT32_C(0);step.argument2=UINT32_C(0);"
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
    compact: str, fragment: str, findings: list[str], message: str
) -> None:
    if compact.count(fragment) != 1:
        findings.append(message)


def _banned_findings(code: str) -> list[str]:
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code))
    return [
        f"forbidden native/platform/allocation identifier: {identifier}"
        for identifier in sorted(BANNED_IDENTIFIERS & identifiers)
    ]


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
        ("#defineROME2_PORT_100E8580_ALUINT8_C(1)",
         "transcript AL constant changed"),
        ("#defineROME2_PORT_100E8580_STEP_COUNTUINT32_C(9)",
         "nine-step count changed"),
        ("#defineROME2_PORT_100E8580_RESULT_DISPLACEMENTUINT32_C(0x68)",
         "checked guest displacement changed"),
        ("#defineROME2_PORT_100E8580_FINISHED_RUN_VARS_IDENTITY"
         "UINT32_C(0x1173fb54)", "Finished run_vars identity changed"),
    ):
        _require_once(compact, fragment, findings, message)

    targets = (
        ("100D6560", "0x100d6560"), ("112D0510", "0x112d0510"),
        ("112E0950", "0x112e0950"), ("100D9810", "0x100d9810"),
        ("100DDF50", "0x100ddf50"), ("100E8240", "0x100e8240"),
        ("112BFEE0", "0x112bfee0"), ("112DCAF0", "0x112dcaf0"),
    )
    for suffix, value in targets:
        _require_once(
            compact,
            f"#defineROME2_PORT_100E8580_TARGET_{suffix}UINT32_C({value})",
            findings,
            f"typed target identity changed: {suffix}",
        )

    enum_body = (
        "typedefenumrome2_100e8580_step_kind{"
        + ",".join(f"{kind}={index}" for index, kind in enumerate(STEP_KINDS, 1))
        + "}rome2_100e8580_step_kind;"
    )
    _require_once(compact, enum_body, findings, "typed nine-step order changed")
    step_type = (
        "typedefstructrome2_100e8580_step{"
        "rome2_100e8580_step_kindkind;uint32_targument_count;"
        "uint32_targument0;uint32_targument1;uint32_targument2;"
        "uint32_thas_guest_result;rome2_guest_addr32returned_guest_identity;}"
        "rome2_100e8580_step;"
    )
    _require_once(compact, step_type, findings, "typed result-bearing step layout changed")
    callback_type = (
        "typedefvoid(*rome2_100e8580_emit_step_fn)("
        "void*context,rome2_100e8580_stepstep);"
    )
    _require_once(compact, callback_type, findings, "by-value callback contract changed")
    effects_type = (
        "typedefstructrome2_100e8580_transcript_effects{"
        "rome2_100e8580_emit_step_fnemit_step;void*context;"
        "rome2_guest_addr32result_100e8240;}"
        "rome2_100e8580_transcript_effects;"
    )
    _require_once(
        compact, effects_type, findings,
        "effects must explicitly inject and snapshot the 100e8240 result",
    )
    declaration = (
        "rome2_guest_status" + FUNCTION + "("
        "rome2_guest_addr32guest_receiver,rome2_guest_addr32guest_argument,"
        "constrome2_100e8580_transcript_effects*effects,uint8_t*return_al_out);"
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
        "ported_100e8580_handler_transcript.h", "stddef.h", "stdint.h"
    ]:
        findings.append("source include containment changed")
    findings.extend(_banned_findings(code))
    if "#pragmacomment(lib" in compact.lower():
        findings.append("native library autolinking is forbidden")

    for fragment, message in (
        ("status=rome2_100e8580_validate_object(effects,sizeof(*effects));",
         "effects borrowed-object validation changed"),
        ("status=rome2_100e8580_validate_object(return_al_out,"
         "sizeof(*return_al_out));", "AL borrowed-object validation changed"),
        ("if(rome2_100e8580_ranges_overlap(effects,sizeof(*effects),"
         "return_al_out,sizeof(*return_al_out))){"
         "returnROME2_GUEST_BAD_ARGUMENT;}",
         "effects/output alias rejection changed"),
        ("effects_snapshot=*effects;", "complete effects snapshot changed"),
        ("if(effects_snapshot.emit_step==NULL||"
         "effects_snapshot.context==NULL){returnROME2_GUEST_BAD_ARGUMENT;}",
         "required callback/context validation changed"),
        ("(void)guest_receiver;(void)guest_argument;",
         "opaque ignored receiver/argument contract changed"),
    ):
        _require_once(compact, fragment, findings, message)

    kinds = tuple(re.findall(r"step\.kind\s*=\s*(ROME2_100E8580_STEP_[A-Z0-9_]+)", code))
    if kinds != STEP_KINDS:
        findings.append("source nine-step order changed")
    if compact.count("effects_snapshot.emit_step(effects_snapshot.context,step);") != 9:
        findings.append("source must emit exactly nine typed steps")
    if compact.count("rome2_100e8580_clear_step(&step);") != 9:
        findings.append("every emitted step must clear all unused argument/result fields")

    previous = -1
    block_positions = []
    for index, block in enumerate(SOURCE_STEP_BLOCKS, 1):
        position = compact.find(block)
        block_positions.append(position)
        if position < 0:
            findings.append(f"typed step {index} arguments/result changed")
        elif position <= previous:
            findings.append("typed step blocks are not in original order")
        previous = position

    checked_add = (
        "status=rome2_guest_add_checked(effects_snapshot.result_100e8240,"
        "ROME2_PORT_100E8580_RESULT_DISPLACEMENT,&adjusted_identity);"
        "if(status!=ROME2_GUEST_OK){returnstatus;}"
    )
    _require_once(
        compact, checked_add, findings,
        "checked snapshotted 100e8240 +0x68 dependency changed",
    )
    add_position = compact.find(checked_add)
    if (
        len(block_positions) == 9
        and min(block_positions, default=-1) >= 0
        and not (block_positions[6] < add_position < block_positions[7])
    ):
        findings.append("dependency failure must retain exactly seven prefix effects")

    output = "*return_al_out=ROME2_PORT_100E8580_AL;"
    if compact.count(output) != 1:
        findings.append("AL must have exactly one publication")
    elif block_positions[-1] < 0 or compact.find(output) <= block_positions[-1]:
        findings.append("AL must publish only after step nine")
    if compact.count(output + "returnROME2_GUEST_OK;") != 1:
        findings.append("success status must immediately follow final AL publication")

    if code.count("guest_receiver") != 2 or code.count("guest_argument") != 2:
        findings.append("opaque handler inputs must not be inspected")
    if re.search(
        r"\([^)]*\*[^)]*\)\s*(?:guest_receiver|guest_argument|"
        r"adjusted_identity(?:\.value)?|effects_snapshot\.result_100e8240)",
        code,
    ):
        findings.append("guest identities must never be cast to host pointers")
    for target in (
        "100d6560", "112d0510", "112e0950", "100d9810", "100ddf50",
        "100e8240", "112bfee0", "112dcaf0",
    ):
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
        "ported_100e8580_handler_transcript.h", "stdint.h", "stdio.h",
        "string.h",
    ]:
        findings.append("runtime oracle include set changed")
    findings.extend(_banned_findings(code))

    required = (
        ("#defineROME2_TEST_FULL_COUNTUINT32_C(9)",
         "runtime full-count oracle changed"),
        ("#defineROME2_TEST_PREFIX_COUNTUINT32_C(7)",
         "runtime seven-prefix oracle changed"),
        ("ROME2_PORT_100E8580_RESULT_DISPLACEMENT==UINT32_C(0x68)",
         "runtime displacement pin changed"),
        ("ROME2_PORT_100E8580_FINISHED_RUN_VARS_IDENTITY=="
         "UINT32_C(0x1173fb54)", "runtime string-identity pin changed"),
        ("step.returned_guest_identity.value=result_100e8240;",
         "runtime explicit 100e8240 result oracle changed"),
        ("step.argument0=result_100e8240+UINT32_C(0x68);",
         "runtime adjusted-result dependency oracle changed"),
        ("trace->effects.emit_step=rome2_test_trap_callback;"
         "trace->effects.context=&trace->decoy_context;"
         "trace->effects.result_100e8240.value=UINT32_C(0);",
         "runtime complete-effects snapshot mutant changed"),
        ("*trace->return_al!=ROME2_TEST_SENTINEL",
         "runtime must observe unpublished AL in every callback"),
        ("trace.observed_count!=ROME2_TEST_PREFIX_COUNT",
         "runtime must require exactly seven committed prefix steps"),
        ("return_al!=ROME2_TEST_SENTINEL",
         "runtime prefix failure must preserve AL"),
        ("(uint8_t*)(void*)&trace.effects",
         "runtime effects/output alias case changed"),
        ("UINTPTR_MAX-(uintptr_t)sizeof(rome2_100e8580_transcript_effects)"
         "+(uintptr_t)2", "runtime host-span overflow case changed"),
        ("UINT32_C(0x01020304)", "ordinary dependent-result case changed"),
        ("UINT32_C(0xffffff97)", "largest admissible result case changed"),
        ("UINT32_C(0xffffff98)", "overflow boundary case changed"),
        ("ROME2_GUEST_NULL_ADDRESS", "null-result status oracle changed"),
        ("ROME2_GUEST_RANGE_OVERFLOW", "overflow-result status oracle changed"),
        ("rome2_test_guest(UINT32_C(0)),"
         "rome2_test_guest(UINT32_MAX)", "opaque all-bit input case changed"),
    )
    for fragment, message in required:
        if fragment not in compact:
            findings.append(message)
    if text.count("100e8580 handler transcript: ok") != 1:
        findings.append("runtime success marker changed")
    if compact.count(FUNCTION + "(") != 9:
        findings.append("runtime must cover two successes, two prefix failures, and validation")
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
        "FUNCTION_VA=0x100E8580",
        "FUNCTION_SHA256=\"baeed663cb3c273a7e4a6cceb6cd6976695f2226e321bb231e484758a2cf3dfe\"",
        "FUNCTION_RAW_OFFSET=0x000E7980",
        "CALL_OFFSETS=(0,5,12,17,22,29,39,48,62)",
        "0x100D6560,0x112D0510,0x112E0950,0x100D9810,0x100DDF50,"
        "0x112E0950,0x100E8240,0x112BFEE0,0x112DCAF0,",
        "FINISHED_RUN_VARS_VA=0x1173FB54",
        "FINISHED_RUN_VARS_BYTES=b\"Finishedrun_vars\\0\"",
        "VTABLE_PAIR_VA=0x1173F21C",
        "VTABLE_PAIR_BYTES=bytes.fromhex(\"50120e1080850e10\")",
        "bytes.fromhex(\"83c408\")",
        "bytes.fromhex(\"83c414\")",
        "bytes.fromhex(\"6a00e894fcffff83c06850\")",
    )
    for fragment in required:
        if fragment not in compact:
            findings.append(f"provenance authority marker changed: {fragment[:64]}")
    if len(re.findall(r"^\s+def test_", text, flags=re.MULTILINE)) != 8:
        findings.append("provenance must retain eight independent assertions")
    for banned in ("ctypes", "subprocess", "LoadLibrary", "WinDLL", "CDLL"):
        if banned in text:
            findings.append(f"provenance must remain data-only: {banned}")
    return sorted(set(findings))


def inspect_headless_text(text: str) -> list[str]:
    code, findings = sanitize_c(text)
    compact = _compact(code)
    if len(text.encode("utf-8")) != EXPECTED_HEADLESS_SIZE:
        findings.append("headless exact size changed")
    if _sha256(text.encode("utf-8")) != EXPECTED_HEADLESS_SHA256:
        findings.append("headless exact digest changed")
    findings.extend(_banned_findings(code))
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
            "headless include order must reach platform-prefix, suffix, router, "
            "handlers, outer"
        )
    if compact.count(FUNCTION + "(") != 2:
        findings.append("headless must execute the 100e8580 transcript exactly twice")
    if compact.count(SUFFIX_FUNCTION + "(") != 0:
        findings.append("headless must not duplicate the composed suffix transcript")
    if compact.count(PREFIX_FUNCTION + "(") != 0:
        findings.append("headless must not duplicate the composed platform-prefix transcript")
    if compact.count(PARENT_FUNCTION + "(") != 1:
        findings.append("headless must execute the empty-preloop parent exactly once")
    if compact.count(LIFECYCLE_FUNCTION + "(") != 1:
        findings.append("headless must execute the ordinary lifecycle exactly once")
    call = (
        "handler_status=" + FUNCTION + "(receiver,argument,"
        "&context->handler_8580_effects,&handler_al);"
    )
    if compact.count(call) != 2:
        findings.append("headless two 100e8580 call arguments changed")
    router_dispatch = _function_body(code, "rome2_headless_router_dispatch")
    outer_dispatch = _function_body(code, "rome2_headless_outer_dispatch")
    if router_dispatch is None or _compact(router_dispatch).count(call) != 1:
        findings.append("standalone router dispatch must call 100e8580 exactly once")
    if outer_dispatch is None or _compact(outer_dispatch).count(call) != 1:
        findings.append("injected outer dispatch must call 100e8580 exactly once")
    for successor in (
        HANDLER_9340_FUNCTION, HANDLER_92C0_FUNCTION, HANDLER_87A0_FUNCTION
    ):
        if compact.count(successor + "(") != 2:
            findings.append(f"headless successor call-site count changed: {successor}")
    for fragment, message in (
        ("router_effect_context.handler_8580_effects.result_100e8240.value="
         "UINT32_C(0x119f3a38);", "headless injected dependency changed"),
        ("outer_effect_context.handler_8580_effects.result_100e8240.value="
         "UINT32_C(0x119f3a38);", "outer injected dependency changed"),
        ("ROME2_100E8580_STEP_CALL_100E8240,1,0,0,0,1,"
         "{UINT32_C(0x119f3a38)}", "headless explicit result oracle changed"),
        ("ROME2_100E8580_STEP_CALL_112BFEE0,1,"
         "UINT32_C(0x119f3aa0),0,0,0,{0}",
         "headless +0x68 dependency oracle changed"),
        ("handler_status!=ROME2_GUEST_OK||"
         "handler_al!=ROME2_PORT_100E8580_AL||"
         "context->handler_8580_calls!=1", "headless status/AL/call oracle changed"),
        ("router_effect_context.handler_8580_context.observed_steps!="
         "ROME2_PORT_100E8580_STEP_COUNT", "headless nine-step count oracle changed"),
        ("outer_effect_context.handler_8580_context.observed_steps!="
         "ROME2_PORT_100E8580_STEP_COUNT", "outer nine-step count oracle changed"),
        ("UINT32_C(0x1173f21c)", "headless 100e8580 vtable identity changed"),
        ("UINT32_C(0x100e8580)", "headless 100e8580 method identity changed"),
    ):
        if fragment not in compact:
            findings.append(message)
    positions = []
    for kind in STEP_KINDS:
        position = compact.find(kind)
        if position < 0:
            findings.append(f"headless typed oracle is missing {kind}")
        positions.append(position)
    if any(left >= right for left, right in zip(positions, positions[1:])):
        findings.append("headless typed nine-step oracle order changed")
    for token in HEADLESS_REQUIRED_TOKENS:
        if text.count(token) != 1:
            findings.append(f"headless truthful status token changed: {token}")
    handler_positions = [
        text.find("initializer-handler-100e8d00=injected-transcript-complete"),
        text.find("initializer-handler-100e85d0=effect-free-complete"),
        text.find("initializer-handler-100e8580=injected-transcript-complete"),
        text.find("initializer-100ea4d0=injected-complete"),
        text.find("initializer-handler-100e9340=injected-transcript-complete"),
        text.find("initializer-handler-100e92c0=injected-transcript-complete"),
        text.find("initializer-handler-100e87a0=injected-transcript-complete"),
        text.find("startup-100df270-suffix=injected-transcript-complete"),
        text.find("startup-100df270-platform-prefix=injected-call-shape-complete"),
        text.find("startup-100ed3c0-empty-preloop=injected-composition-complete"),
        text.find("startup-100ed471-ordinary-lifecycle=injected-bounded-complete"),
    ]
    if any(left >= right for left, right in zip(handler_positions, handler_positions[1:])):
        findings.append("headless original-order handler/final token sequence changed")
    if "0x600000b1" in compact.lower():
        findings.append("headless unknown-method fallback must fail closed")
    for forbidden in (
        "initializer-handler-100e8580=native",
        "initializer-handler-100e8580=not-linked",
        "initializer-100ea4d0=native",
        "initializer-handler-100e9340=native",
        "initializer-handler-100e92c0=native",
        "initializer-handler-100e87a0=native",
        "startup-100df270-suffix=native",
        "startup-100df270-suffix=not-linked",
        "startup-100df270-platform-prefix=native",
        "startup-100df270-platform-prefix=not-linked",
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
        "ported_100e8580_handler_transcript.h",
        "ported_100e8580_handler_transcript.c",
        "test_startup_100e8580_handler_transcript.c",
        "test_x64_startup_100e8580_handler_transcript_provenance.py",
        "test_x64_startup_100e8580_handler_transcript_static_gate.py",
        "x64_startup_100e8580_handler_transcript_static_gate.py",
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
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e8580_handler_transcript.h"'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e8580_handler_transcript.c")'
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
        (f"target_link_libraries({LIBRARY}PRIVATE{GUEST32_LIBRARY})",
         "transcript library direct dependency must be guest32 only"),
        (f"add_executable({TEST_TARGET}"
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e8580_handler_transcript.c")',
         "transcript runtime-test executable is missing"),
        (f"target_link_libraries({TEST_TARGET}PRIVATE{LIBRARY})",
         "dedicated runtime test must link only its transcript library"),
    ):
        if compact.count(fragment) != 1:
            findings.append(message)

    link_commands = re.findall(
        r"target_link_libraries\s*\((.*?)\)", scoped, flags=re.I | re.S
    )
    own_links = [
        _compact(command) for command in link_commands
        if re.split(r"\s+", command.strip(), maxsplit=1)[0] == LIBRARY
    ]
    if own_links != [LIBRARY + "PRIVATE" + GUEST32_LIBRARY]:
        findings.append("transcript library must have exactly one guest32-only link command")
    consumers = [
        re.split(r"\s+", command.strip(), maxsplit=1)[0]
        for command in link_commands
        if LIBRARY in command
        and re.split(r"\s+", command.strip(), maxsplit=1)[0] != LIBRARY
    ]
    if sorted(consumers) != sorted((TEST_TARGET, HEADLESS)):
        findings.append("transcript library has an unexpected consumer")

    exact_headless_link = (
        "target_link_libraries(" + HEADLESS + "PRIVATE"
        + "".join(HEADLESS_LINK_LIBRARIES) + ")"
    )
    if compact.count(exact_headless_link) != 1:
        findings.append(
            "exact headless link tail must end outer, 9340, 92c0, 87a0, "
            "suffix, platform-prefix"
        )

    gate_start = compact.find(
        "add_test(NAMEstartup_100e8580_handler_transcript_static_gateCOMMAND"
    )
    gate_end = compact.find("add_test(", gate_start + 1)
    gate_scope = compact[gate_start:gate_end] if gate_start >= 0 else ""
    for argument in (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100e8580_handler_transcript.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100e8580_handler_transcript.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e8580_handler_transcript.c"',
        '--transcript-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100e8580_handler_transcript_provenance.py"',
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
        "set_tests_properties(startup_100e8580_handler_transcript_provenance"
        "PROPERTIESFIXTURES_SETUPstartup_100e8580_handler_transcript_provenance_verified)",
        "set_tests_properties(startup_100e8580_handler_transcript_static_gate_unit"
        "PROPERTIESFIXTURES_SETUPstartup_100e8580_handler_transcript_static_tool_verified)",
        "set_tests_properties(startup_100e8580_handler_transcript_static_gate"
        "PROPERTIESFIXTURES_REQUIREDstartup_100e8580_handler_transcript_static_tool_verified"
        "FIXTURES_SETUPstartup_100e8580_handler_transcript_static_verified)",
        "set_tests_properties(startup_100e8580_handler_transcript_runtimePROPERTIES"
        "FIXTURES_REQUIRED\"startup_100e85d0_normal_adapter_reload_verified;"
        "startup_100e8580_handler_transcript_provenance_verified;"
        "startup_100e8580_handler_transcript_static_verified\""
        "FIXTURES_SETUPstartup_100e8580_handler_transcript_runtime_verifiedTIMEOUT90)",
        "set_tests_properties(startup_100e8580_handler_transcript_post_pe_gate"
        "PROPERTIESFIXTURES_REQUIRED\""
        "startup_100e8580_handler_transcript_runtime_verified;"
        "entry_policy_probe_pe_tool_verified\""
        "FIXTURES_SETUPstartup_100e8580_handler_transcript_post_verified)",
        "set_tests_properties(x64_bootstrap_load_after_startup_100e8580_handler_transcript"
        "PROPERTIESFIXTURES_REQUIRED\"x64_bootstrap_pre_verified;"
        "startup_100e8580_handler_transcript_post_verified\""
        "FIXTURES_SETUPstartup_100e8580_handler_transcript_reload_verified)",
        "set_tests_properties(headless_bounded_lifecyclePROPERTIES"
        "FIXTURES_REQUIRED\"entry_policy_provenance_verified;"
        "entry_policy_static_verified;"
        "startup_100ed471_ordinary_lifecycle_reload_verified\""
        "TIMEOUT90)",
    )
    for block in fixture_blocks:
        if compact.count(block) != 1:
            findings.append(f"transcript fixture-chain block changed: {block[:78]}")
    return sorted(set(findings))


def inspect_exports_text(text: str) -> list[str]:
    lowered = text.lower()
    findings = []
    for token in (
        FUNCTION.lower(), LIBRARY.lower(), "rome2_100e8580_handler_transcript",
        "ported_100e8580_handler_transcript", "100e8580_handler_transcript",
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

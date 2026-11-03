#!/usr/bin/env python3
"""Fail-closed source and integration gate for original handler 0x100e92c0."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from x64_entry_policy_static_gate import sanitize_c


FUNCTION = "rome2_port_100e92c0_run_handler_transcript"
LIBRARY = "rome2_startup_100e92c0_handler_transcript_runtime"
TEST_TARGET = "rome2_startup_100e92c0_handler_transcript_tests"
HEADLESS = "rome2_headless64"
PREDECESSOR_LIBRARY = "rome2_startup_100e9340_handler_transcript_runtime"
OUTER_INITIALIZER_LIBRARY = "rome2_startup_100ea4d0_injected_runtime"
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
    "6cb1465e69cffc4a935aca41ea767ab750d510c109d31f4081ccea791350d508"
)
EXPECTED_SOURCE_SHA256 = (
    "a806d3b5a75d3683710e694a887e84d2a46b9abde80aa96e613867f666a211f1"
)
EXPECTED_TEST_SHA256 = (
    "a4765be524776960dd368b5c1896128239daa62342ce7a9e6f88005231e5c28e"
)
EXPECTED_HEADER_TOKEN_SHA256 = (
    "7ca158410df74af4bbad0a4390ab37c48c6261700aa38a6e72f515b63e873d41"
)
EXPECTED_SOURCE_TOKEN_SHA256 = (
    "907e51ccf0653fa86092338f3da68fb1e359d3d54108c0e7b2d4cbae0d052881"
)
EXPECTED_TEST_TOKEN_SHA256 = (
    "c47ea7a8eb23700d2ef8a9ed7913b5be844eb1a65d4f12e5902a6312a9fb306b"
)
EXPECTED_PROVENANCE_SHA256 = (
    "c25665b5eb9f12cad8381578feeee65dd2113566a38e08d7159c7f2e1a4fdeb6"
)

TRANSCRIPT_TEST_NAMES = (
    "startup_100e92c0_handler_transcript_provenance",
    "startup_100e92c0_handler_transcript_static_gate_unit",
    "startup_100e92c0_handler_transcript_static_gate",
    "startup_100e92c0_handler_transcript_runtime",
    "startup_100e92c0_handler_transcript_post_pe_gate",
    "x64_bootstrap_load_after_startup_100e92c0_handler_transcript",
)

# Historical prefix stays fixed.  The finalized successor tail extends this
# 0x100e92c0 milestone through the sixth original-order handler, 0x100e87a0.
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
    "rome2_startup_100e8580_handler_transcript_runtime",
)
SUCCESSOR_TAIL_LIBRARIES = (
    OUTER_INITIALIZER_LIBRARY,
    PREDECESSOR_LIBRARY,
    LIBRARY,
    HANDLER_87A0_LIBRARY,
    SUFFIX_LIBRARY,
    PREFIX_LIBRARY,
    "rome2_startup_100ed3c0_empty_preloop_runtime",
    "rome2_startup_100ed471_ordinary_lifecycle_runtime",
)
HEADLESS_LINK_LIBRARIES = FROZEN_HEADLESS_LINK_PREFIX + SUCCESSOR_TAIL_LIBRARIES
PREDECESSOR_RELOAD_FIXTURE = (
    "startup_100e9340_handler_transcript_reload_verified"
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

HEADLESS_FIRST_LOW = "0x11223344"
HEADLESS_SECOND_LOW = "0x55667788"
HEADLESS_SECOND_HIGH = "0x99aabbcc"

BANNED_IDENTIFIERS = {
    "CoCreateGuid", "CreateProcessA", "CreateProcessW", "DispatchMessageA",
    "DispatchMessageW", "EnterCriticalSection", "FreeLibrary",
    "GetCurrentThreadId", "GetMessageA", "GetMessageW", "GetProcAddress",
    "GlobalMemoryStatusEx", "HeapAlloc", "HeapFree", "LoadLibraryA",
    "LoadLibraryW", "PeekMessageA", "PeekMessageW", "PostMessageA",
    "PostMessageW", "SendMessageA", "SendMessageW",
    "SteamInternal_ContextInit", "TlsAlloc", "TlsFree", "TlsGetValue",
    "TlsSetValue", "TranslateMessage", "VirtualAlloc", "VirtualFree",
    "calloc", "dlopen", "dlsym", "free", "malloc", "realloc", "system",
}

STEP_KINDS = (
    "ROME2_100E92C0_STEP_CALL_100D6970",
    "ROME2_100E92C0_STEP_CALL_10FDE370",
    "ROME2_100E92C0_STEP_CALL_10FDE9D0",
    "ROME2_100E92C0_STEP_CALL_10FDE270",
    "ROME2_100E92C0_STEP_CALL_10FDE990",
    "ROME2_100E92C0_STEP_CALL_100D5150",
)

ZERO_FINAL_CALL = (
    "rome2_100e92c0_emit_final(&effects_snapshot,&step,"
    "UINT32_C(0),UINT32_C(0),UINT32_C(0),UINT32_C(0));"
)
SUCCESS_FINAL_CALL = (
    "rome2_100e92c0_emit_final(&effects_snapshot,&step,"
    "effects_snapshot.result_10fde270_low,UINT32_C(0),"
    "effects_snapshot.result_10fde990_low,"
    "effects_snapshot.result_10fde990_high);"
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
        f"forbidden native/Steam/TLS/global/platform identifier: {identifier}"
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

    required_macros = (
        ("#defineROME2_PORT_100E92C0_ALUINT8_C(1)", "AL constant changed"),
        ("#defineROME2_PORT_100E92C0_FIRST_FALSE_STEP_COUNTUINT32_C(3)",
         "first-false three-step count changed"),
        ("#defineROME2_PORT_100E92C0_SECOND_FALSE_STEP_COUNTUINT32_C(4)",
         "second-false four-step count changed"),
        ("#defineROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNTUINT32_C(6)",
         "both-true six-step count changed"),
    )
    for fragment, message in required_macros:
        _require_once(compact, fragment, findings, message)
    for target in (
        "100D6970", "10FDE370", "10FDE9D0", "10FDE270", "10FDE990",
        "100D5150",
    ):
        fragment = (
            f"#defineROME2_PORT_100E92C0_TARGET_{target}"
            f"UINT32_C(0x{target.lower()})"
        )
        _require_once(
            compact, fragment, findings,
            f"callee evidence identity changed: {target.lower()}",
        )

    enum_body = (
        "typedefenumrome2_100e92c0_step_kind{"
        + ",".join(f"{kind}={index}" for index, kind in enumerate(STEP_KINDS, 1))
        + "}rome2_100e92c0_step_kind;"
    )
    _require_once(compact, enum_body, findings, "typed six-kind order changed")
    step_type = (
        "typedefstructrome2_100e92c0_step{"
        "rome2_100e92c0_step_kindkind;uint32_targument_count;"
        "uint32_targument0;uint32_targument1;uint32_targument2;"
        "uint32_targument3;uint32_tresult_count;uint32_tresult0;"
        "uint32_tresult1;uint32_tlocal_before0;uint32_tlocal_before1;"
        "uint32_tlocal_after0;uint32_tlocal_after1;}"
        "rome2_100e92c0_step;"
    )
    _require_once(
        compact, step_type, findings,
        "typed argument/result/local-dependency layout changed",
    )
    callback_type = (
        "typedefvoid(*rome2_100e92c0_emit_step_fn)("
        "void*context,rome2_100e92c0_stepstep);"
    )
    _require_once(compact, callback_type, findings, "by-value callback contract changed")
    effects_type = (
        "typedefstructrome2_100e92c0_transcript_effects{"
        "rome2_100e92c0_emit_step_fnemit_step;void*context;"
        "uint32_tpredicate_10fde370;uint32_tpredicate_10fde9d0;"
        "uint32_tresult_10fde270_low;uint32_tresult_10fde990_low;"
        "uint32_tresult_10fde990_high;}"
        "rome2_100e92c0_transcript_effects;"
    )
    _require_once(
        compact, effects_type, findings,
        "complete predicate/getter-result effects layout changed",
    )
    declaration = (
        "rome2_guest_status" + FUNCTION + "("
        "rome2_guest_addr32guest_receiver,rome2_guest_addr32guest_argument,"
        "constrome2_100e92c0_transcript_effects*effects,uint8_t*return_al_out);"
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
        "ported_100e92c0_handler_transcript.h", "stddef.h", "stdint.h"
    ]:
        findings.append("source include containment changed")
    findings.extend(_banned_findings(code))
    if "#pragmacomment(lib" in compact.lower():
        findings.append("native library autolinking is forbidden")

    required = (
        ("status=rome2_100e92c0_validate_object(effects,sizeof(*effects));",
         "effects borrowed-object validation changed"),
        ("status=rome2_100e92c0_validate_object(return_al_out,"
         "sizeof(*return_al_out));", "AL borrowed-object validation changed"),
        ("(uintptr_t)effects%_Alignof(rome2_100e92c0_transcript_effects)!=0U||"
         "rome2_100e92c0_ranges_overlap(effects,sizeof(*effects),"
         "return_al_out,sizeof(*return_al_out))",
         "effects alignment/output-alias rejection changed"),
        ("effects_snapshot=*effects;", "complete effects snapshot changed"),
        ("effects_snapshot.emit_step==NULL||effects_snapshot.context==NULL||"
         "effects_snapshot.predicate_10fde370>UINT32_C(1)||"
         "effects_snapshot.predicate_10fde9d0>UINT32_C(1)",
         "callback/context/predicate validation changed"),
        ("(void)guest_receiver;(void)guest_argument;",
         "opaque ignored receiver/argument contract changed"),
        ("step->kind=ROME2_100E92C0_STEP_CALL_100D5150;"
         "step->argument_count=UINT32_C(4);"
         "step->argument0=argument0;step->argument1=argument1;"
         "step->argument2=argument2;step->argument3=argument3;"
         "effects->emit_step(effects->context,*step);",
         "final injected-call helper changed"),
    )
    for fragment, message in required:
        if fragment not in compact:
            findings.append(message)

    step_blocks = (
        "rome2_100e92c0_clear_step(&step);"
        "step.kind=ROME2_100E92C0_STEP_CALL_100D6970;"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100e92c0_clear_step(&step);"
        "step.kind=ROME2_100E92C0_STEP_CALL_10FDE370;"
        "step.result_count=UINT32_C(1);"
        "step.result0=effects_snapshot.predicate_10fde370;"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100e92c0_clear_step(&step);"
        "step.kind=ROME2_100E92C0_STEP_CALL_10FDE9D0;"
        "step.result_count=UINT32_C(1);"
        "step.result0=effects_snapshot.predicate_10fde9d0;"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100e92c0_clear_step(&step);"
        "step.kind=ROME2_100E92C0_STEP_CALL_10FDE270;"
        "step.result_count=UINT32_C(2);"
        "step.result0=effects_snapshot.result_10fde270_low;"
        "step.result1=UINT32_C(0);"
        "step.local_after0=effects_snapshot.result_10fde270_low;"
        "step.local_after1=UINT32_C(0);"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
        "rome2_100e92c0_clear_step(&step);"
        "step.kind=ROME2_100E92C0_STEP_CALL_10FDE990;"
        "step.result_count=UINT32_C(2);"
        "step.result0=effects_snapshot.result_10fde990_low;"
        "step.result1=effects_snapshot.result_10fde990_high;"
        "step.local_before0=effects_snapshot.result_10fde270_low;"
        "step.local_before1=UINT32_C(0);"
        "step.local_after0=effects_snapshot.result_10fde990_low;"
        "step.local_after1=effects_snapshot.result_10fde990_high;"
        "effects_snapshot.emit_step(effects_snapshot.context,step);",
    )
    positions = []
    previous = -1
    for index, block in enumerate(step_blocks, 1):
        position = compact.find(block)
        positions.append(position)
        if position < 0:
            findings.append(f"typed route step {index} arguments/result changed")
        elif position <= previous:
            findings.append("typed route steps are not in authenticated order")
        previous = position
    if compact.count(
        "effects_snapshot.emit_step(effects_snapshot.context,step);"
    ) != 5:
        findings.append("source must emit exactly five non-final snapshotted steps")
    if compact.count("rome2_100e92c0_clear_step(&step);") != 5:
        findings.append("every non-final route step must clear unused fields")
    if compact.count("rome2_100e92c0_clear_step(step);") != 1:
        findings.append("final route step must clear unused fields")

    first_branch = (
        "if(effects_snapshot.predicate_10fde370==UINT32_C(0)){"
        + ZERO_FINAL_CALL +
        "*return_al_out=ROME2_PORT_100E92C0_AL;returnROME2_GUEST_OK;}"
    )
    second_branch = (
        "if(effects_snapshot.predicate_10fde9d0==UINT32_C(0)){"
        + ZERO_FINAL_CALL +
        "*return_al_out=ROME2_PORT_100E92C0_AL;returnROME2_GUEST_OK;}"
    )
    success = (
        SUCCESS_FINAL_CALL +
        "*return_al_out=ROME2_PORT_100E92C0_AL;returnROME2_GUEST_OK;"
    )
    _require_once(compact, first_branch, findings, "first-false route changed")
    _require_once(compact, second_branch, findings, "second-false route changed")
    _require_once(compact, success, findings, "both-true dependent-result route changed")
    if compact.count(ZERO_FINAL_CALL) != 2:
        findings.append("both false routes must inject exactly four zero arguments")
    if compact.count(SUCCESS_FINAL_CALL) != 1:
        findings.append("true route final four-argument forwarding changed")
    if compact.count("*return_al_out=ROME2_PORT_100E92C0_AL;") != 3:
        findings.append("AL must publish once on each of the three routes")

    ordered = positions[:2] + [compact.find(first_branch), positions[2],
        compact.find(second_branch), positions[3], positions[4], compact.find(success)]
    if any(position < 0 for position in ordered) or any(
        left >= right for left, right in zip(ordered, ordered[1:])
    ):
        findings.append("3/4/6 route control-flow order changed")

    snapshot_position = compact.find("effects_snapshot=*effects;")
    first_emit = compact.find(
        "effects_snapshot.emit_step(effects_snapshot.context,step);"
    )
    alias_position = compact.find("rome2_100e92c0_ranges_overlap(")
    if not (0 <= alias_position < snapshot_position < first_emit):
        findings.append("alias validation and snapshot must precede every effect")
    main_body = _function_body(code, FUNCTION)
    if main_body is None:
        findings.append("public transcript definition is missing")
    elif "effects->" in main_body:
        findings.append("route decisions/results must be read only from the snapshot")
    if code.count("guest_receiver") != 2 or code.count("guest_argument") != 2:
        findings.append("receiver and stack argument must remain opaque and ignored")
    if re.search(
        r"\([^)]*\*[^)]*\)\s*(?:guest_receiver|guest_argument)", code
    ):
        findings.append("guest identities must never be cast to host pointers")
    for target in (
        "100d6970", "10fde370", "10fde9d0", "10fde270", "10fde990",
        "100d5150",
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
        "ported_100e92c0_handler_transcript.h", "stddef.h", "stdint.h",
        "stdio.h", "string.h",
    ]:
        findings.append("runtime oracle include containment changed")
    findings.extend(_banned_findings(code))

    required = (
        ("#defineROME2_TEST_MAX_STEPSUINT32_C(6)",
         "runtime maximum six-step oracle changed"),
        ("#defineROME2_TEST_SENTINELUINT8_C(0xcc)",
         "runtime unpublished-AL sentinel changed"),
        ("*trace->return_al!=ROME2_TEST_SENTINEL",
         "callbacks must observe unpublished AL"),
        ("step->argument_count=UINT32_C(4);step->argument0=argument0;"
         "step->argument1=argument1;step->argument2=argument2;"
         "step->argument3=argument3;", "runtime final argument oracle changed"),
        ("trace->expected[index].result0=first_low;"
         "trace->expected[index].local_after0=first_low;",
         "runtime first getter/zero-high oracle changed"),
        ("trace->expected[index].local_before0=first_low;"
         "trace->expected[index].local_after0=second_low;"
         "trace->expected[index].local_after1=second_high;",
         "runtime shared-local dependency oracle changed"),
        ("trace->effects.emit_step=rome2_test_unexpected_emit;"
         "trace->effects.context=&trace->unexpected_call_count;"
         "trace->effects.predicate_10fde370=UINT32_C(0);"
         "trace->effects.predicate_10fde9d0=UINT32_C(0);",
         "runtime complete-effects snapshot mutant changed"),
        ("UINTPTR_MAX-(uintptr_t)sizeof(rome2_100e92c0_transcript_effects)+"
         "(uintptr_t)2U", "runtime host-overflow case changed"),
        ("storage.bytes+1U", "runtime misalignment case changed"),
        ("(uint8_t*)(void*)&trace.effects.result_10fde270_low",
         "runtime effects/output alias case changed"),
        ("trace.effects.emit_step=NULL", "runtime null-callback case changed"),
        ("trace.effects.context=NULL", "runtime null-context case changed"),
    )
    for fragment, message in required:
        if fragment not in compact:
            findings.append(message)
    for label, message in (
        ("first predicate false", "first-false route case missing"),
        ("second predicate false", "second-false route case missing"),
        ("both predicates true", "both-true route case missing"),
        ("wide first predicate", "runtime wide-first-predicate case missing"),
        ("wide inactive second predicate",
         "runtime inactive malformed-predicate case missing"),
    ):
        if text.count(label) != 1:
            findings.append(message)
    for function in (
        "rome2_test_exact_branch_routes",
        "rome2_test_ignored_inputs_and_result_boundaries",
        "rome2_test_effects_snapshot_is_complete",
        "rome2_test_invalid_borrowed_objects",
        "rome2_test_invalid_effect_values",
    ):
        if compact.count(function + "(") != 2:
            findings.append(f"runtime coverage function changed: {function}")
    if compact.count(FUNCTION + "(") != 2:
        findings.append("runtime must exercise completed and precommit paths")
    if text.count("100e92c0 handler transcript: ok") != 1:
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
        "FUNCTION_VA=0x100E92C0",
        "FUNCTION_SHA256=\"6a667df2e872494bc91549ca47c5fe87664bfe94737a065b8bd7018154715e6d\"",
        "FUNCTION_RAW_OFFSET=0x000E86C0",
        "DIRECT_CALL_OFFSETS=(5,25,34,48,63,98)",
        "0x100D6970,0x10FDE370,0x10FDE9D0,0x10FDE270,0x10FDE990,0x100D5150",
        "FIRST_FALSE_BRANCH_OFFSET=32",
        "SECOND_FALSE_BRANCH_OFFSET=41",
        "SUCCESS_JOIN_BRANCH_OFFSET=76",
        "FALLBACK_VA=0x100E930E",
        "FINAL_CALL_SETUP_VA=0x100E931E",
        "VTABLE_PAIR_VA=0x1173F2EC",
        "VTABLE_PAIR_BYTES=bytes.fromhex(\"c0180e10c0920e10\")",
        "STEAM_CONTEXT_IAT_VA=0x1172F94C",
        "e2e45622dc3e817af4ec90e4af9df774f9d9e3553cee5e1f6dc6a12236d6146a",
        "2454175dea78e57e058f7112b03e4d6c4d2cdee92cba2ea9f3ba636f0282d6d9",
        "GETTER_270_BYTES[-16:]",
        "GETTER_990_BYTES[-20:]",
        "(\"steam_api.dll\",\"SteamInternal_ContextInit\")",
        "self.assertNotIn(bytes.fromhex(\"b801000000\"),FUNCTION_BYTES)",
        "self.assertEqual(before,b\"\\xcc\"*12)",
    )
    for fragment in required:
        if fragment not in compact:
            findings.append(f"provenance authority marker changed: {fragment[:76]}")
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
    include_names = (
        "ported_100df270_platform_prefix_transcript.h",
        "ported_100df270_suffix_transcript.h",
        "ported_100e2460_router.h",
        "ported_100e8d00_handler_transcript.h",
        "ported_100e85d0_normal_adapter.h",
        "ported_100e8580_handler_transcript.h",
        "ported_100e9340_handler_transcript.h",
        "ported_100e92c0_handler_transcript.h",
        "ported_100e87a0_handler_transcript.h",
        "ported_100ea4d0_injected.h",
    )
    positions = [text.find(f'#include "{name}"') for name in include_names]
    if any(position < 0 for position in positions) or any(
        left >= right for left, right in zip(positions, positions[1:])
    ):
        findings.append(
            "headless include order must reach outer through 9340, 92c0, then 87a0"
        )
    if compact.count(FUNCTION + "(") != 2:
        findings.append("headless must execute the 100e92c0 transcript exactly twice")
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
        "&context->handler_92c0_effects,&handler_al);"
    )
    if compact.count(call) != 2:
        findings.append("headless two 100e92c0 call arguments changed")
    router_dispatch = _function_body(code, "rome2_headless_router_dispatch")
    outer_dispatch = _function_body(code, "rome2_headless_outer_dispatch")
    if router_dispatch is None or _compact(router_dispatch).count(call) != 1:
        findings.append("standalone router dispatch must call 100e92c0 exactly once")
    if outer_dispatch is None or _compact(outer_dispatch).count(call) != 1:
        findings.append("injected outer dispatch must call 100e92c0 exactly once")

    required = (
        ("#defineROME2_HEADLESS_92C0_FIRST_LOWUINT32_C(0x11223344)",
         "headless first-result identity changed"),
        ("#defineROME2_HEADLESS_92C0_SECOND_LOWUINT32_C(0x55667788)",
         "headless second-low identity changed"),
        ("#defineROME2_HEADLESS_92C0_SECOND_HIGHUINT32_C(0x99aabbcc)",
         "headless second-high identity changed"),
        ("context->handler_92c0_context.return_al=&handler_al;",
         "composed calls must expose unpublished AL to the callback"),
        ("handler_status!=ROME2_GUEST_OK||"
         "handler_al!=ROME2_PORT_100E92C0_AL||"
         "context->handler_92c0_calls!=UINT32_C(1)",
         "headless status/AL/call oracle changed"),
        ("router_effect_context.handler_92c0_effects.emit_step="
         "rome2_headless_92c0_emit;", "router injected callback wiring changed"),
        ("outer_effect_context.handler_92c0_effects.emit_step="
         "rome2_headless_92c0_emit;", "outer injected callback wiring changed"),
        ("router_effect_context.handler_92c0_effects.predicate_10fde370="
         "UINT32_C(1);", "router first-predicate injection changed"),
        ("router_effect_context.handler_92c0_effects.predicate_10fde9d0="
         "UINT32_C(1);", "router second-predicate injection changed"),
        ("outer_effect_context.handler_92c0_effects.predicate_10fde370="
         "UINT32_C(1);", "outer first-predicate injection changed"),
        ("outer_effect_context.handler_92c0_effects.predicate_10fde9d0="
         "UINT32_C(1);", "outer second-predicate injection changed"),
        ("router_effect_context.handler_92c0_effects.result_10fde270_low="
         "ROME2_HEADLESS_92C0_FIRST_LOW;", "router first-result injection changed"),
        ("outer_effect_context.handler_92c0_effects.result_10fde270_low="
         "ROME2_HEADLESS_92C0_FIRST_LOW;", "outer first-result injection changed"),
        ("router_effect_context.handler_92c0_effects.result_10fde990_low="
         "ROME2_HEADLESS_92C0_SECOND_LOW;", "router second-low injection changed"),
        ("outer_effect_context.handler_92c0_effects.result_10fde990_low="
         "ROME2_HEADLESS_92C0_SECOND_LOW;", "outer second-low injection changed"),
        ("router_effect_context.handler_92c0_effects.result_10fde990_high="
         "ROME2_HEADLESS_92C0_SECOND_HIGH;", "router second-high injection changed"),
        ("outer_effect_context.handler_92c0_effects.result_10fde990_high="
         "ROME2_HEADLESS_92C0_SECOND_HIGH;", "outer second-high injection changed"),
        ("context->return_al==NULL||*context->return_al!=UINT8_C(0xcc)",
         "headless callback publication oracle changed"),
        ("router_effect_context.handler_92c0_context.observed_steps!="
         "ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT",
         "router six-step completion oracle changed"),
        ("outer_effect_context.handler_92c0_context.observed_steps!="
         "ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT",
         "outer six-step completion oracle changed"),
    )
    for fragment, message in required:
        if fragment not in compact:
            findings.append(message)

    step_positions = [compact.find(kind) for kind in STEP_KINDS]
    if any(position < 0 for position in step_positions):
        findings.append("headless typed six-step oracle is incomplete")
    elif any(left >= right for left, right in zip(step_positions, step_positions[1:])):
        findings.append("headless typed six-step oracle order changed")
    for kind in STEP_KINDS:
        if compact.count(kind) != 1:
            findings.append(f"headless step kind must occur once: {kind}")
    for fragment, message in (
        ("ROME2_100E92C0_STEP_CALL_10FDE270,0,0,0,0,0,2,"
         "ROME2_HEADLESS_92C0_FIRST_LOW,0,0,0,"
         "ROME2_HEADLESS_92C0_FIRST_LOW,0",
         "headless first getter/zero-high oracle changed"),
        ("ROME2_100E92C0_STEP_CALL_10FDE990,0,0,0,0,0,2,"
         "ROME2_HEADLESS_92C0_SECOND_LOW,ROME2_HEADLESS_92C0_SECOND_HIGH,"
         "ROME2_HEADLESS_92C0_FIRST_LOW,0,ROME2_HEADLESS_92C0_SECOND_LOW,"
         "ROME2_HEADLESS_92C0_SECOND_HIGH",
         "headless shared-local dependency oracle changed"),
        ("ROME2_100E92C0_STEP_CALL_100D5150,4,"
         "ROME2_HEADLESS_92C0_FIRST_LOW,0,ROME2_HEADLESS_92C0_SECOND_LOW,"
         "ROME2_HEADLESS_92C0_SECOND_HIGH,0,0,0,0,0,0,0",
         "headless final four-argument oracle changed"),
    ):
        if fragment not in compact:
            findings.append(message)

    token_sequence = FROZEN_HANDLER_TOKEN_PREFIX + SUCCESSOR_HANDLER_TOKEN_TAIL
    token_positions = []
    for token in token_sequence:
        if text.count(token) != 1:
            findings.append(f"headless truthful status token changed: {token}")
        token_positions.append(text.find(token))
    if any(position < 0 for position in token_positions) or any(
        left >= right for left, right in zip(token_positions, token_positions[1:])
    ):
        findings.append("headless original-order handler/outer token sequence changed")
    for forbidden in (
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
        "ported_100e92c0_handler_transcript.h",
        "ported_100e92c0_handler_transcript.c",
        "test_startup_100e92c0_handler_transcript.c",
        "test_x64_startup_100e92c0_handler_transcript_provenance.py",
        "test_x64_startup_100e92c0_handler_transcript_static_gate.py",
        "x64_startup_100e92c0_handler_transcript_static_gate.py",
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
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e92c0_handler_transcript.h"'
        '"${ROME2_GUEST32_PORTED_DIR}/ported_100e92c0_handler_transcript.c")'
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
         '"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e92c0_handler_transcript.c")',
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
        findings.append(
            "exact headless tail must end outer, 9340, 92c0, 87a0, suffix, "
            "platform-prefix"
        )

    gate_start = compact.find(
        "add_test(NAMEstartup_100e92c0_handler_transcript_static_gateCOMMAND"
    )
    gate_end = compact.find("add_test(", gate_start + 1)
    gate_scope = compact[gate_start:gate_end] if gate_start >= 0 else ""
    for argument in (
        '--header"${ROME2_GUEST32_PORTED_DIR}/ported_100e92c0_handler_transcript.h"',
        '--source"${ROME2_GUEST32_PORTED_DIR}/ported_100e92c0_handler_transcript.c"',
        '--test"${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e92c0_handler_transcript.c"',
        '--transcript-provenance"${CMAKE_CURRENT_SOURCE_DIR}/scripts/'
        'test_x64_startup_100e92c0_handler_transcript_provenance.py"',
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
        "set_tests_properties(startup_100e92c0_handler_transcript_provenance"
        "PROPERTIESFIXTURES_SETUPstartup_100e92c0_handler_transcript_provenance_verified)",
        "set_tests_properties(startup_100e92c0_handler_transcript_static_gate_unit"
        "PROPERTIESFIXTURES_SETUPstartup_100e92c0_handler_transcript_static_tool_verified)",
        "set_tests_properties(startup_100e92c0_handler_transcript_static_gate"
        "PROPERTIESFIXTURES_REQUIREDstartup_100e92c0_handler_transcript_static_tool_verified"
        "FIXTURES_SETUPstartup_100e92c0_handler_transcript_static_verified)",
        "set_tests_properties(startup_100e92c0_handler_transcript_runtimePROPERTIES"
        f"FIXTURES_REQUIRED\"{PREDECESSOR_RELOAD_FIXTURE};"
        "startup_100e92c0_handler_transcript_provenance_verified;"
        "startup_100e92c0_handler_transcript_static_verified\""
        "FIXTURES_SETUPstartup_100e92c0_handler_transcript_runtime_verifiedTIMEOUT90)",
        "set_tests_properties(startup_100e92c0_handler_transcript_post_pe_gate"
        "PROPERTIESFIXTURES_REQUIRED\""
        "startup_100e92c0_handler_transcript_runtime_verified;"
        "entry_policy_probe_pe_tool_verified\""
        "FIXTURES_SETUPstartup_100e92c0_handler_transcript_post_verified)",
        "set_tests_properties(x64_bootstrap_load_after_startup_100e92c0_handler_transcript"
        "PROPERTIESFIXTURES_REQUIRED\"x64_bootstrap_pre_verified;"
        "startup_100e92c0_handler_transcript_post_verified\""
        "FIXTURES_SETUPstartup_100e92c0_handler_transcript_reload_verified)",
        "set_tests_properties(startup_100e9340_handler_transcript_runtimePROPERTIES"
        "FIXTURES_REQUIRED\"startup_100ea4d0_injected_reload_verified;"
        "startup_100e9340_handler_transcript_provenance_verified;"
        "startup_100e9340_handler_transcript_static_verified\""
        "FIXTURES_SETUPstartup_100e9340_handler_transcript_runtime_verifiedTIMEOUT90)",
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
        FUNCTION.lower(), LIBRARY.lower(), "rome2_100e92c0_handler_transcript",
        "ported_100e92c0_handler_transcript", "100e92c0_handler_transcript",
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

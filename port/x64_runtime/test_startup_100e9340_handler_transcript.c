#include "ported_100e9340_handler_transcript.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_STEP_COUNT UINT32_C(4)
#define ROME2_TEST_SENTINEL UINT8_C(0xcc)

_Static_assert(
    ROME2_PORT_100E9340_STEP_COUNT == ROME2_TEST_STEP_COUNT,
    "the public transcript must remain four steps");
_Static_assert(
    _Alignof(rome2_100e9340_transcript_effects) > 1U,
    "the misalignment oracle requires a naturally aligned effects object");

typedef struct rome2_test_trace {
    rome2_100e9340_transcript_effects effects;
    rome2_100e9340_step expected[ROME2_TEST_STEP_COUNT];
    rome2_100e9340_step observed[ROME2_TEST_STEP_COUNT];
    uint8_t *return_al;
    uint32_t call_count;
    uint32_t failure_count;
    uint32_t unexpected_call_count;
    int mutate_effects_after_first;
} rome2_test_trace;

typedef union rome2_test_aligned_storage {
    rome2_100e9340_transcript_effects alignment;
    uint8_t bytes[
        sizeof(rome2_100e9340_transcript_effects) +
        _Alignof(rome2_100e9340_transcript_effects)];
} rome2_test_aligned_storage;

static int rome2_test_steps_equal(
    const rome2_100e9340_step *left,
    const rome2_100e9340_step *right)
{
    return
        left->kind == right->kind &&
        left->argument_count == right->argument_count &&
        left->argument0 == right->argument0 &&
        left->argument1 == right->argument1 &&
        left->argument2 == right->argument2 &&
        left->result_width_bytes == right->result_width_bytes &&
        left->result_u32 == right->result_u32;
}

static void rome2_test_unexpected_emit(
    void *context,
    rome2_100e9340_step step)
{
    uint32_t *count = (uint32_t *)context;

    (void)step;
    *count += UINT32_C(1);
}

static void rome2_test_emit(
    void *context,
    rome2_100e9340_step step)
{
    rome2_test_trace *trace = (rome2_test_trace *)context;
    uint32_t index = trace->call_count;

    if (trace->return_al == NULL ||
        *trace->return_al != ROME2_TEST_SENTINEL) {
        trace->failure_count += UINT32_C(1);
    }
    if (index >= ROME2_TEST_STEP_COUNT) {
        trace->failure_count += UINT32_C(1);
        return;
    }

    trace->observed[index] = step;
    if (!rome2_test_steps_equal(&step, &trace->expected[index])) {
        trace->failure_count += UINT32_C(1);
    }
    trace->call_count = index + UINT32_C(1);

    if (index == UINT32_C(0) && trace->mutate_effects_after_first) {
        trace->effects.emit_step = rome2_test_unexpected_emit;
        trace->effects.context = &trace->unexpected_call_count;
        trace->effects.selected_dword_12 = UINT32_C(0x01020304);
        trace->effects.selected_byte_49 = UINT32_C(0x5a);
    }
}

static void rome2_test_set_step(
    rome2_100e9340_step *step,
    uint32_t kind,
    uint32_t argument_count,
    uint32_t argument0,
    uint32_t argument1,
    uint32_t argument2,
    uint32_t result_width_bytes,
    uint32_t result_u32)
{
    step->kind = (rome2_100e9340_step_kind)kind;
    step->argument_count = argument_count;
    step->argument0 = argument0;
    step->argument1 = argument1;
    step->argument2 = argument2;
    step->result_width_bytes = result_width_bytes;
    step->result_u32 = result_u32;
}

static void rome2_test_trace_init(
    rome2_test_trace *trace,
    uint32_t receiver,
    uint32_t selected_dword,
    uint32_t selected_byte,
    uint8_t *return_al)
{
    uint32_t patched_receiver =
        (receiver & UINT32_C(0xffffff00)) | selected_byte;

    (void)memset(trace, 0, sizeof(*trace));
    trace->effects.emit_step = rome2_test_emit;
    trace->effects.context = trace;
    trace->effects.selected_dword_12 = selected_dword;
    trace->effects.selected_byte_49 = selected_byte;
    trace->return_al = return_al;

    rome2_test_set_step(
        &trace->expected[0],
        UINT32_C(1), UINT32_C(1), UINT32_C(0x12),
        UINT32_C(0), UINT32_C(0), UINT32_C(4), selected_dword);
    rome2_test_set_step(
        &trace->expected[1],
        UINT32_C(2), UINT32_C(1), UINT32_C(0x49),
        UINT32_C(0), UINT32_C(0), UINT32_C(1), selected_byte);
    rome2_test_set_step(
        &trace->expected[2],
        UINT32_C(3), UINT32_C(0), UINT32_C(0),
        UINT32_C(0), UINT32_C(0), UINT32_C(0), UINT32_C(0));
    rome2_test_set_step(
        &trace->expected[3],
        UINT32_C(4), UINT32_C(3), selected_dword,
        patched_receiver, UINT32_C(0), UINT32_C(0), UINT32_C(0));
}

static int rome2_test_run_success_case(
    const char *label,
    uint32_t receiver,
    uint32_t argument,
    uint32_t selected_dword,
    uint32_t selected_byte,
    int mutate_effects)
{
    rome2_test_trace trace;
    rome2_guest_status status;
    uint8_t return_al = ROME2_TEST_SENTINEL;

    rome2_test_trace_init(
        &trace, receiver, selected_dword, selected_byte, &return_al);
    trace.mutate_effects_after_first = mutate_effects;
    status = rome2_port_100e9340_run_handler_transcript(
        (rome2_guest_addr32){receiver},
        (rome2_guest_addr32){argument},
        &trace.effects,
        &return_al);

    if (status != ROME2_GUEST_OK ||
        trace.call_count != ROME2_TEST_STEP_COUNT ||
        trace.failure_count != UINT32_C(0) ||
        trace.unexpected_call_count != UINT32_C(0) ||
        return_al != UINT8_C(1)) {
        (void)fprintf(
            stderr,
            "%s: status/calls/failures/unexpected/AL = %d/%u/%u/%u/%u\n",
            label,
            (int)status,
            (unsigned int)trace.call_count,
            (unsigned int)trace.failure_count,
            (unsigned int)trace.unexpected_call_count,
            (unsigned int)return_al);
        return 1;
    }

    if (!mutate_effects &&
        (trace.effects.emit_step != rome2_test_emit ||
         trace.effects.context != &trace ||
         trace.effects.selected_dword_12 != selected_dword ||
         trace.effects.selected_byte_49 != selected_byte)) {
        (void)fprintf(stderr, "%s: adapter mutated the effects object\n", label);
        return 1;
    }
    if (mutate_effects &&
        (trace.effects.emit_step != rome2_test_unexpected_emit ||
         trace.effects.context != &trace.unexpected_call_count ||
         trace.effects.selected_dword_12 != UINT32_C(0x01020304) ||
         trace.effects.selected_byte_49 != UINT32_C(0x5a))) {
        (void)fprintf(stderr, "%s: callback mutation was not retained\n", label);
        return 1;
    }
    return 0;
}

static int rome2_test_success_and_exact_order(void)
{
    return rome2_test_run_success_case(
        "success",
        UINT32_C(0x12345678),
        UINT32_C(0xfedcba98),
        UINT32_C(0x89abcdef),
        UINT32_C(0xa5),
        0);
}

static int rome2_test_receiver_boundaries_and_ignored_argument(void)
{
    static const struct rome2_test_case {
        uint32_t receiver;
        uint32_t argument;
        uint32_t selected_dword;
        uint32_t selected_byte;
    } cases[] = {
        {UINT32_C(0), UINT32_C(0), UINT32_C(0), UINT32_C(0)},
        {UINT32_C(0xffffffff), UINT32_C(0xffffffff),
         UINT32_C(0x80000000), UINT32_C(0)},
        {UINT32_C(0xabcdef00), UINT32_C(0x80000000),
         UINT32_C(0x7fffffff), UINT32_C(0xff)},
        {UINT32_C(0x000000ff), UINT32_C(0x11223344),
         UINT32_C(0xffffffff), UINT32_C(1)},
    };
    size_t index;
    int failures = 0;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        failures += rome2_test_run_success_case(
            "receiver-boundary",
            cases[index].receiver,
            cases[index].argument,
            cases[index].selected_dword,
            cases[index].selected_byte,
            0);
    }
    return failures;
}

static int rome2_test_effects_snapshot_is_complete(void)
{
    return rome2_test_run_success_case(
        "snapshot",
        UINT32_C(0xa1b2c3d4),
        UINT32_C(0x55667788),
        UINT32_C(0xdeadbeef),
        UINT32_C(0x19),
        1);
}

static int rome2_test_expect_precommit_failure(
    const char *label,
    rome2_guest_status expected_status,
    rome2_test_trace *trace,
    const rome2_100e9340_transcript_effects *effects,
    uint8_t *return_al)
{
    rome2_guest_status status =
        rome2_port_100e9340_run_handler_transcript(
            (rome2_guest_addr32){UINT32_C(0x12345678)},
            (rome2_guest_addr32){UINT32_C(0x87654321)},
            effects,
            return_al);

    if (status != expected_status ||
        trace->call_count != UINT32_C(0) ||
        trace->failure_count != UINT32_C(0) ||
        trace->unexpected_call_count != UINT32_C(0) ||
        (return_al != NULL && *return_al != ROME2_TEST_SENTINEL)) {
        (void)fprintf(
            stderr,
            "%s: precommit status/calls/output mismatch (%d/%u/%u)\n",
            label,
            (int)status,
            (unsigned int)trace->call_count,
            return_al == NULL ? 0U : (unsigned int)*return_al);
        return 1;
    }
    return 0;
}

static int rome2_test_invalid_borrowed_objects(void)
{
    rome2_test_trace trace;
    rome2_test_aligned_storage storage;
    rome2_100e9340_transcript_effects *misaligned;
    const rome2_100e9340_transcript_effects *overflowing;
    uint8_t return_al;
    uint8_t *aliased_output;
    int failures = 0;

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(0x12345678), UINT32_C(0x11223344),
        UINT32_C(0x55), &return_al);
    failures += rome2_test_expect_precommit_failure(
        "null-effects", ROME2_GUEST_BAD_ARGUMENT,
        &trace, NULL, &return_al);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(0x12345678), UINT32_C(0x11223344),
        UINT32_C(0x55), &return_al);
    failures += rome2_test_expect_precommit_failure(
        "null-output", ROME2_GUEST_BAD_ARGUMENT,
        &trace, &trace.effects, NULL);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(0x12345678), UINT32_C(0x11223344),
        UINT32_C(0x55), &return_al);
    overflowing =
        (const rome2_100e9340_transcript_effects *)(uintptr_t)(
            UINTPTR_MAX -
            (uintptr_t)sizeof(rome2_100e9340_transcript_effects) +
            (uintptr_t)2U);
    failures += rome2_test_expect_precommit_failure(
        "overflowing-effects", ROME2_GUEST_RANGE_OVERFLOW,
        &trace, overflowing, &return_al);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(0x12345678), UINT32_C(0x11223344),
        UINT32_C(0x55), &return_al);
    misaligned =
        (rome2_100e9340_transcript_effects *)(void *)(storage.bytes + 1U);
    failures += rome2_test_expect_precommit_failure(
        "misaligned-effects", ROME2_GUEST_BAD_ARGUMENT,
        &trace, misaligned, &return_al);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(0x12345678), UINT32_C(0x11223344),
        UINT32_C(0x55), &return_al);
    aliased_output = (uint8_t *)(void *)&trace.effects.selected_byte_49;
    *aliased_output = ROME2_TEST_SENTINEL;
    failures += rome2_test_expect_precommit_failure(
        "effects-output-alias", ROME2_GUEST_BAD_ARGUMENT,
        &trace, &trace.effects, aliased_output);

    return failures;
}

static int rome2_test_invalid_effect_values(void)
{
    rome2_test_trace trace;
    uint8_t return_al;
    int failures = 0;

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(0x12345678), UINT32_C(0x11223344),
        UINT32_C(0x55), &return_al);
    trace.effects.emit_step = NULL;
    failures += rome2_test_expect_precommit_failure(
        "null-callback", ROME2_GUEST_BAD_ARGUMENT,
        &trace, &trace.effects, &return_al);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(0x12345678), UINT32_C(0x11223344),
        UINT32_C(0x55), &return_al);
    trace.effects.context = NULL;
    failures += rome2_test_expect_precommit_failure(
        "null-context", ROME2_GUEST_BAD_ARGUMENT,
        &trace, &trace.effects, &return_al);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(0x12345678), UINT32_C(0x11223344),
        UINT32_C(0x55), &return_al);
    trace.effects.selected_byte_49 = UINT32_C(0x100);
    failures += rome2_test_expect_precommit_failure(
        "wide-byte", ROME2_GUEST_BAD_ARGUMENT,
        &trace, &trace.effects, &return_al);

    return failures;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_success_and_exact_order();
    failures += rome2_test_receiver_boundaries_and_ignored_argument();
    failures += rome2_test_effects_snapshot_is_complete();
    failures += rome2_test_invalid_borrowed_objects();
    failures += rome2_test_invalid_effect_values();

    if (failures != 0) {
        (void)fprintf(
            stderr,
            "100e9340 handler transcript: %d failure(s)\n",
            failures);
        return 1;
    }
    (void)puts("100e9340 handler transcript: ok");
    return 0;
}

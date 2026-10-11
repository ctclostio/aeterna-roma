#include "ported_100e92c0_handler_transcript.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_MAX_STEPS UINT32_C(6)
#define ROME2_TEST_SENTINEL UINT8_C(0xcc)

_Static_assert(
    ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT == ROME2_TEST_MAX_STEPS,
    "the longest authenticated route must remain six steps");
_Static_assert(
    _Alignof(rome2_100e92c0_transcript_effects) > 1U,
    "the misalignment oracle requires a naturally aligned effects object");

typedef struct rome2_test_trace {
    rome2_100e92c0_transcript_effects effects;
    rome2_100e92c0_step expected[ROME2_TEST_MAX_STEPS];
    rome2_100e92c0_step observed[ROME2_TEST_MAX_STEPS];
    uint8_t *return_al;
    uint32_t expected_count;
    uint32_t call_count;
    uint32_t failure_count;
    uint32_t unexpected_call_count;
    int mutate_effects_after_first;
} rome2_test_trace;

typedef union rome2_test_aligned_storage {
    rome2_100e92c0_transcript_effects alignment;
    uint8_t bytes[
        sizeof(rome2_100e92c0_transcript_effects) +
        _Alignof(rome2_100e92c0_transcript_effects)];
} rome2_test_aligned_storage;

static int rome2_test_steps_equal(
    const rome2_100e92c0_step *left,
    const rome2_100e92c0_step *right)
{
    return
        left->kind == right->kind &&
        left->argument_count == right->argument_count &&
        left->argument0 == right->argument0 &&
        left->argument1 == right->argument1 &&
        left->argument2 == right->argument2 &&
        left->argument3 == right->argument3 &&
        left->result_count == right->result_count &&
        left->result0 == right->result0 &&
        left->result1 == right->result1 &&
        left->local_before0 == right->local_before0 &&
        left->local_before1 == right->local_before1 &&
        left->local_after0 == right->local_after0 &&
        left->local_after1 == right->local_after1;
}

static void rome2_test_unexpected_emit(
    void *context,
    rome2_100e92c0_step step)
{
    uint32_t *count = (uint32_t *)context;

    (void)step;
    *count += UINT32_C(1);
}

static void rome2_test_emit(
    void *context,
    rome2_100e92c0_step step)
{
    rome2_test_trace *trace = (rome2_test_trace *)context;
    uint32_t index = trace->call_count;

    if (trace->return_al == NULL ||
        *trace->return_al != ROME2_TEST_SENTINEL) {
        trace->failure_count += UINT32_C(1);
    }
    if (index >= trace->expected_count || index >= ROME2_TEST_MAX_STEPS) {
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
        trace->effects.predicate_10fde370 = UINT32_C(0);
        trace->effects.predicate_10fde9d0 = UINT32_C(0);
        trace->effects.result_10fde270_low = UINT32_C(0x01020304);
        trace->effects.result_10fde990_low = UINT32_C(0x05060708);
        trace->effects.result_10fde990_high = UINT32_C(0x090a0b0c);
    }
}

static void rome2_test_zero_step(
    rome2_100e92c0_step *step,
    rome2_100e92c0_step_kind kind)
{
    (void)memset(step, 0, sizeof(*step));
    step->kind = kind;
}

static void rome2_test_set_final(
    rome2_100e92c0_step *step,
    uint32_t argument0,
    uint32_t argument1,
    uint32_t argument2,
    uint32_t argument3)
{
    rome2_test_zero_step(step, ROME2_100E92C0_STEP_CALL_100D5150);
    step->argument_count = UINT32_C(4);
    step->argument0 = argument0;
    step->argument1 = argument1;
    step->argument2 = argument2;
    step->argument3 = argument3;
}

static void rome2_test_trace_init(
    rome2_test_trace *trace,
    uint32_t predicate_first,
    uint32_t predicate_second,
    uint32_t first_low,
    uint32_t second_low,
    uint32_t second_high,
    uint8_t *return_al)
{
    uint32_t index = UINT32_C(0);

    (void)memset(trace, 0, sizeof(*trace));
    trace->effects.emit_step = rome2_test_emit;
    trace->effects.context = trace;
    trace->effects.predicate_10fde370 = predicate_first;
    trace->effects.predicate_10fde9d0 = predicate_second;
    trace->effects.result_10fde270_low = first_low;
    trace->effects.result_10fde990_low = second_low;
    trace->effects.result_10fde990_high = second_high;
    trace->return_al = return_al;

    rome2_test_zero_step(
        &trace->expected[index], ROME2_100E92C0_STEP_CALL_100D6970);
    index += UINT32_C(1);

    rome2_test_zero_step(
        &trace->expected[index], ROME2_100E92C0_STEP_CALL_10FDE370);
    trace->expected[index].result_count = UINT32_C(1);
    trace->expected[index].result0 = predicate_first;
    index += UINT32_C(1);

    if (predicate_first == UINT32_C(0)) {
        rome2_test_set_final(
            &trace->expected[index],
            UINT32_C(0), UINT32_C(0), UINT32_C(0), UINT32_C(0));
        trace->expected_count = index + UINT32_C(1);
        return;
    }

    rome2_test_zero_step(
        &trace->expected[index], ROME2_100E92C0_STEP_CALL_10FDE9D0);
    trace->expected[index].result_count = UINT32_C(1);
    trace->expected[index].result0 = predicate_second;
    index += UINT32_C(1);

    if (predicate_second == UINT32_C(0)) {
        rome2_test_set_final(
            &trace->expected[index],
            UINT32_C(0), UINT32_C(0), UINT32_C(0), UINT32_C(0));
        trace->expected_count = index + UINT32_C(1);
        return;
    }

    rome2_test_zero_step(
        &trace->expected[index], ROME2_100E92C0_STEP_CALL_10FDE270);
    trace->expected[index].result_count = UINT32_C(2);
    trace->expected[index].result0 = first_low;
    trace->expected[index].local_after0 = first_low;
    index += UINT32_C(1);

    rome2_test_zero_step(
        &trace->expected[index], ROME2_100E92C0_STEP_CALL_10FDE990);
    trace->expected[index].result_count = UINT32_C(2);
    trace->expected[index].result0 = second_low;
    trace->expected[index].result1 = second_high;
    trace->expected[index].local_before0 = first_low;
    trace->expected[index].local_after0 = second_low;
    trace->expected[index].local_after1 = second_high;
    index += UINT32_C(1);

    rome2_test_set_final(
        &trace->expected[index],
        first_low, UINT32_C(0), second_low, second_high);
    trace->expected_count = index + UINT32_C(1);
}

static int rome2_test_run_case(
    const char *label,
    uint32_t receiver,
    uint32_t argument,
    uint32_t predicate_first,
    uint32_t predicate_second,
    uint32_t first_low,
    uint32_t second_low,
    uint32_t second_high,
    int mutate_effects)
{
    rome2_test_trace trace;
    rome2_guest_status status;
    uint8_t return_al = ROME2_TEST_SENTINEL;

    rome2_test_trace_init(
        &trace, predicate_first, predicate_second,
        first_low, second_low, second_high, &return_al);
    trace.mutate_effects_after_first = mutate_effects;
    status = rome2_port_100e92c0_run_handler_transcript(
        (rome2_guest_addr32){receiver},
        (rome2_guest_addr32){argument},
        &trace.effects,
        &return_al);

    if (status != ROME2_GUEST_OK ||
        trace.call_count != trace.expected_count ||
        trace.failure_count != UINT32_C(0) ||
        trace.unexpected_call_count != UINT32_C(0) ||
        return_al != ROME2_PORT_100E92C0_AL) {
        (void)fprintf(
            stderr,
            "%s: status/calls/expected/failures/unexpected/AL "
            "= %d/%u/%u/%u/%u/%u\n",
            label,
            (int)status,
            (unsigned int)trace.call_count,
            (unsigned int)trace.expected_count,
            (unsigned int)trace.failure_count,
            (unsigned int)trace.unexpected_call_count,
            (unsigned int)return_al);
        return 1;
    }

    if (!mutate_effects &&
        (trace.effects.emit_step != rome2_test_emit ||
         trace.effects.context != &trace ||
         trace.effects.predicate_10fde370 != predicate_first ||
         trace.effects.predicate_10fde9d0 != predicate_second ||
         trace.effects.result_10fde270_low != first_low ||
         trace.effects.result_10fde990_low != second_low ||
         trace.effects.result_10fde990_high != second_high)) {
        (void)fprintf(stderr, "%s: adapter mutated the effects object\n", label);
        return 1;
    }
    if (mutate_effects &&
        (trace.effects.emit_step != rome2_test_unexpected_emit ||
         trace.effects.context != &trace.unexpected_call_count ||
         trace.effects.predicate_10fde370 != UINT32_C(0) ||
         trace.effects.predicate_10fde9d0 != UINT32_C(0) ||
         trace.effects.result_10fde270_low != UINT32_C(0x01020304) ||
         trace.effects.result_10fde990_low != UINT32_C(0x05060708) ||
         trace.effects.result_10fde990_high != UINT32_C(0x090a0b0c))) {
        (void)fprintf(stderr, "%s: callback mutation was not retained\n", label);
        return 1;
    }
    return 0;
}

static int rome2_test_exact_branch_routes(void)
{
    int failures = 0;

    failures += rome2_test_run_case(
        "first predicate false",
        UINT32_C(0x12345678), UINT32_C(0x87654321),
        UINT32_C(0), UINT32_C(1),
        UINT32_C(0x11111111), UINT32_C(0x22222222),
        UINT32_C(0x33333333), 0);
    failures += rome2_test_run_case(
        "second predicate false",
        UINT32_C(0xffffffff), UINT32_C(0),
        UINT32_C(1), UINT32_C(0),
        UINT32_C(0x44444444), UINT32_C(0x55555555),
        UINT32_C(0x66666666), 0);
    failures += rome2_test_run_case(
        "both predicates true",
        UINT32_C(0), UINT32_C(0xffffffff),
        UINT32_C(1), UINT32_C(1),
        UINT32_C(0x89abcdef), UINT32_C(0x01234567),
        UINT32_C(0xfedcba98), 0);
    return failures;
}

static int rome2_test_ignored_inputs_and_result_boundaries(void)
{
    int failures = 0;

    failures += rome2_test_run_case(
        "all zero bits",
        UINT32_C(0), UINT32_C(0), UINT32_C(1), UINT32_C(1),
        UINT32_C(0), UINT32_C(0), UINT32_C(0), 0);
    failures += rome2_test_run_case(
        "all one result bits",
        UINT32_C(0xffffffff), UINT32_C(0x80000000),
        UINT32_C(1), UINT32_C(1),
        UINT32_C(0xffffffff), UINT32_C(0xffffffff),
        UINT32_C(0xffffffff), 0);
    return failures;
}

static int rome2_test_effects_snapshot_is_complete(void)
{
    return rome2_test_run_case(
        "complete effects snapshot",
        UINT32_C(0xa1b2c3d4), UINT32_C(0x55667788),
        UINT32_C(1), UINT32_C(1),
        UINT32_C(0xdeadbeef), UINT32_C(0xcafebabe),
        UINT32_C(0x76543210), 1);
}

static int rome2_test_expect_precommit_failure(
    const char *label,
    rome2_guest_status expected_status,
    rome2_test_trace *trace,
    const rome2_100e92c0_transcript_effects *effects,
    uint8_t *return_al)
{
    rome2_guest_status status =
        rome2_port_100e92c0_run_handler_transcript(
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
    rome2_100e92c0_transcript_effects *misaligned;
    const rome2_100e92c0_transcript_effects *overflowing;
    uint8_t return_al;
    uint8_t *aliased_output;
    int failures = 0;

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(1), UINT32_C(1),
        UINT32_C(1), UINT32_C(2), UINT32_C(3), &return_al);
    failures += rome2_test_expect_precommit_failure(
        "null effects", ROME2_GUEST_BAD_ARGUMENT,
        &trace, NULL, &return_al);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(1), UINT32_C(1),
        UINT32_C(1), UINT32_C(2), UINT32_C(3), &return_al);
    failures += rome2_test_expect_precommit_failure(
        "null output", ROME2_GUEST_BAD_ARGUMENT,
        &trace, &trace.effects, NULL);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(1), UINT32_C(1),
        UINT32_C(1), UINT32_C(2), UINT32_C(3), &return_al);
    overflowing =
        (const rome2_100e92c0_transcript_effects *)(uintptr_t)(
            UINTPTR_MAX -
            (uintptr_t)sizeof(rome2_100e92c0_transcript_effects) +
            (uintptr_t)2U);
    failures += rome2_test_expect_precommit_failure(
        "overflowing effects", ROME2_GUEST_RANGE_OVERFLOW,
        &trace, overflowing, &return_al);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(1), UINT32_C(1),
        UINT32_C(1), UINT32_C(2), UINT32_C(3), &return_al);
    misaligned =
        (rome2_100e92c0_transcript_effects *)(void *)(storage.bytes + 1U);
    failures += rome2_test_expect_precommit_failure(
        "misaligned effects", ROME2_GUEST_BAD_ARGUMENT,
        &trace, misaligned, &return_al);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(1), UINT32_C(1),
        UINT32_C(1), UINT32_C(2), UINT32_C(3), &return_al);
    aliased_output =
        (uint8_t *)(void *)&trace.effects.result_10fde270_low;
    *aliased_output = ROME2_TEST_SENTINEL;
    failures += rome2_test_expect_precommit_failure(
        "effects output alias", ROME2_GUEST_BAD_ARGUMENT,
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
        &trace, UINT32_C(1), UINT32_C(1),
        UINT32_C(1), UINT32_C(2), UINT32_C(3), &return_al);
    trace.effects.emit_step = NULL;
    failures += rome2_test_expect_precommit_failure(
        "null callback", ROME2_GUEST_BAD_ARGUMENT,
        &trace, &trace.effects, &return_al);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(1), UINT32_C(1),
        UINT32_C(1), UINT32_C(2), UINT32_C(3), &return_al);
    trace.effects.context = NULL;
    failures += rome2_test_expect_precommit_failure(
        "null context", ROME2_GUEST_BAD_ARGUMENT,
        &trace, &trace.effects, &return_al);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(2), UINT32_C(1),
        UINT32_C(1), UINT32_C(2), UINT32_C(3), &return_al);
    failures += rome2_test_expect_precommit_failure(
        "wide first predicate", ROME2_GUEST_BAD_ARGUMENT,
        &trace, &trace.effects, &return_al);

    return_al = ROME2_TEST_SENTINEL;
    rome2_test_trace_init(
        &trace, UINT32_C(0), UINT32_C(2),
        UINT32_C(1), UINT32_C(2), UINT32_C(3), &return_al);
    failures += rome2_test_expect_precommit_failure(
        "wide inactive second predicate", ROME2_GUEST_BAD_ARGUMENT,
        &trace, &trace.effects, &return_al);

    return failures;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_exact_branch_routes();
    failures += rome2_test_ignored_inputs_and_result_boundaries();
    failures += rome2_test_effects_snapshot_is_complete();
    failures += rome2_test_invalid_borrowed_objects();
    failures += rome2_test_invalid_effect_values();

    if (failures != 0) {
        (void)fprintf(
            stderr,
            "100e92c0 handler transcript: %d failure(s)\n",
            failures);
        return 1;
    }
    (void)puts("100e92c0 handler transcript: ok");
    return 0;
}

#include "ported_100e8580_handler_transcript.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_SENTINEL UINT8_C(0xa6)
#define ROME2_TEST_FULL_COUNT UINT32_C(9)
#define ROME2_TEST_PREFIX_COUNT UINT32_C(7)

_Static_assert(ROME2_PORT_100E8580_AL == UINT8_C(1),
    "the public AL contract must remain one");
_Static_assert(ROME2_PORT_100E8580_STEP_COUNT == UINT32_C(9),
    "the public transcript must remain nine steps");
_Static_assert(ROME2_PORT_100E8580_RESULT_DISPLACEMENT == UINT32_C(0x68),
    "the dependent guest displacement must remain authenticated");
_Static_assert(
    ROME2_PORT_100E8580_FINISHED_RUN_VARS_IDENTITY == UINT32_C(0x1173fb54),
    "the Finished run_vars identity must remain authenticated");

struct rome2_test_trace;

typedef struct rome2_test_callback_context {
    struct rome2_test_trace *trace;
    int is_decoy;
} rome2_test_callback_context;

typedef struct rome2_test_trace {
    rome2_100e8580_transcript_effects effects;
    rome2_test_callback_context primary_context;
    rome2_test_callback_context decoy_context;
    rome2_100e8580_step observed[ROME2_TEST_FULL_COUNT];
    uint32_t observed_count;
    uint32_t trap_count;
    uint32_t callback_failures;
    uint32_t original_result;
    uint8_t *return_al;
} rome2_test_trace;

static rome2_guest_addr32 rome2_test_guest(uint32_t value)
{
    rome2_guest_addr32 result;

    result.value = value;
    return result;
}

static rome2_100e8580_step rome2_test_expected_step(
    uint32_t index,
    uint32_t result_100e8240)
{
    rome2_100e8580_step step;

    step.kind = ROME2_100E8580_STEP_CALL_100D6560;
    step.argument_count = UINT32_C(0);
    step.argument0 = UINT32_C(0);
    step.argument1 = UINT32_C(0);
    step.argument2 = UINT32_C(0);
    step.has_guest_result = UINT32_C(0);
    step.returned_guest_identity.value = UINT32_C(0);

    switch (index) {
    case 0:
        break;
    case 1:
        step.kind = ROME2_100E8580_STEP_CALL_112D0510;
        break;
    case 2:
        step.kind = ROME2_100E8580_STEP_CALL_112E0950_ONE;
        step.argument_count = UINT32_C(1);
        step.argument0 = UINT32_C(1);
        break;
    case 3:
        step.kind = ROME2_100E8580_STEP_CALL_100D9810;
        break;
    case 4:
        step.kind = ROME2_100E8580_STEP_CALL_100DDF50;
        break;
    case 5:
        step.kind = ROME2_100E8580_STEP_CALL_112E0950_ZERO;
        step.argument_count = UINT32_C(1);
        break;
    case 6:
        step.kind = ROME2_100E8580_STEP_CALL_100E8240;
        step.argument_count = UINT32_C(1);
        step.has_guest_result = UINT32_C(1);
        step.returned_guest_identity.value = result_100e8240;
        break;
    case 7:
        step.kind = ROME2_100E8580_STEP_CALL_112BFEE0;
        step.argument_count = UINT32_C(1);
        step.argument0 = result_100e8240 + UINT32_C(0x68);
        break;
    case 8:
        step.kind = ROME2_100E8580_STEP_CALL_112DCAF0;
        step.argument_count = UINT32_C(3);
        step.argument0 = UINT32_C(0x1173fb54);
        break;
    default:
        step.kind = (rome2_100e8580_step_kind)0;
        break;
    }

    return step;
}

static int rome2_test_step_equal(
    const rome2_100e8580_step *left,
    const rome2_100e8580_step *right)
{
    return left->kind == right->kind &&
        left->argument_count == right->argument_count &&
        left->argument0 == right->argument0 &&
        left->argument1 == right->argument1 &&
        left->argument2 == right->argument2 &&
        left->has_guest_result == right->has_guest_result &&
        left->returned_guest_identity.value ==
            right->returned_guest_identity.value;
}

static void rome2_test_trap_callback(
    void *context,
    rome2_100e8580_step step)
{
    rome2_test_callback_context *callback_context =
        (rome2_test_callback_context *)context;

    (void)step;
    if (callback_context != NULL && callback_context->trace != NULL) {
        callback_context->trace->trap_count += UINT32_C(1);
    }
}

static void rome2_test_record_callback(
    void *context,
    rome2_100e8580_step step)
{
    rome2_test_callback_context *callback_context =
        (rome2_test_callback_context *)context;
    rome2_test_trace *trace;
    rome2_100e8580_step expected;

    if (callback_context == NULL || callback_context->trace == NULL) {
        return;
    }
    trace = callback_context->trace;
    if (callback_context->is_decoy != 0) {
        trace->callback_failures += UINT32_C(1);
    }
    if (trace->return_al == NULL ||
        *trace->return_al != ROME2_TEST_SENTINEL) {
        trace->callback_failures += UINT32_C(1);
    }
    if (trace->observed_count >= ROME2_TEST_FULL_COUNT) {
        trace->callback_failures += UINT32_C(1);
        return;
    }

    expected = rome2_test_expected_step(
        trace->observed_count, trace->original_result);
    if (!rome2_test_step_equal(&step, &expected)) {
        trace->callback_failures += UINT32_C(1);
    }
    trace->observed[trace->observed_count] = step;
    trace->observed_count += UINT32_C(1);

    if (trace->observed_count == UINT32_C(1)) {
        /* Later calls and the dependency must use the complete snapshot. */
        trace->effects.emit_step = rome2_test_trap_callback;
        trace->effects.context = &trace->decoy_context;
        trace->effects.result_100e8240.value = UINT32_C(0);
    }
}

static void rome2_test_trace_init(
    rome2_test_trace *trace,
    uint32_t result_100e8240,
    uint8_t *return_al)
{
    (void)memset(trace, 0, sizeof(*trace));
    trace->primary_context.trace = trace;
    trace->primary_context.is_decoy = 0;
    trace->decoy_context.trace = trace;
    trace->decoy_context.is_decoy = 1;
    trace->effects.emit_step = rome2_test_record_callback;
    trace->effects.context = &trace->primary_context;
    trace->effects.result_100e8240.value = result_100e8240;
    trace->original_result = result_100e8240;
    trace->return_al = return_al;
}

static int rome2_test_expect_status(
    const char *label,
    rome2_guest_status actual,
    rome2_guest_status expected)
{
    if (actual != expected) {
        (void)fprintf(
            stderr,
            "%s: status %d, expected %d\n",
            label,
            (int)actual,
            (int)expected);
        return 1;
    }
    return 0;
}

static int rome2_test_success(
    const char *label,
    uint32_t result_100e8240,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 argument)
{
    rome2_test_trace trace;
    rome2_guest_status status;
    uint8_t return_al = ROME2_TEST_SENTINEL;
    int failures = 0;

    rome2_test_trace_init(&trace, result_100e8240, &return_al);
    status = rome2_port_100e8580_run_handler_transcript(
        receiver, argument, &trace.effects, &return_al);
    failures += rome2_test_expect_status(label, status, ROME2_GUEST_OK);
    if (trace.observed_count != ROME2_TEST_FULL_COUNT ||
        trace.callback_failures != UINT32_C(0) ||
        trace.trap_count != UINT32_C(0)) {
        (void)fprintf(
            stderr,
            "%s: transcript/snapshot mismatch (%u/%u/%u)\n",
            label,
            (unsigned int)trace.observed_count,
            (unsigned int)trace.callback_failures,
            (unsigned int)trace.trap_count);
        failures += 1;
    }
    if (return_al != UINT8_C(1)) {
        (void)fprintf(stderr, "%s: AL was not published after step nine\n", label);
        failures += 1;
    }
    return failures;
}

static int rome2_test_prefix_failure(
    const char *label,
    uint32_t result_100e8240,
    rome2_guest_status expected_status)
{
    rome2_test_trace trace;
    rome2_guest_status status;
    uint8_t return_al = ROME2_TEST_SENTINEL;
    int failures = 0;

    rome2_test_trace_init(&trace, result_100e8240, &return_al);
    status = rome2_port_100e8580_run_handler_transcript(
        rome2_test_guest(UINT32_C(0)),
        rome2_test_guest(UINT32_MAX),
        &trace.effects,
        &return_al);
    failures += rome2_test_expect_status(label, status, expected_status);
    if (trace.observed_count != ROME2_TEST_PREFIX_COUNT ||
        trace.callback_failures != UINT32_C(0) ||
        trace.trap_count != UINT32_C(0)) {
        (void)fprintf(
            stderr,
            "%s: prefix was not exactly seven committed steps (%u/%u/%u)\n",
            label,
            (unsigned int)trace.observed_count,
            (unsigned int)trace.callback_failures,
            (unsigned int)trace.trap_count);
        failures += 1;
    }
    if (return_al != ROME2_TEST_SENTINEL) {
        (void)fprintf(stderr, "%s: failure published AL\n", label);
        failures += 1;
    }
    return failures;
}

static int rome2_test_validation(void)
{
    rome2_test_trace trace;
    rome2_100e8580_transcript_effects effects_copy;
    rome2_guest_status status;
    uint8_t saved_effects[sizeof(rome2_100e8580_transcript_effects)];
    uint8_t return_al = ROME2_TEST_SENTINEL;
    int failures = 0;

    rome2_test_trace_init(&trace, UINT32_C(0x1000), &return_al);
    status = rome2_port_100e8580_run_handler_transcript(
        rome2_test_guest(UINT32_C(1)),
        rome2_test_guest(UINT32_C(2)),
        NULL,
        &return_al);
    failures += rome2_test_expect_status(
        "null effects", status, ROME2_GUEST_BAD_ARGUMENT);
    if (return_al != ROME2_TEST_SENTINEL ||
        trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "null effects changed observable state\n");
        failures += 1;
    }

    rome2_test_trace_init(&trace, UINT32_C(0x1000), &return_al);
    trace.effects.emit_step = NULL;
    status = rome2_port_100e8580_run_handler_transcript(
        rome2_test_guest(UINT32_C(0)),
        rome2_test_guest(UINT32_MAX),
        &trace.effects,
        &return_al);
    failures += rome2_test_expect_status(
        "null callback", status, ROME2_GUEST_BAD_ARGUMENT);

    rome2_test_trace_init(&trace, UINT32_C(0x1000), &return_al);
    trace.effects.context = NULL;
    status = rome2_port_100e8580_run_handler_transcript(
        rome2_test_guest(UINT32_MAX),
        rome2_test_guest(UINT32_C(0)),
        &trace.effects,
        &return_al);
    failures += rome2_test_expect_status(
        "null callback context", status, ROME2_GUEST_BAD_ARGUMENT);

    rome2_test_trace_init(&trace, UINT32_C(0x1000), &return_al);
    status = rome2_port_100e8580_run_handler_transcript(
        rome2_test_guest(UINT32_C(3)),
        rome2_test_guest(UINT32_C(4)),
        &trace.effects,
        NULL);
    failures += rome2_test_expect_status(
        "null AL output", status, ROME2_GUEST_BAD_ARGUMENT);
    if (trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "null AL output emitted a step\n");
        failures += 1;
    }

    rome2_test_trace_init(&trace, UINT32_C(0x1000), &return_al);
    (void)memcpy(saved_effects, &trace.effects, sizeof(saved_effects));
    status = rome2_port_100e8580_run_handler_transcript(
        rome2_test_guest(UINT32_C(5)),
        rome2_test_guest(UINT32_C(6)),
        &trace.effects,
        (uint8_t *)(void *)&trace.effects);
    failures += rome2_test_expect_status(
        "effects/output alias", status, ROME2_GUEST_BAD_ARGUMENT);
    if (memcmp(saved_effects, &trace.effects, sizeof(saved_effects)) != 0 ||
        trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "effects/output alias changed effects\n");
        failures += 1;
    }

    rome2_test_trace_init(&trace, UINT32_C(0x1000), &return_al);
    status = rome2_port_100e8580_run_handler_transcript(
        rome2_test_guest(UINT32_C(7)),
        rome2_test_guest(UINT32_C(8)),
        (const rome2_100e8580_transcript_effects *)(uintptr_t)(
            UINTPTR_MAX -
            (uintptr_t)sizeof(rome2_100e8580_transcript_effects) +
            (uintptr_t)2),
        &return_al);
    failures += rome2_test_expect_status(
        "effects numeric range overflow",
        status,
        ROME2_GUEST_RANGE_OVERFLOW);
    if (return_al != ROME2_TEST_SENTINEL ||
        trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "effects overflow changed observable state\n");
        failures += 1;
    }

    rome2_test_trace_init(&trace, UINT32_C(0x1000), &return_al);
    effects_copy = trace.effects;
    status = rome2_port_100e8580_run_handler_transcript(
        rome2_test_guest(UINT32_C(9)),
        rome2_test_guest(UINT32_C(10)),
        &effects_copy,
        (uint8_t *)(uintptr_t)UINTPTR_MAX);
    failures += rome2_test_expect_status(
        "AL output numeric range overflow",
        status,
        ROME2_GUEST_RANGE_OVERFLOW);
    if (trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "AL output overflow emitted a step\n");
        failures += 1;
    }

    return failures;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_success(
        "ordinary dependent identity",
        UINT32_C(0x01020304),
        rome2_test_guest(UINT32_C(0)),
        rome2_test_guest(UINT32_MAX));
    failures += rome2_test_success(
        "largest admissible dependent identity",
        UINT32_C(0xffffff97),
        rome2_test_guest(UINT32_C(0x12345678)),
        rome2_test_guest(UINT32_C(0x87654321)));
    failures += rome2_test_prefix_failure(
        "null dependent identity",
        UINT32_C(0),
        ROME2_GUEST_NULL_ADDRESS);
    failures += rome2_test_prefix_failure(
        "overflowing dependent identity",
        UINT32_C(0xffffff98),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += rome2_test_validation();

    if (failures != 0) {
        (void)fprintf(
            stderr,
            "100e8580 handler transcript: %d failure(s)\n",
            failures);
        return 1;
    }

    (void)puts("100e8580 handler transcript: ok");
    return 0;
}

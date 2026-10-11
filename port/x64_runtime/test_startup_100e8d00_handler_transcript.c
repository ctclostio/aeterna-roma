#include "ported_100e8d00_handler_transcript.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_SENTINEL UINT8_C(0xa5)
#define ROME2_TEST_EXPECTED_STEP_COUNT UINT32_C(6)

_Static_assert(ROME2_PORT_100E8D00_AL == UINT8_C(1),
    "the public AL contract must remain one");
_Static_assert(ROME2_PORT_100E8D00_STEP_COUNT == UINT32_C(6),
    "the public transcript contract must remain six steps");
_Static_assert(
    ROME2_PORT_100E8D00_PRE_DB_APP_INIT_IDENTITY == UINT32_C(0x1173fb44),
    "the public PRE_DB_APP_INIT identity must remain authenticated");
_Static_assert(ROME2_100E8D00_STEP_CALL_10CB6160 == 1,
    "the first typed step value must remain stable");
_Static_assert(ROME2_100E8D00_STEP_CALL_10115D40 == 2,
    "the second typed step value must remain stable");
_Static_assert(ROME2_100E8D00_STEP_CALL_112DC9F0 == 3,
    "the third typed step value must remain stable");
_Static_assert(ROME2_100E8D00_STEP_CALL_101150A0 == 4,
    "the fourth typed step value must remain stable");
_Static_assert(ROME2_100E8D00_STEP_CALL_101151D0 == 5,
    "the fifth typed step value must remain stable");
_Static_assert(ROME2_100E8D00_STEP_CALL_112E2CB0 == 6,
    "the sixth typed step value must remain stable");

struct rome2_test_trace;

typedef struct rome2_test_callback_context {
    struct rome2_test_trace *trace;
    int is_decoy;
} rome2_test_callback_context;

typedef struct rome2_test_trace {
    rome2_100e8d00_transcript_effects effects;
    rome2_test_callback_context primary_context;
    rome2_test_callback_context decoy_context;
    rome2_100e8d00_step observed[ROME2_TEST_EXPECTED_STEP_COUNT];
    uint32_t observed_count;
    uint32_t trap_count;
    uint32_t callback_failures;
    uint8_t *return_al;
} rome2_test_trace;

static const rome2_100e8d00_step ROME2_EXPECTED_STEPS[
    ROME2_TEST_EXPECTED_STEP_COUNT] = {
    {
        ROME2_100E8D00_STEP_CALL_10CB6160,
        UINT32_C(2),
        UINT32_C(0),
        UINT32_C(1)
    },
    {
        ROME2_100E8D00_STEP_CALL_10115D40,
        UINT32_C(1),
        UINT32_C(0),
        UINT32_C(0)
    },
    {
        ROME2_100E8D00_STEP_CALL_112DC9F0,
        UINT32_C(2),
        UINT32_C(0x1173fb44),
        UINT32_C(0)
    },
    {
        ROME2_100E8D00_STEP_CALL_101150A0,
        UINT32_C(1),
        UINT32_C(1),
        UINT32_C(0)
    },
    {
        ROME2_100E8D00_STEP_CALL_101151D0,
        UINT32_C(1),
        UINT32_C(0),
        UINT32_C(0)
    },
    {
        ROME2_100E8D00_STEP_CALL_112E2CB0,
        UINT32_C(0),
        UINT32_C(0),
        UINT32_C(0)
    }
};

static rome2_guest_addr32 rome2_test_guest(uint32_t value)
{
    rome2_guest_addr32 result;

    result.value = value;
    return result;
}

static int rome2_test_step_equal(
    const rome2_100e8d00_step *left,
    const rome2_100e8d00_step *right)
{
    return left->kind == right->kind &&
        left->argument_count == right->argument_count &&
        left->argument0 == right->argument0 &&
        left->argument1 == right->argument1;
}

static void rome2_test_trap_callback(
    void *context,
    rome2_100e8d00_step step)
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
    rome2_100e8d00_step step)
{
    rome2_test_callback_context *callback_context =
        (rome2_test_callback_context *)context;
    rome2_test_trace *trace;

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
    if (trace->observed_count >= ROME2_TEST_EXPECTED_STEP_COUNT) {
        trace->callback_failures += UINT32_C(1);
        return;
    }

    trace->observed[trace->observed_count] = step;
    trace->observed_count += UINT32_C(1);

    if (trace->observed_count == UINT32_C(1)) {
        /* Prove the source uses its pre-effect callback/context snapshot. */
        trace->effects.emit_step = rome2_test_trap_callback;
        trace->effects.context = &trace->decoy_context;
    }
}

static void rome2_test_trace_init(
    rome2_test_trace *trace,
    uint8_t *return_al)
{
    (void)memset(trace, 0, sizeof(*trace));
    trace->primary_context.trace = trace;
    trace->primary_context.is_decoy = 0;
    trace->decoy_context.trace = trace;
    trace->decoy_context.is_decoy = 1;
    trace->effects.emit_step = rome2_test_record_callback;
    trace->effects.context = &trace->primary_context;
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

static int rome2_test_success_case(
    const char *label,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 argument)
{
    rome2_test_trace trace;
    rome2_guest_status status;
    uint8_t return_al = ROME2_TEST_SENTINEL;
    uint32_t index;
    int failures = 0;

    rome2_test_trace_init(&trace, &return_al);
    status = rome2_port_100e8d00_run_handler_transcript(
        receiver, argument, &trace.effects, &return_al);
    failures += rome2_test_expect_status(label, status, ROME2_GUEST_OK);

    if (return_al != UINT8_C(1)) {
        (void)fprintf(stderr, "%s: AL was not published as one\n", label);
        failures += 1;
    }
    if (trace.observed_count != ROME2_TEST_EXPECTED_STEP_COUNT) {
        (void)fprintf(
            stderr,
            "%s: observed %u steps, expected %u\n",
            label,
            (unsigned int)trace.observed_count,
            (unsigned int)ROME2_TEST_EXPECTED_STEP_COUNT);
        failures += 1;
    }
    if (trace.callback_failures != UINT32_C(0) ||
        trace.trap_count != UINT32_C(0)) {
        (void)fprintf(
            stderr,
            "%s: callback publication/snapshot failure (%u/%u)\n",
            label,
            (unsigned int)trace.callback_failures,
            (unsigned int)trace.trap_count);
        failures += 1;
    }

    for (index = UINT32_C(0);
         index < trace.observed_count &&
             index < ROME2_TEST_EXPECTED_STEP_COUNT;
         index += UINT32_C(1)) {
        if (!rome2_test_step_equal(
                &trace.observed[index], &ROME2_EXPECTED_STEPS[index])) {
            (void)fprintf(
                stderr,
                "%s: step %u did not match the independent oracle\n",
                label,
                (unsigned int)index);
            failures += 1;
        }
    }

    return failures;
}

static int rome2_test_validation_failures(void)
{
    rome2_test_trace trace;
    rome2_100e8d00_transcript_effects effects_copy;
    rome2_guest_status status;
    uint8_t effects_bytes[sizeof(rome2_100e8d00_transcript_effects)];
    uint8_t return_al = ROME2_TEST_SENTINEL;
    int failures = 0;

    rome2_test_trace_init(&trace, &return_al);
    status = rome2_port_100e8d00_run_handler_transcript(
        rome2_test_guest(UINT32_C(1)),
        rome2_test_guest(UINT32_C(2)),
        NULL,
        &return_al);
    failures += rome2_test_expect_status(
        "null effects", status, ROME2_GUEST_BAD_ARGUMENT);
    if (return_al != ROME2_TEST_SENTINEL ||
        trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "null effects: observable state changed\n");
        failures += 1;
    }

    rome2_test_trace_init(&trace, &return_al);
    trace.effects.emit_step = NULL;
    status = rome2_port_100e8d00_run_handler_transcript(
        rome2_test_guest(UINT32_C(0)),
        rome2_test_guest(UINT32_MAX),
        &trace.effects,
        &return_al);
    failures += rome2_test_expect_status(
        "null callback", status, ROME2_GUEST_BAD_ARGUMENT);
    if (return_al != ROME2_TEST_SENTINEL ||
        trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "null callback: observable state changed\n");
        failures += 1;
    }

    rome2_test_trace_init(&trace, &return_al);
    trace.effects.context = NULL;
    status = rome2_port_100e8d00_run_handler_transcript(
        rome2_test_guest(UINT32_MAX),
        rome2_test_guest(UINT32_C(0)),
        &trace.effects,
        &return_al);
    failures += rome2_test_expect_status(
        "null callback context", status, ROME2_GUEST_BAD_ARGUMENT);
    if (return_al != ROME2_TEST_SENTINEL ||
        trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "null callback context: state changed\n");
        failures += 1;
    }

    rome2_test_trace_init(&trace, &return_al);
    status = rome2_port_100e8d00_run_handler_transcript(
        rome2_test_guest(UINT32_C(0xdeadbeef)),
        rome2_test_guest(UINT32_C(0xcafebabe)),
        &trace.effects,
        NULL);
    failures += rome2_test_expect_status(
        "null AL output", status, ROME2_GUEST_BAD_ARGUMENT);
    if (trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "null AL output: callback ran\n");
        failures += 1;
    }

    rome2_test_trace_init(&trace, &return_al);
    (void)memcpy(effects_bytes, &trace.effects, sizeof(effects_bytes));
    status = rome2_port_100e8d00_run_handler_transcript(
        rome2_test_guest(UINT32_C(3)),
        rome2_test_guest(UINT32_C(4)),
        &trace.effects,
        (uint8_t *)(void *)&trace.effects);
    failures += rome2_test_expect_status(
        "effects/output alias", status, ROME2_GUEST_BAD_ARGUMENT);
    if (memcmp(effects_bytes, &trace.effects, sizeof(effects_bytes)) != 0 ||
        trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "effects/output alias: effects changed\n");
        failures += 1;
    }

    rome2_test_trace_init(&trace, &return_al);
    status = rome2_port_100e8d00_run_handler_transcript(
        rome2_test_guest(UINT32_C(5)),
        rome2_test_guest(UINT32_C(6)),
        (const rome2_100e8d00_transcript_effects *)(uintptr_t)(
            UINTPTR_MAX -
            (uintptr_t)sizeof(rome2_100e8d00_transcript_effects) +
            (uintptr_t)2),
        &return_al);
    failures += rome2_test_expect_status(
        "effects numeric range overflow",
        status,
        ROME2_GUEST_RANGE_OVERFLOW);
    if (return_al != ROME2_TEST_SENTINEL ||
        trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "effects overflow: observable state changed\n");
        failures += 1;
    }

    rome2_test_trace_init(&trace, &return_al);
    effects_copy = trace.effects;
    status = rome2_port_100e8d00_run_handler_transcript(
        rome2_test_guest(UINT32_C(7)),
        rome2_test_guest(UINT32_C(8)),
        &effects_copy,
        (uint8_t *)(uintptr_t)UINTPTR_MAX);
    failures += rome2_test_expect_status(
        "AL output numeric range overflow",
        status,
        ROME2_GUEST_RANGE_OVERFLOW);
    if (trace.observed_count != UINT32_C(0)) {
        (void)fprintf(stderr, "AL output overflow: callback ran\n");
        failures += 1;
    }

    return failures;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_success_case(
        "zero/max opaque identities",
        rome2_test_guest(UINT32_C(0)),
        rome2_test_guest(UINT32_MAX));
    failures += rome2_test_success_case(
        "distinct opaque identities",
        rome2_test_guest(UINT32_C(0x12345678)),
        rome2_test_guest(UINT32_C(0x87654321)));
    failures += rome2_test_validation_failures();

    if (failures != 0) {
        (void)fprintf(
            stderr,
            "100e8d00 handler transcript: %d failure(s)\n",
            failures);
        return 1;
    }

    (void)puts("100e8d00 handler transcript: ok");
    return 0;
}

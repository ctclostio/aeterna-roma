#include "ported_100edd70_unified_entry.h"

#define main rome2_caller_closure_regression_main
#include "test_startup_100edd70_caller_closure.c"
#undef main

#define TEST_EVENT_REGISTRATION_BASE UINT32_C(0x700)
#define TEST_EVENT_TERMINAL_BASE UINT32_C(0x800)

static rome2_100edd70_unified_entry_result unified_result;
static rome2_100edd70_unified_entry_result unified_initial_result;
static rome2_100edd70_registration_effects unified_registration_effects;
static rome2_100edd70_terminal_effects unified_terminal_effects;
static uint32_t unified_registration_count;
static uint32_t unified_terminal_count;

static const uint16_t unified_exact_literal[22] = {
    UINT16_C(0x002d), UINT16_C(0x006e), UINT16_C(0x006f),
    UINT16_C(0x005f), UINT16_C(0x0065), UINT16_C(0x0078),
    UINT16_C(0x0063), UINT16_C(0x0065), UINT16_C(0x0070),
    UINT16_C(0x0074), UINT16_C(0x0069), UINT16_C(0x006f),
    UINT16_C(0x006e), UINT16_C(0x005f), UINT16_C(0x0068),
    UINT16_C(0x0061), UINT16_C(0x006e), UINT16_C(0x0064),
    UINT16_C(0x006c), UINT16_C(0x0065), UINT16_C(0x0072),
    UINT16_C(0x0000)
};

static void unified_registration_emit(
    void *context,
    rome2_100edd70_registration_step step)
{
    test_trace *trace = (test_trace *)context;
    ++unified_registration_count;
    test_append_event(
        trace,
        TEST_EVENT_REGISTRATION_BASE + (uint32_t)step.kind);
}

static void unified_terminal_emit(
    void *context,
    rome2_100edd70_terminal_step step)
{
    test_trace *trace = (test_trace *)context;
    ++unified_terminal_count;
    test_append_event(
        trace,
        TEST_EVENT_TERMINAL_BASE + (uint32_t)step.kind);
}

static void unified_set_result_sentinel(void)
{
    memset(&unified_result, TEST_RESULT_BYTE, sizeof(unified_result));
    unified_initial_result = unified_result;
}

static int unified_result_is_sentinel(void)
{
    return memcmp(
        &unified_result,
        &unified_initial_result,
        sizeof(unified_result)) == 0;
}

static void unified_write_exact_literal(test_fixture *fixture)
{
    uint32_t index;

    for (index = UINT32_C(0); index < UINT32_C(22); ++index) {
        test_write_u16_le(
            fixture->text.bytes + TEST_TEXT_OFFSET + index * UINT32_C(2),
            unified_exact_literal[index]);
    }
}

static void unified_write_mismatch_literal(test_fixture *fixture)
{
    test_write_u16_le(
        fixture->text.bytes + TEST_TEXT_OFFSET,
        UINT16_C(0x0061));
    test_write_u16_le(
        fixture->text.bytes + TEST_TEXT_OFFSET + UINT32_C(2),
        UINT16_C(0x0000));
}

static int unified_run_route(
    const char *case_name,
    rome2_invalid_parameter_policy policy,
    uint32_t poll_count)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    uint32_t length =
        policy == ROME2_INVALID_PARAMETER_SKIP_HANDLER ?
            UINT32_C(21) : UINT32_C(3);
    uint32_t expected_registration =
        policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER ? UINT32_C(4) : UINT32_C(0);
    uint32_t expected_tail =
        policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER ? UINT32_C(2) : UINT32_C(0);
    uint32_t expected_epilogue = UINT32_C(10);
    uint32_t expected_total_events =
        expected_registration + (UINT32_C(45) + poll_count) + expected_tail + expected_epilogue;
    int failed = 0;

    test_init_fixture(fixture, length, poll_count, UINT32_C(0), UINT32_C(1), 0, 0);
    if (policy == ROME2_INVALID_PARAMETER_SKIP_HANDLER) {
        unified_write_exact_literal(fixture);
    } else {
        unified_write_mismatch_literal(fixture);
    }

    unified_registration_effects.emit_step = unified_registration_emit;
    unified_registration_effects.context = &fixture->trace;
    unified_registration_effects.context_byte_count = sizeof(fixture->trace);
    unified_registration_count = UINT32_C(0);

    unified_terminal_effects.emit_step = unified_terminal_emit;
    unified_terminal_effects.context = &fixture->trace;
    unified_terminal_effects.context_byte_count = sizeof(fixture->trace);
    unified_terminal_count = UINT32_C(0);
    unified_set_result_sentinel();

    status = rome2_port_100edd70_run_unified_entry_sequence(
        TEST_ARGUMENT1,
        fixture->caller_position2,
        fixture->text_identity,
        fixture->caller_position4,
        &fixture->frame_view,
        (rome2_guest_addr32){fixture->frame_view.guest_base},
        &fixture->text_view,
        fixture->length_units + UINT32_C(1),
        &fixture->selector_view,
        &fixture->temporary_heap_view,
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->dispatch_view,
        fixture->dispatch_receiver,
        fixture->max_poll_calls,
        &fixture->effects,
        &fixture->continuation_effects,
        &unified_registration_effects,
        &unified_terminal_effects,
        &fixture->temporary_owner,
        &fixture->persistent_owner,
        &fixture->lifecycle,
        &unified_result);

    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK,
        case_name, "unified entry sequence failed");
    failed |= test_expect(
        fixture->trace.event_count == expected_total_events,
        case_name, "total event count formula differs");
    failed |= test_expect(
        unified_result.policy == policy,
        case_name, "policy differs");
    failed |= test_expect(
        unified_result.registration_record_count == expected_registration,
        case_name, "registration record count differs");
    failed |= test_expect(
        unified_registration_count == expected_registration,
        case_name, "emitted registration count differs");
    failed |= test_expect(
        unified_terminal_count == (expected_tail + expected_epilogue),
        case_name, "emitted terminal count differs");
    failed |= test_expect(
        unified_result.terminal.policy == (uint32_t)policy &&
        unified_result.terminal.tail_record_count == expected_tail &&
        unified_result.terminal.epilogue_record_count == expected_epilogue &&
        unified_result.terminal.return_source_identity == UINT32_C(0x119f3144) &&
        unified_result.terminal.return_original_pc == UINT32_C(0x100edfaf),
        case_name, "terminal transcript result differs");
    return failed;
}

int main(void)
{
    int failed;

    failed = rome2_caller_closure_regression_main();

    /* Unified entry sequence route tests:
     * Formula:
     *   skip:    45 + P child + 10 epilogue = 55 + P
     *   install: 4 reg + 45 + P child + 2 tail + 10 epilogue = 61 + P
     */
    failed |= unified_run_route("unified skip P1",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, UINT32_C(1));
    failed |= unified_run_route("unified skip P3",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, UINT32_C(3));
    failed |= unified_run_route("unified skip P64",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, UINT32_C(64));

    failed |= unified_run_route("unified install P1",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(1));
    failed |= unified_run_route("unified install P3",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(3));
    failed |= unified_run_route("unified install P64",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(64));

    /* Null result rejection check */
    {
        test_fixture *fixture = &test_fixture_storage;
        rome2_100f1bb0_owned_status status;

        test_init_fixture(fixture, UINT32_C(21), UINT32_C(1), UINT32_C(0), UINT32_C(1), 0, 0);
        unified_write_exact_literal(fixture);
        status = rome2_port_100edd70_run_unified_entry_sequence(
            TEST_ARGUMENT1,
            fixture->caller_position2,
            fixture->text_identity,
            fixture->caller_position4,
            &fixture->frame_view,
            (rome2_guest_addr32){fixture->frame_view.guest_base},
            &fixture->text_view,
            fixture->length_units + UINT32_C(1),
            &fixture->selector_view,
            &fixture->temporary_heap_view,
            &fixture->persistent_descriptor_view,
            &fixture->persistent_heap_view,
            &fixture->dispatch_view,
            fixture->dispatch_receiver,
            fixture->max_poll_calls,
            &fixture->effects,
            &fixture->continuation_effects,
            &unified_registration_effects,
            &unified_terminal_effects,
            &fixture->temporary_owner,
            &fixture->persistent_owner,
            &fixture->lifecycle,
            NULL);
        failed |= test_expect(
            status == ROME2_100F1BB0_OWNED_BAD_ARGUMENT,
            "null result rejection",
            "null result was not rejected");
    }

    if (failed != 0) {
        (void)fprintf(stderr,
            "100edd70 unified entry sequence: FAIL\n");
        return 1;
    }
    (void)printf(
        "100edd70 unified entry sequence: PASS (44 regression + 7 unified cases)\n");
    return 0;
}

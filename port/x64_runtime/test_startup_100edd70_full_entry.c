#include "ported_100edd70_full_entry.h"

#define main rome2_unified_entry_regression_main
#include "test_startup_100edd70_unified_entry.c"
#undef main

#define TEST_EVENT_PREFIX_BASE UINT32_C(0x600)

static rome2_100edd70_full_entry_result full_entry_result;
static rome2_100edd70_full_entry_result full_entry_initial_result;
static rome2_100edd70_prefix_effects full_entry_prefix_effects;
static uint32_t full_entry_prefix_count;

static void full_entry_prefix_emit(
    void *context,
    rome2_100edd70_prefix_step step)
{
    test_trace *trace = (test_trace *)context;
    ++full_entry_prefix_count;
    test_append_event(
        trace,
        TEST_EVENT_PREFIX_BASE + (uint32_t)step.kind);
}

static void full_entry_set_result_sentinel(void)
{
    memset(&full_entry_result, TEST_RESULT_BYTE, sizeof(full_entry_result));
    full_entry_initial_result = full_entry_result;
}

static int full_run_route(
    const char *case_name,
    rome2_invalid_parameter_policy policy,
    uint32_t poll_count,
    rome2_100edd70_game_explorer_route ge_route,
    int prior_alloc)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    uint32_t length =
        policy == ROME2_INVALID_PARAMETER_SKIP_HANDLER ?
            UINT32_C(21) : UINT32_C(3);
    uint32_t expected_prefix;
    uint32_t expected_registration =
        policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER ? UINT32_C(4) : UINT32_C(0);
    uint32_t expected_tail =
        policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER ? UINT32_C(2) : UINT32_C(0);
    uint32_t expected_epilogue = UINT32_C(10);
    uint32_t expected_total_events;
    int failed = 0;

    if (ge_route == ROME2_100EDD70_GAME_EXPLORER_DENIED_ACCESS) {
        expected_prefix = (prior_alloc ? 14U : 13U);
        expected_total_events = expected_prefix;
    } else if (ge_route == ROME2_100EDD70_GAME_EXPLORER_VERIFIED_ACCESS) {
        expected_prefix = (prior_alloc ? 13U : 12U);
        expected_total_events = expected_prefix +
            expected_registration + (UINT32_C(45) + poll_count) + expected_tail + expected_epilogue;
    } else {
        /* BYPASS_CLASSNOTREG */
        expected_prefix = (prior_alloc ? 11U : 10U);
        expected_total_events = expected_prefix +
            expected_registration + (UINT32_C(45) + poll_count) + expected_tail + expected_epilogue;
    }

    test_init_fixture(fixture, length, poll_count, UINT32_C(0), UINT32_C(1), 0, 0);
    if (policy == ROME2_INVALID_PARAMETER_SKIP_HANDLER) {
        unified_write_exact_literal(fixture);
    } else {
        unified_write_mismatch_literal(fixture);
    }

    full_entry_prefix_effects.emit_step = full_entry_prefix_emit;
    full_entry_prefix_effects.context = &fixture->trace;
    full_entry_prefix_effects.context_byte_count = sizeof(fixture->trace);
    full_entry_prefix_count = UINT32_C(0);

    unified_registration_effects.emit_step = unified_registration_emit;
    unified_registration_effects.context = &fixture->trace;
    unified_registration_effects.context_byte_count = sizeof(fixture->trace);
    unified_registration_count = UINT32_C(0);

    unified_terminal_effects.emit_step = unified_terminal_emit;
    unified_terminal_effects.context = &fixture->trace;
    unified_terminal_effects.context_byte_count = sizeof(fixture->trace);
    unified_terminal_count = UINT32_C(0);
    full_entry_set_result_sentinel();

    status = rome2_port_100edd70_run_full_entry_sequence(
        (void *)(uintptr_t)TEST_ARGUMENT1,
        fixture->caller_position2,
        fixture->text_identity,
        1, /* nCmdShow */
        0x12345678, /* param_5 */
        0x23456789, /* param_6 */
        0x3456789a, /* param_7 */
        fixture->caller_position4,
        prior_alloc,
        ge_route,
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
        &full_entry_prefix_effects,
        &fixture->effects,
        &fixture->continuation_effects,
        &unified_registration_effects,
        &unified_terminal_effects,
        &fixture->temporary_owner,
        &fixture->persistent_owner,
        &fixture->lifecycle,
        &full_entry_result);

    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK,
        case_name, "full entry sequence returned non-OK status");
    failed |= test_expect(
        fixture->trace.event_count == expected_total_events,
        case_name, "total event count formula differs");
    failed |= test_expect(
        full_entry_prefix_count == expected_prefix,
        case_name, "emitted prefix count differs");
    failed |= test_expect(
        full_entry_result.prefix_record_count == expected_prefix,
        case_name, "prefix record count in result differs");

    if (ge_route == ROME2_100EDD70_GAME_EXPLORER_DENIED_ACCESS) {
        failed |= test_expect(
            full_entry_result.early_exit_taken == 1U,
            case_name, "early exit flag not set");
        failed |= test_expect(
            full_entry_result.exit_code == 0U,
            case_name, "early exit code is non-zero");
        failed |= test_expect(
            unified_registration_count == 0U,
            case_name, "registration emitted on early exit");
        failed |= test_expect(
            unified_terminal_count == 0U,
            case_name, "terminal emitted on early exit");
    } else {
        failed |= test_expect(
            full_entry_result.early_exit_taken == 0U,
            case_name, "early exit flag unexpectedly set");
        failed |= test_expect(
            full_entry_result.exit_code == 0x44U,
            case_name, "normal exit code differs from DAT_119f3144 byte");
        failed |= test_expect(
            full_entry_result.unified_result.policy == policy,
            case_name, "policy differs");
    }

    return failed;
}

int main(void)
{
    int failed = 0;

    /* First run full unified entry and caller closure regressions (51 cases) */
    failed |= rome2_unified_entry_regression_main();

    /* Route A: Modern OS Bypass Route (REGDB_E_CLASSNOTREG) without prior alloc */
    failed |= full_run_route("full bypass skip P1 no-prior",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, UINT32_C(1),
        ROME2_100EDD70_GAME_EXPLORER_BYPASS_CLASSNOTREG, 0);
    failed |= full_run_route("full bypass skip P3 no-prior",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, UINT32_C(3),
        ROME2_100EDD70_GAME_EXPLORER_BYPASS_CLASSNOTREG, 0);
    failed |= full_run_route("full bypass skip P64 no-prior",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, UINT32_C(64),
        ROME2_100EDD70_GAME_EXPLORER_BYPASS_CLASSNOTREG, 0);

    failed |= full_run_route("full bypass install P1 no-prior",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(1),
        ROME2_100EDD70_GAME_EXPLORER_BYPASS_CLASSNOTREG, 0);
    failed |= full_run_route("full bypass install P3 no-prior",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(3),
        ROME2_100EDD70_GAME_EXPLORER_BYPASS_CLASSNOTREG, 0);
    failed |= full_run_route("full bypass install P64 no-prior",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(64),
        ROME2_100EDD70_GAME_EXPLORER_BYPASS_CLASSNOTREG, 0);

    /* Route B: Modern OS Bypass Route WITH prior allocation cleanup */
    failed |= full_run_route("full bypass skip P1 with-prior",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, UINT32_C(1),
        ROME2_100EDD70_GAME_EXPLORER_BYPASS_CLASSNOTREG, 1);
    failed |= full_run_route("full bypass install P1 with-prior",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(1),
        ROME2_100EDD70_GAME_EXPLORER_BYPASS_CLASSNOTREG, 1);

    /* Route C: Verified Access Route (GameExplorer returns 1) */
    failed |= full_run_route("full verified skip P1 no-prior",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, UINT32_C(1),
        ROME2_100EDD70_GAME_EXPLORER_VERIFIED_ACCESS, 0);
    failed |= full_run_route("full verified install P1 no-prior",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(1),
        ROME2_100EDD70_GAME_EXPLORER_VERIFIED_ACCESS, 0);
    failed |= full_run_route("full verified install P3 with-prior",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(3),
        ROME2_100EDD70_GAME_EXPLORER_VERIFIED_ACCESS, 1);

    /* Route D: Denied Access Route (GameExplorer returns 0 -> early exit with code 0) */
    failed |= full_run_route("full denied early exit no-prior",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, UINT32_C(1),
        ROME2_100EDD70_GAME_EXPLORER_DENIED_ACCESS, 0);
    failed |= full_run_route("full denied early exit with-prior",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, UINT32_C(1),
        ROME2_100EDD70_GAME_EXPLORER_DENIED_ACCESS, 1);

    /* Route E: Top-level entry point export test */
    {
        uint8_t exit_code = rome2_port_100edd70_entry_point(
            NULL, 0, NULL, 1, 0, 0, 0, 0);
        failed |= test_expect(
            exit_code == 0x44U,
            "export entry point",
            "entry point returned unexpected exit code");
    }

    /* Route F: Null result rejection check */
    {
        test_fixture *fixture = &test_fixture_storage;
        rome2_100f1bb0_owned_status status;

        test_init_fixture(fixture, UINT32_C(21), UINT32_C(1), UINT32_C(0), UINT32_C(1), 0, 0);
        unified_write_exact_literal(fixture);
        status = rome2_port_100edd70_run_full_entry_sequence(
            (void *)(uintptr_t)TEST_ARGUMENT1,
            fixture->caller_position2,
            fixture->text_identity,
            1, 0, 0, 0,
            fixture->caller_position4,
            0, ROME2_100EDD70_GAME_EXPLORER_BYPASS_CLASSNOTREG,
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
            &full_entry_prefix_effects,
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
            "100edd70 full entry sequence: FAIL\n");
        return 1;
    }
    (void)printf(
        "100edd70 full entry sequence: PASS (51 unified regression + 15 full entry cases)\n");
    return 0;
}

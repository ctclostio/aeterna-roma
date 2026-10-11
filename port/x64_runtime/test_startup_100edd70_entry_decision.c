#include "ported_100edd70_entry_decision.h"

#define main rome2_caller_closure_regression_main
#include "test_startup_100edd70_caller_closure.c"
#undef main

#define ENTRY_TEST_EXPECTED_CASES UINT32_C(44)
#define TEST_EVENT_REGISTRATION_BASE UINT32_C(0x700)

static rome2_100edd70_entry_decision_result entry_result;
static rome2_100edd70_entry_decision_result entry_initial_result;
static rome2_100edd70_registration_effects entry_registration_effects;
static uint32_t entry_case_count;
static uint32_t entry_registration_count;
static uint32_t entry_bad_observations;
static uint32_t entry_mutate_registration;
static uint32_t entry_registration_mutated;

static const uint16_t entry_exact_literal[22] = {
    UINT16_C(0x002d), UINT16_C(0x006e), UINT16_C(0x006f),
    UINT16_C(0x005f), UINT16_C(0x0065), UINT16_C(0x0078),
    UINT16_C(0x0063), UINT16_C(0x0065), UINT16_C(0x0070),
    UINT16_C(0x0074), UINT16_C(0x0069), UINT16_C(0x006f),
    UINT16_C(0x006e), UINT16_C(0x005f), UINT16_C(0x0068),
    UINT16_C(0x0061), UINT16_C(0x006e), UINT16_C(0x0064),
    UINT16_C(0x006c), UINT16_C(0x0065), UINT16_C(0x0072),
    UINT16_C(0x0000)
};

_Static_assert(
    ROME2_PORT_100EDD70_REGISTRATION_RECORD_COUNT == UINT32_C(4) &&
        ROME2_PORT_100EDD70_REGISTRATION_END_PC -
            ROME2_PORT_100EDD70_REGISTRATION_START_PC == UINT32_C(27),
    "the four-record registration transaction changed");

static void entry_begin_case(void)
{
    ++entry_case_count;
}

static void entry_set_result_sentinel(void)
{
    memset(&entry_result, TEST_RESULT_BYTE, sizeof(entry_result));
    entry_initial_result = entry_result;
}

static int entry_result_is_sentinel(void)
{
    return memcmp(
        &entry_result,
        &entry_initial_result,
        sizeof(entry_result)) == 0;
}

static void entry_write_exact_literal(test_fixture *fixture)
{
    uint32_t index;

    for (index = UINT32_C(0); index < UINT32_C(22); ++index) {
        test_write_u16_le(
            fixture->text.bytes + TEST_TEXT_OFFSET + index * UINT32_C(2),
            entry_exact_literal[index]);
    }
}

static int entry_registration_step_is_exact(
    uint32_t index,
    rome2_100edd70_registration_step step)
{
    if (step.value != UINT32_C(0) ||
        step.width_or_cleanup_bytes != UINT32_C(4)) {
        return 0;
    }
    switch (index) {
    case 0U:
        return
            step.kind ==
                ROME2_100EDD70_REGISTRATION_STEP_REGISTER_HANDLER_CALL &&
            step.instruction_original_pc ==
                ROME2_PORT_100EDD70_REGISTRATION_CALL_PC &&
            step.push_original_pc ==
                ROME2_PORT_100EDD70_REGISTRATION_PUSH_PC &&
            step.callee_original_pc ==
                ROME2_PORT_100EDD70_REGISTRATION_CALLEE_PC &&
            step.handler_argument ==
                ROME2_PORT_100EDD70_REGISTRATION_HANDLER_ARGUMENT &&
            step.frame_displacement == INT32_C(0);
    case 1U:
        return
            step.kind == ROME2_100EDD70_REGISTRATION_STEP_CLEANUP_4 &&
            step.instruction_original_pc ==
                ROME2_PORT_100EDD70_REGISTRATION_CLEANUP_PC &&
            step.push_original_pc == UINT32_C(0) &&
            step.callee_original_pc == UINT32_C(0) &&
            step.handler_argument == UINT32_C(0) &&
            step.frame_displacement == INT32_C(0);
    case 2U:
        return
            step.kind == ROME2_100EDD70_REGISTRATION_STEP_FRAME_STORE &&
            step.instruction_original_pc ==
                ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_20_PC &&
            step.push_original_pc == UINT32_C(0) &&
            step.callee_original_pc == UINT32_C(0) &&
            step.handler_argument == UINT32_C(0) &&
            step.frame_displacement ==
                ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_20;
    case 3U:
        return
            step.kind == ROME2_100EDD70_REGISTRATION_STEP_FRAME_STORE &&
            step.instruction_original_pc ==
                ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_04_PC &&
            step.push_original_pc == UINT32_C(0) &&
            step.callee_original_pc == UINT32_C(0) &&
            step.handler_argument == UINT32_C(0) &&
            step.frame_displacement ==
                ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_04;
    default:
        return 0;
    }
}

static void entry_evil_registration(
    void *context,
    rome2_100edd70_registration_step step)
{
    (void)context;
    (void)step;
    ++entry_bad_observations;
}

static void entry_registration_emit(
    void *context,
    rome2_100edd70_registration_step step)
{
    test_trace *trace = (test_trace *)context;

    test_append_event(
        trace,
        TEST_EVENT_REGISTRATION_BASE + (uint32_t)step.kind);
    if (entry_registration_count >=
            ROME2_PORT_100EDD70_REGISTRATION_RECORD_COUNT ||
        !entry_registration_step_is_exact(entry_registration_count, step) ||
        trace->parent_count != UINT32_C(0) ||
        trace->prefix_count != UINT32_C(0) ||
        trace->ordinary_count != UINT32_C(0) ||
        trace->caller_count != UINT32_C(0) ||
        !entry_result_is_sentinel()) {
        ++entry_bad_observations;
    }
    ++entry_registration_count;
    if (entry_mutate_registration != UINT32_C(0) &&
        entry_registration_count == UINT32_C(1)) {
        entry_registration_effects.emit_step = entry_evil_registration;
        entry_registration_effects.context = NULL;
        entry_registration_effects.context_byte_count = UINT64_C(0);
        entry_registration_mutated = UINT32_C(1);
    }
}

static void entry_prepare(
    test_fixture *fixture,
    uint32_t length_units,
    uint32_t poll_count,
    rome2_invalid_parameter_policy expected_policy,
    int mutate_child_effects)
{
    test_init_fixture(
        fixture,
        length_units,
        poll_count,
        UINT32_C(0),
        UINT32_C(1),
        0,
        mutate_child_effects);
    if (expected_policy == ROME2_INVALID_PARAMETER_SKIP_HANDLER) {
        entry_write_exact_literal(fixture);
    }
    fixture->trace.expected_policy = expected_policy;
    entry_set_result_sentinel();
    fixture->trace.result = &entry_result.child;
    fixture->trace.initial_result = entry_result.child;
    entry_registration_effects.emit_step = entry_registration_emit;
    entry_registration_effects.context = &fixture->trace;
    entry_registration_effects.context_byte_count = sizeof(fixture->trace);
    entry_registration_count = UINT32_C(0);
    entry_bad_observations = UINT32_C(0);
    entry_mutate_registration = UINT32_C(0);
    entry_registration_mutated = UINT32_C(0);
}

static rome2_100f1bb0_owned_status entry_call_with(
    test_fixture *fixture,
    rome2_guest_addr32 position3,
    const rome2_guest_write_view *frame_view,
    const rome2_guest_read_view *text_view,
    const rome2_100edd70_caller_closure_effects *continuation_effects,
    const rome2_100edd70_registration_effects *registration_effects,
    rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_100edd70_entry_decision_result *result_out)
{
    return rome2_port_100edd70_run_selected_route(
        TEST_ARGUMENT1,
        fixture->caller_position2,
        position3,
        fixture->caller_position4,
        frame_view,
        (rome2_guest_addr32){fixture->frame_view.guest_base},
        text_view,
        fixture->length_units + UINT32_C(1),
        &fixture->selector_view,
        &fixture->temporary_heap_view,
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->dispatch_view,
        fixture->dispatch_receiver,
        fixture->max_poll_calls,
        &fixture->effects,
        continuation_effects,
        registration_effects,
        temporary_owner,
        persistent_owner,
        lifecycle,
        result_out);
}

static rome2_100f1bb0_owned_status entry_call(test_fixture *fixture)
{
    return entry_call_with(
        fixture,
        fixture->text_identity,
        &fixture->frame_view,
        &fixture->text_view,
        &fixture->continuation_effects,
        &entry_registration_effects,
        &fixture->temporary_owner,
        &fixture->persistent_owner,
        &fixture->lifecycle,
        &entry_result);
}

static void entry_build_expected_events(
    rome2_invalid_parameter_policy policy,
    uint32_t poll_count,
    uint32_t *events,
    uint32_t *count_out)
{
    uint32_t child_events[TEST_MAX_EVENTS];
    uint32_t child_count;
    uint32_t count = UINT32_C(0);

    if (policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER) {
        events[count++] = TEST_EVENT_REGISTRATION_BASE + UINT32_C(1);
        events[count++] = TEST_EVENT_REGISTRATION_BASE + UINT32_C(2);
        events[count++] = TEST_EVENT_REGISTRATION_BASE + UINT32_C(3);
        events[count++] = TEST_EVENT_REGISTRATION_BASE + UINT32_C(3);
    }
    test_build_success_events(poll_count, child_events, &child_count);
    memcpy(events + count, child_events, child_count * sizeof(child_events[0]));
    *count_out = count + child_count;
}

static int entry_verify_success(
    const char *case_name,
    test_fixture *fixture,
    rome2_invalid_parameter_policy policy,
    uint32_t poll_count,
    int expect_registration_mutation,
    int expect_child_mutation)
{
    uint32_t expected[TEST_MAX_EVENTS] = {0};
    uint32_t expected_count;
    uint32_t registration_count =
        policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER ?
            UINT32_C(4) : UINT32_C(0);
    uint32_t window_start =
        policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER ?
            ROME2_PORT_100EDD70_HANDLER_WINDOW_START_PC :
            ROME2_PORT_100EDD70_SKIP_WINDOW_START_PC;
    uint32_t hard_stop =
        policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER ?
            ROME2_PORT_100EDD70_HANDLER_HARD_STOP_PC :
            ROME2_PORT_100EDD70_SKIP_HARD_STOP_PC;
    uint32_t index;
    int failed = 0;

    entry_build_expected_events(policy, poll_count, expected, &expected_count);
    failed |= test_expect(
        fixture->trace.event_count == expected_count &&
            memcmp(
                fixture->trace.events,
                expected,
                expected_count * sizeof(expected[0])) == 0 &&
            expected_count == UINT32_C(45) + poll_count + registration_count,
        case_name,
        "the selected-route total order changed");
    failed |= test_expect(
        fixture->trace.bad_observations == UINT32_C(0) &&
            entry_bad_observations == UINT32_C(0) &&
            entry_registration_count == registration_count &&
            entry_result.policy == policy &&
            entry_result.registration_record_count == registration_count,
        case_name,
        "registration/result cardinality changed");
    for (index = UINT32_C(0); index < registration_count; ++index) {
        failed |= test_expect(
            entry_registration_step_is_exact(
                index,
                entry_result.registration[index]),
            case_name,
            "a committed registration record changed");
    }
    failed |= test_expect(
        entry_result.child.policy == policy &&
            entry_result.child.window_start_original_pc == window_start &&
            entry_result.child.hard_stop_original_pc == hard_stop &&
            entry_result.child.cleanup_bytes ==
                ROME2_PORT_100EDD70_CALLER_CLEANUP_BYTES &&
            entry_result.child.pushes[0].value == fixture->caller_position4 &&
            entry_result.child.pushes[1].value ==
                fixture->text_identity.value &&
            entry_result.child.pushes[2].value == fixture->caller_position2 &&
            entry_result.child.pushes[3].value == TEST_ARGUMENT1 &&
            entry_result.child.parent.preloop.next_original_pc ==
                ROME2_PORT_100ED471_START_PC &&
            entry_result.child.parent.ordinary.return_original_pc ==
                ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_RETURN_PC,
        case_name,
        "the embedded admitted child result changed");
    failed |= test_expect(
        fixture->temporary_owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED &&
            fixture->persistent_owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE &&
            fixture->lifecycle.phase ==
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE &&
            entry_registration_mutated ==
                (expect_registration_mutation != 0 ? UINT32_C(1) : UINT32_C(0)) &&
            fixture->trace.mutation_performed ==
                (expect_child_mutation != 0 ? UINT32_C(1) : UINT32_C(0)),
        case_name,
        "ownership or snapshot isolation changed");
    return failed;
}

static int entry_run_success(
    const char *case_name,
    rome2_invalid_parameter_policy policy,
    uint32_t poll_count,
    int mutate_registration,
    int mutate_child)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    uint32_t length =
        policy == ROME2_INVALID_PARAMETER_SKIP_HANDLER ?
            UINT32_C(21) : UINT32_C(3);
    int failed = 0;

    entry_begin_case();
    entry_prepare(fixture, length, poll_count, policy, mutate_child);
    entry_mutate_registration =
        mutate_registration != 0 ? UINT32_C(1) : UINT32_C(0);
    status = entry_call(fixture);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK,
        case_name,
        "the selected route failed");
    if (status == ROME2_100F1BB0_OWNED_OK) {
        failed |= entry_verify_success(
            case_name,
            fixture,
            policy,
            poll_count,
            mutate_registration,
            mutate_child);
    }
    return failed;
}

static int entry_route_success_cases(void)
{
    int failed = 0;

    failed |= entry_run_success("skip P1", ROME2_INVALID_PARAMETER_SKIP_HANDLER,
        UINT32_C(1), 0, 0);
    failed |= entry_run_success("skip P3", ROME2_INVALID_PARAMETER_SKIP_HANDLER,
        UINT32_C(3), 0, 0);
    failed |= entry_run_success("skip P64", ROME2_INVALID_PARAMETER_SKIP_HANDLER,
        UINT32_C(64), 0, 0);
    failed |= entry_run_success("install P1",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(1), 0, 0);
    failed |= entry_run_success("install P3",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(3), 0, 0);
    failed |= entry_run_success("install P64",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(64), 0, 0);
    return failed;
}

static int entry_selector_boundary_cases(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    entry_begin_case();
    entry_prepare(fixture, UINT32_C(21), UINT32_C(1),
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, 0);
    test_write_u16_le(
        fixture->text.bytes + TEST_TEXT_OFFSET + UINT32_C(20),
        UINT16_C(0x1234));
    fixture->trace.expected_policy = ROME2_INVALID_PARAMETER_INSTALL_HANDLER;
    status = entry_call(fixture);
    failed |= test_expect(status == ROME2_100F1BB0_OWNED_OK,
        "mid-literal mismatch", "the selector did not stop at the mismatch");
    if (status == ROME2_100F1BB0_OWNED_OK) {
        failed |= entry_verify_success(
            "mid-literal mismatch", fixture,
            ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(1), 0, 0);
    }

    entry_begin_case();
    entry_prepare(fixture, UINT32_C(21), UINT32_C(1),
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, 0);
    status = entry_call(fixture);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK &&
            (fixture->text_identity.value & UINT32_C(1)) != UINT32_C(0),
        "unaligned exact literal",
        "the shared unaligned selector address failed");
    if (status == ROME2_100F1BB0_OWNED_OK) {
        failed |= entry_verify_success(
            "unaligned exact literal", fixture,
            ROME2_INVALID_PARAMETER_SKIP_HANDLER, UINT32_C(1), 0, 0);
    }
    return failed;
}

static int entry_expect_tier0(
    const char *case_name,
    test_fixture *fixture,
    rome2_100f1bb0_owned_status status,
    rome2_100f1bb0_owned_status expected)
{
    return test_expect(
        status == expected &&
            fixture->trace.event_count == UINT32_C(0) &&
            fixture->trace.bad_observations == UINT32_C(0) &&
            entry_registration_count == UINT32_C(0) &&
            entry_bad_observations == UINT32_C(0) &&
            entry_result_is_sentinel(),
        case_name,
        "a pre-effect denial changed status, output, or effects");
}

static int entry_tier0_cases(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_guest_read_view text_view;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

#define ENTRY_TIER0_PREPARE(label_) \
    do { \
        entry_begin_case(); \
        entry_prepare(fixture, UINT32_C(21), UINT32_C(1), \
            ROME2_INVALID_PARAMETER_SKIP_HANDLER, 0); \
        (void)(label_); \
    } while (0)

    ENTRY_TIER0_PREPARE("null position three");
    status = entry_call_with(fixture, (rome2_guest_addr32){UINT32_C(0)},
        &fixture->frame_view, &fixture->text_view,
        &fixture->continuation_effects, &entry_registration_effects,
        &fixture->temporary_owner, &fixture->persistent_owner,
        &fixture->lifecycle, &entry_result);
    failed |= entry_expect_tier0("null position three", fixture, status,
        ROME2_100F1BB0_OWNED_NULL_ADDRESS);

    ENTRY_TIER0_PREPARE("missing terminator");
    text_view = fixture->text_view;
    text_view.host_base = fixture->text.bytes + TEST_TEXT_OFFSET;
    text_view.guest_base = fixture->text_identity.value;
    text_view.byte_count = UINT64_C(42);
    status = entry_call_with(fixture, fixture->text_identity,
        &fixture->frame_view, &text_view, &fixture->continuation_effects,
        &entry_registration_effects, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle, &entry_result);
    failed |= entry_expect_tier0("missing terminator", fixture, status,
        ROME2_100F1BB0_OWNED_OUT_OF_RANGE);

    ENTRY_TIER0_PREPARE("one-byte final unit");
    text_view = fixture->text_view;
    text_view.host_base = fixture->text.bytes + TEST_TEXT_OFFSET;
    text_view.guest_base = fixture->text_identity.value;
    text_view.byte_count = UINT64_C(43);
    status = entry_call_with(fixture, fixture->text_identity,
        &fixture->frame_view, &text_view, &fixture->continuation_effects,
        &entry_registration_effects, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle, &entry_result);
    failed |= entry_expect_tier0("one-byte final unit", fixture, status,
        ROME2_100F1BB0_OWNED_OUT_OF_RANGE);

    ENTRY_TIER0_PREPARE("truncated interior unit");
    text_view = fixture->text_view;
    text_view.host_base = fixture->text.bytes + TEST_TEXT_OFFSET;
    text_view.guest_base = fixture->text_identity.value;
    text_view.byte_count = UINT64_C(21);
    status = entry_call_with(fixture, fixture->text_identity,
        &fixture->frame_view, &text_view, &fixture->continuation_effects,
        &entry_registration_effects, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle, &entry_result);
    failed |= entry_expect_tier0("truncated interior unit", fixture, status,
        ROME2_100F1BB0_OWNED_OUT_OF_RANGE);

    ENTRY_TIER0_PREPARE("guest extent overflow");
    text_view = fixture->text_view;
    text_view.guest_base = UINT32_C(0);
    text_view.byte_count = UINT64_C(0x100000001);
    status = entry_call_with(fixture, fixture->text_identity,
        &fixture->frame_view, &text_view, &fixture->continuation_effects,
        &entry_registration_effects, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle, &entry_result);
    failed |= entry_expect_tier0("guest extent overflow", fixture, status,
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    ENTRY_TIER0_PREPARE("host interval overflow");
    text_view = fixture->text_view;
    text_view.host_base = (const uint8_t *)(UINTPTR_MAX - (uintptr_t)2U);
    text_view.byte_count = UINT64_C(4);
    status = entry_call_with(fixture, fixture->text_identity,
        &fixture->frame_view, &text_view, &fixture->continuation_effects,
        &entry_registration_effects, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle, &entry_result);
    failed |= entry_expect_tier0("host interval overflow", fixture, status,
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    ENTRY_TIER0_PREPARE("checked selector cursor overflow");
    text_view = fixture->text_view;
    text_view.host_base = fixture->text.bytes + TEST_TEXT_OFFSET;
    text_view.guest_base = UINT32_C(0xffffffd6);
    text_view.byte_count = UINT64_C(42);
    status = entry_call_with(fixture,
        (rome2_guest_addr32){UINT32_C(0xffffffd6)},
        &fixture->frame_view, &text_view, &fixture->continuation_effects,
        &entry_registration_effects, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle, &entry_result);
    failed |= entry_expect_tier0("checked selector cursor overflow", fixture,
        status, ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    ENTRY_TIER0_PREPARE("null text view");
    status = entry_call_with(fixture, fixture->text_identity,
        &fixture->frame_view, NULL, &fixture->continuation_effects,
        &entry_registration_effects, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle, &entry_result);
    failed |= entry_expect_tier0("null text view", fixture, status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    ENTRY_TIER0_PREPARE("null registration effects");
    status = entry_call_with(fixture, fixture->text_identity,
        &fixture->frame_view, &fixture->text_view,
        &fixture->continuation_effects, NULL, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle, &entry_result);
    failed |= entry_expect_tier0("null registration effects", fixture, status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    ENTRY_TIER0_PREPARE("null result");
    status = entry_call_with(fixture, fixture->text_identity,
        &fixture->frame_view, &fixture->text_view,
        &fixture->continuation_effects, &entry_registration_effects,
        &fixture->temporary_owner, &fixture->persistent_owner,
        &fixture->lifecycle, NULL);
    failed |= entry_expect_tier0("null result", fixture, status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    ENTRY_TIER0_PREPARE("null continuation effects");
    status = entry_call_with(fixture, fixture->text_identity,
        &fixture->frame_view, &fixture->text_view, NULL,
        &entry_registration_effects, &fixture->temporary_owner,
        &fixture->persistent_owner, &fixture->lifecycle, &entry_result);
    failed |= entry_expect_tier0("null continuation effects", fixture, status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    ENTRY_TIER0_PREPARE("null registration callback");
    entry_registration_effects.emit_step = NULL;
    status = entry_call(fixture);
    failed |= entry_expect_tier0("null registration callback", fixture, status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    ENTRY_TIER0_PREPARE("frame size and ownership prestate");
    fixture->frame_view.byte_count = TEST_FRAME_BYTES - UINT32_C(1);
    status = entry_call(fixture);
    failed |= entry_expect_tier0("frame size", fixture, status,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    entry_prepare(fixture, UINT32_C(21), UINT32_C(1),
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, 0);
    fixture->temporary_owner.phase = ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE;
    status = entry_call(fixture);
    failed |= entry_expect_tier0("temporary owner prestate", fixture, status,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    entry_prepare(fixture, UINT32_C(21), UINT32_C(1),
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, 0);
    fixture->lifecycle.phase =
        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE;
    status = entry_call(fixture);
    failed |= entry_expect_tier0("lifecycle prestate", fixture, status,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    entry_prepare(fixture, UINT32_C(21), UINT32_C(1),
        ROME2_INVALID_PARAMETER_SKIP_HANDLER, 0);
    fixture->persistent_descriptor.bytes[
        ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
            TEST_PERSISTENT_DESCRIPTOR_BASE] = UINT8_C(1);
    status = entry_call(fixture);
    failed |= entry_expect_tier0("sentinel descriptor prestate", fixture,
        status, ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

#undef ENTRY_TIER0_PREPARE
    return failed;
}

static int entry_alias_cases(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

#define ENTRY_ALIAS_CONTROL(label_, pointer_) \
    do { \
        entry_begin_case(); \
        entry_prepare(fixture, UINT32_C(3), UINT32_C(1), \
            ROME2_INVALID_PARAMETER_INSTALL_HANDLER, 0); \
        status = entry_call_with(fixture, fixture->text_identity, \
            &fixture->frame_view, &fixture->text_view, \
            &fixture->continuation_effects, \
            (const rome2_100edd70_registration_effects *)(pointer_), \
            &fixture->temporary_owner, &fixture->persistent_owner, \
            &fixture->lifecycle, &entry_result); \
        failed |= entry_expect_tier0((label_), fixture, status, \
            ROME2_100F1BB0_OWNED_BAD_ARGUMENT); \
    } while (0)

    ENTRY_ALIAS_CONTROL("registration overlaps result", &entry_result);
    ENTRY_ALIAS_CONTROL("registration overlaps continuation",
        &fixture->continuation_effects);
    ENTRY_ALIAS_CONTROL("registration overlaps lifecycle", &fixture->lifecycle);
    ENTRY_ALIAS_CONTROL("registration overlaps parent", &fixture->effects);
    ENTRY_ALIAS_CONTROL("registration overlaps temporary owner",
        &fixture->temporary_owner);
    ENTRY_ALIAS_CONTROL("registration overlaps persistent owner",
        &fixture->persistent_owner);

#undef ENTRY_ALIAS_CONTROL

    entry_begin_case();
    entry_prepare(fixture, UINT32_C(3), UINT32_C(1),
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, 0);
    entry_registration_effects.context = (uint8_t *)&fixture->trace + 1U;
    entry_registration_effects.context_byte_count = sizeof(fixture->trace) - 1U;
    status = entry_call(fixture);
    failed |= entry_expect_tier0("partial continuation context overlap",
        fixture, status, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    entry_begin_case();
    entry_prepare(fixture, UINT32_C(3), UINT32_C(1),
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, 0);
    fixture->effects.ordinary.context = (uint8_t *)&fixture->trace + 2U;
    fixture->effects.ordinary_context_byte_count = sizeof(fixture->trace) - 2U;
    status = entry_call(fixture);
    failed |= entry_expect_tier0("partial ordinary context overlap",
        fixture, status, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    entry_begin_case();
    entry_prepare(fixture, UINT32_C(3), UINT32_C(1),
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, 0);
    entry_registration_effects.context = &entry_result;
    entry_registration_effects.context_byte_count = sizeof(entry_result);
    status = entry_call(fixture);
    failed |= entry_expect_tier0("registration context overlaps result",
        fixture, status, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    entry_begin_case();
    entry_prepare(fixture, UINT32_C(3), UINT32_C(1),
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, 0);
    entry_registration_effects.context = fixture->text.bytes;
    entry_registration_effects.context_byte_count = sizeof(fixture->text.bytes);
    status = entry_call(fixture);
    failed |= entry_expect_tier0("registration context overlaps text backing",
        fixture, status, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= entry_run_success("identical shared recorder",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(1), 0, 0);
    return failed;
}

static int entry_mutation_cases(void)
{
    int failed = 0;

    failed |= entry_run_success("registration effects snapshot",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(1), 1, 0);
    failed |= entry_run_success("child effects snapshot through route",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(1), 0, 1);
    return failed;
}

static int entry_failure_case(
    const char *case_name,
    uint32_t failure_kind,
    rome2_invalid_parameter_policy policy,
    rome2_100f1bb0_owned_status expected_status,
    uint32_t expected_child_prefix)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    uint32_t registration =
        policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER ?
            UINT32_C(4) : UINT32_C(0);
    uint32_t length =
        policy == ROME2_INVALID_PARAMETER_SKIP_HANDLER ?
            UINT32_C(21) : UINT32_C(3);
    int failed = 0;

    entry_begin_case();
    entry_prepare(fixture, length, UINT32_C(3), policy, 0);
    switch (failure_kind) {
    case 0U:
        fixture->trace.temporary_plan.result =
            ROME2_100F1BB0_OWNED_GRANT_DENIED;
        memset(&fixture->trace.temporary_plan.grant, 0,
            sizeof(fixture->trace.temporary_plan.grant));
        break;
    case 1U:
        fixture->trace.temporary_plan.result =
            ROME2_100F1BB0_OWNED_GRANT_DENIED;
        break;
    case 2U:
        fixture->trace.persistent_plan.result =
            ROME2_100F1BB0_OWNED_GRANT_DENIED;
        memset(&fixture->trace.persistent_plan.grant, 0,
            sizeof(fixture->trace.persistent_plan.grant));
        break;
    case 3U:
        fixture->trace.persistent_plan.grant.reserved = UINT32_C(1);
        break;
    default:
        fixture->trace.persistent_plan.grant.token = TEST_TEMPORARY_TOKEN;
        break;
    }
    status = entry_call(fixture);
    failed |= test_expect(
        status == expected_status &&
            fixture->trace.event_count == registration + expected_child_prefix &&
            entry_registration_count == registration &&
            fixture->trace.caller_count == UINT32_C(0) &&
            entry_result_is_sentinel(),
        case_name,
        "the inherited committed prefix changed");
    return failed;
}

static int entry_failure_cases(void)
{
    int failed = 0;

    failed |= entry_failure_case("install F1 temporary denial", 0U,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER,
        ROME2_100F1BB0_OWNED_ALLOCATION_DENIED, UINT32_C(8));
    failed |= entry_failure_case("install F2 temporary compensation", 1U,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(9));
    failed |= entry_failure_case("install F3 persistent denial", 2U,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER,
        ROME2_100F1BB0_OWNED_ALLOCATION_DENIED, UINT32_C(20));
    failed |= entry_failure_case("install F4 persistent malformed", 3U,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(21));
    failed |= entry_failure_case("install F5 token collision", 4U,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(20));
    failed |= entry_failure_case("skip F1 temporary denial", 0U,
        ROME2_INVALID_PARAMETER_SKIP_HANDLER,
        ROME2_100F1BB0_OWNED_ALLOCATION_DENIED, UINT32_C(8));
    return failed;
}

static int entry_result_last_case(void)
{
    return entry_run_success("result once and last",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, UINT32_C(1), 0, 0);
}

static int entry_teardown_case(
    const char *case_name,
    rome2_invalid_parameter_policy policy)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    uint32_t before;
    uint32_t length =
        policy == ROME2_INVALID_PARAMETER_SKIP_HANDLER ?
            UINT32_C(21) : UINT32_C(3);
    int failed = 0;

    entry_begin_case();
    entry_prepare(fixture, length, UINT32_C(1), policy, 0);
    status = entry_call(fixture);
    failed |= test_expect(status == ROME2_100F1BB0_OWNED_OK,
        case_name, "the route failed before teardown");
    if (status != ROME2_100F1BB0_OWNED_OK) return failed;
    fixture->trace.require_result_sentinel = UINT32_C(0);
    before = fixture->trace.event_count;
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects.preloop.persistent_owned,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK &&
            fixture->trace.event_count == before + UINT32_C(2) &&
            fixture->lifecycle.phase ==
                ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED,
        case_name,
        "one-shot persistent teardown changed");
    before = fixture->trace.event_count;
    status = rome2_port_100f2750_teardown_first_use_owned(
        &fixture->persistent_descriptor_view,
        &fixture->persistent_heap_view,
        &fixture->effects.preloop.persistent_owned,
        &fixture->persistent_owner,
        &fixture->lifecycle);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_ALREADY_CONSUMED &&
            fixture->trace.event_count == before,
        case_name,
        "repeated persistent teardown emitted an effect");
    return failed;
}

static int entry_teardown_cases(void)
{
    int failed = 0;

    failed |= entry_teardown_case("skip one-shot teardown",
        ROME2_INVALID_PARAMETER_SKIP_HANDLER);
    failed |= entry_teardown_case("install one-shot teardown",
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER);
    return failed;
}

static int entry_committed_child_denial_case(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    entry_begin_case();
    entry_prepare(fixture, UINT32_C(1), UINT32_C(1),
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER, 0);
    test_write_u16_le(
        fixture->text.bytes + TEST_TEXT_OFFSET,
        UINT16_C(0));
    status = entry_call(fixture);
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_BAD_ARGUMENT &&
            fixture->trace.event_count == UINT32_C(4) &&
            entry_registration_count == UINT32_C(4) &&
            fixture->trace.parent_count == UINT32_C(0) &&
            fixture->trace.caller_count == UINT32_C(0) &&
            entry_result_is_sentinel(),
        "install committed-prefix child denial",
        "content validation did not preserve exactly four registration records");
    return failed;
}

int main(void)
{
    int failed;

    failed = rome2_caller_closure_regression_main();
    failed |= entry_route_success_cases();
    failed |= entry_selector_boundary_cases();
    failed |= entry_tier0_cases();
    failed |= entry_alias_cases();
    failed |= entry_mutation_cases();
    failed |= entry_failure_cases();
    failed |= entry_result_last_case();
    failed |= entry_teardown_cases();
    failed |= entry_committed_child_denial_case();
    failed |= test_expect(
        entry_case_count == ENTRY_TEST_EXPECTED_CASES,
        "entry-decision case registry",
        "the exact 44-case outer registry changed");

    if (failed != 0) {
        (void)fprintf(stderr,
            "100edd70 entry decision runtime: FAIL (%u/%u outer cases)\n",
            (unsigned)entry_case_count,
            (unsigned)ENTRY_TEST_EXPECTED_CASES);
        return 1;
    }
    (void)printf(
        "100edd70 entry decision runtime: PASS (%u outer cases)\n",
        (unsigned)entry_case_count);
    return 0;
}

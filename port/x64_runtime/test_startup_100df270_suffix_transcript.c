#include "ported_100df270_suffix_transcript.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_MEMORY_BYTES 128U
#define TEST_GUEST_BASE UINT32_C(0x24000000)
#define TEST_FIRST_OFFSET UINT32_C(13)
#define TEST_SECOND_OFFSET UINT32_C(73)
#define TEST_RETURN_SENTINEL UINT32_C(0xa5a55a5a)
#define TEST_MAX_STEPS UINT32_C(11)

/* Keep the oracle independent of implementation-local spellings. */
_Static_assert(
    ROME2_PORT_100DF270_SUFFIX_ALREADY_MARKED_STEP_COUNT == UINT32_C(7),
    "the authenticated already-marked route must remain seven steps");
_Static_assert(
    ROME2_PORT_100DF270_SUFFIX_MISMATCH_STEP_COUNT == TEST_MAX_STEPS,
    "the authenticated mismatch route must remain eleven steps");
_Static_assert(
    ROME2_PORT_100DF270_SUFFIX_GLOBAL_RECEIVER == UINT32_C(0x119f3140),
    "the published global identity changed");
_Static_assert(
    ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD == UINT32_C(0x119f3a38),
    "the completed 100e8240 result identity changed");
_Static_assert(
    ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET == UINT32_C(0x874),
    "the selector-query owner offset changed");
_Static_assert(
    ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET == UINT32_C(0x68),
    "the completed-result adjustment changed");
_Static_assert(
    ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE == UINT32_C(0x1173dc18),
    "the selector-query vtable identity changed");
_Static_assert(
    ROME2_PORT_100DF270_SUFFIX_VIRTUAL_SLOT_OFFSET == UINT32_C(0x0c),
    "the selector-query slot offset changed");
_Static_assert(
    ROME2_PORT_100DF270_SUFFIX_SELECTOR == UINT32_C(2),
    "the selector constant changed");
_Static_assert(
    ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER == UINT32_C(0x4e3b),
    "the final marker changed");
_Static_assert(
    _Alignof(rome2_100df270_suffix_effects) > 1U,
    "the misalignment oracle requires aligned effects");

typedef union test_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_MEMORY_BYTES];
} test_memory;

typedef union test_effects_storage {
    rome2_100df270_suffix_effects alignment;
    uint8_t bytes[
        sizeof(rome2_100df270_suffix_effects) +
        _Alignof(rome2_100df270_suffix_effects)];
} test_effects_storage;

typedef union test_view_storage {
    rome2_guest_write_view alignment;
    uint8_t bytes[
        sizeof(rome2_guest_write_view) +
        _Alignof(rome2_guest_write_view)];
} test_view_storage;

typedef union test_output_storage {
    rome2_guest_addr32 alignment;
    uint8_t bytes[
        sizeof(rome2_guest_addr32) +
        _Alignof(rome2_guest_addr32)];
} test_output_storage;

typedef union test_delegate_storage {
    rome2_100df270_suffix_100f2750_delegate alignment;
    uint8_t bytes[
        sizeof(rome2_100df270_suffix_100f2750_delegate) +
        _Alignof(rome2_100df270_suffix_100f2750_delegate)];
} test_delegate_storage;

typedef struct test_trace {
    rome2_100df270_suffix_step expected[TEST_MAX_STEPS];
    rome2_100df270_suffix_step observed[TEST_MAX_STEPS];
    test_memory baseline_memory;
    test_memory final_memory;
    test_memory *memory;
    rome2_100df270_suffix_effects *caller_effects;
    rome2_100df270_suffix_100f2750_delegate *caller_delegate;
    rome2_guest_addr32 *return_receiver;
    uint32_t expected_count;
    uint32_t call_count;
    uint32_t failure_count;
    uint32_t unexpected_call_count;
    uint32_t delegate_call_count;
    uint32_t unexpected_delegate_count;
    uint32_t delegate_destination;
    uint32_t delegate_source;
    rome2_guest_status delegate_status;
    int mutate_effects_after_first;
    int mutate_delegate_after_first;
} test_trace;

typedef struct test_fixture {
    test_memory memory;
    rome2_guest_write_view view;
    rome2_100df270_suffix_effects effects;
    rome2_100df270_suffix_100f2750_delegate delegate;
    test_trace trace;
    rome2_guest_addr32 return_receiver;
} test_fixture;

static uint32_t test_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void test_write_u32_le(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static int test_steps_equal(
    const rome2_100df270_suffix_step *left,
    const rome2_100df270_suffix_step *right)
{
    return
        left->kind == right->kind &&
        left->argument_count == right->argument_count &&
        left->argument0 == right->argument0 &&
        left->argument1 == right->argument1 &&
        left->result_count == right->result_count &&
        left->result0 == right->result0 &&
        left->dispatch_vtable == right->dispatch_vtable &&
        left->dispatch_slot_offset == right->dispatch_slot_offset &&
        left->observed_value == right->observed_value;
}

static void test_evil_emit(
    void *opaque,
    rome2_100df270_suffix_step step)
{
    uint32_t *unexpected_call_count = (uint32_t *)opaque;

    (void)step;
    *unexpected_call_count += UINT32_C(1);
}

static rome2_guest_status test_evil_delegate(
    void *opaque,
    rome2_guest_addr32 guest_destination,
    rome2_guest_addr32 guest_source)
{
    test_trace *trace = (test_trace *)opaque;

    (void)guest_destination;
    (void)guest_source;
    trace->unexpected_delegate_count += UINT32_C(1);
    return ROME2_GUEST_BAD_ARGUMENT;
}

static rome2_guest_status test_delegate(
    void *opaque,
    rome2_guest_addr32 guest_destination,
    rome2_guest_addr32 guest_source)
{
    test_trace *trace = (test_trace *)opaque;

    if (trace->call_count != UINT32_C(3) ||
        trace->return_receiver == NULL ||
        trace->return_receiver->value != TEST_RETURN_SENTINEL ||
        trace->memory == NULL ||
        memcmp(
            trace->memory->bytes,
            trace->baseline_memory.bytes,
            TEST_MEMORY_BYTES) != 0 ||
        guest_destination.value != UINT32_C(0x119f3aa0)) {
        trace->failure_count += UINT32_C(1);
    }
    trace->delegate_call_count += UINT32_C(1);
    trace->delegate_destination = guest_destination.value;
    trace->delegate_source = guest_source.value;
    return trace->delegate_status;
}

static void test_emit(
    void *opaque,
    rome2_100df270_suffix_step step)
{
    test_trace *trace = (test_trace *)opaque;
    uint32_t index = trace->call_count;
    int is_final =
        step.kind == ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER;

    if (trace->return_receiver == NULL ||
        trace->return_receiver->value != TEST_RETURN_SENTINEL) {
        trace->failure_count += UINT32_C(1);
    }
    if (trace->memory == NULL ||
        memcmp(
            trace->memory->bytes,
            is_final ? trace->final_memory.bytes : trace->baseline_memory.bytes,
            TEST_MEMORY_BYTES) != 0) {
        trace->failure_count += UINT32_C(1);
    }
    if (index >= trace->expected_count || index >= TEST_MAX_STEPS) {
        trace->failure_count += UINT32_C(1);
        return;
    }

    trace->observed[index] = step;
    if (!test_steps_equal(&step, &trace->expected[index])) {
        trace->failure_count += UINT32_C(1);
    }
    trace->call_count = index + UINT32_C(1);

    if (index == UINT32_C(0) && trace->mutate_effects_after_first != 0 &&
        trace->caller_effects != NULL) {
        trace->caller_effects->emit_step = test_evil_emit;
        trace->caller_effects->context = &trace->unexpected_call_count;
        trace->caller_effects->result_100e8240.value = UINT32_C(0);
        trace->caller_effects->first_selector_result.value = UINT32_C(0);
        trace->caller_effects->second_selector_result.value = UINT32_C(0);
    }
    if (index == UINT32_C(0) && trace->mutate_delegate_after_first != 0 &&
        trace->caller_delegate != NULL) {
        trace->caller_delegate->execute = test_evil_delegate;
        trace->caller_delegate->context = trace;
        trace->caller_delegate->context_byte_count = sizeof(*trace);
    }
}

static void test_zero_step(
    rome2_100df270_suffix_step *step,
    rome2_100df270_suffix_step_kind kind)
{
    (void)memset(step, 0, sizeof(*step));
    step->kind = kind;
}

static void test_set_arguments(
    rome2_100df270_suffix_step *step,
    uint32_t count,
    uint32_t argument0,
    uint32_t argument1)
{
    step->argument_count = count;
    step->argument0 = argument0;
    step->argument1 = argument1;
}

static void test_set_query(
    rome2_100df270_suffix_step *step,
    rome2_100df270_suffix_step_kind kind,
    uint32_t owner,
    uint32_t result,
    uint32_t observed)
{
    test_zero_step(step, kind);
    test_set_arguments(step, UINT32_C(2), owner, UINT32_C(2));
    step->result_count = UINT32_C(1);
    step->result0 = result;
    step->dispatch_vtable = UINT32_C(0x1173dc18);
    step->dispatch_slot_offset = UINT32_C(0x0c);
    step->observed_value = observed;
}

static void test_build_expected(
    test_trace *trace,
    uint32_t receiver,
    uint32_t argument,
    uint32_t first_result,
    uint32_t second_result,
    uint32_t first_value)
{
    static const uint32_t mismatch_arguments[4] = {
        UINT32_C(0x2d), UINT32_C(0x12),
        UINT32_C(0x16), UINT32_C(0x21),
    };
    uint32_t owner = receiver + UINT32_C(0x874);
    uint32_t index = UINT32_C(0);
    size_t mismatch_index;

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_SUFFIX_STEP_PUBLISH_RECEIVER);
    test_set_arguments(
        &trace->expected[index], UINT32_C(2),
        UINT32_C(0x119f3140), receiver);
    index += UINT32_C(1);

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_SUFFIX_STEP_CALL_100E8240);
    test_set_arguments(
        &trace->expected[index], UINT32_C(1), argument, UINT32_C(0));
    trace->expected[index].result_count = UINT32_C(1);
    trace->expected[index].result0 = UINT32_C(0x119f3a38);
    index += UINT32_C(1);

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_SUFFIX_STEP_CALL_100F2750);
    test_set_arguments(
        &trace->expected[index], UINT32_C(2),
        UINT32_C(0x119f3aa0), argument);
    index += UINT32_C(1);

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0);
    test_set_arguments(
        &trace->expected[index], UINT32_C(1), receiver, UINT32_C(0));
    index += UINT32_C(1);

    test_set_query(
        &trace->expected[index],
        ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_FIRST,
        owner, first_result, first_value);
    index += UINT32_C(1);

    if (first_value != UINT32_C(0x4e3b)) {
        for (mismatch_index = 0;
             mismatch_index < sizeof(mismatch_arguments) /
                sizeof(mismatch_arguments[0]);
             ++mismatch_index) {
            test_zero_step(
                &trace->expected[index],
                ROME2_100DF270_SUFFIX_STEP_CALL_101046D0);
            test_set_arguments(
                &trace->expected[index], UINT32_C(1),
                mismatch_arguments[mismatch_index], UINT32_C(0));
            index += UINT32_C(1);
        }
    }

    test_set_query(
        &trace->expected[index],
        ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_SECOND,
        owner, second_result, UINT32_C(0));
    index += UINT32_C(1);

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER);
    test_set_arguments(
        &trace->expected[index], UINT32_C(2),
        second_result, UINT32_C(0x4e3b));
    trace->expected_count = index + UINT32_C(1);
}

static void test_init_fixture(
    test_fixture *fixture,
    uint32_t receiver,
    uint32_t argument,
    uint32_t first_offset,
    uint32_t second_offset,
    uint32_t first_value,
    uint32_t second_value,
    int mutate_effects)
{
    uint32_t first_result = TEST_GUEST_BASE + first_offset;
    uint32_t second_result = TEST_GUEST_BASE + second_offset;

    (void)memset(fixture, 0, sizeof(*fixture));
    (void)memset(fixture->memory.bytes, 0xa7, sizeof(fixture->memory.bytes));
    test_write_u32_le(fixture->memory.bytes + first_offset, first_value);
    if (first_offset != second_offset) {
        test_write_u32_le(fixture->memory.bytes + second_offset, second_value);
    }

    fixture->view.host_base = fixture->memory.bytes;
    fixture->view.guest_base = TEST_GUEST_BASE;
    fixture->view.byte_count = sizeof(fixture->memory.bytes);
    fixture->effects.emit_step = test_emit;
    fixture->effects.context = &fixture->trace;
    fixture->effects.result_100e8240.value = UINT32_C(0x119f3a38);
    fixture->effects.first_selector_result.value = first_result;
    fixture->effects.second_selector_result.value = second_result;
    fixture->delegate.execute = test_delegate;
    fixture->delegate.context = &fixture->trace;
    fixture->delegate.context_byte_count = sizeof(fixture->trace);
    fixture->return_receiver.value = TEST_RETURN_SENTINEL;

    fixture->trace.baseline_memory = fixture->memory;
    fixture->trace.final_memory = fixture->memory;
    test_write_u32_le(
        fixture->trace.final_memory.bytes + second_offset,
        UINT32_C(0x4e3b));
    fixture->trace.memory = &fixture->memory;
    fixture->trace.caller_effects = &fixture->effects;
    fixture->trace.caller_delegate = &fixture->delegate;
    fixture->trace.return_receiver = &fixture->return_receiver;
    fixture->trace.delegate_status = ROME2_GUEST_OK;
    fixture->trace.mutate_effects_after_first = mutate_effects;
    test_build_expected(
        &fixture->trace, receiver, argument,
        first_result, second_result, first_value);
}

static int test_expect(int condition, const char *case_name, const char *detail)
{
    if (condition) {
        return 0;
    }
    (void)fprintf(stderr, "100df270 suffix runtime: %s: %s\n",
        case_name, detail);
    return 1;
}

static int test_run_success(
    const char *case_name,
    uint32_t receiver,
    uint32_t argument,
    uint32_t first_offset,
    uint32_t second_offset,
    uint32_t first_value,
    uint32_t second_value,
    int mutate_effects)
{
    test_fixture fixture;
    rome2_100df270_suffix_effects saved_effects;
    rome2_guest_write_view saved_view;
    rome2_guest_status status;
    uint32_t index;
    int failed = 0;

    test_init_fixture(
        &fixture, receiver, argument, first_offset, second_offset,
        first_value, second_value, mutate_effects);
    saved_effects = fixture.effects;
    saved_view = fixture.view;
    status = rome2_port_100df270_run_suffix_transcript(
        &fixture.view,
        (rome2_guest_addr32){receiver},
        (rome2_guest_addr32){argument},
        &fixture.effects,
        &fixture.return_receiver);

    failed |= test_expect(status == ROME2_GUEST_OK,
        case_name, "status was not OK");
    failed |= test_expect(
        fixture.trace.call_count == fixture.trace.expected_count &&
        fixture.trace.failure_count == UINT32_C(0) &&
        fixture.trace.unexpected_call_count == UINT32_C(0),
        case_name, "step count, order, fields, or commit timing changed");
    failed |= test_expect(
        fixture.return_receiver.value == receiver,
        case_name, "receiver output did not commit after the final callback");
    failed |= test_expect(
        memcmp(fixture.memory.bytes, fixture.trace.final_memory.bytes,
            sizeof(fixture.memory.bytes)) == 0,
        case_name, "guest bytes differed from the single final marker store");
    failed |= test_expect(
        memcmp(&fixture.view, &saved_view, sizeof(saved_view)) == 0,
        case_name, "state-view descriptor was mutated");
    if (mutate_effects == 0) {
        failed |= test_expect(
            memcmp(&fixture.effects, &saved_effects, sizeof(saved_effects)) == 0,
            case_name, "effects descriptor was mutated by the adapter");
    } else {
        failed |= test_expect(
            fixture.effects.emit_step == test_evil_emit &&
            fixture.effects.context == &fixture.trace.unexpected_call_count &&
            fixture.effects.result_100e8240.value == UINT32_C(0) &&
            fixture.effects.first_selector_result.value == UINT32_C(0) &&
            fixture.effects.second_selector_result.value == UINT32_C(0),
            case_name, "callback mutation of the caller effects was lost");
    }

    for (index = UINT32_C(0);
         index < fixture.trace.expected_count && index < TEST_MAX_STEPS;
         ++index) {
        failed |= test_expect(
            test_steps_equal(
                &fixture.trace.observed[index],
                &fixture.trace.expected[index]),
            case_name, "observed transcript differs from the independent oracle");
    }
    return failed;
}

static int test_success_routes_are_exact(void)
{
    int failed = 0;

    failed |= test_run_success(
        "already-marked route is exactly seven steps",
        UINT32_C(0x10203040), UINT32_C(0xffffffff),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0x12345678), 0);
    failed |= test_run_success(
        "mismatch route is exactly eleven steps",
        UINT32_C(0x55667000), UINT32_C(0x89abcdef),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x01020304), UINT32_C(0xfedcba98), 0);
    failed |= test_run_success(
        "repeated selector queries may return the same guest cell",
        UINT32_C(0x12345000), UINT32_C(0x80000000),
        TEST_FIRST_OFFSET, TEST_FIRST_OFFSET,
        UINT32_C(0x11223344), UINT32_C(0x11223344), 0);
    failed |= test_run_success(
        "receiver plus 0x874 may equal the guest32 maximum",
        UINT32_C(0xfffff78b), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    return failed;
}

static int test_effects_snapshot_is_complete(void)
{
    return test_run_success(
        "effects are snapshotted before the first callback",
        UINT32_C(0x76543000), UINT32_C(0xdeadbeef),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x01010101), UINT32_C(0x02020202), 1);
}

static int test_expect_precommit_failure(
    const char *case_name,
    rome2_guest_status expected_status,
    test_fixture *fixture,
    const rome2_guest_write_view *view,
    uint32_t receiver,
    const rome2_100df270_suffix_effects *effects,
    rome2_guest_addr32 *return_receiver,
    int output_is_observable)
{
    test_memory saved_memory = fixture->memory;
    rome2_100df270_suffix_effects saved_effects = fixture->effects;
    rome2_100df270_suffix_100f2750_delegate saved_delegate = fixture->delegate;
    rome2_guest_addr32 saved_output = fixture->return_receiver;
    rome2_guest_status delegated_status;
    rome2_guest_status status;
    int failed = 0;

    /* Every baseline precommit scenario also exercises the mirrored checks in
     * the additive delegated entry, with no observer or delegate effect. */
    delegated_status =
        rome2_port_100df270_run_suffix_transcript_delegated(
            view,
            (rome2_guest_addr32){receiver},
            (rome2_guest_addr32){UINT32_C(0x89abcdef)},
            effects,
            &fixture->delegate,
            return_receiver);
    failed |= test_expect(delegated_status == expected_status,
        case_name, "delegated mirror failure status changed");
    failed |= test_expect(
        fixture->trace.call_count == UINT32_C(0) &&
        fixture->trace.delegate_call_count == UINT32_C(0) &&
        fixture->trace.failure_count == UINT32_C(0) &&
        fixture->trace.unexpected_call_count == UINT32_C(0) &&
        fixture->trace.unexpected_delegate_count == UINT32_C(0),
        case_name, "delegated mirror validation emitted an effect");
    failed |= test_expect(
        memcmp(fixture->memory.bytes, saved_memory.bytes,
            sizeof(saved_memory.bytes)) == 0 &&
        memcmp(&fixture->effects, &saved_effects, sizeof(saved_effects)) == 0 &&
        memcmp(
            &fixture->delegate, &saved_delegate, sizeof(saved_delegate)) == 0 &&
        fixture->return_receiver.value == saved_output.value,
        case_name, "delegated mirror validation changed caller state");

    status = rome2_port_100df270_run_suffix_transcript(
        view,
        (rome2_guest_addr32){receiver},
        (rome2_guest_addr32){UINT32_C(0x89abcdef)},
        effects,
        return_receiver);
    failed |= test_expect(status == expected_status,
        case_name, "failure status changed");
    failed |= test_expect(
        fixture->trace.call_count == UINT32_C(0) &&
        fixture->trace.failure_count == UINT32_C(0) &&
        fixture->trace.unexpected_call_count == UINT32_C(0),
        case_name, "validation failure emitted a callback");
    failed |= test_expect(
        memcmp(fixture->memory.bytes, saved_memory.bytes,
            sizeof(saved_memory.bytes)) == 0,
        case_name, "validation failure mutated guest bytes");
    failed |= test_expect(
        memcmp(&fixture->effects, &saved_effects, sizeof(saved_effects)) == 0,
        case_name, "validation failure mutated the caller effects");
    if (output_is_observable != 0) {
        failed |= test_expect(
            fixture->return_receiver.value == TEST_RETURN_SENTINEL,
            case_name, "validation failure changed the receiver output");
    }
    return failed;
}

static int test_required_objects_and_guest_values_fail_closed(void)
{
    test_fixture fixture;
    int failed = 0;

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0x89abcdef),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    failed |= test_expect_precommit_failure(
        "null state view", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        NULL, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0x89abcdef),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    failed |= test_expect_precommit_failure(
        "null effects", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, UINT32_C(0x12345000), NULL,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0x89abcdef),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    failed |= test_expect_precommit_failure(
        "null receiver output", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        NULL, 0);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0x89abcdef),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.effects.emit_step = NULL;
    failed |= test_expect_precommit_failure(
        "null emit callback", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0x89abcdef),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.effects.context = NULL;
    failed |= test_expect_precommit_failure(
        "null callback context", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0x89abcdef),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    failed |= test_expect_precommit_failure(
        "null receiver identity", ROME2_GUEST_NULL_ADDRESS, &fixture,
        &fixture.view, UINT32_C(0), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0x89abcdef),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    failed |= test_expect_precommit_failure(
        "receiver plus 0x874 overflows", ROME2_GUEST_RANGE_OVERFLOW, &fixture,
        &fixture.view, UINT32_C(0xfffff78c), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0x89abcdef),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.effects.result_100e8240.value = UINT32_C(0);
    failed |= test_expect_precommit_failure(
        "null 100e8240 result", ROME2_GUEST_NULL_ADDRESS, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0x89abcdef),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.effects.result_100e8240.value = UINT32_C(0x119f3a39);
    failed |= test_expect_precommit_failure(
        "wrong completed 100e8240 identity", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);
    return failed;
}

static int test_result_cells_and_view_ranges_fail_closed(void)
{
    test_fixture fixture;
    int failed = 0;

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.effects.first_selector_result.value = UINT32_C(0);
    failed |= test_expect_precommit_failure(
        "null first selector cell", ROME2_GUEST_NULL_ADDRESS, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.effects.second_selector_result.value = UINT32_C(0xffffffff);
    failed |= test_expect_precommit_failure(
        "second selector cell span overflows guest32",
        ROME2_GUEST_RANGE_OVERFLOW, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.effects.first_selector_result.value = TEST_GUEST_BASE - UINT32_C(1);
    failed |= test_expect_precommit_failure(
        "first selector cell below view", ROME2_GUEST_OUT_OF_RANGE, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.effects.second_selector_result.value =
        TEST_GUEST_BASE + TEST_MEMORY_BYTES - UINT32_C(3);
    failed |= test_expect_precommit_failure(
        "second selector cell is truncated", ROME2_GUEST_OUT_OF_RANGE, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.view.guest_base = UINT32_C(0xfffffff0);
    fixture.view.byte_count = UINT64_C(32);
    failed |= test_expect_precommit_failure(
        "guest view interval overflows", ROME2_GUEST_RANGE_OVERFLOW, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.view.host_base = NULL;
    failed |= test_expect_precommit_failure(
        "null state host interval", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.view.host_base =
        (uint8_t *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)1U);
    fixture.view.guest_base = TEST_GUEST_BASE;
    fixture.view.byte_count = UINT64_C(4);
    fixture.effects.first_selector_result.value = TEST_GUEST_BASE;
    fixture.effects.second_selector_result.value = TEST_GUEST_BASE;
    failed |= test_expect_precommit_failure(
        "native host interval overflows", ROME2_GUEST_RANGE_OVERFLOW, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);
    return failed;
}

static int test_aliases_and_alignment_fail_closed(void)
{
    test_fixture fixture;
    test_effects_storage raw_storage;
    test_view_storage raw_view_storage;
    test_output_storage raw_output_storage;
    rome2_100df270_suffix_effects *misaligned_effects;
    rome2_guest_write_view *misaligned_view;
    rome2_guest_addr32 *misaligned_output;
    uint8_t raw_snapshot[sizeof(raw_storage.bytes)];
    uint8_t raw_view_snapshot[sizeof(raw_view_storage.bytes)];
    uint8_t raw_output_snapshot[sizeof(raw_output_storage.bytes)];
    int failed = 0;

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    failed |= test_expect_precommit_failure(
        "effects and output overlap", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        (rome2_guest_addr32 *)(void *)&fixture.effects, 0);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    failed |= test_expect_precommit_failure(
        "state-view descriptor and effects overlap",
        ROME2_GUEST_BAD_ARGUMENT, &fixture,
        (const rome2_guest_write_view *)(const void *)&fixture.effects,
        UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    failed |= test_expect_precommit_failure(
        "state-view descriptor and output overlap",
        ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        (rome2_guest_addr32 *)(void *)&fixture.view, 0);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.view.host_base = (uint8_t *)(void *)&fixture.effects;
    fixture.view.guest_base = TEST_GUEST_BASE;
    fixture.view.byte_count = sizeof(fixture.effects);
    fixture.effects.first_selector_result.value = TEST_GUEST_BASE;
    fixture.effects.second_selector_result.value = TEST_GUEST_BASE;
    failed |= test_expect_precommit_failure(
        "state host interval overlaps effects", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.view.host_base = (uint8_t *)(void *)&fixture.return_receiver;
    fixture.view.guest_base = TEST_GUEST_BASE;
    fixture.view.byte_count = sizeof(fixture.return_receiver);
    fixture.effects.first_selector_result.value = TEST_GUEST_BASE;
    fixture.effects.second_selector_result.value = TEST_GUEST_BASE;
    failed |= test_expect_precommit_failure(
        "state host interval overlaps output", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    fixture.view.host_base = (uint8_t *)(void *)&fixture.view;
    fixture.view.guest_base = TEST_GUEST_BASE;
    fixture.view.byte_count = sizeof(fixture.view);
    fixture.effects.first_selector_result.value = TEST_GUEST_BASE;
    fixture.effects.second_selector_result.value = TEST_GUEST_BASE;
    failed |= test_expect_precommit_failure(
        "state host interval overlaps its descriptor", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    (void)memset(&raw_storage, 0, sizeof(raw_storage));
    (void)memcpy(raw_storage.bytes + 1U,
        &fixture.effects, sizeof(fixture.effects));
    (void)memcpy(raw_snapshot, raw_storage.bytes, sizeof(raw_storage.bytes));
    misaligned_effects =
        (rome2_100df270_suffix_effects *)(void *)(raw_storage.bytes + 1U);
    failed |= test_expect_precommit_failure(
        "misaligned effects descriptor", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, UINT32_C(0x12345000), misaligned_effects,
        &fixture.return_receiver, 1);
    failed |= test_expect(
        memcmp(raw_storage.bytes, raw_snapshot, sizeof(raw_snapshot)) == 0,
        "misaligned effects descriptor",
        "rejected descriptor storage was mutated");

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    (void)memset(&raw_view_storage, 0, sizeof(raw_view_storage));
    (void)memcpy(raw_view_storage.bytes + 1U,
        &fixture.view, sizeof(fixture.view));
    (void)memcpy(raw_view_snapshot, raw_view_storage.bytes,
        sizeof(raw_view_storage.bytes));
    misaligned_view =
        (rome2_guest_write_view *)(void *)(raw_view_storage.bytes + 1U);
    failed |= test_expect_precommit_failure(
        "misaligned state-view descriptor", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, misaligned_view, UINT32_C(0x12345000), &fixture.effects,
        &fixture.return_receiver, 1);
    failed |= test_expect(
        memcmp(raw_view_storage.bytes, raw_view_snapshot,
            sizeof(raw_view_snapshot)) == 0,
        "misaligned state-view descriptor",
        "rejected descriptor storage was mutated");

    test_init_fixture(
        &fixture, UINT32_C(0x12345000), UINT32_C(0),
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    (void)memset(&raw_output_storage, 0, sizeof(raw_output_storage));
    test_write_u32_le(raw_output_storage.bytes + 1U, TEST_RETURN_SENTINEL);
    (void)memcpy(raw_output_snapshot, raw_output_storage.bytes,
        sizeof(raw_output_storage.bytes));
    misaligned_output =
        (rome2_guest_addr32 *)(void *)(raw_output_storage.bytes + 1U);
    failed |= test_expect_precommit_failure(
        "misaligned receiver output", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, UINT32_C(0x12345000), &fixture.effects,
        misaligned_output, 0);
    failed |= test_expect(
        memcmp(raw_output_storage.bytes, raw_output_snapshot,
            sizeof(raw_output_snapshot)) == 0,
        "misaligned receiver output",
        "rejected output storage was mutated");
    return failed;
}

static int test_run_delegated_success(
    const char *case_name,
    uint32_t first_value,
    uint32_t second_offset,
    int mutate_effects,
    int mutate_delegate)
{
    const uint32_t receiver = UINT32_C(0x23456000);
    const uint32_t argument = UINT32_C(0x34567000);
    test_fixture fixture;
    rome2_guest_write_view saved_view;
    rome2_100df270_suffix_effects saved_effects;
    rome2_100df270_suffix_100f2750_delegate saved_delegate;
    rome2_guest_status status;
    int failed = 0;

    test_init_fixture(
        &fixture,
        receiver,
        argument,
        TEST_FIRST_OFFSET,
        second_offset,
        first_value,
        UINT32_C(0x76543210),
        mutate_effects);
    fixture.trace.mutate_delegate_after_first = mutate_delegate;
    saved_view = fixture.view;
    saved_effects = fixture.effects;
    saved_delegate = fixture.delegate;

    status = rome2_port_100df270_run_suffix_transcript_delegated(
        &fixture.view,
        (rome2_guest_addr32){receiver},
        (rome2_guest_addr32){argument},
        &fixture.effects,
        &fixture.delegate,
        &fixture.return_receiver);

    failed |= test_expect(
        status == ROME2_GUEST_OK,
        case_name,
        "delegated success status changed");
    failed |= test_expect(
        fixture.trace.call_count == fixture.trace.expected_count &&
        fixture.trace.failure_count == UINT32_C(0) &&
        fixture.trace.unexpected_call_count == UINT32_C(0),
        case_name,
        "delegated transcript order or callback timing changed");
    failed |= test_expect(
        fixture.trace.delegate_call_count == UINT32_C(1) &&
        fixture.trace.unexpected_delegate_count == UINT32_C(0) &&
        fixture.trace.delegate_destination == UINT32_C(0x119f3aa0) &&
        fixture.trace.delegate_source == argument,
        case_name,
        "typed delegate count, position, or arguments changed");
    failed |= test_expect(
        fixture.return_receiver.value == receiver,
        case_name,
        "delegated receiver output did not commit last");
    failed |= test_expect(
        memcmp(
            fixture.memory.bytes,
            fixture.trace.final_memory.bytes,
            sizeof(fixture.memory.bytes)) == 0,
        case_name,
        "delegated success marker store changed");
    failed |= test_expect(
        memcmp(&fixture.view, &saved_view, sizeof(saved_view)) == 0,
        case_name,
        "delegated success mutated the state-view descriptor");
    if (mutate_effects == 0) {
        failed |= test_expect(
            memcmp(
                &fixture.effects,
                &saved_effects,
                sizeof(saved_effects)) == 0,
            case_name,
            "delegated success mutated its caller effects descriptor");
    } else {
        failed |= test_expect(
            fixture.effects.emit_step == test_evil_emit &&
            fixture.effects.context == &fixture.trace.unexpected_call_count &&
            fixture.effects.result_100e8240.value == UINT32_C(0) &&
            fixture.effects.first_selector_result.value == UINT32_C(0) &&
            fixture.effects.second_selector_result.value == UINT32_C(0),
            case_name,
            "caller-side effects mutation was lost during delegated success");
    }
    if (mutate_delegate == 0) {
        failed |= test_expect(
            memcmp(
                &fixture.delegate,
                &saved_delegate,
                sizeof(saved_delegate)) == 0,
            case_name,
            "delegated success mutated its caller descriptor");
    } else {
        failed |= test_expect(
            fixture.delegate.execute == test_evil_delegate &&
            fixture.delegate.context == &fixture.trace &&
            fixture.delegate.context_byte_count == sizeof(fixture.trace),
            case_name,
            "caller-side delegate mutation was lost");
    }
    return failed;
}

static int test_delegated_success_order_and_snapshot(void)
{
    int failed = 0;

    failed |= test_run_delegated_success(
        "delegated already-marked route executes between steps three and four",
        UINT32_C(0x4e3b),
        TEST_SECOND_OFFSET,
        0,
        0);
    failed |= test_run_delegated_success(
        "delegated mismatch route preserves all eleven steps",
        UINT32_C(0x01020304),
        TEST_SECOND_OFFSET,
        0,
        0);
    failed |= test_run_delegated_success(
        "delegated repeated selector queries may return the same guest cell",
        UINT32_C(0x11223344),
        TEST_FIRST_OFFSET,
        0,
        0);
    failed |= test_run_delegated_success(
        "delegate descriptor is snapshotted before the first observer callback",
        UINT32_C(0x4e3b),
        TEST_SECOND_OFFSET,
        0,
        1);
    failed |= test_run_delegated_success(
        "effects descriptor is snapshotted before the first delegated observer",
        UINT32_C(0x0badc0de),
        TEST_SECOND_OFFSET,
        1,
        0);
    return failed;
}

static int test_delegated_failure_is_exact_committed_prefix(void)
{
    const char *case_name =
        "delegate failure stops after the observed CALL_100F2750 step";
    const uint32_t receiver = UINT32_C(0x23456000);
    const uint32_t argument = UINT32_C(0x34567000);
    test_fixture fixture;
    rome2_guest_status status;
    uint32_t index;
    int failed = 0;

    test_init_fixture(
        &fixture,
        receiver,
        argument,
        TEST_FIRST_OFFSET,
        TEST_SECOND_OFFSET,
        UINT32_C(0x01020304),
        UINT32_C(0x76543210),
        0);
    fixture.trace.delegate_status = ROME2_GUEST_OUT_OF_RANGE;
    status = rome2_port_100df270_run_suffix_transcript_delegated(
        &fixture.view,
        (rome2_guest_addr32){receiver},
        (rome2_guest_addr32){argument},
        &fixture.effects,
        &fixture.delegate,
        &fixture.return_receiver);

    failed |= test_expect(
        status == ROME2_GUEST_OUT_OF_RANGE,
        case_name,
        "delegate failure status was not propagated");
    failed |= test_expect(
        fixture.trace.call_count == UINT32_C(3) &&
        fixture.trace.delegate_call_count == UINT32_C(1) &&
        fixture.trace.failure_count == UINT32_C(0) &&
        fixture.trace.unexpected_call_count == UINT32_C(0) &&
        fixture.trace.unexpected_delegate_count == UINT32_C(0),
        case_name,
        "failure prefix count or delegate position changed");
    for (index = UINT32_C(0); index < UINT32_C(3); ++index) {
        failed |= test_expect(
            test_steps_equal(
                &fixture.trace.observed[index],
                &fixture.trace.expected[index]),
            case_name,
            "failure prefix step payload changed");
    }
    failed |= test_expect(
        memcmp(
            fixture.memory.bytes,
            fixture.trace.baseline_memory.bytes,
            sizeof(fixture.memory.bytes)) == 0,
        case_name,
        "delegate failure reached the marker store");
    failed |= test_expect(
        fixture.return_receiver.value == TEST_RETURN_SENTINEL,
        case_name,
        "delegate failure committed the receiver output");
    return failed;
}

static int test_expect_delegated_validation_failure(
    const char *case_name,
    rome2_guest_status expected_status,
    test_fixture *fixture,
    const rome2_guest_write_view *view,
    const rome2_100df270_suffix_effects *effects,
    const rome2_100df270_suffix_100f2750_delegate *delegate,
    rome2_guest_addr32 *return_receiver)
{
    test_memory saved_memory = fixture->memory;
    rome2_100df270_suffix_effects saved_effects = fixture->effects;
    rome2_100df270_suffix_100f2750_delegate saved_delegate = fixture->delegate;
    rome2_guest_addr32 saved_output = fixture->return_receiver;
    rome2_guest_status status =
        rome2_port_100df270_run_suffix_transcript_delegated(
            view,
            (rome2_guest_addr32){UINT32_C(0x23456000)},
            (rome2_guest_addr32){UINT32_C(0x34567000)},
            effects,
            delegate,
            return_receiver);
    int failed = 0;

    failed |= test_expect(
        status == expected_status,
        case_name,
        "delegated validation status changed");
    failed |= test_expect(
        fixture->trace.call_count == UINT32_C(0) &&
        fixture->trace.delegate_call_count == UINT32_C(0) &&
        fixture->trace.failure_count == UINT32_C(0) &&
        fixture->trace.unexpected_call_count == UINT32_C(0) &&
        fixture->trace.unexpected_delegate_count == UINT32_C(0),
        case_name,
        "delegated validation failure emitted an effect");
    failed |= test_expect(
        memcmp(
            fixture->memory.bytes,
            saved_memory.bytes,
            sizeof(saved_memory.bytes)) == 0 &&
        memcmp(&fixture->effects, &saved_effects, sizeof(saved_effects)) == 0 &&
        memcmp(
            &fixture->delegate,
            &saved_delegate,
            sizeof(saved_delegate)) == 0 &&
        fixture->return_receiver.value == saved_output.value,
        case_name,
        "delegated validation failure changed caller state");
    return failed;
}

static int test_delegated_boundary_failures_are_pre_effect(void)
{
    test_fixture fixture;
    test_delegate_storage raw_delegate_storage;
    rome2_100df270_suffix_100f2750_delegate *misaligned_delegate;
    uint8_t raw_delegate_snapshot[sizeof(raw_delegate_storage.bytes)];
    int failed = 0;

#define TEST_INIT_DELEGATED_FIXTURE() \
    test_init_fixture( \
        &fixture, UINT32_C(0x23456000), UINT32_C(0x34567000), \
        TEST_FIRST_OFFSET, TEST_SECOND_OFFSET, \
        UINT32_C(0x4e3b), UINT32_C(0x76543210), 0)

    TEST_INIT_DELEGATED_FIXTURE();
    failed |= test_expect_delegated_validation_failure(
        "null delegate descriptor", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, &fixture.effects, NULL, &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    fixture.delegate.execute = NULL;
    failed |= test_expect_delegated_validation_failure(
        "null delegate callback", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, &fixture.effects, &fixture.delegate,
        &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    fixture.delegate.context = NULL;
    failed |= test_expect_delegated_validation_failure(
        "null delegate context", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, &fixture.effects, &fixture.delegate,
        &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    fixture.delegate.context_byte_count = UINT64_C(0);
    failed |= test_expect_delegated_validation_failure(
        "empty delegate context", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, &fixture.effects, &fixture.delegate,
        &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    fixture.delegate.context = (void *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)1U);
    fixture.delegate.context_byte_count = UINT64_C(4);
    failed |= test_expect_delegated_validation_failure(
        "delegate context host interval overflows",
        ROME2_GUEST_RANGE_OVERFLOW, &fixture,
        &fixture.view, &fixture.effects, &fixture.delegate,
        &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    failed |= test_expect_delegated_validation_failure(
        "delegate descriptor overlaps effects", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, &fixture.effects,
        (const rome2_100df270_suffix_100f2750_delegate *)(const void *)
            &fixture.effects,
        &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    failed |= test_expect_delegated_validation_failure(
        "delegate descriptor overlaps state descriptor",
        ROME2_GUEST_BAD_ARGUMENT, &fixture, &fixture.view, &fixture.effects,
        (const rome2_100df270_suffix_100f2750_delegate *)(const void *)
            &fixture.view,
        &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    failed |= test_expect_delegated_validation_failure(
        "delegate descriptor overlaps receiver output",
        ROME2_GUEST_BAD_ARGUMENT, &fixture, &fixture.view, &fixture.effects,
        &fixture.delegate,
        (rome2_guest_addr32 *)(void *)&fixture.delegate);

    TEST_INIT_DELEGATED_FIXTURE();
    fixture.view.host_base = (uint8_t *)(void *)&fixture.delegate;
    fixture.view.byte_count = sizeof(fixture.delegate);
    failed |= test_expect_delegated_validation_failure(
        "state backing overlaps delegate descriptor",
        ROME2_GUEST_BAD_ARGUMENT, &fixture, &fixture.view, &fixture.effects,
        &fixture.delegate, &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    fixture.delegate.context = fixture.memory.bytes;
    fixture.delegate.context_byte_count = UINT64_C(1);
    failed |= test_expect_delegated_validation_failure(
        "delegate context overlaps state backing", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, &fixture.effects, &fixture.delegate,
        &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    fixture.delegate.context = &fixture.effects;
    fixture.delegate.context_byte_count = sizeof(fixture.effects);
    failed |= test_expect_delegated_validation_failure(
        "delegate context overlaps effects descriptor",
        ROME2_GUEST_BAD_ARGUMENT, &fixture, &fixture.view, &fixture.effects,
        &fixture.delegate, &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    fixture.delegate.context = &fixture.delegate;
    fixture.delegate.context_byte_count = sizeof(fixture.delegate);
    failed |= test_expect_delegated_validation_failure(
        "delegate context overlaps its descriptor",
        ROME2_GUEST_BAD_ARGUMENT, &fixture, &fixture.view, &fixture.effects,
        &fixture.delegate, &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    fixture.delegate.context = &fixture.return_receiver;
    fixture.delegate.context_byte_count = sizeof(fixture.return_receiver);
    failed |= test_expect_delegated_validation_failure(
        "delegate context overlaps receiver output",
        ROME2_GUEST_BAD_ARGUMENT, &fixture, &fixture.view, &fixture.effects,
        &fixture.delegate, &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    fixture.delegate.context = &fixture.view;
    fixture.delegate.context_byte_count = sizeof(fixture.view);
    failed |= test_expect_delegated_validation_failure(
        "delegate context overlaps state descriptor",
        ROME2_GUEST_BAD_ARGUMENT, &fixture, &fixture.view, &fixture.effects,
        &fixture.delegate, &fixture.return_receiver);

    TEST_INIT_DELEGATED_FIXTURE();
    (void)memset(&raw_delegate_storage, 0, sizeof(raw_delegate_storage));
    (void)memcpy(
        raw_delegate_storage.bytes + 1U,
        &fixture.delegate,
        sizeof(fixture.delegate));
    (void)memcpy(
        raw_delegate_snapshot,
        raw_delegate_storage.bytes,
        sizeof(raw_delegate_snapshot));
    misaligned_delegate =
        (rome2_100df270_suffix_100f2750_delegate *)(void *)
            (raw_delegate_storage.bytes + 1U);
    failed |= test_expect_delegated_validation_failure(
        "misaligned delegate descriptor", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, &fixture.effects, misaligned_delegate,
        &fixture.return_receiver);
    failed |= test_expect(
        memcmp(
            raw_delegate_storage.bytes,
            raw_delegate_snapshot,
            sizeof(raw_delegate_snapshot)) == 0,
        "misaligned delegate descriptor",
        "rejected delegate storage was mutated");

#undef TEST_INIT_DELEGATED_FIXTURE
    return failed;
}

int main(void)
{
    int failed = 0;

    failed |= test_success_routes_are_exact();
    failed |= test_effects_snapshot_is_complete();
    failed |= test_required_objects_and_guest_values_fail_closed();
    failed |= test_result_cells_and_view_ranges_fail_closed();
    failed |= test_aliases_and_alignment_fail_closed();
    failed |= test_delegated_success_order_and_snapshot();
    failed |= test_delegated_failure_is_exact_committed_prefix();
    failed |= test_delegated_boundary_failures_are_pre_effect();
    if (failed != 0) {
        return 1;
    }
    (void)puts("100df270 suffix transcript runtime: 76/76 cases passed");
    return 0;
}

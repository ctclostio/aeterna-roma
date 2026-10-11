#include "ported_100df270_platform_prefix_transcript.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_MEMORY_BYTES UINT32_C(0x900)
#define TEST_GUEST_BASE UINT32_C(0x24000000)
#define TEST_RECEIVER_OFFSET UINT32_C(0)
#define TEST_PACKET_OFFSET UINT32_C(0x840)
#define TEST_RETURN_SENTINEL UINT32_C(0xa5a55a5a)
#define TEST_MAX_STEPS UINT32_C(10)
#define TEST_EXPECTED_CASES UINT32_C(36)

/* Keep the oracle independent of implementation-local helper spellings. */
_Static_assert(
    ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT == UINT32_C(7),
    "the normal prefix route must remain seven steps");
_Static_assert(
    ROME2_PORT_100DF270_PREFIX_DUPLICATE_STEP_COUNT == TEST_MAX_STEPS,
    "the duplicate-instance route must remain ten steps");
_Static_assert(
    ROME2_PORT_100DF270_PREFIX_RECEIVER_BYTES == UINT32_C(0x80c),
    "the exact prefix receiver span changed");
_Static_assert(
    ROME2_PORT_100DF270_PREFIX_PACKET_BYTES == UINT32_C(0x2d),
    "the exact prefix packet span changed");
_Static_assert(
    ROME2_PORT_100DF270_PREFIX_INITIAL_VTABLE == UINT32_C(0x1173f208),
    "the initial vtable identity changed");
_Static_assert(
    ROME2_PORT_100DF270_PREFIX_RESOURCE_TITLE == UINT32_C(0x6d),
    "the title resource identity changed");
_Static_assert(
    ROME2_PORT_100DF270_PREFIX_RESOURCE_NAME == UINT32_C(0x67),
    "the name resource identity changed");
_Static_assert(
    ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY == UINT32_C(0x200),
    "the resource/local-buffer capacity changed");
_Static_assert(
    ROME2_PORT_100DF270_PREFIX_ERROR_ALREADY_EXISTS == UINT32_C(0xb7),
    "the duplicate-instance error changed");
_Static_assert(
    ROME2_PORT_100DF270_PREFIX_SPI_GETMOUSETRAILS == UINT32_C(0x5e) &&
        ROME2_PORT_100DF270_PREFIX_SPI_SETMOUSETRAILS == UINT32_C(0x5d),
    "the mouse-trails actions changed");
_Static_assert(
    _Alignof(rome2_100df270_prefix_effects) > 1U,
    "the effects-misalignment oracle requires natural alignment");

typedef union test_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_MEMORY_BYTES];
} test_memory;

typedef union test_effects_storage {
    rome2_100df270_prefix_effects alignment;
    uint8_t bytes[
        sizeof(rome2_100df270_prefix_effects) +
        _Alignof(rome2_100df270_prefix_effects)];
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

typedef struct test_trace {
    rome2_100df270_prefix_step expected[TEST_MAX_STEPS];
    rome2_100df270_prefix_step observed[TEST_MAX_STEPS];
    test_memory pre_handle_memory;
    test_memory final_memory;
    test_memory *memory;
    rome2_100df270_prefix_effects *caller_effects;
    rome2_guest_addr32 *return_receiver;
    uint32_t expected_count;
    uint32_t call_count;
    uint32_t failure_count;
    uint32_t unexpected_call_count;
    int mutate_effects_after_first;
} test_trace;

typedef struct test_fixture {
    test_memory memory;
    rome2_guest_write_view view;
    rome2_100df270_prefix_effects effects;
    test_trace trace;
    rome2_guest_addr32 return_receiver;
    uint32_t receiver_offset;
    uint32_t packet_offset;
} test_fixture;

static uint32_t test_case_count;

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

static int test_values_equal(
    const rome2_100df270_prefix_value *left,
    const rome2_100df270_prefix_value *right)
{
    return left->kind == right->kind && left->value == right->value;
}

static int test_steps_equal(
    const rome2_100df270_prefix_step *left,
    const rome2_100df270_prefix_step *right)
{
    return
        left->kind == right->kind &&
        left->argument_count == right->argument_count &&
        test_values_equal(&left->argument0, &right->argument0) &&
        test_values_equal(&left->argument1, &right->argument1) &&
        test_values_equal(&left->argument2, &right->argument2) &&
        test_values_equal(&left->argument3, &right->argument3) &&
        left->result_count == right->result_count &&
        test_values_equal(&left->result0, &right->result0);
}

static rome2_100df270_prefix_value test_value(
    rome2_100df270_prefix_value_kind kind,
    uint32_t value)
{
    rome2_100df270_prefix_value result;

    result.kind = kind;
    result.value = value;
    return result;
}

static void test_zero_step(
    rome2_100df270_prefix_step *step,
    rome2_100df270_prefix_step_kind kind)
{
    (void)memset(step, 0, sizeof(*step));
    step->kind = kind;
}

static void test_set_arguments(
    rome2_100df270_prefix_step *step,
    uint32_t count,
    rome2_100df270_prefix_value argument0,
    rome2_100df270_prefix_value argument1,
    rome2_100df270_prefix_value argument2,
    rome2_100df270_prefix_value argument3)
{
    step->argument_count = count;
    step->argument0 = argument0;
    step->argument1 = argument1;
    step->argument2 = argument2;
    step->argument3 = argument3;
}

static void test_build_expected(
    test_trace *trace,
    uint32_t receiver,
    uint32_t instance,
    uint32_t created_mutex,
    uint32_t last_error,
    uint8_t allow_duplicate)
{
    rome2_100df270_prefix_value none = test_value(
        ROME2_100DF270_PREFIX_VALUE_NONE, UINT32_C(0));
    rome2_100df270_prefix_value zero = test_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0));
    rome2_100df270_prefix_value local = test_value(
        ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER, UINT32_C(1));
    rome2_100df270_prefix_value capacity = test_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x200));
    rome2_100df270_prefix_value name = test_value(
        ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY,
        receiver + UINT32_C(0x08));
    uint32_t index = UINT32_C(0);

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_PREFIX_STEP_LOAD_TITLE);
    test_set_arguments(
        &trace->expected[index], UINT32_C(4),
        test_value(ROME2_100DF270_PREFIX_VALUE_OPAQUE32, instance),
        test_value(ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x6d)),
        test_value(
            ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY,
            receiver + UINT32_C(0x408)),
        capacity);
    index += UINT32_C(1);

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_PREFIX_STEP_LOAD_NAME);
    test_set_arguments(
        &trace->expected[index], UINT32_C(4),
        test_value(ROME2_100DF270_PREFIX_VALUE_OPAQUE32, instance),
        test_value(ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x67)),
        name,
        capacity);
    index += UINT32_C(1);

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_PREFIX_STEP_FORMAT_MUTEX_NAME);
    test_set_arguments(
        &trace->expected[index], UINT32_C(4),
        local,
        capacity,
        test_value(
            ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
            UINT32_C(0x1173f460)),
        name);
    index += UINT32_C(1);

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_PREFIX_STEP_CREATE_MUTEX);
    test_set_arguments(
        &trace->expected[index], UINT32_C(3),
        zero,
        test_value(ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(1)),
        local,
        none);
    trace->expected[index].result_count = UINT32_C(1);
    trace->expected[index].result0 = test_value(
        ROME2_100DF270_PREFIX_VALUE_OPAQUE32, created_mutex);
    index += UINT32_C(1);

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_PREFIX_STEP_GET_LAST_ERROR);
    trace->expected[index].result_count = UINT32_C(1);
    trace->expected[index].result0 = test_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, last_error);
    index += UINT32_C(1);

    if (last_error == UINT32_C(0xb7) && allow_duplicate == UINT8_C(0)) {
        test_zero_step(
            &trace->expected[index],
            ROME2_100DF270_PREFIX_STEP_FORMAT_DUPLICATE_MESSAGE);
        test_set_arguments(
            &trace->expected[index], UINT32_C(4),
            local,
            capacity,
            test_value(
                ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
                UINT32_C(0x1173f4a0)),
            name);
        index += UINT32_C(1);

        test_zero_step(
            &trace->expected[index],
            ROME2_100DF270_PREFIX_STEP_SHOW_DUPLICATE_MESSAGE);
        test_set_arguments(
            &trace->expected[index], UINT32_C(4),
            zero,
            local,
            test_value(
                ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
                UINT32_C(0x1173f440)),
            test_value(
                ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x10)));
        index += UINT32_C(1);

        test_zero_step(
            &trace->expected[index],
            ROME2_100DF270_PREFIX_STEP_TERMINATE_PROCESS);
        index += UINT32_C(1);
    }

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_PREFIX_STEP_GET_MOUSE_TRAILS);
    test_set_arguments(
        &trace->expected[index], UINT32_C(4),
        test_value(
            ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x5e)),
        zero,
        test_value(
            ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
            UINT32_C(0x119f3854)),
        zero);
    index += UINT32_C(1);

    test_zero_step(
        &trace->expected[index],
        ROME2_100DF270_PREFIX_STEP_SET_MOUSE_TRAILS);
    test_set_arguments(
        &trace->expected[index], UINT32_C(4),
        test_value(
            ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x5d)),
        zero,
        zero,
        zero);
    trace->expected_count = index + UINT32_C(1);
}

static void test_evil_emit(
    void *opaque,
    rome2_100df270_prefix_step step)
{
    uint32_t *unexpected_call_count = (uint32_t *)opaque;

    (void)step;
    *unexpected_call_count += UINT32_C(1);
}

static void test_emit(
    void *opaque,
    rome2_100df270_prefix_step step)
{
    test_trace *trace = (test_trace *)opaque;
    uint32_t index = trace->call_count;
    int handle_must_be_committed =
        step.kind >= ROME2_100DF270_PREFIX_STEP_GET_LAST_ERROR;
    const test_memory *expected_memory =
        handle_must_be_committed != 0 ?
            &trace->final_memory : &trace->pre_handle_memory;

    if (trace->return_receiver == NULL ||
        trace->return_receiver->value != TEST_RETURN_SENTINEL) {
        trace->failure_count += UINT32_C(1);
    }
    if (trace->memory == NULL ||
        memcmp(
            trace->memory->bytes,
            expected_memory->bytes,
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
        trace->caller_effects->created_mutex = UINT32_C(0x01020304);
        trace->caller_effects->last_error = UINT32_C(0);
    }
}

static void test_init_fixture(
    test_fixture *fixture,
    uint32_t guest_base,
    uint32_t receiver_offset,
    uint32_t packet_offset,
    uint32_t instance,
    uint32_t created_mutex,
    uint32_t last_error,
    uint8_t allow_duplicate,
    int mutate_effects)
{
    uint32_t receiver = guest_base + receiver_offset;

    (void)memset(fixture, 0, sizeof(*fixture));
    (void)memset(fixture->memory.bytes, 0xa7, sizeof(fixture->memory.bytes));
    test_write_u32_le(
        fixture->memory.bytes + packet_offset,
        instance);
    fixture->memory.bytes[
        packet_offset +
        ROME2_PORT_100DF270_PREFIX_ALLOW_DUPLICATE_OFFSET] = allow_duplicate;

    fixture->view.host_base = fixture->memory.bytes;
    fixture->view.guest_base = guest_base;
    fixture->view.byte_count = sizeof(fixture->memory.bytes);
    fixture->effects.emit_step = test_emit;
    fixture->effects.context = &fixture->trace;
    fixture->effects.created_mutex = created_mutex;
    fixture->effects.last_error = last_error;
    fixture->return_receiver.value = TEST_RETURN_SENTINEL;
    fixture->receiver_offset = receiver_offset;
    fixture->packet_offset = packet_offset;

    fixture->trace.pre_handle_memory = fixture->memory;
    test_write_u32_le(
        fixture->trace.pre_handle_memory.bytes + receiver_offset +
            ROME2_PORT_100DF270_PREFIX_INSTANCE_OFFSET,
        instance);
    test_write_u32_le(
        fixture->trace.pre_handle_memory.bytes + receiver_offset,
        ROME2_PORT_100DF270_PREFIX_INITIAL_VTABLE);
    fixture->trace.final_memory = fixture->trace.pre_handle_memory;
    test_write_u32_le(
        fixture->trace.final_memory.bytes + receiver_offset +
            ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET,
        created_mutex);
    fixture->trace.memory = &fixture->memory;
    fixture->trace.caller_effects = &fixture->effects;
    fixture->trace.return_receiver = &fixture->return_receiver;
    fixture->trace.mutate_effects_after_first = mutate_effects;
    test_build_expected(
        &fixture->trace,
        receiver,
        instance,
        created_mutex,
        last_error,
        allow_duplicate);
}

static int test_expect(int condition, const char *case_name, const char *detail)
{
    if (condition) {
        return 0;
    }
    (void)fprintf(stderr, "100df270 prefix runtime: %s: %s\n",
        case_name, detail);
    return 1;
}

static int test_run_success(
    const char *case_name,
    uint32_t guest_base,
    uint32_t receiver_offset,
    uint32_t packet_offset,
    uint32_t instance,
    uint32_t created_mutex,
    uint32_t last_error,
    uint8_t allow_duplicate,
    int mutate_effects)
{
    test_fixture fixture;
    rome2_100df270_prefix_effects saved_effects;
    rome2_guest_write_view saved_view;
    rome2_guest_status status;
    uint32_t receiver = guest_base + receiver_offset;
    uint32_t index;
    int failed = 0;

    test_case_count += UINT32_C(1);
    test_init_fixture(
        &fixture,
        guest_base,
        receiver_offset,
        packet_offset,
        instance,
        created_mutex,
        last_error,
        allow_duplicate,
        mutate_effects);
    saved_effects = fixture.effects;
    saved_view = fixture.view;
    status = rome2_port_100df270_run_platform_prefix_transcript(
        &fixture.view,
        (rome2_guest_addr32){receiver},
        (rome2_guest_addr32){guest_base + packet_offset},
        &fixture.effects,
        &fixture.return_receiver);

    failed |= test_expect(status == ROME2_GUEST_OK,
        case_name, "status was not OK");
    failed |= test_expect(
        fixture.trace.call_count == fixture.trace.expected_count &&
        fixture.trace.failure_count == UINT32_C(0) &&
        fixture.trace.unexpected_call_count == UINT32_C(0),
        case_name, "step order, typed fields, zero fields, or commit timing changed");
    failed |= test_expect(
        fixture.return_receiver.value == receiver,
        case_name, "receiver output did not commit after the final callback");
    failed |= test_expect(
        memcmp(
            fixture.memory.bytes,
            fixture.trace.final_memory.bytes,
            sizeof(fixture.memory.bytes)) == 0,
        case_name, "bytes outside the exact +0/+4/+0x808 cells changed");
    failed |= test_expect(
        memcmp(&fixture.view, &saved_view, sizeof(saved_view)) == 0,
        case_name, "state-view descriptor was mutated");
    failed |= test_expect(
        test_read_u32_le(
            fixture.memory.bytes + packet_offset) == instance &&
        fixture.memory.bytes[
            packet_offset +
            ROME2_PORT_100DF270_PREFIX_ALLOW_DUPLICATE_OFFSET] ==
            allow_duplicate,
        case_name, "the complete input packet was not preserved");

    if (mutate_effects == 0) {
        failed |= test_expect(
            memcmp(&fixture.effects, &saved_effects, sizeof(saved_effects)) == 0,
            case_name, "the adapter mutated its caller effects descriptor");
    } else {
        failed |= test_expect(
            fixture.effects.emit_step == test_evil_emit &&
            fixture.effects.context == &fixture.trace.unexpected_call_count &&
            fixture.effects.created_mutex == UINT32_C(0x01020304) &&
            fixture.effects.last_error == UINT32_C(0),
            case_name, "first-callback mutation of caller effects was lost");
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

static int test_success_routes_and_boundaries(void)
{
    int failed = 0;

    failed |= test_run_success(
        "normal route is exactly seven typed steps",
        TEST_GUEST_BASE, TEST_RECEIVER_OFFSET, TEST_PACKET_OFFSET,
        UINT32_C(0x11223344), UINT32_C(0x55667788),
        UINT32_C(0), UINT8_C(1), 0);
    failed |= test_run_success(
        "duplicate route is exactly ten typed steps with SPI fallthrough",
        TEST_GUEST_BASE, TEST_RECEIVER_OFFSET, TEST_PACKET_OFFSET,
        UINT32_C(0x89abcdef), UINT32_C(0x10203040),
        UINT32_C(0xb7), UINT8_C(0), 0);
    failed |= test_run_success(
        "already-exists plus nonzero packet byte bypasses duplicate route",
        TEST_GUEST_BASE, TEST_RECEIVER_OFFSET, TEST_PACKET_OFFSET,
        UINT32_C(0x12345678), UINT32_C(0x87654321),
        UINT32_C(0xb7), UINT8_C(1), 0);
    failed |= test_run_success(
        "different error plus zero packet byte bypasses duplicate route",
        TEST_GUEST_BASE, TEST_RECEIVER_OFFSET, TEST_PACKET_OFFSET,
        UINT32_C(0x01010101), UINT32_C(0x02020202),
        UINT32_C(0xb6), UINT8_C(0), 0);
    failed |= test_run_success(
        "effects table and branch inputs are snapshotted pre-callback",
        TEST_GUEST_BASE, TEST_RECEIVER_OFFSET, TEST_PACKET_OFFSET,
        UINT32_C(0x13572468), UINT32_C(0xcafebabe),
        UINT32_C(0xb7), UINT8_C(0), 1);
    failed |= test_run_success(
        "zero opaque instance and mutex values remain admissible",
        TEST_GUEST_BASE, TEST_RECEIVER_OFFSET, TEST_PACKET_OFFSET,
        UINT32_C(0), UINT32_C(0),
        UINT32_C(0), UINT8_C(1), 0);
    failed |= test_run_success(
        "all-ones opaque instance and mutex values remain admissible",
        TEST_GUEST_BASE, TEST_RECEIVER_OFFSET, TEST_PACKET_OFFSET,
        UINT32_MAX, UINT32_MAX,
        UINT32_C(0xffffffff), UINT8_C(1), 0);
    failed |= test_run_success(
        "unaligned guest receiver and packet spans are bytewise safe",
        TEST_GUEST_BASE, UINT32_C(3), UINT32_C(0x843),
        UINT32_C(0x0badf00d), UINT32_C(0xdecafbad),
        UINT32_C(0), UINT8_C(1), 0);
    failed |= test_run_success(
        "view and packet may end exactly at the guest32 address-space end",
        UINT32_C(0xfffff700), UINT32_C(0), UINT32_C(0x8d3),
        UINT32_C(0xabcdef01), UINT32_C(0x76543210),
        UINT32_C(0), UINT8_C(1), 0);
    return failed;
}

static int test_expect_precommit_failure(
    const char *case_name,
    rome2_guest_status expected_status,
    test_fixture *fixture,
    const rome2_guest_write_view *view,
    uint32_t receiver,
    uint32_t packet,
    const rome2_100df270_prefix_effects *effects,
    rome2_guest_addr32 *return_receiver,
    int output_is_observable)
{
    test_memory saved_memory = fixture->memory;
    rome2_100df270_prefix_effects saved_effects = fixture->effects;
    rome2_guest_status status;
    int failed = 0;

    test_case_count += UINT32_C(1);
    status = rome2_port_100df270_run_platform_prefix_transcript(
        view,
        (rome2_guest_addr32){receiver},
        (rome2_guest_addr32){packet},
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
        memcmp(
            fixture->memory.bytes,
            saved_memory.bytes,
            sizeof(saved_memory.bytes)) == 0,
        case_name, "validation failure mutated guest bytes");
    failed |= test_expect(
        memcmp(&fixture->effects, &saved_effects, sizeof(saved_effects)) == 0,
        case_name, "validation failure mutated caller effects");
    if (output_is_observable != 0) {
        failed |= test_expect(
            fixture->return_receiver.value == TEST_RETURN_SENTINEL,
            case_name, "validation failure changed receiver output");
    }
    return failed;
}

static void test_init_default_fixture(test_fixture *fixture)
{
    test_init_fixture(
        fixture,
        TEST_GUEST_BASE,
        TEST_RECEIVER_OFFSET,
        TEST_PACKET_OFFSET,
        UINT32_C(0x11223344),
        UINT32_C(0x55667788),
        UINT32_C(0),
        UINT8_C(1),
        0);
}

static int test_required_objects_fail_closed(void)
{
    test_fixture fixture;
    int failed = 0;

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "null state view", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        NULL, TEST_GUEST_BASE, TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "null effects", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        NULL, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "null receiver output", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, NULL, 0);

    test_init_default_fixture(&fixture);
    fixture.effects.emit_step = NULL;
    failed |= test_expect_precommit_failure(
        "missing emit callback", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    fixture.effects.context = NULL;
    failed |= test_expect_precommit_failure(
        "missing callback context", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    fixture.view.host_base = NULL;
    failed |= test_expect_precommit_failure(
        "null state backing", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "null receiver identity", ROME2_GUEST_NULL_ADDRESS, &fixture,
        &fixture.view, UINT32_C(0),
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "null packet identity", ROME2_GUEST_NULL_ADDRESS, &fixture,
        &fixture.view, TEST_GUEST_BASE, UINT32_C(0),
        &fixture.effects, &fixture.return_receiver, 1);
    return failed;
}

static int test_ranges_fail_closed(void)
{
    test_fixture fixture;
    int failed = 0;

    test_init_default_fixture(&fixture);
    fixture.view.guest_base = UINT32_C(0xffffff00);
    fixture.view.byte_count = UINT64_C(0x200);
    failed |= test_expect_precommit_failure(
        "guest view interval wraps", ROME2_GUEST_RANGE_OVERFLOW, &fixture,
        &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    fixture.view.guest_base = UINT32_C(0);
    fixture.view.byte_count = UINT64_C(0x100000001);
    failed |= test_expect_precommit_failure(
        "guest view is larger than guest32", ROME2_GUEST_RANGE_OVERFLOW,
        &fixture, &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    fixture.view.host_base =
        (uint8_t *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)1U);
    fixture.view.byte_count = UINT64_C(4);
    failed |= test_expect_precommit_failure(
        "native host interval wraps", ROME2_GUEST_RANGE_OVERFLOW, &fixture,
        &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "receiver lies below view", ROME2_GUEST_OUT_OF_RANGE, &fixture,
        &fixture.view, TEST_GUEST_BASE - UINT32_C(1),
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "packet lies below view", ROME2_GUEST_OUT_OF_RANGE, &fixture,
        &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE - UINT32_C(1),
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "receiver span is truncated", ROME2_GUEST_OUT_OF_RANGE, &fixture,
        &fixture.view, TEST_GUEST_BASE + UINT32_C(0x100),
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "packet span is truncated", ROME2_GUEST_OUT_OF_RANGE, &fixture,
        &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_MEMORY_BYTES - UINT32_C(0x2c),
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "receiver span overflows guest32", ROME2_GUEST_RANGE_OVERFLOW,
        &fixture, &fixture.view, UINT32_MAX,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "packet span overflows guest32", ROME2_GUEST_RANGE_OVERFLOW,
        &fixture, &fixture.view, TEST_GUEST_BASE, UINT32_MAX,
        &fixture.effects, &fixture.return_receiver, 1);
    return failed;
}

static int test_aliases_and_alignment_fail_closed(void)
{
    test_fixture fixture;
    test_effects_storage raw_effects;
    test_view_storage raw_view;
    test_output_storage raw_output;
    rome2_100df270_prefix_effects *misaligned_effects;
    rome2_guest_write_view *misaligned_view;
    rome2_guest_addr32 *misaligned_output;
    uint8_t saved_raw_effects[sizeof(raw_effects.bytes)];
    uint8_t saved_raw_view[sizeof(raw_view.bytes)];
    uint8_t saved_raw_output[sizeof(raw_output.bytes)];
    int failed = 0;

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "receiver and packet spans alias logically and physically",
        ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + UINT32_C(8),
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "effects and output controls overlap", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects,
        (rome2_guest_addr32 *)(void *)&fixture.effects, 0);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "view and effects controls overlap", ROME2_GUEST_BAD_ARGUMENT,
        &fixture,
        (const rome2_guest_write_view *)(const void *)&fixture.effects,
        TEST_GUEST_BASE, TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    failed |= test_expect_precommit_failure(
        "view and output controls overlap", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects,
        (rome2_guest_addr32 *)(void *)&fixture.view, 0);

    test_init_default_fixture(&fixture);
    fixture.view.host_base = (uint8_t *)(void *)&fixture.effects;
    fixture.view.byte_count = sizeof(fixture.effects);
    failed |= test_expect_precommit_failure(
        "state backing overlaps effects control", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    fixture.view.host_base = (uint8_t *)(void *)&fixture.return_receiver;
    fixture.view.byte_count = sizeof(fixture.return_receiver);
    failed |= test_expect_precommit_failure(
        "state backing overlaps output control", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    fixture.view.host_base = (uint8_t *)(void *)&fixture.view;
    fixture.view.byte_count = sizeof(fixture.view);
    failed |= test_expect_precommit_failure(
        "state backing overlaps its view control", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);

    test_init_default_fixture(&fixture);
    (void)memset(&raw_effects, 0, sizeof(raw_effects));
    (void)memcpy(
        raw_effects.bytes + 1U,
        &fixture.effects,
        sizeof(fixture.effects));
    (void)memcpy(
        saved_raw_effects,
        raw_effects.bytes,
        sizeof(saved_raw_effects));
    misaligned_effects =
        (rome2_100df270_prefix_effects *)(void *)(raw_effects.bytes + 1U);
    failed |= test_expect_precommit_failure(
        "misaligned effects control", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        misaligned_effects, &fixture.return_receiver, 1);
    failed |= test_expect(
        memcmp(
            raw_effects.bytes,
            saved_raw_effects,
            sizeof(saved_raw_effects)) == 0,
        "misaligned effects control", "rejected storage was mutated");

    test_init_default_fixture(&fixture);
    (void)memset(&raw_view, 0, sizeof(raw_view));
    (void)memcpy(raw_view.bytes + 1U, &fixture.view, sizeof(fixture.view));
    (void)memcpy(saved_raw_view, raw_view.bytes, sizeof(saved_raw_view));
    misaligned_view =
        (rome2_guest_write_view *)(void *)(raw_view.bytes + 1U);
    failed |= test_expect_precommit_failure(
        "misaligned view control", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, misaligned_view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, &fixture.return_receiver, 1);
    failed |= test_expect(
        memcmp(raw_view.bytes, saved_raw_view, sizeof(saved_raw_view)) == 0,
        "misaligned view control", "rejected storage was mutated");

    test_init_default_fixture(&fixture);
    (void)memset(&raw_output, 0, sizeof(raw_output));
    test_write_u32_le(raw_output.bytes + 1U, TEST_RETURN_SENTINEL);
    (void)memcpy(saved_raw_output, raw_output.bytes, sizeof(saved_raw_output));
    misaligned_output =
        (rome2_guest_addr32 *)(void *)(raw_output.bytes + 1U);
    failed |= test_expect_precommit_failure(
        "misaligned output control", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.view, TEST_GUEST_BASE,
        TEST_GUEST_BASE + TEST_PACKET_OFFSET,
        &fixture.effects, misaligned_output, 0);
    failed |= test_expect(
        memcmp(
            raw_output.bytes,
            saved_raw_output,
            sizeof(saved_raw_output)) == 0,
        "misaligned output control", "rejected storage was mutated");
    return failed;
}

int main(void)
{
    int failed = 0;

    failed |= test_success_routes_and_boundaries();
    failed |= test_required_objects_fail_closed();
    failed |= test_ranges_fail_closed();
    failed |= test_aliases_and_alignment_fail_closed();
    failed |= test_expect(
        test_case_count == TEST_EXPECTED_CASES,
        "runtime case accounting",
        "the declared independent case count changed");
    if (failed != 0) {
        return 1;
    }
    (void)printf(
        "100df270 platform-prefix transcript runtime: %lu/%lu cases passed\n",
        (unsigned long)test_case_count,
        (unsigned long)TEST_EXPECTED_CASES);
    return 0;
}

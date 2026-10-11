#include "ported_100ed3c0_empty_preloop.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_FRAME_BYTES UINT32_C(0x90c)
#define TEST_TEXT_BYTES UINT32_C(4)
#define TEST_SELECTOR_BYTES UINT32_C(16)
#define TEST_FRAME_BASE UINT32_C(0x22000000)
#define TEST_TEXT_BASE UINT32_C(0x33000000)
#define TEST_SELECTOR_BASE UINT32_C(0x44000000)
#define TEST_FIRST_SELECTOR_OFFSET UINT32_C(0)
#define TEST_SECOND_SELECTOR_OFFSET UINT32_C(8)
#define TEST_ARGUMENT1 UINT32_C(0x89abcdef)
#define TEST_RESULT_SENTINEL UINT32_C(0xa55a5aa5)
#define TEST_PARENT_STEPS UINT32_C(9)
#define TEST_PREFIX_STEPS UINT32_C(10)
#define TEST_SUFFIX_STEPS UINT32_C(11)
#define TEST_ANY_FAILURE (-1)
#define TEST_EXPECTED_CASES UINT32_C(50)

/* These assertions keep this oracle tied to the authenticated parent slice. */
_Static_assert(
    ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES == TEST_FRAME_BYTES,
    "the authenticated parent frame size changed");
_Static_assert(
    ROME2_PORT_100ED3C0_PRELOOP_STEP_COUNT == TEST_PARENT_STEPS,
    "the authenticated parent operation count changed");
_Static_assert(
    ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET == UINT32_C(0x64),
    "the child receiver offset changed");
_Static_assert(
    ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET == UINT32_C(0x34),
    "the child packet offset changed");
_Static_assert(
    ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET == UINT32_C(0x28),
    "the child argument offset changed");
_Static_assert(
    ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC == UINT32_C(0x100ed471),
    "the hard stop before the excluded loop changed");
_Static_assert(
    ROME2_PORT_100DF270_OBJECT_BYTES +
        ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET == TEST_FRAME_BYTES,
    "the child receiver must end exactly at the parent frame boundary");
_Static_assert(
    _Alignof(rome2_100ed3c0_preloop_effects) > 1U &&
        _Alignof(rome2_100ed3c0_preloop_result) > 1U,
    "the misalignment tests require naturally aligned controls");

typedef union test_frame_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_FRAME_BYTES];
} test_frame_memory;

typedef union test_text_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_TEXT_BYTES];
} test_text_memory;

typedef union test_selector_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_SELECTOR_BYTES];
} test_selector_memory;

typedef union test_effects_storage {
    rome2_100ed3c0_preloop_effects alignment;
    uint8_t bytes[
        sizeof(rome2_100ed3c0_preloop_effects) +
        _Alignof(rome2_100ed3c0_preloop_effects)];
} test_effects_storage;

typedef union test_write_view_storage {
    rome2_guest_write_view alignment;
    uint8_t bytes[
        sizeof(rome2_guest_write_view) +
        _Alignof(rome2_guest_write_view)];
} test_write_view_storage;

typedef union test_result_storage {
    rome2_100ed3c0_preloop_result alignment;
    uint8_t bytes[
        sizeof(rome2_100ed3c0_preloop_result) +
        _Alignof(rome2_100ed3c0_preloop_result)];
} test_result_storage;

typedef struct test_trace {
    rome2_100ed3c0_preloop_step parent_expected[TEST_PARENT_STEPS];
    rome2_100ed3c0_preloop_step parent_observed[TEST_PARENT_STEPS];
    rome2_100df270_prefix_step prefix_expected[TEST_PREFIX_STEPS];
    rome2_100df270_prefix_step prefix_observed[TEST_PREFIX_STEPS];
    rome2_100df270_suffix_step suffix_expected[TEST_SUFFIX_STEPS];
    rome2_100df270_suffix_step suffix_observed[TEST_SUFFIX_STEPS];
    test_selector_memory selector_initial;
    test_selector_memory selector_final;
    test_selector_memory *selector;
    rome2_100ed3c0_preloop_effects *caller_effects;
    rome2_100ed3c0_preloop_result *result;
    uint32_t parent_expected_count;
    uint32_t prefix_expected_count;
    uint32_t suffix_expected_count;
    uint32_t parent_count;
    uint32_t prefix_count;
    uint32_t suffix_count;
    uint32_t failure_count;
    uint32_t unexpected_count;
    int mutate_effects_after_first;
} test_trace;

typedef struct test_fixture {
    test_frame_memory frame;
    test_text_memory text;
    test_selector_memory selector;
    rome2_guest_write_view frame_view;
    rome2_guest_read_view text_view;
    rome2_guest_write_view selector_view;
    rome2_100ed3c0_preloop_effects effects;
    rome2_100ed3c0_preloop_result result;
    test_trace trace;
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

static void test_write_triplet(uint8_t *bytes)
{
    test_write_u32_le(bytes, UINT32_C(0));
    test_write_u32_le(bytes + 4, UINT32_C(0));
    test_write_u32_le(bytes + 8, UINT32_C(0x11af4090));
}

static int test_parent_values_equal(
    const rome2_100ed3c0_preloop_value *left,
    const rome2_100ed3c0_preloop_value *right)
{
    return left->kind == right->kind && left->value == right->value;
}

static int test_parent_steps_equal(
    const rome2_100ed3c0_preloop_step *left,
    const rome2_100ed3c0_preloop_step *right)
{
    return
        left->kind == right->kind &&
        left->argument_count == right->argument_count &&
        test_parent_values_equal(&left->argument0, &right->argument0) &&
        test_parent_values_equal(&left->argument1, &right->argument1) &&
        test_parent_values_equal(&left->argument2, &right->argument2) &&
        left->result_count == right->result_count &&
        test_parent_values_equal(&left->result0, &right->result0);
}

static int test_prefix_values_equal(
    const rome2_100df270_prefix_value *left,
    const rome2_100df270_prefix_value *right)
{
    return left->kind == right->kind && left->value == right->value;
}

static int test_prefix_steps_equal(
    const rome2_100df270_prefix_step *left,
    const rome2_100df270_prefix_step *right)
{
    return
        left->kind == right->kind &&
        left->argument_count == right->argument_count &&
        test_prefix_values_equal(&left->argument0, &right->argument0) &&
        test_prefix_values_equal(&left->argument1, &right->argument1) &&
        test_prefix_values_equal(&left->argument2, &right->argument2) &&
        test_prefix_values_equal(&left->argument3, &right->argument3) &&
        left->result_count == right->result_count &&
        test_prefix_values_equal(&left->result0, &right->result0);
}

static int test_suffix_steps_equal(
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

static rome2_100ed3c0_preloop_value test_parent_value(
    rome2_100ed3c0_preloop_value_kind kind,
    uint32_t value)
{
    rome2_100ed3c0_preloop_value result;

    result.kind = kind;
    result.value = value;
    return result;
}

static void test_clear_parent_step(
    rome2_100ed3c0_preloop_step *step,
    rome2_100ed3c0_preloop_step_kind kind)
{
    (void)memset(step, 0, sizeof(*step));
    step->kind = kind;
}

static rome2_100df270_prefix_value test_prefix_value(
    rome2_100df270_prefix_value_kind kind,
    uint32_t value)
{
    rome2_100df270_prefix_value result;

    result.kind = kind;
    result.value = value;
    return result;
}

static void test_clear_prefix_step(
    rome2_100df270_prefix_step *step,
    rome2_100df270_prefix_step_kind kind)
{
    (void)memset(step, 0, sizeof(*step));
    step->kind = kind;
}

static void test_set_prefix_arguments(
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

static void test_clear_suffix_step(
    rome2_100df270_suffix_step *step,
    rome2_100df270_suffix_step_kind kind)
{
    (void)memset(step, 0, sizeof(*step));
    step->kind = kind;
}

static void test_set_suffix_arguments(
    rome2_100df270_suffix_step *step,
    uint32_t count,
    uint32_t argument0,
    uint32_t argument1)
{
    step->argument_count = count;
    step->argument0 = argument0;
    step->argument1 = argument1;
}

static void test_set_suffix_query(
    rome2_100df270_suffix_step *step,
    rome2_100df270_suffix_step_kind kind,
    uint32_t owner,
    uint32_t result,
    uint32_t observed)
{
    test_clear_suffix_step(step, kind);
    test_set_suffix_arguments(step, UINT32_C(2), owner, UINT32_C(2));
    step->result_count = UINT32_C(1);
    step->result0 = result;
    step->dispatch_vtable = UINT32_C(0x1173dc18);
    step->dispatch_slot_offset = UINT32_C(0x0c);
    step->observed_value = observed;
}

static void test_build_parent_expected(test_trace *trace, uint32_t argument1)
{
    uint32_t frame = TEST_FRAME_BASE;
    rome2_100ed3c0_preloop_value none = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_NONE, UINT32_C(0));
    uint32_t index = UINT32_C(0);

    (void)memset(trace->parent_expected, 0, sizeof(trace->parent_expected));
    test_clear_parent_step(
        &trace->parent_expected[index],
        ROME2_100ED3C0_PRELOOP_STEP_WRITE_GLOBAL_119F31C8);
    trace->parent_expected[index].argument_count = UINT32_C(2);
    trace->parent_expected[index].argument0 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_ORIGINAL_IDENTITY,
        UINT32_C(0x119f31c8));
    trace->parent_expected[index].argument1 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_SCALAR, UINT32_C(1));
    index += UINT32_C(1);

    test_clear_parent_step(
        &trace->parent_expected[index],
        ROME2_100ED3C0_PRELOOP_STEP_WRITE_GLOBAL_119F31C5);
    trace->parent_expected[index].argument_count = UINT32_C(2);
    trace->parent_expected[index].argument0 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_ORIGINAL_IDENTITY,
        UINT32_C(0x119f31c5));
    trace->parent_expected[index].argument1 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_SCALAR, UINT32_C(1));
    index += UINT32_C(1);

    test_clear_parent_step(
        &trace->parent_expected[index],
        ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET0);
    trace->parent_expected[index].argument_count = UINT32_C(1);
    trace->parent_expected[index].argument0 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY, frame + UINT32_C(0x04));
    index += UINT32_C(1);

    test_clear_parent_step(
        &trace->parent_expected[index],
        ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET1);
    trace->parent_expected[index].argument_count = UINT32_C(1);
    trace->parent_expected[index].argument0 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY, frame + UINT32_C(0x10));
    index += UINT32_C(1);

    test_clear_parent_step(
        &trace->parent_expected[index],
        ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY0);
    trace->parent_expected[index].argument_count = UINT32_C(2);
    trace->parent_expected[index].argument0 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY, frame + UINT32_C(0x3c));
    trace->parent_expected[index].argument1 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY, frame + UINT32_C(0x04));
    index += UINT32_C(1);

    test_clear_parent_step(
        &trace->parent_expected[index],
        ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY1);
    trace->parent_expected[index].argument_count = UINT32_C(2);
    trace->parent_expected[index].argument0 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY, frame + UINT32_C(0x48));
    trace->parent_expected[index].argument1 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY, frame + UINT32_C(0x10));
    index += UINT32_C(1);

    test_clear_parent_step(
        &trace->parent_expected[index],
        ROME2_100ED3C0_PRELOOP_STEP_BUILD_EMPTY_DESCRIPTOR);
    trace->parent_expected[index].argument_count = UINT32_C(2);
    trace->parent_expected[index].argument0 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY, frame + UINT32_C(0x28));
    trace->parent_expected[index].argument1 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_GUEST_IDENTITY, TEST_TEXT_BASE);
    trace->parent_expected[index].result_count = UINT32_C(1);
    trace->parent_expected[index].result0 =
        trace->parent_expected[index].argument0;
    index += UINT32_C(1);

    test_clear_parent_step(
        &trace->parent_expected[index],
        ROME2_100ED3C0_PRELOOP_STEP_RUN_100DF270);
    trace->parent_expected[index].argument_count = UINT32_C(3);
    trace->parent_expected[index].argument0 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY, frame + UINT32_C(0x64));
    trace->parent_expected[index].argument1 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY, frame + UINT32_C(0x34));
    trace->parent_expected[index].argument2 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY, frame + UINT32_C(0x28));
    index += UINT32_C(1);

    test_clear_parent_step(
        &trace->parent_expected[index],
        ROME2_100ED3C0_PRELOOP_STEP_CLEANUP_DESCRIPTOR);
    trace->parent_expected[index].argument_count = UINT32_C(1);
    trace->parent_expected[index].argument0 = test_parent_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY, frame + UINT32_C(0x28));
    index += UINT32_C(1);

    trace->parent_expected_count = index;
    (void)argument1;
    (void)none;
}

static void test_build_prefix_expected(
    test_trace *trace,
    uint32_t argument1,
    uint32_t created_mutex,
    uint32_t last_error)
{
    rome2_100df270_prefix_value none = test_prefix_value(
        ROME2_100DF270_PREFIX_VALUE_NONE, UINT32_C(0));
    rome2_100df270_prefix_value zero = test_prefix_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0));
    rome2_100df270_prefix_value local = test_prefix_value(
        ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER, UINT32_C(1));
    rome2_100df270_prefix_value capacity = test_prefix_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x200));
    uint32_t receiver = TEST_FRAME_BASE + UINT32_C(0x64);
    rome2_100df270_prefix_value name = test_prefix_value(
        ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY,
        receiver + UINT32_C(0x08));
    uint32_t index = UINT32_C(0);

    (void)memset(trace->prefix_expected, 0, sizeof(trace->prefix_expected));
    test_clear_prefix_step(
        &trace->prefix_expected[index],
        ROME2_100DF270_PREFIX_STEP_LOAD_TITLE);
    test_set_prefix_arguments(
        &trace->prefix_expected[index], UINT32_C(4),
        test_prefix_value(ROME2_100DF270_PREFIX_VALUE_OPAQUE32, argument1),
        test_prefix_value(ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x6d)),
        test_prefix_value(
            ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY,
            receiver + UINT32_C(0x408)),
        capacity);
    index += UINT32_C(1);

    test_clear_prefix_step(
        &trace->prefix_expected[index],
        ROME2_100DF270_PREFIX_STEP_LOAD_NAME);
    test_set_prefix_arguments(
        &trace->prefix_expected[index], UINT32_C(4),
        test_prefix_value(ROME2_100DF270_PREFIX_VALUE_OPAQUE32, argument1),
        test_prefix_value(ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x67)),
        name,
        capacity);
    index += UINT32_C(1);

    test_clear_prefix_step(
        &trace->prefix_expected[index],
        ROME2_100DF270_PREFIX_STEP_FORMAT_MUTEX_NAME);
    test_set_prefix_arguments(
        &trace->prefix_expected[index], UINT32_C(4),
        local,
        capacity,
        test_prefix_value(
            ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
            UINT32_C(0x1173f460)),
        name);
    index += UINT32_C(1);

    test_clear_prefix_step(
        &trace->prefix_expected[index],
        ROME2_100DF270_PREFIX_STEP_CREATE_MUTEX);
    test_set_prefix_arguments(
        &trace->prefix_expected[index], UINT32_C(3),
        zero,
        test_prefix_value(ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(1)),
        local,
        none);
    trace->prefix_expected[index].result_count = UINT32_C(1);
    trace->prefix_expected[index].result0 = test_prefix_value(
        ROME2_100DF270_PREFIX_VALUE_OPAQUE32, created_mutex);
    index += UINT32_C(1);

    test_clear_prefix_step(
        &trace->prefix_expected[index],
        ROME2_100DF270_PREFIX_STEP_GET_LAST_ERROR);
    trace->prefix_expected[index].result_count = UINT32_C(1);
    trace->prefix_expected[index].result0 = test_prefix_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, last_error);
    index += UINT32_C(1);

    if (last_error == UINT32_C(0xb7)) {
        test_clear_prefix_step(
            &trace->prefix_expected[index],
            ROME2_100DF270_PREFIX_STEP_FORMAT_DUPLICATE_MESSAGE);
        test_set_prefix_arguments(
            &trace->prefix_expected[index], UINT32_C(4),
            local,
            capacity,
            test_prefix_value(
                ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
                UINT32_C(0x1173f4a0)),
            name);
        index += UINT32_C(1);

        test_clear_prefix_step(
            &trace->prefix_expected[index],
            ROME2_100DF270_PREFIX_STEP_SHOW_DUPLICATE_MESSAGE);
        test_set_prefix_arguments(
            &trace->prefix_expected[index], UINT32_C(4),
            zero,
            local,
            test_prefix_value(
                ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
                UINT32_C(0x1173f440)),
            test_prefix_value(
                ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x10)));
        index += UINT32_C(1);

        test_clear_prefix_step(
            &trace->prefix_expected[index],
            ROME2_100DF270_PREFIX_STEP_TERMINATE_PROCESS);
        index += UINT32_C(1);
    }

    test_clear_prefix_step(
        &trace->prefix_expected[index],
        ROME2_100DF270_PREFIX_STEP_GET_MOUSE_TRAILS);
    test_set_prefix_arguments(
        &trace->prefix_expected[index], UINT32_C(4),
        test_prefix_value(ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x5e)),
        zero,
        test_prefix_value(
            ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
            UINT32_C(0x119f3854)),
        zero);
    index += UINT32_C(1);

    test_clear_prefix_step(
        &trace->prefix_expected[index],
        ROME2_100DF270_PREFIX_STEP_SET_MOUSE_TRAILS);
    test_set_prefix_arguments(
        &trace->prefix_expected[index], UINT32_C(4),
        test_prefix_value(ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0x5d)),
        zero,
        zero,
        zero);
    trace->prefix_expected_count = index + UINT32_C(1);
}

static void test_build_suffix_expected(
    test_trace *trace,
    uint32_t first_result,
    uint32_t second_result,
    uint32_t first_value)
{
    static const uint32_t mismatch_arguments[4] = {
        UINT32_C(0x2d), UINT32_C(0x12),
        UINT32_C(0x16), UINT32_C(0x21)
    };
    uint32_t receiver = TEST_FRAME_BASE + UINT32_C(0x64);
    uint32_t argument = TEST_FRAME_BASE + UINT32_C(0x28);
    uint32_t owner = receiver + UINT32_C(0x874);
    uint32_t index = UINT32_C(0);
    size_t mismatch_index;

    (void)memset(trace->suffix_expected, 0, sizeof(trace->suffix_expected));
    test_clear_suffix_step(
        &trace->suffix_expected[index],
        ROME2_100DF270_SUFFIX_STEP_PUBLISH_RECEIVER);
    test_set_suffix_arguments(
        &trace->suffix_expected[index], UINT32_C(2),
        UINT32_C(0x119f3140), receiver);
    index += UINT32_C(1);

    test_clear_suffix_step(
        &trace->suffix_expected[index],
        ROME2_100DF270_SUFFIX_STEP_CALL_100E8240);
    test_set_suffix_arguments(
        &trace->suffix_expected[index], UINT32_C(1), argument, UINT32_C(0));
    trace->suffix_expected[index].result_count = UINT32_C(1);
    trace->suffix_expected[index].result0 = UINT32_C(0x119f3a38);
    index += UINT32_C(1);

    test_clear_suffix_step(
        &trace->suffix_expected[index],
        ROME2_100DF270_SUFFIX_STEP_CALL_100F2750);
    test_set_suffix_arguments(
        &trace->suffix_expected[index], UINT32_C(2),
        UINT32_C(0x119f3aa0), argument);
    index += UINT32_C(1);

    test_clear_suffix_step(
        &trace->suffix_expected[index],
        ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0);
    test_set_suffix_arguments(
        &trace->suffix_expected[index], UINT32_C(1), receiver, UINT32_C(0));
    index += UINT32_C(1);

    test_set_suffix_query(
        &trace->suffix_expected[index],
        ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_FIRST,
        owner, first_result, first_value);
    index += UINT32_C(1);

    if (first_value != UINT32_C(0x4e3b)) {
        for (mismatch_index = 0;
             mismatch_index < sizeof(mismatch_arguments) /
                 sizeof(mismatch_arguments[0]);
             ++mismatch_index) {
            test_clear_suffix_step(
                &trace->suffix_expected[index],
                ROME2_100DF270_SUFFIX_STEP_CALL_101046D0);
            test_set_suffix_arguments(
                &trace->suffix_expected[index], UINT32_C(1),
                mismatch_arguments[mismatch_index], UINT32_C(0));
            index += UINT32_C(1);
        }
    }

    test_set_suffix_query(
        &trace->suffix_expected[index],
        ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_SECOND,
        owner, second_result, UINT32_C(0));
    index += UINT32_C(1);

    test_clear_suffix_step(
        &trace->suffix_expected[index],
        ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER);
    test_set_suffix_arguments(
        &trace->suffix_expected[index], UINT32_C(2),
        second_result, UINT32_C(0x4e3b));
    trace->suffix_expected_count = index + UINT32_C(1);
}

static void test_evil_parent_emit(
    void *opaque,
    rome2_100ed3c0_preloop_step step)
{
    uint32_t *count = (uint32_t *)opaque;

    (void)step;
    *count += UINT32_C(1);
}

static void test_evil_prefix_emit(
    void *opaque,
    rome2_100df270_prefix_step step)
{
    uint32_t *count = (uint32_t *)opaque;

    (void)step;
    *count += UINT32_C(1);
}

static void test_evil_suffix_emit(
    void *opaque,
    rome2_100df270_suffix_step step)
{
    uint32_t *count = (uint32_t *)opaque;

    (void)step;
    *count += UINT32_C(1);
}

static void test_parent_emit(
    void *opaque,
    rome2_100ed3c0_preloop_step step)
{
    test_trace *trace = (test_trace *)opaque;
    uint32_t index = trace->parent_count;

    if (trace->result == NULL ||
        trace->result->child_receiver.value != TEST_RESULT_SENTINEL ||
        trace->result->child_packet.value != TEST_RESULT_SENTINEL ||
        trace->result->child_argument.value != TEST_RESULT_SENTINEL ||
        trace->result->next_original_pc != TEST_RESULT_SENTINEL) {
        trace->failure_count += UINT32_C(1);
    }
    if ((index < UINT32_C(8) &&
         (trace->prefix_count != UINT32_C(0) ||
          trace->suffix_count != UINT32_C(0))) ||
        (index == UINT32_C(8) &&
         (trace->prefix_count != trace->prefix_expected_count ||
          trace->suffix_count != trace->suffix_expected_count))) {
        trace->failure_count += UINT32_C(1);
    }
    if (index >= trace->parent_expected_count ||
        index >= TEST_PARENT_STEPS) {
        trace->failure_count += UINT32_C(1);
        return;
    }
    trace->parent_observed[index] = step;
    if (!test_parent_steps_equal(&step, &trace->parent_expected[index])) {
        trace->failure_count += UINT32_C(1);
    }
    trace->parent_count = index + UINT32_C(1);

    if (index == UINT32_C(0) && trace->mutate_effects_after_first != 0 &&
        trace->caller_effects != NULL) {
        trace->caller_effects->emit_step = test_evil_parent_emit;
        trace->caller_effects->context = &trace->unexpected_count;
        trace->caller_effects->child_prefix.emit_step = test_evil_prefix_emit;
        trace->caller_effects->child_prefix.context = &trace->unexpected_count;
        trace->caller_effects->child_prefix.created_mutex = UINT32_C(0);
        trace->caller_effects->child_prefix.last_error = UINT32_C(0);
        trace->caller_effects->child_suffix.emit_step = test_evil_suffix_emit;
        trace->caller_effects->child_suffix.context = &trace->unexpected_count;
        trace->caller_effects->child_suffix.result_100e8240.value = UINT32_C(0);
        trace->caller_effects->child_suffix.first_selector_result.value =
            UINT32_C(0);
        trace->caller_effects->child_suffix.second_selector_result.value =
            UINT32_C(0);
    }
}

static void test_prefix_emit(
    void *opaque,
    rome2_100df270_prefix_step step)
{
    test_trace *trace = (test_trace *)opaque;
    uint32_t index = trace->prefix_count;

    if (trace->result == NULL ||
        trace->result->next_original_pc != TEST_RESULT_SENTINEL ||
        trace->parent_count != UINT32_C(8) ||
        trace->suffix_count != UINT32_C(0)) {
        trace->failure_count += UINT32_C(1);
    }
    if (index >= trace->prefix_expected_count || index >= TEST_PREFIX_STEPS) {
        trace->failure_count += UINT32_C(1);
        return;
    }
    trace->prefix_observed[index] = step;
    if (!test_prefix_steps_equal(&step, &trace->prefix_expected[index])) {
        trace->failure_count += UINT32_C(1);
    }
    trace->prefix_count = index + UINT32_C(1);
}

static void test_suffix_emit(
    void *opaque,
    rome2_100df270_suffix_step step)
{
    test_trace *trace = (test_trace *)opaque;
    uint32_t index = trace->suffix_count;
    int final_step =
        step.kind == ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER;

    if (trace->result == NULL ||
        trace->result->next_original_pc != TEST_RESULT_SENTINEL ||
        trace->parent_count != UINT32_C(8) ||
        trace->prefix_count != trace->prefix_expected_count ||
        trace->selector == NULL ||
        memcmp(
            trace->selector->bytes,
            final_step != 0 ? trace->selector_final.bytes :
                trace->selector_initial.bytes,
            TEST_SELECTOR_BYTES) != 0) {
        trace->failure_count += UINT32_C(1);
    }
    if (index >= trace->suffix_expected_count || index >= TEST_SUFFIX_STEPS) {
        trace->failure_count += UINT32_C(1);
        return;
    }
    trace->suffix_observed[index] = step;
    if (!test_suffix_steps_equal(&step, &trace->suffix_expected[index])) {
        trace->failure_count += UINT32_C(1);
    }
    trace->suffix_count = index + UINT32_C(1);
}

static void test_build_final_frame(
    test_frame_memory *expected,
    uint32_t argument1,
    uint32_t created_mutex)
{
    uint8_t *frame = expected->bytes;
    uint8_t *receiver = frame + UINT32_C(0x64);
    uint32_t receiver_guest = TEST_FRAME_BASE + UINT32_C(0x64);

    test_write_u32_le(frame + UINT32_C(0x00), UINT32_C(0));
    test_write_triplet(frame + UINT32_C(0x04));
    test_write_triplet(frame + UINT32_C(0x10));
    test_write_u32_le(frame + UINT32_C(0x1c), argument1);
    frame[UINT32_C(0x20)] = UINT8_C(0);
    test_write_u32_le(frame + UINT32_C(0x24), UINT32_C(0));
    test_write_triplet(frame + UINT32_C(0x28));
    test_write_u32_le(frame + UINT32_C(0x34), argument1);
    test_write_u32_le(frame + UINT32_C(0x38), UINT32_C(0));
    test_write_triplet(frame + UINT32_C(0x3c));
    test_write_triplet(frame + UINT32_C(0x48));
    test_write_u32_le(frame + UINT32_C(0x54), argument1);
    frame[UINT32_C(0x58)] = UINT8_C(0);
    test_write_u32_le(frame + UINT32_C(0x5c), UINT32_C(0));
    frame[UINT32_C(0x60)] = UINT8_C(0);

    test_write_u32_le(receiver + UINT32_C(0x000), UINT32_C(0x1173f2f4));
    test_write_u32_le(receiver + UINT32_C(0x004), argument1);
    test_write_u32_le(receiver + UINT32_C(0x808), created_mutex);
    test_write_u32_le(receiver + UINT32_C(0x80c), UINT32_C(0x11741e08));
    test_write_u32_le(receiver + UINT32_C(0x810), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x814), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x81c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x820), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x824), argument1);
    test_write_u32_le(receiver + UINT32_C(0x828), UINT32_C(0));
    test_write_triplet(receiver + UINT32_C(0x82c));
    test_write_triplet(receiver + UINT32_C(0x838));
    test_write_u32_le(receiver + UINT32_C(0x844), argument1);
    receiver[UINT32_C(0x848)] = UINT8_C(0);
    test_write_u32_le(receiver + UINT32_C(0x84c), UINT32_C(0));
    receiver[UINT32_C(0x850)] = UINT8_C(0);
    test_write_u32_le(receiver + UINT32_C(0x854), receiver_guest);
    test_write_u32_le(receiver + UINT32_C(0x858), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x85c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x860), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x864), receiver_guest);
    test_write_u32_le(receiver + UINT32_C(0x868), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x86c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x870), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x874), UINT32_C(0x1173dc18));
    test_write_u32_le(receiver + UINT32_C(0x878), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x87c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x880), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x888), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x88c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x894), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x898), UINT32_MAX);
    test_write_u32_le(receiver + UINT32_C(0x89c), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x8a0), UINT32_C(0));
    test_write_u32_le(receiver + UINT32_C(0x8a4), UINT32_C(0));
}

static void test_init_fixture(
    test_fixture *fixture,
    uint32_t argument1,
    uint32_t created_mutex,
    uint32_t last_error,
    uint32_t first_offset,
    uint32_t second_offset,
    uint32_t first_value,
    uint32_t second_value,
    int mutate_effects)
{
    uint32_t first_result = TEST_SELECTOR_BASE + first_offset;
    uint32_t second_result = TEST_SELECTOR_BASE + second_offset;

    (void)memset(fixture, 0, sizeof(*fixture));
    (void)memset(fixture->frame.bytes, 0xa7, sizeof(fixture->frame.bytes));
    (void)memset(fixture->text.bytes, 0xb8, sizeof(fixture->text.bytes));
    (void)memset(fixture->selector.bytes, 0xc9, sizeof(fixture->selector.bytes));
    fixture->text.bytes[0] = UINT8_C(0);
    fixture->text.bytes[1] = UINT8_C(0);
    test_write_u32_le(fixture->selector.bytes + first_offset, first_value);
    if (first_offset != second_offset) {
        test_write_u32_le(fixture->selector.bytes + second_offset, second_value);
    }

    fixture->frame_view.host_base = fixture->frame.bytes;
    fixture->frame_view.guest_base = TEST_FRAME_BASE;
    fixture->frame_view.byte_count = sizeof(fixture->frame.bytes);
    fixture->text_view.host_base = fixture->text.bytes;
    fixture->text_view.guest_base = TEST_TEXT_BASE;
    fixture->text_view.byte_count = sizeof(fixture->text.bytes);
    fixture->selector_view.host_base = fixture->selector.bytes;
    fixture->selector_view.guest_base = TEST_SELECTOR_BASE;
    fixture->selector_view.byte_count = sizeof(fixture->selector.bytes);

    fixture->effects.emit_step = test_parent_emit;
    fixture->effects.context = &fixture->trace;
    fixture->effects.child_prefix.emit_step = test_prefix_emit;
    fixture->effects.child_prefix.context = &fixture->trace;
    fixture->effects.child_prefix.created_mutex = created_mutex;
    fixture->effects.child_prefix.last_error = last_error;
    fixture->effects.child_suffix.emit_step = test_suffix_emit;
    fixture->effects.child_suffix.context = &fixture->trace;
    fixture->effects.child_suffix.result_100e8240.value = UINT32_C(0x119f3a38);
    fixture->effects.child_suffix.first_selector_result.value = first_result;
    fixture->effects.child_suffix.second_selector_result.value = second_result;

    fixture->result.child_receiver.value = TEST_RESULT_SENTINEL;
    fixture->result.child_packet.value = TEST_RESULT_SENTINEL;
    fixture->result.child_argument.value = TEST_RESULT_SENTINEL;
    fixture->result.next_original_pc = TEST_RESULT_SENTINEL;

    fixture->trace.selector_initial = fixture->selector;
    fixture->trace.selector_final = fixture->selector;
    test_write_u32_le(
        fixture->trace.selector_final.bytes + second_offset,
        UINT32_C(0x4e3b));
    fixture->trace.selector = &fixture->selector;
    fixture->trace.caller_effects = &fixture->effects;
    fixture->trace.result = &fixture->result;
    fixture->trace.mutate_effects_after_first = mutate_effects;
    test_build_parent_expected(&fixture->trace, argument1);
    test_build_prefix_expected(
        &fixture->trace, argument1, created_mutex, last_error);
    test_build_suffix_expected(
        &fixture->trace, first_result, second_result, first_value);
}

static int test_expect(int condition, const char *case_name, const char *detail)
{
    if (condition) {
        return 0;
    }
    (void)fprintf(stderr, "100ed3c0 empty preloop runtime: %s: %s\n",
        case_name, detail);
    return 1;
}

static int test_run_success(
    const char *case_name,
    uint32_t argument1,
    uint32_t created_mutex,
    uint32_t last_error,
    uint32_t first_offset,
    uint32_t second_offset,
    uint32_t first_value,
    uint32_t second_value,
    int mutate_effects)
{
    test_fixture fixture;
    test_frame_memory expected_frame;
    rome2_guest_write_view saved_frame_view;
    rome2_guest_read_view saved_text_view;
    rome2_guest_write_view saved_selector_view;
    rome2_100ed3c0_preloop_effects saved_effects;
    rome2_guest_status status;
    uint32_t index;
    int failed = 0;

    test_case_count += UINT32_C(1);
    test_init_fixture(
        &fixture, argument1, created_mutex, last_error,
        first_offset, second_offset, first_value, second_value,
        mutate_effects);
    expected_frame = fixture.frame;
    test_build_final_frame(&expected_frame, argument1, created_mutex);
    saved_frame_view = fixture.frame_view;
    saved_text_view = fixture.text_view;
    saved_selector_view = fixture.selector_view;
    saved_effects = fixture.effects;

    status = rome2_port_100ed3c0_run_empty_preloop(
        &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE},
        argument1,
        &fixture.text_view,
        (rome2_guest_addr32){TEST_TEXT_BASE},
        UINT32_C(1),
        &fixture.selector_view,
        &fixture.effects,
        &fixture.result);

    failed |= test_expect(status == ROME2_GUEST_OK,
        case_name, "status was not OK");
    failed |= test_expect(
        fixture.trace.parent_count == fixture.trace.parent_expected_count &&
        fixture.trace.prefix_count == fixture.trace.prefix_expected_count &&
        fixture.trace.suffix_count == fixture.trace.suffix_expected_count &&
        fixture.trace.failure_count == UINT32_C(0) &&
        fixture.trace.unexpected_count == UINT32_C(0),
        case_name, "transcript fields, nesting order, or commit timing changed");
    failed |= test_expect(
        fixture.result.child_receiver.value == TEST_FRAME_BASE + UINT32_C(0x64) &&
        fixture.result.child_packet.value == TEST_FRAME_BASE + UINT32_C(0x34) &&
        fixture.result.child_argument.value == TEST_FRAME_BASE + UINT32_C(0x28) &&
        fixture.result.next_original_pc == UINT32_C(0x100ed471),
        case_name, "the four-field result did not commit exactly at completion");
    failed |= test_expect(
        memcmp(fixture.frame.bytes, expected_frame.bytes,
            sizeof(fixture.frame.bytes)) == 0,
        case_name, "the exact frame projection or untouched padding changed");
    failed |= test_expect(
        memcmp(fixture.selector.bytes, fixture.trace.selector_final.bytes,
            sizeof(fixture.selector.bytes)) == 0,
        case_name, "the suffix marker was not the sole selector-view write");
    failed |= test_expect(
        fixture.text.bytes[0] == UINT8_C(0) &&
        fixture.text.bytes[1] == UINT8_C(0) &&
        fixture.text.bytes[2] == UINT8_C(0xb8) &&
        fixture.text.bytes[3] == UINT8_C(0xb8),
        case_name, "the read-only UTF-16 backing changed");
    failed |= test_expect(
        memcmp(&fixture.frame_view, &saved_frame_view,
            sizeof(saved_frame_view)) == 0 &&
        memcmp(&fixture.text_view, &saved_text_view,
            sizeof(saved_text_view)) == 0 &&
        memcmp(&fixture.selector_view, &saved_selector_view,
            sizeof(saved_selector_view)) == 0,
        case_name, "a caller view descriptor was mutated");
    if (mutate_effects == 0) {
        failed |= test_expect(
            memcmp(&fixture.effects, &saved_effects, sizeof(saved_effects)) == 0,
            case_name, "the adapter mutated its caller effects descriptor");
    } else {
        failed |= test_expect(
            fixture.effects.emit_step == test_evil_parent_emit &&
            fixture.effects.child_prefix.emit_step == test_evil_prefix_emit &&
            fixture.effects.child_suffix.emit_step == test_evil_suffix_emit &&
            fixture.effects.child_suffix.result_100e8240.value == UINT32_C(0),
            case_name, "first-callback mutation of caller effects was lost");
    }

    for (index = UINT32_C(0); index < fixture.trace.parent_expected_count;
         ++index) {
        failed |= test_expect(
            test_parent_steps_equal(
                &fixture.trace.parent_observed[index],
                &fixture.trace.parent_expected[index]),
            case_name, "parent transcript differs from its independent oracle");
    }
    for (index = UINT32_C(0); index < fixture.trace.prefix_expected_count;
         ++index) {
        failed |= test_expect(
            test_prefix_steps_equal(
                &fixture.trace.prefix_observed[index],
                &fixture.trace.prefix_expected[index]),
            case_name, "child prefix transcript differs from its oracle");
    }
    for (index = UINT32_C(0); index < fixture.trace.suffix_expected_count;
         ++index) {
        failed |= test_expect(
            test_suffix_steps_equal(
                &fixture.trace.suffix_observed[index],
                &fixture.trace.suffix_expected[index]),
            case_name, "child suffix transcript differs from its oracle");
    }
    return failed;
}

static int test_success_routes(void)
{
    int failed = 0;

    failed |= test_run_success(
        "normal prefix plus mismatch suffix",
        TEST_ARGUMENT1, UINT32_C(0x10203040), UINT32_C(0),
        TEST_FIRST_SELECTOR_OFFSET, TEST_SECOND_SELECTOR_OFFSET,
        UINT32_C(0x12345678), UINT32_C(0xfedcba98), 0);
    failed |= test_run_success(
        "duplicate prefix plus already-marked suffix",
        UINT32_C(0x01020304), UINT32_C(0x55667788), UINT32_C(0xb7),
        TEST_FIRST_SELECTOR_OFFSET, TEST_SECOND_SELECTOR_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0xa0b0c0d0), 0);
    failed |= test_run_success(
        "repeated selector result cell remains admissible",
        UINT32_C(0), UINT32_C(0), UINT32_C(0),
        TEST_FIRST_SELECTOR_OFFSET, TEST_FIRST_SELECTOR_OFFSET,
        UINT32_C(0x0badcafe), UINT32_C(0x0badcafe), 0);
    failed |= test_run_success(
        "opaque caller and mutex words may be all ones",
        UINT32_MAX, UINT32_MAX, UINT32_C(0),
        TEST_FIRST_SELECTOR_OFFSET, TEST_SECOND_SELECTOR_OFFSET,
        UINT32_C(0x4e3b), UINT32_C(0), 0);
    failed |= test_run_success(
        "all nested effects are snapshotted before the first callback",
        UINT32_C(0x13572468), UINT32_C(0xcafebabe), UINT32_C(0xb7),
        TEST_FIRST_SELECTOR_OFFSET, TEST_SECOND_SELECTOR_OFFSET,
        UINT32_C(0x87654321), UINT32_C(0x01010101), 1);
    return failed;
}

static int test_expect_failure(
    const char *case_name,
    int expected_status,
    test_fixture *fixture,
    const rome2_guest_write_view *frame_view,
    rome2_guest_addr32 guest_frame,
    const rome2_guest_read_view *text_view,
    rome2_guest_addr32 guest_text,
    uint32_t max_units,
    const rome2_guest_write_view *selector_view,
    const rome2_100ed3c0_preloop_effects *effects,
    rome2_100ed3c0_preloop_result *result,
    int result_is_observable)
{
    test_frame_memory saved_frame = fixture->frame;
    test_text_memory saved_text = fixture->text;
    test_selector_memory saved_selector = fixture->selector;
    rome2_guest_write_view saved_frame_view = fixture->frame_view;
    rome2_guest_read_view saved_text_view = fixture->text_view;
    rome2_guest_write_view saved_selector_view = fixture->selector_view;
    rome2_100ed3c0_preloop_effects saved_effects = fixture->effects;
    rome2_100ed3c0_preloop_result saved_result = fixture->result;
    rome2_guest_status status;
    int failed = 0;

    test_case_count += UINT32_C(1);
    status = rome2_port_100ed3c0_run_empty_preloop(
        frame_view,
        guest_frame,
        TEST_ARGUMENT1,
        text_view,
        guest_text,
        max_units,
        selector_view,
        effects,
        result);

    failed |= test_expect(
        status != ROME2_GUEST_OK &&
        (expected_status == TEST_ANY_FAILURE ||
         status == (rome2_guest_status)expected_status),
        case_name, "failure status changed or the input was accepted");
    failed |= test_expect(
        fixture->trace.parent_count == UINT32_C(0) &&
        fixture->trace.prefix_count == UINT32_C(0) &&
        fixture->trace.suffix_count == UINT32_C(0) &&
        fixture->trace.failure_count == UINT32_C(0) &&
        fixture->trace.unexpected_count == UINT32_C(0),
        case_name, "preflight failure emitted a callback");
    failed |= test_expect(
        memcmp(fixture->frame.bytes, saved_frame.bytes,
            sizeof(saved_frame.bytes)) == 0 &&
        memcmp(fixture->text.bytes, saved_text.bytes,
            sizeof(saved_text.bytes)) == 0 &&
        memcmp(fixture->selector.bytes, saved_selector.bytes,
            sizeof(saved_selector.bytes)) == 0,
        case_name, "preflight failure mutated a backing interval");
    failed |= test_expect(
        memcmp(&fixture->frame_view, &saved_frame_view,
            sizeof(saved_frame_view)) == 0 &&
        memcmp(&fixture->text_view, &saved_text_view,
            sizeof(saved_text_view)) == 0 &&
        memcmp(&fixture->selector_view, &saved_selector_view,
            sizeof(saved_selector_view)) == 0 &&
        memcmp(&fixture->effects, &saved_effects, sizeof(saved_effects)) == 0,
        case_name, "preflight failure mutated a caller control descriptor");
    if (result_is_observable != 0) {
        failed |= test_expect(
            memcmp(&fixture->result, &saved_result, sizeof(saved_result)) == 0,
            case_name, "preflight failure changed the result object");
    }
    return failed;
}

static void test_init_default(test_fixture *fixture)
{
    test_init_fixture(
        fixture, TEST_ARGUMENT1, UINT32_C(0x10203040), UINT32_C(0),
        TEST_FIRST_SELECTOR_OFFSET, TEST_SECOND_SELECTOR_OFFSET,
        UINT32_C(0x12345678), UINT32_C(0xfedcba98), 0);
}

static int test_required_objects_and_effects_fail_closed(void)
{
    test_fixture fixture;
    int failed = 0;

    test_init_default(&fixture);
    failed |= test_expect_failure(
        "null frame view", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        NULL, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    failed |= test_expect_failure(
        "null text view", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        NULL, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    failed |= test_expect_failure(
        "null selector view", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        NULL, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    failed |= test_expect_failure(
        "null effects", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, NULL, &fixture.result, 1);
    test_init_default(&fixture);
    failed |= test_expect_failure(
        "null result", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, NULL, 0);

    test_init_default(&fixture);
    fixture.effects.emit_step = NULL;
    failed |= test_expect_failure(
        "null parent callback", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.effects.context = NULL;
    failed |= test_expect_failure(
        "null parent callback context", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.effects.child_prefix.emit_step = NULL;
    failed |= test_expect_failure(
        "null child-prefix callback", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.effects.child_suffix.context = NULL;
    failed |= test_expect_failure(
        "null child-suffix callback context", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.effects.child_suffix.result_100e8240.value = UINT32_C(0x119f3a39);
    failed |= test_expect_failure(
        "wrong admitted child result identity", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.text_view,
        (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.effects.child_suffix.first_selector_result.value = UINT32_C(0);
    failed |= test_expect_failure(
        "null first selector-result identity", ROME2_GUEST_NULL_ADDRESS,
        &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.text_view,
        (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.effects.child_suffix.second_selector_result.value = UINT32_MAX;
    failed |= test_expect_failure(
        "second selector-result span crosses 2^32",
        ROME2_GUEST_RANGE_OVERFLOW, &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.text_view,
        (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.effects.child_suffix.second_selector_result.value =
        TEST_SELECTOR_BASE + TEST_SELECTOR_BYTES - UINT32_C(3);
    failed |= test_expect_failure(
        "second selector-result cell is truncated",
        ROME2_GUEST_OUT_OF_RANGE, &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.text_view,
        (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    return failed;
}

static int test_frame_text_and_range_fail_closed(void)
{
    test_fixture fixture;
    int failed = 0;

    test_init_default(&fixture);
    fixture.frame_view.byte_count = TEST_FRAME_BYTES - UINT32_C(1);
    failed |= test_expect_failure(
        "frame view is one byte short", TEST_ANY_FAILURE, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.frame_view.byte_count = TEST_FRAME_BYTES + UINT32_C(1);
    failed |= test_expect_failure(
        "frame view is one byte too large", TEST_ANY_FAILURE, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.frame_view.guest_base = TEST_FRAME_BASE - UINT32_C(1);
    failed |= test_expect_failure(
        "frame view base differs from guest frame", TEST_ANY_FAILURE, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    failed |= test_expect_failure(
        "null guest frame", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){UINT32_C(0)},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);

    test_init_default(&fixture);
    failed |= test_expect_failure(
        "zero UTF-16 containment bound", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(0),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    failed |= test_expect_failure(
        "two-unit containment bound exceeds admitted empty input", TEST_ANY_FAILURE,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(2),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.text.bytes[0] = UINT8_C(1);
    fixture.text.bytes[1] = UINT8_C(0);
    failed |= test_expect_failure(
        "nonempty UTF-16 input", TEST_ANY_FAILURE, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.text.bytes[0] = UINT8_C(1);
    fixture.text.bytes[1] = UINT8_C(0);
    fixture.text.bytes[2] = UINT8_C(2);
    fixture.text.bytes[3] = UINT8_C(0);
    failed |= test_expect_failure(
        "unterminated UTF-16 input within exact bound", ROME2_GUEST_OUT_OF_RANGE,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.text_view.byte_count = UINT64_C(1);
    failed |= test_expect_failure(
        "truncated UTF-16 unit", ROME2_GUEST_OUT_OF_RANGE, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    failed |= test_expect_failure(
        "null UTF-16 guest identity", ROME2_GUEST_NULL_ADDRESS, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){UINT32_C(0)}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    failed |= test_expect_failure(
        "UTF-16 guest identity is below its view", ROME2_GUEST_OUT_OF_RANGE,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view,
        (rome2_guest_addr32){TEST_TEXT_BASE - UINT32_C(1)}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);

    test_init_default(&fixture);
    fixture.frame_view.host_base = NULL;
    failed |= test_expect_failure(
        "null frame backing", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.text_view.host_base = NULL;
    failed |= test_expect_failure(
        "null text backing", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.selector_view.host_base = NULL;
    failed |= test_expect_failure(
        "null selector backing", ROME2_GUEST_BAD_ARGUMENT, &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);

    test_init_default(&fixture);
    fixture.frame_view.guest_base = UINT32_C(0xfffff800);
    fixture.frame_view.byte_count = TEST_FRAME_BYTES;
    failed |= test_expect_failure(
        "frame guest interval crosses 2^32", ROME2_GUEST_RANGE_OVERFLOW,
        &fixture, &fixture.frame_view,
        (rome2_guest_addr32){UINT32_C(0xfffff800)}, &fixture.text_view,
        (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.text_view.guest_base = UINT32_C(0xfffffffe);
    fixture.text_view.byte_count = UINT64_C(2);
    failed |= test_expect_failure(
        "UTF-16 unit address crosses 2^32", ROME2_GUEST_RANGE_OVERFLOW,
        &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.text_view,
        (rome2_guest_addr32){UINT32_C(0xffffffff)}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.selector_view.guest_base = UINT32_C(0xfffffff8);
    fixture.selector_view.byte_count = TEST_SELECTOR_BYTES;
    failed |= test_expect_failure(
        "selector guest interval crosses 2^32", ROME2_GUEST_RANGE_OVERFLOW,
        &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.text_view,
        (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    return failed;
}

static int test_backing_and_logical_aliases_fail_closed(void)
{
    test_fixture fixture;
    int failed = 0;

    test_init_default(&fixture);
    fixture.text_view.host_base = fixture.frame.bytes;
    fixture.text_view.byte_count = UINT64_C(2);
    failed |= test_expect_failure(
        "text backing overlaps frame backing", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.selector_view.host_base = fixture.frame.bytes;
    failed |= test_expect_failure(
        "selector backing overlaps frame backing", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.text_view.host_base = fixture.selector.bytes;
    fixture.text_view.byte_count = UINT64_C(2);
    failed |= test_expect_failure(
        "text backing overlaps selector backing", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);

    test_init_default(&fixture);
    fixture.text_view.guest_base = TEST_FRAME_BASE;
    failed |= test_expect_failure(
        "text guest unit overlaps frame guest interval", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_FRAME_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.selector_view.guest_base = TEST_FRAME_BASE;
    fixture.effects.child_suffix.first_selector_result.value = TEST_FRAME_BASE;
    fixture.effects.child_suffix.second_selector_result.value =
        TEST_FRAME_BASE + UINT32_C(8);
    failed |= test_expect_failure(
        "selector guest cells overlap frame guest interval",
        ROME2_GUEST_BAD_ARGUMENT, &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.text_view,
        (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.text_view.guest_base = TEST_SELECTOR_BASE;
    failed |= test_expect_failure(
        "text guest unit overlaps first selector cell",
        ROME2_GUEST_BAD_ARGUMENT, &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.text_view,
        (rome2_guest_addr32){TEST_SELECTOR_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    return failed;
}

static int test_controls_alignment_and_host_ranges_fail_closed(void)
{
    test_fixture fixture;
    test_effects_storage effects_storage;
    test_write_view_storage view_storage;
    test_result_storage result_storage;
    rome2_100ed3c0_preloop_effects *misaligned_effects;
    rome2_guest_write_view *misaligned_view;
    rome2_100ed3c0_preloop_result *misaligned_result;
    int failed = 0;

    test_init_default(&fixture);
    failed |= test_expect_failure(
        "effects and result controls overlap", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects,
        (rome2_100ed3c0_preloop_result *)(void *)&fixture.effects, 0);
    test_init_default(&fixture);
    failed |= test_expect_failure(
        "frame-view and text-view controls overlap", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        (const rome2_guest_read_view *)(const void *)&fixture.frame_view,
        (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    failed |= test_expect_failure(
        "selector-view and effects controls overlap", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        (const rome2_guest_write_view *)(const void *)&fixture.effects,
        &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.frame_view.host_base = (uint8_t *)(void *)&fixture.effects;
    failed |= test_expect_failure(
        "frame backing overlaps effects control", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    fixture.selector_view.host_base = (uint8_t *)(void *)&fixture.result;
    fixture.selector_view.byte_count = sizeof(fixture.result);
    fixture.effects.child_suffix.first_selector_result.value = TEST_SELECTOR_BASE;
    fixture.effects.child_suffix.second_selector_result.value = TEST_SELECTOR_BASE;
    failed |= test_expect_failure(
        "selector backing overlaps result control", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);

    test_init_default(&fixture);
    (void)memset(&effects_storage, 0, sizeof(effects_storage));
    (void)memcpy(effects_storage.bytes + 1U,
        &fixture.effects, sizeof(fixture.effects));
    misaligned_effects =
        (rome2_100ed3c0_preloop_effects *)(void *)(effects_storage.bytes + 1U);
    failed |= test_expect_failure(
        "misaligned effects control", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, misaligned_effects, &fixture.result, 1);
    test_init_default(&fixture);
    (void)memset(&view_storage, 0, sizeof(view_storage));
    (void)memcpy(view_storage.bytes + 1U,
        &fixture.frame_view, sizeof(fixture.frame_view));
    misaligned_view =
        (rome2_guest_write_view *)(void *)(view_storage.bytes + 1U);
    failed |= test_expect_failure(
        "misaligned frame-view control", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, misaligned_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    test_init_default(&fixture);
    (void)memset(&result_storage, 0, sizeof(result_storage));
    test_write_u32_le(result_storage.bytes + 1U, TEST_RESULT_SENTINEL);
    misaligned_result =
        (rome2_100ed3c0_preloop_result *)(void *)(result_storage.bytes + 1U);
    failed |= test_expect_failure(
        "misaligned result control", ROME2_GUEST_BAD_ARGUMENT,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, misaligned_result, 0);

    test_init_default(&fixture);
    fixture.frame_view.host_base =
        (uint8_t *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)1U);
    failed |= test_expect_failure(
        "frame host interval overflows uintptr", ROME2_GUEST_RANGE_OVERFLOW,
        &fixture, &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.text_view, (rome2_guest_addr32){TEST_TEXT_BASE}, UINT32_C(1),
        &fixture.selector_view, &fixture.effects, &fixture.result, 1);
    return failed;
}

int main(void)
{
    int failed = 0;

    failed |= test_success_routes();
    failed |= test_required_objects_and_effects_fail_closed();
    failed |= test_frame_text_and_range_fail_closed();
    failed |= test_backing_and_logical_aliases_fail_closed();
    failed |= test_controls_alignment_and_host_ranges_fail_closed();
    failed |= test_expect(
        test_case_count == TEST_EXPECTED_CASES,
        "suite accounting", "the expected runtime case count changed");
    if (failed != 0) {
        return 1;
    }
    (void)printf(
        "100ed3c0 empty preloop runtime: %u/%u cases passed\n",
        (unsigned)test_case_count, (unsigned)TEST_EXPECTED_CASES);
    return 0;
}

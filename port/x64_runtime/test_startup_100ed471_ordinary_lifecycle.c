#include "ported_100ed471_ordinary_lifecycle.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_FRAME_BYTES UINT32_C(0x90c)
#define TEST_FRAME_BASE UINT32_C(0x24000000)
#define TEST_LOCAL_DISPATCH_BASE UINT32_C(0x11897860)
#define TEST_LOCAL_DISPATCH_BYTES UINT32_C(0x140)
#define TEST_LOCAL_RECEIVER TEST_LOCAL_DISPATCH_BASE
#define TEST_FALLBACK_DISPATCH_BASE UINT32_C(0x11897910)
#define TEST_FALLBACK_DISPATCH_BYTES UINT32_C(0x1496f8)
#define TEST_SETUP_STEPS UINT32_C(6)
#define TEST_TERMINAL_STEPS UINT32_C(5)
#define TEST_MAX_STEPS \
    (TEST_SETUP_STEPS + ROME2_PORT_100ED471_MAX_POLL_CALLS + \
        TEST_TERMINAL_STEPS)
#define TEST_TIMESTAMP_LOW UINT32_C(0x89abcdef)
#define TEST_TIMESTAMP_HIGH UINT32_C(0x01234567)
#define TEST_SENTINEL UINT32_C(0xa55aa55a)

_Static_assert(
    ROME2_PORT_100ED471_FRAME_BYTES == TEST_FRAME_BYTES,
    "the authenticated lifecycle frame size changed");
_Static_assert(
    ROME2_PORT_100ED471_START_PC == UINT32_C(0x100ed471) &&
        ROME2_PORT_100ED471_POLL_PC == UINT32_C(0x100ed4c1) &&
        ROME2_PORT_100ED471_RETURN_PC == UINT32_C(0x100ed550),
    "the authenticated lifecycle boundaries changed");
_Static_assert(
    ROME2_PORT_100ED471_RECEIVER_OFFSET == UINT32_C(0x64) &&
        ROME2_PORT_100ED471_TIMESTAMP_OFFSET == UINT32_C(0x28) &&
        ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET == UINT32_C(0x904),
    "the receiver or timestamp layout changed");
_Static_assert(
    ROME2_PORT_100ED471_CLEANUP0_OFFSET == UINT32_C(0x48) &&
        ROME2_PORT_100ED471_CLEANUP1_OFFSET == UINT32_C(0x3c) &&
        ROME2_PORT_100ED471_CLEANUP2_OFFSET == UINT32_C(0x10) &&
        ROME2_PORT_100ED471_CLEANUP3_OFFSET == UINT32_C(0x04),
    "the cleanup order changed");
_Static_assert(
    ROME2_PORT_100ED471_MAX_POLL_CALLS == UINT32_C(64),
    "the finite poll ceiling changed");
_Static_assert(
    ROME2_PORT_100ED471_LOCAL_VTABLE == UINT32_C(0x11897870) &&
        ROME2_PORT_100ED471_LOCAL_METHOD == UINT32_C(0x112e2cd0) &&
        ROME2_PORT_100ED471_FALLBACK_OBJECT == UINT32_C(0x119e1004) &&
        ROME2_PORT_100ED471_FALLBACK_VTABLE == UINT32_C(0x1189791c) &&
        ROME2_PORT_100ED471_FALLBACK_METHOD == UINT32_C(0x100f3d00),
    "the authenticated dispatch allowlist changed");
_Static_assert(
    _Alignof(rome2_guest_write_view) > 1U &&
        _Alignof(rome2_guest_read_view) > 1U &&
        _Alignof(rome2_100ed471_lifecycle_effects) > 1U &&
        _Alignof(rome2_100ed471_lifecycle_result) > 1U,
    "the alignment adversaries require naturally aligned controls");

typedef union test_frame_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_FRAME_BYTES];
} test_frame_memory;

typedef union test_dispatch_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_LOCAL_DISPATCH_BYTES];
} test_dispatch_memory;

typedef union test_fallback_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_FALLBACK_DISPATCH_BYTES];
} test_fallback_memory;

typedef union test_write_view_storage {
    rome2_guest_write_view alignment;
    uint8_t bytes[
        sizeof(rome2_guest_write_view) + _Alignof(rome2_guest_write_view)];
} test_write_view_storage;

typedef union test_read_view_storage {
    rome2_guest_read_view alignment;
    uint8_t bytes[
        sizeof(rome2_guest_read_view) + _Alignof(rome2_guest_read_view)];
} test_read_view_storage;

typedef union test_effects_storage {
    rome2_100ed471_lifecycle_effects alignment;
    uint8_t bytes[
        sizeof(rome2_100ed471_lifecycle_effects) +
        _Alignof(rome2_100ed471_lifecycle_effects)];
} test_effects_storage;

typedef union test_result_storage {
    rome2_100ed471_lifecycle_result alignment;
    uint8_t bytes[
        sizeof(rome2_100ed471_lifecycle_result) +
        _Alignof(rome2_100ed471_lifecycle_result)];
} test_result_storage;

typedef struct test_trace {
    rome2_100ed471_step observed_steps[TEST_MAX_STEPS];
    uint32_t expected_poll_results[ROME2_PORT_100ED471_MAX_POLL_CALLS];
    test_frame_memory initial_frame;
    test_frame_memory post_timestamp_frame;
    rome2_100ed471_lifecycle_result initial_result;
    test_frame_memory *frame;
    rome2_100ed471_lifecycle_effects *caller_effects;
    rome2_100ed471_lifecycle_result *result;
    rome2_guest_addr32 expected_guest_receiver;
    uint32_t expected_timestamp_low;
    uint32_t expected_timestamp_high;
    uint32_t expected_poll_result_count;
    uint32_t step_count;
    uint32_t bad_observations;
    uint32_t evil_calls;
    int mutate_caller_effects;
} test_trace;

typedef struct test_fixture {
    test_frame_memory frame;
    test_dispatch_memory dispatch;
    rome2_guest_write_view frame_view;
    rome2_guest_read_view dispatch_view;
    rome2_100ed471_lifecycle_effects effects;
    rome2_100ed471_lifecycle_result result;
    test_trace trace;
} test_fixture;

static test_fallback_memory test_fallback;
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

static void test_write_empty_descriptor(uint8_t *bytes)
{
    test_write_u32_le(bytes, UINT32_C(0));
    test_write_u32_le(bytes + 4, UINT32_C(0));
    test_write_u32_le(bytes + 8, ROME2_PORT_100F1CC0_SENTINEL);
}

static void test_set_result_sentinel(
    rome2_100ed471_lifecycle_result *result)
{
    result->dispatch_receiver.value = TEST_SENTINEL;
    result->dispatch_vtable.value = TEST_SENTINEL;
    result->dispatch_target.value = TEST_SENTINEL;
    result->poll_calls = TEST_SENTINEL;
    result->terminal_poll_result = TEST_SENTINEL;
    result->timestamp_low = TEST_SENTINEL;
    result->timestamp_high = TEST_SENTINEL;
    result->return_original_pc = TEST_SENTINEL;
}

static int test_expect(int condition, const char *case_name, const char *detail)
{
    if (condition) {
        return 0;
    }
    (void)fprintf(
        stderr, "100ed471 ordinary lifecycle runtime: %s: %s\n",
        case_name, detail);
    return 1;
}

static void test_begin_case(void)
{
    test_case_count += UINT32_C(1);
}

static int test_steps_equal(
    const rome2_100ed471_step *left,
    const rome2_100ed471_step *right)
{
    return
        left->kind == right->kind &&
        left->argument_count == right->argument_count &&
        left->argument0 == right->argument0 &&
        left->argument1 == right->argument1 &&
        left->argument2 == right->argument2 &&
        left->result_count == right->result_count &&
        left->result0 == right->result0 &&
        left->result1 == right->result1 &&
        left->dispatch_vtable == right->dispatch_vtable &&
        left->dispatch_slot_offset == right->dispatch_slot_offset &&
        left->dispatch_target == right->dispatch_target;
}

static rome2_100ed471_step test_clear_step(rome2_100ed471_step_kind kind)
{
    rome2_100ed471_step step;

    memset(&step, 0, sizeof(step));
    step.kind = kind;
    return step;
}

static uint32_t test_build_expected_steps(
    rome2_100ed471_step expected[TEST_MAX_STEPS],
    rome2_guest_addr32 guest_frame,
    rome2_guest_addr32 dispatch_receiver,
    rome2_guest_addr32 dispatch_vtable,
    rome2_guest_addr32 dispatch_target,
    uint32_t timestamp_low,
    uint32_t timestamp_high,
    uint32_t poll_result_count,
    const uint32_t poll_results[ROME2_PORT_100ED471_MAX_POLL_CALLS])
{
    static const uint32_t cleanup_offsets[4] = {
        ROME2_PORT_100ED471_CLEANUP0_OFFSET,
        ROME2_PORT_100ED471_CLEANUP1_OFFSET,
        ROME2_PORT_100ED471_CLEANUP2_OFFSET,
        ROME2_PORT_100ED471_CLEANUP3_OFFSET
    };
    uint32_t receiver = guest_frame.value +
        ROME2_PORT_100ED471_RECEIVER_OFFSET;
    uint32_t cursor;
    uint32_t index;

    expected[0] = test_clear_step(ROME2_100ED471_STEP_CALL_100EA060);
    expected[0].argument_count = UINT32_C(1);
    expected[0].argument0 = receiver;

    expected[1] = test_clear_step(ROME2_100ED471_STEP_CALL_112DCAF0);
    expected[1].argument_count = UINT32_C(3);
    expected[1].argument0 = ROME2_PORT_100ED471_LOG_MESSAGE;

    expected[2] = test_clear_step(ROME2_100ED471_STEP_CALL_100D6560);
    expected[2].argument_count = UINT32_C(1);

    expected[3] = test_clear_step(ROME2_100ED471_STEP_CALL_112E3D20);
    expected[3].result_count = UINT32_C(1);
    expected[3].result0 = dispatch_receiver.value;

    expected[4] = test_clear_step(ROME2_100ED471_STEP_INDIRECT_SLOT_54);
    expected[4].argument_count = UINT32_C(2);
    expected[4].argument0 = dispatch_receiver.value;
    expected[4].dispatch_vtable = dispatch_vtable.value;
    expected[4].dispatch_slot_offset =
        ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET;
    expected[4].dispatch_target = dispatch_target.value;

    expected[5] = test_clear_step(ROME2_100ED471_STEP_CALL_112E2BB0);
    expected[5].argument_count = UINT32_C(1);
    expected[5].argument0 = guest_frame.value +
        ROME2_PORT_100ED471_TIMESTAMP_OFFSET;
    expected[5].result_count = UINT32_C(2);
    expected[5].result0 = timestamp_low;
    expected[5].result1 = timestamp_high;

    cursor = TEST_SETUP_STEPS;
    for (index = UINT32_C(0); index < poll_result_count; ++index) {
        expected[cursor] =
            test_clear_step(ROME2_100ED471_STEP_CALL_100EC5C0);
        expected[cursor].argument_count = UINT32_C(1);
        expected[cursor].argument0 = receiver;
        expected[cursor].result_count = UINT32_C(1);
        expected[cursor].result0 = poll_results[index];
        cursor += UINT32_C(1);
    }

    expected[cursor] = test_clear_step(ROME2_100ED471_STEP_CALL_100E0650);
    expected[cursor].argument_count = UINT32_C(1);
    expected[cursor].argument0 = receiver;
    cursor += UINT32_C(1);

    for (index = UINT32_C(0); index < UINT32_C(4); ++index) {
        expected[cursor] =
            test_clear_step(ROME2_100ED471_STEP_CALL_100F1CC0);
        expected[cursor].argument_count = UINT32_C(1);
        expected[cursor].argument0 =
            guest_frame.value + cleanup_offsets[index];
        cursor += UINT32_C(1);
    }
    return cursor;
}

static void test_evil_emit(void *opaque, rome2_100ed471_step step)
{
    test_trace *trace = (test_trace *)opaque;

    (void)step;
    if (trace != NULL) {
        trace->evil_calls += UINT32_C(1);
    }
}

static void test_emit(void *opaque, rome2_100ed471_step step)
{
    test_trace *trace = (test_trace *)opaque;

    if (trace == NULL) {
        return;
    }
    if (trace->step_count < TEST_MAX_STEPS) {
        trace->observed_steps[trace->step_count] = step;
    } else {
        trace->bad_observations += UINT32_C(1);
    }
    trace->step_count += UINT32_C(1);
    if (trace->frame == NULL || trace->result == NULL) {
        trace->bad_observations += UINT32_C(1);
    } else {
        if ((uint32_t)step.kind <=
                (uint32_t)ROME2_100ED471_STEP_CALL_112E2BB0) {
            if (memcmp(
                    trace->frame->bytes,
                    trace->initial_frame.bytes,
                    TEST_FRAME_BYTES) != 0) {
                trace->bad_observations += UINT32_C(1);
            }
        } else if (memcmp(
                trace->frame->bytes,
                trace->post_timestamp_frame.bytes,
                TEST_FRAME_BYTES) != 0) {
            trace->bad_observations += UINT32_C(1);
        }
        if (memcmp(
                trace->result,
                &trace->initial_result,
                sizeof(trace->initial_result)) != 0) {
            trace->bad_observations += UINT32_C(1);
        }
    }

    if (trace->mutate_caller_effects != 0 &&
        trace->step_count == UINT32_C(1) &&
        trace->caller_effects != NULL) {
        trace->caller_effects->emit_step = test_evil_emit;
        trace->caller_effects->context = trace;
        trace->caller_effects->timestamp_low = UINT32_C(0xdeadbeef);
        trace->caller_effects->timestamp_high = UINT32_C(0xcafef00d);
        trace->caller_effects->poll_result_count = UINT32_C(1);
        trace->caller_effects->poll_results[0] = UINT32_C(1);
    }
}

static void test_prepare_post_timestamp(test_trace *trace)
{
    trace->post_timestamp_frame = trace->initial_frame;
    test_write_u32_le(
        trace->post_timestamp_frame.bytes +
            ROME2_PORT_100ED471_TIMESTAMP_OFFSET,
        trace->expected_timestamp_low);
    test_write_u32_le(
        trace->post_timestamp_frame.bytes +
            ROME2_PORT_100ED471_TIMESTAMP_OFFSET + UINT32_C(4),
        trace->expected_timestamp_high);
    test_write_u32_le(
        trace->post_timestamp_frame.bytes +
            ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET,
        trace->expected_timestamp_low);
    test_write_u32_le(
        trace->post_timestamp_frame.bytes +
            ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET + UINT32_C(4),
        trace->expected_timestamp_high);
}

static void test_init_fixture(test_fixture *fixture)
{
    static const uint32_t cleanup_offsets[4] = {
        ROME2_PORT_100ED471_CLEANUP0_OFFSET,
        ROME2_PORT_100ED471_CLEANUP1_OFFSET,
        ROME2_PORT_100ED471_CLEANUP2_OFFSET,
        ROME2_PORT_100ED471_CLEANUP3_OFFSET
    };
    size_t index;

    memset(fixture, 0, sizeof(*fixture));
    memset(fixture->frame.bytes, 0x5a, sizeof(fixture->frame.bytes));
    for (index = 0U; index < 4U; ++index) {
        test_write_empty_descriptor(
            fixture->frame.bytes + cleanup_offsets[index]);
    }
    memset(fixture->dispatch.bytes, 0xcc, sizeof(fixture->dispatch.bytes));
    test_write_u32_le(
        fixture->dispatch.bytes +
            (TEST_LOCAL_RECEIVER - TEST_LOCAL_DISPATCH_BASE),
        ROME2_PORT_100ED471_LOCAL_VTABLE);
    test_write_u32_le(
        fixture->dispatch.bytes +
            (ROME2_PORT_100ED471_LOCAL_VTABLE +
                ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET -
                TEST_LOCAL_DISPATCH_BASE),
        ROME2_PORT_100ED471_LOCAL_METHOD);

    fixture->frame_view.host_base = fixture->frame.bytes;
    fixture->frame_view.guest_base = TEST_FRAME_BASE;
    fixture->frame_view.byte_count = TEST_FRAME_BYTES;
    fixture->dispatch_view.host_base = fixture->dispatch.bytes;
    fixture->dispatch_view.guest_base = TEST_LOCAL_DISPATCH_BASE;
    fixture->dispatch_view.byte_count = TEST_LOCAL_DISPATCH_BYTES;
    fixture->effects.emit_step = test_emit;
    fixture->effects.context = &fixture->trace;
    fixture->effects.timestamp_low = TEST_TIMESTAMP_LOW;
    fixture->effects.timestamp_high = TEST_TIMESTAMP_HIGH;
    fixture->effects.poll_result_count = UINT32_C(1);
    fixture->effects.poll_results[0] = UINT32_C(2);
    test_set_result_sentinel(&fixture->result);

    fixture->trace.frame = &fixture->frame;
    fixture->trace.caller_effects = &fixture->effects;
    fixture->trace.result = &fixture->result;
    fixture->trace.expected_guest_receiver.value =
        TEST_FRAME_BASE + ROME2_PORT_100ED471_RECEIVER_OFFSET;
    fixture->trace.expected_timestamp_low = TEST_TIMESTAMP_LOW;
    fixture->trace.expected_timestamp_high = TEST_TIMESTAMP_HIGH;
    fixture->trace.expected_poll_result_count = UINT32_C(1);
    fixture->trace.expected_poll_results[0] = UINT32_C(2);
    fixture->trace.initial_frame = fixture->frame;
    fixture->trace.initial_result = fixture->result;
    test_prepare_post_timestamp(&fixture->trace);
}

static void test_rebase_frame(test_fixture *fixture, uint32_t guest_base)
{
    fixture->frame_view.guest_base = guest_base;
    fixture->trace.expected_guest_receiver.value =
        guest_base + ROME2_PORT_100ED471_RECEIVER_OFFSET;
}

static void test_set_valid_poll_transcript(
    test_fixture *fixture,
    uint32_t poll_result_count)
{
    uint32_t index;

    fixture->effects.poll_result_count = poll_result_count;
    fixture->trace.expected_poll_result_count = poll_result_count;
    for (index = UINT32_C(0); index < poll_result_count; ++index) {
        const uint32_t value =
            index + UINT32_C(1) == poll_result_count
                ? UINT32_C(2)
                : UINT32_C(0);
        fixture->effects.poll_results[index] = value;
        fixture->trace.expected_poll_results[index] = value;
    }
}

static int test_verify_step_prefix(
    const char *case_name,
    const test_fixture *fixture,
    rome2_guest_addr32 dispatch_receiver,
    rome2_guest_addr32 dispatch_vtable,
    rome2_guest_addr32 dispatch_target,
    uint32_t expected_count)
{
    rome2_100ed471_step expected[TEST_MAX_STEPS];
    uint32_t built_count;
    uint32_t index;
    int failed = 0;

    built_count = test_build_expected_steps(
        expected,
        (rome2_guest_addr32){fixture->frame_view.guest_base},
        dispatch_receiver,
        dispatch_vtable,
        dispatch_target,
        fixture->trace.expected_timestamp_low,
        fixture->trace.expected_timestamp_high,
        fixture->trace.expected_poll_result_count,
        fixture->trace.expected_poll_results);
    failed |= test_expect(
        built_count == expected_count,
        case_name, "oracle expected-step count changed");
    failed |= test_expect(
        fixture->trace.step_count == expected_count,
        case_name, "emitted step count changed");
    for (index = UINT32_C(0);
         index < expected_count && index < TEST_MAX_STEPS;
         ++index) {
        failed |= test_expect(
            test_steps_equal(
                &fixture->trace.observed_steps[index], &expected[index]),
            case_name, "an emitted step field or order changed");
    }
    return failed;
}

static int test_verify_success(
    const char *case_name,
    test_fixture *fixture,
    rome2_guest_addr32 dispatch_receiver,
    rome2_guest_addr32 dispatch_vtable,
    rome2_guest_addr32 dispatch_target,
    uint32_t poll_calls,
    rome2_guest_status status)
{
    rome2_100ed471_lifecycle_result expected_result;
    int failed = 0;

    expected_result.dispatch_receiver = dispatch_receiver;
    expected_result.dispatch_vtable = dispatch_vtable;
    expected_result.dispatch_target = dispatch_target;
    expected_result.poll_calls = poll_calls;
    expected_result.terminal_poll_result = UINT32_C(2);
    expected_result.timestamp_low = fixture->trace.expected_timestamp_low;
    expected_result.timestamp_high = fixture->trace.expected_timestamp_high;
    expected_result.return_original_pc = ROME2_PORT_100ED471_RETURN_PC;

    failed |= test_expect(
        status == ROME2_GUEST_OK, case_name, "status was not OK");
    failed |= test_verify_step_prefix(
        case_name, fixture, dispatch_receiver, dispatch_vtable,
        dispatch_target,
        TEST_SETUP_STEPS + poll_calls + TEST_TERMINAL_STEPS);
    failed |= test_expect(
        fixture->trace.bad_observations == UINT32_C(0),
        case_name, "a callback observed an early or malformed commit");
    failed |= test_expect(
        fixture->trace.evil_calls == UINT32_C(0),
        case_name, "a callback was reread from caller storage");
    failed |= test_expect(
        memcmp(
            fixture->frame.bytes,
            fixture->trace.post_timestamp_frame.bytes,
            TEST_FRAME_BYTES) == 0,
        case_name, "frame mutation differed from the two timestamp pairs");
    failed |= test_expect(
        memcmp(
            &fixture->result, &expected_result,
            sizeof(expected_result)) == 0,
        case_name, "published lifecycle result changed");
    return failed;
}

static int test_local_success_routes(void)
{
    static const uint32_t poll_counts[] = {UINT32_C(1), UINT32_C(3)};
    size_t route;
    int failed = 0;

    for (route = 0U; route < 2U; ++route) {
        static const char *const labels[] = {
            "local dispatch immediate terminal result",
            "local dispatch repeats zero then exits on two"
        };
        test_fixture fixture;
        rome2_guest_status status;

        test_begin_case();
        test_init_fixture(&fixture);
        test_set_valid_poll_transcript(&fixture, poll_counts[route]);
        status = rome2_port_100ed471_run_ordinary_lifecycle(
            &fixture.frame_view,
            (rome2_guest_addr32){fixture.frame_view.guest_base},
            &fixture.dispatch_view,
            (rome2_guest_addr32){TEST_LOCAL_RECEIVER},
            poll_counts[route],
            &fixture.effects,
            &fixture.result);
        failed |= test_verify_success(
            labels[route], &fixture,
            (rome2_guest_addr32){TEST_LOCAL_RECEIVER},
            (rome2_guest_addr32){ROME2_PORT_100ED471_LOCAL_VTABLE},
            (rome2_guest_addr32){ROME2_PORT_100ED471_LOCAL_METHOD},
            poll_counts[route], status);
    }
    return failed;
}

static int test_fallback_success(void)
{
    static const char case_name[] = "fixed fallback object pair is admitted";
    test_fixture fixture;
    rome2_guest_status status;
    uint32_t object_offset =
        ROME2_PORT_100ED471_FALLBACK_OBJECT - TEST_FALLBACK_DISPATCH_BASE;
    uint32_t method_offset =
        ROME2_PORT_100ED471_FALLBACK_VTABLE +
        ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET -
        TEST_FALLBACK_DISPATCH_BASE;
    int failed = 0;

    test_begin_case();
    test_init_fixture(&fixture);
    memset(test_fallback.bytes, 0xcc, sizeof(test_fallback.bytes));
    test_write_u32_le(
        test_fallback.bytes + object_offset,
        ROME2_PORT_100ED471_FALLBACK_VTABLE);
    test_write_u32_le(
        test_fallback.bytes + method_offset,
        ROME2_PORT_100ED471_FALLBACK_METHOD);
    fixture.dispatch_view.host_base = test_fallback.bytes;
    fixture.dispatch_view.guest_base = TEST_FALLBACK_DISPATCH_BASE;
    fixture.dispatch_view.byte_count = TEST_FALLBACK_DISPATCH_BYTES;
    test_set_valid_poll_transcript(&fixture, UINT32_C(1));
    status = rome2_port_100ed471_run_ordinary_lifecycle(
        &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){ROME2_PORT_100ED471_FALLBACK_OBJECT},
        UINT32_C(1),
        &fixture.effects,
        &fixture.result);
    failed |= test_verify_success(
        case_name, &fixture,
        (rome2_guest_addr32){ROME2_PORT_100ED471_FALLBACK_OBJECT},
        (rome2_guest_addr32){ROME2_PORT_100ED471_FALLBACK_VTABLE},
        (rome2_guest_addr32){ROME2_PORT_100ED471_FALLBACK_METHOD},
        UINT32_C(1), status);
    failed |= test_expect(
        test_read_u32_le(test_fallback.bytes + object_offset) ==
                ROME2_PORT_100ED471_FALLBACK_VTABLE &&
            test_read_u32_le(test_fallback.bytes + method_offset) ==
                ROME2_PORT_100ED471_FALLBACK_METHOD,
        case_name, "read-only fallback dispatch cells changed");
    return failed;
}

static int test_frame_end_boundary_success(void)
{
    static const char case_name[] =
        "exact frame may end at the guest32 address-space end";
    test_fixture fixture;
    rome2_guest_status status;
    uint32_t guest_base = UINT32_MAX - TEST_FRAME_BYTES + UINT32_C(1);

    test_begin_case();
    test_init_fixture(&fixture);
    test_rebase_frame(&fixture, guest_base);
    test_set_valid_poll_transcript(&fixture, UINT32_C(1));
    status = rome2_port_100ed471_run_ordinary_lifecycle(
        &fixture.frame_view,
        (rome2_guest_addr32){guest_base},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER},
        UINT32_C(1), &fixture.effects, &fixture.result);
    return test_verify_success(
        case_name, &fixture,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER},
        (rome2_guest_addr32){ROME2_PORT_100ED471_LOCAL_VTABLE},
        (rome2_guest_addr32){ROME2_PORT_100ED471_LOCAL_METHOD},
        UINT32_C(1), status);
}

static int test_effect_snapshot(void)
{
    static const char case_name[] =
        "effects and timestamp are snapshotted before first callback";
    test_fixture fixture;
    rome2_guest_status status;

    test_begin_case();
    test_init_fixture(&fixture);
    fixture.trace.mutate_caller_effects = 1;
    test_set_valid_poll_transcript(&fixture, UINT32_C(1));
    status = rome2_port_100ed471_run_ordinary_lifecycle(
        &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER},
        UINT32_C(1), &fixture.effects, &fixture.result);
    return test_verify_success(
        case_name, &fixture,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER},
        (rome2_guest_addr32){ROME2_PORT_100ED471_LOCAL_VTABLE},
        (rome2_guest_addr32){ROME2_PORT_100ED471_LOCAL_METHOD},
        UINT32_C(1), status);
}

static int test_maximum_poll_budget(void)
{
    static const char case_name[] =
        "terminal two on the sixty-fourth poll is admitted";
    test_fixture fixture;
    rome2_guest_status status;

    test_begin_case();
    test_init_fixture(&fixture);
    test_set_valid_poll_transcript(
        &fixture, ROME2_PORT_100ED471_MAX_POLL_CALLS);
    status = rome2_port_100ed471_run_ordinary_lifecycle(
        &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER},
        ROME2_PORT_100ED471_MAX_POLL_CALLS,
        &fixture.effects, &fixture.result);
    return test_verify_success(
        case_name, &fixture,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER},
        (rome2_guest_addr32){ROME2_PORT_100ED471_LOCAL_VTABLE},
        (rome2_guest_addr32){ROME2_PORT_100ED471_LOCAL_METHOD},
        ROME2_PORT_100ED471_MAX_POLL_CALLS, status);
}

static int test_expect_preflight_failure(
    const char *case_name,
    test_fixture *fixture,
    const rome2_guest_write_view *frame_view,
    rome2_guest_addr32 guest_frame,
    const rome2_guest_read_view *dispatch_view,
    rome2_guest_addr32 dispatch_receiver,
    uint32_t max_poll_calls,
    const rome2_100ed471_lifecycle_effects *effects,
    rome2_100ed471_lifecycle_result *result_out,
    rome2_guest_status expected_status)
{
    test_frame_memory frame_snapshot = fixture->frame;
    rome2_100ed471_lifecycle_result result_snapshot = fixture->result;
    rome2_guest_status status;
    int failed = 0;

    test_begin_case();
    status = rome2_port_100ed471_run_ordinary_lifecycle(
        frame_view, guest_frame, dispatch_view, dispatch_receiver,
        max_poll_calls, effects, result_out);
    if (status != expected_status) {
        (void)fprintf(
            stderr, "%s: got status %u, expected %u\n",
            case_name, (unsigned int)status, (unsigned int)expected_status);
    }
    failed |= test_expect(
        status == expected_status,
        case_name, "preflight status changed");
    failed |= test_expect(
        fixture->trace.step_count == UINT32_C(0) &&
            fixture->trace.evil_calls == UINT32_C(0),
        case_name, "preflight failure emitted a callback");
    failed |= test_expect(
        memcmp(&fixture->frame, &frame_snapshot, sizeof(frame_snapshot)) == 0,
        case_name, "preflight failure changed frame bytes");
    if (result_out == &fixture->result) {
        failed |= test_expect(
            memcmp(
                &fixture->result, &result_snapshot,
                sizeof(result_snapshot)) == 0,
            case_name, "preflight failure changed result output");
    }
    return failed;
}

static int test_poll_transcript_preflight_failures(void)
{
    test_fixture fixture;
    int failed = 0;

#define TEST_BAD_POLL(label_, budget_) \
    do { \
        failed |= test_expect_preflight_failure( \
            (label_), &fixture, &fixture.frame_view, \
            (rome2_guest_addr32){TEST_FRAME_BASE}, \
            &fixture.dispatch_view, \
            (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, (budget_), \
            &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT); \
    } while (0)

    test_init_fixture(&fixture);
    fixture.effects.poll_result_count = UINT32_C(0);
    TEST_BAD_POLL("empty poll transcript", UINT32_C(1));

    test_init_fixture(&fixture);
    fixture.effects.poll_result_count = UINT32_C(1);
    fixture.effects.poll_results[0] = UINT32_C(1);
    TEST_BAD_POLL(
        "ordinary-unreachable result one is rejected precommit",
        UINT32_C(1));

    test_init_fixture(&fixture);
    fixture.effects.poll_result_count = UINT32_C(1);
    fixture.effects.poll_results[0] = UINT32_C(3);
    TEST_BAD_POLL("unsupported result three", UINT32_C(1));

    test_init_fixture(&fixture);
    fixture.effects.poll_result_count = UINT32_C(1);
    fixture.effects.poll_results[0] = UINT32_MAX;
    TEST_BAD_POLL("all-bits-set poll result", UINT32_C(1));

    test_init_fixture(&fixture);
    fixture.effects.poll_result_count = UINT32_C(3);
    fixture.effects.poll_results[0] = UINT32_C(0);
    fixture.effects.poll_results[1] = UINT32_C(0);
    fixture.effects.poll_results[2] = UINT32_C(0);
    TEST_BAD_POLL("zero-only transcript exhausts budget", UINT32_C(3));

    test_init_fixture(&fixture);
    fixture.effects.poll_result_count = UINT32_C(2);
    fixture.effects.poll_results[0] = UINT32_C(2);
    fixture.effects.poll_results[1] = UINT32_C(2);
    TEST_BAD_POLL("terminal two has a trailing result", UINT32_C(2));

    test_init_fixture(&fixture);
    fixture.effects.poll_result_count = UINT32_C(3);
    fixture.effects.poll_results[0] = UINT32_C(0);
    fixture.effects.poll_results[1] = UINT32_C(2);
    fixture.effects.poll_results[2] = UINT32_C(2);
    TEST_BAD_POLL("early terminal two has a trailing result", UINT32_C(3));

    test_init_fixture(&fixture);
    fixture.effects.poll_result_count = UINT32_C(2);
    fixture.effects.poll_results[0] = UINT32_C(0);
    fixture.effects.poll_results[1] = UINT32_C(2);
    TEST_BAD_POLL("transcript count exceeds explicit budget", UINT32_C(1));

    test_init_fixture(&fixture);
    fixture.effects.poll_result_count =
        ROME2_PORT_100ED471_MAX_POLL_CALLS + UINT32_C(1);
    TEST_BAD_POLL(
        "transcript count exceeds fixed storage ceiling",
        ROME2_PORT_100ED471_MAX_POLL_CALLS);

    test_init_fixture(&fixture);
    fixture.effects.poll_result_count = UINT32_C(2);
    fixture.effects.poll_results[0] = UINT32_C(2);
    fixture.effects.poll_results[1] = UINT32_C(0);
    TEST_BAD_POLL("terminal two followed by zero", UINT32_C(2));

#undef TEST_BAD_POLL
    return failed;
}

static int test_basic_preflight_failures(void)
{
    test_fixture fixture;
    int failed = 0;

#define TEST_PREFLIGHT(label_, frame_, guest_, dispatch_, receiver_, budget_, \
        effects_, result_, status_) \
    do { \
        test_init_fixture(&fixture); \
        failed |= test_expect_preflight_failure( \
            (label_), &fixture, (frame_), (guest_), (dispatch_), (receiver_), \
            (budget_), (effects_), (result_), (status_)); \
    } while (0)

    test_init_fixture(&fixture);
    failed |= test_expect_preflight_failure(
        "null frame view", &fixture, NULL,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    TEST_PREFLIGHT(
        "null dispatch view", &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, NULL,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);
    TEST_PREFLIGHT(
        "null effects", &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        NULL, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);
    TEST_PREFLIGHT(
        "null result", &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, NULL, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    fixture.frame_view.host_base = NULL;
    failed |= test_expect_preflight_failure(
        "null frame host", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);
    test_init_fixture(&fixture);
    fixture.dispatch_view.host_base = NULL;
    failed |= test_expect_preflight_failure(
        "null dispatch host", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    TEST_PREFLIGHT(
        "null guest frame", &fixture.frame_view,
        (rome2_guest_addr32){UINT32_C(0)}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);
    TEST_PREFLIGHT(
        "guest frame differs from exact view base", &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE + UINT32_C(1)},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    fixture.frame_view.byte_count = TEST_FRAME_BYTES - UINT32_C(1);
    failed |= test_expect_preflight_failure(
        "short frame", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);
    test_init_fixture(&fixture);
    fixture.frame_view.byte_count = TEST_FRAME_BYTES + UINT32_C(1);
    failed |= test_expect_preflight_failure(
        "oversized frame", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    TEST_PREFLIGHT(
        "zero poll budget", &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(0),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);
    TEST_PREFLIGHT(
        "poll budget exceeds authenticated ceiling", &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER},
        ROME2_PORT_100ED471_MAX_POLL_CALLS + UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    fixture.effects.emit_step = NULL;
    failed |= test_expect_preflight_failure(
        "null emitter", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);
    test_init_fixture(&fixture);
    fixture.effects.context = NULL;
    failed |= test_expect_preflight_failure(
        "null emitter context", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);
#undef TEST_PREFLIGHT
    return failed;
}

static int test_numeric_range_failures(void)
{
    test_fixture fixture;
    int failed = 0;

    test_init_fixture(&fixture);
    fixture.frame_view.guest_base =
        UINT32_MAX - TEST_FRAME_BYTES + UINT32_C(2);
    failed |= test_expect_preflight_failure(
        "frame guest interval overflows 32 bits", &fixture,
        &fixture.frame_view,
        (rome2_guest_addr32){fixture.frame_view.guest_base},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_RANGE_OVERFLOW);

    test_init_fixture(&fixture);
    fixture.dispatch_view.guest_base = UINT32_MAX - UINT32_C(0x40);
    fixture.dispatch_view.byte_count = UINT32_C(0x80);
    failed |= test_expect_preflight_failure(
        "dispatch guest interval overflows 32 bits", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){fixture.dispatch_view.guest_base}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_RANGE_OVERFLOW);

    test_init_fixture(&fixture);
    fixture.frame_view.host_base = (uint8_t *)(uintptr_t)(
        UINTPTR_MAX - (uintptr_t)UINT32_C(0x100));
    failed |= test_expect_preflight_failure(
        "frame host interval overflows uintptr", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_RANGE_OVERFLOW);

    test_init_fixture(&fixture);
    fixture.dispatch_view.host_base = (const uint8_t *)(uintptr_t)(
        UINTPTR_MAX - (uintptr_t)UINT32_C(0x20));
    failed |= test_expect_preflight_failure(
        "dispatch host interval overflows uintptr", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_RANGE_OVERFLOW);
    return failed;
}

static int test_descriptor_failures(void)
{
    static const uint32_t cleanup_offsets[4] = {
        ROME2_PORT_100ED471_CLEANUP0_OFFSET,
        ROME2_PORT_100ED471_CLEANUP1_OFFSET,
        ROME2_PORT_100ED471_CLEANUP2_OFFSET,
        ROME2_PORT_100ED471_CLEANUP3_OFFSET
    };
    static const uint32_t field_offsets[3] = {
        UINT32_C(0), UINT32_C(4), UINT32_C(8)
    };
    size_t cleanup;
    size_t field;
    int failed = 0;

    for (cleanup = 0U; cleanup < 4U; ++cleanup) {
        for (field = 0U; field < 3U; ++field) {
            char label[96];
            test_fixture fixture;

            test_init_fixture(&fixture);
            (void)snprintf(
                label, sizeof(label),
                "cleanup %u field %u must retain empty descriptor state",
                (unsigned int)cleanup, (unsigned int)field);
            test_write_u32_le(
                fixture.frame.bytes + cleanup_offsets[cleanup] +
                    field_offsets[field],
                field == 2U ? UINT32_C(0) : UINT32_C(1));
            fixture.trace.initial_frame = fixture.frame;
            test_prepare_post_timestamp(&fixture.trace);
            failed |= test_expect_preflight_failure(
                label, &fixture, &fixture.frame_view,
                (rome2_guest_addr32){TEST_FRAME_BASE},
                &fixture.dispatch_view,
                (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
                &fixture.effects, &fixture.result,
                ROME2_GUEST_BAD_ARGUMENT);
        }
    }
    return failed;
}

static int test_dispatch_failures(void)
{
    test_fixture fixture;
    int failed = 0;

    test_init_fixture(&fixture);
    failed |= test_expect_preflight_failure(
        "null dispatch receiver", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){UINT32_C(0)}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    failed |= test_expect_preflight_failure(
        "dispatch receiver below view", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_DISPATCH_BASE - UINT32_C(1)},
        UINT32_C(1), &fixture.effects, &fixture.result,
        ROME2_GUEST_OUT_OF_RANGE);

    test_init_fixture(&fixture);
    failed |= test_expect_preflight_failure(
        "truncated dispatch receiver cell", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){
            TEST_LOCAL_DISPATCH_BASE + TEST_LOCAL_DISPATCH_BYTES -
            UINT32_C(3)},
        UINT32_C(1), &fixture.effects, &fixture.result,
        ROME2_GUEST_OUT_OF_RANGE);

    test_init_fixture(&fixture);
    test_write_u32_le(fixture.dispatch.bytes, UINT32_C(0));
    failed |= test_expect_preflight_failure(
        "null vtable identity", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_NULL_ADDRESS);

    test_init_fixture(&fixture);
    test_write_u32_le(
        fixture.dispatch.bytes,
        UINT32_MAX - ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET +
            UINT32_C(1));
    failed |= test_expect_preflight_failure(
        "vtable plus slot overflows guest32", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_RANGE_OVERFLOW);

    test_init_fixture(&fixture);
    fixture.dispatch_view.byte_count =
        ROME2_PORT_100ED471_LOCAL_VTABLE +
        ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET -
        TEST_LOCAL_DISPATCH_BASE + UINT32_C(3);
    failed |= test_expect_preflight_failure(
        "truncated vtable slot cell", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_OUT_OF_RANGE);

    test_init_fixture(&fixture);
    test_write_u32_le(
        fixture.dispatch.bytes +
            (ROME2_PORT_100ED471_LOCAL_VTABLE +
                ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET -
                TEST_LOCAL_DISPATCH_BASE),
        UINT32_C(0));
    failed |= test_expect_preflight_failure(
        "null dispatch target is outside allowlist", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    test_write_u32_le(
        fixture.dispatch.bytes +
            (ROME2_PORT_100ED471_LOCAL_VTABLE +
                ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET -
                TEST_LOCAL_DISPATCH_BASE),
        ROME2_PORT_100ED471_FALLBACK_METHOD);
    failed |= test_expect_preflight_failure(
        "mixed local vtable and fallback method", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    test_write_u32_le(
        fixture.dispatch.bytes,
        ROME2_PORT_100ED471_FALLBACK_VTABLE);
    test_write_u32_le(
        fixture.dispatch.bytes +
            (ROME2_PORT_100ED471_FALLBACK_VTABLE +
                ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET -
                TEST_LOCAL_DISPATCH_BASE),
        ROME2_PORT_100ED471_FALLBACK_METHOD);
    failed |= test_expect_preflight_failure(
        "fallback pair requires fixed fallback object", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);
    return failed;
}

static int test_alignment_failures(void)
{
    test_fixture fixture;
    test_write_view_storage write_storage;
    test_read_view_storage read_storage;
    test_effects_storage effects_storage;
    test_result_storage result_storage;
    rome2_guest_write_view *misaligned_write;
    rome2_guest_read_view *misaligned_read;
    rome2_100ed471_lifecycle_effects *misaligned_effects;
    rome2_100ed471_lifecycle_result *misaligned_result;
    int failed = 0;

    test_init_fixture(&fixture);
    misaligned_write = (rome2_guest_write_view *)(void *)(
        write_storage.bytes + 1U);
    memcpy(misaligned_write, &fixture.frame_view, sizeof(*misaligned_write));
    failed |= test_expect_preflight_failure(
        "misaligned frame descriptor", &fixture, misaligned_write,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    misaligned_read = (rome2_guest_read_view *)(void *)(
        read_storage.bytes + 1U);
    memcpy(misaligned_read, &fixture.dispatch_view, sizeof(*misaligned_read));
    failed |= test_expect_preflight_failure(
        "misaligned dispatch descriptor", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, misaligned_read,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    misaligned_effects = (rome2_100ed471_lifecycle_effects *)(void *)(
        effects_storage.bytes + 1U);
    memcpy(misaligned_effects, &fixture.effects, sizeof(*misaligned_effects));
    failed |= test_expect_preflight_failure(
        "misaligned effects", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        misaligned_effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    misaligned_result = (rome2_100ed471_lifecycle_result *)(void *)(
        result_storage.bytes + 1U);
    memcpy(misaligned_result, &fixture.result, sizeof(*misaligned_result));
    failed |= test_expect_preflight_failure(
        "misaligned result", &fixture, &fixture.frame_view,
        (rome2_guest_addr32){TEST_FRAME_BASE}, &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, misaligned_result, ROME2_GUEST_BAD_ARGUMENT);
    return failed;
}

static int test_alias_failures(void)
{
    test_fixture fixture;
    rome2_guest_read_view overlapping_dispatch;
    rome2_100ed471_lifecycle_effects effects_copy;
    int failed = 0;

    test_init_fixture(&fixture);
    failed |= test_expect_preflight_failure(
        "frame and dispatch descriptors alias", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        (const rome2_guest_read_view *)(const void *)&fixture.frame_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    failed |= test_expect_preflight_failure(
        "effects and result controls alias", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects,
        (rome2_100ed471_lifecycle_result *)(void *)&fixture.effects,
        ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    effects_copy = fixture.effects;
    memcpy(
        fixture.frame.bytes + UINT32_C(0x100),
        &effects_copy, sizeof(effects_copy));
    fixture.trace.initial_frame = fixture.frame;
    test_prepare_post_timestamp(&fixture.trace);
    failed |= test_expect_preflight_failure(
        "effects control aliases frame backing", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        (const rome2_100ed471_lifecycle_effects *)(const void *)(
            fixture.frame.bytes + UINT32_C(0x100)),
        &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    failed |= test_expect_preflight_failure(
        "result control aliases frame backing", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects,
        (rome2_100ed471_lifecycle_result *)(void *)(
            fixture.frame.bytes + UINT32_C(0x100)),
        ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    failed |= test_expect_preflight_failure(
        "result control aliases dispatch backing", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects,
        (rome2_100ed471_lifecycle_result *)(void *)(
            fixture.dispatch.bytes + UINT32_C(0x80)),
        ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    fixture.effects.context = &fixture.effects;
    failed |= test_expect_preflight_failure(
        "emitter context aliases effects control", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    fixture.effects.context = fixture.dispatch.bytes;
    failed |= test_expect_preflight_failure(
        "emitter context aliases dispatch backing", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    memcpy(
        fixture.frame.bytes,
        fixture.dispatch.bytes,
        sizeof(fixture.dispatch.bytes));
    overlapping_dispatch = fixture.dispatch_view;
    overlapping_dispatch.host_base = fixture.frame.bytes;
    fixture.trace.initial_frame = fixture.frame;
    test_prepare_post_timestamp(&fixture.trace);
    failed |= test_expect_preflight_failure(
        "frame and dispatch physical backings overlap", &fixture,
        &fixture.frame_view, (rome2_guest_addr32){TEST_FRAME_BASE},
        &overlapping_dispatch,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);

    test_init_fixture(&fixture);
    test_rebase_frame(&fixture, UINT32_C(0x11897000));
    failed |= test_expect_preflight_failure(
        "frame and dispatch guest intervals overlap", &fixture,
        &fixture.frame_view,
        (rome2_guest_addr32){fixture.frame_view.guest_base},
        &fixture.dispatch_view,
        (rome2_guest_addr32){TEST_LOCAL_RECEIVER}, UINT32_C(1),
        &fixture.effects, &fixture.result, ROME2_GUEST_BAD_ARGUMENT);
    return failed;
}

int main(void)
{
    int failed = 0;

    failed |= test_local_success_routes();
    failed |= test_fallback_success();
    failed |= test_frame_end_boundary_success();
    failed |= test_effect_snapshot();
    failed |= test_maximum_poll_budget();
    failed |= test_poll_transcript_preflight_failures();
    failed |= test_basic_preflight_failures();
    failed |= test_numeric_range_failures();
    failed |= test_descriptor_failures();
    failed |= test_dispatch_failures();
    failed |= test_alignment_failures();
    failed |= test_alias_failures();
    if (failed != 0) {
        return 1;
    }
    (void)printf(
        "100ed471 ordinary lifecycle runtime: %u/%u cases passed\n",
        (unsigned int)test_case_count,
        (unsigned int)test_case_count);
    return 0;
}

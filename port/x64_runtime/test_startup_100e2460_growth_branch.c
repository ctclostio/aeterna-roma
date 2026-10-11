#include "ported_100e2460_growth_branch.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_STATE_BASE UINT32_C(0x10000)
#define ROME2_TEST_STATE_BYTES 2048
#define ROME2_TEST_VECTOR_OFFSET UINT32_C(0x40)
#define ROME2_TEST_OLD_OFFSET UINT32_C(0x200)
#define ROME2_TEST_NEW_OFFSET UINT32_C(0x500)
#define ROME2_TEST_HANDLER_OFFSET UINT32_C(0x700)
#define ROME2_TEST_VTABLE_BASE UINT32_C(0x20000000)
#define ROME2_TEST_VTABLE_BYTES 2048
#define ROME2_TEST_VTABLE_OFFSET UINT32_C(0x20)
#define ROME2_TEST_METHOD_IDENTITY UINT32_C(0x100e9340)
#define ROME2_TEST_ARGUMENT UINT32_C(0x2824)
#define ROME2_TEST_VECTOR_SENTINEL UINT32_C(0xfeedface)
#define ROME2_TEST_SPARE_SENTINEL UINT32_C(0xa5a5a5a5)
#define ROME2_TEST_MAX_CELLS 8
#define ROME2_TEST_MAX_EVENTS 32

#define ROME2_TEST_EVENT_ALLOCATE UINT32_C(1)
#define ROME2_TEST_EVENT_RELEASE UINT32_C(2)
#define ROME2_TEST_EVENT_DISPATCH UINT32_C(3)
#define ROME2_TEST_EVENT_PEEK UINT32_C(4)

typedef union rome2_test_state_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_TEST_STATE_BYTES];
} rome2_test_state_memory;

typedef union rome2_test_vtable_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_TEST_VTABLE_BYTES];
} rome2_test_vtable_memory;

typedef struct rome2_test_effect_context {
    uint8_t *state_bytes;
    size_t vector_offset;
    size_t old_offset;
    size_t new_offset;
    uint32_t old_capacity;
    uint32_t new_capacity;
    uint32_t expected_allocation_bytes;
    uint32_t expected_old_backing;
    uint32_t expected_new_backing;
    uint32_t expected_handler;
    uint32_t expected_method;
    uint32_t expected_argument;
    uint32_t old_values[ROME2_TEST_MAX_CELLS];
    rome2_guest_addr32 allocation_result;
    uint32_t dispatch_eax;
    uint32_t peek_values[ROME2_TEST_MAX_EVENTS];
    uint32_t peek_value_count;
    uint32_t peek_index;
    uint32_t trace[ROME2_TEST_MAX_EVENTS];
    uint32_t trace_count;
    uint32_t allocate_calls;
    uint32_t release_calls;
    uint32_t dispatch_calls;
    uint32_t peek_calls;
    uint32_t observed_allocation_bytes;
    uint32_t observed_allocation_class;
    uint32_t observed_release;
    uint32_t observed_receiver;
    uint32_t observed_method;
    uint32_t observed_argument;
    uint32_t bad_observation_count;
    int inspect_mapped_bytes;
} rome2_test_effect_context;

typedef struct rome2_test_fixture {
    rome2_test_state_memory state;
    rome2_test_vtable_memory vtables;
    rome2_guest_write_view state_view;
    rome2_guest_read_view vtable_view;
    rome2_100e2460_growth_effects effects;
    rome2_test_effect_context context;
} rome2_test_fixture;

_Static_assert(
    ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY ==
        UINT32_C(0x1fffffff),
    "growth safe-capacity boundary changed");
_Static_assert(sizeof(rome2_guest_addr32) == 4,
    "growth source remains a by-value guest32 identity");

static rome2_guest_addr32 rome2_test_address(uint32_t value)
{
    rome2_guest_addr32 address;

    address.value = value;
    return address;
}

static void rome2_test_put_u32(
    uint8_t *bytes,
    size_t offset,
    uint32_t value)
{
    bytes[offset] = (uint8_t)value;
    bytes[offset + 1] = (uint8_t)(value >> 8);
    bytes[offset + 2] = (uint8_t)(value >> 16);
    bytes[offset + 3] = (uint8_t)(value >> 24);
}

static uint32_t rome2_test_get_u32(const uint8_t *bytes, size_t offset)
{
    return
        (uint32_t)bytes[offset] |
        ((uint32_t)bytes[offset + 1] << 8) |
        ((uint32_t)bytes[offset + 2] << 16) |
        ((uint32_t)bytes[offset + 3] << 24);
}

static uint32_t rome2_test_old_value(uint32_t index)
{
    return UINT32_C(0x10203040) + index * UINT32_C(0x01010101);
}

static void rome2_test_trace(
    rome2_test_effect_context *context,
    uint32_t event)
{
    if (context->trace_count >= ROME2_TEST_MAX_EVENTS) {
        ++context->bad_observation_count;
        return;
    }
    context->trace[context->trace_count] = event;
    ++context->trace_count;
}

static int rome2_test_growth_storage_is_ready(
    const rome2_test_effect_context *context,
    int count_is_incremented)
{
    uint32_t index;
    uint32_t expected_count = context->old_capacity;

    if (count_is_incremented) {
        ++expected_count;
    }
    if (rome2_test_get_u32(
            context->state_bytes, context->vector_offset + 4) !=
            context->new_capacity ||
        rome2_test_get_u32(
            context->state_bytes, context->vector_offset + 8) !=
            expected_count ||
        rome2_test_get_u32(
            context->state_bytes, context->vector_offset + 12) !=
            context->expected_new_backing) {
        return 0;
    }
    for (index = 0; index < context->old_capacity; ++index) {
        if (rome2_test_get_u32(
                context->state_bytes,
                context->old_offset + (size_t)index * 4) !=
                context->old_values[index] ||
            rome2_test_get_u32(
                context->state_bytes,
                context->new_offset + (size_t)index * 4) !=
                context->old_values[index]) {
            return 0;
        }
    }
    if (rome2_test_get_u32(
            context->state_bytes,
            context->new_offset + (size_t)context->old_capacity * 4) !=
            context->expected_handler) {
        return 0;
    }
    for (index = context->old_capacity + UINT32_C(1);
         index < context->new_capacity;
         ++index) {
        if (rome2_test_get_u32(
                context->state_bytes,
                context->new_offset + (size_t)index * 4) !=
                ROME2_TEST_SPARE_SENTINEL) {
            return 0;
        }
    }
    return 1;
}

static rome2_guest_addr32 rome2_test_allocate(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    rome2_test_effect_context *context =
        (rome2_test_effect_context *)opaque_context;
    uint32_t index;

    rome2_test_trace(context, ROME2_TEST_EVENT_ALLOCATE);
    ++context->allocate_calls;
    context->observed_allocation_bytes = byte_count;
    context->observed_allocation_class = allocation_class;
    if (context->trace_count != 1 ||
        context->trace[0] != ROME2_TEST_EVENT_ALLOCATE ||
        context->allocate_calls != 1 || context->release_calls != 0 ||
        context->dispatch_calls != 0 || context->peek_calls != 0 ||
        byte_count != context->expected_allocation_bytes ||
        allocation_class != ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS) {
        ++context->bad_observation_count;
    }
    if (context->inspect_mapped_bytes) {
        if (rome2_test_get_u32(
                context->state_bytes, context->vector_offset) !=
                ROME2_TEST_VECTOR_SENTINEL ||
            rome2_test_get_u32(
                context->state_bytes, context->vector_offset + 4) !=
                context->new_capacity ||
            rome2_test_get_u32(
                context->state_bytes, context->vector_offset + 8) !=
                context->old_capacity ||
            rome2_test_get_u32(
                context->state_bytes, context->vector_offset + 12) !=
                context->expected_old_backing) {
            ++context->bad_observation_count;
        }
        for (index = 0; index < context->old_capacity; ++index) {
            if (rome2_test_get_u32(
                    context->state_bytes,
                    context->old_offset + (size_t)index * 4) !=
                    context->old_values[index]) {
                ++context->bad_observation_count;
                break;
            }
        }
        for (index = 0; index < context->new_capacity; ++index) {
            if (rome2_test_get_u32(
                    context->state_bytes,
                    context->new_offset + (size_t)index * 4) !=
                    ROME2_TEST_SPARE_SENTINEL) {
                ++context->bad_observation_count;
                break;
            }
        }
    }
    return context->allocation_result;
}

static void rome2_test_release(
    void *opaque_context,
    rome2_guest_addr32 allocation)
{
    rome2_test_effect_context *context =
        (rome2_test_effect_context *)opaque_context;

    rome2_test_trace(context, ROME2_TEST_EVENT_RELEASE);
    ++context->release_calls;
    context->observed_release = allocation.value;
    if (context->trace_count != 2 ||
        context->trace[0] != ROME2_TEST_EVENT_ALLOCATE ||
        context->trace[1] != ROME2_TEST_EVENT_RELEASE ||
        context->allocate_calls != 1 || context->release_calls != 1 ||
        context->dispatch_calls != 0 || context->peek_calls != 0 ||
        allocation.value != context->expected_old_backing ||
        !rome2_test_growth_storage_is_ready(context, 0)) {
        ++context->bad_observation_count;
    }
}

static uint32_t rome2_test_dispatch(
    void *opaque_context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 method,
    rome2_guest_addr32 argument)
{
    rome2_test_effect_context *context =
        (rome2_test_effect_context *)opaque_context;

    rome2_test_trace(context, ROME2_TEST_EVENT_DISPATCH);
    ++context->dispatch_calls;
    context->observed_receiver = receiver.value;
    context->observed_method = method.value;
    context->observed_argument = argument.value;
    if (context->trace_count != 3 ||
        context->trace[0] != ROME2_TEST_EVENT_ALLOCATE ||
        context->trace[1] != ROME2_TEST_EVENT_RELEASE ||
        context->trace[2] != ROME2_TEST_EVENT_DISPATCH ||
        context->allocate_calls != 1 || context->release_calls != 1 ||
        context->dispatch_calls != 1 || context->peek_calls != 0 ||
        context->observed_release != context->expected_old_backing ||
        receiver.value != context->expected_handler ||
        method.value != context->expected_method ||
        argument.value != context->expected_argument ||
        !rome2_test_growth_storage_is_ready(context, 1)) {
        ++context->bad_observation_count;
    }
    return context->dispatch_eax;
}

static uint32_t rome2_test_peek(
    void *opaque_context,
    rome2_guest_addr32 message,
    rome2_guest_addr32 window,
    uint32_t filter_min,
    uint32_t filter_max,
    uint32_t remove_flags)
{
    rome2_test_effect_context *context =
        (rome2_test_effect_context *)opaque_context;
    uint32_t value;

    rome2_test_trace(context, ROME2_TEST_EVENT_PEEK);
    ++context->peek_calls;
    if (context->trace_count < 4 || context->allocate_calls != 1 ||
        context->release_calls != 1 || context->dispatch_calls != 1 ||
        message.value != 0 || window.value != 0 || filter_min != 0 ||
        filter_max != 0 ||
        remove_flags != ROME2_PORT_100E2460_PM_REMOVE ||
        context->peek_index >= context->peek_value_count ||
        !rome2_test_growth_storage_is_ready(context, 1)) {
        ++context->bad_observation_count;
    }
    if (context->peek_index >= context->peek_value_count) {
        return 0;
    }
    value = context->peek_values[context->peek_index];
    ++context->peek_index;
    return value;
}

static void rome2_test_setup(
    rome2_test_fixture *fixture,
    uint32_t capacity)
{
    uint32_t index;
    uint32_t old_backing = ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET;
    uint32_t new_backing = ROME2_TEST_STATE_BASE + ROME2_TEST_NEW_OFFSET;
    uint32_t handler = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    uint32_t vtable = ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET;

    memset(fixture, 0, sizeof(*fixture));
    memset(fixture->state.bytes, 0xa5, sizeof(fixture->state.bytes));
    memset(fixture->vtables.bytes, 0x5a, sizeof(fixture->vtables.bytes));
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET,
        ROME2_TEST_VECTOR_SENTINEL);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, capacity);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, capacity);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 12, old_backing);
    for (index = 0; index < capacity; ++index) {
        fixture->context.old_values[index] = rome2_test_old_value(index);
        rome2_test_put_u32(
            fixture->state.bytes,
            ROME2_TEST_OLD_OFFSET + (size_t)index * 4,
            fixture->context.old_values[index]);
    }
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_HANDLER_OFFSET, vtable);
    rome2_test_put_u32(
        fixture->vtables.bytes,
        ROME2_TEST_VTABLE_OFFSET + 4,
        ROME2_TEST_METHOD_IDENTITY);

    fixture->state_view.host_base = fixture->state.bytes;
    fixture->state_view.guest_base = ROME2_TEST_STATE_BASE;
    fixture->state_view.byte_count = sizeof(fixture->state.bytes);
    fixture->vtable_view.host_base = fixture->vtables.bytes;
    fixture->vtable_view.guest_base = ROME2_TEST_VTABLE_BASE;
    fixture->vtable_view.byte_count = sizeof(fixture->vtables.bytes);
    fixture->effects.tail_effects.context = &fixture->context;
    fixture->effects.tail_effects.dispatch = rome2_test_dispatch;
    fixture->effects.tail_effects.peek = rome2_test_peek;
    fixture->effects.allocate = rome2_test_allocate;
    fixture->effects.release = rome2_test_release;

    fixture->context.state_bytes = fixture->state.bytes;
    fixture->context.vector_offset = ROME2_TEST_VECTOR_OFFSET;
    fixture->context.old_offset = ROME2_TEST_OLD_OFFSET;
    fixture->context.new_offset = ROME2_TEST_NEW_OFFSET;
    fixture->context.old_capacity = capacity;
    fixture->context.new_capacity = capacity * UINT32_C(2);
    fixture->context.expected_allocation_bytes = capacity * UINT32_C(8);
    fixture->context.expected_old_backing = old_backing;
    fixture->context.expected_new_backing = new_backing;
    fixture->context.expected_handler = handler;
    fixture->context.expected_method = ROME2_TEST_METHOD_IDENTITY;
    fixture->context.expected_argument = ROME2_TEST_ARGUMENT;
    fixture->context.allocation_result = rome2_test_address(new_backing);
    fixture->context.inspect_mapped_bytes = 1;
}

static int rome2_test_expect_status(
    const char *label,
    rome2_100e2460_branch_status actual,
    rome2_100e2460_branch_status expected)
{
    if (actual == expected) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: status=%d expected=%d\n",
        label, (int)actual, (int)expected);
    return 1;
}

static int rome2_test_effect_table_unchanged(
    const char *label,
    const rome2_100e2460_growth_effects *actual,
    const rome2_100e2460_growth_effects *expected)
{
    if (actual->tail_effects.context == expected->tail_effects.context &&
        actual->tail_effects.dispatch == expected->tail_effects.dispatch &&
        actual->tail_effects.peek == expected->tail_effects.peek &&
        actual->allocate == expected->allocate &&
        actual->release == expected->release) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: effect table changed\n", label);
    return 1;
}

static int rome2_test_success_case(
    const char *label,
    uint32_t capacity,
    size_t new_offset,
    rome2_guest_addr32 argument,
    uint32_t dispatch_eax,
    const uint32_t *peek_values,
    uint32_t peek_value_count,
    uint32_t max_peek_calls,
    rome2_100e2460_branch_status expected_status,
    uint8_t expected_al,
    int output_changes)
{
    rome2_test_fixture fixture;
    rome2_test_state_memory expected_state;
    rome2_test_vtable_memory expected_vtables;
    rome2_guest_write_view expected_state_view;
    rome2_guest_read_view expected_vtable_view;
    rome2_100e2460_growth_effects expected_effects;
    rome2_100e2460_branch_status status;
    uint32_t index;
    uint8_t result = UINT8_C(0xc7);
    int failures = 0;

    rome2_test_setup(&fixture, capacity);
    fixture.context.new_offset = new_offset;
    fixture.context.expected_new_backing =
        ROME2_TEST_STATE_BASE + (uint32_t)new_offset;
    fixture.context.allocation_result = rome2_test_address(
        fixture.context.expected_new_backing);
    fixture.context.expected_argument = argument.value;
    fixture.context.dispatch_eax = dispatch_eax;
    fixture.context.peek_value_count = peek_value_count;
    for (index = 0; index < peek_value_count; ++index) {
        fixture.context.peek_values[index] = peek_values[index];
    }

    expected_state = fixture.state;
    expected_vtables = fixture.vtables;
    expected_state_view = fixture.state_view;
    expected_vtable_view = fixture.vtable_view;
    expected_effects = fixture.effects;
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 4,
        capacity * UINT32_C(2));
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 12,
        fixture.context.expected_new_backing);
    for (index = 0; index < capacity; ++index) {
        rome2_test_put_u32(
            expected_state.bytes, new_offset + (size_t)index * 4,
            fixture.context.old_values[index]);
    }
    rome2_test_put_u32(
        expected_state.bytes, new_offset + (size_t)capacity * 4,
        fixture.context.expected_handler);
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 8,
        capacity + UINT32_C(1));

    status = rome2_port_100e2460_run_growth_branch(
        &fixture.state_view,
        &fixture.vtable_view,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        argument,
        &fixture.effects,
        max_peek_calls,
        &result);
    failures += rome2_test_expect_status(label, status, expected_status);
    if ((output_changes && result != expected_al) ||
        (!output_changes && result != UINT8_C(0xc7)) ||
        memcmp(&fixture.state, &expected_state, sizeof(fixture.state)) != 0 ||
        memcmp(&fixture.vtables, &expected_vtables,
            sizeof(fixture.vtables)) != 0 ||
        fixture.state_view.host_base != expected_state_view.host_base ||
        fixture.state_view.guest_base != expected_state_view.guest_base ||
        fixture.state_view.byte_count != expected_state_view.byte_count ||
        fixture.vtable_view.host_base != expected_vtable_view.host_base ||
        fixture.vtable_view.guest_base != expected_vtable_view.guest_base ||
        fixture.vtable_view.byte_count != expected_vtable_view.byte_count) {
        fprintf(stderr, "FAIL %s: exact byte/view/output oracle differs\n", label);
        ++failures;
    }
    failures += rome2_test_effect_table_unchanged(
        label, &fixture.effects, &expected_effects);
    if (fixture.context.allocate_calls != 1 ||
        fixture.context.release_calls != 1 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != peek_value_count ||
        fixture.context.peek_index != peek_value_count ||
        fixture.context.trace_count != peek_value_count + UINT32_C(3) ||
        fixture.context.trace[0] != ROME2_TEST_EVENT_ALLOCATE ||
        fixture.context.trace[1] != ROME2_TEST_EVENT_RELEASE ||
        fixture.context.trace[2] != ROME2_TEST_EVENT_DISPATCH ||
        fixture.context.observed_allocation_bytes != capacity * UINT32_C(8) ||
        fixture.context.observed_allocation_class !=
            ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS ||
        fixture.context.observed_release != fixture.context.expected_old_backing ||
        fixture.context.observed_receiver != fixture.context.expected_handler ||
        fixture.context.observed_method != fixture.context.expected_method ||
        fixture.context.observed_argument != argument.value ||
        fixture.context.bad_observation_count != 0) {
        fprintf(stderr, "FAIL %s: effect order/arguments/state visibility differ\n",
            label);
        ++failures;
    }
    for (index = 3; index < fixture.context.trace_count; ++index) {
        if (fixture.context.trace[index] != ROME2_TEST_EVENT_PEEK) {
            fprintf(stderr, "FAIL %s: Peek trace order differs\n", label);
            ++failures;
            break;
        }
    }
    return failures;
}

static int rome2_test_success_and_drain(void)
{
    static const uint32_t empty_queue[] = {UINT32_C(0)};
    static const uint32_t multi_queue[] = {
        UINT32_C(1), UINT32_C(0x80000000), UINT32_C(0)
    };
    static const uint32_t final_false[] = {UINT32_C(7), UINT32_C(0)};
    static const uint32_t exhausted[] = {UINT32_C(1)};
    int failures = 0;

    failures += rome2_test_success_case(
        "capacity one grows, copies, releases, and drains",
        1, ROME2_TEST_NEW_OFFSET, rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0x123456a5), empty_queue, 1, 1,
        ROME2_100E2460_BRANCH_OK, UINT8_C(0xa5), 1);
    failures += rome2_test_success_case(
        "capacity greater than one preserves spare cells and nonzero Peek",
        3, ROME2_TEST_NEW_OFFSET, rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0xabcdefff), multi_queue, 3, 3,
        ROME2_100E2460_BRANCH_OK, UINT8_C(0xff), 1);
    failures += rome2_test_success_case(
        "opaque zero argument and zero low AL are preserved",
        2, ROME2_TEST_NEW_OFFSET, rome2_test_address(0),
        UINT32_C(0x12340000), final_false, 2, 2,
        ROME2_100E2460_BRANCH_OK, UINT8_C(0), 1);
    failures += rome2_test_success_case(
        "unaligned new span is byte-addressable",
        3, ROME2_TEST_NEW_OFFSET + 1, rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0x55), empty_queue, 1, 1,
        ROME2_100E2460_BRANCH_OK, UINT8_C(0x55), 1);
    failures += rome2_test_success_case(
        "new span ends exactly at state view end",
        3, ROME2_TEST_STATE_BYTES - 24,
        rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0x66), empty_queue, 1, 1,
        ROME2_100E2460_BRANCH_OK, UINT8_C(0x66), 1);
    failures += rome2_test_success_case(
        "new span begins exactly at vector end",
        2, ROME2_TEST_VECTOR_OFFSET + ROME2_PORT_100E2460_VECTOR_BYTES,
        rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0x77), empty_queue, 1, 1,
        ROME2_100E2460_BRANCH_OK, UINT8_C(0x77), 1);
    failures += rome2_test_success_case(
        "one-call DRAIN_LIMIT keeps growth and effects committed",
        3, ROME2_TEST_NEW_OFFSET, rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0x1234565a), exhausted, 1, 1,
        ROME2_100E2460_BRANCH_DRAIN_LIMIT, UINT8_C(0), 0);
    return failures;
}

static int rome2_test_invalid_allocation_result(
    const char *label,
    rome2_test_fixture *fixture,
    rome2_guest_addr32 allocation_result)
{
    rome2_test_state_memory expected_state = fixture->state;
    rome2_test_vtable_memory expected_vtables = fixture->vtables;
    rome2_guest_write_view expected_state_view = fixture->state_view;
    rome2_guest_read_view expected_vtable_view = fixture->vtable_view;
    rome2_100e2460_growth_effects expected_effects = fixture->effects;
    rome2_100e2460_branch_status status;
    uint8_t result = UINT8_C(0xc7);
    int failures = 0;

    fixture->context.allocation_result = allocation_result;
    fixture->context.inspect_mapped_bytes = 0;
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 4,
        fixture->context.new_capacity);
    status = rome2_port_100e2460_run_growth_branch(
        &fixture->state_view,
        &fixture->vtable_view,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        rome2_test_address(ROME2_TEST_ARGUMENT),
        &fixture->effects,
        3,
        &result);
    failures += rome2_test_expect_status(
        label, status, ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID);
    if (result != UINT8_C(0xc7) ||
        memcmp(&fixture->state, &expected_state, sizeof(fixture->state)) != 0 ||
        memcmp(&fixture->vtables, &expected_vtables,
            sizeof(fixture->vtables)) != 0 ||
        fixture->state_view.host_base != expected_state_view.host_base ||
        fixture->state_view.guest_base != expected_state_view.guest_base ||
        fixture->state_view.byte_count != expected_state_view.byte_count ||
        fixture->vtable_view.host_base != expected_vtable_view.host_base ||
        fixture->vtable_view.guest_base != expected_vtable_view.guest_base ||
        fixture->vtable_view.byte_count != expected_vtable_view.byte_count) {
        fprintf(stderr, "FAIL %s: capacity-only partial commit differs\n", label);
        ++failures;
    }
    failures += rome2_test_effect_table_unchanged(
        label, &fixture->effects, &expected_effects);
    if (fixture->context.allocate_calls != 1 ||
        fixture->context.release_calls != 0 ||
        fixture->context.dispatch_calls != 0 ||
        fixture->context.peek_calls != 0 || fixture->context.peek_index != 0 ||
        fixture->context.trace_count != 1 ||
        fixture->context.trace[0] != ROME2_TEST_EVENT_ALLOCATE ||
        fixture->context.observed_allocation_bytes !=
            fixture->context.expected_allocation_bytes ||
        fixture->context.observed_allocation_class !=
            ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS ||
        fixture->context.bad_observation_count != 0) {
        fprintf(stderr, "FAIL %s: invalid-result effect boundary differs\n", label);
        ++failures;
    }
    return failures;
}

static void rome2_test_logical_method_at(
    rome2_test_fixture *fixture,
    size_t state_offset)
{
    uint32_t method_guest = ROME2_TEST_STATE_BASE + (uint32_t)state_offset;

    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_HANDLER_OFFSET,
        method_guest - UINT32_C(4));
    fixture->vtable_view.guest_base = ROME2_TEST_STATE_BASE;
    rome2_test_put_u32(
        fixture->vtables.bytes, state_offset, ROME2_TEST_METHOD_IDENTITY);
}

static void rome2_test_physical_method_at(
    rome2_test_fixture *fixture,
    size_t state_offset)
{
    uint32_t method_guest =
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET + UINT32_C(4);

    fixture->vtable_view.host_base = fixture->state.bytes;
    fixture->vtable_view.guest_base =
        method_guest - (uint32_t)state_offset;
    fixture->vtable_view.byte_count = sizeof(fixture->state.bytes);
}

static int rome2_test_invalid_allocation_results(void)
{
    rome2_test_fixture fixture;
    uint32_t bytes;
    int failures = 0;

    rome2_test_setup(&fixture, 3);
    bytes = fixture.context.expected_allocation_bytes;
    failures += rome2_test_invalid_allocation_result(
        "null growth allocation result", &fixture, rome2_test_address(0));

    rome2_test_setup(&fixture, 3);
    failures += rome2_test_invalid_allocation_result(
        "growth allocation result below state view", &fixture,
        rome2_test_address(ROME2_TEST_STATE_BASE - UINT32_C(1)));

    rome2_test_setup(&fixture, 3);
    failures += rome2_test_invalid_allocation_result(
        "growth allocation result guest span overflows", &fixture,
        rome2_test_address(UINT32_MAX - UINT32_C(4)));

    rome2_test_setup(&fixture, 3);
    failures += rome2_test_invalid_allocation_result(
        "growth allocation result is truncated at view end", &fixture,
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES - bytes + 1));

    rome2_test_setup(&fixture, 3);
    failures += rome2_test_invalid_allocation_result(
        "growth allocation result overlaps vector by one byte", &fixture,
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET - bytes + 1));

    rome2_test_setup(&fixture, 3);
    failures += rome2_test_invalid_allocation_result(
        "growth allocation result aliases old span", &fixture,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET));

    rome2_test_setup(&fixture, 3);
    failures += rome2_test_invalid_allocation_result(
        "growth allocation result aliases handler", &fixture,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET));

    rome2_test_setup(&fixture, 3);
    rome2_test_logical_method_at(&fixture, ROME2_TEST_NEW_OFFSET);
    failures += rome2_test_invalid_allocation_result(
        "growth allocation result logically aliases method", &fixture,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_NEW_OFFSET));

    rome2_test_setup(&fixture, 3);
    rome2_test_physical_method_at(&fixture, ROME2_TEST_NEW_OFFSET);
    failures += rome2_test_invalid_allocation_result(
        "growth allocation result physically aliases method", &fixture,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_NEW_OFFSET));
    return failures;
}

static int rome2_test_precommit_failure(
    const char *label,
    rome2_test_fixture *fixture,
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 vector,
    rome2_guest_addr32 handler,
    const rome2_100e2460_growth_effects *effects,
    uint32_t max_peek_calls,
    uint8_t *result_out,
    rome2_100e2460_branch_status expected_status)
{
    rome2_test_fixture snapshot = *fixture;
    uint8_t result_snapshot = result_out == NULL ? 0 : *result_out;
    rome2_100e2460_branch_status status;
    int failures = 0;

    status = rome2_port_100e2460_run_growth_branch(
        state_view,
        vtable_view,
        vector,
        handler,
        rome2_test_address(ROME2_TEST_ARGUMENT),
        effects,
        max_peek_calls,
        result_out);
    failures += rome2_test_expect_status(label, status, expected_status);
    if (memcmp(fixture, &snapshot, sizeof(*fixture)) != 0 ||
        (result_out != NULL && *result_out != result_snapshot)) {
        fprintf(stderr, "FAIL %s: precommit state/effect/output changed\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_precommit_basics(void)
{
    rome2_test_fixture fixture;
    rome2_guest_addr32 vector = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET);
    rome2_guest_addr32 handler = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET);
    uint8_t result;
    int failures = 0;

#define ROME2_RESET() \
    do { rome2_test_setup(&fixture, 3); result = UINT8_C(0xc7); } while (0)
#define ROME2_FAIL(label, expected) \
    (failures += rome2_test_precommit_failure( \
        (label), &fixture, &fixture.state_view, &fixture.vtable_view, \
        vector, handler, &fixture.effects, 3, &result, (expected)))

    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "null growth state view", &fixture, NULL, &fixture.vtable_view,
        vector, handler, &fixture.effects, 3, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "null growth vtable view", &fixture, &fixture.state_view, NULL,
        vector, handler, &fixture.effects, 3, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "null growth effects", &fixture, &fixture.state_view,
        &fixture.vtable_view, vector, handler, NULL, 3, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "null growth output", &fixture, &fixture.state_view,
        &fixture.vtable_view, vector, handler, &fixture.effects, 3, NULL,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET(); fixture.effects.allocate = NULL;
    ROME2_FAIL("null growth allocation adapter", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET(); fixture.effects.release = NULL;
    ROME2_FAIL("null growth release adapter", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET(); fixture.effects.tail_effects.dispatch = NULL;
    ROME2_FAIL("null growth dispatch adapter", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET(); fixture.effects.tail_effects.peek = NULL;
    ROME2_FAIL("null growth Peek adapter", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "zero growth drain budget", &fixture, &fixture.state_view,
        &fixture.vtable_view, vector, handler, &fixture.effects, 0, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET(); fixture.state_view.host_base = NULL;
    ROME2_FAIL("null growth state host", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET(); fixture.vtable_view.host_base = NULL;
    ROME2_FAIL("null growth vtable host", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET(); fixture.state_view.guest_base = UINT32_MAX - UINT32_C(7);
    fixture.state_view.byte_count = 9;
    ROME2_FAIL("growth state guest end overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    ROME2_RESET(); fixture.vtable_view.guest_base = UINT32_MAX - UINT32_C(7);
    fixture.vtable_view.byte_count = 9;
    ROME2_FAIL("growth vtable guest end overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);

    ROME2_RESET(); vector.value = 0;
    ROME2_FAIL("null growth vector", ROME2_100E2460_BRANCH_NULL_ADDRESS);
    vector.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;
    ROME2_RESET(); vector.value = ROME2_TEST_STATE_BASE - UINT32_C(1);
    ROME2_FAIL("growth vector below state view",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    vector.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;
    ROME2_RESET(); vector.value = UINT32_MAX - UINT32_C(14);
    ROME2_FAIL("growth vector guest end overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    vector.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;
    ROME2_RESET(); vector.value =
        ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES - UINT32_C(15);
    ROME2_FAIL("truncated growth vector", ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    vector.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;

    ROME2_RESET();
    rome2_test_put_u32(fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 0);
    ROME2_FAIL("zero capacity belongs to capacity-zero route",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 2);
    ROME2_FAIL("count below capacity belongs to preallocated route",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 4);
    ROME2_FAIL("count above capacity is malformed growth state",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 4,
        ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY);
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8,
        ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY);
    ROME2_FAIL("maximum safe capacity reaches old-span validation",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 4,
        ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY + UINT32_C(1));
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8,
        ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY + UINT32_C(1));
    ROME2_FAIL("capacity above safe doubled-byte boundary",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);

    ROME2_RESET();
    rome2_test_put_u32(fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 12, 0);
    ROME2_FAIL("null old growth backing", ROME2_100E2460_BRANCH_NULL_ADDRESS);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 12,
        ROME2_TEST_STATE_BASE - UINT32_C(1));
    ROME2_FAIL("old growth span below state view",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 12,
        UINT32_MAX - UINT32_C(4));
    ROME2_FAIL("old growth span guest overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 12,
        ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES - UINT32_C(8));
    ROME2_FAIL("truncated old growth span",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);

    ROME2_RESET(); handler.value = 0;
    ROME2_FAIL("null growth handler", ROME2_100E2460_BRANCH_NULL_ADDRESS);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    ROME2_RESET(); handler.value = ROME2_TEST_STATE_BASE - UINT32_C(1);
    ROME2_FAIL("growth handler below state view",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    ROME2_RESET(); handler.value =
        ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES - UINT32_C(3);
    ROME2_FAIL("truncated growth handler",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    ROME2_RESET();
    rome2_test_put_u32(fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET, 0);
    ROME2_FAIL("null growth vtable identity", ROME2_100E2460_BRANCH_NULL_ADDRESS);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET,
        UINT32_MAX - UINT32_C(3));
    ROME2_FAIL("growth vtable plus four overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET,
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_BYTES - UINT32_C(7));
    ROME2_FAIL("truncated growth method cell",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.vtables.bytes, ROME2_TEST_VTABLE_OFFSET + 4, 0);
    ROME2_FAIL("null growth method identity", ROME2_100E2460_BRANCH_NULL_ADDRESS);

#undef ROME2_FAIL
#undef ROME2_RESET
    return failures;
}

static int rome2_test_precommit_plan_aliases(void)
{
    rome2_test_fixture fixture;
    rome2_guest_addr32 vector = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET);
    rome2_guest_addr32 handler = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET);
    uint32_t method_guest;
    uint8_t result;
    int failures = 0;

#define ROME2_RESET() \
    do { rome2_test_setup(&fixture, 3); result = UINT8_C(0xc7); } while (0)
#define ROME2_ALIAS_FAIL(label) \
    (failures += rome2_test_precommit_failure( \
        (label), &fixture, &fixture.state_view, &fixture.vtable_view, \
        vector, handler, &fixture.effects, 3, &result, \
        ROME2_100E2460_BRANCH_BAD_ARGUMENT))

    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 12,
        ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET);
    ROME2_ALIAS_FAIL("growth vector and old span alias");

    ROME2_RESET();
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET,
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET);
    ROME2_ALIAS_FAIL("growth vector and handler alias");
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;

    ROME2_RESET();
    rome2_test_logical_method_at(&fixture, ROME2_TEST_VECTOR_OFFSET);
    ROME2_ALIAS_FAIL("growth vector and method logically alias");
    ROME2_RESET();
    rome2_test_physical_method_at(&fixture, ROME2_TEST_VECTOR_OFFSET);
    ROME2_ALIAS_FAIL("growth vector and method physically alias");

    ROME2_RESET();
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET;
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_OLD_OFFSET,
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET);
    ROME2_ALIAS_FAIL("growth old span and handler alias");
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;

    ROME2_RESET();
    rome2_test_logical_method_at(&fixture, ROME2_TEST_OLD_OFFSET);
    ROME2_ALIAS_FAIL("growth old span and method logically alias");
    ROME2_RESET();
    rome2_test_physical_method_at(&fixture, ROME2_TEST_OLD_OFFSET);
    ROME2_ALIAS_FAIL("growth old span and method physically alias");

    ROME2_RESET();
    method_guest = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET,
        method_guest - UINT32_C(4));
    fixture.vtable_view.guest_base = ROME2_TEST_STATE_BASE;
    rome2_test_put_u32(
        fixture.vtables.bytes, ROME2_TEST_HANDLER_OFFSET,
        ROME2_TEST_METHOD_IDENTITY);
    ROME2_ALIAS_FAIL("growth handler and method logically alias");
    ROME2_RESET();
    rome2_test_physical_method_at(&fixture, ROME2_TEST_HANDLER_OFFSET);
    ROME2_ALIAS_FAIL("growth handler and method physically alias");

#undef ROME2_ALIAS_FAIL
#undef ROME2_RESET
    return failures;
}

static int rome2_test_control_aliases(void)
{
    rome2_test_fixture fixture;
    rome2_guest_addr32 vector = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET);
    rome2_guest_addr32 handler = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET);
    rome2_guest_write_view bad_state_view;
    rome2_guest_read_view bad_vtable_view;
    uint8_t result;
    int failures = 0;

#define ROME2_RESET() \
    do { rome2_test_setup(&fixture, 3); result = UINT8_C(0xc7); } while (0)
#define ROME2_CONTROL_FAIL(label, state_arg, vtable_arg, effects_arg, output_arg) \
    (failures += rome2_test_precommit_failure( \
        (label), &fixture, (state_arg), (vtable_arg), vector, handler, \
        (effects_arg), 3, (output_arg), ROME2_100E2460_BRANCH_BAD_ARGUMENT))

    ROME2_RESET();
    ROME2_CONTROL_FAIL(
        "growth state and vtable descriptors alias",
        &fixture.state_view,
        (const rome2_guest_read_view *)(const void *)&fixture.state_view,
        &fixture.effects,
        &result);
    ROME2_RESET();
    ROME2_CONTROL_FAIL(
        "growth state descriptor and effects alias",
        &fixture.state_view,
        &fixture.vtable_view,
        (const rome2_100e2460_growth_effects *)(const void *)&fixture.state_view,
        &result);
    ROME2_RESET();
    ROME2_CONTROL_FAIL(
        "growth vtable descriptor and effects alias",
        &fixture.state_view,
        &fixture.vtable_view,
        (const rome2_100e2460_growth_effects *)(const void *)&fixture.vtable_view,
        &result);
    ROME2_RESET();
    ROME2_CONTROL_FAIL(
        "growth output aliases state descriptor",
        &fixture.state_view, &fixture.vtable_view, &fixture.effects,
        (uint8_t *)(void *)&fixture.state_view);
    ROME2_RESET();
    ROME2_CONTROL_FAIL(
        "growth output aliases vtable descriptor",
        &fixture.state_view, &fixture.vtable_view, &fixture.effects,
        (uint8_t *)(void *)&fixture.vtable_view);
    ROME2_RESET();
    ROME2_CONTROL_FAIL(
        "growth output aliases effects table",
        &fixture.state_view, &fixture.vtable_view, &fixture.effects,
        (uint8_t *)(void *)&fixture.effects);

    ROME2_RESET();
    bad_state_view = fixture.state_view;
    bad_state_view.host_base = (uint8_t *)(void *)&bad_state_view;
    bad_state_view.byte_count = sizeof(bad_state_view);
    ROME2_CONTROL_FAIL(
        "growth state bytes alias state descriptor",
        &bad_state_view, &fixture.vtable_view, &fixture.effects, &result);
    ROME2_RESET();
    bad_state_view = fixture.state_view;
    bad_state_view.host_base = (uint8_t *)(void *)&fixture.vtable_view;
    bad_state_view.byte_count = sizeof(fixture.vtable_view);
    ROME2_CONTROL_FAIL(
        "growth state bytes alias vtable descriptor",
        &bad_state_view, &fixture.vtable_view, &fixture.effects, &result);
    ROME2_RESET();
    bad_state_view = fixture.state_view;
    bad_state_view.host_base = (uint8_t *)(void *)&fixture.effects;
    bad_state_view.byte_count = sizeof(fixture.effects);
    ROME2_CONTROL_FAIL(
        "growth state bytes alias effects table",
        &bad_state_view, &fixture.vtable_view, &fixture.effects, &result);
    ROME2_RESET();
    ROME2_CONTROL_FAIL(
        "growth output aliases state bytes",
        &fixture.state_view, &fixture.vtable_view, &fixture.effects,
        &fixture.state.bytes[0]);
    ROME2_RESET();
    ROME2_CONTROL_FAIL(
        "growth output aliases vtable bytes",
        &fixture.state_view, &fixture.vtable_view, &fixture.effects,
        &fixture.vtables.bytes[0]);

    ROME2_RESET();
    bad_vtable_view = fixture.vtable_view;
    bad_vtable_view.host_base = fixture.state.bytes;
    bad_vtable_view.guest_base = ROME2_TEST_VTABLE_BASE;
    bad_vtable_view.byte_count = sizeof(fixture.state.bytes);
    /* Read-only vtable/state overlap is admissible except at borrowed cells;
     * this setup itself is not an error and is exercised by physical cases. */
    if (bad_vtable_view.host_base != fixture.state.bytes) {
        fprintf(stderr, "FAIL growth physical-view setup\n");
        ++failures;
    }

#undef ROME2_CONTROL_FAIL
#undef ROME2_RESET
    return failures;
}

static int rome2_test_by_value_source_boundary(void)
{
    rome2_guest_addr32 by_value_handler =
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET);

    /* There is deliberately no source-cell guest address in the API.  The
     * original &param_1/native-stack self-alias route therefore cannot be
     * requested; only these four opaque by-value bits cross the boundary. */
    if (sizeof(by_value_handler) != 4 ||
        by_value_handler.value !=
            ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET) {
        fprintf(stderr,
            "FAIL source-stack self-alias route excluded by by-value contract\n");
        return 1;
    }
    return 0;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_success_and_drain();
    failures += rome2_test_invalid_allocation_results();
    failures += rome2_test_precommit_basics();
    failures += rome2_test_precommit_plan_aliases();
    failures += rome2_test_control_aliases();
    failures += rome2_test_by_value_source_boundary();
    if (failures != 0) {
        fprintf(stderr,
            "startup 100e2460 growth-branch tests: %d failure(s)\n",
            failures);
        return 1;
    }
    puts("startup 100e2460 growth-branch tests: pass");
    return 0;
}

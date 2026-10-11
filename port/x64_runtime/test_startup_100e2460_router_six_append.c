#include "ported_100e2460_router.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_STATE_BASE UINT32_C(0x10000)
#define ROME2_TEST_STATE_BYTES 8192
#define ROME2_TEST_VECTOR_OFFSET UINT32_C(0x40)
#define ROME2_TEST_BUFFER_A_OFFSET UINT32_C(0x200)
#define ROME2_TEST_BUFFER_B_OFFSET UINT32_C(0x300)
#define ROME2_TEST_BUFFER_C_OFFSET UINT32_C(0x400)
#define ROME2_TEST_BUFFER_D_OFFSET UINT32_C(0x500)
#define ROME2_TEST_HANDLER_OFFSET UINT32_C(0x800)
#define ROME2_TEST_HANDLER_STRIDE UINT32_C(0x10)
#define ROME2_TEST_VTABLE_BASE UINT32_C(0x30000000)
#define ROME2_TEST_VTABLE_BYTES 256
#define ROME2_TEST_VTABLE_OFFSET UINT32_C(0x20)
#define ROME2_TEST_METHOD UINT32_C(0x100e9340)
#define ROME2_TEST_ARGUMENT_BASE UINT32_C(0x2824)
#define ROME2_TEST_VECTOR_SENTINEL UINT32_C(0xfeedface)
#define ROME2_TEST_SPARE UINT32_C(0xa5a5a5a5)
#define ROME2_TEST_APPEND_COUNT 6
#define ROME2_TEST_ALLOCATION_COUNT 4
#define ROME2_TEST_RELEASE_COUNT 3
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
    const uint8_t *state_bytes;
    uint32_t handlers[ROME2_TEST_APPEND_COUNT];
    uint32_t allocation_results[ROME2_TEST_ALLOCATION_COUNT];
    uint32_t current_append;
    uint32_t allocate_calls_at_start;
    uint32_t release_calls_at_start;
    uint32_t dispatch_calls_at_start;
    uint32_t peek_calls_at_start;
    uint32_t allocate_calls;
    uint32_t release_calls;
    uint32_t dispatch_calls;
    uint32_t peek_calls;
    uint32_t allocation_bytes[ROME2_TEST_ALLOCATION_COUNT];
    uint32_t allocation_classes[ROME2_TEST_ALLOCATION_COUNT];
    uint32_t released_identities[ROME2_TEST_RELEASE_COUNT];
    uint32_t dispatched_receivers[ROME2_TEST_APPEND_COUNT];
    uint32_t dispatched_methods[ROME2_TEST_APPEND_COUNT];
    uint32_t dispatched_arguments[ROME2_TEST_APPEND_COUNT];
    uint32_t events[ROME2_TEST_MAX_EVENTS];
    uint32_t event_count;
    uint32_t bad_observations;
} rome2_test_effect_context;

typedef struct rome2_test_fixture {
    rome2_test_state_memory state;
    rome2_test_vtable_memory vtables;
    rome2_guest_write_view state_view;
    rome2_guest_read_view vtable_view;
    rome2_100e2460_growth_effects effects;
    rome2_test_effect_context context;
} rome2_test_fixture;

static const uint32_t rome2_test_expected_capacities[
    ROME2_TEST_APPEND_COUNT] = {1, 2, 4, 4, 8, 8};
static const uint32_t rome2_test_expected_counts[
    ROME2_TEST_APPEND_COUNT] = {1, 2, 3, 4, 5, 6};
static const uint32_t rome2_test_expected_backing_offsets[
    ROME2_TEST_APPEND_COUNT] = {
        ROME2_TEST_BUFFER_A_OFFSET,
        ROME2_TEST_BUFFER_B_OFFSET,
        ROME2_TEST_BUFFER_C_OFFSET,
        ROME2_TEST_BUFFER_C_OFFSET,
        ROME2_TEST_BUFFER_D_OFFSET,
        ROME2_TEST_BUFFER_D_OFFSET,
    };
static const uint32_t rome2_test_expected_allocate_delta[
    ROME2_TEST_APPEND_COUNT] = {1, 1, 1, 0, 1, 0};
static const uint32_t rome2_test_expected_release_delta[
    ROME2_TEST_APPEND_COUNT] = {0, 1, 1, 0, 1, 0};
static const uint32_t rome2_test_allocation_append[
    ROME2_TEST_ALLOCATION_COUNT] = {0, 1, 2, 4};
static const uint32_t rome2_test_allocation_bytes[
    ROME2_TEST_ALLOCATION_COUNT] = {4, 8, 16, 32};
static const uint32_t rome2_test_allocation_capacity[
    ROME2_TEST_ALLOCATION_COUNT] = {1, 2, 4, 8};
static const uint32_t rome2_test_allocation_count_before[
    ROME2_TEST_ALLOCATION_COUNT] = {0, 1, 2, 4};
static const uint32_t rome2_test_release_append[
    ROME2_TEST_RELEASE_COUNT] = {1, 2, 4};

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

static uint32_t rome2_test_guest_from_offset(uint32_t offset)
{
    return ROME2_TEST_STATE_BASE + offset;
}

static int rome2_test_buffer_shape(
    uint32_t backing,
    size_t *offset_out,
    uint32_t *capacity_out)
{
    uint32_t offset;

    if (backing < ROME2_TEST_STATE_BASE) {
        return 0;
    }
    offset = backing - ROME2_TEST_STATE_BASE;
    switch (offset) {
    case ROME2_TEST_BUFFER_A_OFFSET:
        *offset_out = ROME2_TEST_BUFFER_A_OFFSET;
        *capacity_out = 1;
        return 1;
    case ROME2_TEST_BUFFER_B_OFFSET:
        *offset_out = ROME2_TEST_BUFFER_B_OFFSET;
        *capacity_out = 2;
        return 1;
    case ROME2_TEST_BUFFER_C_OFFSET:
        *offset_out = ROME2_TEST_BUFFER_C_OFFSET;
        *capacity_out = 4;
        return 1;
    case ROME2_TEST_BUFFER_D_OFFSET:
        *offset_out = ROME2_TEST_BUFFER_D_OFFSET;
        *capacity_out = 8;
        return 1;
    default:
        return 0;
    }
}

static int rome2_test_buffer_is_ordered(
    const rome2_test_effect_context *context,
    uint32_t backing,
    uint32_t populated_count)
{
    size_t offset;
    uint32_t capacity;
    uint32_t index;

    if (!rome2_test_buffer_shape(backing, &offset, &capacity) ||
        populated_count > capacity) {
        return 0;
    }
    for (index = 0; index < populated_count; ++index) {
        if (rome2_test_get_u32(
                context->state_bytes, offset + (size_t)index * 4) !=
            context->handlers[index]) {
            return 0;
        }
    }
    for (index = populated_count; index < capacity; ++index) {
        if (rome2_test_get_u32(
                context->state_bytes, offset + (size_t)index * 4) !=
            ROME2_TEST_SPARE) {
            return 0;
        }
    }
    return 1;
}

static int rome2_test_buffer_is_spare(
    const rome2_test_effect_context *context,
    uint32_t backing)
{
    return rome2_test_buffer_is_ordered(context, backing, 0);
}

static uint32_t rome2_test_vector_capacity(
    const rome2_test_effect_context *context)
{
    return rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_VECTOR_OFFSET + 4);
}

static uint32_t rome2_test_vector_count(
    const rome2_test_effect_context *context)
{
    return rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_VECTOR_OFFSET + 8);
}

static uint32_t rome2_test_vector_backing(
    const rome2_test_effect_context *context)
{
    return rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_VECTOR_OFFSET + 12);
}

static void rome2_test_record_event(
    rome2_test_effect_context *context,
    uint32_t event)
{
    if (context->event_count >= ROME2_TEST_MAX_EVENTS) {
        ++context->bad_observations;
        return;
    }
    context->events[context->event_count] = event;
    ++context->event_count;
}

static rome2_guest_addr32 rome2_test_allocate(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    rome2_test_effect_context *context =
        (rome2_test_effect_context *)opaque_context;
    uint32_t allocation_index = context->allocate_calls;
    rome2_guest_addr32 result = {0};

    rome2_test_record_event(context, ROME2_TEST_EVENT_ALLOCATE);
    if (allocation_index >= ROME2_TEST_ALLOCATION_COUNT) {
        ++context->bad_observations;
        return result;
    }
    context->allocation_bytes[allocation_index] = byte_count;
    context->allocation_classes[allocation_index] = allocation_class;
    ++context->allocate_calls;
    result.value = context->allocation_results[allocation_index];
    if (context->current_append !=
            rome2_test_allocation_append[allocation_index] ||
        context->allocate_calls != context->allocate_calls_at_start + 1 ||
        context->release_calls != context->release_calls_at_start ||
        context->dispatch_calls != context->dispatch_calls_at_start ||
        context->peek_calls != context->peek_calls_at_start ||
        byte_count != rome2_test_allocation_bytes[allocation_index] ||
        allocation_class != ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS ||
        rome2_test_vector_capacity(context) !=
            rome2_test_allocation_capacity[allocation_index] ||
        rome2_test_vector_count(context) !=
            rome2_test_allocation_count_before[allocation_index] ||
        !rome2_test_buffer_is_spare(context, result.value)) {
        ++context->bad_observations;
    }
    if (allocation_index == 0) {
        if (rome2_test_vector_backing(context) != 0) {
            ++context->bad_observations;
        }
    } else if (rome2_test_vector_backing(context) !=
        context->allocation_results[allocation_index - 1]) {
        ++context->bad_observations;
    }
    return result;
}

static void rome2_test_release(
    void *opaque_context,
    rome2_guest_addr32 allocation)
{
    rome2_test_effect_context *context =
        (rome2_test_effect_context *)opaque_context;
    uint32_t release_index = context->release_calls;
    uint32_t new_backing = rome2_test_vector_backing(context);
    uint32_t old_capacity;
    size_t old_offset;

    rome2_test_record_event(context, ROME2_TEST_EVENT_RELEASE);
    if (release_index >= ROME2_TEST_RELEASE_COUNT) {
        ++context->bad_observations;
        return;
    }
    context->released_identities[release_index] = allocation.value;
    ++context->release_calls;
    if (context->current_append != rome2_test_release_append[release_index] ||
        context->allocate_calls != context->allocate_calls_at_start + 1 ||
        context->release_calls != context->release_calls_at_start + 1 ||
        context->dispatch_calls != context->dispatch_calls_at_start ||
        context->peek_calls != context->peek_calls_at_start ||
        allocation.value != context->allocation_results[release_index] ||
        new_backing != context->allocation_results[release_index + 1] ||
        rome2_test_vector_capacity(context) !=
            rome2_test_expected_capacities[context->current_append] ||
        rome2_test_vector_count(context) != context->current_append ||
        !rome2_test_buffer_is_ordered(
            context, new_backing, context->current_append + 1) ||
        !rome2_test_buffer_shape(
            allocation.value, &old_offset, &old_capacity) ||
        old_capacity != context->current_append ||
        !rome2_test_buffer_is_ordered(
            context, allocation.value, context->current_append)) {
        ++context->bad_observations;
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
    uint32_t append = context->current_append;
    uint32_t dispatch_index = context->dispatch_calls;
    uint32_t expected_backing;

    rome2_test_record_event(context, ROME2_TEST_EVENT_DISPATCH);
    if (append >= ROME2_TEST_APPEND_COUNT) {
        ++context->dispatch_calls;
        ++context->bad_observations;
        return UINT32_C(0x900000a1);
    }
    expected_backing = rome2_test_guest_from_offset(
        rome2_test_expected_backing_offsets[append]);
    if (dispatch_index < ROME2_TEST_APPEND_COUNT) {
        context->dispatched_receivers[dispatch_index] = receiver.value;
        context->dispatched_methods[dispatch_index] = method.value;
        context->dispatched_arguments[dispatch_index] = argument.value;
    } else {
        ++context->bad_observations;
    }
    ++context->dispatch_calls;
    if (dispatch_index != append ||
        context->allocate_calls != context->allocate_calls_at_start +
            rome2_test_expected_allocate_delta[append] ||
        context->release_calls != context->release_calls_at_start +
            rome2_test_expected_release_delta[append] ||
        context->dispatch_calls != context->dispatch_calls_at_start + 1 ||
        context->peek_calls != context->peek_calls_at_start ||
        rome2_test_vector_capacity(context) !=
            rome2_test_expected_capacities[append] ||
        rome2_test_vector_count(context) !=
            rome2_test_expected_counts[append] ||
        rome2_test_vector_backing(context) != expected_backing ||
        !rome2_test_buffer_is_ordered(
            context, expected_backing, rome2_test_expected_counts[append]) ||
        receiver.value != context->handlers[append] ||
        method.value != ROME2_TEST_METHOD ||
        argument.value != ROME2_TEST_ARGUMENT_BASE + append) {
        ++context->bad_observations;
    }
    return UINT32_C(0x900000a1) + append;
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
    uint32_t append = context->current_append;

    rome2_test_record_event(context, ROME2_TEST_EVENT_PEEK);
    ++context->peek_calls;
    if (append >= ROME2_TEST_APPEND_COUNT) {
        ++context->bad_observations;
        return 0;
    }
    if (context->dispatch_calls != context->dispatch_calls_at_start + 1 ||
        context->peek_calls != context->peek_calls_at_start + 1 ||
        rome2_test_vector_count(context) !=
            rome2_test_expected_counts[append] ||
        message.value != 0 || window.value != 0 || filter_min != 0 ||
        filter_max != 0 ||
        remove_flags != ROME2_PORT_100E2460_PM_REMOVE) {
        ++context->bad_observations;
    }
    return 0;
}

static void rome2_test_initialize_buffer(
    uint8_t *state_bytes,
    uint32_t offset,
    uint32_t capacity)
{
    uint32_t index;

    for (index = 0; index < capacity; ++index) {
        rome2_test_put_u32(
            state_bytes, (size_t)offset + (size_t)index * 4,
            ROME2_TEST_SPARE);
    }
}

static void rome2_test_setup(rome2_test_fixture *fixture)
{
    uint32_t index;
    uint32_t vtable = ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET;

    memset(fixture, 0, sizeof(*fixture));
    memset(fixture->state.bytes, 0x5a, sizeof(fixture->state.bytes));
    memset(fixture->vtables.bytes, 0x5a, sizeof(fixture->vtables.bytes));
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET,
        ROME2_TEST_VECTOR_SENTINEL);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 0);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 0);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 12, 0);
    rome2_test_initialize_buffer(
        fixture->state.bytes, ROME2_TEST_BUFFER_A_OFFSET, 1);
    rome2_test_initialize_buffer(
        fixture->state.bytes, ROME2_TEST_BUFFER_B_OFFSET, 2);
    rome2_test_initialize_buffer(
        fixture->state.bytes, ROME2_TEST_BUFFER_C_OFFSET, 4);
    rome2_test_initialize_buffer(
        fixture->state.bytes, ROME2_TEST_BUFFER_D_OFFSET, 8);
    for (index = 0; index < ROME2_TEST_APPEND_COUNT; ++index) {
        uint32_t handler_offset =
            ROME2_TEST_HANDLER_OFFSET + index * ROME2_TEST_HANDLER_STRIDE;

        fixture->context.handlers[index] =
            rome2_test_guest_from_offset(handler_offset);
        rome2_test_put_u32(fixture->state.bytes, handler_offset, vtable);
    }
    rome2_test_put_u32(
        fixture->vtables.bytes, ROME2_TEST_VTABLE_OFFSET + 4,
        ROME2_TEST_METHOD);

    fixture->state_view.host_base = fixture->state.bytes;
    fixture->state_view.guest_base = ROME2_TEST_STATE_BASE;
    fixture->state_view.byte_count = sizeof(fixture->state.bytes);
    fixture->vtable_view.host_base = fixture->vtables.bytes;
    fixture->vtable_view.guest_base = ROME2_TEST_VTABLE_BASE;
    fixture->vtable_view.byte_count = sizeof(fixture->vtables.bytes);
    fixture->context.state_bytes = fixture->state.bytes;
    fixture->context.allocation_results[0] =
        rome2_test_guest_from_offset(ROME2_TEST_BUFFER_A_OFFSET);
    fixture->context.allocation_results[1] =
        rome2_test_guest_from_offset(ROME2_TEST_BUFFER_B_OFFSET);
    fixture->context.allocation_results[2] =
        rome2_test_guest_from_offset(ROME2_TEST_BUFFER_C_OFFSET);
    fixture->context.allocation_results[3] =
        rome2_test_guest_from_offset(ROME2_TEST_BUFFER_D_OFFSET);
    fixture->effects.tail_effects.context = &fixture->context;
    fixture->effects.tail_effects.dispatch = rome2_test_dispatch;
    fixture->effects.tail_effects.peek = rome2_test_peek;
    fixture->effects.allocate = rome2_test_allocate;
    fixture->effects.release = rome2_test_release;
}

static int rome2_test_events_are_exact(
    const rome2_test_effect_context *context)
{
    static const uint32_t expected[] = {
        ROME2_TEST_EVENT_ALLOCATE,
        ROME2_TEST_EVENT_DISPATCH,
        ROME2_TEST_EVENT_PEEK,
        ROME2_TEST_EVENT_ALLOCATE,
        ROME2_TEST_EVENT_RELEASE,
        ROME2_TEST_EVENT_DISPATCH,
        ROME2_TEST_EVENT_PEEK,
        ROME2_TEST_EVENT_ALLOCATE,
        ROME2_TEST_EVENT_RELEASE,
        ROME2_TEST_EVENT_DISPATCH,
        ROME2_TEST_EVENT_PEEK,
        ROME2_TEST_EVENT_DISPATCH,
        ROME2_TEST_EVENT_PEEK,
        ROME2_TEST_EVENT_ALLOCATE,
        ROME2_TEST_EVENT_RELEASE,
        ROME2_TEST_EVENT_DISPATCH,
        ROME2_TEST_EVENT_PEEK,
        ROME2_TEST_EVENT_DISPATCH,
        ROME2_TEST_EVENT_PEEK,
    };
    uint32_t index;

    if (context->event_count !=
        (uint32_t)(sizeof(expected) / sizeof(expected[0]))) {
        return 0;
    }
    for (index = 0;
         index < (uint32_t)(sizeof(expected) / sizeof(expected[0]));
         ++index) {
        if (context->events[index] != expected[index]) {
            return 0;
        }
    }
    return 1;
}

static int rome2_test_final_observations_are_exact(
    const rome2_test_fixture *fixture,
    uint8_t final_al)
{
    const rome2_test_effect_context *context = &fixture->context;
    uint32_t index;

    if (final_al != UINT8_C(0xa6) || context->allocate_calls != 4 ||
        context->release_calls != 3 || context->dispatch_calls != 6 ||
        context->peek_calls != 6 || context->bad_observations != 0 ||
        rome2_test_vector_capacity(context) != 8 ||
        rome2_test_vector_count(context) != 6 ||
        rome2_test_vector_backing(context) !=
            rome2_test_guest_from_offset(ROME2_TEST_BUFFER_D_OFFSET) ||
        !rome2_test_buffer_is_ordered(
            context,
            rome2_test_guest_from_offset(ROME2_TEST_BUFFER_D_OFFSET),
            6) ||
        !rome2_test_events_are_exact(context)) {
        return 0;
    }
    for (index = 0; index < ROME2_TEST_ALLOCATION_COUNT; ++index) {
        if (context->allocation_bytes[index] !=
                rome2_test_allocation_bytes[index] ||
            context->allocation_classes[index] !=
                ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS) {
            return 0;
        }
    }
    for (index = 0; index < ROME2_TEST_RELEASE_COUNT; ++index) {
        if (context->released_identities[index] !=
            context->allocation_results[index]) {
            return 0;
        }
    }
    for (index = 0; index < ROME2_TEST_APPEND_COUNT; ++index) {
        if (context->dispatched_receivers[index] != context->handlers[index] ||
            context->dispatched_methods[index] != ROME2_TEST_METHOD ||
            context->dispatched_arguments[index] !=
                ROME2_TEST_ARGUMENT_BASE + index) {
            return 0;
        }
    }
    if (!rome2_test_buffer_is_ordered(
            context,
            rome2_test_guest_from_offset(ROME2_TEST_BUFFER_A_OFFSET),
            1) ||
        !rome2_test_buffer_is_ordered(
            context,
            rome2_test_guest_from_offset(ROME2_TEST_BUFFER_B_OFFSET),
            2) ||
        !rome2_test_buffer_is_ordered(
            context,
            rome2_test_guest_from_offset(ROME2_TEST_BUFFER_C_OFFSET),
            4)) {
        return 0;
    }
    return 1;
}

int main(void)
{
    rome2_test_fixture fixture;
    rome2_100e2460_branch_status status;
    uint32_t append;
    uint8_t return_al = UINT8_C(0xcc);

    rome2_test_setup(&fixture);
    for (append = 0; append < ROME2_TEST_APPEND_COUNT; ++append) {
        fixture.context.current_append = append;
        fixture.context.allocate_calls_at_start =
            fixture.context.allocate_calls;
        fixture.context.release_calls_at_start = fixture.context.release_calls;
        fixture.context.dispatch_calls_at_start =
            fixture.context.dispatch_calls;
        fixture.context.peek_calls_at_start = fixture.context.peek_calls;
        return_al = UINT8_C(0xcc);
        status = rome2_port_100e2460_run_router(
            &fixture.state_view,
            &fixture.vtable_view,
            rome2_test_address(
                ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
            rome2_test_address(fixture.context.handlers[append]),
            rome2_test_address(ROME2_TEST_ARGUMENT_BASE + append),
            &fixture.effects,
            1,
            &return_al);
        if (status != ROME2_100E2460_BRANCH_OK ||
            return_al != (uint8_t)(UINT8_C(0xa1) + append) ||
            rome2_test_vector_capacity(&fixture.context) !=
                rome2_test_expected_capacities[append] ||
            rome2_test_vector_count(&fixture.context) !=
                rome2_test_expected_counts[append] ||
            rome2_test_vector_backing(&fixture.context) !=
                rome2_test_guest_from_offset(
                    rome2_test_expected_backing_offsets[append]) ||
            fixture.context.allocate_calls !=
                fixture.context.allocate_calls_at_start +
                    rome2_test_expected_allocate_delta[append] ||
            fixture.context.release_calls !=
                fixture.context.release_calls_at_start +
                    rome2_test_expected_release_delta[append] ||
            fixture.context.dispatch_calls !=
                fixture.context.dispatch_calls_at_start + 1 ||
            fixture.context.peek_calls !=
                fixture.context.peek_calls_at_start + 1 ||
            fixture.context.bad_observations != 0) {
            fprintf(stderr,
                "startup 100e2460 router six-append test failed at append %lu\n",
                (unsigned long)(append + 1));
            return 1;
        }
    }
    if (!rome2_test_final_observations_are_exact(&fixture, return_al)) {
        fputs("startup 100e2460 router six-append final oracle failed\n",
            stderr);
        return 1;
    }
    puts("startup 100e2460 router six-append tests: pass");
    return 0;
}

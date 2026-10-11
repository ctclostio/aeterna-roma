#include "ported_100ea4d0_injected.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_STATE_BASE UINT32_C(0x20000000)
#define ROME2_TEST_STATE_BYTES 16384
#define ROME2_TEST_RECEIVER_OFFSET UINT32_C(0x100)
#define ROME2_TEST_VECTOR_OFFSET \
    (ROME2_TEST_RECEIVER_OFFSET + ROME2_PORT_100EA4D0_VECTOR_OFFSET)
#define ROME2_TEST_VTABLE_BASE UINT32_C(0x1173f000)
#define ROME2_TEST_VTABLE_BYTES 1024
#define ROME2_TEST_HANDLER_COUNT 6
#define ROME2_TEST_BACKING_COUNT 4
#define ROME2_TEST_MAX_EVENTS 32
#define ROME2_TEST_VECTOR_SENTINEL UINT32_C(0xfeedface)
#define ROME2_TEST_SPARE UINT32_C(0xcccccccc)

#define ROME2_TEST_EVENT_HANDLER_ALLOCATE UINT32_C(1)
#define ROME2_TEST_EVENT_BACKING_ALLOCATE UINT32_C(2)
#define ROME2_TEST_EVENT_RELEASE UINT32_C(3)
#define ROME2_TEST_EVENT_DISPATCH UINT32_C(4)
#define ROME2_TEST_EVENT_PEEK UINT32_C(5)

static const uint32_t rome2_test_handler_offsets[ROME2_TEST_HANDLER_COUNT] = {
    UINT32_C(0x1000), UINT32_C(0x1100), UINT32_C(0x1200),
    UINT32_C(0x1300), UINT32_C(0x1400), UINT32_C(0x1500),
};

static const uint32_t rome2_test_backing_offsets[ROME2_TEST_BACKING_COUNT] = {
    UINT32_C(0x2000), UINT32_C(0x2100),
    UINT32_C(0x2200), UINT32_C(0x2300),
};

static const uint32_t rome2_test_vtables[ROME2_TEST_HANDLER_COUNT] = {
    UINT32_C(0x1173f20c), UINT32_C(0x1173f214),
    UINT32_C(0x1173f21c), UINT32_C(0x1173f224),
    UINT32_C(0x1173f2ec), UINT32_C(0x1173f2dc),
};

static const uint32_t rome2_test_methods[ROME2_TEST_HANDLER_COUNT] = {
    UINT32_C(0x100e8d00), UINT32_C(0x100e85d0),
    UINT32_C(0x100e8580), UINT32_C(0x100e9340),
    UINT32_C(0x100e92c0), UINT32_C(0x100e87a0),
};

typedef union rome2_test_state_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_TEST_STATE_BYTES];
} rome2_test_state_memory;

typedef union rome2_test_vtable_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_TEST_VTABLE_BYTES];
} rome2_test_vtable_memory;

typedef struct rome2_test_context {
    uint8_t *state_bytes;
    rome2_guest_addr32 handler_results[ROME2_TEST_HANDLER_COUNT];
    rome2_guest_addr32 backing_results[ROME2_TEST_BACKING_COUNT];
    uint32_t events[ROME2_TEST_MAX_EVENTS];
    uint32_t event_count;
    uint32_t handler_calls;
    uint32_t backing_calls;
    uint32_t release_calls;
    uint32_t dispatch_calls;
    uint32_t peek_calls;
    uint32_t handler_bytes[ROME2_TEST_HANDLER_COUNT];
    uint32_t handler_classes[ROME2_TEST_HANDLER_COUNT];
    uint32_t backing_bytes[ROME2_TEST_BACKING_COUNT];
    uint32_t backing_classes[ROME2_TEST_BACKING_COUNT];
    uint32_t released[ROME2_TEST_BACKING_COUNT];
    uint32_t dispatched_receivers[ROME2_TEST_HANDLER_COUNT];
    uint32_t dispatched_methods[ROME2_TEST_HANDLER_COUNT];
    uint32_t dispatched_arguments[ROME2_TEST_HANDLER_COUNT];
    uint32_t dispatch_eax;
    uint32_t force_peek_nonzero;
    uint32_t skip_prefix_check;
    uint32_t bad_observations;
} rome2_test_context;

typedef struct rome2_test_fixture {
    rome2_test_state_memory state;
    rome2_test_vtable_memory vtables;
    rome2_guest_write_view state_view;
    rome2_guest_read_view vtable_view;
    rome2_100ea4d0_effects effects;
    rome2_test_context context;
} rome2_test_fixture;

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

static uint32_t rome2_test_capacity(const rome2_test_context *context)
{
    return rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_VECTOR_OFFSET + UINT32_C(4));
}

static uint32_t rome2_test_count(const rome2_test_context *context)
{
    return rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_VECTOR_OFFSET + UINT32_C(8));
}

static uint32_t rome2_test_backing(const rome2_test_context *context)
{
    return rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_VECTOR_OFFSET + UINT32_C(12));
}

static void rome2_test_record_event(
    rome2_test_context *context,
    uint32_t event)
{
    if (context->event_count >= ROME2_TEST_MAX_EVENTS) {
        ++context->bad_observations;
        return;
    }
    context->events[context->event_count] = event;
    ++context->event_count;
}

static int rome2_test_prefix_is_exact(
    const rome2_test_context *context,
    uint32_t completed)
{
    static const uint32_t capacities[ROME2_TEST_HANDLER_COUNT + 1] = {
        0, 1, 2, 4, 4, 8, 8,
    };
    static const uint32_t backing_indices[ROME2_TEST_HANDLER_COUNT + 1] = {
        UINT32_MAX, 0, 1, 2, 2, 3, 3,
    };
    uint32_t backing_index;
    uint32_t cell_index;
    uint32_t handler_index;
    uint32_t backing_offset;

    if (completed > ROME2_TEST_HANDLER_COUNT ||
        rome2_test_capacity(context) != capacities[completed] ||
        rome2_test_count(context) != completed) {
        return 0;
    }
    backing_index = backing_indices[completed];
    if (backing_index == UINT32_MAX) {
        if (rome2_test_backing(context) != 0) {
            return 0;
        }
    } else {
        backing_offset = rome2_test_backing_offsets[backing_index];
        if (rome2_test_backing(context) !=
            rome2_test_guest_from_offset(backing_offset)) {
            return 0;
        }
        for (cell_index = 0; cell_index < completed; ++cell_index) {
            if (rome2_test_get_u32(
                    context->state_bytes,
                    backing_offset + cell_index * UINT32_C(4)) !=
                rome2_test_guest_from_offset(
                    rome2_test_handler_offsets[cell_index])) {
                return 0;
            }
        }
        for (cell_index = completed;
             cell_index < capacities[completed];
             ++cell_index) {
            if (rome2_test_get_u32(
                    context->state_bytes,
                    backing_offset + cell_index * UINT32_C(4)) !=
                ROME2_TEST_SPARE) {
                return 0;
            }
        }
    }
    for (handler_index = 0; handler_index < completed; ++handler_index) {
        if (rome2_test_get_u32(
                context->state_bytes,
                rome2_test_handler_offsets[handler_index]) !=
            rome2_test_vtables[handler_index]) {
            return 0;
        }
    }
    return 1;
}

static rome2_guest_addr32 rome2_test_allocate_handler(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    rome2_test_context *context = (rome2_test_context *)opaque_context;
    uint32_t index = context->handler_calls;

    rome2_test_record_event(context, ROME2_TEST_EVENT_HANDLER_ALLOCATE);
    if (index >= ROME2_TEST_HANDLER_COUNT) {
        ++context->bad_observations;
        return rome2_test_address(0);
    }
    context->handler_bytes[index] = byte_count;
    context->handler_classes[index] = allocation_class;
    if (byte_count != ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_BYTES ||
        allocation_class != ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_CLASS ||
        (!context->skip_prefix_check &&
         !rome2_test_prefix_is_exact(context, index))) {
        ++context->bad_observations;
    }
    ++context->handler_calls;
    return context->handler_results[index];
}

static rome2_guest_addr32 rome2_test_allocate_backing(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    static const uint32_t registrations[ROME2_TEST_BACKING_COUNT] = {
        0, 1, 2, 4,
    };
    static const uint32_t byte_counts[ROME2_TEST_BACKING_COUNT] = {
        4, 8, 16, 32,
    };
    static const uint32_t capacities[ROME2_TEST_BACKING_COUNT] = {
        1, 2, 4, 8,
    };
    static const uint32_t old_backing_indices[ROME2_TEST_BACKING_COUNT] = {
        UINT32_MAX, 0, 1, 2,
    };
    rome2_test_context *context = (rome2_test_context *)opaque_context;
    uint32_t index = context->backing_calls;
    uint32_t registration;
    uint32_t old_index;
    uint32_t wanted_old_backing = 0;

    rome2_test_record_event(context, ROME2_TEST_EVENT_BACKING_ALLOCATE);
    if (index >= ROME2_TEST_BACKING_COUNT) {
        ++context->bad_observations;
        return rome2_test_address(0);
    }
    registration = registrations[index];
    old_index = old_backing_indices[index];
    if (old_index != UINT32_MAX) {
        wanted_old_backing = rome2_test_guest_from_offset(
            rome2_test_backing_offsets[old_index]);
    }
    context->backing_bytes[index] = byte_count;
    context->backing_classes[index] = allocation_class;
    if (byte_count != byte_counts[index] ||
        allocation_class != ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS ||
        context->handler_calls != registration + UINT32_C(1) ||
        rome2_test_capacity(context) != capacities[index] ||
        rome2_test_count(context) != registration ||
        rome2_test_backing(context) != wanted_old_backing ||
        rome2_test_get_u32(
            context->state_bytes,
            rome2_test_handler_offsets[registration]) !=
            rome2_test_vtables[registration]) {
        ++context->bad_observations;
    }
    ++context->backing_calls;
    return context->backing_results[index];
}

static void rome2_test_release_backing(
    void *opaque_context,
    rome2_guest_addr32 allocation)
{
    static const uint32_t registrations[3] = {1, 2, 4};
    static const uint32_t old_indices[3] = {0, 1, 2};
    static const uint32_t new_indices[3] = {1, 2, 3};
    static const uint32_t capacities[3] = {2, 4, 8};
    rome2_test_context *context = (rome2_test_context *)opaque_context;
    uint32_t index = context->release_calls;
    uint32_t registration;
    uint32_t new_offset;

    rome2_test_record_event(context, ROME2_TEST_EVENT_RELEASE);
    if (index >= 3) {
        ++context->bad_observations;
        return;
    }
    registration = registrations[index];
    new_offset = rome2_test_backing_offsets[new_indices[index]];
    context->released[index] = allocation.value;
    if (allocation.value != rome2_test_guest_from_offset(
            rome2_test_backing_offsets[old_indices[index]]) ||
        rome2_test_capacity(context) != capacities[index] ||
        rome2_test_count(context) != registration ||
        rome2_test_backing(context) !=
            rome2_test_guest_from_offset(new_offset) ||
        rome2_test_get_u32(
            context->state_bytes,
            new_offset + registration * UINT32_C(4)) !=
            rome2_test_guest_from_offset(
                rome2_test_handler_offsets[registration])) {
        ++context->bad_observations;
    }
    ++context->release_calls;
}

static uint32_t rome2_test_dispatch(
    void *opaque_context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 method,
    rome2_guest_addr32 argument)
{
    rome2_test_context *context = (rome2_test_context *)opaque_context;
    uint32_t index = context->dispatch_calls;

    rome2_test_record_event(context, ROME2_TEST_EVENT_DISPATCH);
    if (index >= ROME2_TEST_HANDLER_COUNT) {
        ++context->bad_observations;
        return context->dispatch_eax;
    }
    context->dispatched_receivers[index] = receiver.value;
    context->dispatched_methods[index] = method.value;
    context->dispatched_arguments[index] = argument.value;
    if (receiver.value != rome2_test_guest_from_offset(
            rome2_test_handler_offsets[index]) ||
        method.value != rome2_test_methods[index] ||
        argument.value !=
            rome2_test_guest_from_offset(
                ROME2_TEST_RECEIVER_OFFSET +
                ROME2_PORT_100EA4D0_ARGUMENT_OFFSET) ||
        rome2_test_get_u32(
            context->state_bytes,
            rome2_test_handler_offsets[index]) != rome2_test_vtables[index] ||
        !rome2_test_prefix_is_exact(context, index + UINT32_C(1))) {
        ++context->bad_observations;
    }
    ++context->dispatch_calls;
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
    rome2_test_context *context = (rome2_test_context *)opaque_context;

    rome2_test_record_event(context, ROME2_TEST_EVENT_PEEK);
    if (message.value != 0 || window.value != 0 || filter_min != 0 ||
        filter_max != 0 ||
        remove_flags != ROME2_PORT_100E2460_PM_REMOVE ||
        context->dispatch_calls != context->peek_calls + UINT32_C(1) ||
        !rome2_test_prefix_is_exact(context, context->dispatch_calls)) {
        ++context->bad_observations;
    }
    ++context->peek_calls;
    return context->force_peek_nonzero;
}

static void rome2_test_setup(rome2_test_fixture *fixture)
{
    uint32_t index;

    memset(fixture, 0, sizeof(*fixture));
    memset(fixture->state.bytes, 0xcc, sizeof(fixture->state.bytes));
    memset(fixture->vtables.bytes, 0xcc, sizeof(fixture->vtables.bytes));
    rome2_test_put_u32(
        fixture->state.bytes,
        ROME2_TEST_VECTOR_OFFSET,
        ROME2_TEST_VECTOR_SENTINEL);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 0);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 0);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 12, 0);
    for (index = 0; index < ROME2_TEST_HANDLER_COUNT; ++index) {
        fixture->context.handler_results[index] = rome2_test_address(
            rome2_test_guest_from_offset(rome2_test_handler_offsets[index]));
        rome2_test_put_u32(
            fixture->vtables.bytes,
            (size_t)(rome2_test_vtables[index] - ROME2_TEST_VTABLE_BASE) + 4,
            rome2_test_methods[index]);
    }
    for (index = 0; index < ROME2_TEST_BACKING_COUNT; ++index) {
        fixture->context.backing_results[index] = rome2_test_address(
            rome2_test_guest_from_offset(rome2_test_backing_offsets[index]));
    }

    fixture->state_view.host_base = fixture->state.bytes;
    fixture->state_view.guest_base = ROME2_TEST_STATE_BASE;
    fixture->state_view.byte_count = sizeof(fixture->state.bytes);
    fixture->vtable_view.host_base = fixture->vtables.bytes;
    fixture->vtable_view.guest_base = ROME2_TEST_VTABLE_BASE;
    fixture->vtable_view.byte_count = sizeof(fixture->vtables.bytes);
    fixture->context.state_bytes = fixture->state.bytes;
    fixture->context.dispatch_eax = UINT32_C(0x123456a1);
    fixture->effects.allocation_context = &fixture->context;
    fixture->effects.allocate_handler = rome2_test_allocate_handler;
    fixture->effects.router_effects.tail_effects.context = &fixture->context;
    fixture->effects.router_effects.tail_effects.dispatch = rome2_test_dispatch;
    fixture->effects.router_effects.tail_effects.peek = rome2_test_peek;
    fixture->effects.router_effects.allocate = rome2_test_allocate_backing;
    fixture->effects.router_effects.release = rome2_test_release_backing;
}

static rome2_100ea4d0_status rome2_test_run(
    rome2_test_fixture *fixture,
    uint32_t max_peek_calls)
{
    return rome2_port_100ea4d0_run_injected(
        &fixture->state_view,
        &fixture->vtable_view,
        rome2_test_address(
            rome2_test_guest_from_offset(ROME2_TEST_RECEIVER_OFFSET)),
        &fixture->effects,
        max_peek_calls);
}

static int rome2_test_no_effects(const rome2_test_context *context)
{
    return
        context->handler_calls == 0 &&
        context->backing_calls == 0 &&
        context->release_calls == 0 &&
        context->dispatch_calls == 0 &&
        context->peek_calls == 0 &&
        context->event_count == 0;
}

static int rome2_test_failure(const char *name)
{
    fprintf(stderr, "startup 100ea4d0 injected test failed: %s\n", name);
    return 1;
}

static int rome2_test_six_registration_success(void)
{
    static const uint32_t wanted_events[25] = {
        1, 2, 4, 5,
        1, 2, 3, 4, 5,
        1, 2, 3, 4, 5,
        1, 4, 5,
        1, 2, 3, 4, 5,
        1, 4, 5,
    };
    static rome2_test_fixture fixture;
    rome2_100ea4d0_status status;
    uint32_t index;
    uint32_t final_offset = rome2_test_backing_offsets[3];

    rome2_test_setup(&fixture);
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_OK ||
        fixture.context.bad_observations != 0 ||
        fixture.context.handler_calls != 6 ||
        fixture.context.backing_calls != 4 ||
        fixture.context.release_calls != 3 ||
        fixture.context.dispatch_calls != 6 ||
        fixture.context.peek_calls != 6 ||
        fixture.context.event_count != 25 ||
        memcmp(
            fixture.context.events,
            wanted_events,
            sizeof(wanted_events)) != 0 ||
        !rome2_test_prefix_is_exact(&fixture.context, 6)) {
        return rome2_test_failure("six registrations and exact effect trace");
    }
    for (index = 0; index < ROME2_TEST_HANDLER_COUNT; ++index) {
        if (fixture.context.handler_bytes[index] != 4 ||
            fixture.context.handler_classes[index] != 0 ||
            fixture.context.dispatched_receivers[index] !=
                rome2_test_guest_from_offset(rome2_test_handler_offsets[index]) ||
            fixture.context.dispatched_methods[index] != rome2_test_methods[index] ||
            fixture.context.dispatched_arguments[index] !=
                rome2_test_guest_from_offset(
                    ROME2_TEST_RECEIVER_OFFSET +
                    ROME2_PORT_100EA4D0_ARGUMENT_OFFSET)) {
            return rome2_test_failure("handler allocation/store/dispatch order");
        }
    }
    for (index = 0; index < ROME2_TEST_BACKING_COUNT; ++index) {
        if (fixture.context.backing_bytes[index] !=
                UINT32_C(4) << index ||
            fixture.context.backing_classes[index] != 0) {
            return rome2_test_failure("router backing allocation progression");
        }
    }
    if (rome2_test_get_u32(fixture.state.bytes, final_offset + 24) !=
            ROME2_TEST_SPARE ||
        rome2_test_get_u32(fixture.state.bytes, final_offset + 28) !=
            ROME2_TEST_SPARE) {
        return rome2_test_failure("final spare cells stay untouched");
    }
    return 0;
}

static int rome2_test_receiver_and_vector_precommit_failures(void)
{
    static rome2_test_fixture fixture;
    static rome2_test_state_memory before;
    rome2_100ea4d0_status status;
    rome2_guest_addr32 receiver;

    rome2_test_setup(&fixture);
    before = fixture.state;
    status = rome2_port_100ea4d0_run_injected(
        &fixture.state_view,
        &fixture.vtable_view,
        rome2_test_address(0),
        &fixture.effects,
        1);
    if (status != ROME2_100EA4D0_NULL_ADDRESS ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("null receiver is precommit");
    }

    rome2_test_setup(&fixture);
    before = fixture.state;
    receiver.value =
        UINT32_MAX - ROME2_PORT_100EA4D0_VECTOR_OFFSET + UINT32_C(1);
    status = rome2_port_100ea4d0_run_injected(
        &fixture.state_view,
        &fixture.vtable_view,
        receiver,
        &fixture.effects,
        1);
    if (status != ROME2_100EA4D0_RANGE_OVERFLOW ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("receiver-derived vector overflow is precommit");
    }

    rome2_test_setup(&fixture);
    before = fixture.state;
    fixture.state_view.byte_count = ROME2_TEST_VECTOR_OFFSET + UINT32_C(15);
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_OUT_OF_RANGE ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("truncated derived vector is precommit");
    }

    rome2_test_setup(&fixture);
    before = fixture.state;
    fixture.vtable_view.guest_base =
        rome2_test_guest_from_offset(ROME2_TEST_VECTOR_OFFSET);
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_BAD_ARGUMENT ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("vector logical vtable alias is precommit");
    }

    rome2_test_setup(&fixture);
    before = fixture.state;
    fixture.vtable_view.host_base =
        fixture.state.bytes + ROME2_TEST_VECTOR_OFFSET;
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_BAD_ARGUMENT ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("vector physical vtable alias is precommit");
    }

    rome2_test_setup(&fixture);
    before = fixture.state;
    status = rome2_test_run(&fixture, 0);
    if (status != ROME2_100EA4D0_BAD_ARGUMENT ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("zero Peek budget is precommit");
    }

    rome2_test_setup(&fixture);
    before = fixture.state;
    fixture.effects.allocate_handler = NULL;
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_BAD_ARGUMENT ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("null outer allocator is precommit");
    }
    return 0;
}

static int rome2_test_first_allocation_result_failures(void)
{
    static rome2_test_fixture fixture;
    static rome2_test_state_memory before;
    rome2_100ea4d0_status status;
    uint32_t handler = rome2_test_guest_from_offset(
        rome2_test_handler_offsets[0]);

    rome2_test_setup(&fixture);
    fixture.context.handler_results[0] = rome2_test_address(0);
    before = fixture.state;
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ALLOCATION_RESULT_INVALID ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        fixture.context.handler_calls != 1 ||
        fixture.context.event_count != 1 ||
        fixture.context.events[0] != ROME2_TEST_EVENT_HANDLER_ALLOCATE ||
        fixture.context.backing_calls != 0) {
        return rome2_test_failure("null handler allocation result");
    }

    rome2_test_setup(&fixture);
    fixture.context.handler_results[0] =
        rome2_test_address(ROME2_TEST_STATE_BASE - UINT32_C(4));
    before = fixture.state;
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ALLOCATION_RESULT_INVALID ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        fixture.context.handler_calls != 1 || fixture.context.backing_calls != 0) {
        return rome2_test_failure("handler allocation below state mapping");
    }

    rome2_test_setup(&fixture);
    fixture.context.handler_results[0] = rome2_test_address(UINT32_MAX - 1);
    before = fixture.state;
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ALLOCATION_RESULT_INVALID ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        fixture.context.handler_calls != 1 || fixture.context.backing_calls != 0) {
        return rome2_test_failure("handler allocation guest overflow");
    }

    rome2_test_setup(&fixture);
    fixture.context.handler_results[0] = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES - UINT32_C(2));
    before = fixture.state;
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ALLOCATION_RESULT_INVALID ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        fixture.context.handler_calls != 1 || fixture.context.backing_calls != 0) {
        return rome2_test_failure("truncated handler allocation span");
    }

    rome2_test_setup(&fixture);
    fixture.context.handler_results[0] = rome2_test_address(
        rome2_test_guest_from_offset(ROME2_TEST_VECTOR_OFFSET));
    before = fixture.state;
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ALLOCATION_RESULT_INVALID ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        fixture.context.handler_calls != 1 || fixture.context.backing_calls != 0) {
        return rome2_test_failure("handler allocation aliases vector");
    }

    rome2_test_setup(&fixture);
    fixture.context.handler_results[0] = rome2_test_address(
        rome2_test_guest_from_offset(
            ROME2_TEST_RECEIVER_OFFSET +
            ROME2_PORT_100EA4D0_ARGUMENT_OFFSET));
    before = fixture.state;
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ALLOCATION_RESULT_INVALID ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        fixture.context.handler_calls != 1 || fixture.context.backing_calls != 0) {
        return rome2_test_failure("handler allocation aliases argument cell");
    }

    rome2_test_setup(&fixture);
    fixture.vtable_view.guest_base = handler;
    fixture.vtable_view.byte_count = 4;
    before = fixture.state;
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ALLOCATION_RESULT_INVALID ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        fixture.context.handler_calls != 1 || fixture.context.backing_calls != 0) {
        return rome2_test_failure("handler allocation logically aliases vtable");
    }

    rome2_test_setup(&fixture);
    fixture.vtable_view.host_base =
        fixture.state.bytes + rome2_test_handler_offsets[0];
    fixture.vtable_view.byte_count = 4;
    before = fixture.state;
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ALLOCATION_RESULT_INVALID ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        fixture.context.handler_calls != 1 || fixture.context.backing_calls != 0) {
        return rome2_test_failure("handler allocation physically aliases vtable");
    }
    return 0;
}

static int rome2_test_duplicate_allocation_commits_prefix_only(void)
{
    static const uint32_t wanted_events[5] = {1, 2, 4, 5, 1};
    static rome2_test_fixture fixture;
    rome2_100ea4d0_status status;

    rome2_test_setup(&fixture);
    fixture.context.handler_results[1] = fixture.context.handler_results[0];
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ALLOCATION_RESULT_INVALID ||
        fixture.context.bad_observations != 0 ||
        fixture.context.handler_calls != 2 ||
        fixture.context.backing_calls != 1 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1 ||
        fixture.context.event_count != 5 ||
        memcmp(fixture.context.events, wanted_events, sizeof(wanted_events)) != 0 ||
        !rome2_test_prefix_is_exact(&fixture.context, 1) ||
        rome2_test_get_u32(
            fixture.state.bytes, rome2_test_handler_offsets[1]) !=
            ROME2_TEST_SPARE) {
        return rome2_test_failure("duplicate allocation preserves prior prefix");
    }

    rome2_test_setup(&fixture);
    fixture.context.handler_results[1] = rome2_test_address(
        rome2_test_guest_from_offset(rome2_test_backing_offsets[0]));
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ALLOCATION_RESULT_INVALID ||
        fixture.context.bad_observations != 0 ||
        fixture.context.handler_calls != 2 ||
        fixture.context.backing_calls != 1 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1 ||
        !rome2_test_prefix_is_exact(&fixture.context, 1) ||
        rome2_test_get_u32(
            fixture.state.bytes, rome2_test_handler_offsets[1]) !=
            ROME2_TEST_SPARE) {
        return rome2_test_failure("handler allocation aliases active backing");
    }
    return 0;
}

static int rome2_test_router_failure_commits_current_handler_store(void)
{
    static rome2_test_fixture fixture;
    rome2_100ea4d0_status status;

    rome2_test_setup(&fixture);
    fixture.context.skip_prefix_check = 1;
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 1);
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ROUTER_FAILED ||
        fixture.context.handler_calls != 1 ||
        fixture.context.backing_calls != 0 ||
        fixture.context.dispatch_calls != 0 ||
        fixture.context.peek_calls != 0 ||
        rome2_test_get_u32(
            fixture.state.bytes, rome2_test_handler_offsets[0]) !=
            rome2_test_vtables[0] ||
        rome2_test_capacity(&fixture.context) != 0 ||
        rome2_test_count(&fixture.context) != 1) {
        return rome2_test_failure("router failure keeps allocation and vtable store");
    }

    rome2_test_setup(&fixture);
    fixture.context.skip_prefix_check = 1;
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 1);
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 0);
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 12, 0);
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ROUTER_FAILED ||
        fixture.context.handler_calls != 1 ||
        fixture.context.backing_calls != 0 ||
        fixture.context.dispatch_calls != 0 ||
        fixture.context.peek_calls != 0 ||
        rome2_test_get_u32(
            fixture.state.bytes, rome2_test_handler_offsets[0]) !=
            ROME2_TEST_SPARE ||
        rome2_test_capacity(&fixture.context) != 1 ||
        rome2_test_count(&fixture.context) != 0 ||
        rome2_test_backing(&fixture.context) != 0) {
        return rome2_test_failure(
            "invalid active backing fails after allocation before store");
    }

    rome2_test_setup(&fixture);
    rome2_test_put_u32(
        fixture.vtables.bytes,
        (size_t)(rome2_test_vtables[0] - ROME2_TEST_VTABLE_BASE) + 4,
        0);
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ROUTER_FAILED ||
        fixture.context.handler_calls != 1 ||
        fixture.context.backing_calls != 0 ||
        fixture.context.dispatch_calls != 0 ||
        rome2_test_get_u32(
            fixture.state.bytes, rome2_test_handler_offsets[0]) !=
            rome2_test_vtables[0]) {
        return rome2_test_failure("missing method fails after vtable store");
    }
    return 0;
}

static int rome2_test_router_drain_and_zero_al_commits(void)
{
    static const uint32_t wanted_events[4] = {1, 2, 4, 5};
    static rome2_test_fixture fixture;
    rome2_100ea4d0_status status;

    rome2_test_setup(&fixture);
    fixture.context.force_peek_nonzero = 1;
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ROUTER_FAILED ||
        fixture.context.bad_observations != 0 ||
        fixture.context.handler_calls != 1 ||
        fixture.context.backing_calls != 1 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1 ||
        fixture.context.event_count != 4 ||
        memcmp(fixture.context.events, wanted_events, sizeof(wanted_events)) != 0 ||
        !rome2_test_prefix_is_exact(&fixture.context, 1)) {
        return rome2_test_failure("router drain limit keeps current commits");
    }

    rome2_test_setup(&fixture);
    fixture.context.dispatch_eax = UINT32_C(0x12345600);
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_ROUTER_RETURNED_ZERO ||
        fixture.context.bad_observations != 0 ||
        fixture.context.handler_calls != 1 ||
        fixture.context.backing_calls != 1 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1 ||
        !rome2_test_prefix_is_exact(&fixture.context, 1)) {
        return rome2_test_failure("zero router AL replaces original null trap");
    }
    return 0;
}

static int rome2_test_router_storage_corrupts_earlier_handler(void)
{
    static const uint32_t wanted_events[9] = {
        1, 2, 4, 5, 1, 2, 3, 4, 5,
    };
    static rome2_test_fixture fixture;
    rome2_100ea4d0_status status;

    rome2_test_setup(&fixture);
    fixture.context.backing_results[1] = fixture.context.handler_results[0];
    status = rome2_test_run(&fixture, 1);
    if (status != ROME2_100EA4D0_HANDLER_GRAPH_CORRUPTED ||
        fixture.context.handler_calls != 2 ||
        fixture.context.backing_calls != 2 ||
        fixture.context.release_calls != 1 ||
        fixture.context.dispatch_calls != 2 ||
        fixture.context.peek_calls != 2 ||
        fixture.context.event_count != 9 ||
        memcmp(fixture.context.events, wanted_events, sizeof(wanted_events)) != 0 ||
        rome2_test_get_u32(
            fixture.state.bytes, rome2_test_handler_offsets[0]) ==
            rome2_test_vtables[0] ||
        rome2_test_get_u32(
            fixture.state.bytes, rome2_test_handler_offsets[1]) !=
            rome2_test_vtables[1] ||
        rome2_test_capacity(&fixture.context) != 2 ||
        rome2_test_count(&fixture.context) != 2 ||
        rome2_test_backing(&fixture.context) !=
            rome2_test_guest_from_offset(rome2_test_handler_offsets[0])) {
        return rome2_test_failure(
            "router storage alias triggers handler graph corruption status");
    }
    return 0;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_six_registration_success();
    failures += rome2_test_receiver_and_vector_precommit_failures();
    failures += rome2_test_first_allocation_result_failures();
    failures += rome2_test_duplicate_allocation_commits_prefix_only();
    failures += rome2_test_router_failure_commits_current_handler_store();
    failures += rome2_test_router_drain_and_zero_al_commits();
    failures += rome2_test_router_storage_corrupts_earlier_handler();
    if (failures != 0) {
        return 1;
    }
    puts("startup 100ea4d0 injected tests: pass");
    return 0;
}

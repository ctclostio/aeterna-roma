#include "ported_100e2460_router.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_STATE_BASE UINT32_C(0x10000)
#define ROME2_TEST_STATE_BYTES 3072
#define ROME2_TEST_VECTOR_OFFSET UINT32_C(0x40)
#define ROME2_TEST_OLD_OFFSET UINT32_C(0x200)
#define ROME2_TEST_NEW_OFFSET UINT32_C(0x500)
#define ROME2_TEST_HANDLER_OFFSET UINT32_C(0x900)
#define ROME2_TEST_OUTPUT_OFFSET UINT32_C(0xb00)
#define ROME2_TEST_VTABLE_BASE UINT32_C(0x30000000)
#define ROME2_TEST_VTABLE_BYTES 256
#define ROME2_TEST_VTABLE_OFFSET UINT32_C(0x20)
#define ROME2_TEST_METHOD UINT32_C(0x100e9340)
#define ROME2_TEST_ARGUMENT UINT32_C(0x2824)
#define ROME2_TEST_VECTOR_SENTINEL UINT32_C(0xfeedface)
#define ROME2_TEST_OLD_A UINT32_C(0x10203040)
#define ROME2_TEST_OLD_B UINT32_C(0x50607080)
#define ROME2_TEST_SPARE UINT32_C(0xa5a5a5a5)
#define ROME2_TEST_DISPATCH_EAX UINT32_C(0x123456d3)
#define ROME2_TEST_MAX_EVENTS 16

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

typedef struct rome2_test_observation {
    uint32_t capacity;
    uint32_t count;
    uint32_t backing;
    uint32_t old_a;
    uint32_t old_b;
    uint32_t new_a;
    uint32_t new_b;
    uint32_t new_c;
    uint32_t new_d;
} rome2_test_observation;

typedef struct rome2_test_effect_context {
    const uint8_t *state_bytes;
    rome2_guest_addr32 allocation_result;
    uint32_t dispatch_eax;
    uint32_t peek_values[ROME2_TEST_MAX_EVENTS];
    uint32_t peek_value_count;
    uint32_t peek_index;
    uint32_t events[ROME2_TEST_MAX_EVENTS];
    uint32_t event_count;
    uint32_t allocate_calls;
    uint32_t release_calls;
    uint32_t dispatch_calls;
    uint32_t peek_calls;
    uint32_t allocation_bytes;
    uint32_t allocation_class;
    uint32_t released_identity;
    uint32_t dispatch_receiver;
    uint32_t dispatch_method;
    uint32_t dispatch_argument;
    uint32_t bad_observations;
    rome2_test_observation allocation_observation;
    rome2_test_observation release_observation;
    rome2_test_observation dispatch_observation;
    rome2_test_observation peek_observations[ROME2_TEST_MAX_EVENTS];
} rome2_test_effect_context;

typedef struct rome2_test_fixture {
    rome2_test_state_memory state;
    rome2_test_vtable_memory vtables;
    rome2_guest_write_view state_view;
    rome2_guest_read_view vtable_view;
    rome2_100e2460_growth_effects effects;
    rome2_test_effect_context context;
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

static void rome2_test_observe(
    const rome2_test_effect_context *context,
    rome2_test_observation *observation)
{
    observation->capacity = rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_VECTOR_OFFSET + 4);
    observation->count = rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_VECTOR_OFFSET + 8);
    observation->backing = rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_VECTOR_OFFSET + 12);
    observation->old_a = rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_OLD_OFFSET);
    observation->old_b = rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_OLD_OFFSET + 4);
    observation->new_a = rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_NEW_OFFSET);
    observation->new_b = rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_NEW_OFFSET + 4);
    observation->new_c = rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_NEW_OFFSET + 8);
    observation->new_d = rome2_test_get_u32(
        context->state_bytes, ROME2_TEST_NEW_OFFSET + 12);
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

    rome2_test_record_event(context, ROME2_TEST_EVENT_ALLOCATE);
    ++context->allocate_calls;
    context->allocation_bytes = byte_count;
    context->allocation_class = allocation_class;
    rome2_test_observe(context, &context->allocation_observation);
    return context->allocation_result;
}

static void rome2_test_release(
    void *opaque_context,
    rome2_guest_addr32 allocation)
{
    rome2_test_effect_context *context =
        (rome2_test_effect_context *)opaque_context;

    rome2_test_record_event(context, ROME2_TEST_EVENT_RELEASE);
    ++context->release_calls;
    context->released_identity = allocation.value;
    rome2_test_observe(context, &context->release_observation);
}

static uint32_t rome2_test_dispatch(
    void *opaque_context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 method,
    rome2_guest_addr32 argument)
{
    rome2_test_effect_context *context =
        (rome2_test_effect_context *)opaque_context;

    rome2_test_record_event(context, ROME2_TEST_EVENT_DISPATCH);
    ++context->dispatch_calls;
    context->dispatch_receiver = receiver.value;
    context->dispatch_method = method.value;
    context->dispatch_argument = argument.value;
    rome2_test_observe(context, &context->dispatch_observation);
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
    uint32_t value = 0;

    rome2_test_record_event(context, ROME2_TEST_EVENT_PEEK);
    ++context->peek_calls;
    if (context->peek_calls <= ROME2_TEST_MAX_EVENTS) {
        rome2_test_observe(
            context, &context->peek_observations[context->peek_calls - 1]);
    }
    if (message.value != 0 || window.value != 0 || filter_min != 0 ||
        filter_max != 0 ||
        remove_flags != ROME2_PORT_100E2460_PM_REMOVE) {
        ++context->bad_observations;
    }
    if (context->peek_index >= context->peek_value_count) {
        ++context->bad_observations;
    } else {
        value = context->peek_values[context->peek_index];
        ++context->peek_index;
    }
    return value;
}

static void rome2_test_setup(
    rome2_test_fixture *fixture,
    uint32_t capacity,
    uint32_t count,
    uint32_t backing)
{
    uint32_t vtable = ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET;

    memset(fixture, 0, sizeof(*fixture));
    memset(fixture->state.bytes, 0xa5, sizeof(fixture->state.bytes));
    memset(fixture->vtables.bytes, 0xa5, sizeof(fixture->vtables.bytes));
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET,
        ROME2_TEST_VECTOR_SENTINEL);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, capacity);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, count);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 12, backing);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_OLD_OFFSET, ROME2_TEST_OLD_A);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_OLD_OFFSET + 4, ROME2_TEST_OLD_B);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_NEW_OFFSET, ROME2_TEST_SPARE);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_NEW_OFFSET + 4, ROME2_TEST_SPARE);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_NEW_OFFSET + 8, ROME2_TEST_SPARE);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_NEW_OFFSET + 12, ROME2_TEST_SPARE);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_HANDLER_OFFSET, vtable);
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
    fixture->context.allocation_result = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_NEW_OFFSET);
    fixture->context.dispatch_eax = ROME2_TEST_DISPATCH_EAX;
    fixture->context.peek_values[0] = 0;
    fixture->context.peek_value_count = 1;
    fixture->effects.tail_effects.context = &fixture->context;
    fixture->effects.tail_effects.dispatch = rome2_test_dispatch;
    fixture->effects.tail_effects.peek = rome2_test_peek;
    fixture->effects.allocate = rome2_test_allocate;
    fixture->effects.release = rome2_test_release;
}

static rome2_100e2460_branch_status rome2_test_run(
    rome2_test_fixture *fixture,
    uint32_t max_peek_calls,
    uint8_t *return_al_out)
{
    return rome2_port_100e2460_run_router(
        &fixture->state_view,
        &fixture->vtable_view,
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        rome2_test_address(ROME2_TEST_ARGUMENT),
        &fixture->effects,
        max_peek_calls,
        return_al_out);
}

static int rome2_test_events_equal(
    const rome2_test_effect_context *context,
    const uint32_t *expected,
    uint32_t expected_count)
{
    uint32_t index;

    if (context->event_count != expected_count) {
        return 0;
    }
    for (index = 0; index < expected_count; ++index) {
        if (context->events[index] != expected[index]) {
            return 0;
        }
    }
    return 1;
}

static int rome2_test_no_effects(
    const rome2_test_effect_context *context)
{
    return
        context->event_count == 0 && context->allocate_calls == 0 &&
        context->release_calls == 0 && context->dispatch_calls == 0 &&
        context->peek_calls == 0 && context->bad_observations == 0;
}

static int rome2_test_failure(const char *name)
{
    fprintf(stderr, "startup 100e2460 router test failed: %s\n", name);
    return 1;
}

static int rome2_test_preallocated_route(void)
{
    static const uint32_t expected_events[] = {
        ROME2_TEST_EVENT_DISPATCH,
        ROME2_TEST_EVENT_PEEK,
    };
    rome2_test_fixture fixture;
    rome2_test_state_memory expected;
    rome2_100e2460_branch_status status;
    uint32_t backing = ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET;
    uint32_t handler = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    uint8_t result = UINT8_C(0xcc);

    rome2_test_setup(&fixture, 2, 1, backing);
    expected = fixture.state;
    rome2_test_put_u32(expected.bytes, ROME2_TEST_OLD_OFFSET + 4, handler);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 2);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_OK || result != UINT8_C(0xd3) ||
        memcmp(&fixture.state, &expected, sizeof(expected)) != 0 ||
        fixture.context.allocate_calls != 0 ||
        fixture.context.release_calls != 0 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1 ||
        fixture.context.bad_observations != 0 ||
        !rome2_test_events_equal(
            &fixture.context, expected_events,
            (uint32_t)(sizeof(expected_events) / sizeof(expected_events[0]))) ||
        fixture.context.dispatch_observation.capacity != 2 ||
        fixture.context.dispatch_observation.count != 2 ||
        fixture.context.dispatch_observation.backing != backing ||
        fixture.context.dispatch_observation.old_b != handler ||
        fixture.context.dispatch_receiver != handler ||
        fixture.context.dispatch_method != ROME2_TEST_METHOD ||
        fixture.context.dispatch_argument != ROME2_TEST_ARGUMENT) {
        return rome2_test_failure("count below capacity selects preallocated");
    }
    return 0;
}

static int rome2_test_unsigned_preallocated_route(void)
{
    static const uint32_t expected_events[] = {
        ROME2_TEST_EVENT_DISPATCH,
        ROME2_TEST_EVENT_PEEK,
    };
    rome2_test_fixture fixture;
    rome2_100e2460_branch_status status;
    uint32_t backing = ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET;
    uint32_t handler = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    uint8_t result = UINT8_C(0xcc);

    rome2_test_setup(&fixture, UINT32_C(0x80000000), 0, backing);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_OK || result != UINT8_C(0xd3) ||
        rome2_test_get_u32(
            fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 4) !=
            UINT32_C(0x80000000) ||
        rome2_test_get_u32(
            fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8) != 1 ||
        rome2_test_get_u32(fixture.state.bytes, ROME2_TEST_OLD_OFFSET) !=
            handler ||
        fixture.context.allocate_calls != 0 ||
        fixture.context.release_calls != 0 ||
        !rome2_test_events_equal(
            &fixture.context, expected_events,
            (uint32_t)(sizeof(expected_events) / sizeof(expected_events[0])))) {
        return rome2_test_failure("high-bit capacity comparison is unsigned");
    }
    return 0;
}

static int rome2_test_capacity_zero_route(void)
{
    static const uint32_t expected_events[] = {
        ROME2_TEST_EVENT_ALLOCATE,
        ROME2_TEST_EVENT_DISPATCH,
        ROME2_TEST_EVENT_PEEK,
    };
    rome2_test_fixture fixture;
    rome2_test_state_memory expected;
    rome2_100e2460_branch_status status;
    uint32_t allocation = ROME2_TEST_STATE_BASE + ROME2_TEST_NEW_OFFSET;
    uint32_t handler = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    uint8_t result = UINT8_C(0xcc);

    rome2_test_setup(&fixture, 0, 0, 0);
    expected = fixture.state;
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 1);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 1);
    rome2_test_put_u32(
        expected.bytes, ROME2_TEST_VECTOR_OFFSET + 12, allocation);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_NEW_OFFSET, handler);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_OK || result != UINT8_C(0xd3) ||
        memcmp(&fixture.state, &expected, sizeof(expected)) != 0 ||
        fixture.context.allocate_calls != 1 ||
        fixture.context.release_calls != 0 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1 ||
        fixture.context.allocation_bytes != 4 ||
        fixture.context.allocation_class != 0 ||
        fixture.context.allocation_observation.capacity != 1 ||
        fixture.context.allocation_observation.count != 0 ||
        fixture.context.allocation_observation.backing != 0 ||
        fixture.context.dispatch_observation.capacity != 1 ||
        fixture.context.dispatch_observation.count != 1 ||
        fixture.context.dispatch_observation.backing != allocation ||
        fixture.context.dispatch_observation.new_a != handler ||
        !rome2_test_events_equal(
            &fixture.context, expected_events,
            (uint32_t)(sizeof(expected_events) / sizeof(expected_events[0])))) {
        return rome2_test_failure("zero capacity selects allocation route");
    }
    return 0;
}

static int rome2_test_growth_route(void)
{
    static const uint32_t expected_events[] = {
        ROME2_TEST_EVENT_ALLOCATE,
        ROME2_TEST_EVENT_RELEASE,
        ROME2_TEST_EVENT_DISPATCH,
        ROME2_TEST_EVENT_PEEK,
    };
    rome2_test_fixture fixture;
    rome2_test_state_memory expected;
    rome2_100e2460_branch_status status;
    uint32_t old_backing = ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET;
    uint32_t allocation = ROME2_TEST_STATE_BASE + ROME2_TEST_NEW_OFFSET;
    uint32_t handler = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    uint8_t result = UINT8_C(0xcc);

    rome2_test_setup(&fixture, 2, 2, old_backing);
    expected = fixture.state;
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 4);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 3);
    rome2_test_put_u32(
        expected.bytes, ROME2_TEST_VECTOR_OFFSET + 12, allocation);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_NEW_OFFSET, ROME2_TEST_OLD_A);
    rome2_test_put_u32(
        expected.bytes, ROME2_TEST_NEW_OFFSET + 4, ROME2_TEST_OLD_B);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_NEW_OFFSET + 8, handler);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_OK || result != UINT8_C(0xd3) ||
        memcmp(&fixture.state, &expected, sizeof(expected)) != 0 ||
        fixture.context.allocate_calls != 1 ||
        fixture.context.release_calls != 1 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1 ||
        fixture.context.allocation_bytes != 16 ||
        fixture.context.allocation_class != 0 ||
        fixture.context.released_identity != old_backing ||
        fixture.context.allocation_observation.capacity != 4 ||
        fixture.context.allocation_observation.count != 2 ||
        fixture.context.allocation_observation.backing != old_backing ||
        fixture.context.release_observation.capacity != 4 ||
        fixture.context.release_observation.count != 2 ||
        fixture.context.release_observation.backing != allocation ||
        fixture.context.release_observation.new_a != ROME2_TEST_OLD_A ||
        fixture.context.release_observation.new_b != ROME2_TEST_OLD_B ||
        fixture.context.release_observation.new_c != handler ||
        fixture.context.dispatch_observation.count != 3 ||
        !rome2_test_events_equal(
            &fixture.context, expected_events,
            (uint32_t)(sizeof(expected_events) / sizeof(expected_events[0])))) {
        return rome2_test_failure("equal nonzero count selects growth");
    }
    return 0;
}

static int rome2_test_inactive_callbacks_are_route_specific(void)
{
    rome2_test_fixture fixture;
    rome2_test_state_memory expected;
    rome2_100e2460_branch_status status;
    uint32_t old_backing = ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET;
    uint32_t allocation = ROME2_TEST_STATE_BASE + ROME2_TEST_NEW_OFFSET;
    uint32_t handler = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    uint8_t result;

    rome2_test_setup(&fixture, 2, 1, old_backing);
    fixture.effects.allocate = NULL;
    fixture.effects.release = NULL;
    expected = fixture.state;
    rome2_test_put_u32(expected.bytes, ROME2_TEST_OLD_OFFSET + 4, handler);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 2);
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_OK || result != UINT8_C(0xd3) ||
        memcmp(&fixture.state, &expected, sizeof(expected)) != 0 ||
        fixture.context.allocate_calls != 0 ||
        fixture.context.release_calls != 0 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1) {
        return rome2_test_failure(
            "preallocated accepts null inactive allocation callbacks");
    }

    rome2_test_setup(&fixture, 0, 0, 0);
    fixture.effects.release = NULL;
    expected = fixture.state;
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 1);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 1);
    rome2_test_put_u32(
        expected.bytes, ROME2_TEST_VECTOR_OFFSET + 12, allocation);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_NEW_OFFSET, handler);
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_OK || result != UINT8_C(0xd3) ||
        memcmp(&fixture.state, &expected, sizeof(expected)) != 0 ||
        fixture.context.allocate_calls != 1 ||
        fixture.context.release_calls != 0 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1) {
        return rome2_test_failure(
            "capacity-zero accepts null inactive release callback");
    }
    return 0;
}

static int rome2_test_drain_limit_all_routes(void)
{
    rome2_test_fixture fixture;
    rome2_test_state_memory expected;
    rome2_100e2460_branch_status status;
    uint32_t old_backing = ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET;
    uint32_t allocation = ROME2_TEST_STATE_BASE + ROME2_TEST_NEW_OFFSET;
    uint32_t handler = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    uint8_t result;

    rome2_test_setup(&fixture, 2, 1, old_backing);
    fixture.context.peek_values[0] = 1;
    expected = fixture.state;
    rome2_test_put_u32(expected.bytes, ROME2_TEST_OLD_OFFSET + 4, handler);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 2);
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_DRAIN_LIMIT ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &expected, sizeof(expected)) != 0 ||
        fixture.context.allocate_calls != 0 ||
        fixture.context.release_calls != 0 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1) {
        return rome2_test_failure("preallocated drain-limit propagation");
    }

    rome2_test_setup(&fixture, 0, 0, 0);
    fixture.context.peek_values[0] = UINT32_MAX;
    expected = fixture.state;
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 1);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 1);
    rome2_test_put_u32(
        expected.bytes, ROME2_TEST_VECTOR_OFFSET + 12, allocation);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_NEW_OFFSET, handler);
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_DRAIN_LIMIT ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &expected, sizeof(expected)) != 0 ||
        fixture.context.allocate_calls != 1 ||
        fixture.context.release_calls != 0 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1) {
        return rome2_test_failure("capacity-zero drain-limit propagation");
    }

    rome2_test_setup(&fixture, 2, 2, old_backing);
    fixture.context.peek_values[0] = 1;
    expected = fixture.state;
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 4);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 3);
    rome2_test_put_u32(
        expected.bytes, ROME2_TEST_VECTOR_OFFSET + 12, allocation);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_NEW_OFFSET, ROME2_TEST_OLD_A);
    rome2_test_put_u32(
        expected.bytes, ROME2_TEST_NEW_OFFSET + 4, ROME2_TEST_OLD_B);
    rome2_test_put_u32(expected.bytes, ROME2_TEST_NEW_OFFSET + 8, handler);
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_DRAIN_LIMIT ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &expected, sizeof(expected)) != 0 ||
        fixture.context.allocate_calls != 1 ||
        fixture.context.release_calls != 1 ||
        fixture.context.dispatch_calls != 1 ||
        fixture.context.peek_calls != 1) {
        return rome2_test_failure("growth drain-limit propagation");
    }
    return 0;
}

static int rome2_test_invalid_allocation_partial_commits(void)
{
    rome2_test_fixture fixture;
    rome2_test_state_memory expected;
    rome2_100e2460_branch_status status;
    uint32_t old_backing = ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET;
    uint8_t result;

    rome2_test_setup(&fixture, 0, 0, 0);
    fixture.context.allocation_result = rome2_test_address(0);
    expected = fixture.state;
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 1);
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &expected, sizeof(expected)) != 0 ||
        fixture.context.allocate_calls != 1 ||
        fixture.context.release_calls != 0 ||
        fixture.context.dispatch_calls != 0 ||
        fixture.context.peek_calls != 0 ||
        fixture.context.event_count != 1 ||
        fixture.context.events[0] != ROME2_TEST_EVENT_ALLOCATE) {
        return rome2_test_failure("capacity-zero invalid allocation commit");
    }

    rome2_test_setup(&fixture, 2, 2, old_backing);
    fixture.context.allocation_result = rome2_test_address(0);
    expected = fixture.state;
    rome2_test_put_u32(expected.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 4);
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &expected, sizeof(expected)) != 0 ||
        fixture.context.allocate_calls != 1 ||
        fixture.context.release_calls != 0 ||
        fixture.context.dispatch_calls != 0 ||
        fixture.context.peek_calls != 0 ||
        fixture.context.event_count != 1 ||
        fixture.context.events[0] != ROME2_TEST_EVENT_ALLOCATE) {
        return rome2_test_failure("growth invalid allocation commit");
    }
    return 0;
}

static int rome2_test_malformed_count_capacity_states(void)
{
    rome2_test_fixture fixture;
    rome2_test_state_memory before;
    rome2_100e2460_branch_status status;
    uint32_t old_backing = ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET;
    uint8_t result;

    rome2_test_setup(&fixture, 2, 3, old_backing);
    before = fixture.state;
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_BAD_ARGUMENT ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("count greater than capacity rejected");
    }

    rome2_test_setup(&fixture, 0, 1, 0);
    before = fixture.state;
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_BAD_ARGUMENT ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("zero capacity nonzero count rejected");
    }

    rome2_test_setup(&fixture, 0, 0, old_backing);
    before = fixture.state;
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_BAD_ARGUMENT ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("zero route nonzero backing rejected");
    }

    rome2_test_setup(
        &fixture,
        ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY + UINT32_C(1),
        ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY + UINT32_C(1),
        old_backing);
    before = fixture.state;
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_RANGE_OVERFLOW ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("unsafe equal growth capacity rejected");
    }
    return 0;
}

static int rome2_test_descriptor_and_output_failures(void)
{
    rome2_test_fixture fixture;
    rome2_test_state_memory before;
    rome2_guest_write_view descriptor_before;
    rome2_100e2460_branch_status status;
    uint32_t old_backing = ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET;
    uint8_t result = UINT8_C(0xcc);

    rome2_test_setup(&fixture, 2, 1, old_backing);
    before = fixture.state;
    status = rome2_port_100e2460_run_router(
        NULL,
        &fixture.vtable_view,
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        rome2_test_address(ROME2_TEST_ARGUMENT),
        &fixture.effects,
        1,
        &result);
    if (status != ROME2_100E2460_BRANCH_BAD_ARGUMENT ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("null state descriptor rejected");
    }

    rome2_test_setup(&fixture, 2, 1, old_backing);
    before = fixture.state;
    result = UINT8_C(0xcc);
    status = rome2_port_100e2460_run_router(
        &fixture.state_view,
        &fixture.vtable_view,
        rome2_test_address(ROME2_TEST_STATE_BASE - UINT32_C(4)),
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        rome2_test_address(ROME2_TEST_ARGUMENT),
        &fixture.effects,
        1,
        &result);
    if (status != ROME2_100E2460_BRANCH_OUT_OF_RANGE ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("vector outside state descriptor rejected");
    }

    rome2_test_setup(&fixture, 2, 1, old_backing);
    before = fixture.state;
    descriptor_before = fixture.state_view;
    status = rome2_port_100e2460_run_router(
        &fixture.state_view,
        &fixture.vtable_view,
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        rome2_test_address(ROME2_TEST_ARGUMENT),
        &fixture.effects,
        1,
        (uint8_t *)&fixture.state_view);
    if (status != ROME2_100E2460_BRANCH_BAD_ARGUMENT ||
        memcmp(&fixture.state_view, &descriptor_before,
            sizeof(descriptor_before)) != 0 ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("output aliases state descriptor");
    }

    rome2_test_setup(&fixture, 2, 1, old_backing);
    before = fixture.state;
    result = UINT8_C(0xcc);
    status = rome2_port_100e2460_run_router(
        &fixture.state_view,
        &fixture.vtable_view,
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        rome2_test_address(ROME2_TEST_ARGUMENT),
        &fixture.effects,
        1,
        fixture.state.bytes + ROME2_TEST_OUTPUT_OFFSET);
    if (status != ROME2_100E2460_BRANCH_BAD_ARGUMENT ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("output aliases mapped state bytes");
    }
    return 0;
}

static int rome2_test_method_alias_failures(void)
{
    rome2_test_fixture fixture;
    rome2_test_state_memory before;
    rome2_100e2460_branch_status status;
    uint32_t old_backing = ROME2_TEST_STATE_BASE + ROME2_TEST_OLD_OFFSET;
    uint32_t alias_vtable;
    uint8_t result;

    rome2_test_setup(&fixture, 2, 1, old_backing);
    alias_vtable =
        ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET + UINT32_C(4);
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET, alias_vtable);
    fixture.vtable_view.guest_base = ROME2_TEST_STATE_BASE;
    rome2_test_put_u32(
        fixture.vtables.bytes, ROME2_TEST_VECTOR_OFFSET + 8,
        ROME2_TEST_METHOD);
    before = fixture.state;
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_BAD_ARGUMENT ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("method logically aliases count write");
    }

    rome2_test_setup(&fixture, 2, 1, old_backing);
    alias_vtable =
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VECTOR_OFFSET + UINT32_C(4);
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET, alias_vtable);
    fixture.vtable_view.host_base = fixture.state.bytes;
    fixture.vtable_view.byte_count = sizeof(fixture.state.bytes);
    before = fixture.state;
    result = UINT8_C(0xcc);
    status = rome2_test_run(&fixture, 1, &result);
    if (status != ROME2_100E2460_BRANCH_BAD_ARGUMENT ||
        result != UINT8_C(0xcc) ||
        memcmp(&fixture.state, &before, sizeof(before)) != 0 ||
        !rome2_test_no_effects(&fixture.context)) {
        return rome2_test_failure("method physically aliases count write");
    }
    return 0;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_preallocated_route();
    failures += rome2_test_unsigned_preallocated_route();
    failures += rome2_test_capacity_zero_route();
    failures += rome2_test_growth_route();
    failures += rome2_test_inactive_callbacks_are_route_specific();
    failures += rome2_test_drain_limit_all_routes();
    failures += rome2_test_invalid_allocation_partial_commits();
    failures += rome2_test_malformed_count_capacity_states();
    failures += rome2_test_descriptor_and_output_failures();
    failures += rome2_test_method_alias_failures();
    if (failures != 0) {
        return 1;
    }
    puts("startup 100e2460 router tests: pass");
    return 0;
}

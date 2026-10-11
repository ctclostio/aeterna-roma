#include "ported_100e2460_capacity_zero_branch.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_STATE_BASE UINT32_C(0x3000)
#define ROME2_TEST_STATE_BYTES 512
#define ROME2_TEST_VECTOR_OFFSET UINT32_C(0x40)
#define ROME2_TEST_HANDLER_OFFSET UINT32_C(0xa0)
#define ROME2_TEST_ALLOCATION_OFFSET UINT32_C(0x140)
#define ROME2_TEST_VTABLE_BASE UINT32_C(0x1173f200)
#define ROME2_TEST_VTABLE_BYTES 512
#define ROME2_TEST_VTABLE_OFFSET UINT32_C(0x20)
#define ROME2_TEST_METHOD_IDENTITY UINT32_C(0x100e9340)
#define ROME2_TEST_ARGUMENT UINT32_C(0x2824)
#define ROME2_TEST_VECTOR_SENTINEL UINT32_C(0xfeedface)
#define ROME2_TEST_CELL_SENTINEL UINT32_C(0xa5a5a5a5)
#define ROME2_TEST_MAX_EVENTS 32

#define ROME2_TEST_EVENT_ALLOCATE UINT32_C(1)
#define ROME2_TEST_EVENT_DISPATCH UINT32_C(2)
#define ROME2_TEST_EVENT_PEEK UINT32_C(3)

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
    size_t expected_allocation_offset;
    uint32_t expected_handler;
    uint32_t expected_method;
    uint32_t expected_argument;
    uint32_t expected_allocation_before;
    rome2_guest_addr32 allocation_result;
    uint32_t dispatch_eax;
    uint32_t peek_values[ROME2_TEST_MAX_EVENTS];
    uint32_t peek_value_count;
    uint32_t peek_index;
    uint32_t trace[ROME2_TEST_MAX_EVENTS];
    uint32_t trace_count;
    uint32_t allocate_calls;
    uint32_t dispatch_calls;
    uint32_t peek_calls;
    uint32_t observed_allocation_bytes;
    uint32_t observed_allocation_class;
    uint32_t observed_receiver;
    uint32_t observed_method;
    uint32_t observed_argument;
    uint32_t bad_observation_count;
    int check_allocation_cell;
} rome2_test_effect_context;

typedef struct rome2_test_fixture {
    rome2_test_state_memory state;
    rome2_test_vtable_memory vtables;
    rome2_guest_write_view state_view;
    rome2_guest_read_view vtable_view;
    rome2_100e2460_capacity_zero_effects effects;
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

static rome2_guest_addr32 rome2_test_allocate(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    rome2_test_effect_context *context =
        (rome2_test_effect_context *)opaque_context;

    rome2_test_trace(context, ROME2_TEST_EVENT_ALLOCATE);
    ++context->allocate_calls;
    context->observed_allocation_bytes = byte_count;
    context->observed_allocation_class = allocation_class;
    if (context->trace_count != 1 ||
        context->trace[0] != ROME2_TEST_EVENT_ALLOCATE ||
        byte_count != ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_BYTES ||
        allocation_class !=
            ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_CLASS ||
        rome2_test_get_u32(
            context->state_bytes, context->vector_offset) !=
                ROME2_TEST_VECTOR_SENTINEL ||
        rome2_test_get_u32(
            context->state_bytes, context->vector_offset + 4) != 1 ||
        rome2_test_get_u32(
            context->state_bytes, context->vector_offset + 8) != 0 ||
        rome2_test_get_u32(
            context->state_bytes, context->vector_offset + 12) != 0 ||
        context->dispatch_calls != 0 || context->peek_calls != 0) {
        ++context->bad_observation_count;
    }
    if (context->check_allocation_cell &&
        rome2_test_get_u32(
            context->state_bytes, context->expected_allocation_offset) !=
                context->expected_allocation_before) {
        ++context->bad_observation_count;
    }
    return context->allocation_result;
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
    if (context->trace_count != 2 ||
        context->trace[0] != ROME2_TEST_EVENT_ALLOCATE ||
        context->trace[1] != ROME2_TEST_EVENT_DISPATCH ||
        context->allocate_calls != 1 || context->peek_calls != 0 ||
        rome2_test_get_u32(
            context->state_bytes, context->vector_offset + 4) != 1 ||
        rome2_test_get_u32(
            context->state_bytes, context->vector_offset + 8) != 1 ||
        rome2_test_get_u32(
            context->state_bytes, context->vector_offset + 12) !=
                context->allocation_result.value ||
        rome2_test_get_u32(
            context->state_bytes, context->expected_allocation_offset) !=
                context->expected_handler ||
        receiver.value != context->expected_handler ||
        method.value != context->expected_method ||
        argument.value != context->expected_argument) {
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
    if (context->trace_count < 3 ||
        context->trace[0] != ROME2_TEST_EVENT_ALLOCATE ||
        context->trace[1] != ROME2_TEST_EVENT_DISPATCH ||
        context->allocate_calls != 1 || context->dispatch_calls != 1 ||
        message.value != 0 || window.value != 0 || filter_min != 0 ||
        filter_max != 0 ||
        remove_flags != ROME2_PORT_100E2460_PM_REMOVE ||
        context->peek_index >= context->peek_value_count) {
        ++context->bad_observation_count;
    }
    if (context->peek_index >= context->peek_value_count) {
        return 0;
    }
    value = context->peek_values[context->peek_index];
    ++context->peek_index;
    return value;
}

static void rome2_test_setup(rome2_test_fixture *fixture)
{
    uint32_t handler = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    uint32_t vtable = ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET;

    memset(fixture, 0, sizeof(*fixture));
    memset(fixture->state.bytes, 0xa5, sizeof(fixture->state.bytes));
    memset(fixture->vtables.bytes, 0x5a, sizeof(fixture->vtables.bytes));
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
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_HANDLER_OFFSET, vtable);
    rome2_test_put_u32(
        fixture->vtables.bytes,
        ROME2_TEST_VTABLE_OFFSET,
        UINT32_C(0x100e1900));
    rome2_test_put_u32(
        fixture->vtables.bytes,
        ROME2_TEST_VTABLE_OFFSET + 4,
        ROME2_TEST_METHOD_IDENTITY);
    rome2_test_put_u32(
        fixture->vtables.bytes,
        ROME2_TEST_VTABLE_OFFSET + 8,
        UINT32_C(0x100e9999));

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

    fixture->context.state_bytes = fixture->state.bytes;
    fixture->context.vector_offset = ROME2_TEST_VECTOR_OFFSET;
    fixture->context.expected_allocation_offset =
        ROME2_TEST_ALLOCATION_OFFSET;
    fixture->context.expected_handler = handler;
    fixture->context.expected_method = ROME2_TEST_METHOD_IDENTITY;
    fixture->context.expected_argument = ROME2_TEST_ARGUMENT;
    fixture->context.expected_allocation_before = ROME2_TEST_CELL_SENTINEL;
    fixture->context.allocation_result = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_ALLOCATION_OFFSET);
    fixture->context.check_allocation_cell = 1;
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

static int rome2_test_views_unchanged(
    const char *label,
    const rome2_test_fixture *fixture,
    const rome2_guest_write_view *expected_state_view,
    const rome2_guest_read_view *expected_vtable_view)
{
    if (fixture->state_view.host_base == expected_state_view->host_base &&
        fixture->state_view.guest_base == expected_state_view->guest_base &&
        fixture->state_view.byte_count == expected_state_view->byte_count &&
        fixture->vtable_view.host_base == expected_vtable_view->host_base &&
        fixture->vtable_view.guest_base == expected_vtable_view->guest_base &&
        fixture->vtable_view.byte_count == expected_vtable_view->byte_count) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: view descriptor changed\n", label);
    return 1;
}

static int rome2_test_effects_unchanged(
    const char *label,
    const rome2_100e2460_capacity_zero_effects *actual,
    const rome2_100e2460_capacity_zero_effects *expected)
{
    if (actual->tail_effects.context == expected->tail_effects.context &&
        actual->tail_effects.dispatch == expected->tail_effects.dispatch &&
        actual->tail_effects.peek == expected->tail_effects.peek &&
        actual->allocate == expected->allocate) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: effects table changed\n", label);
    return 1;
}

static int rome2_test_effect_trace(
    const char *label,
    const rome2_test_effect_context *context,
    uint32_t expected_peek_calls)
{
    uint32_t index;
    int failures = 0;

    if (context->allocate_calls != 1 || context->dispatch_calls != 1 ||
        context->peek_calls != expected_peek_calls ||
        context->peek_index != expected_peek_calls ||
        context->trace_count != expected_peek_calls + UINT32_C(2) ||
        context->trace[0] != ROME2_TEST_EVENT_ALLOCATE ||
        context->trace[1] != ROME2_TEST_EVENT_DISPATCH ||
        context->observed_allocation_bytes !=
            ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_BYTES ||
        context->observed_allocation_class !=
            ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_CLASS ||
        context->observed_receiver != context->expected_handler ||
        context->observed_method != context->expected_method ||
        context->observed_argument != context->expected_argument ||
        context->bad_observation_count != 0) {
        fprintf(stderr, "FAIL %s: effect count/order/arguments differ\n", label);
        ++failures;
    }
    for (index = 2; index < context->trace_count; ++index) {
        if (context->trace[index] != ROME2_TEST_EVENT_PEEK) {
            fprintf(stderr, "FAIL %s: Peek effect order differs\n", label);
            ++failures;
            break;
        }
    }
    return failures;
}

static int rome2_test_success_case(
    const char *label,
    size_t allocation_offset,
    rome2_guest_addr32 argument,
    uint32_t dispatch_eax,
    const uint32_t *peek_values,
    uint32_t peek_value_count,
    uint32_t max_peek_calls,
    uint8_t expected_al)
{
    rome2_test_fixture fixture;
    rome2_test_state_memory expected_state;
    rome2_test_vtable_memory expected_vtables;
    rome2_guest_write_view expected_state_view;
    rome2_guest_read_view expected_vtable_view;
    rome2_100e2460_capacity_zero_effects expected_effects;
    rome2_100e2460_branch_status status;
    uint32_t index;
    uint8_t result = UINT8_C(0xc7);
    int failures = 0;

    rome2_test_setup(&fixture);
    fixture.context.expected_allocation_offset = allocation_offset;
    fixture.context.expected_allocation_before = rome2_test_get_u32(
        fixture.state.bytes, allocation_offset);
    fixture.context.allocation_result = rome2_test_address(
        ROME2_TEST_STATE_BASE + (uint32_t)allocation_offset);
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
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 1);
    rome2_test_put_u32(
        expected_state.bytes,
        ROME2_TEST_VECTOR_OFFSET + 12,
        fixture.context.allocation_result.value);
    rome2_test_put_u32(
        expected_state.bytes,
        allocation_offset,
        fixture.context.expected_handler);
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 1);

    status = rome2_port_100e2460_run_capacity_zero_branch(
        &fixture.state_view,
        &fixture.vtable_view,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        argument,
        &fixture.effects,
        max_peek_calls,
        &result);
    failures += rome2_test_expect_status(
        label, status, ROME2_100E2460_BRANCH_OK);
    if (result != expected_al) {
        fprintf(stderr, "FAIL %s: AL=0x%02x expected=0x%02x\n",
            label, (unsigned int)result, (unsigned int)expected_al);
        ++failures;
    }
    if (memcmp(&fixture.state, &expected_state, sizeof(fixture.state)) != 0) {
        fprintf(stderr, "FAIL %s: exact guest-state oracle differs\n", label);
        ++failures;
    }
    if (memcmp(&fixture.vtables, &expected_vtables,
            sizeof(fixture.vtables)) != 0) {
        fprintf(stderr, "FAIL %s: vtable bytes changed\n", label);
        ++failures;
    }
    failures += rome2_test_views_unchanged(
        label, &fixture, &expected_state_view, &expected_vtable_view);
    failures += rome2_test_effects_unchanged(
        label, &fixture.effects, &expected_effects);
    failures += rome2_test_effect_trace(
        label, &fixture.context, peek_value_count);
    return failures;
}

static int rome2_test_success_matrix(void)
{
    static const uint32_t empty_queue[] = {UINT32_C(0)};
    static const uint32_t nonzero_queue[] = {
        UINT32_C(1), UINT32_C(0x80000000), UINT32_C(0)
    };
    static const uint32_t final_false[] = {UINT32_C(7), UINT32_C(0)};
    int failures = 0;

    failures += rome2_test_success_case(
        "capacity zero allocates before empty queue tail",
        ROME2_TEST_ALLOCATION_OFFSET,
        rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0x123456a5),
        empty_queue,
        1,
        1,
        UINT8_C(0xa5));
    failures += rome2_test_success_case(
        "any nonzero Peek result continues and returns low ff",
        ROME2_TEST_ALLOCATION_OFFSET,
        rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0xabcdefff),
        nonzero_queue,
        3,
        3,
        UINT8_C(0xff));
    failures += rome2_test_success_case(
        "false on final budget call publishes zero AL",
        ROME2_TEST_ALLOCATION_OFFSET,
        rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0x12340000),
        final_false,
        2,
        2,
        UINT8_C(0));
    failures += rome2_test_success_case(
        "opaque zero dispatch argument is preserved",
        ROME2_TEST_ALLOCATION_OFFSET,
        rome2_test_address(0),
        UINT32_C(0x1020307e),
        empty_queue,
        1,
        1,
        UINT8_C(0x7e));
    failures += rome2_test_success_case(
        "unaligned allocation result is byte-addressable",
        ROME2_TEST_ALLOCATION_OFFSET + 1,
        rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0x55),
        empty_queue,
        1,
        1,
        UINT8_C(0x55));
    failures += rome2_test_success_case(
        "allocation cell ends exactly at state view end",
        ROME2_TEST_STATE_BYTES - ROME2_PORT_100E2460_ELEMENT_BYTES,
        rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0x66),
        empty_queue,
        1,
        1,
        UINT8_C(0x66));
    failures += rome2_test_success_case(
        "allocation cell ends exactly at vector start",
        ROME2_TEST_VECTOR_OFFSET - ROME2_PORT_100E2460_ELEMENT_BYTES,
        rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0x77),
        empty_queue,
        1,
        1,
        UINT8_C(0x77));
    failures += rome2_test_success_case(
        "allocation cell begins exactly at vector end",
        ROME2_TEST_VECTOR_OFFSET + ROME2_PORT_100E2460_VECTOR_BYTES,
        rome2_test_address(ROME2_TEST_ARGUMENT),
        UINT32_C(0x88),
        empty_queue,
        1,
        1,
        UINT8_C(0x88));
    return failures;
}

static int rome2_test_drain_limit(void)
{
    rome2_test_fixture fixture;
    rome2_test_state_memory expected_state;
    rome2_test_vtable_memory expected_vtables;
    rome2_100e2460_branch_status status;
    uint8_t result = UINT8_C(0xc7);
    int failures = 0;

    rome2_test_setup(&fixture);
    fixture.context.dispatch_eax = UINT32_C(0x1234565a);
    fixture.context.peek_values[0] = UINT32_C(0x80000000);
    fixture.context.peek_value_count = 1;
    expected_state = fixture.state;
    expected_vtables = fixture.vtables;
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 1);
    rome2_test_put_u32(
        expected_state.bytes,
        ROME2_TEST_VECTOR_OFFSET + 12,
        ROME2_TEST_STATE_BASE + ROME2_TEST_ALLOCATION_OFFSET);
    rome2_test_put_u32(
        expected_state.bytes,
        ROME2_TEST_ALLOCATION_OFFSET,
        ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET);
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 1);

    status = rome2_port_100e2460_run_capacity_zero_branch(
        &fixture.state_view,
        &fixture.vtable_view,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        rome2_test_address(ROME2_TEST_ARGUMENT),
        &fixture.effects,
        1,
        &result);
    failures += rome2_test_expect_status(
        "one-call drain limit",
        status,
        ROME2_100E2460_BRANCH_DRAIN_LIMIT);
    if (result != UINT8_C(0xc7) ||
        memcmp(&fixture.state, &expected_state, sizeof(fixture.state)) != 0 ||
        memcmp(&fixture.vtables, &expected_vtables,
            sizeof(fixture.vtables)) != 0) {
        fprintf(stderr,
            "FAIL one-call drain limit: commit/output oracle differs\n");
        ++failures;
    }
    failures += rome2_test_effect_trace(
        "one-call drain limit", &fixture.context, 1);
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
    rome2_100e2460_capacity_zero_effects expected_effects = fixture->effects;
    rome2_100e2460_branch_status status;
    uint8_t result = UINT8_C(0xc7);
    int failures = 0;

    fixture->context.allocation_result = allocation_result;
    fixture->context.check_allocation_cell = 0;
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 1);
    status = rome2_port_100e2460_run_capacity_zero_branch(
        &fixture->state_view,
        &fixture->vtable_view,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        rome2_test_address(ROME2_TEST_ARGUMENT),
        &fixture->effects,
        3,
        &result);
    failures += rome2_test_expect_status(
        label,
        status,
        ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID);
    if (result != UINT8_C(0xc7) ||
        memcmp(&fixture->state, &expected_state, sizeof(fixture->state)) != 0 ||
        memcmp(&fixture->vtables, &expected_vtables,
            sizeof(fixture->vtables)) != 0) {
        fprintf(stderr,
            "FAIL %s: invalid-result partial-commit oracle differs\n", label);
        ++failures;
    }
    failures += rome2_test_views_unchanged(
        label, fixture, &expected_state_view, &expected_vtable_view);
    failures += rome2_test_effects_unchanged(
        label, &fixture->effects, &expected_effects);
    if (fixture->context.allocate_calls != 1 ||
        fixture->context.dispatch_calls != 0 ||
        fixture->context.peek_calls != 0 ||
        fixture->context.peek_index != 0 ||
        fixture->context.trace_count != 1 ||
        fixture->context.trace[0] != ROME2_TEST_EVENT_ALLOCATE ||
        fixture->context.bad_observation_count != 0) {
        fprintf(stderr,
            "FAIL %s: invalid-result callback boundary differs\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_invalid_allocation_results(void)
{
    rome2_test_fixture fixture;
    uint32_t method_guest;
    int failures = 0;

    rome2_test_setup(&fixture);
    failures += rome2_test_invalid_allocation_result(
        "null allocation result",
        &fixture,
        rome2_test_address(0));

    rome2_test_setup(&fixture);
    failures += rome2_test_invalid_allocation_result(
        "allocation result below state view",
        &fixture,
        rome2_test_address(ROME2_TEST_STATE_BASE - UINT32_C(1)));

    rome2_test_setup(&fixture);
    failures += rome2_test_invalid_allocation_result(
        "allocation result guest end overflows",
        &fixture,
        rome2_test_address(UINT32_MAX - UINT32_C(2)));

    rome2_test_setup(&fixture);
    failures += rome2_test_invalid_allocation_result(
        "allocation result is truncated at view end",
        &fixture,
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES - UINT32_C(3)));

    rome2_test_setup(&fixture);
    failures += rome2_test_invalid_allocation_result(
        "allocation result overlaps vector by one byte",
        &fixture,
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET - UINT32_C(3)));

    rome2_test_setup(&fixture);
    failures += rome2_test_invalid_allocation_result(
        "allocation result aliases handler cell",
        &fixture,
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET));

    rome2_test_setup(&fixture);
    method_guest = ROME2_TEST_STATE_BASE + UINT32_C(0x180);
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_HANDLER_OFFSET,
        method_guest - UINT32_C(4));
    fixture.vtable_view.guest_base = ROME2_TEST_STATE_BASE;
    rome2_test_put_u32(
        fixture.vtables.bytes,
        method_guest - ROME2_TEST_STATE_BASE,
        ROME2_TEST_METHOD_IDENTITY);
    failures += rome2_test_invalid_allocation_result(
        "allocation result logically aliases method cell",
        &fixture,
        rome2_test_address(method_guest));

    rome2_test_setup(&fixture);
    method_guest =
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET + UINT32_C(4);
    fixture.vtable_view.host_base = fixture.state.bytes;
    fixture.vtable_view.guest_base =
        method_guest - ROME2_TEST_ALLOCATION_OFFSET;
    fixture.vtable_view.byte_count = sizeof(fixture.state.bytes);
    failures += rome2_test_invalid_allocation_result(
        "allocation result physically aliases method cell",
        &fixture,
        rome2_test_address(
            ROME2_TEST_STATE_BASE + ROME2_TEST_ALLOCATION_OFFSET));
    return failures;
}

static int rome2_test_precommit_failure(
    const char *label,
    rome2_test_fixture *fixture,
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 vector,
    rome2_guest_addr32 handler,
    const rome2_100e2460_capacity_zero_effects *effects,
    uint32_t max_peek_calls,
    uint8_t *result_out,
    rome2_100e2460_branch_status expected_status)
{
    rome2_test_state_memory state_snapshot = fixture->state;
    rome2_test_vtable_memory vtable_snapshot = fixture->vtables;
    rome2_guest_write_view state_view_snapshot = fixture->state_view;
    rome2_guest_read_view vtable_view_snapshot = fixture->vtable_view;
    rome2_100e2460_capacity_zero_effects effects_snapshot = fixture->effects;
    uint8_t result_snapshot = result_out == NULL ? 0 : *result_out;
    rome2_100e2460_branch_status status;
    int failures = 0;

    status = rome2_port_100e2460_run_capacity_zero_branch(
        state_view,
        vtable_view,
        vector,
        handler,
        rome2_test_address(ROME2_TEST_ARGUMENT),
        effects,
        max_peek_calls,
        result_out);
    failures += rome2_test_expect_status(label, status, expected_status);
    if (memcmp(&fixture->state, &state_snapshot, sizeof(fixture->state)) != 0 ||
        memcmp(&fixture->vtables, &vtable_snapshot,
            sizeof(fixture->vtables)) != 0) {
        fprintf(stderr, "FAIL %s: guest bytes changed before commit\n", label);
        ++failures;
    }
    failures += rome2_test_views_unchanged(
        label, fixture, &state_view_snapshot, &vtable_view_snapshot);
    failures += rome2_test_effects_unchanged(
        label, &fixture->effects, &effects_snapshot);
    if (result_out != NULL && *result_out != result_snapshot) {
        fprintf(stderr, "FAIL %s: return byte changed before commit\n", label);
        ++failures;
    }
    if (fixture->context.allocate_calls != 0 ||
        fixture->context.dispatch_calls != 0 ||
        fixture->context.peek_calls != 0 ||
        fixture->context.peek_index != 0 ||
        fixture->context.trace_count != 0 ||
        fixture->context.bad_observation_count != 0) {
        fprintf(stderr, "FAIL %s: callback ran before commit\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_precommit_failures(void)
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
    do { rome2_test_setup(&fixture); result = UINT8_C(0xc7); } while (0)
#define ROME2_FAIL(label, expected) \
    (failures += rome2_test_precommit_failure( \
        (label), &fixture, &fixture.state_view, &fixture.vtable_view, \
        vector, handler, &fixture.effects, 3, &result, (expected)))

    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "null state view", &fixture, NULL, &fixture.vtable_view,
        vector, handler, &fixture.effects, 3, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "null vtable view", &fixture, &fixture.state_view, NULL,
        vector, handler, &fixture.effects, 3, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "null effects", &fixture, &fixture.state_view, &fixture.vtable_view,
        vector, handler, NULL, 3, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "null result", &fixture, &fixture.state_view, &fixture.vtable_view,
        vector, handler, &fixture.effects, 3, NULL,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    fixture.effects.allocate = NULL;
    ROME2_FAIL("null allocation adapter", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    fixture.effects.tail_effects.dispatch = NULL;
    ROME2_FAIL("null dispatch adapter", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    fixture.effects.tail_effects.peek = NULL;
    ROME2_FAIL("null Peek adapter", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "zero drain budget", &fixture, &fixture.state_view,
        &fixture.vtable_view, vector, handler, &fixture.effects, 0, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    fixture.state_view.host_base = NULL;
    ROME2_FAIL("null state host", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    fixture.vtable_view.host_base = NULL;
    ROME2_FAIL("null vtable host", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    fixture.state_view.guest_base = UINT32_MAX - UINT32_C(7);
    fixture.state_view.byte_count = 9;
    ROME2_FAIL(
        "state guest end overflow", ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    ROME2_RESET();
    fixture.vtable_view.guest_base = UINT32_MAX - UINT32_C(7);
    fixture.vtable_view.byte_count = 9;
    ROME2_FAIL(
        "vtable guest end overflow", ROME2_100E2460_BRANCH_RANGE_OVERFLOW);

    ROME2_RESET();
    vector.value = 0;
    ROME2_FAIL("null vector", ROME2_100E2460_BRANCH_NULL_ADDRESS);
    vector.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;
    ROME2_RESET();
    vector.value = UINT32_MAX - UINT32_C(14);
    ROME2_FAIL("vector end overflow", ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    vector.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;
    ROME2_RESET();
    vector.value =
        ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES - UINT32_C(15);
    ROME2_FAIL("truncated vector", ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    vector.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;

    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 1);
    ROME2_FAIL("nonzero capacity is another route",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 1);
    ROME2_FAIL("zero capacity with nonzero count is unsafe",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, UINT32_MAX);
    ROME2_FAIL("zero capacity with maximum count is unsafe",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_VECTOR_OFFSET + 12,
        ROME2_TEST_STATE_BASE + ROME2_TEST_ALLOCATION_OFFSET);
    ROME2_FAIL("nonzero old backing violates ownership invariant",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    handler.value = 0;
    ROME2_FAIL("null handler", ROME2_100E2460_BRANCH_NULL_ADDRESS);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    ROME2_RESET();
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES - 3;
    ROME2_FAIL("truncated handler cell",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    ROME2_RESET();
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET + 4;
    ROME2_FAIL("handler aliases pending capacity write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    ROME2_RESET();
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET + 8;
    ROME2_FAIL("handler aliases pending count write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    ROME2_RESET();
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET + 12;
    ROME2_FAIL("handler aliases pending backing write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;

    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET, 0);
    ROME2_FAIL("null vtable identity", ROME2_100E2460_BRANCH_NULL_ADDRESS);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_HANDLER_OFFSET,
        UINT32_MAX - UINT32_C(3));
    ROME2_FAIL("vtable plus four overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_HANDLER_OFFSET,
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_BYTES - 7);
    ROME2_FAIL("truncated method cell",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.vtables.bytes, ROME2_TEST_VTABLE_OFFSET + 4, 0);
    ROME2_FAIL("null method identity", ROME2_100E2460_BRANCH_NULL_ADDRESS);

    ROME2_RESET();
    method_guest = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET + 4;
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_HANDLER_OFFSET,
        method_guest - UINT32_C(4));
    fixture.vtable_view.guest_base = ROME2_TEST_STATE_BASE;
    rome2_test_put_u32(
        fixture.vtables.bytes,
        method_guest - ROME2_TEST_STATE_BASE,
        ROME2_TEST_METHOD_IDENTITY);
    ROME2_FAIL("method logically aliases capacity write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    method_guest = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET + 8;
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_HANDLER_OFFSET,
        method_guest - UINT32_C(4));
    fixture.vtable_view.guest_base = ROME2_TEST_STATE_BASE;
    rome2_test_put_u32(
        fixture.vtables.bytes,
        method_guest - ROME2_TEST_STATE_BASE,
        ROME2_TEST_METHOD_IDENTITY);
    ROME2_FAIL("method logically aliases count write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    method_guest = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET + 12;
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_HANDLER_OFFSET,
        method_guest - UINT32_C(4));
    fixture.vtable_view.guest_base = ROME2_TEST_STATE_BASE;
    rome2_test_put_u32(
        fixture.vtables.bytes,
        method_guest - ROME2_TEST_STATE_BASE,
        ROME2_TEST_METHOD_IDENTITY);
    ROME2_FAIL("method logically aliases backing write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    method_guest =
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET + UINT32_C(4);
    fixture.vtable_view.host_base = fixture.state.bytes;
    fixture.vtable_view.guest_base =
        method_guest - (ROME2_TEST_VECTOR_OFFSET + UINT32_C(4));
    fixture.vtable_view.byte_count = sizeof(fixture.state.bytes);
    ROME2_FAIL("method physically aliases capacity write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    method_guest =
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET + UINT32_C(4);
    fixture.vtable_view.host_base = fixture.state.bytes;
    fixture.vtable_view.guest_base =
        method_guest - (ROME2_TEST_VECTOR_OFFSET + UINT32_C(8));
    fixture.vtable_view.byte_count = sizeof(fixture.state.bytes);
    ROME2_FAIL("method physically aliases count write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    method_guest =
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET + UINT32_C(4);
    fixture.vtable_view.host_base = fixture.state.bytes;
    fixture.vtable_view.guest_base =
        method_guest - (ROME2_TEST_VECTOR_OFFSET + UINT32_C(12));
    fixture.vtable_view.byte_count = sizeof(fixture.state.bytes);
    ROME2_FAIL("method physically aliases backing write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "return byte aliases state bytes", &fixture, &fixture.state_view,
        &fixture.vtable_view, vector, handler, &fixture.effects, 3,
        &fixture.state.bytes[0], ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "return byte aliases vtable bytes", &fixture, &fixture.state_view,
        &fixture.vtable_view, vector, handler, &fixture.effects, 3,
        &fixture.vtables.bytes[0], ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "return byte aliases effects table", &fixture, &fixture.state_view,
        &fixture.vtable_view, vector, handler, &fixture.effects, 3,
        (uint8_t *)(void *)&fixture.effects,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "state and vtable descriptors alias", &fixture,
        &fixture.state_view,
        (const rome2_guest_read_view *)(const void *)&fixture.state_view,
        vector, handler, &fixture.effects, 3, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "state descriptor and effects alias", &fixture,
        &fixture.state_view, &fixture.vtable_view, vector, handler,
        (const rome2_100e2460_capacity_zero_effects *)(const void *)
            &fixture.state_view,
        3, &result, ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "vtable descriptor and effects alias", &fixture,
        &fixture.state_view, &fixture.vtable_view, vector, handler,
        (const rome2_100e2460_capacity_zero_effects *)(const void *)
            &fixture.vtable_view,
        3, &result, ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "return byte aliases state descriptor", &fixture,
        &fixture.state_view, &fixture.vtable_view, vector, handler,
        &fixture.effects, 3, (uint8_t *)(void *)&fixture.state_view,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_precommit_failure(
        "return byte aliases vtable descriptor", &fixture,
        &fixture.state_view, &fixture.vtable_view, vector, handler,
        &fixture.effects, 3, (uint8_t *)(void *)&fixture.vtable_view,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    fixture.state_view.host_base = (uint8_t *)(void *)&fixture.state_view;
    fixture.state_view.byte_count = sizeof(fixture.state_view);
    ROME2_FAIL("state host aliases state descriptor",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    fixture.state_view.host_base = (uint8_t *)(void *)&fixture.vtable_view;
    fixture.state_view.byte_count = sizeof(fixture.vtable_view);
    ROME2_FAIL("state host aliases vtable descriptor",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    fixture.state_view.host_base = (uint8_t *)(void *)&fixture.effects;
    fixture.state_view.byte_count = sizeof(fixture.effects);
    ROME2_FAIL("state host aliases effects table",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

#undef ROME2_FAIL
#undef ROME2_RESET
    return failures;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_success_matrix();
    failures += rome2_test_drain_limit();
    failures += rome2_test_invalid_allocation_results();
    failures += rome2_test_precommit_failures();
    if (failures != 0) {
        fprintf(stderr,
            "startup 100e2460 capacity-zero-branch tests: %d failure(s)\n",
            failures);
        return 1;
    }
    puts("startup 100e2460 capacity-zero-branch tests: pass");
    return 0;
}

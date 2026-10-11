#include "ported_100e2460_preallocated_branch.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_STATE_BASE UINT32_C(0x2000)
#define ROME2_TEST_STATE_BYTES 256
#define ROME2_TEST_VECTOR_OFFSET UINT32_C(0x20)
#define ROME2_TEST_HANDLER_OFFSET UINT32_C(0x60)
#define ROME2_TEST_BACKING_OFFSET UINT32_C(0x80)
#define ROME2_TEST_VTABLE_BASE UINT32_C(0x1173f200)
#define ROME2_TEST_VTABLE_BYTES 256
#define ROME2_TEST_VTABLE_OFFSET UINT32_C(0x20)
#define ROME2_TEST_METHOD_IDENTITY UINT32_C(0x100e9340)
#define ROME2_TEST_ARGUMENT UINT32_C(0x2824)
#define ROME2_TEST_MAX_EFFECTS 12

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
    size_t expected_count_offset;
    size_t expected_slot_offset;
    uint32_t expected_count;
    uint32_t expected_handler;
    uint32_t expected_method;
    uint32_t expected_argument;
    uint32_t dispatch_eax;
    uint32_t peek_values[ROME2_TEST_MAX_EFFECTS];
    uint32_t peek_value_count;
    uint32_t peek_index;
    uint32_t trace[ROME2_TEST_MAX_EFFECTS];
    uint32_t trace_count;
    uint32_t observed_receiver;
    uint32_t observed_method;
    uint32_t observed_argument;
    uint32_t bad_observation_count;
} rome2_test_effect_context;

typedef struct rome2_test_fixture {
    rome2_test_state_memory state;
    rome2_test_vtable_memory vtables;
    rome2_guest_write_view state_view;
    rome2_guest_read_view vtable_view;
    rome2_100e2460_effects effects;
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
    if (context->trace_count >= ROME2_TEST_MAX_EFFECTS) {
        ++context->bad_observation_count;
        return;
    }
    context->trace[context->trace_count] = event;
    ++context->trace_count;
}

static uint32_t rome2_test_dispatch(
    void *opaque_context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 method,
    rome2_guest_addr32 argument)
{
    rome2_test_effect_context *context =
        (rome2_test_effect_context *)opaque_context;
    uint32_t count = rome2_test_get_u32(
        context->state_bytes, context->expected_count_offset);
    uint32_t slot = rome2_test_get_u32(
        context->state_bytes, context->expected_slot_offset);

    rome2_test_trace(context, UINT32_C(1));
    context->observed_receiver = receiver.value;
    context->observed_method = method.value;
    context->observed_argument = argument.value;
    if (count != context->expected_count ||
        slot != context->expected_handler ||
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

    rome2_test_trace(context, UINT32_C(2));
    if (context->trace_count < 2 || context->trace[0] != UINT32_C(1) ||
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
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET,
        UINT32_C(0xfeedface));
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, 4);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 2);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_VECTOR_OFFSET + 12,
        ROME2_TEST_STATE_BASE + ROME2_TEST_BACKING_OFFSET);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_HANDLER_OFFSET, vtable);
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_BACKING_OFFSET,
        UINT32_C(0x20006010));
    rome2_test_put_u32(
        fixture->state.bytes, ROME2_TEST_BACKING_OFFSET + 4,
        UINT32_C(0x20006020));
    rome2_test_put_u32(
        fixture->vtables.bytes, ROME2_TEST_VTABLE_OFFSET,
        UINT32_C(0x100e1900));
    rome2_test_put_u32(
        fixture->vtables.bytes, ROME2_TEST_VTABLE_OFFSET + 4,
        ROME2_TEST_METHOD_IDENTITY);
    rome2_test_put_u32(
        fixture->vtables.bytes, ROME2_TEST_VTABLE_OFFSET + 8,
        UINT32_C(0x100e9999));

    fixture->state_view.host_base = fixture->state.bytes;
    fixture->state_view.guest_base = ROME2_TEST_STATE_BASE;
    fixture->state_view.byte_count = sizeof(fixture->state.bytes);
    fixture->vtable_view.host_base = fixture->vtables.bytes;
    fixture->vtable_view.guest_base = ROME2_TEST_VTABLE_BASE;
    fixture->vtable_view.byte_count = sizeof(fixture->vtables.bytes);
    fixture->effects.context = &fixture->context;
    fixture->effects.dispatch = rome2_test_dispatch;
    fixture->effects.peek = rome2_test_peek;
    fixture->context.state_bytes = fixture->state.bytes;
    fixture->context.expected_count_offset = ROME2_TEST_VECTOR_OFFSET + 8;
    fixture->context.expected_slot_offset = ROME2_TEST_BACKING_OFFSET + 8;
    fixture->context.expected_count = 3;
    fixture->context.expected_handler = handler;
    fixture->context.expected_method = ROME2_TEST_METHOD_IDENTITY;
    fixture->context.expected_argument = ROME2_TEST_ARGUMENT;
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

static int rome2_test_effects_unchanged(
    const char *label,
    const rome2_100e2460_effects *actual,
    const rome2_100e2460_effects *expected)
{
    if (actual->context == expected->context &&
        actual->dispatch == expected->dispatch &&
        actual->peek == expected->peek) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: effects table changed\n", label);
    return 1;
}

static int rome2_test_success_case(
    const char *label,
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
    rome2_100e2460_effects expected_effects;
    rome2_100e2460_branch_status status;
    uint32_t index;
    uint8_t result = UINT8_C(0xc7);
    int failures = 0;

    rome2_test_setup(&fixture);
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
        expected_state.bytes, ROME2_TEST_BACKING_OFFSET + 8,
        ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET);
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 3);

    status = rome2_port_100e2460_run_preallocated_branch(
        &fixture.state_view,
        &fixture.vtable_view,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        rome2_test_address(ROME2_TEST_ARGUMENT),
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
    if (fixture.state_view.host_base != expected_state_view.host_base ||
        fixture.state_view.guest_base != expected_state_view.guest_base ||
        fixture.state_view.byte_count != expected_state_view.byte_count ||
        fixture.vtable_view.host_base != expected_vtable_view.host_base ||
        fixture.vtable_view.guest_base != expected_vtable_view.guest_base ||
        fixture.vtable_view.byte_count != expected_vtable_view.byte_count) {
        fprintf(stderr, "FAIL %s: view descriptor changed\n", label);
        ++failures;
    }
    failures += rome2_test_effects_unchanged(
        label, &fixture.effects, &expected_effects);
    if (fixture.context.bad_observation_count != 0 ||
        fixture.context.observed_receiver !=
            ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET ||
        fixture.context.observed_method != ROME2_TEST_METHOD_IDENTITY ||
        fixture.context.observed_argument != ROME2_TEST_ARGUMENT ||
        fixture.context.peek_index != peek_value_count ||
        fixture.context.trace_count != peek_value_count + 1 ||
        fixture.context.trace[0] != 1) {
        fprintf(stderr, "FAIL %s: effect trace/arguments differ\n", label);
        ++failures;
    }
    for (index = 1; index < fixture.context.trace_count; ++index) {
        if (fixture.context.trace[index] != 2) {
            fprintf(stderr, "FAIL %s: effect order differs\n", label);
            ++failures;
            break;
        }
    }
    return failures;
}

static int rome2_test_success_matrix(void)
{
    static const uint32_t empty_queue[] = {0};
    static const uint32_t two_messages[] = {
        UINT32_C(1), UINT32_C(0x80000000), UINT32_C(0)
    };
    static const uint32_t last_call_false[] = {UINT32_C(7), UINT32_C(0)};
    int failures = 0;

    failures += rome2_test_success_case(
        "empty queue still probes once and returns low AL",
        UINT32_C(0x123456a5), empty_queue, 1, 1, UINT8_C(0xa5));
    failures += rome2_test_success_case(
        "any nonzero BOOL continues through true true false",
        UINT32_C(0xabcdefFF), two_messages, 3, 3, UINT8_C(0xff));
    failures += rome2_test_success_case(
        "false on final allowed probe succeeds with zero AL",
        UINT32_C(0x12340000), last_call_false, 2, 2, UINT8_C(0));
    return failures;
}

static int rome2_test_adjacent_append_case(
    const char *label,
    size_t backing_offset)
{
    static const uint32_t empty_queue[] = {0};
    rome2_test_fixture fixture;
    rome2_test_state_memory expected_state;
    rome2_100e2460_branch_status status;
    uint8_t result = UINT8_C(0xc7);
    int failures = 0;

    rome2_test_setup(&fixture);
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, UINT32_C(1));
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, UINT32_C(0));
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_VECTOR_OFFSET + 12,
        ROME2_TEST_STATE_BASE + (uint32_t)backing_offset);
    fixture.context.expected_count = 1;
    fixture.context.expected_slot_offset = backing_offset;
    fixture.context.dispatch_eax = UINT32_C(0x1234567e);
    fixture.context.peek_values[0] = empty_queue[0];
    fixture.context.peek_value_count = 1;
    expected_state = fixture.state;
    rome2_test_put_u32(
        expected_state.bytes,
        backing_offset,
        ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET);
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, UINT32_C(1));

    status = rome2_port_100e2460_run_preallocated_branch(
        &fixture.state_view,
        &fixture.vtable_view,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        rome2_test_address(ROME2_TEST_ARGUMENT),
        &fixture.effects,
        UINT32_C(1),
        &result);
    failures += rome2_test_expect_status(
        label, status, ROME2_100E2460_BRANCH_OK);
    if (result != UINT8_C(0x7e) ||
        memcmp(&fixture.state, &expected_state, sizeof(fixture.state)) != 0 ||
        fixture.context.trace_count != 2 ||
        fixture.context.trace[0] != 1 || fixture.context.trace[1] != 2 ||
        fixture.context.peek_index != 1 ||
        fixture.context.bad_observation_count != 0) {
        fprintf(stderr, "FAIL %s: adjacent success oracle differs\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_adjacent_appends(void)
{
    int failures = 0;

    failures += rome2_test_adjacent_append_case(
        "append ends exactly at vector start",
        ROME2_TEST_VECTOR_OFFSET - ROME2_PORT_100E2460_ELEMENT_BYTES);
    failures += rome2_test_adjacent_append_case(
        "append begins exactly at vector end",
        ROME2_TEST_VECTOR_OFFSET + ROME2_PORT_100E2460_VECTOR_BYTES);
    return failures;
}

static int rome2_test_drain_limit_case(
    const char *label,
    uint32_t max_peek_calls)
{
    rome2_test_fixture fixture;
    rome2_test_state_memory expected_state;
    rome2_test_vtable_memory expected_vtables;
    rome2_100e2460_branch_status status;
    uint32_t index;
    uint8_t result = UINT8_C(0xc7);
    int failures = 0;

    rome2_test_setup(&fixture);
    fixture.context.dispatch_eax = UINT32_C(0x1234565a);
    for (index = 0; index < max_peek_calls; ++index) {
        fixture.context.peek_values[index] = UINT32_C(1) + index;
    }
    fixture.context.peek_value_count = max_peek_calls;
    expected_state = fixture.state;
    expected_vtables = fixture.vtables;
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_BACKING_OFFSET + 8,
        ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET);
    rome2_test_put_u32(
        expected_state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 3);

    status = rome2_port_100e2460_run_preallocated_branch(
        &fixture.state_view,
        &fixture.vtable_view,
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET),
        rome2_test_address(ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET),
        rome2_test_address(ROME2_TEST_ARGUMENT),
        &fixture.effects,
        max_peek_calls,
        &result);
    failures += rome2_test_expect_status(
        label, status, ROME2_100E2460_BRANCH_DRAIN_LIMIT);
    if (result != UINT8_C(0xc7) ||
        memcmp(&fixture.state, &expected_state, sizeof(fixture.state)) != 0 ||
        memcmp(&fixture.vtables, &expected_vtables,
            sizeof(fixture.vtables)) != 0 ||
        fixture.context.peek_index != max_peek_calls ||
        fixture.context.trace_count != max_peek_calls + UINT32_C(1) ||
        fixture.context.trace[0] != 1 ||
        fixture.context.bad_observation_count != 0) {
        fprintf(stderr,
            "FAIL %s: drain-limit commit/output/effect postcondition differs\n",
            label);
        ++failures;
    }
    for (index = 1; index < fixture.context.trace_count; ++index) {
        if (fixture.context.trace[index] != 2) {
            fprintf(stderr, "FAIL %s: drain-limit effect order differs\n", label);
            ++failures;
            break;
        }
    }
    return failures;
}

static int rome2_test_preserved_failure(
    const char *label,
    rome2_test_fixture *fixture,
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 vector,
    rome2_guest_addr32 handler,
    const rome2_100e2460_effects *effects,
    uint32_t max_peek_calls,
    uint8_t *result_out,
    rome2_100e2460_branch_status expected_status)
{
    rome2_test_state_memory state_snapshot = fixture->state;
    rome2_test_vtable_memory vtable_snapshot = fixture->vtables;
    rome2_guest_write_view state_view_snapshot = fixture->state_view;
    rome2_guest_read_view vtable_view_snapshot = fixture->vtable_view;
    rome2_100e2460_effects effects_snapshot = fixture->effects;
    uint8_t result_snapshot = result_out == NULL ? 0 : *result_out;
    rome2_100e2460_branch_status status;
    int failures = 0;

    status = rome2_port_100e2460_run_preallocated_branch(
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
    if (fixture->state_view.host_base != state_view_snapshot.host_base ||
        fixture->state_view.guest_base != state_view_snapshot.guest_base ||
        fixture->state_view.byte_count != state_view_snapshot.byte_count ||
        fixture->vtable_view.host_base != vtable_view_snapshot.host_base ||
        fixture->vtable_view.guest_base != vtable_view_snapshot.guest_base ||
        fixture->vtable_view.byte_count != vtable_view_snapshot.byte_count) {
        fprintf(stderr, "FAIL %s: view descriptor changed on failure\n", label);
        ++failures;
    }
    failures += rome2_test_effects_unchanged(
        label, &fixture->effects, &effects_snapshot);
    if (result_out != NULL && *result_out != result_snapshot) {
        fprintf(stderr, "FAIL %s: return byte changed on failure\n", label);
        ++failures;
    }
    if (fixture->context.trace_count != 0 ||
        fixture->context.peek_index != 0 ||
        fixture->context.bad_observation_count != 0) {
        fprintf(stderr, "FAIL %s: effect ran before commit\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_validation_failures(void)
{
    rome2_test_fixture fixture;
    rome2_guest_addr32 vector = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET);
    rome2_guest_addr32 handler = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET);
    uint8_t result;
    int failures = 0;

#define ROME2_RESET() \
    do { rome2_test_setup(&fixture); result = UINT8_C(0xc7); } while (0)
#define ROME2_FAIL(label, expected) \
    (failures += rome2_test_preserved_failure( \
        (label), &fixture, &fixture.state_view, &fixture.vtable_view, \
        vector, handler, &fixture.effects, 3, &result, (expected)))

    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "null state view", &fixture, NULL, &fixture.vtable_view,
        vector, handler, &fixture.effects, 3, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "null vtable view", &fixture, &fixture.state_view, NULL,
        vector, handler, &fixture.effects, 3, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "null effects", &fixture, &fixture.state_view, &fixture.vtable_view,
        vector, handler, NULL, 3, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "null result", &fixture, &fixture.state_view, &fixture.vtable_view,
        vector, handler, &fixture.effects, 3, NULL,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    fixture.effects.dispatch = NULL;
    ROME2_FAIL("null dispatch adapter", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    fixture.effects.peek = NULL;
    ROME2_FAIL("null peek adapter", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_preserved_failure(
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
    vector.value = 0;
    ROME2_FAIL("null vector", ROME2_100E2460_BRANCH_NULL_ADDRESS);
    vector.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;
    ROME2_RESET();
    vector.value = UINT32_MAX - UINT32_C(14);
    ROME2_FAIL("vector end overflow", ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    vector.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;
    ROME2_RESET();
    vector.value = ROME2_TEST_STATE_BASE - UINT32_C(1);
    ROME2_FAIL("vector below state view", ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    vector.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;
    ROME2_RESET();
    vector.value =
        ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES - UINT32_C(15);
    ROME2_FAIL("truncated vector", ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    vector.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET;

    ROME2_RESET();
    fixture.state_view.guest_base = UINT32_MAX - UINT32_C(7);
    fixture.state_view.byte_count = 9;
    ROME2_FAIL("state guest end overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    ROME2_RESET();
    fixture.vtable_view.guest_base = UINT32_MAX - UINT32_C(7);
    fixture.vtable_view.byte_count = 9;
    ROME2_FAIL("vtable guest end overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    ROME2_RESET();
    fixture.state_view.host_base = (uint8_t *)(UINTPTR_MAX - 1);
    fixture.state_view.byte_count = 4;
    ROME2_FAIL("state host end overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    ROME2_RESET();
    fixture.vtable_view.host_base =
        (const uint8_t *)(UINTPTR_MAX - 1);
    fixture.vtable_view.byte_count = 4;
    ROME2_FAIL("vtable host end overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);

    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, 4);
    ROME2_FAIL("growth route rejected", ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 12, 0);
    ROME2_FAIL("null backing", ROME2_100E2460_BRANCH_NULL_ADDRESS);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_VECTOR_OFFSET + 12,
        ROME2_TEST_STATE_BASE - UINT32_C(1));
    ROME2_FAIL("backing below state view",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_VECTOR_OFFSET + 4,
        UINT32_C(0x40000001));
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_VECTOR_OFFSET + 8,
        UINT32_C(0x40000000));
    ROME2_FAIL("scaled append index overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, UINT32_C(2));
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, UINT32_C(1));
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_VECTOR_OFFSET + 12,
        UINT32_MAX - UINT32_C(3));
    ROME2_FAIL("append address overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, UINT32_C(1));
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, UINT32_C(0));
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_VECTOR_OFFSET + 12,
        ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES);
    ROME2_FAIL("append cell outside state view",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 4, UINT32_C(1));
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 8, UINT32_C(0));
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_VECTOR_OFFSET + 12,
        ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES - UINT32_C(3));
    ROME2_FAIL("truncated append cell",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_VECTOR_OFFSET + 12,
        ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET);
    ROME2_FAIL("append aliases vector", ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    handler.value = 0;
    ROME2_FAIL("null handler", ROME2_100E2460_BRANCH_NULL_ADDRESS);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    ROME2_RESET();
    handler.value = ROME2_TEST_STATE_BASE - 1;
    ROME2_FAIL("handler below state view",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    ROME2_RESET();
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_STATE_BYTES - 3;
    ROME2_FAIL("truncated handler cell",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    ROME2_RESET();
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET + 8;
    ROME2_FAIL("handler aliases pending count write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;
    ROME2_RESET();
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_BACKING_OFFSET + 8;
    ROME2_FAIL("handler aliases pending append write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    handler.value = ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET;

    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET, 0);
    ROME2_FAIL("null vtable identity", ROME2_100E2460_BRANCH_NULL_ADDRESS);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET,
        UINT32_MAX - UINT32_C(3));
    ROME2_FAIL("vtable plus four overflow",
        ROME2_100E2460_BRANCH_RANGE_OVERFLOW);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_HANDLER_OFFSET,
        ROME2_TEST_VTABLE_BASE - UINT32_C(8));
    ROME2_FAIL("method cell below vtable view",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET,
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_BYTES - 7);
    ROME2_FAIL("truncated vtable method cell",
        ROME2_100E2460_BRANCH_OUT_OF_RANGE);
    ROME2_RESET();
    rome2_test_put_u32(
        fixture.vtables.bytes, ROME2_TEST_VTABLE_OFFSET + 4, 0);
    ROME2_FAIL("null method identity", ROME2_100E2460_BRANCH_NULL_ADDRESS);

    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET,
        ROME2_TEST_STATE_BASE + ROME2_TEST_BACKING_OFFSET + 4);
    fixture.vtable_view.guest_base = ROME2_TEST_STATE_BASE;
    fixture.vtable_view.byte_count = sizeof(fixture.vtables.bytes);
    rome2_test_put_u32(
        fixture.vtables.bytes, ROME2_TEST_BACKING_OFFSET + 8,
        ROME2_TEST_METHOD_IDENTITY);
    ROME2_FAIL("method cell logically aliases append write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_HANDLER_OFFSET,
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET);
    fixture.vtable_view.host_base = fixture.state.bytes;
    fixture.vtable_view.guest_base =
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET + 4 -
            (ROME2_TEST_BACKING_OFFSET + 8);
    fixture.vtable_view.byte_count = sizeof(fixture.state.bytes);
    rome2_test_put_u32(
        fixture.state.bytes, ROME2_TEST_BACKING_OFFSET + 8,
        ROME2_TEST_METHOD_IDENTITY);
    ROME2_FAIL("method cell physically aliases append write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    rome2_test_put_u32(
        fixture.state.bytes,
        ROME2_TEST_HANDLER_OFFSET,
        ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET + UINT32_C(4));
    fixture.vtable_view.guest_base = ROME2_TEST_STATE_BASE;
    fixture.vtable_view.byte_count = sizeof(fixture.vtables.bytes);
    ROME2_FAIL("method cell logically aliases count write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    fixture.vtable_view.host_base = fixture.state.bytes;
    fixture.vtable_view.guest_base =
        ROME2_TEST_VTABLE_BASE + ROME2_TEST_VTABLE_OFFSET + UINT32_C(4) -
            (ROME2_TEST_VECTOR_OFFSET + UINT32_C(8));
    fixture.vtable_view.byte_count = sizeof(fixture.state.bytes);
    ROME2_FAIL("method cell physically aliases count write",
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "return byte aliases state view", &fixture, &fixture.state_view,
        &fixture.vtable_view, vector, handler, &fixture.effects, 3,
        &fixture.state.bytes[0], ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "return byte aliases vtable view", &fixture, &fixture.state_view,
        &fixture.vtable_view, vector, handler, &fixture.effects, 3,
        &fixture.vtables.bytes[0], ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "return byte aliases effects table", &fixture, &fixture.state_view,
        &fixture.vtable_view, vector, handler, &fixture.effects, 3,
        (uint8_t *)(void *)&fixture.effects,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "return byte aliases state descriptor", &fixture,
        &fixture.state_view, &fixture.vtable_view, vector, handler,
        &fixture.effects, 3, (uint8_t *)(void *)&fixture.state_view,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "return byte aliases vtable descriptor", &fixture,
        &fixture.state_view, &fixture.vtable_view, vector, handler,
        &fixture.effects, 3, (uint8_t *)(void *)&fixture.vtable_view,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "state and vtable descriptors alias", &fixture,
        &fixture.state_view,
        (const rome2_guest_read_view *)(const void *)&fixture.state_view,
        vector, handler, &fixture.effects, 3, &result,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "state descriptor and effects alias", &fixture,
        &fixture.state_view, &fixture.vtable_view, vector, handler,
        (const rome2_100e2460_effects *)(const void *)&fixture.state_view,
        3, &result, ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "vtable descriptor and effects alias", &fixture,
        &fixture.state_view, &fixture.vtable_view, vector, handler,
        (const rome2_100e2460_effects *)(const void *)&fixture.vtable_view,
        3, &result, ROME2_100E2460_BRANCH_BAD_ARGUMENT);

#undef ROME2_FAIL
#undef ROME2_RESET
    return failures;
}

static int rome2_test_control_object_aliases(void)
{
    struct rome2_state_descriptor_alias {
        rome2_guest_write_view embedded;
        uint8_t padding[64];
    } state_alias;
    struct rome2_vtable_descriptor_alias {
        rome2_guest_read_view embedded;
        uint8_t padding[64];
    } vtable_alias;
    struct rome2_effects_alias {
        rome2_100e2460_effects embedded;
        uint8_t padding[64];
    } effects_alias;
    rome2_test_fixture fixture;
    rome2_guest_addr32 vector = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_VECTOR_OFFSET);
    rome2_guest_addr32 handler = rome2_test_address(
        ROME2_TEST_STATE_BASE + ROME2_TEST_HANDLER_OFFSET);
    rome2_100e2460_branch_status status;
    uint8_t result = UINT8_C(0xc7);
    int failures = 0;

    rome2_test_setup(&fixture);
    memset(&state_alias, 0x4d, sizeof(state_alias));
    state_alias.embedded.host_base = (uint8_t *)(void *)&state_alias;
    state_alias.embedded.guest_base = ROME2_TEST_STATE_BASE;
    state_alias.embedded.byte_count = sizeof(state_alias);
    status = rome2_port_100e2460_run_preallocated_branch(
        &state_alias.embedded, &fixture.vtable_view, vector, handler,
        rome2_test_address(ROME2_TEST_ARGUMENT), &fixture.effects, 3, &result);
    failures += rome2_test_expect_status(
        "state descriptor aliases state bytes", status,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    rome2_test_setup(&fixture);
    memset(&vtable_alias, 0x4d, sizeof(vtable_alias));
    vtable_alias.embedded.host_base = fixture.vtables.bytes;
    vtable_alias.embedded.guest_base = ROME2_TEST_VTABLE_BASE;
    vtable_alias.embedded.byte_count = sizeof(fixture.vtables.bytes);
    fixture.state_view.host_base = (uint8_t *)(void *)&vtable_alias;
    fixture.state_view.byte_count = sizeof(vtable_alias);
    status = rome2_port_100e2460_run_preallocated_branch(
        &fixture.state_view, &vtable_alias.embedded, vector, handler,
        rome2_test_address(ROME2_TEST_ARGUMENT), &fixture.effects, 3, &result);
    failures += rome2_test_expect_status(
        "vtable descriptor aliases state bytes", status,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);

    rome2_test_setup(&fixture);
    memset(&effects_alias, 0x4d, sizeof(effects_alias));
    effects_alias.embedded = fixture.effects;
    fixture.state_view.host_base = (uint8_t *)(void *)&effects_alias;
    fixture.state_view.byte_count = sizeof(effects_alias);
    status = rome2_port_100e2460_run_preallocated_branch(
        &fixture.state_view, &fixture.vtable_view, vector, handler,
        rome2_test_address(ROME2_TEST_ARGUMENT), &effects_alias.embedded,
        3, &result);
    failures += rome2_test_expect_status(
        "effects table aliases state bytes", status,
        ROME2_100E2460_BRANCH_BAD_ARGUMENT);
    if (fixture.context.trace_count != 0 || result != UINT8_C(0xc7)) {
        fprintf(stderr, "FAIL control-object alias: effect/output changed\n");
        ++failures;
    }
    return failures;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_success_matrix();
    failures += rome2_test_adjacent_appends();
    failures += rome2_test_drain_limit_case(
        "drain limit keeps committed effects", UINT32_C(2));
    failures += rome2_test_drain_limit_case(
        "one-call drain limit keeps committed effects", UINT32_C(1));
    failures += rome2_test_validation_failures();
    failures += rome2_test_control_object_aliases();
    if (failures != 0) {
        fprintf(stderr,
            "startup 100e2460 preallocated-branch tests: %d failure(s)\n",
            failures);
        return 1;
    }
    puts("startup 100e2460 preallocated-branch tests: pass");
    return 0;
}

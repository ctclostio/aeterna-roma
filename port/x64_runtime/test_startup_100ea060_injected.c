#include "ported_100ea060_injected.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_STATE_BASE UINT32_C(0x20000000)
#define ROME2_TEST_STATE_BYTES 65536
#define ROME2_TEST_RECEIVER_OFFSET UINT32_C(0x100)
#define ROME2_TEST_VECTOR_OFFSET \
    (ROME2_TEST_RECEIVER_OFFSET + ROME2_PORT_100EA060_VECTOR_OFFSET)
#define ROME2_TEST_ARGUMENT_OFFSET \
    (ROME2_TEST_RECEIVER_OFFSET + ROME2_PORT_100EA060_ARGUMENT_OFFSET)
#define ROME2_TEST_VTABLE_BASE UINT32_C(0x1173f000)
#define ROME2_TEST_VTABLE_BYTES 2048
#define ROME2_TEST_HANDLER_COUNT ROME2_PORT_100EA060_REGISTRATION_COUNT

static const uint32_t rome2_test_vtables[ROME2_TEST_HANDLER_COUNT] = {
    UINT32_C(0x1173f22c), UINT32_C(0x1173f24c), UINT32_C(0x1173f234),
    UINT32_C(0x1173f23c), UINT32_C(0x1173f264), UINT32_C(0x1173f26c),
    UINT32_C(0x1173f244), UINT32_C(0x1173f254), UINT32_C(0x1173f274),
    UINT32_C(0x1173f27c), UINT32_C(0x1173f284), UINT32_C(0x1173f28c),
    UINT32_C(0x1173f294), UINT32_C(0x1173f2ac), UINT32_C(0x1173f2b4),
    UINT32_C(0x1173f25c), UINT32_C(0x1173f2e4), UINT32_C(0x1173f2bc),
    UINT32_C(0x1173f2c4), UINT32_C(0x1173f29c), UINT32_C(0x1173f2a4),
    UINT32_C(0x1173f2cc), UINT32_C(0x1173f2d4),
};

static const uint32_t rome2_test_methods[ROME2_TEST_HANDLER_COUNT] = {
    UINT32_C(0x100e9230), UINT32_C(0x100e8550), UINT32_C(0x100e8e50),
    UINT32_C(0x100e9490), UINT32_C(0x100e8be0), UINT32_C(0x100e8bb0),
    UINT32_C(0x100ea040), UINT32_C(0x100e8e80), UINT32_C(0x100e85e0),
    UINT32_C(0x100e8410), UINT32_C(0x100e8760), UINT32_C(0x100e9270),
    UINT32_C(0x100e8c00), UINT32_C(0x100e8660), UINT32_C(0x100e86d0),
    UINT32_C(0x100e8d40), UINT32_C(0x100e8810), UINT32_C(0x100e9390),
    UINT32_C(0x100e8890), UINT32_C(0x100e8e10), UINT32_C(0x100e8df0),
    UINT32_C(0x100e8480), UINT32_C(0x100e8c80),
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
    uint32_t handler_calls;
    uint32_t backing_calls;
    uint32_t release_calls;
    uint32_t next_handler_offset;
    uint32_t next_backing_offset;
    uint32_t bad_observations;
} rome2_test_context;

static rome2_guest_addr32 test_allocate_handler(
    void *context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    rome2_test_context *ctx = (rome2_test_context *)context;
    rome2_guest_addr32 addr;

    (void)allocation_class;
    addr.value = ROME2_TEST_STATE_BASE + ctx->next_handler_offset;
    ctx->next_handler_offset += ((byte_count + 15U) & ~15U);
    ctx->handler_calls++;
    return addr;
}

static rome2_guest_addr32 test_allocate_backing(
    void *context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    rome2_test_context *ctx = (rome2_test_context *)context;
    rome2_guest_addr32 addr;

    (void)allocation_class;
    addr.value = ROME2_TEST_STATE_BASE + ctx->next_backing_offset;
    ctx->next_backing_offset += ((byte_count + 15U) & ~15U);
    ctx->backing_calls++;
    return addr;
}

static void test_release_backing(
    void *context,
    rome2_guest_addr32 base)
{
    rome2_test_context *ctx = (rome2_test_context *)context;
    (void)base;
    ctx->release_calls++;
}

static uint32_t test_dispatch_handler(
    void *context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 method,
    rome2_guest_addr32 argument)
{
    (void)context;
    (void)receiver;
    (void)method;
    (void)argument;
    return 1U;
}

static uint32_t test_peek_queue(
    void *context,
    rome2_guest_addr32 message,
    rome2_guest_addr32 window,
    uint32_t filter_min,
    uint32_t filter_max,
    uint32_t remove_flags)
{
    (void)context;
    (void)message;
    (void)window;
    (void)filter_min;
    (void)filter_max;
    (void)remove_flags;
    return 0U;
}

static void write_u32(uint8_t *p, uint32_t val)
{
    p[0] = (uint8_t)val;
    p[1] = (uint8_t)(val >> 8);
    p[2] = (uint8_t)(val >> 16);
    p[3] = (uint8_t)(val >> 24);
}

int main(void)
{
    rome2_test_state_memory state;
    rome2_test_vtable_memory vtables;
    rome2_guest_write_view state_view;
    rome2_guest_read_view vtable_view;
    rome2_100ea060_effects effects;
    rome2_test_context context;
    rome2_guest_addr32 receiver;
    rome2_100ea060_status status;
    uint32_t vector_offset;
    uint32_t index;
    uint32_t count;
    uint32_t capacity;
    int failed = 0;

    memset(&state, 0, sizeof(state));
    memset(&vtables, 0, sizeof(vtables));
    memset(&context, 0, sizeof(context));

    context.state_bytes = state.bytes;
    context.next_handler_offset = UINT32_C(0x1000);
    context.next_backing_offset = UINT32_C(0x8000);

    state_view.host_base = state.bytes;
    state_view.guest_base = ROME2_TEST_STATE_BASE;
    state_view.byte_count = ROME2_TEST_STATE_BYTES;

    vtable_view.host_base = vtables.bytes;
    vtable_view.guest_base = ROME2_TEST_VTABLE_BASE;
    vtable_view.byte_count = ROME2_TEST_VTABLE_BYTES;

    receiver.value = ROME2_TEST_STATE_BASE + ROME2_TEST_RECEIVER_OFFSET;

    /* Initialize vector structure at receiver + 0x854 */
    vector_offset = ROME2_TEST_VECTOR_OFFSET;
    write_u32(state.bytes + vector_offset, UINT32_C(0xfeedface)); /* sentinel */
    write_u32(state.bytes + vector_offset + 4, 0);                 /* capacity */
    write_u32(state.bytes + vector_offset + 8, 0);                 /* count */
    write_u32(state.bytes + vector_offset + 12, 0);                /* backing */

    /* Initialize argument at receiver + 0x824 */
    write_u32(state.bytes + ROME2_TEST_ARGUMENT_OFFSET, UINT32_C(0x2824));

    /* Initialize vtable methods in vtable memory */
    for (index = 0; index < ROME2_TEST_HANDLER_COUNT; ++index) {
        size_t vt_offset = (size_t)(rome2_test_vtables[index] - ROME2_TEST_VTABLE_BASE);
        write_u32(vtables.bytes + vt_offset + 4, rome2_test_methods[index]);
    }

    effects.allocation_context = &context;
    effects.allocate_handler = test_allocate_handler;
    effects.router_effects.tail_effects.context = &context;
    effects.router_effects.tail_effects.dispatch = test_dispatch_handler;
    effects.router_effects.tail_effects.peek = test_peek_queue;
    effects.router_effects.allocate = test_allocate_backing;
    effects.router_effects.release = test_release_backing;

    /* Run registration of all 23 handlers */
    status = rome2_port_100ea060_register_handlers(
        receiver,
        &state_view,
        &vtable_view,
        &effects);

    if (status != ROME2_100EA060_OK) {
        (void)fprintf(stderr,
            "100ea060 register_handlers failed with status %d\n", (int)status);
        return 1;
    }

    if (context.handler_calls != ROME2_PORT_100EA060_REGISTRATION_COUNT) {
        (void)fprintf(stderr,
            "100ea060 handler_calls: expected %u, got %u\n",
            ROME2_PORT_100EA060_REGISTRATION_COUNT, context.handler_calls);
        failed = 1;
    }

    /* Verify vector count and capacity in state memory at receiver + 0x854 */
    capacity = (uint32_t)state.bytes[vector_offset + 4] |
               ((uint32_t)state.bytes[vector_offset + 5] << 8) |
               ((uint32_t)state.bytes[vector_offset + 6] << 16) |
               ((uint32_t)state.bytes[vector_offset + 7] << 24);
    count = (uint32_t)state.bytes[vector_offset + 8] |
            ((uint32_t)state.bytes[vector_offset + 9] << 8) |
            ((uint32_t)state.bytes[vector_offset + 10] << 16) |
            ((uint32_t)state.bytes[vector_offset + 11] << 24);

    if (count != ROME2_PORT_100EA060_REGISTRATION_COUNT) {
        (void)fprintf(stderr,
            "100ea060 vector count: expected %u, got %u\n",
            ROME2_PORT_100EA060_REGISTRATION_COUNT, count);
        failed = 1;
    }
    if (capacity < count) {
        (void)fprintf(stderr,
            "100ea060 vector capacity %u is less than count %u\n",
            capacity, count);
        failed = 1;
    }

    /* Defensive test: null effects rejection */
    status = rome2_port_100ea060_register_handlers(
        receiver,
        &state_view,
        &vtable_view,
        NULL);
    if (status != ROME2_100EA060_BAD_ARGUMENT) {
        (void)fprintf(stderr, "100ea060 null effects was not rejected\n");
        failed = 1;
    }

    /* Defensive test: null allocate_handler rejection */
    effects.allocate_handler = NULL;
    status = rome2_port_100ea060_register_handlers(
        receiver,
        &state_view,
        &vtable_view,
        &effects);
    if (status != ROME2_100EA060_BAD_ARGUMENT) {
        (void)fprintf(stderr, "100ea060 null allocate_handler was not rejected\n");
        failed = 1;
    }

    if (failed != 0) {
        (void)fprintf(stderr, "100ea060 registrars: FAIL\n");
        return 1;
    }

    (void)printf("100ea060 registrars: PASS (23 subsystem functors registered, vector growth verified)\n");
    return 0;
}

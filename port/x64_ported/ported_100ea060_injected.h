#ifndef ROME2_PORTED_100EA060_INJECTED_H
#define ROME2_PORTED_100EA060_INJECTED_H

#include "ported_100e2460_router.h"

#define ROME2_PORT_100EA060_REGISTRATION_COUNT UINT32_C(23)
#define ROME2_PORT_100EA060_HANDLER_ALLOCATION_BYTES UINT32_C(4)
#define ROME2_PORT_100EA060_HANDLER_ALLOCATION_CLASS UINT32_C(0)
#define ROME2_PORT_100EA060_ARGUMENT_OFFSET UINT32_C(0x824)
#define ROME2_PORT_100EA060_VECTOR_OFFSET UINT32_C(0x854)

typedef enum rome2_100ea060_status {
    ROME2_100EA060_OK = ROME2_GUEST_OK,
    ROME2_100EA060_BAD_ARGUMENT = ROME2_GUEST_BAD_ARGUMENT,
    ROME2_100EA060_NULL_ADDRESS = ROME2_GUEST_NULL_ADDRESS,
    ROME2_100EA060_RANGE_OVERFLOW = ROME2_GUEST_RANGE_OVERFLOW,
    ROME2_100EA060_OUT_OF_RANGE = ROME2_GUEST_OUT_OF_RANGE,
    ROME2_100EA060_ALLOCATION_RESULT_INVALID = 5,
    ROME2_100EA060_ROUTER_FAILED = 6,
    ROME2_100EA060_ROUTER_RETURNED_ZERO = 7,
    ROME2_100EA060_HANDLER_GRAPH_CORRUPTED = 8
} rome2_100ea060_status;

typedef rome2_guest_addr32 (*rome2_100ea060_handler_allocate_effect_fn)(
    void *context,
    uint32_t byte_count,
    uint32_t allocation_class);

typedef struct rome2_100ea060_effects {
    void *allocation_context;
    rome2_100ea060_handler_allocate_effect_fn allocate_handler;
    rome2_100e2460_growth_effects router_effects;
} rome2_100ea060_effects;

/*
 * Bounded injected-allocation composition of engine subsystem registrars
 * at 0x100ea060.
 *
 * Iterates through the 23 subsystem functor vtables:
 *   0x1173f22c, 0x1173f24c, 0x1173f234, 0x1173f23c, 0x1173f264,
 *   0x1173f26c, 0x1173f244, 0x1173f254, 0x1173f274, 0x1173f27c,
 *   0x1173f284, 0x1173f28c, 0x1173f294, 0x1173f2ac, 0x1173f2b4,
 *   0x1173f25c, 0x1173f2e4, 0x1173f2bc, 0x1173f2c4, 0x1173f29c,
 *   0x1173f2a4, 0x1173f2cc, 0x1173f2d4
 *
 * Each is allocated via allocate_handler(context, 4, 0), initialized with its
 * vtable pointer, and pushed into the vector at receiver + 0x824 via the
 * 0x100e2460 growth router.
 */
rome2_100ea060_status rome2_port_100ea060_register_handlers(
    rome2_guest_addr32 receiver,
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    const rome2_100ea060_effects *effects);

#endif

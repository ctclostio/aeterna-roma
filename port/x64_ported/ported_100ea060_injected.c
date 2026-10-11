#include "ported_100ea060_injected.h"

#include <limits.h>

#define ROME2_100EA060_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)

typedef struct rome2_100ea060_span {
    uint64_t guest_start;
    uintptr_t host_start;
    uint64_t byte_count;
    uint64_t view_offset;
} rome2_100ea060_span;

static const uint32_t rome2_100ea060_vtables[
    ROME2_PORT_100EA060_REGISTRATION_COUNT] = {
    UINT32_C(0x1173f22c),
    UINT32_C(0x1173f24c),
    UINT32_C(0x1173f234),
    UINT32_C(0x1173f23c),
    UINT32_C(0x1173f264),
    UINT32_C(0x1173f26c),
    UINT32_C(0x1173f244),
    UINT32_C(0x1173f254),
    UINT32_C(0x1173f274),
    UINT32_C(0x1173f27c),
    UINT32_C(0x1173f284),
    UINT32_C(0x1173f28c),
    UINT32_C(0x1173f294),
    UINT32_C(0x1173f2ac),
    UINT32_C(0x1173f2b4),
    UINT32_C(0x1173f25c),
    UINT32_C(0x1173f2e4),
    UINT32_C(0x1173f2bc),
    UINT32_C(0x1173f2c4),
    UINT32_C(0x1173f29c),
    UINT32_C(0x1173f2a4),
    UINT32_C(0x1173f2cc),
    UINT32_C(0x1173f2d4),
};

static void rome2_100ea060_write_u32_le(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static uint32_t rome2_100ea060_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static int rome2_100ea060_spans_overlap(
    uint64_t first_start,
    uint64_t first_size,
    uint64_t second_start,
    uint64_t second_size)
{
    if (first_size == 0 || second_size == 0) {
        return 0;
    }
    if (first_start >= second_start) {
        return first_start - second_start < second_size;
    }
    return second_start - first_start < first_size;
}

static int rome2_100ea060_mapped_spans_alias(
    const rome2_100ea060_span *first,
    const rome2_100ea060_span *second)
{
    return
        rome2_100ea060_spans_overlap(
            first->guest_start,
            first->byte_count,
            second->guest_start,
            second->byte_count) ||
        rome2_100ea060_spans_overlap(
            (uint64_t)first->host_start,
            first->byte_count,
            (uint64_t)second->host_start,
            second->byte_count);
}

static rome2_100ea060_status rome2_100ea060_validate_object(
    const void *object,
    size_t byte_count)
{
    uintptr_t address;

    if (object == NULL || byte_count == 0) {
        return ROME2_100EA060_BAD_ARGUMENT;
    }
    address = (uintptr_t)object;
    if (byte_count - 1 > UINTPTR_MAX - address) {
        return ROME2_100EA060_RANGE_OVERFLOW;
    }
    return ROME2_100EA060_OK;
}

static rome2_100ea060_status rome2_100ea060_validate_interval(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100EA060_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100EA060_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count > ROME2_100EA060_ADDRESS_SPACE_SIZE) {
        return ROME2_100EA060_OUT_OF_RANGE;
    }
    host_address = (uintptr_t)host_base;
    if (byte_count > 0 &&
        byte_count - 1 > UINTPTR_MAX - host_address) {
        return ROME2_100EA060_RANGE_OVERFLOW;
    }
    return ROME2_100EA060_OK;
}

static rome2_100ea060_status rome2_100ea060_resolve_span(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count,
    rome2_guest_addr32 guest_address,
    uint64_t span_bytes,
    rome2_100ea060_span *span_out)
{
    uint64_t offset;

    if (span_bytes == 0 ||
        (uint64_t)guest_address.value + span_bytes >
            ROME2_100EA060_ADDRESS_SPACE_SIZE) {
        return ROME2_100EA060_OUT_OF_RANGE;
    }
    if ((uint64_t)guest_address.value < (uint64_t)guest_base ||
        (uint64_t)guest_address.value + span_bytes >
            (uint64_t)guest_base + byte_count) {
        return ROME2_100EA060_OUT_OF_RANGE;
    }
    offset = (uint64_t)guest_address.value - (uint64_t)guest_base;
    span_out->guest_start = (uint64_t)guest_address.value;
    span_out->host_start = (uintptr_t)host_base + (uintptr_t)offset;
    span_out->byte_count = span_bytes;
    span_out->view_offset = offset;
    return ROME2_100EA060_OK;
}

rome2_100ea060_status rome2_port_100ea060_register_handlers(
    rome2_guest_addr32 receiver,
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    const rome2_100ea060_effects *effects)
{
    rome2_100ea060_effects effects_snapshot;
    rome2_100ea060_handler_allocate_effect_fn allocate_handler;
    rome2_100ea060_span handlers[ROME2_PORT_100EA060_REGISTRATION_COUNT];
    rome2_100ea060_span vector;
    rome2_100ea060_span argument;
    rome2_100ea060_span handler;
    rome2_guest_addr32 vector_address;
    rome2_guest_addr32 argument_address;
    rome2_100ea060_status status;
    uint32_t index;

    status = rome2_100ea060_validate_object(state_view, sizeof(*state_view));
    if (status != ROME2_100EA060_OK) return status;
    status = rome2_100ea060_validate_object(vtable_view, sizeof(*vtable_view));
    if (status != ROME2_100EA060_OK) return status;
    status = rome2_100ea060_validate_object(effects, sizeof(*effects));
    if (status != ROME2_100EA060_OK) return status;

    status = rome2_100ea060_validate_interval(
        state_view->host_base, state_view->guest_base, state_view->byte_count);
    if (status != ROME2_100EA060_OK) return status;
    status = rome2_100ea060_validate_interval(
        vtable_view->host_base, vtable_view->guest_base, vtable_view->byte_count);
    if (status != ROME2_100EA060_OK) return status;

    if (effects->allocate_handler == NULL) {
        return ROME2_100EA060_BAD_ARGUMENT;
    }

    effects_snapshot = *effects;
    allocate_handler = effects_snapshot.allocate_handler;

    if ((uint64_t)receiver.value + ROME2_PORT_100EA060_VECTOR_OFFSET + 16U >
        ROME2_100EA060_ADDRESS_SPACE_SIZE) {
        return ROME2_100EA060_OUT_OF_RANGE;
    }
    vector_address.value = receiver.value + ROME2_PORT_100EA060_VECTOR_OFFSET;
    argument_address.value = receiver.value + ROME2_PORT_100EA060_ARGUMENT_OFFSET;

    status = rome2_100ea060_resolve_span(
        state_view->host_base, state_view->guest_base, state_view->byte_count,
        vector_address, 16U, &vector);
    if (status != ROME2_100EA060_OK) return status;

    status = rome2_100ea060_resolve_span(
        state_view->host_base, state_view->guest_base, state_view->byte_count,
        argument_address, 4U, &argument);
    if (status != ROME2_100EA060_OK) return status;

    for (index = 0U; index < ROME2_PORT_100EA060_REGISTRATION_COUNT; ++index) {
        rome2_guest_addr32 allocated = allocate_handler(
            effects_snapshot.allocation_context,
            ROME2_PORT_100EA060_HANDLER_ALLOCATION_BYTES,
            ROME2_PORT_100EA060_HANDLER_ALLOCATION_CLASS);
        uint8_t router_return = 0U;
        rome2_100e2460_branch_status router_status;

        if (allocated.value == 0U) {
            return ROME2_100EA060_ALLOCATION_RESULT_INVALID;
        }

        status = rome2_100ea060_resolve_span(
            state_view->host_base, state_view->guest_base, state_view->byte_count,
            allocated, ROME2_PORT_100EA060_HANDLER_ALLOCATION_BYTES, &handler);
        if (status != ROME2_100EA060_OK) return status;

        handlers[index] = handler;
        rome2_100ea060_write_u32_le(
            (uint8_t *)handler.host_start, rome2_100ea060_vtables[index]);

        router_status = rome2_port_100e2460_run_router(
            state_view,
            vtable_view,
            vector_address,
            allocated,
            argument_address,
            &effects_snapshot.router_effects,
            64U, /* max_peek_calls */
            &router_return);

        if (router_status != ROME2_100E2460_BRANCH_OK) {
            return ROME2_100EA060_ROUTER_FAILED;
        }
        if (router_return == 0U) {
            return ROME2_100EA060_ROUTER_RETURNED_ZERO;
        }
    }

    return ROME2_100EA060_OK;
}

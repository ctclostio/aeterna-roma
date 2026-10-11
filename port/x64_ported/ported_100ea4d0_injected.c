#include "ported_100ea4d0_injected.h"

#include <limits.h>

#define ROME2_100EA4D0_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)

typedef struct rome2_100ea4d0_span {
    uint64_t guest_start;
    uintptr_t host_start;
    uint64_t byte_count;
    uint64_t view_offset;
} rome2_100ea4d0_span;

static const uint32_t rome2_100ea4d0_vtables[
    ROME2_PORT_100EA4D0_REGISTRATION_COUNT] = {
    UINT32_C(0x1173f20c),
    UINT32_C(0x1173f214),
    UINT32_C(0x1173f21c),
    UINT32_C(0x1173f224),
    UINT32_C(0x1173f2ec),
    UINT32_C(0x1173f2dc),
};

static void rome2_100ea4d0_write_u32_le(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static uint32_t rome2_100ea4d0_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static int rome2_100ea4d0_spans_overlap(
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

static int rome2_100ea4d0_mapped_spans_alias(
    const rome2_100ea4d0_span *first,
    const rome2_100ea4d0_span *second)
{
    return
        rome2_100ea4d0_spans_overlap(
            first->guest_start,
            first->byte_count,
            second->guest_start,
            second->byte_count) ||
        rome2_100ea4d0_spans_overlap(
            (uint64_t)first->host_start,
            first->byte_count,
            (uint64_t)second->host_start,
            second->byte_count);
}

static rome2_100ea4d0_status rome2_100ea4d0_validate_object(
    const void *object,
    size_t byte_count)
{
    uintptr_t address;

    if (object == NULL || byte_count == 0) {
        return ROME2_100EA4D0_BAD_ARGUMENT;
    }
    address = (uintptr_t)object;
    if (byte_count - 1 > UINTPTR_MAX - address) {
        return ROME2_100EA4D0_RANGE_OVERFLOW;
    }
    return ROME2_100EA4D0_OK;
}

static rome2_100ea4d0_status rome2_100ea4d0_validate_interval(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100EA4D0_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100EA4D0_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100EA4D0_ADDRESS_SPACE_SIZE) {
        return ROME2_100EA4D0_RANGE_OVERFLOW;
    }
    host_address = (uintptr_t)host_base;
    if (byte_count != 0 &&
        byte_count - UINT64_C(1) >
            (uint64_t)(UINTPTR_MAX - host_address)) {
        return ROME2_100EA4D0_RANGE_OVERFLOW;
    }
    return ROME2_100EA4D0_OK;
}

static rome2_100ea4d0_status rome2_100ea4d0_resolve_span(
    const void *host_base,
    uint32_t guest_base,
    uint64_t view_byte_count,
    rome2_guest_addr32 guest_start,
    uint64_t span_byte_count,
    rome2_100ea4d0_span *span_out)
{
    uint64_t offset;

    if (span_out == NULL || span_byte_count == 0) {
        return ROME2_100EA4D0_BAD_ARGUMENT;
    }
    if (guest_start.value == 0) {
        return ROME2_100EA4D0_NULL_ADDRESS;
    }
    if (span_byte_count > ROME2_100EA4D0_ADDRESS_SPACE_SIZE ||
        span_byte_count >
            ROME2_100EA4D0_ADDRESS_SPACE_SIZE -
                (uint64_t)guest_start.value) {
        return ROME2_100EA4D0_RANGE_OVERFLOW;
    }
    if (guest_start.value < guest_base) {
        return ROME2_100EA4D0_OUT_OF_RANGE;
    }
    offset = (uint64_t)guest_start.value - (uint64_t)guest_base;
    if (offset > view_byte_count ||
        span_byte_count > view_byte_count - offset ||
        offset > (uint64_t)SIZE_MAX) {
        return ROME2_100EA4D0_OUT_OF_RANGE;
    }

    span_out->guest_start = (uint64_t)guest_start.value;
    span_out->host_start = (uintptr_t)host_base + (uintptr_t)offset;
    span_out->byte_count = span_byte_count;
    span_out->view_offset = offset;
    return ROME2_100EA4D0_OK;
}

static int rome2_100ea4d0_control_objects_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    const rome2_100ea4d0_effects *effects)
{
    return
        rome2_100ea4d0_spans_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100ea4d0_spans_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100ea4d0_spans_overlap(
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects));
}

static int rome2_100ea4d0_host_objects_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    const rome2_100ea4d0_effects *effects)
{
    return
        rome2_100ea4d0_spans_overlap(
            (uint64_t)(uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100ea4d0_spans_overlap(
            (uint64_t)(uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100ea4d0_spans_overlap(
            (uint64_t)(uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100ea4d0_spans_overlap(
            (uint64_t)(uintptr_t)vtable_view->host_base,
            vtable_view->byte_count,
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100ea4d0_spans_overlap(
            (uint64_t)(uintptr_t)vtable_view->host_base,
            vtable_view->byte_count,
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100ea4d0_spans_overlap(
            (uint64_t)(uintptr_t)vtable_view->host_base,
            vtable_view->byte_count,
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects));
}

static int rome2_100ea4d0_handler_aliases(
    const rome2_100ea4d0_span *handler,
    const rome2_100ea4d0_span *vector,
    const rome2_100ea4d0_span *argument,
    const rome2_100ea4d0_span *vtable_interval,
    const rome2_100ea4d0_span *backing,
    int has_backing,
    const rome2_100ea4d0_span *earlier_handlers,
    uint32_t earlier_count)
{
    uint32_t index;

    if (rome2_100ea4d0_mapped_spans_alias(handler, vector) ||
        rome2_100ea4d0_mapped_spans_alias(handler, argument) ||
        rome2_100ea4d0_mapped_spans_alias(handler, vtable_interval) ||
        (has_backing &&
         rome2_100ea4d0_mapped_spans_alias(handler, backing))) {
        return 1;
    }
    for (index = 0; index < earlier_count; ++index) {
        if (rome2_100ea4d0_mapped_spans_alias(
                handler, &earlier_handlers[index])) {
            return 1;
        }
    }
    return 0;
}

static rome2_100ea4d0_status rome2_100ea4d0_resolve_current_backing(
    const rome2_guest_write_view *state_view,
    const rome2_100ea4d0_span *vector,
    rome2_100ea4d0_span *backing_out,
    int *has_backing_out)
{
    const uint8_t *vector_bytes =
        state_view->host_base + (size_t)vector->view_offset;
    rome2_guest_addr32 backing;
    uint32_t capacity;
    uint64_t backing_byte_count;

    capacity = rome2_100ea4d0_read_u32_le(vector_bytes + 4);
    if (capacity == 0) {
        *has_backing_out = 0;
        return ROME2_100EA4D0_OK;
    }
    backing.value = rome2_100ea4d0_read_u32_le(vector_bytes + 12);
    backing_byte_count = (uint64_t)capacity * UINT64_C(4);
    *has_backing_out = 1;
    return rome2_100ea4d0_resolve_span(
        state_view->host_base,
        state_view->guest_base,
        state_view->byte_count,
        backing,
        backing_byte_count,
        backing_out);
}

static int rome2_100ea4d0_handler_graph_is_exact(
    const rome2_guest_write_view *state_view,
    const rome2_100ea4d0_span *handlers,
    uint32_t handler_count)
{
    uint32_t index;

    for (index = 0; index < handler_count; ++index) {
        if (rome2_100ea4d0_read_u32_le(
                state_view->host_base + (size_t)handlers[index].view_offset) !=
            rome2_100ea4d0_vtables[index]) {
            return 0;
        }
    }
    return 1;
}

rome2_100ea4d0_status rome2_port_100ea4d0_run_injected(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_receiver,
    const rome2_100ea4d0_effects *effects,
    uint32_t max_peek_calls)
{
    rome2_100ea4d0_effects effects_snapshot;
    rome2_100ea4d0_handler_allocate_effect_fn allocate_handler;
    rome2_100ea4d0_span handlers[ROME2_PORT_100EA4D0_REGISTRATION_COUNT];
    rome2_100ea4d0_span vector;
    rome2_100ea4d0_span argument;
    rome2_100ea4d0_span vtable_interval;
    rome2_100ea4d0_span handler;
    rome2_100ea4d0_span backing;
    rome2_100ea4d0_status status;
    rome2_100e2460_branch_status router_status;
    rome2_guest_addr32 guest_argument;
    rome2_guest_addr32 guest_vector;
    rome2_guest_addr32 guest_handler;
    void *allocation_context;
    uint32_t registration_index;
    uint8_t router_al;
    int has_backing;

    status = rome2_100ea4d0_validate_object(
        state_view, sizeof(*state_view));
    if (status != ROME2_100EA4D0_OK) {
        return status;
    }
    status = rome2_100ea4d0_validate_object(
        vtable_view, sizeof(*vtable_view));
    if (status != ROME2_100EA4D0_OK) {
        return status;
    }
    status = rome2_100ea4d0_validate_object(effects, sizeof(*effects));
    if (status != ROME2_100EA4D0_OK) {
        return status;
    }
    if (rome2_100ea4d0_control_objects_overlap(
            state_view, vtable_view, effects)) {
        return ROME2_100EA4D0_BAD_ARGUMENT;
    }

    status = rome2_100ea4d0_validate_interval(
        state_view->host_base, state_view->guest_base, state_view->byte_count);
    if (status != ROME2_100EA4D0_OK) {
        return status;
    }
    status = rome2_100ea4d0_validate_interval(
        vtable_view->host_base,
        vtable_view->guest_base,
        vtable_view->byte_count);
    if (status != ROME2_100EA4D0_OK) {
        return status;
    }
    if (rome2_100ea4d0_host_objects_overlap(
            state_view, vtable_view, effects)) {
        return ROME2_100EA4D0_BAD_ARGUMENT;
    }
    if (max_peek_calls == 0) {
        return ROME2_100EA4D0_BAD_ARGUMENT;
    }

    if (guest_receiver.value == 0) {
        return ROME2_100EA4D0_NULL_ADDRESS;
    }
    if (guest_receiver.value >
        UINT32_MAX - ROME2_PORT_100EA4D0_ARGUMENT_OFFSET) {
        return ROME2_100EA4D0_RANGE_OVERFLOW;
    }
    guest_argument.value =
        guest_receiver.value + ROME2_PORT_100EA4D0_ARGUMENT_OFFSET;
    if (guest_receiver.value >
        UINT32_MAX - ROME2_PORT_100EA4D0_VECTOR_OFFSET) {
        return ROME2_100EA4D0_RANGE_OVERFLOW;
    }
    guest_vector.value =
        guest_receiver.value + ROME2_PORT_100EA4D0_VECTOR_OFFSET;

    status = rome2_100ea4d0_resolve_span(
        state_view->host_base,
        state_view->guest_base,
        state_view->byte_count,
        guest_vector,
        ROME2_PORT_100E2460_VECTOR_BYTES,
        &vector);
    if (status != ROME2_100EA4D0_OK) {
        return status;
    }
    status = rome2_100ea4d0_resolve_span(
        state_view->host_base,
        state_view->guest_base,
        state_view->byte_count,
        guest_argument,
        UINT64_C(4),
        &argument);
    if (status != ROME2_100EA4D0_OK) {
        return status;
    }
    vtable_interval.guest_start = (uint64_t)vtable_view->guest_base;
    vtable_interval.host_start = (uintptr_t)vtable_view->host_base;
    vtable_interval.byte_count = vtable_view->byte_count;
    vtable_interval.view_offset = 0;
    if (rome2_100ea4d0_mapped_spans_alias(&vector, &vtable_interval)) {
        return ROME2_100EA4D0_BAD_ARGUMENT;
    }

    effects_snapshot = *effects;
    allocate_handler = effects_snapshot.allocate_handler;
    allocation_context = effects_snapshot.allocation_context;
    if (allocate_handler == NULL) {
        return ROME2_100EA4D0_BAD_ARGUMENT;
    }

    for (registration_index = 0;
         registration_index < ROME2_PORT_100EA4D0_REGISTRATION_COUNT;
         ++registration_index) {
        guest_handler = allocate_handler(
            allocation_context,
            ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_BYTES,
            ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_CLASS);
        status = rome2_100ea4d0_resolve_span(
            state_view->host_base,
            state_view->guest_base,
            state_view->byte_count,
            guest_handler,
            ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_BYTES,
            &handler);
        if (status != ROME2_100EA4D0_OK) {
            return ROME2_100EA4D0_ALLOCATION_RESULT_INVALID;
        }
        status = rome2_100ea4d0_resolve_current_backing(
            state_view, &vector, &backing, &has_backing);
        if (status != ROME2_100EA4D0_OK) {
            return ROME2_100EA4D0_ROUTER_FAILED;
        }
        if (
            rome2_100ea4d0_handler_aliases(
                &handler,
                &vector,
                &argument,
                &vtable_interval,
                &backing,
                has_backing,
                handlers,
                registration_index)) {
            return ROME2_100EA4D0_ALLOCATION_RESULT_INVALID;
        }
        handlers[registration_index] = handler;
        rome2_100ea4d0_write_u32_le(
            state_view->host_base + (size_t)handler.view_offset,
            rome2_100ea4d0_vtables[registration_index]);

        router_al = 0;
        router_status = rome2_port_100e2460_run_router(
            state_view,
            vtable_view,
            guest_vector,
            guest_handler,
            guest_argument,
            &effects_snapshot.router_effects,
            max_peek_calls,
            &router_al);
        if (!rome2_100ea4d0_handler_graph_is_exact(
                state_view, handlers, registration_index + UINT32_C(1))) {
            return ROME2_100EA4D0_HANDLER_GRAPH_CORRUPTED;
        }
        if (router_status != ROME2_100E2460_BRANCH_OK) {
            return ROME2_100EA4D0_ROUTER_FAILED;
        }
        if (router_al == 0) {
            return ROME2_100EA4D0_ROUTER_RETURNED_ZERO;
        }
    }
    return ROME2_100EA4D0_OK;
}

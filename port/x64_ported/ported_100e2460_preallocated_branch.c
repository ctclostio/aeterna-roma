#include "ported_100e2460_preallocated_branch.h"

#include <limits.h>

#define ROME2_100E2460_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100E2460_CELL_BYTES UINT64_C(4)

typedef struct rome2_100e2460_append_plan {
    uint64_t vector_offset;
    uint64_t count_offset;
    uint64_t append_offset;
} rome2_100e2460_append_plan;

static uint32_t rome2_100e2460_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static int rome2_100e2460_spans_overlap(
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

static rome2_100e2460_branch_status rome2_100e2460_map_guest_status(
    rome2_guest_status status)
{
    switch (status) {
    case ROME2_GUEST_OK:
        return ROME2_100E2460_BRANCH_OK;
    case ROME2_GUEST_BAD_ARGUMENT:
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    case ROME2_GUEST_NULL_ADDRESS:
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    case ROME2_GUEST_RANGE_OVERFLOW:
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    case ROME2_GUEST_OUT_OF_RANGE:
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    default:
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
}

static rome2_100e2460_branch_status rome2_100e2460_validate_interval(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100E2460_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100E2460_ADDRESS_SPACE_SIZE) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    host_address = (uintptr_t)host_base;
    if (byte_count != 0 &&
        byte_count - UINT64_C(1) >
            (uint64_t)(UINTPTR_MAX - host_address)) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    return ROME2_100E2460_BRANCH_OK;
}

static rome2_100e2460_branch_status rome2_100e2460_validate_object(
    const void *object,
    size_t byte_count)
{
    uintptr_t address;

    if (object == NULL || byte_count == 0) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    address = (uintptr_t)object;
    if (byte_count - 1 > UINTPTR_MAX - address) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    return ROME2_100E2460_BRANCH_OK;
}

static rome2_100e2460_branch_status rome2_100e2460_resolve_cell(
    uint32_t guest_base,
    uint64_t byte_count,
    rome2_guest_addr32 cell,
    uint64_t *offset_out)
{
    uint64_t offset;

    if (cell.value == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    if (cell.value < guest_base) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }
    offset = (uint64_t)cell.value - (uint64_t)guest_base;
    if (offset > byte_count ||
        ROME2_100E2460_CELL_BYTES > byte_count - offset ||
        offset > (uint64_t)SIZE_MAX) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }
    *offset_out = offset;
    return ROME2_100E2460_BRANCH_OK;
}

static rome2_100e2460_branch_status rome2_100e2460_plan_append(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_vector,
    rome2_100e2460_append_plan *plan_out)
{
    const uint8_t *vector;
    uint64_t append_guest;
    uint64_t displacement;
    uint64_t vector_offset;
    uint32_t backing;
    uint32_t capacity;
    uint32_t count;

    if (guest_vector.value == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    if (guest_vector.value >
        UINT32_MAX - (ROME2_PORT_100E2460_VECTOR_BYTES - UINT32_C(1))) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    if (guest_vector.value < view->guest_base) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }
    vector_offset =
        (uint64_t)guest_vector.value - (uint64_t)view->guest_base;
    if (vector_offset > view->byte_count ||
        ROME2_PORT_100E2460_VECTOR_BYTES >
            view->byte_count - vector_offset ||
        vector_offset > (uint64_t)SIZE_MAX) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }

    vector = view->host_base + (size_t)vector_offset;
    capacity = rome2_100e2460_read_u32_le(vector + 4);
    count = rome2_100e2460_read_u32_le(vector + 8);
    backing = rome2_100e2460_read_u32_le(vector + 12);
    if (count >= capacity) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    if (backing == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    if (backing < view->guest_base) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }

    displacement = (uint64_t)count * UINT64_C(4);
    if (displacement > UINT32_MAX) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    append_guest = (uint64_t)backing + displacement;
    if (append_guest > UINT32_MAX) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    plan_out->append_offset = append_guest - (uint64_t)view->guest_base;
    if (plan_out->append_offset > view->byte_count ||
        ROME2_PORT_100E2460_ELEMENT_BYTES >
            view->byte_count - plan_out->append_offset ||
        plan_out->append_offset > (uint64_t)SIZE_MAX) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }
    if (rome2_100e2460_spans_overlap(
            vector_offset,
            ROME2_PORT_100E2460_VECTOR_BYTES,
            plan_out->append_offset,
            ROME2_PORT_100E2460_ELEMENT_BYTES)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    plan_out->vector_offset = vector_offset;
    plan_out->count_offset = vector_offset + UINT64_C(8);
    return ROME2_100E2460_BRANCH_OK;
}

rome2_100e2460_branch_status rome2_port_100e2460_run_preallocated_branch(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_handler,
    rome2_guest_addr32 guest_argument,
    const rome2_100e2460_effects *effects,
    uint32_t max_peek_calls,
    uint8_t *return_al_out)
{
    rome2_100e2460_append_plan plan;
    rome2_100e2460_branch_status status;
    rome2_100e2460_dispatch_effect_fn dispatch;
    rome2_100e2460_peek_effect_fn peek;
    rome2_guest_addr32 method_cell;
    rome2_guest_addr32 method_identity;
    rome2_guest_addr32 null_identity;
    rome2_guest_addr32 vtable_identity;
    rome2_guest_status append_status;
    uint64_t handler_offset;
    uint64_t method_offset;
    uint32_t dispatch_eax;
    uint32_t peek_eax;
    uint32_t peek_calls;
    uint8_t saved_al;
    void *context;

    status = rome2_100e2460_validate_object(state_view, sizeof(*state_view));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_validate_object(vtable_view, sizeof(*vtable_view));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_validate_object(effects, sizeof(*effects));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_validate_object(return_al_out, sizeof(*return_al_out));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }

    /* Reject overlapping control objects before dereferencing any descriptor
     * through a potentially aliased, incompatible structure type. */
    if (rome2_100e2460_spans_overlap(
            (uintptr_t)state_view,
            sizeof(*state_view),
            (uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_spans_overlap(
            (uintptr_t)state_view,
            sizeof(*state_view),
            (uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_spans_overlap(
            (uintptr_t)vtable_view,
            sizeof(*vtable_view),
            (uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_spans_overlap(
            (uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100e2460_spans_overlap(
            (uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_spans_overlap(
            (uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uintptr_t)effects,
            sizeof(*effects))) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    status = rome2_100e2460_validate_interval(
        state_view->host_base, state_view->guest_base, state_view->byte_count);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_validate_interval(
        vtable_view->host_base,
        vtable_view->guest_base,
        vtable_view->byte_count);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }

    if (rome2_100e2460_spans_overlap(
            (uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100e2460_spans_overlap(
            (uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_spans_overlap(
            (uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_spans_overlap(
            (uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uintptr_t)return_al_out,
            sizeof(*return_al_out)) ||
        rome2_100e2460_spans_overlap(
            (uintptr_t)vtable_view->host_base,
            vtable_view->byte_count,
            (uintptr_t)return_al_out,
            sizeof(*return_al_out))) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    dispatch = effects->dispatch;
    peek = effects->peek;
    context = effects->context;
    if (dispatch == NULL || peek == NULL || max_peek_calls == 0) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    status = rome2_100e2460_plan_append(state_view, guest_vector, &plan);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_resolve_cell(
        state_view->guest_base,
        state_view->byte_count,
        guest_handler,
        &handler_offset);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    if (rome2_100e2460_spans_overlap(
            handler_offset,
            ROME2_100E2460_CELL_BYTES,
            plan.append_offset,
            ROME2_100E2460_CELL_BYTES) ||
        rome2_100e2460_spans_overlap(
            handler_offset,
            ROME2_100E2460_CELL_BYTES,
            plan.count_offset,
            ROME2_100E2460_CELL_BYTES)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    vtable_identity.value = rome2_100e2460_read_u32_le(
        state_view->host_base + (size_t)handler_offset);
    if (vtable_identity.value == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    if (vtable_identity.value > UINT32_MAX - UINT32_C(4)) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    method_cell.value = vtable_identity.value + UINT32_C(4);
    status = rome2_100e2460_resolve_cell(
        vtable_view->guest_base,
        vtable_view->byte_count,
        method_cell,
        &method_offset);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    if (rome2_100e2460_spans_overlap(
            (uint64_t)method_cell.value,
            ROME2_100E2460_CELL_BYTES,
            (uint64_t)state_view->guest_base + plan.append_offset,
            ROME2_100E2460_CELL_BYTES) ||
        rome2_100e2460_spans_overlap(
            (uint64_t)method_cell.value,
            ROME2_100E2460_CELL_BYTES,
            (uint64_t)state_view->guest_base + plan.count_offset,
            ROME2_100E2460_CELL_BYTES) ||
        rome2_100e2460_spans_overlap(
            (uintptr_t)vtable_view->host_base + method_offset,
            ROME2_100E2460_CELL_BYTES,
            (uintptr_t)state_view->host_base + plan.append_offset,
            ROME2_100E2460_CELL_BYTES) ||
        rome2_100e2460_spans_overlap(
            (uintptr_t)vtable_view->host_base + method_offset,
            ROME2_100E2460_CELL_BYTES,
            (uintptr_t)state_view->host_base + plan.count_offset,
            ROME2_100E2460_CELL_BYTES)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    method_identity.value = rome2_100e2460_read_u32_le(
        vtable_view->host_base + (size_t)method_offset);
    if (method_identity.value == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }

    append_status = rome2_port_100e2460_append_preallocated_prefix(
        state_view, guest_vector, guest_handler);
    if (append_status != ROME2_GUEST_OK) {
        return rome2_100e2460_map_guest_status(append_status);
    }

    dispatch_eax = dispatch(
        context, guest_handler, method_identity, guest_argument);
    saved_al = (uint8_t)dispatch_eax;
    null_identity.value = 0;
    for (peek_calls = 0; peek_calls < max_peek_calls; ++peek_calls) {
        peek_eax = peek(
            context,
            null_identity,
            null_identity,
            UINT32_C(0),
            UINT32_C(0),
            ROME2_PORT_100E2460_PM_REMOVE);
        if (peek_eax == 0) {
            *return_al_out = saved_al;
            return ROME2_100E2460_BRANCH_OK;
        }
    }
    return ROME2_100E2460_BRANCH_DRAIN_LIMIT;
}

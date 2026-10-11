#include "ported_100e2460_capacity_zero_branch.h"

#include <limits.h>

#define ROME2_100E2460_ZERO_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100E2460_ZERO_CELL_BYTES UINT64_C(4)

typedef struct rome2_100e2460_zero_plan {
    uint64_t vector_offset;
    uint64_t capacity_offset;
    uint64_t count_offset;
    uint64_t backing_offset;
    uint64_t handler_offset;
    uint64_t method_offset;
    rome2_guest_addr32 method_cell;
} rome2_100e2460_zero_plan;

static uint32_t rome2_100e2460_zero_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100e2460_zero_write_u32_le(
    uint8_t *bytes,
    uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static int rome2_100e2460_zero_spans_overlap(
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

static rome2_100e2460_branch_status rome2_100e2460_zero_validate_object(
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

static rome2_100e2460_branch_status rome2_100e2460_zero_validate_interval(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100E2460_ZERO_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100E2460_ZERO_ADDRESS_SPACE_SIZE) {
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

static rome2_100e2460_branch_status rome2_100e2460_zero_resolve_cell(
    uint32_t guest_base,
    uint64_t byte_count,
    rome2_guest_addr32 cell,
    uint64_t *offset_out)
{
    uint64_t offset;

    if (cell.value == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    if (cell.value > UINT32_MAX - UINT32_C(3)) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    if (cell.value < guest_base) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }
    offset = (uint64_t)cell.value - (uint64_t)guest_base;
    if (offset > byte_count ||
        ROME2_100E2460_ZERO_CELL_BYTES > byte_count - offset ||
        offset > (uint64_t)SIZE_MAX) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }
    *offset_out = offset;
    return ROME2_100E2460_BRANCH_OK;
}

static int rome2_100e2460_zero_control_objects_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    const rome2_100e2460_capacity_zero_effects *effects,
    const uint8_t *return_al_out)
{
    return
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)state_view,
            sizeof(*state_view),
            (uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)state_view,
            sizeof(*state_view),
            (uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)vtable_view,
            sizeof(*vtable_view),
            (uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uintptr_t)effects,
            sizeof(*effects));
}

static int rome2_100e2460_zero_host_objects_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    const rome2_100e2460_capacity_zero_effects *effects,
    const uint8_t *return_al_out)
{
    return
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uintptr_t)return_al_out,
            sizeof(*return_al_out)) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)vtable_view->host_base,
            vtable_view->byte_count,
            (uintptr_t)return_al_out,
            sizeof(*return_al_out));
}

static int rome2_100e2460_zero_cell_overlaps_vector_writes(
    uint64_t cell_offset,
    const rome2_100e2460_zero_plan *plan)
{
    return
        rome2_100e2460_zero_spans_overlap(
            cell_offset,
            ROME2_100E2460_ZERO_CELL_BYTES,
            plan->capacity_offset,
            ROME2_100E2460_ZERO_CELL_BYTES) ||
        rome2_100e2460_zero_spans_overlap(
            cell_offset,
            ROME2_100E2460_ZERO_CELL_BYTES,
            plan->count_offset,
            ROME2_100E2460_ZERO_CELL_BYTES) ||
        rome2_100e2460_zero_spans_overlap(
            cell_offset,
            ROME2_100E2460_ZERO_CELL_BYTES,
            plan->backing_offset,
            ROME2_100E2460_ZERO_CELL_BYTES);
}

static rome2_100e2460_branch_status rome2_100e2460_zero_plan_precommit(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_handler,
    rome2_100e2460_zero_plan *plan)
{
    const uint8_t *vector;
    rome2_100e2460_branch_status status;
    rome2_guest_addr32 vtable_identity;
    uint64_t method_guest;
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
    if (guest_vector.value < state_view->guest_base) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }
    plan->vector_offset =
        (uint64_t)guest_vector.value - (uint64_t)state_view->guest_base;
    if (plan->vector_offset > state_view->byte_count ||
        ROME2_PORT_100E2460_VECTOR_BYTES >
            state_view->byte_count - plan->vector_offset ||
        plan->vector_offset > (uint64_t)SIZE_MAX) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }
    plan->capacity_offset = plan->vector_offset + UINT64_C(4);
    plan->count_offset = plan->vector_offset + UINT64_C(8);
    plan->backing_offset = plan->vector_offset + UINT64_C(12);
    vector = state_view->host_base + (size_t)plan->vector_offset;
    capacity = rome2_100e2460_zero_read_u32_le(vector + 4);
    count = rome2_100e2460_zero_read_u32_le(vector + 8);
    backing = rome2_100e2460_zero_read_u32_le(vector + 12);
    if (capacity != 0 || count != 0 || backing != 0) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    status = rome2_100e2460_zero_resolve_cell(
        state_view->guest_base,
        state_view->byte_count,
        guest_handler,
        &plan->handler_offset);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    if (rome2_100e2460_zero_cell_overlaps_vector_writes(
            plan->handler_offset, plan)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    vtable_identity.value = rome2_100e2460_zero_read_u32_le(
        state_view->host_base + (size_t)plan->handler_offset);
    if (vtable_identity.value == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    if (vtable_identity.value > UINT32_MAX - UINT32_C(4)) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    plan->method_cell.value = vtable_identity.value + UINT32_C(4);
    status = rome2_100e2460_zero_resolve_cell(
        vtable_view->guest_base,
        vtable_view->byte_count,
        plan->method_cell,
        &plan->method_offset);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    method_guest = (uint64_t)plan->method_cell.value;
    if (rome2_100e2460_zero_spans_overlap(
            method_guest,
            ROME2_100E2460_ZERO_CELL_BYTES,
            (uint64_t)state_view->guest_base + plan->capacity_offset,
            ROME2_100E2460_ZERO_CELL_BYTES) ||
        rome2_100e2460_zero_spans_overlap(
            method_guest,
            ROME2_100E2460_ZERO_CELL_BYTES,
            (uint64_t)state_view->guest_base + plan->count_offset,
            ROME2_100E2460_ZERO_CELL_BYTES) ||
        rome2_100e2460_zero_spans_overlap(
            method_guest,
            ROME2_100E2460_ZERO_CELL_BYTES,
            (uint64_t)state_view->guest_base + plan->backing_offset,
            ROME2_100E2460_ZERO_CELL_BYTES) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)vtable_view->host_base + plan->method_offset,
            ROME2_100E2460_ZERO_CELL_BYTES,
            (uintptr_t)state_view->host_base + plan->capacity_offset,
            ROME2_100E2460_ZERO_CELL_BYTES) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)vtable_view->host_base + plan->method_offset,
            ROME2_100E2460_ZERO_CELL_BYTES,
            (uintptr_t)state_view->host_base + plan->count_offset,
            ROME2_100E2460_ZERO_CELL_BYTES) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)vtable_view->host_base + plan->method_offset,
            ROME2_100E2460_ZERO_CELL_BYTES,
            (uintptr_t)state_view->host_base + plan->backing_offset,
            ROME2_100E2460_ZERO_CELL_BYTES)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    if (rome2_100e2460_zero_read_u32_le(
            vtable_view->host_base + (size_t)plan->method_offset) == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    return ROME2_100E2460_BRANCH_OK;
}

static int rome2_100e2460_zero_result_aliases_borrowed_cells(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    const rome2_100e2460_zero_plan *plan,
    rome2_guest_addr32 allocation,
    uint64_t allocation_offset)
{
    return
        rome2_100e2460_zero_spans_overlap(
            allocation_offset,
            ROME2_100E2460_ZERO_CELL_BYTES,
            plan->vector_offset,
            ROME2_PORT_100E2460_VECTOR_BYTES) ||
        rome2_100e2460_zero_spans_overlap(
            allocation_offset,
            ROME2_100E2460_ZERO_CELL_BYTES,
            plan->handler_offset,
            ROME2_100E2460_ZERO_CELL_BYTES) ||
        rome2_100e2460_zero_spans_overlap(
            (uint64_t)allocation.value,
            ROME2_100E2460_ZERO_CELL_BYTES,
            (uint64_t)plan->method_cell.value,
            ROME2_100E2460_ZERO_CELL_BYTES) ||
        rome2_100e2460_zero_spans_overlap(
            (uintptr_t)state_view->host_base + allocation_offset,
            ROME2_100E2460_ZERO_CELL_BYTES,
            (uintptr_t)vtable_view->host_base + plan->method_offset,
            ROME2_100E2460_ZERO_CELL_BYTES);
}

rome2_100e2460_branch_status rome2_port_100e2460_run_capacity_zero_branch(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_handler,
    rome2_guest_addr32 guest_argument,
    const rome2_100e2460_capacity_zero_effects *effects,
    uint32_t max_peek_calls,
    uint8_t *return_al_out)
{
    rome2_100e2460_allocate_effect_fn allocate;
    rome2_100e2460_branch_status status;
    rome2_100e2460_zero_plan plan;
    rome2_guest_addr32 allocation;
    uint64_t allocation_offset;
    void *context;

    status = rome2_100e2460_zero_validate_object(
        state_view, sizeof(*state_view));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_zero_validate_object(
        vtable_view, sizeof(*vtable_view));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_zero_validate_object(effects, sizeof(*effects));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_zero_validate_object(
        return_al_out, sizeof(*return_al_out));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    if (rome2_100e2460_zero_control_objects_overlap(
            state_view, vtable_view, effects, return_al_out)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    status = rome2_100e2460_zero_validate_interval(
        state_view->host_base, state_view->guest_base, state_view->byte_count);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_zero_validate_interval(
        vtable_view->host_base,
        vtable_view->guest_base,
        vtable_view->byte_count);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    if (rome2_100e2460_zero_host_objects_overlap(
            state_view, vtable_view, effects, return_al_out)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    allocate = effects->allocate;
    context = effects->tail_effects.context;
    if (allocate == NULL || effects->tail_effects.dispatch == NULL ||
        effects->tail_effects.peek == NULL || max_peek_calls == 0) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    status = rome2_100e2460_zero_plan_precommit(
        state_view, vtable_view, guest_vector, guest_handler, &plan);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }

    rome2_100e2460_zero_write_u32_le(
        state_view->host_base + (size_t)plan.capacity_offset, UINT32_C(1));
    allocation = allocate(
        context,
        ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_BYTES,
        ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_CLASS);

    status = rome2_100e2460_zero_resolve_cell(
        state_view->guest_base,
        state_view->byte_count,
        allocation,
        &allocation_offset);
    if (status != ROME2_100E2460_BRANCH_OK ||
        rome2_100e2460_zero_result_aliases_borrowed_cells(
            state_view,
            vtable_view,
            &plan,
            allocation,
            allocation_offset)) {
        return ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID;
    }

    rome2_100e2460_zero_write_u32_le(
        state_view->host_base + (size_t)plan.backing_offset,
        allocation.value);
    return rome2_port_100e2460_run_preallocated_branch(
        state_view,
        vtable_view,
        guest_vector,
        guest_handler,
        guest_argument,
        &effects->tail_effects,
        max_peek_calls,
        return_al_out);
}

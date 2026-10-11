#include "ported_100e2460_growth_branch.h"

#include <limits.h>

#define ROME2_100E2460_GROWTH_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100E2460_GROWTH_CELL_BYTES UINT64_C(4)

typedef struct rome2_100e2460_growth_span {
    uint64_t guest_start;
    uintptr_t host_start;
    uint64_t byte_count;
    uint64_t view_offset;
} rome2_100e2460_growth_span;

typedef struct rome2_100e2460_growth_plan {
    rome2_100e2460_growth_span vector;
    rome2_100e2460_growth_span old_buffer;
    rome2_100e2460_growth_span handler;
    rome2_100e2460_growth_span method;
    uint64_t capacity_offset;
    uint64_t count_offset;
    uint64_t backing_offset;
    uint32_t capacity;
    uint32_t count;
    uint32_t new_capacity;
    uint32_t allocation_bytes;
    rome2_guest_addr32 old_backing;
    rome2_guest_addr32 method_identity;
} rome2_100e2460_growth_plan;

static uint32_t rome2_100e2460_growth_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100e2460_growth_write_u32_le(
    uint8_t *bytes,
    uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static int rome2_100e2460_growth_spans_overlap(
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

static int rome2_100e2460_growth_mapped_spans_alias(
    const rome2_100e2460_growth_span *first,
    const rome2_100e2460_growth_span *second)
{
    return
        rome2_100e2460_growth_spans_overlap(
            first->guest_start,
            first->byte_count,
            second->guest_start,
            second->byte_count) ||
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)first->host_start,
            first->byte_count,
            (uint64_t)second->host_start,
            second->byte_count);
}

static rome2_100e2460_branch_status
rome2_100e2460_growth_validate_object(
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

static rome2_100e2460_branch_status
rome2_100e2460_growth_validate_interval(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100E2460_GROWTH_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100E2460_GROWTH_ADDRESS_SPACE_SIZE) {
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

static rome2_100e2460_branch_status
rome2_100e2460_growth_resolve_span(
    const void *host_base,
    uint32_t guest_base,
    uint64_t view_byte_count,
    rome2_guest_addr32 guest_start,
    uint64_t span_byte_count,
    rome2_100e2460_growth_span *span_out)
{
    uint64_t offset;

    if (span_out == NULL || span_byte_count == 0) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    if (guest_start.value == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    if (span_byte_count > ROME2_100E2460_GROWTH_ADDRESS_SPACE_SIZE ||
        span_byte_count >
            ROME2_100E2460_GROWTH_ADDRESS_SPACE_SIZE -
                (uint64_t)guest_start.value) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    if (guest_start.value < guest_base) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }
    offset = (uint64_t)guest_start.value - (uint64_t)guest_base;
    if (offset > view_byte_count ||
        span_byte_count > view_byte_count - offset ||
        offset > (uint64_t)SIZE_MAX) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }

    span_out->guest_start = (uint64_t)guest_start.value;
    span_out->host_start = (uintptr_t)host_base + (uintptr_t)offset;
    span_out->byte_count = span_byte_count;
    span_out->view_offset = offset;
    return ROME2_100E2460_BRANCH_OK;
}

static int rome2_100e2460_growth_control_objects_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    const rome2_100e2460_growth_effects *effects,
    const uint8_t *return_al_out)
{
    return
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects));
}

static int rome2_100e2460_growth_host_objects_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    const rome2_100e2460_growth_effects *effects,
    const uint8_t *return_al_out)
{
    return
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)(uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)(uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)(uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)(uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out)) ||
        rome2_100e2460_growth_spans_overlap(
            (uint64_t)(uintptr_t)vtable_view->host_base,
            vtable_view->byte_count,
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out));
}

static int rome2_100e2460_growth_plan_has_alias(
    const rome2_100e2460_growth_plan *plan)
{
    return
        rome2_100e2460_growth_mapped_spans_alias(
            &plan->vector, &plan->old_buffer) ||
        rome2_100e2460_growth_mapped_spans_alias(
            &plan->vector, &plan->handler) ||
        rome2_100e2460_growth_mapped_spans_alias(
            &plan->vector, &plan->method) ||
        rome2_100e2460_growth_mapped_spans_alias(
            &plan->old_buffer, &plan->handler) ||
        rome2_100e2460_growth_mapped_spans_alias(
            &plan->old_buffer, &plan->method) ||
        rome2_100e2460_growth_mapped_spans_alias(
            &plan->handler, &plan->method);
}

static rome2_100e2460_branch_status
rome2_100e2460_growth_plan_precommit(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_handler,
    rome2_100e2460_growth_plan *plan)
{
    const uint8_t *vector;
    rome2_100e2460_branch_status status;
    rome2_guest_addr32 method_cell;
    rome2_guest_addr32 vtable_identity;
    uint64_t old_byte_count;

    status = rome2_100e2460_growth_resolve_span(
        state_view->host_base,
        state_view->guest_base,
        state_view->byte_count,
        guest_vector,
        ROME2_PORT_100E2460_VECTOR_BYTES,
        &plan->vector);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    plan->capacity_offset = plan->vector.view_offset + UINT64_C(4);
    plan->count_offset = plan->vector.view_offset + UINT64_C(8);
    plan->backing_offset = plan->vector.view_offset + UINT64_C(12);
    vector = state_view->host_base + (size_t)plan->vector.view_offset;
    plan->capacity = rome2_100e2460_growth_read_u32_le(vector + 4);
    plan->count = rome2_100e2460_growth_read_u32_le(vector + 8);
    plan->old_backing.value =
        rome2_100e2460_growth_read_u32_le(vector + 12);

    if (plan->capacity == 0 || plan->count != plan->capacity) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    if (plan->old_backing.value == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    if (plan->capacity >
        ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    plan->new_capacity = plan->capacity * UINT32_C(2);
    plan->allocation_bytes = plan->new_capacity * UINT32_C(4);
    old_byte_count =
        (uint64_t)plan->count * ROME2_100E2460_GROWTH_CELL_BYTES;

    status = rome2_100e2460_growth_resolve_span(
        state_view->host_base,
        state_view->guest_base,
        state_view->byte_count,
        plan->old_backing,
        old_byte_count,
        &plan->old_buffer);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_growth_resolve_span(
        state_view->host_base,
        state_view->guest_base,
        state_view->byte_count,
        guest_handler,
        ROME2_100E2460_GROWTH_CELL_BYTES,
        &plan->handler);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }

    vtable_identity.value = rome2_100e2460_growth_read_u32_le(
        state_view->host_base + (size_t)plan->handler.view_offset);
    if (vtable_identity.value == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    if (vtable_identity.value > UINT32_MAX - UINT32_C(4)) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    method_cell.value = vtable_identity.value + UINT32_C(4);
    status = rome2_100e2460_growth_resolve_span(
        vtable_view->host_base,
        vtable_view->guest_base,
        vtable_view->byte_count,
        method_cell,
        ROME2_100E2460_GROWTH_CELL_BYTES,
        &plan->method);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    plan->method_identity.value = rome2_100e2460_growth_read_u32_le(
        vtable_view->host_base + (size_t)plan->method.view_offset);
    if (plan->method_identity.value == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    if (rome2_100e2460_growth_plan_has_alias(plan)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    return ROME2_100E2460_BRANCH_OK;
}

static int rome2_100e2460_growth_result_aliases_plan(
    const rome2_100e2460_growth_span *allocation,
    const rome2_100e2460_growth_plan *plan)
{
    return
        rome2_100e2460_growth_mapped_spans_alias(
            allocation, &plan->vector) ||
        rome2_100e2460_growth_mapped_spans_alias(
            allocation, &plan->old_buffer) ||
        rome2_100e2460_growth_mapped_spans_alias(
            allocation, &plan->handler) ||
        rome2_100e2460_growth_mapped_spans_alias(
            allocation, &plan->method);
}

rome2_100e2460_branch_status rome2_port_100e2460_run_growth_branch(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_handler,
    rome2_guest_addr32 guest_argument,
    const rome2_100e2460_growth_effects *effects,
    uint32_t max_peek_calls,
    uint8_t *return_al_out)
{
    rome2_100e2460_allocate_effect_fn allocate;
    rome2_100e2460_branch_status status;
    rome2_100e2460_dispatch_effect_fn dispatch;
    rome2_100e2460_growth_effects effects_snapshot;
    rome2_100e2460_growth_plan plan;
    rome2_100e2460_growth_span allocation_span;
    rome2_100e2460_peek_effect_fn peek;
    rome2_100e2460_release_effect_fn release;
    rome2_guest_addr32 allocation;
    rome2_guest_addr32 null_identity;
    uint32_t cell_index;
    uint32_t cell_value;
    uint32_t dispatch_eax;
    uint32_t peek_calls;
    uint32_t peek_eax;
    uint8_t saved_al;
    void *context;

    status = rome2_100e2460_growth_validate_object(
        state_view, sizeof(*state_view));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_growth_validate_object(
        vtable_view, sizeof(*vtable_view));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_growth_validate_object(
        effects, sizeof(*effects));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_growth_validate_object(
        return_al_out, sizeof(*return_al_out));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    if (rome2_100e2460_growth_control_objects_overlap(
            state_view, vtable_view, effects, return_al_out)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    status = rome2_100e2460_growth_validate_interval(
        state_view->host_base, state_view->guest_base, state_view->byte_count);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_growth_validate_interval(
        vtable_view->host_base,
        vtable_view->guest_base,
        vtable_view->byte_count);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    if (rome2_100e2460_growth_host_objects_overlap(
            state_view, vtable_view, effects, return_al_out)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    /* Snapshot every injected identity before the first guest write. */
    effects_snapshot = *effects;
    allocate = effects_snapshot.allocate;
    release = effects_snapshot.release;
    dispatch = effects_snapshot.tail_effects.dispatch;
    peek = effects_snapshot.tail_effects.peek;
    context = effects_snapshot.tail_effects.context;
    if (allocate == NULL || release == NULL || dispatch == NULL ||
        peek == NULL || max_peek_calls == 0) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    status = rome2_100e2460_growth_plan_precommit(
        state_view, vtable_view, guest_vector, guest_handler, &plan);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }

    rome2_100e2460_growth_write_u32_le(
        state_view->host_base + (size_t)plan.capacity_offset,
        plan.new_capacity);
    allocation = allocate(
        context,
        plan.allocation_bytes,
        ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS);

    status = rome2_100e2460_growth_resolve_span(
        state_view->host_base,
        state_view->guest_base,
        state_view->byte_count,
        allocation,
        plan.allocation_bytes,
        &allocation_span);
    if (status != ROME2_100E2460_BRANCH_OK ||
        rome2_100e2460_growth_result_aliases_plan(
            &allocation_span, &plan)) {
        return ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID;
    }

    rome2_100e2460_growth_write_u32_le(
        state_view->host_base + (size_t)plan.backing_offset,
        allocation.value);
    for (cell_index = 0; cell_index < plan.count; ++cell_index) {
        uint64_t cell_displacement =
            (uint64_t)cell_index * ROME2_100E2460_GROWTH_CELL_BYTES;

        cell_value = rome2_100e2460_growth_read_u32_le(
            state_view->host_base +
                (size_t)(plan.old_buffer.view_offset + cell_displacement));
        rome2_100e2460_growth_write_u32_le(
            state_view->host_base +
                (size_t)(allocation_span.view_offset + cell_displacement),
            cell_value);
    }
    rome2_100e2460_growth_write_u32_le(
        state_view->host_base +
            (size_t)(allocation_span.view_offset +
                (uint64_t)plan.count *
                    ROME2_100E2460_GROWTH_CELL_BYTES),
        guest_handler.value);

    release(context, plan.old_backing);
    rome2_100e2460_growth_write_u32_le(
        state_view->host_base + (size_t)plan.count_offset,
        plan.count + UINT32_C(1));

    dispatch_eax = dispatch(
        context, guest_handler, plan.method_identity, guest_argument);
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

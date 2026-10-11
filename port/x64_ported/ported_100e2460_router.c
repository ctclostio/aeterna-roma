#include "ported_100e2460_router.h"

#include <limits.h>

#define ROME2_100E2460_ROUTER_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100E2460_ROUTER_SELECTION_BYTES UINT64_C(12)

static uint32_t rome2_100e2460_router_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static int rome2_100e2460_router_spans_overlap(
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

static rome2_100e2460_branch_status
rome2_100e2460_router_validate_object(
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
rome2_100e2460_router_validate_interval(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100E2460_ROUTER_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100E2460_ROUTER_ADDRESS_SPACE_SIZE) {
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

static int rome2_100e2460_router_control_objects_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    const rome2_100e2460_growth_effects *effects,
    const uint8_t *return_al_out)
{
    return
        rome2_100e2460_router_spans_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_router_spans_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_router_spans_overlap(
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_router_spans_overlap(
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100e2460_router_spans_overlap(
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_router_spans_overlap(
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects));
}

static int rome2_100e2460_router_host_objects_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    const rome2_100e2460_growth_effects *effects,
    const uint8_t *return_al_out)
{
    return
        rome2_100e2460_router_spans_overlap(
            (uint64_t)(uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100e2460_router_spans_overlap(
            (uint64_t)(uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uint64_t)(uintptr_t)vtable_view,
            sizeof(*vtable_view)) ||
        rome2_100e2460_router_spans_overlap(
            (uint64_t)(uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e2460_router_spans_overlap(
            (uint64_t)(uintptr_t)state_view->host_base,
            state_view->byte_count,
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out)) ||
        rome2_100e2460_router_spans_overlap(
            (uint64_t)(uintptr_t)vtable_view->host_base,
            vtable_view->byte_count,
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out));
}

static rome2_100e2460_branch_status
rome2_100e2460_router_read_selector(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_vector,
    uint32_t *capacity_out,
    uint32_t *count_out)
{
    const uint8_t *vector;
    uint64_t vector_offset;

    if (guest_vector.value == 0) {
        return ROME2_100E2460_BRANCH_NULL_ADDRESS;
    }
    if (guest_vector.value >
        UINT32_MAX -
            (uint32_t)(ROME2_100E2460_ROUTER_SELECTION_BYTES - UINT64_C(1))) {
        return ROME2_100E2460_BRANCH_RANGE_OVERFLOW;
    }
    if (guest_vector.value < state_view->guest_base) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }
    vector_offset =
        (uint64_t)guest_vector.value - (uint64_t)state_view->guest_base;
    if (vector_offset > state_view->byte_count ||
        ROME2_100E2460_ROUTER_SELECTION_BYTES >
            state_view->byte_count - vector_offset ||
        vector_offset > (uint64_t)SIZE_MAX) {
        return ROME2_100E2460_BRANCH_OUT_OF_RANGE;
    }

    vector = state_view->host_base + (size_t)vector_offset;
    *capacity_out = rome2_100e2460_router_read_u32_le(vector + 4);
    *count_out = rome2_100e2460_router_read_u32_le(vector + 8);
    return ROME2_100E2460_BRANCH_OK;
}

rome2_100e2460_branch_status rome2_port_100e2460_run_router(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_handler,
    rome2_guest_addr32 guest_argument,
    const rome2_100e2460_growth_effects *effects,
    uint32_t max_peek_calls,
    uint8_t *return_al_out)
{
    rome2_100e2460_branch_status status;
    rome2_100e2460_capacity_zero_effects zero_effects;
    rome2_100e2460_growth_effects effects_snapshot;
    uint32_t capacity;
    uint32_t count;

    status = rome2_100e2460_router_validate_object(
        state_view, sizeof(*state_view));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_router_validate_object(
        vtable_view, sizeof(*vtable_view));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_router_validate_object(
        effects, sizeof(*effects));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_router_validate_object(
        return_al_out, sizeof(*return_al_out));
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    if (rome2_100e2460_router_control_objects_overlap(
            state_view, vtable_view, effects, return_al_out)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    status = rome2_100e2460_router_validate_interval(
        state_view->host_base, state_view->guest_base, state_view->byte_count);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    status = rome2_100e2460_router_validate_interval(
        vtable_view->host_base,
        vtable_view->guest_base,
        vtable_view->byte_count);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }
    if (rome2_100e2460_router_host_objects_overlap(
            state_view, vtable_view, effects, return_al_out)) {
        return ROME2_100E2460_BRANCH_BAD_ARGUMENT;
    }

    /* Preserve the complete callback/context identity set before routing. */
    effects_snapshot = *effects;
    status = rome2_100e2460_router_read_selector(
        state_view, guest_vector, &capacity, &count);
    if (status != ROME2_100E2460_BRANCH_OK) {
        return status;
    }

    if (count < capacity) {
        return rome2_port_100e2460_run_preallocated_branch(
            state_view,
            vtable_view,
            guest_vector,
            guest_handler,
            guest_argument,
            &effects_snapshot.tail_effects,
            max_peek_calls,
            return_al_out);
    }

    if (capacity == 0) {
        zero_effects.tail_effects = effects_snapshot.tail_effects;
        zero_effects.allocate = effects_snapshot.allocate;
        return rome2_port_100e2460_run_capacity_zero_branch(
            state_view,
            vtable_view,
            guest_vector,
            guest_handler,
            guest_argument,
            &zero_effects,
            max_peek_calls,
            return_al_out);
    }

    return rome2_port_100e2460_run_growth_branch(
        state_view,
        vtable_view,
        guest_vector,
        guest_handler,
        guest_argument,
        &effects_snapshot,
        max_peek_calls,
        return_al_out);
}

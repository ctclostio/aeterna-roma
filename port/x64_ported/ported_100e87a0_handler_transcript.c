#include "ported_100e87a0_handler_transcript.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define ROME2_100E87A0_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)

typedef struct rome2_100e87a0_span {
    uint64_t guest_start;
    uintptr_t host_start;
    uint64_t byte_count;
    uint64_t view_offset;
} rome2_100e87a0_span;

static rome2_100e87a0_status rome2_100e87a0_validate_object(
    const void *object,
    size_t byte_count)
{
    uintptr_t address;

    if (object == NULL || byte_count == 0U) {
        return ROME2_100E87A0_BAD_ARGUMENT;
    }
    address = (uintptr_t)object;
    if (byte_count - 1U > UINTPTR_MAX - address) {
        return ROME2_100E87A0_RANGE_OVERFLOW;
    }
    return ROME2_100E87A0_OK;
}

static int rome2_100e87a0_ranges_overlap(
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

static rome2_100e87a0_status rome2_100e87a0_validate_interval(
    const rome2_guest_write_view *view)
{
    uintptr_t host_address;

    if (view->host_base == NULL) {
        return ROME2_100E87A0_BAD_ARGUMENT;
    }
    if (view->byte_count > ROME2_100E87A0_ADDRESS_SPACE_SIZE ||
        (uint64_t)view->guest_base + view->byte_count >
            ROME2_100E87A0_ADDRESS_SPACE_SIZE) {
        return ROME2_100E87A0_RANGE_OVERFLOW;
    }
    host_address = (uintptr_t)view->host_base;
    if (view->byte_count != 0 &&
        view->byte_count - UINT64_C(1) >
            (uint64_t)(UINTPTR_MAX - host_address)) {
        return ROME2_100E87A0_RANGE_OVERFLOW;
    }
    return ROME2_100E87A0_OK;
}

static int rome2_100e87a0_control_objects_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_100e87a0_effects *effects,
    const uint8_t *return_al_out)
{
    return
        rome2_100e87a0_ranges_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e87a0_ranges_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out)) ||
        rome2_100e87a0_ranges_overlap(
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects),
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out));
}

static int rome2_100e87a0_host_interval_overlaps_controls(
    const rome2_guest_write_view *view,
    const rome2_guest_write_view *state_view,
    const rome2_100e87a0_effects *effects,
    const uint8_t *return_al_out)
{
    uint64_t host_start = (uint64_t)(uintptr_t)view->host_base;

    return
        rome2_100e87a0_ranges_overlap(
            host_start,
            view->byte_count,
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100e87a0_ranges_overlap(
            host_start,
            view->byte_count,
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100e87a0_ranges_overlap(
            host_start,
            view->byte_count,
            (uint64_t)(uintptr_t)return_al_out,
            sizeof(*return_al_out));
}

static rome2_100e87a0_status rome2_100e87a0_resolve_listener(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 listener,
    rome2_100e87a0_span *span_out)
{
    uint64_t offset;

    if (span_out == NULL) {
        return ROME2_100E87A0_BAD_ARGUMENT;
    }
    if (listener.value == 0) {
        return ROME2_100E87A0_NULL_ADDRESS;
    }
    if (ROME2_PORT_100E87A0_LISTENER_BYTES >
        ROME2_100E87A0_ADDRESS_SPACE_SIZE - (uint64_t)listener.value) {
        return ROME2_100E87A0_RANGE_OVERFLOW;
    }
    if (listener.value < view->guest_base) {
        return ROME2_100E87A0_OUT_OF_RANGE;
    }
    offset = (uint64_t)listener.value - (uint64_t)view->guest_base;
    if (offset > view->byte_count ||
        ROME2_PORT_100E87A0_LISTENER_BYTES > view->byte_count - offset ||
        offset > (uint64_t)SIZE_MAX) {
        return ROME2_100E87A0_OUT_OF_RANGE;
    }

    span_out->guest_start = (uint64_t)listener.value;
    span_out->host_start = (uintptr_t)view->host_base + (uintptr_t)offset;
    span_out->byte_count = ROME2_PORT_100E87A0_LISTENER_BYTES;
    span_out->view_offset = offset;
    return ROME2_100E87A0_OK;
}

static void rome2_100e87a0_write_u32_le(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static rome2_100e87a0_memory_policy rome2_100e87a0_policy(void)
{
    rome2_100e87a0_memory_policy policy;

    policy.allocation_type = ROME2_PORT_100E87A0_POLICY_TYPE;
    policy.track_allocations =
        ROME2_PORT_100E87A0_POLICY_TRACK_ALLOCATIONS;
    policy.allocate_identity =
        ROME2_PORT_100E87A0_POLICY_ALLOCATE_IDENTITY;
    policy.allocate_debug_identity =
        ROME2_PORT_100E87A0_POLICY_ALLOCATE_DEBUG_IDENTITY;
    policy.free_identity = ROME2_PORT_100E87A0_POLICY_FREE_IDENTITY;
    return policy;
}

rome2_100e87a0_status rome2_port_100e87a0_run_handler_transcript(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100e87a0_effects *effects,
    uint8_t *return_al_out)
{
    rome2_guest_write_view state_snapshot;
    rome2_100e87a0_effects effects_snapshot;
    rome2_100e87a0_memory_policy policy;
    rome2_100e87a0_span listener_span;
    rome2_guest_addr32 listener;
    rome2_100e87a0_status status;

    status = rome2_100e87a0_validate_object(
        state_view, sizeof(*state_view));
    if (status != ROME2_100E87A0_OK) {
        return status;
    }
    status = rome2_100e87a0_validate_object(effects, sizeof(*effects));
    if (status != ROME2_100E87A0_OK) {
        return status;
    }
    status = rome2_100e87a0_validate_object(
        return_al_out, sizeof(*return_al_out));
    if (status != ROME2_100E87A0_OK) {
        return status;
    }
    if ((uintptr_t)state_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)effects % _Alignof(rome2_100e87a0_effects) != 0U ||
        rome2_100e87a0_control_objects_overlap(
            state_view, effects, return_al_out)) {
        return ROME2_100E87A0_BAD_ARGUMENT;
    }

    state_snapshot = *state_view;
    status = rome2_100e87a0_validate_interval(&state_snapshot);
    if (status != ROME2_100E87A0_OK) {
        return status;
    }
    if (rome2_100e87a0_host_interval_overlaps_controls(
            &state_snapshot, state_view, effects, return_al_out)) {
        return ROME2_100E87A0_BAD_ARGUMENT;
    }

    effects_snapshot = *effects;
    if (effects_snapshot.allocate_listener == NULL ||
        effects_snapshot.publish_listener == NULL ||
        effects_snapshot.startup_facefx == NULL ||
        effects_snapshot.context == NULL) {
        return ROME2_100E87A0_BAD_ARGUMENT;
    }

    (void)guest_receiver;
    (void)guest_argument;
    policy = rome2_100e87a0_policy();

    listener = effects_snapshot.allocate_listener(
        effects_snapshot.context,
        ROME2_PORT_100E87A0_LISTENER_BYTES,
        ROME2_PORT_100E87A0_ALLOCATION_CLASS);
    if (listener.value != 0) {
        status = rome2_100e87a0_resolve_listener(
            &state_snapshot, listener, &listener_span);
        if (status != ROME2_100E87A0_OK) {
            return ROME2_100E87A0_ALLOCATION_RESULT_INVALID;
        }
        rome2_100e87a0_write_u32_le(
            state_snapshot.host_base + (size_t)listener_span.view_offset,
            ROME2_PORT_100E87A0_LISTENER_VTABLE);
    }

    effects_snapshot.publish_listener(effects_snapshot.context, listener);
    effects_snapshot.startup_facefx(
        effects_snapshot.context,
        policy,
        listener,
        ROME2_PORT_100E87A0_LOG_LEVEL);
    *return_al_out = ROME2_PORT_100E87A0_AL;
    return ROME2_100E87A0_OK;
}

#include "ported_100f2750_first_use_owned.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define ROME2_100F2750_FIRST_USE_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100F2750_FIRST_USE_DESCRIPTOR_BYTES UINT32_C(12)
#define ROME2_100F2750_FIRST_USE_HEADER_BYTES UINT32_C(4)
#define ROME2_100F2750_FIRST_USE_UNIT_BYTES UINT32_C(2)
#define ROME2_100F2750_FIRST_USE_ALLOCATION_OVERHEAD UINT32_C(10)
#define ROME2_100F2750_FIRST_USE_PAYLOAD_BIAS UINT32_C(8)
#define ROME2_100F2750_FIRST_USE_CONTROL_COUNT 9U
#define ROME2_100F2750_FIRST_USE_BACKING_COUNT 4U
#define ROME2_100F2750_FIRST_USE_PRIVATE_COUNT 1U
#define ROME2_100F2750_FIRST_USE_REGISTER_CONTROL_COUNT 3U
#define ROME2_100F2750_FIRST_USE_TEARDOWN_CONTROL_COUNT 5U
#define ROME2_100F2750_FIRST_USE_TEARDOWN_BACKING_COUNT 2U

typedef struct rome2_100f2750_first_use_host_span {
    uint64_t start;
    uint64_t byte_count;
} rome2_100f2750_first_use_host_span;

typedef struct rome2_100f2750_first_use_span {
    uint64_t guest_start;
    uint64_t host_start;
    uint64_t byte_count;
    uint64_t view_offset;
} rome2_100f2750_first_use_span;

typedef struct rome2_100f2750_first_use_private {
    rome2_guest_write_view persistent_descriptor_view;
    rome2_guest_write_view temporary_descriptor_view;
    rome2_guest_write_view temporary_heap_view;
    rome2_guest_write_view persistent_heap_view;
    rome2_100f1bb0_owned_effects effects;
    rome2_100f1bb0_owned_owner temporary_owner;
    rome2_100f1bb0_owned_owner persistent_owner_initial;
    rome2_100f1bb0_owned_owner persistent_owner_commit;
    rome2_100f1bb0_owned_grant grant;
    rome2_100f1bb0_owned_grant_result grant_result;
    rome2_100f2750_first_use_lifecycle lifecycle_initial;
    rome2_100f2750_first_use_host_span
        controls[ROME2_100F2750_FIRST_USE_CONTROL_COUNT];
    rome2_100f2750_first_use_host_span
        backings[ROME2_100F2750_FIRST_USE_BACKING_COUNT];
    rome2_100f2750_first_use_host_span context;
    rome2_100f2750_first_use_host_span
        private_spans[ROME2_100F2750_FIRST_USE_PRIVATE_COUNT];
    rome2_100f2750_first_use_span persistent_descriptor;
    rome2_100f2750_first_use_span temporary_descriptor;
    rome2_100f2750_first_use_span temporary_allocation;
    rome2_100f2750_first_use_span temporary_header;
    rome2_100f2750_first_use_span temporary_payload;
    rome2_100f2750_first_use_span temporary_terminator;
    rome2_100f2750_first_use_span persistent_allocation;
    rome2_100f2750_first_use_span persistent_header;
    rome2_100f2750_first_use_span persistent_payload;
    rome2_100f2750_first_use_span persistent_terminator;
    rome2_100f1bb0_owned_status status;
    rome2_guest_addr32 temporary_header_identity;
    rome2_guest_addr32 temporary_terminator_identity;
    rome2_guest_addr32 persistent_header_identity;
    rome2_guest_addr32 persistent_payload_identity;
    rome2_guest_addr32 persistent_terminator_identity;
    uint64_t expected_payload;
    uint64_t terminator_value;
    uint64_t persistent_payload_value;
    uint64_t persistent_terminator_value;
    uint64_t persistent_available_bytes;
    uint32_t payload_bytes;
    uint32_t allocation_bytes;
    uint32_t copy_index;
} rome2_100f2750_first_use_private;

typedef struct rome2_100f2750_first_use_register_private {
    rome2_guest_write_view descriptor_view;
    rome2_100f1bb0_owned_owner owner;
    rome2_100f2750_first_use_lifecycle lifecycle;
    rome2_100f2750_first_use_host_span
        controls[ROME2_100F2750_FIRST_USE_REGISTER_CONTROL_COUNT];
    rome2_100f2750_first_use_host_span backing;
    rome2_100f2750_first_use_host_span private_span;
    rome2_100f2750_first_use_span descriptor;
    rome2_100f1bb0_owned_status status;
} rome2_100f2750_first_use_register_private;

typedef struct rome2_100f2750_first_use_teardown_private {
    rome2_guest_write_view descriptor_view;
    rome2_guest_write_view heap_view;
    rome2_100f1bb0_owned_effects effects;
    rome2_100f1bb0_owned_owner owner;
    rome2_100f2750_first_use_lifecycle lifecycle;
    rome2_100f2750_first_use_host_span
        controls[ROME2_100F2750_FIRST_USE_TEARDOWN_CONTROL_COUNT];
    rome2_100f2750_first_use_host_span
        backings[ROME2_100F2750_FIRST_USE_TEARDOWN_BACKING_COUNT];
    rome2_100f2750_first_use_host_span context;
    rome2_100f2750_first_use_host_span private_span;
    rome2_100f2750_first_use_span descriptor;
    rome2_100f2750_first_use_span allocation;
    rome2_100f2750_first_use_span header;
    rome2_100f2750_first_use_span terminator;
    rome2_guest_addr32 header_identity;
    rome2_guest_addr32 terminator_identity;
    rome2_100f1bb0_owned_status status;
    uint64_t expected_payload;
    uint64_t terminator_value;
    uint32_t expected_payload_bytes;
    uint32_t expected_allocation_bytes;
} rome2_100f2750_first_use_teardown_private;

static uint32_t rome2_100f2750_first_use_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100f2750_first_use_write_u32_le(
    uint8_t *bytes,
    uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static int rome2_100f2750_first_use_ranges_overlap(
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

static rome2_100f1bb0_owned_status rome2_100f2750_first_use_validate_object(
    const void *object,
    size_t byte_count)
{
    uintptr_t address;

    if (object == NULL || byte_count == 0U) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    address = (uintptr_t)object;
    if (byte_count - 1U > UINTPTR_MAX - address) {
        return ROME2_100F1BB0_OWNED_RANGE_OVERFLOW;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

static rome2_100f1bb0_owned_status rome2_100f2750_first_use_validate_view(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100F2750_FIRST_USE_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100F2750_FIRST_USE_ADDRESS_SPACE_SIZE) {
        return ROME2_100F1BB0_OWNED_RANGE_OVERFLOW;
    }
    host_address = (uintptr_t)host_base;
    if (byte_count != 0 &&
        byte_count - UINT64_C(1) >
            (uint64_t)(UINTPTR_MAX - host_address)) {
        return ROME2_100F1BB0_OWNED_RANGE_OVERFLOW;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

static rome2_100f1bb0_owned_status
rome2_100f2750_first_use_validate_host_interval(
    const void *host_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL || byte_count == 0) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    host_address = (uintptr_t)host_base;
    if (byte_count - UINT64_C(1) >
        (uint64_t)(UINTPTR_MAX - host_address)) {
        return ROME2_100F1BB0_OWNED_RANGE_OVERFLOW;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

static rome2_100f1bb0_owned_status rome2_100f2750_first_use_resolve_span(
    const void *host_base,
    uint32_t guest_base,
    uint64_t view_byte_count,
    rome2_guest_addr32 guest_start,
    uint32_t span_byte_count,
    rome2_100f2750_first_use_span *span_out)
{
    uint64_t offset;

    if (span_out == NULL || span_byte_count == 0) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (guest_start.value == 0) {
        return ROME2_100F1BB0_OWNED_NULL_ADDRESS;
    }
    if ((uint64_t)span_byte_count >
        ROME2_100F2750_FIRST_USE_ADDRESS_SPACE_SIZE -
            (uint64_t)guest_start.value) {
        return ROME2_100F1BB0_OWNED_RANGE_OVERFLOW;
    }
    if (guest_start.value < guest_base) {
        return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
    }
    offset = (uint64_t)guest_start.value - (uint64_t)guest_base;
    if (offset > view_byte_count ||
        (uint64_t)span_byte_count > view_byte_count - offset ||
        offset > (uint64_t)SIZE_MAX) {
        return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
    }

    span_out->guest_start = (uint64_t)guest_start.value;
    span_out->host_start = (uint64_t)(uintptr_t)host_base + offset;
    span_out->byte_count = (uint64_t)span_byte_count;
    span_out->view_offset = offset;
    return ROME2_100F1BB0_OWNED_OK;
}

static int rome2_100f2750_first_use_host_spans_overlap(
    const rome2_100f2750_first_use_host_span *spans,
    size_t span_count)
{
    size_t first;
    size_t second;

    for (first = 0; first < span_count; ++first) {
        for (second = first + 1U; second < span_count; ++second) {
            if (rome2_100f2750_first_use_ranges_overlap(
                    spans[first].start,
                    spans[first].byte_count,
                    spans[second].start,
                    spans[second].byte_count)) {
                return 1;
            }
        }
    }
    return 0;
}

static int rome2_100f2750_first_use_span_sets_overlap(
    const rome2_100f2750_first_use_host_span *first,
    size_t first_count,
    const rome2_100f2750_first_use_host_span *second,
    size_t second_count)
{
    size_t first_index;
    size_t second_index;

    for (first_index = 0; first_index < first_count; ++first_index) {
        for (second_index = 0; second_index < second_count; ++second_index) {
            if (rome2_100f2750_first_use_ranges_overlap(
                    first[first_index].start,
                    first[first_index].byte_count,
                    second[second_index].start,
                    second[second_index].byte_count)) {
                return 1;
            }
        }
    }
    return 0;
}

static int rome2_100f2750_first_use_views_logically_overlap(
    uint32_t first_base,
    uint64_t first_size,
    uint32_t second_base,
    uint64_t second_size)
{
    return rome2_100f2750_first_use_ranges_overlap(
        (uint64_t)first_base,
        first_size,
        (uint64_t)second_base,
        second_size);
}

static int rome2_100f2750_first_use_span_is_contained(
    const rome2_100f2750_first_use_span *outer,
    const rome2_100f2750_first_use_span *inner)
{
    if (inner->guest_start < outer->guest_start ||
        inner->host_start < outer->host_start) {
        return 0;
    }
    return
        inner->guest_start - outer->guest_start <= outer->byte_count &&
        inner->byte_count <=
            outer->byte_count - (inner->guest_start - outer->guest_start) &&
        inner->host_start - outer->host_start <= outer->byte_count &&
        inner->byte_count <=
            outer->byte_count - (inner->host_start - outer->host_start);
}

static int rome2_100f2750_first_use_owner_is_empty(
    const rome2_100f1bb0_owned_owner *owner)
{
    return
        owner->token == UINT64_C(0) &&
        owner->raw_base.value == UINT32_C(0) &&
        owner->payload.value == UINT32_C(0) &&
        owner->allocation_bytes == UINT32_C(0) &&
        owner->length_units == UINT32_C(0) &&
        owner->phase == UINT32_C(0) &&
        owner->reserved == UINT32_C(0);
}

static int rome2_100f2750_first_use_lifecycle_is_empty(
    const rome2_100f2750_first_use_lifecycle *lifecycle)
{
    return
        lifecycle->phase ==
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_EMPTY &&
        lifecycle->reserved == UINT32_C(0);
}

static int rome2_100f2750_first_use_grant_is_zero(
    const rome2_100f1bb0_owned_grant *grant)
{
    return
        grant->token == UINT64_C(0) &&
        grant->raw_base.value == UINT32_C(0) &&
        grant->reserved == UINT32_C(0);
}

static void rome2_100f2750_first_use_compensate_grant(
    const rome2_100f2750_first_use_private *state)
{
    if (state->grant.token != UINT64_C(0)) {
        state->effects.release(
            state->effects.context,
            state->grant.token,
            state->grant.raw_base,
            state->allocation_bytes,
            ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS);
    }
}

static rome2_100f1bb0_owned_status
rome2_100f2750_first_use_validate_controls(
    rome2_100f2750_first_use_private *state,
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_guest_write_view *temporary_descriptor_view,
    const rome2_guest_write_view *temporary_heap_view,
    const rome2_guest_write_view *persistent_heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    const rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner_out,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_guest_addr32 *guest_return_out)
{
    state->controls[0].start =
        (uint64_t)(uintptr_t)persistent_descriptor_view;
    state->controls[0].byte_count = sizeof(*persistent_descriptor_view);
    state->controls[1].start =
        (uint64_t)(uintptr_t)temporary_descriptor_view;
    state->controls[1].byte_count = sizeof(*temporary_descriptor_view);
    state->controls[2].start = (uint64_t)(uintptr_t)temporary_heap_view;
    state->controls[2].byte_count = sizeof(*temporary_heap_view);
    state->controls[3].start = (uint64_t)(uintptr_t)persistent_heap_view;
    state->controls[3].byte_count = sizeof(*persistent_heap_view);
    state->controls[4].start = (uint64_t)(uintptr_t)effects;
    state->controls[4].byte_count = sizeof(*effects);
    state->controls[5].start = (uint64_t)(uintptr_t)temporary_owner;
    state->controls[5].byte_count = sizeof(*temporary_owner);
    state->controls[6].start = (uint64_t)(uintptr_t)persistent_owner_out;
    state->controls[6].byte_count = sizeof(*persistent_owner_out);
    state->controls[7].start = (uint64_t)(uintptr_t)lifecycle;
    state->controls[7].byte_count = sizeof(*lifecycle);
    state->controls[8].start = (uint64_t)(uintptr_t)guest_return_out;
    state->controls[8].byte_count = sizeof(*guest_return_out);
    state->private_spans[0].start = (uint64_t)(uintptr_t)state;
    state->private_spans[0].byte_count = sizeof(*state);

    if (rome2_100f2750_first_use_host_spans_overlap(
            state->controls,
            ROME2_100F2750_FIRST_USE_CONTROL_COUNT) ||
        rome2_100f2750_first_use_host_spans_overlap(
            state->private_spans,
            ROME2_100F2750_FIRST_USE_PRIVATE_COUNT) ||
        rome2_100f2750_first_use_span_sets_overlap(
            state->controls,
            ROME2_100F2750_FIRST_USE_CONTROL_COUNT,
            state->private_spans,
            ROME2_100F2750_FIRST_USE_PRIVATE_COUNT)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

static rome2_100f1bb0_owned_status
rome2_100f2750_first_use_validate_backings(
    rome2_100f2750_first_use_private *state)
{
    state->backings[0].start =
        (uint64_t)(uintptr_t)state->persistent_descriptor_view.host_base;
    state->backings[0].byte_count =
        state->persistent_descriptor_view.byte_count;
    state->backings[1].start =
        (uint64_t)(uintptr_t)state->temporary_descriptor_view.host_base;
    state->backings[1].byte_count =
        state->temporary_descriptor_view.byte_count;
    state->backings[2].start =
        (uint64_t)(uintptr_t)state->temporary_heap_view.host_base;
    state->backings[2].byte_count = state->temporary_heap_view.byte_count;
    state->backings[3].start =
        (uint64_t)(uintptr_t)state->persistent_heap_view.host_base;
    state->backings[3].byte_count = state->persistent_heap_view.byte_count;
    state->context.start = (uint64_t)(uintptr_t)state->effects.context;
    state->context.byte_count = state->effects.context_byte_count;

    if (rome2_100f2750_first_use_host_spans_overlap(
            state->backings,
            ROME2_100F2750_FIRST_USE_BACKING_COUNT) ||
        rome2_100f2750_first_use_span_sets_overlap(
            state->backings,
            ROME2_100F2750_FIRST_USE_BACKING_COUNT,
            state->controls,
            ROME2_100F2750_FIRST_USE_CONTROL_COUNT) ||
        rome2_100f2750_first_use_span_sets_overlap(
            state->backings,
            ROME2_100F2750_FIRST_USE_BACKING_COUNT,
            &state->context,
            1U) ||
        rome2_100f2750_first_use_span_sets_overlap(
            state->backings,
            ROME2_100F2750_FIRST_USE_BACKING_COUNT,
            state->private_spans,
            ROME2_100F2750_FIRST_USE_PRIVATE_COUNT) ||
        rome2_100f2750_first_use_span_sets_overlap(
            state->controls,
            ROME2_100F2750_FIRST_USE_CONTROL_COUNT,
            &state->context,
            1U) ||
        rome2_100f2750_first_use_span_sets_overlap(
            &state->context,
            1U,
            state->private_spans,
            ROME2_100F2750_FIRST_USE_PRIVATE_COUNT)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    if (rome2_100f2750_first_use_views_logically_overlap(
            state->persistent_descriptor_view.guest_base,
            state->persistent_descriptor_view.byte_count,
            state->temporary_descriptor_view.guest_base,
            state->temporary_descriptor_view.byte_count) ||
        rome2_100f2750_first_use_views_logically_overlap(
            state->persistent_descriptor_view.guest_base,
            state->persistent_descriptor_view.byte_count,
            state->temporary_heap_view.guest_base,
            state->temporary_heap_view.byte_count) ||
        rome2_100f2750_first_use_views_logically_overlap(
            state->persistent_descriptor_view.guest_base,
            state->persistent_descriptor_view.byte_count,
            state->persistent_heap_view.guest_base,
            state->persistent_heap_view.byte_count) ||
        rome2_100f2750_first_use_views_logically_overlap(
            state->temporary_descriptor_view.guest_base,
            state->temporary_descriptor_view.byte_count,
            state->temporary_heap_view.guest_base,
            state->temporary_heap_view.byte_count) ||
        rome2_100f2750_first_use_views_logically_overlap(
            state->temporary_descriptor_view.guest_base,
            state->temporary_descriptor_view.byte_count,
            state->persistent_heap_view.guest_base,
            state->persistent_heap_view.byte_count) ||
        rome2_100f2750_first_use_views_logically_overlap(
            state->temporary_heap_view.guest_base,
            state->temporary_heap_view.byte_count,
            state->persistent_heap_view.guest_base,
            state->persistent_heap_view.byte_count)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

static rome2_100f1bb0_owned_status
rome2_100f2750_first_use_authenticate_temporary(
    rome2_100f2750_first_use_private *state,
    rome2_guest_addr32 guest_temporary_descriptor)
{
    const uint8_t *descriptor_bytes;

    if (state->temporary_owner.phase !=
            ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||
        state->temporary_owner.token == UINT64_C(0) ||
        state->temporary_owner.raw_base.value == UINT32_C(0) ||
        state->temporary_owner.payload.value == UINT32_C(0) ||
        state->temporary_owner.reserved != UINT32_C(0) ||
        state->temporary_owner.length_units == UINT32_C(0) ||
        state->temporary_owner.length_units >=
            ROME2_PORT_100F1BB0_OWNED_MAX_UNITS) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    state->payload_bytes =
        state->temporary_owner.length_units *
        ROME2_100F2750_FIRST_USE_UNIT_BYTES;
    state->allocation_bytes =
        state->payload_bytes +
        ROME2_100F2750_FIRST_USE_ALLOCATION_OVERHEAD;
    state->expected_payload =
        ((uint64_t)state->temporary_owner.raw_base.value +
            ROME2_100F2750_FIRST_USE_PAYLOAD_BIAS) &
        ~UINT64_C(3);
    if (state->temporary_owner.allocation_bytes !=
            state->allocation_bytes ||
        state->expected_payload > UINT32_MAX ||
        state->temporary_owner.payload.value !=
            (uint32_t)state->expected_payload ||
        state->temporary_owner.payload.value <
            ROME2_100F2750_FIRST_USE_HEADER_BYTES) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    state->status = rome2_100f2750_first_use_resolve_span(
        state->temporary_descriptor_view.host_base,
        state->temporary_descriptor_view.guest_base,
        state->temporary_descriptor_view.byte_count,
        guest_temporary_descriptor,
        ROME2_100F2750_FIRST_USE_DESCRIPTOR_BYTES,
        &state->temporary_descriptor);
    if (state->status != ROME2_100F1BB0_OWNED_OK) {
        return state->status;
    }
    state->status = rome2_100f2750_first_use_resolve_span(
        state->temporary_heap_view.host_base,
        state->temporary_heap_view.guest_base,
        state->temporary_heap_view.byte_count,
        state->temporary_owner.raw_base,
        state->allocation_bytes,
        &state->temporary_allocation);
    if (state->status != ROME2_100F1BB0_OWNED_OK) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    state->temporary_header_identity.value =
        state->temporary_owner.payload.value -
        ROME2_100F2750_FIRST_USE_HEADER_BYTES;
    state->terminator_value =
        (uint64_t)state->temporary_owner.payload.value +
        (uint64_t)state->payload_bytes;
    if (state->terminator_value > UINT32_MAX) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }
    state->temporary_terminator_identity.value =
        (uint32_t)state->terminator_value;

    state->status = rome2_100f2750_first_use_resolve_span(
        state->temporary_heap_view.host_base,
        state->temporary_heap_view.guest_base,
        state->temporary_heap_view.byte_count,
        state->temporary_header_identity,
        ROME2_100F2750_FIRST_USE_HEADER_BYTES,
        &state->temporary_header);
    if (state->status == ROME2_100F1BB0_OWNED_OK) {
        state->status = rome2_100f2750_first_use_resolve_span(
            state->temporary_heap_view.host_base,
            state->temporary_heap_view.guest_base,
            state->temporary_heap_view.byte_count,
            state->temporary_owner.payload,
            state->payload_bytes,
            &state->temporary_payload);
    }
    if (state->status == ROME2_100F1BB0_OWNED_OK) {
        state->status = rome2_100f2750_first_use_resolve_span(
            state->temporary_heap_view.host_base,
            state->temporary_heap_view.guest_base,
            state->temporary_heap_view.byte_count,
            state->temporary_terminator_identity,
            ROME2_100F2750_FIRST_USE_UNIT_BYTES,
            &state->temporary_terminator);
    }
    if (state->status != ROME2_100F1BB0_OWNED_OK ||
        !rome2_100f2750_first_use_span_is_contained(
            &state->temporary_allocation,
            &state->temporary_header) ||
        !rome2_100f2750_first_use_span_is_contained(
            &state->temporary_allocation,
            &state->temporary_payload) ||
        !rome2_100f2750_first_use_span_is_contained(
            &state->temporary_allocation,
            &state->temporary_terminator)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    descriptor_bytes =
        state->temporary_descriptor_view.host_base +
        (size_t)state->temporary_descriptor.view_offset;
    if (rome2_100f2750_first_use_read_u32_le(descriptor_bytes) !=
            state->temporary_owner.length_units ||
        rome2_100f2750_first_use_read_u32_le(descriptor_bytes + 4U) !=
            state->temporary_owner.length_units ||
        rome2_100f2750_first_use_read_u32_le(descriptor_bytes + 8U) !=
            state->temporary_owner.payload.value ||
        rome2_100f2750_first_use_read_u32_le(
            state->temporary_heap_view.host_base +
                (size_t)state->temporary_header.view_offset) !=
            state->temporary_owner.raw_base.value ||
        state->temporary_heap_view.host_base[
            (size_t)state->temporary_terminator.view_offset] != UINT8_C(0) ||
        state->temporary_heap_view.host_base[
            (size_t)state->temporary_terminator.view_offset + 1U] !=
            UINT8_C(0)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

rome2_100f1bb0_owned_status rome2_port_100f2750_register_first_use_owned(
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle_out)
{
    rome2_100f2750_first_use_register_private state = {0};
    const uint8_t *descriptor_bytes;
    rome2_guest_addr32 descriptor_identity = {
        ROME2_PORT_100F2750_FIRST_USE_DESTINATION
    };

    state.status = rome2_100f2750_first_use_validate_object(
        persistent_descriptor_view, sizeof(*persistent_descriptor_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        persistent_owner, sizeof(*persistent_owner));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        lifecycle_out, sizeof(*lifecycle_out));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    if ((uintptr_t)persistent_descriptor_view %
            _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)persistent_owner %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)lifecycle_out %
            _Alignof(rome2_100f2750_first_use_lifecycle) != 0U) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.controls[0].start =
        (uint64_t)(uintptr_t)persistent_descriptor_view;
    state.controls[0].byte_count = sizeof(*persistent_descriptor_view);
    state.controls[1].start = (uint64_t)(uintptr_t)persistent_owner;
    state.controls[1].byte_count = sizeof(*persistent_owner);
    state.controls[2].start = (uint64_t)(uintptr_t)lifecycle_out;
    state.controls[2].byte_count = sizeof(*lifecycle_out);
    state.private_span.start = (uint64_t)(uintptr_t)&state;
    state.private_span.byte_count = sizeof(state);
    if (rome2_100f2750_first_use_host_spans_overlap(
            state.controls,
            ROME2_100F2750_FIRST_USE_REGISTER_CONTROL_COUNT) ||
        rome2_100f2750_first_use_span_sets_overlap(
            state.controls,
            ROME2_100F2750_FIRST_USE_REGISTER_CONTROL_COUNT,
            &state.private_span,
            1U)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.descriptor_view = *persistent_descriptor_view;
    state.owner = *persistent_owner;
    state.lifecycle = *lifecycle_out;
    state.status = rome2_100f2750_first_use_validate_view(
        state.descriptor_view.host_base,
        state.descriptor_view.guest_base,
        state.descriptor_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.backing.start =
        (uint64_t)(uintptr_t)state.descriptor_view.host_base;
    state.backing.byte_count = state.descriptor_view.byte_count;
    if (rome2_100f2750_first_use_span_sets_overlap(
            &state.backing,
            1U,
            state.controls,
            ROME2_100F2750_FIRST_USE_REGISTER_CONTROL_COUNT) ||
        rome2_100f2750_first_use_ranges_overlap(
            state.backing.start,
            state.backing.byte_count,
            state.private_span.start,
            state.private_span.byte_count)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (!rome2_100f2750_first_use_owner_is_empty(&state.owner) ||
        !rome2_100f2750_first_use_lifecycle_is_empty(&state.lifecycle)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    state.status = rome2_100f2750_first_use_resolve_span(
        state.descriptor_view.host_base,
        state.descriptor_view.guest_base,
        state.descriptor_view.byte_count,
        descriptor_identity,
        ROME2_100F2750_FIRST_USE_DESCRIPTOR_BYTES,
        &state.descriptor);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    descriptor_bytes =
        state.descriptor_view.host_base +
        (size_t)state.descriptor.view_offset;
    if (rome2_100f2750_first_use_read_u32_le(descriptor_bytes) !=
            UINT32_C(0) ||
        rome2_100f2750_first_use_read_u32_le(descriptor_bytes + 4U) !=
            UINT32_C(0) ||
        rome2_100f2750_first_use_read_u32_le(descriptor_bytes + 8U) !=
            ROME2_PORT_100F2750_FIRST_USE_SENTINEL) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    lifecycle_out->phase =
        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL;
    return ROME2_100F1BB0_OWNED_OK;
}

rome2_100f1bb0_owned_status rome2_port_100f2750_first_use_owned(
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_guest_write_view *temporary_descriptor_view,
    rome2_guest_addr32 guest_temporary_descriptor,
    const rome2_guest_write_view *temporary_heap_view,
    const rome2_guest_write_view *persistent_heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    const rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner_out,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_guest_addr32 *guest_return_out)
{
    rome2_100f2750_first_use_private state = {0};
    const uint8_t *persistent_descriptor_bytes;
    rome2_guest_addr32 persistent_descriptor_identity = {
        ROME2_PORT_100F2750_FIRST_USE_DESTINATION
    };

    state.status = rome2_100f2750_first_use_validate_object(
        persistent_descriptor_view, sizeof(*persistent_descriptor_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        temporary_descriptor_view, sizeof(*temporary_descriptor_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        temporary_heap_view, sizeof(*temporary_heap_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        persistent_heap_view, sizeof(*persistent_heap_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        effects, sizeof(*effects));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        temporary_owner, sizeof(*temporary_owner));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        persistent_owner_out, sizeof(*persistent_owner_out));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        lifecycle, sizeof(*lifecycle));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        guest_return_out, sizeof(*guest_return_out));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    if ((uintptr_t)persistent_descriptor_view %
            _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)temporary_descriptor_view %
            _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)temporary_heap_view %
            _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)persistent_heap_view %
            _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)effects %
            _Alignof(rome2_100f1bb0_owned_effects) != 0U ||
        (uintptr_t)temporary_owner %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)persistent_owner_out %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)lifecycle %
            _Alignof(rome2_100f2750_first_use_lifecycle) != 0U ||
        (uintptr_t)guest_return_out % _Alignof(rome2_guest_addr32) != 0U) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.status = rome2_100f2750_first_use_validate_controls(
        &state,
        persistent_descriptor_view,
        temporary_descriptor_view,
        temporary_heap_view,
        persistent_heap_view,
        effects,
        temporary_owner,
        persistent_owner_out,
        lifecycle,
        guest_return_out);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }

    state.persistent_descriptor_view = *persistent_descriptor_view;
    state.temporary_descriptor_view = *temporary_descriptor_view;
    state.temporary_heap_view = *temporary_heap_view;
    state.persistent_heap_view = *persistent_heap_view;
    state.effects = *effects;
    state.temporary_owner = *temporary_owner;
    state.persistent_owner_initial = *persistent_owner_out;
    state.lifecycle_initial = *lifecycle;

    state.status = rome2_100f2750_first_use_validate_view(
        state.persistent_descriptor_view.host_base,
        state.persistent_descriptor_view.guest_base,
        state.persistent_descriptor_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_view(
        state.temporary_descriptor_view.host_base,
        state.temporary_descriptor_view.guest_base,
        state.temporary_descriptor_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_view(
        state.temporary_heap_view.host_base,
        state.temporary_heap_view.guest_base,
        state.temporary_heap_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_view(
        state.persistent_heap_view.host_base,
        state.persistent_heap_view.guest_base,
        state.persistent_heap_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_host_interval(
        state.effects.context,
        state.effects.context_byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    if (state.effects.allocate == NULL || state.effects.release == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    state.status = rome2_100f2750_first_use_validate_backings(&state);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    if (!rome2_100f2750_first_use_owner_is_empty(
            &state.persistent_owner_initial)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }
    if (state.lifecycle_initial.phase !=
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL ||
        state.lifecycle_initial.reserved != UINT32_C(0)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }
    state.status = rome2_100f2750_first_use_resolve_span(
        state.persistent_descriptor_view.host_base,
        state.persistent_descriptor_view.guest_base,
        state.persistent_descriptor_view.byte_count,
        persistent_descriptor_identity,
        ROME2_100F2750_FIRST_USE_DESCRIPTOR_BYTES,
        &state.persistent_descriptor);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    persistent_descriptor_bytes =
        state.persistent_descriptor_view.host_base +
        (size_t)state.persistent_descriptor.view_offset;
    if (rome2_100f2750_first_use_read_u32_le(
            persistent_descriptor_bytes) != UINT32_C(0) ||
        rome2_100f2750_first_use_read_u32_le(
            persistent_descriptor_bytes + 4U) != UINT32_C(0) ||
        rome2_100f2750_first_use_read_u32_le(
            persistent_descriptor_bytes + 8U) !=
            ROME2_PORT_100F2750_FIRST_USE_SENTINEL) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    state.status = rome2_100f2750_first_use_authenticate_temporary(
        &state, guest_temporary_descriptor);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }

    state.persistent_available_bytes = state.persistent_heap_view.byte_count;
    if (state.persistent_heap_view.guest_base == UINT32_C(0)) {
        if (state.persistent_available_bytes == UINT64_C(0)) {
            return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
        }
        --state.persistent_available_bytes;
    }
    if (state.persistent_available_bytes <
        (uint64_t)state.allocation_bytes) {
        return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
    }

    state.grant_result = state.effects.allocate(
        state.effects.context,
        state.allocation_bytes,
        ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS,
        &state.grant);

    if (state.grant.token == state.temporary_owner.token) {
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }
    if (state.grant_result == ROME2_100F1BB0_OWNED_GRANT_DENIED) {
        if (rome2_100f2750_first_use_grant_is_zero(&state.grant)) {
            return ROME2_100F1BB0_OWNED_ALLOCATION_DENIED;
        }
        rome2_100f2750_first_use_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }
    if (state.grant_result != ROME2_100F1BB0_OWNED_GRANT_GRANTED ||
        state.grant.token == UINT64_C(0) ||
        state.grant.reserved != UINT32_C(0)) {
        rome2_100f2750_first_use_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }
    if (state.grant.raw_base.value == UINT32_C(0)) {
        rome2_100f2750_first_use_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID;
    }
    state.status = rome2_100f2750_first_use_resolve_span(
        state.persistent_heap_view.host_base,
        state.persistent_heap_view.guest_base,
        state.persistent_heap_view.byte_count,
        state.grant.raw_base,
        state.allocation_bytes,
        &state.persistent_allocation);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        rome2_100f2750_first_use_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID;
    }

    state.persistent_payload_value =
        ((uint64_t)state.grant.raw_base.value +
            ROME2_100F2750_FIRST_USE_PAYLOAD_BIAS) &
        ~UINT64_C(3);
    if (state.persistent_payload_value > UINT32_MAX ||
        state.persistent_payload_value <
            ROME2_100F2750_FIRST_USE_HEADER_BYTES) {
        rome2_100f2750_first_use_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID;
    }
    state.persistent_payload_identity.value =
        (uint32_t)state.persistent_payload_value;
    state.persistent_header_identity.value =
        state.persistent_payload_identity.value -
        ROME2_100F2750_FIRST_USE_HEADER_BYTES;
    state.persistent_terminator_value =
        state.persistent_payload_value + (uint64_t)state.payload_bytes;
    if (state.persistent_terminator_value > UINT32_MAX) {
        rome2_100f2750_first_use_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID;
    }
    state.persistent_terminator_identity.value =
        (uint32_t)state.persistent_terminator_value;

    state.status = rome2_100f2750_first_use_resolve_span(
        state.persistent_heap_view.host_base,
        state.persistent_heap_view.guest_base,
        state.persistent_heap_view.byte_count,
        state.persistent_header_identity,
        ROME2_100F2750_FIRST_USE_HEADER_BYTES,
        &state.persistent_header);
    if (state.status == ROME2_100F1BB0_OWNED_OK) {
        state.status = rome2_100f2750_first_use_resolve_span(
            state.persistent_heap_view.host_base,
            state.persistent_heap_view.guest_base,
            state.persistent_heap_view.byte_count,
            state.persistent_payload_identity,
            state.payload_bytes,
            &state.persistent_payload);
    }
    if (state.status == ROME2_100F1BB0_OWNED_OK) {
        state.status = rome2_100f2750_first_use_resolve_span(
            state.persistent_heap_view.host_base,
            state.persistent_heap_view.guest_base,
            state.persistent_heap_view.byte_count,
            state.persistent_terminator_identity,
            ROME2_100F2750_FIRST_USE_UNIT_BYTES,
            &state.persistent_terminator);
    }
    if (state.status != ROME2_100F1BB0_OWNED_OK ||
        !rome2_100f2750_first_use_span_is_contained(
            &state.persistent_allocation, &state.persistent_header) ||
        !rome2_100f2750_first_use_span_is_contained(
            &state.persistent_allocation, &state.persistent_payload) ||
        !rome2_100f2750_first_use_span_is_contained(
            &state.persistent_allocation, &state.persistent_terminator) ||
        rome2_100f2750_first_use_ranges_overlap(
            state.persistent_allocation.guest_start,
            state.persistent_allocation.byte_count,
            state.temporary_allocation.guest_start,
            state.temporary_allocation.byte_count) ||
        rome2_100f2750_first_use_ranges_overlap(
            state.persistent_allocation.host_start,
            state.persistent_allocation.byte_count,
            state.temporary_allocation.host_start,
            state.temporary_allocation.byte_count)) {
        rome2_100f2750_first_use_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID;
    }

    rome2_100f2750_first_use_write_u32_le(
        state.persistent_heap_view.host_base +
            (size_t)state.persistent_header.view_offset,
        state.grant.raw_base.value);
    for (state.copy_index = UINT32_C(0);
         state.copy_index < state.payload_bytes;
         ++state.copy_index) {
        state.persistent_heap_view.host_base[
            (size_t)state.persistent_payload.view_offset +
                state.copy_index] =
            state.temporary_heap_view.host_base[
                (size_t)state.temporary_payload.view_offset +
                    state.copy_index];
    }
    state.persistent_heap_view.host_base[
        (size_t)state.persistent_terminator.view_offset] = UINT8_C(0);
    state.persistent_heap_view.host_base[
        (size_t)state.persistent_terminator.view_offset + 1U] = UINT8_C(0);
    rome2_100f2750_first_use_write_u32_le(
        state.persistent_descriptor_view.host_base +
            (size_t)state.persistent_descriptor.view_offset,
        state.temporary_owner.length_units);
    rome2_100f2750_first_use_write_u32_le(
        state.persistent_descriptor_view.host_base +
            (size_t)state.persistent_descriptor.view_offset + 4U,
        state.temporary_owner.length_units);
    rome2_100f2750_first_use_write_u32_le(
        state.persistent_descriptor_view.host_base +
            (size_t)state.persistent_descriptor.view_offset + 8U,
        state.persistent_payload_identity.value);

    state.persistent_owner_commit.token = state.grant.token;
    state.persistent_owner_commit.raw_base = state.grant.raw_base;
    state.persistent_owner_commit.payload =
        state.persistent_payload_identity;
    state.persistent_owner_commit.allocation_bytes = state.allocation_bytes;
    state.persistent_owner_commit.length_units =
        state.temporary_owner.length_units;
    state.persistent_owner_commit.phase =
        ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE;
    state.persistent_owner_commit.reserved = UINT32_C(0);
    *persistent_owner_out = state.persistent_owner_commit;
    lifecycle->phase =
        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE;
    *guest_return_out = persistent_descriptor_identity;
    return ROME2_100F1BB0_OWNED_OK;
}

rome2_100f1bb0_owned_status
rome2_port_100f2750_teardown_first_use_owned(
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_guest_write_view *persistent_heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle)
{
    rome2_100f2750_first_use_teardown_private state = {0};
    const uint8_t *descriptor_bytes;
    rome2_guest_addr32 persistent_descriptor_identity = {
        ROME2_PORT_100F2750_FIRST_USE_DESTINATION
    };

    state.status = rome2_100f2750_first_use_validate_object(
        persistent_descriptor_view, sizeof(*persistent_descriptor_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        persistent_heap_view, sizeof(*persistent_heap_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        effects, sizeof(*effects));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        persistent_owner, sizeof(*persistent_owner));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_object(
        lifecycle, sizeof(*lifecycle));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    if ((uintptr_t)persistent_descriptor_view %
            _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)persistent_heap_view %
            _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)effects %
            _Alignof(rome2_100f1bb0_owned_effects) != 0U ||
        (uintptr_t)persistent_owner %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)lifecycle %
            _Alignof(rome2_100f2750_first_use_lifecycle) != 0U) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.controls[0].start =
        (uint64_t)(uintptr_t)persistent_descriptor_view;
    state.controls[0].byte_count = sizeof(*persistent_descriptor_view);
    state.controls[1].start = (uint64_t)(uintptr_t)persistent_heap_view;
    state.controls[1].byte_count = sizeof(*persistent_heap_view);
    state.controls[2].start = (uint64_t)(uintptr_t)effects;
    state.controls[2].byte_count = sizeof(*effects);
    state.controls[3].start = (uint64_t)(uintptr_t)persistent_owner;
    state.controls[3].byte_count = sizeof(*persistent_owner);
    state.controls[4].start = (uint64_t)(uintptr_t)lifecycle;
    state.controls[4].byte_count = sizeof(*lifecycle);
    state.private_span.start = (uint64_t)(uintptr_t)&state;
    state.private_span.byte_count = sizeof(state);
    if (rome2_100f2750_first_use_host_spans_overlap(
            state.controls,
            ROME2_100F2750_FIRST_USE_TEARDOWN_CONTROL_COUNT) ||
        rome2_100f2750_first_use_span_sets_overlap(
            state.controls,
            ROME2_100F2750_FIRST_USE_TEARDOWN_CONTROL_COUNT,
            &state.private_span,
            1U)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.descriptor_view = *persistent_descriptor_view;
    state.heap_view = *persistent_heap_view;
    state.effects = *effects;
    state.owner = *persistent_owner;
    state.lifecycle = *lifecycle;
    state.status = rome2_100f2750_first_use_validate_view(
        state.descriptor_view.host_base,
        state.descriptor_view.guest_base,
        state.descriptor_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_view(
        state.heap_view.host_base,
        state.heap_view.guest_base,
        state.heap_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f2750_first_use_validate_host_interval(
        state.effects.context,
        state.effects.context_byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    if (state.effects.release == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.backings[0].start =
        (uint64_t)(uintptr_t)state.descriptor_view.host_base;
    state.backings[0].byte_count = state.descriptor_view.byte_count;
    state.backings[1].start =
        (uint64_t)(uintptr_t)state.heap_view.host_base;
    state.backings[1].byte_count = state.heap_view.byte_count;
    state.context.start = (uint64_t)(uintptr_t)state.effects.context;
    state.context.byte_count = state.effects.context_byte_count;
    if (rome2_100f2750_first_use_host_spans_overlap(
            state.backings,
            ROME2_100F2750_FIRST_USE_TEARDOWN_BACKING_COUNT) ||
        rome2_100f2750_first_use_span_sets_overlap(
            state.backings,
            ROME2_100F2750_FIRST_USE_TEARDOWN_BACKING_COUNT,
            state.controls,
            ROME2_100F2750_FIRST_USE_TEARDOWN_CONTROL_COUNT) ||
        rome2_100f2750_first_use_span_sets_overlap(
            state.backings,
            ROME2_100F2750_FIRST_USE_TEARDOWN_BACKING_COUNT,
            &state.context,
            1U) ||
        rome2_100f2750_first_use_span_sets_overlap(
            state.backings,
            ROME2_100F2750_FIRST_USE_TEARDOWN_BACKING_COUNT,
            &state.private_span,
            1U) ||
        rome2_100f2750_first_use_span_sets_overlap(
            state.controls,
            ROME2_100F2750_FIRST_USE_TEARDOWN_CONTROL_COUNT,
            &state.context,
            1U) ||
        rome2_100f2750_first_use_ranges_overlap(
            state.context.start,
            state.context.byte_count,
            state.private_span.start,
            state.private_span.byte_count) ||
        rome2_100f2750_first_use_views_logically_overlap(
            state.descriptor_view.guest_base,
            state.descriptor_view.byte_count,
            state.heap_view.guest_base,
            state.heap_view.byte_count)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (state.lifecycle.reserved != UINT32_C(0)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }
    if (state.lifecycle.phase ==
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED) {
        return ROME2_100F1BB0_OWNED_ALREADY_CONSUMED;
    }

    state.status = rome2_100f2750_first_use_resolve_span(
        state.descriptor_view.host_base,
        state.descriptor_view.guest_base,
        state.descriptor_view.byte_count,
        persistent_descriptor_identity,
        ROME2_100F2750_FIRST_USE_DESCRIPTOR_BYTES,
        &state.descriptor);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    descriptor_bytes =
        state.descriptor_view.host_base +
        (size_t)state.descriptor.view_offset;

    if (state.lifecycle.phase ==
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL) {
        if (!rome2_100f2750_first_use_owner_is_empty(&state.owner) ||
            rome2_100f2750_first_use_read_u32_le(descriptor_bytes) !=
                UINT32_C(0) ||
            rome2_100f2750_first_use_read_u32_le(descriptor_bytes + 4U) !=
                UINT32_C(0) ||
            rome2_100f2750_first_use_read_u32_le(descriptor_bytes + 8U) !=
                ROME2_PORT_100F2750_FIRST_USE_SENTINEL) {
            return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
        }
        lifecycle->phase =
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED;
        return ROME2_100F1BB0_OWNED_OK;
    }
    if (state.lifecycle.phase !=
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE ||
        state.owner.phase != ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||
        state.owner.token == UINT64_C(0) ||
        state.owner.raw_base.value == UINT32_C(0) ||
        state.owner.payload.value == UINT32_C(0) ||
        state.owner.reserved != UINT32_C(0) ||
        state.owner.length_units == UINT32_C(0) ||
        state.owner.length_units >=
            ROME2_PORT_100F1BB0_OWNED_MAX_UNITS) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    state.expected_payload_bytes =
        state.owner.length_units * ROME2_100F2750_FIRST_USE_UNIT_BYTES;
    state.expected_allocation_bytes =
        state.expected_payload_bytes +
        ROME2_100F2750_FIRST_USE_ALLOCATION_OVERHEAD;
    state.expected_payload =
        ((uint64_t)state.owner.raw_base.value +
            ROME2_100F2750_FIRST_USE_PAYLOAD_BIAS) &
        ~UINT64_C(3);
    if (state.owner.allocation_bytes != state.expected_allocation_bytes ||
        state.expected_payload > UINT32_MAX ||
        state.owner.payload.value != (uint32_t)state.expected_payload ||
        state.owner.payload.value < ROME2_100F2750_FIRST_USE_HEADER_BYTES) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }
    state.status = rome2_100f2750_first_use_resolve_span(
        state.heap_view.host_base,
        state.heap_view.guest_base,
        state.heap_view.byte_count,
        state.owner.raw_base,
        state.expected_allocation_bytes,
        &state.allocation);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }
    state.header_identity.value =
        state.owner.payload.value - ROME2_100F2750_FIRST_USE_HEADER_BYTES;
    state.terminator_value =
        (uint64_t)state.owner.payload.value +
        (uint64_t)state.expected_payload_bytes;
    if (state.terminator_value > UINT32_MAX) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }
    state.terminator_identity.value = (uint32_t)state.terminator_value;
    state.status = rome2_100f2750_first_use_resolve_span(
        state.heap_view.host_base,
        state.heap_view.guest_base,
        state.heap_view.byte_count,
        state.header_identity,
        ROME2_100F2750_FIRST_USE_HEADER_BYTES,
        &state.header);
    if (state.status == ROME2_100F1BB0_OWNED_OK) {
        state.status = rome2_100f2750_first_use_resolve_span(
            state.heap_view.host_base,
            state.heap_view.guest_base,
            state.heap_view.byte_count,
            state.terminator_identity,
            ROME2_100F2750_FIRST_USE_UNIT_BYTES,
            &state.terminator);
    }
    if (state.status != ROME2_100F1BB0_OWNED_OK ||
        !rome2_100f2750_first_use_span_is_contained(
            &state.allocation, &state.header) ||
        !rome2_100f2750_first_use_span_is_contained(
            &state.allocation, &state.terminator) ||
        rome2_100f2750_first_use_read_u32_le(descriptor_bytes) !=
            state.owner.length_units ||
        rome2_100f2750_first_use_read_u32_le(descriptor_bytes + 4U) !=
            state.owner.length_units ||
        rome2_100f2750_first_use_read_u32_le(descriptor_bytes + 8U) !=
            state.owner.payload.value ||
        rome2_100f2750_first_use_read_u32_le(
            state.heap_view.host_base +
                (size_t)state.header.view_offset) !=
            state.owner.raw_base.value ||
        state.heap_view.host_base[
            (size_t)state.terminator.view_offset] != UINT8_C(0) ||
        state.heap_view.host_base[
            (size_t)state.terminator.view_offset + 1U] != UINT8_C(0)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    lifecycle->phase =
        ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED;
    state.status = rome2_port_100f1cc0_cleanup_owned_utf16(
        &state.descriptor_view,
        persistent_descriptor_identity,
        &state.heap_view,
        &state.effects,
        persistent_owner);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        lifecycle->phase =
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE;
    }
    return state.status;
}

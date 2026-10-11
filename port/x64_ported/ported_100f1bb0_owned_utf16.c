#include "ported_100f1bb0_owned_utf16.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define ROME2_100F1BB0_OWNED_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100F1BB0_OWNED_DESCRIPTOR_BYTES UINT32_C(12)
#define ROME2_100F1BB0_OWNED_HEADER_BYTES UINT32_C(4)
#define ROME2_100F1BB0_OWNED_UNIT_BYTES UINT32_C(2)
#define ROME2_100F1BB0_OWNED_ALLOCATION_OVERHEAD UINT32_C(10)
#define ROME2_100F1BB0_OWNED_PAYLOAD_BIAS UINT32_C(8)
#define ROME2_100F1BB0_OWNED_BUILD_CONTROL_COUNT 6U
#define ROME2_100F1BB0_OWNED_BUILD_BACKING_COUNT 3U
#define ROME2_100F1BB0_OWNED_CLEANUP_CONTROL_COUNT 4U
#define ROME2_100F1BB0_OWNED_CLEANUP_BACKING_COUNT 2U

typedef struct rome2_100f1bb0_owned_host_span {
    uint64_t start;
    uint64_t byte_count;
} rome2_100f1bb0_owned_host_span;

typedef struct rome2_100f1bb0_owned_span {
    uint64_t guest_start;
    uint64_t host_start;
    uint64_t byte_count;
    uint64_t view_offset;
} rome2_100f1bb0_owned_span;

typedef struct rome2_100f1bb0_owned_build_private {
    rome2_guest_write_view descriptor_view;
    rome2_guest_read_view text_view;
    rome2_guest_write_view heap_view;
    rome2_100f1bb0_owned_effects effects;
    rome2_100f1bb0_owned_owner owner_initial;
    rome2_100f1bb0_owned_owner owner_commit;
    rome2_100f1bb0_owned_grant grant;
    rome2_100f1bb0_owned_grant_result grant_result;
    rome2_100f1bb0_owned_host_span
        controls[ROME2_100F1BB0_OWNED_BUILD_CONTROL_COUNT];
    rome2_100f1bb0_owned_host_span
        backings[ROME2_100F1BB0_OWNED_BUILD_BACKING_COUNT];
    rome2_100f1bb0_owned_host_span context;
    rome2_100f1bb0_owned_host_span private_span;
    rome2_100f1bb0_owned_span descriptor;
    rome2_100f1bb0_owned_span source;
    rome2_100f1bb0_owned_span allocation;
    rome2_100f1bb0_owned_span header;
    rome2_100f1bb0_owned_span payload;
    rome2_100f1bb0_owned_span terminator;
    rome2_guest_addr32 payload_identity;
    rome2_guest_addr32 header_identity;
    rome2_guest_addr32 terminator_identity;
    rome2_100f1bb0_owned_status status;
    uint64_t payload_value;
    uint64_t terminator_value;
    uint64_t heap_available_bytes;
    uint32_t length_units;
    uint32_t allocation_bytes;
    uint32_t payload_bytes;
    uint32_t copy_index;
} rome2_100f1bb0_owned_build_private;

typedef struct rome2_100f1bb0_owned_cleanup_private {
    rome2_guest_write_view descriptor_view;
    rome2_guest_write_view heap_view;
    rome2_100f1bb0_owned_effects effects;
    rome2_100f1bb0_owned_owner owner;
    rome2_100f1bb0_owned_host_span
        controls[ROME2_100F1BB0_OWNED_CLEANUP_CONTROL_COUNT];
    rome2_100f1bb0_owned_host_span
        backings[ROME2_100F1BB0_OWNED_CLEANUP_BACKING_COUNT];
    rome2_100f1bb0_owned_host_span context;
    rome2_100f1bb0_owned_host_span private_span;
    rome2_100f1bb0_owned_span descriptor;
    rome2_100f1bb0_owned_span allocation;
    rome2_100f1bb0_owned_span header;
    rome2_100f1bb0_owned_span terminator;
    rome2_guest_addr32 header_identity;
    rome2_guest_addr32 terminator_identity;
    rome2_100f1bb0_owned_status status;
    uint64_t expected_payload;
    uint64_t terminator_value;
    const uint8_t *descriptor_bytes;
    uint32_t expected_allocation_bytes;
    uint32_t expected_payload_bytes;
} rome2_100f1bb0_owned_cleanup_private;

static uint32_t rome2_100f1bb0_owned_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100f1bb0_owned_write_u32_le(
    uint8_t *bytes,
    uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static int rome2_100f1bb0_owned_ranges_overlap(
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

static rome2_100f1bb0_owned_status rome2_100f1bb0_owned_validate_object(
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

static rome2_100f1bb0_owned_status rome2_100f1bb0_owned_validate_view(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100F1BB0_OWNED_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100F1BB0_OWNED_ADDRESS_SPACE_SIZE) {
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
rome2_100f1bb0_owned_validate_host_interval(
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

static rome2_100f1bb0_owned_status rome2_100f1bb0_owned_resolve_span(
    const void *host_base,
    uint32_t guest_base,
    uint64_t view_byte_count,
    rome2_guest_addr32 guest_start,
    uint32_t span_byte_count,
    rome2_100f1bb0_owned_span *span_out)
{
    uint64_t offset;

    if (span_out == NULL || span_byte_count == 0) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (guest_start.value == 0) {
        return ROME2_100F1BB0_OWNED_NULL_ADDRESS;
    }
    if ((uint64_t)span_byte_count >
        ROME2_100F1BB0_OWNED_ADDRESS_SPACE_SIZE -
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
    span_out->host_start =
        (uint64_t)(uintptr_t)host_base + offset;
    span_out->byte_count = (uint64_t)span_byte_count;
    span_out->view_offset = offset;
    return ROME2_100F1BB0_OWNED_OK;
}

static int rome2_100f1bb0_owned_host_spans_overlap(
    const rome2_100f1bb0_owned_host_span *spans,
    size_t span_count)
{
    size_t first;
    size_t second;

    for (first = 0; first < span_count; ++first) {
        for (second = first + 1U; second < span_count; ++second) {
            if (rome2_100f1bb0_owned_ranges_overlap(
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

static int rome2_100f1bb0_owned_span_sets_overlap(
    const rome2_100f1bb0_owned_host_span *first,
    size_t first_count,
    const rome2_100f1bb0_owned_host_span *second,
    size_t second_count)
{
    size_t first_index;
    size_t second_index;

    for (first_index = 0; first_index < first_count; ++first_index) {
        for (second_index = 0; second_index < second_count; ++second_index) {
            if (rome2_100f1bb0_owned_ranges_overlap(
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

static int rome2_100f1bb0_owned_views_logically_overlap(
    uint32_t first_base,
    uint64_t first_size,
    uint32_t second_base,
    uint64_t second_size)
{
    return rome2_100f1bb0_owned_ranges_overlap(
        (uint64_t)first_base,
        first_size,
        (uint64_t)second_base,
        second_size);
}

static int rome2_100f1bb0_owned_span_is_contained(
    const rome2_100f1bb0_owned_span *outer,
    const rome2_100f1bb0_owned_span *inner)
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

static int rome2_100f1bb0_owned_owner_is_empty(
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

static int rome2_100f1bb0_owned_grant_is_zero(
    const rome2_100f1bb0_owned_grant *grant)
{
    return
        grant->token == UINT64_C(0) &&
        grant->raw_base.value == UINT32_C(0) &&
        grant->reserved == UINT32_C(0);
}

static rome2_100f1bb0_owned_status
rome2_100f1bb0_owned_scan_nonempty_text(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 guest_text,
    uint32_t max_units,
    uint32_t *length_out,
    rome2_100f1bb0_owned_span *source_out)
{
    uint64_t guest_unit;
    uint64_t offset;
    uint16_t unit;
    uint32_t index;
    uint32_t source_bytes;

    if (max_units < UINT32_C(2) ||
        max_units > ROME2_PORT_100F1BB0_OWNED_MAX_UNITS ||
        length_out == NULL || source_out == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (guest_text.value == 0) {
        return ROME2_100F1BB0_OWNED_NULL_ADDRESS;
    }

    for (index = 0; index < max_units; ++index) {
        guest_unit =
            (uint64_t)guest_text.value +
            (uint64_t)index * ROME2_100F1BB0_OWNED_UNIT_BYTES;
        if (guest_unit > UINT32_MAX - UINT32_C(1)) {
            return ROME2_100F1BB0_OWNED_RANGE_OVERFLOW;
        }
        if (guest_unit < (uint64_t)view->guest_base) {
            return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
        }
        offset = guest_unit - (uint64_t)view->guest_base;
        if (offset > view->byte_count ||
            ROME2_100F1BB0_OWNED_UNIT_BYTES > view->byte_count - offset ||
            offset > (uint64_t)SIZE_MAX) {
            return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
        }
        unit = (uint16_t)(
            (uint16_t)view->host_base[(size_t)offset] |
            ((uint16_t)view->host_base[(size_t)offset + 1U] << 8));
        if (unit == 0) {
            if (index == 0) {
                return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
            }
            source_bytes =
                (index + UINT32_C(1)) *
                ROME2_100F1BB0_OWNED_UNIT_BYTES;
            *length_out = index;
            return rome2_100f1bb0_owned_resolve_span(
                view->host_base,
                view->guest_base,
                view->byte_count,
                guest_text,
                source_bytes,
                source_out);
        }
    }
    return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
}

static void rome2_100f1bb0_owned_compensate_grant(
    const rome2_100f1bb0_owned_build_private *state)
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
rome2_100f1bb0_owned_validate_build_controls(
    rome2_100f1bb0_owned_build_private *state,
    const rome2_guest_write_view *descriptor_view,
    const rome2_guest_read_view *text_view,
    const rome2_guest_write_view *heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    rome2_100f1bb0_owned_owner *owner_out,
    rome2_guest_addr32 *guest_return_out)
{
    state->controls[0].start = (uint64_t)(uintptr_t)descriptor_view;
    state->controls[0].byte_count = sizeof(*descriptor_view);
    state->controls[1].start = (uint64_t)(uintptr_t)text_view;
    state->controls[1].byte_count = sizeof(*text_view);
    state->controls[2].start = (uint64_t)(uintptr_t)heap_view;
    state->controls[2].byte_count = sizeof(*heap_view);
    state->controls[3].start = (uint64_t)(uintptr_t)effects;
    state->controls[3].byte_count = sizeof(*effects);
    state->controls[4].start = (uint64_t)(uintptr_t)owner_out;
    state->controls[4].byte_count = sizeof(*owner_out);
    state->controls[5].start = (uint64_t)(uintptr_t)guest_return_out;
    state->controls[5].byte_count = sizeof(*guest_return_out);
    state->private_span.start = (uint64_t)(uintptr_t)state;
    state->private_span.byte_count = sizeof(*state);

    if (rome2_100f1bb0_owned_host_spans_overlap(
            state->controls,
            ROME2_100F1BB0_OWNED_BUILD_CONTROL_COUNT) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->controls,
            ROME2_100F1BB0_OWNED_BUILD_CONTROL_COUNT,
            &state->private_span,
            1U)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

static rome2_100f1bb0_owned_status
rome2_100f1bb0_owned_validate_build_backings(
    rome2_100f1bb0_owned_build_private *state)
{
    state->backings[0].start =
        (uint64_t)(uintptr_t)state->descriptor_view.host_base;
    state->backings[0].byte_count = state->descriptor_view.byte_count;
    state->backings[1].start =
        (uint64_t)(uintptr_t)state->text_view.host_base;
    state->backings[1].byte_count = state->text_view.byte_count;
    state->backings[2].start =
        (uint64_t)(uintptr_t)state->heap_view.host_base;
    state->backings[2].byte_count = state->heap_view.byte_count;
    state->context.start = (uint64_t)(uintptr_t)state->effects.context;
    state->context.byte_count = state->effects.context_byte_count;

    if (rome2_100f1bb0_owned_host_spans_overlap(
            state->backings,
            ROME2_100F1BB0_OWNED_BUILD_BACKING_COUNT) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->backings,
            ROME2_100F1BB0_OWNED_BUILD_BACKING_COUNT,
            state->controls,
            ROME2_100F1BB0_OWNED_BUILD_CONTROL_COUNT) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->backings,
            ROME2_100F1BB0_OWNED_BUILD_BACKING_COUNT,
            &state->context,
            1U) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->backings,
            ROME2_100F1BB0_OWNED_BUILD_BACKING_COUNT,
            &state->private_span,
            1U) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->controls,
            ROME2_100F1BB0_OWNED_BUILD_CONTROL_COUNT,
            &state->context,
            1U) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->controls,
            ROME2_100F1BB0_OWNED_BUILD_CONTROL_COUNT,
            &state->private_span,
            1U) ||
        rome2_100f1bb0_owned_ranges_overlap(
            state->context.start,
            state->context.byte_count,
            state->private_span.start,
            state->private_span.byte_count)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    if (rome2_100f1bb0_owned_views_logically_overlap(
            state->descriptor_view.guest_base,
            state->descriptor_view.byte_count,
            state->text_view.guest_base,
            state->text_view.byte_count) ||
        rome2_100f1bb0_owned_views_logically_overlap(
            state->descriptor_view.guest_base,
            state->descriptor_view.byte_count,
            state->heap_view.guest_base,
            state->heap_view.byte_count) ||
        rome2_100f1bb0_owned_views_logically_overlap(
            state->text_view.guest_base,
            state->text_view.byte_count,
            state->heap_view.guest_base,
            state->heap_view.byte_count)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

rome2_100f1bb0_owned_status rome2_port_100f1bb0_build_owned_utf16(
    const rome2_guest_write_view *descriptor_view,
    rome2_guest_addr32 guest_descriptor,
    const rome2_guest_read_view *text_view,
    rome2_guest_addr32 guest_text,
    uint32_t max_units,
    const rome2_guest_write_view *heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    rome2_100f1bb0_owned_owner *owner_out,
    rome2_guest_addr32 *guest_return_out)
{
    rome2_100f1bb0_owned_build_private state = {0};

    state.status = rome2_100f1bb0_owned_validate_object(
        descriptor_view, sizeof(*descriptor_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_object(
        text_view, sizeof(*text_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_object(
        heap_view, sizeof(*heap_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_object(
        effects, sizeof(*effects));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_object(
        owner_out, sizeof(*owner_out));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_object(
        guest_return_out, sizeof(*guest_return_out));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    if ((uintptr_t)descriptor_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)text_view % _Alignof(rome2_guest_read_view) != 0U ||
        (uintptr_t)heap_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)effects % _Alignof(rome2_100f1bb0_owned_effects) != 0U ||
        (uintptr_t)owner_out %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)guest_return_out % _Alignof(rome2_guest_addr32) != 0U) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.status = rome2_100f1bb0_owned_validate_build_controls(
        &state,
        descriptor_view,
        text_view,
        heap_view,
        effects,
        owner_out,
        guest_return_out);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }

    state.descriptor_view = *descriptor_view;
    state.text_view = *text_view;
    state.heap_view = *heap_view;
    state.effects = *effects;
    state.owner_initial = *owner_out;

    state.status = rome2_100f1bb0_owned_validate_view(
        state.descriptor_view.host_base,
        state.descriptor_view.guest_base,
        state.descriptor_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_view(
        state.text_view.host_base,
        state.text_view.guest_base,
        state.text_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_view(
        state.heap_view.host_base,
        state.heap_view.guest_base,
        state.heap_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_host_interval(
        state.effects.context,
        state.effects.context_byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    if (state.effects.allocate == NULL || state.effects.release == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (!rome2_100f1bb0_owned_owner_is_empty(&state.owner_initial)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    state.status = rome2_100f1bb0_owned_validate_build_backings(&state);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_resolve_span(
        state.descriptor_view.host_base,
        state.descriptor_view.guest_base,
        state.descriptor_view.byte_count,
        guest_descriptor,
        ROME2_100F1BB0_OWNED_DESCRIPTOR_BYTES,
        &state.descriptor);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_scan_nonempty_text(
        &state.text_view,
        guest_text,
        max_units,
        &state.length_units,
        &state.source);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.payload_bytes =
        state.length_units * ROME2_100F1BB0_OWNED_UNIT_BYTES;
    state.allocation_bytes =
        state.payload_bytes + ROME2_100F1BB0_OWNED_ALLOCATION_OVERHEAD;
    state.heap_available_bytes = state.heap_view.byte_count;
    if (state.heap_view.guest_base == UINT32_C(0)) {
        if (state.heap_available_bytes == UINT64_C(0)) {
            return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
        }
        --state.heap_available_bytes;
    }
    if (state.heap_available_bytes < (uint64_t)state.allocation_bytes) {
        return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
    }

    state.grant_result = state.effects.allocate(
        state.effects.context,
        state.allocation_bytes,
        ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS,
        &state.grant);

    if (state.grant_result == ROME2_100F1BB0_OWNED_GRANT_DENIED) {
        if (rome2_100f1bb0_owned_grant_is_zero(&state.grant)) {
            return ROME2_100F1BB0_OWNED_ALLOCATION_DENIED;
        }
        rome2_100f1bb0_owned_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }
    if (state.grant_result != ROME2_100F1BB0_OWNED_GRANT_GRANTED ||
        state.grant.token == UINT64_C(0) || state.grant.reserved != 0) {
        rome2_100f1bb0_owned_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }
    if (state.grant.raw_base.value == 0) {
        rome2_100f1bb0_owned_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID;
    }
    state.status = rome2_100f1bb0_owned_resolve_span(
        state.heap_view.host_base,
        state.heap_view.guest_base,
        state.heap_view.byte_count,
        state.grant.raw_base,
        state.allocation_bytes,
        &state.allocation);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        rome2_100f1bb0_owned_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID;
    }

    state.payload_value =
        ((uint64_t)state.grant.raw_base.value +
            ROME2_100F1BB0_OWNED_PAYLOAD_BIAS) &
        ~UINT64_C(3);
    if (state.payload_value > UINT32_MAX ||
        state.payload_value < ROME2_100F1BB0_OWNED_HEADER_BYTES) {
        rome2_100f1bb0_owned_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID;
    }
    state.payload_identity.value = (uint32_t)state.payload_value;
    state.header_identity.value =
        state.payload_identity.value - ROME2_100F1BB0_OWNED_HEADER_BYTES;
    state.terminator_value =
        state.payload_value + (uint64_t)state.payload_bytes;
    if (state.terminator_value > UINT32_MAX) {
        rome2_100f1bb0_owned_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID;
    }
    state.terminator_identity.value = (uint32_t)state.terminator_value;

    state.status = rome2_100f1bb0_owned_resolve_span(
        state.heap_view.host_base,
        state.heap_view.guest_base,
        state.heap_view.byte_count,
        state.header_identity,
        ROME2_100F1BB0_OWNED_HEADER_BYTES,
        &state.header);
    if (state.status == ROME2_100F1BB0_OWNED_OK) {
        state.status = rome2_100f1bb0_owned_resolve_span(
            state.heap_view.host_base,
            state.heap_view.guest_base,
            state.heap_view.byte_count,
            state.payload_identity,
            state.payload_bytes,
            &state.payload);
    }
    if (state.status == ROME2_100F1BB0_OWNED_OK) {
        state.status = rome2_100f1bb0_owned_resolve_span(
            state.heap_view.host_base,
            state.heap_view.guest_base,
            state.heap_view.byte_count,
            state.terminator_identity,
            ROME2_100F1BB0_OWNED_UNIT_BYTES,
            &state.terminator);
    }
    if (state.status != ROME2_100F1BB0_OWNED_OK ||
        !rome2_100f1bb0_owned_span_is_contained(
            &state.allocation, &state.header) ||
        !rome2_100f1bb0_owned_span_is_contained(
            &state.allocation, &state.payload) ||
        !rome2_100f1bb0_owned_span_is_contained(
            &state.allocation, &state.terminator)) {
        rome2_100f1bb0_owned_compensate_grant(&state);
        return ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID;
    }

    rome2_100f1bb0_owned_write_u32_le(
        state.heap_view.host_base + (size_t)state.header.view_offset,
        state.grant.raw_base.value);
    for (state.copy_index = 0;
         state.copy_index < state.payload_bytes;
         ++state.copy_index) {
        state.heap_view.host_base[
            (size_t)state.payload.view_offset + state.copy_index] =
            state.text_view.host_base[
                (size_t)state.source.view_offset + state.copy_index];
    }
    state.heap_view.host_base[(size_t)state.terminator.view_offset] =
        UINT8_C(0);
    state.heap_view.host_base[(size_t)state.terminator.view_offset + 1U] =
        UINT8_C(0);
    rome2_100f1bb0_owned_write_u32_le(
        state.descriptor_view.host_base +
            (size_t)state.descriptor.view_offset,
        state.length_units);
    rome2_100f1bb0_owned_write_u32_le(
        state.descriptor_view.host_base +
            (size_t)state.descriptor.view_offset + 4U,
        state.length_units);
    rome2_100f1bb0_owned_write_u32_le(
        state.descriptor_view.host_base +
            (size_t)state.descriptor.view_offset + 8U,
        state.payload_identity.value);

    state.owner_commit.token = state.grant.token;
    state.owner_commit.raw_base = state.grant.raw_base;
    state.owner_commit.payload = state.payload_identity;
    state.owner_commit.allocation_bytes = state.allocation_bytes;
    state.owner_commit.length_units = state.length_units;
    state.owner_commit.phase = ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE;
    state.owner_commit.reserved = UINT32_C(0);
    *owner_out = state.owner_commit;
    *guest_return_out = guest_descriptor;
    return ROME2_100F1BB0_OWNED_OK;
}

static rome2_100f1bb0_owned_status
rome2_100f1bb0_owned_validate_cleanup_controls(
    rome2_100f1bb0_owned_cleanup_private *state,
    const rome2_guest_write_view *descriptor_view,
    const rome2_guest_write_view *heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    rome2_100f1bb0_owned_owner *owner)
{
    state->controls[0].start = (uint64_t)(uintptr_t)descriptor_view;
    state->controls[0].byte_count = sizeof(*descriptor_view);
    state->controls[1].start = (uint64_t)(uintptr_t)heap_view;
    state->controls[1].byte_count = sizeof(*heap_view);
    state->controls[2].start = (uint64_t)(uintptr_t)effects;
    state->controls[2].byte_count = sizeof(*effects);
    state->controls[3].start = (uint64_t)(uintptr_t)owner;
    state->controls[3].byte_count = sizeof(*owner);
    state->private_span.start = (uint64_t)(uintptr_t)state;
    state->private_span.byte_count = sizeof(*state);

    if (rome2_100f1bb0_owned_host_spans_overlap(
            state->controls,
            ROME2_100F1BB0_OWNED_CLEANUP_CONTROL_COUNT) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->controls,
            ROME2_100F1BB0_OWNED_CLEANUP_CONTROL_COUNT,
            &state->private_span,
            1U)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

static rome2_100f1bb0_owned_status
rome2_100f1bb0_owned_validate_cleanup_backings(
    rome2_100f1bb0_owned_cleanup_private *state)
{
    state->backings[0].start =
        (uint64_t)(uintptr_t)state->descriptor_view.host_base;
    state->backings[0].byte_count = state->descriptor_view.byte_count;
    state->backings[1].start =
        (uint64_t)(uintptr_t)state->heap_view.host_base;
    state->backings[1].byte_count = state->heap_view.byte_count;
    state->context.start = (uint64_t)(uintptr_t)state->effects.context;
    state->context.byte_count = state->effects.context_byte_count;

    if (rome2_100f1bb0_owned_host_spans_overlap(
            state->backings,
            ROME2_100F1BB0_OWNED_CLEANUP_BACKING_COUNT) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->backings,
            ROME2_100F1BB0_OWNED_CLEANUP_BACKING_COUNT,
            state->controls,
            ROME2_100F1BB0_OWNED_CLEANUP_CONTROL_COUNT) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->backings,
            ROME2_100F1BB0_OWNED_CLEANUP_BACKING_COUNT,
            &state->context,
            1U) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->backings,
            ROME2_100F1BB0_OWNED_CLEANUP_BACKING_COUNT,
            &state->private_span,
            1U) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->controls,
            ROME2_100F1BB0_OWNED_CLEANUP_CONTROL_COUNT,
            &state->context,
            1U) ||
        rome2_100f1bb0_owned_span_sets_overlap(
            state->controls,
            ROME2_100F1BB0_OWNED_CLEANUP_CONTROL_COUNT,
            &state->private_span,
            1U) ||
        rome2_100f1bb0_owned_ranges_overlap(
            state->context.start,
            state->context.byte_count,
            state->private_span.start,
            state->private_span.byte_count)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (rome2_100f1bb0_owned_views_logically_overlap(
            state->descriptor_view.guest_base,
            state->descriptor_view.byte_count,
            state->heap_view.guest_base,
            state->heap_view.byte_count)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

rome2_100f1bb0_owned_status rome2_port_100f1cc0_cleanup_owned_utf16(
    const rome2_guest_write_view *descriptor_view,
    rome2_guest_addr32 guest_descriptor,
    const rome2_guest_write_view *heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    rome2_100f1bb0_owned_owner *owner)
{
    rome2_100f1bb0_owned_cleanup_private state = {0};

    state.status = rome2_100f1bb0_owned_validate_object(
        descriptor_view, sizeof(*descriptor_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_object(
        heap_view, sizeof(*heap_view));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_object(
        effects, sizeof(*effects));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_object(
        owner, sizeof(*owner));
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    if ((uintptr_t)descriptor_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)heap_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)effects % _Alignof(rome2_100f1bb0_owned_effects) != 0U ||
        (uintptr_t)owner % _Alignof(rome2_100f1bb0_owned_owner) != 0U) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.status = rome2_100f1bb0_owned_validate_cleanup_controls(
        &state, descriptor_view, heap_view, effects, owner);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.descriptor_view = *descriptor_view;
    state.heap_view = *heap_view;
    state.effects = *effects;
    state.owner = *owner;

    state.status = rome2_100f1bb0_owned_validate_view(
        state.descriptor_view.host_base,
        state.descriptor_view.guest_base,
        state.descriptor_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_view(
        state.heap_view.host_base,
        state.heap_view.guest_base,
        state.heap_view.byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_validate_host_interval(
        state.effects.context,
        state.effects.context_byte_count);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    if (state.effects.release == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    state.status = rome2_100f1bb0_owned_validate_cleanup_backings(&state);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }

    if (state.owner.phase == ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED) {
        return ROME2_100F1BB0_OWNED_ALREADY_CONSUMED;
    }
    if (state.owner.phase != ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||
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
        state.owner.length_units * ROME2_100F1BB0_OWNED_UNIT_BYTES;
    state.expected_allocation_bytes =
        state.expected_payload_bytes +
        ROME2_100F1BB0_OWNED_ALLOCATION_OVERHEAD;
    state.expected_payload =
        ((uint64_t)state.owner.raw_base.value +
            ROME2_100F1BB0_OWNED_PAYLOAD_BIAS) &
        ~UINT64_C(3);
    if (state.owner.allocation_bytes != state.expected_allocation_bytes ||
        state.expected_payload > UINT32_MAX ||
        state.owner.payload.value != (uint32_t)state.expected_payload ||
        state.owner.payload.value < ROME2_100F1BB0_OWNED_HEADER_BYTES) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    state.status = rome2_100f1bb0_owned_resolve_span(
        state.descriptor_view.host_base,
        state.descriptor_view.guest_base,
        state.descriptor_view.byte_count,
        guest_descriptor,
        ROME2_100F1BB0_OWNED_DESCRIPTOR_BYTES,
        &state.descriptor);
    if (state.status != ROME2_100F1BB0_OWNED_OK) {
        return state.status;
    }
    state.status = rome2_100f1bb0_owned_resolve_span(
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
        state.owner.payload.value - ROME2_100F1BB0_OWNED_HEADER_BYTES;
    state.terminator_value =
        (uint64_t)state.owner.payload.value +
        (uint64_t)state.expected_payload_bytes;
    if (state.terminator_value > UINT32_MAX) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }
    state.terminator_identity.value = (uint32_t)state.terminator_value;
    state.status = rome2_100f1bb0_owned_resolve_span(
        state.heap_view.host_base,
        state.heap_view.guest_base,
        state.heap_view.byte_count,
        state.header_identity,
        ROME2_100F1BB0_OWNED_HEADER_BYTES,
        &state.header);
    if (state.status == ROME2_100F1BB0_OWNED_OK) {
        state.status = rome2_100f1bb0_owned_resolve_span(
            state.heap_view.host_base,
            state.heap_view.guest_base,
            state.heap_view.byte_count,
            state.terminator_identity,
            ROME2_100F1BB0_OWNED_UNIT_BYTES,
            &state.terminator);
    }
    if (state.status != ROME2_100F1BB0_OWNED_OK ||
        !rome2_100f1bb0_owned_span_is_contained(
            &state.allocation, &state.header) ||
        !rome2_100f1bb0_owned_span_is_contained(
            &state.allocation, &state.terminator)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    state.descriptor_bytes =
        state.descriptor_view.host_base +
        (size_t)state.descriptor.view_offset;
    if (rome2_100f1bb0_owned_read_u32_le(state.descriptor_bytes) !=
            state.owner.length_units ||
        rome2_100f1bb0_owned_read_u32_le(state.descriptor_bytes + 4U) !=
            state.owner.length_units ||
        rome2_100f1bb0_owned_read_u32_le(state.descriptor_bytes + 8U) !=
            state.owner.payload.value ||
        rome2_100f1bb0_owned_read_u32_le(
            state.heap_view.host_base +
                (size_t)state.header.view_offset) !=
            state.owner.raw_base.value ||
        state.heap_view.host_base[
            (size_t)state.terminator.view_offset] != UINT8_C(0) ||
        state.heap_view.host_base[
            (size_t)state.terminator.view_offset + 1U] != UINT8_C(0)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    owner->phase = ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;
    state.effects.release(
        state.effects.context,
        state.owner.token,
        state.owner.raw_base,
        state.owner.allocation_bytes,
        ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS);
    if (state.effects.release_hook != NULL) {
        state.effects.release_hook(
            state.effects.context,
            state.owner.raw_base,
            UINT32_C(0));
    }
    return ROME2_100F1BB0_OWNED_OK;
}

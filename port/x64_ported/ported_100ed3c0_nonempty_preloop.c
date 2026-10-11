#include "ported_100ed3c0_nonempty_preloop.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ROME2_100ED3C0_NONEMPTY_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100ED3C0_NONEMPTY_EXTERNAL_CONTROL_COUNT 11U
#define ROME2_100ED3C0_NONEMPTY_BACKING_COUNT 6U
#define ROME2_100ED3C0_NONEMPTY_CONTEXT_COUNT 5U

typedef struct rome2_100ed3c0_nonempty_span {
    uint64_t guest_start;
    uintptr_t host_start;
    uint64_t byte_count;
    uint64_t view_offset;
} rome2_100ed3c0_nonempty_span;

typedef struct rome2_100ed3c0_nonempty_host_span {
    uint64_t start;
    uint64_t byte_count;
} rome2_100ed3c0_nonempty_host_span;

typedef struct rome2_100ed3c0_nonempty_backing {
    uint64_t guest_start;
    uint64_t host_start;
    uint64_t byte_count;
} rome2_100ed3c0_nonempty_backing;

typedef struct rome2_100ed3c0_nonempty_deny_context {
    uint32_t call_count;
    uint32_t requested_bytes;
    uint32_t requested_class;
    uint32_t release_count;
} rome2_100ed3c0_nonempty_deny_context;

typedef struct rome2_100ed3c0_nonempty_noop_delegate_context {
    rome2_guest_addr32 expected_destination;
    rome2_guest_addr32 expected_source;
    uint32_t call_count;
    uint32_t mismatch;
} rome2_100ed3c0_nonempty_noop_delegate_context;

typedef struct rome2_100ed3c0_nonempty_owned_delegate_context {
    const rome2_guest_write_view *persistent_descriptor_view;
    const rome2_guest_write_view *temporary_descriptor_view;
    const rome2_guest_write_view *temporary_heap_view;
    const rome2_guest_write_view *persistent_heap_view;
    const rome2_100f1bb0_owned_effects *effects;
    const rome2_100f1bb0_owned_owner *temporary_owner;
    rome2_100f1bb0_owned_owner *persistent_owner_work;
    rome2_100f2750_first_use_lifecycle *lifecycle_work;
    rome2_100f1bb0_owned_owner *persistent_owner_external;
    rome2_100f2750_first_use_lifecycle *lifecycle_external;
    rome2_guest_addr32 expected_destination;
    rome2_guest_addr32 expected_source;
    rome2_guest_addr32 guest_return;
    rome2_100f1bb0_owned_status owned_status;
    uint32_t call_count;
    uint32_t reserved;
} rome2_100ed3c0_nonempty_owned_delegate_context;

typedef struct rome2_100ed3c0_nonempty_private {
    rome2_guest_write_view frame_view;
    rome2_guest_read_view text_view;
    rome2_guest_write_view selector_view;
    rome2_guest_write_view temporary_heap_view;
    rome2_guest_write_view persistent_descriptor_view;
    rome2_guest_write_view persistent_heap_view;
    rome2_100ed3c0_nonempty_effects effects;

    rome2_100f1bb0_owned_owner temporary_owner_initial;
    rome2_100f1bb0_owned_owner persistent_owner_initial;
    rome2_100f2750_first_use_lifecycle lifecycle_initial;
    rome2_100f1bb0_owned_owner temporary_owner_work;
    rome2_100f1bb0_owned_owner persistent_owner_work;
    rome2_100f2750_first_use_lifecycle lifecycle_work;

    rome2_100ed3c0_nonempty_span frame_span;
    rome2_100ed3c0_nonempty_span persistent_descriptor_span;
    rome2_100ed3c0_nonempty_span first_selector_span;
    rome2_100ed3c0_nonempty_span second_selector_span;

    rome2_guest_addr32 guest_triplet0;
    rome2_guest_addr32 guest_triplet1;
    rome2_guest_addr32 guest_descriptor;
    rome2_guest_addr32 guest_packet;
    rome2_guest_addr32 guest_copy0;
    rome2_guest_addr32 guest_copy1;
    rome2_guest_addr32 guest_receiver;

    rome2_guest_addr32 leaf_return;
    rome2_guest_addr32 child_return;
    rome2_guest_addr32 preflight_return;

    rome2_guest_write_view frame_preview_view;
    rome2_guest_write_view selector_preview_view;
    rome2_100df270_prefix_effects prefix_preflight;
    rome2_100df270_suffix_effects suffix_preflight;
    rome2_100f1bb0_owned_effects owned_deny_effects;
    rome2_100df270_suffix_100f2750_delegate suffix_noop_delegate;
    rome2_100df270_suffix_100f2750_delegate suffix_owned_delegate;
    rome2_100ed3c0_nonempty_deny_context deny_context;
    rome2_100ed3c0_nonempty_noop_delegate_context noop_delegate_context;
    rome2_100ed3c0_nonempty_owned_delegate_context owned_delegate_context;
    rome2_100f1bb0_owned_owner preflight_owner;

    uint8_t frame_preview[ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES];
    uint8_t selector_preview[8];
    uint8_t preview_observer_context;
    uint8_t reserved0[3];
    uint32_t text_length;
    uint32_t allocation_bytes;
    uint32_t first_selector_value;
} rome2_100ed3c0_nonempty_private;

static rome2_100f1bb0_owned_status rome2_100ed3c0_nonempty_validate_object(
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

static int rome2_100ed3c0_nonempty_ranges_overlap(
    uint64_t first_start,
    uint64_t first_size,
    uint64_t second_start,
    uint64_t second_size)
{
    if (first_size == UINT64_C(0) || second_size == UINT64_C(0)) {
        return 0;
    }
    if (first_start >= second_start) {
        return first_start - second_start < second_size;
    }
    return second_start - first_start < first_size;
}

static rome2_100f1bb0_owned_status rome2_100ed3c0_nonempty_validate_view(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100ED3C0_NONEMPTY_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100ED3C0_NONEMPTY_ADDRESS_SPACE_SIZE) {
        return ROME2_100F1BB0_OWNED_RANGE_OVERFLOW;
    }
    host_address = (uintptr_t)host_base;
    if (byte_count != UINT64_C(0) &&
        byte_count - UINT64_C(1) >
            (uint64_t)(UINTPTR_MAX - host_address)) {
        return ROME2_100F1BB0_OWNED_RANGE_OVERFLOW;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

static rome2_100f1bb0_owned_status
rome2_100ed3c0_nonempty_validate_host_interval(
    const void *host_base,
    uint64_t byte_count)
{
    uintptr_t address;

    if (host_base == NULL || byte_count == UINT64_C(0)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    address = (uintptr_t)host_base;
    if (byte_count - UINT64_C(1) >
        (uint64_t)(UINTPTR_MAX - address)) {
        return ROME2_100F1BB0_OWNED_RANGE_OVERFLOW;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

static rome2_100f1bb0_owned_status rome2_100ed3c0_nonempty_resolve_span(
    const void *host_base,
    uint32_t guest_base,
    uint64_t view_byte_count,
    rome2_guest_addr32 guest_start,
    uint32_t span_byte_count,
    rome2_100ed3c0_nonempty_span *span_out)
{
    uint64_t offset;

    if (span_out == NULL || span_byte_count == UINT32_C(0)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (guest_start.value == UINT32_C(0)) {
        return ROME2_100F1BB0_OWNED_NULL_ADDRESS;
    }
    if ((uint64_t)span_byte_count >
        ROME2_100ED3C0_NONEMPTY_ADDRESS_SPACE_SIZE -
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
    span_out->host_start = (uintptr_t)host_base + (uintptr_t)offset;
    span_out->byte_count = (uint64_t)span_byte_count;
    span_out->view_offset = offset;
    return ROME2_100F1BB0_OWNED_OK;
}

static int rome2_100ed3c0_nonempty_host_spans_overlap(
    const rome2_100ed3c0_nonempty_host_span *spans,
    size_t span_count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < span_count; ++first) {
        for (second = first + 1U; second < span_count; ++second) {
            if (rome2_100ed3c0_nonempty_ranges_overlap(
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

static int rome2_100ed3c0_nonempty_backings_overlap(
    const rome2_100ed3c0_nonempty_backing *backings,
    size_t backing_count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < backing_count; ++first) {
        for (second = first + 1U; second < backing_count; ++second) {
            if (rome2_100ed3c0_nonempty_ranges_overlap(
                    backings[first].host_start,
                    backings[first].byte_count,
                    backings[second].host_start,
                    backings[second].byte_count) ||
                rome2_100ed3c0_nonempty_ranges_overlap(
                    backings[first].guest_start,
                    backings[first].byte_count,
                    backings[second].guest_start,
                    backings[second].byte_count)) {
                return 1;
            }
        }
    }
    return 0;
}

static int rome2_100ed3c0_nonempty_sets_overlap(
    const rome2_100ed3c0_nonempty_host_span *first,
    size_t first_count,
    const rome2_100ed3c0_nonempty_host_span *second,
    size_t second_count)
{
    size_t first_index;
    size_t second_index;

    for (first_index = 0U; first_index < first_count; ++first_index) {
        for (second_index = 0U; second_index < second_count; ++second_index) {
            if (rome2_100ed3c0_nonempty_ranges_overlap(
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

static int rome2_100ed3c0_nonempty_contexts_partially_overlap(
    const rome2_100ed3c0_nonempty_host_span *contexts,
    size_t context_count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < context_count; ++first) {
        for (second = first + 1U; second < context_count; ++second) {
            if (contexts[first].start == contexts[second].start &&
                contexts[first].byte_count == contexts[second].byte_count) {
                continue;
            }
            if (rome2_100ed3c0_nonempty_ranges_overlap(
                    contexts[first].start,
                    contexts[first].byte_count,
                    contexts[second].start,
                    contexts[second].byte_count)) {
                return 1;
            }
        }
    }
    return 0;
}

static int rome2_100ed3c0_nonempty_owner_is_empty(
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

static uint32_t rome2_100ed3c0_nonempty_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100ed3c0_nonempty_write_u32_le(
    uint8_t *bytes,
    uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void rome2_100ed3c0_nonempty_stage_scalar_fields(
    uint8_t *frame,
    uint32_t argument_position1)
{
    rome2_100ed3c0_nonempty_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_ZERO_OFFSET,
        UINT32_C(0));
    rome2_100ed3c0_nonempty_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_ARGUMENT_COPY_OFFSET,
        argument_position1);
    rome2_100ed3c0_nonempty_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET,
        argument_position1);
    rome2_100ed3c0_nonempty_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET + 4U,
        UINT32_C(0));
    frame[ROME2_PORT_100ED3C0_PRELOOP_ZERO_BYTE_OFFSET] = UINT8_C(0);
    rome2_100ed3c0_nonempty_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_ZERO_DWORD_OFFSET,
        UINT32_C(0));
    rome2_100ed3c0_nonempty_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_PACKET_ARGUMENT_OFFSET,
        argument_position1);
    frame[ROME2_PORT_100ED3C0_PRELOOP_PACKET_BYTE_OFFSET] = UINT8_C(0);
    rome2_100ed3c0_nonempty_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_PACKET_DWORD_OFFSET,
        UINT32_C(0));
    frame[ROME2_PORT_100ED3C0_PRELOOP_PACKET_FLAG_OFFSET] = UINT8_C(0);
}

static rome2_100ed3c0_preloop_value rome2_100ed3c0_nonempty_make_value(
    rome2_100ed3c0_preloop_value_kind kind,
    uint32_t value)
{
    rome2_100ed3c0_preloop_value result;

    result.kind = kind;
    result.value = value;
    return result;
}

static void rome2_100ed3c0_nonempty_clear_step(
    rome2_100ed3c0_nonempty_step *step,
    rome2_100ed3c0_nonempty_step_kind kind)
{
    step->kind = kind;
    step->argument_count = UINT32_C(0);
    step->argument0 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_NONE, UINT32_C(0));
    step->argument1 = step->argument0;
    step->argument2 = step->argument0;
    step->result_count = UINT32_C(0);
    step->result0 = step->argument0;
}

static rome2_100f1bb0_owned_status rome2_100ed3c0_nonempty_from_guest(
    rome2_guest_status status)
{
    switch (status) {
    case ROME2_GUEST_OK:
        return ROME2_100F1BB0_OWNED_OK;
    case ROME2_GUEST_BAD_ARGUMENT:
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    case ROME2_GUEST_NULL_ADDRESS:
        return ROME2_100F1BB0_OWNED_NULL_ADDRESS;
    case ROME2_GUEST_RANGE_OVERFLOW:
        return ROME2_100F1BB0_OWNED_RANGE_OVERFLOW;
    case ROME2_GUEST_OUT_OF_RANGE:
        return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
    default:
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }
}

static void rome2_100ed3c0_nonempty_noop_prefix_step(
    void *context,
    rome2_100df270_prefix_step step)
{
    (void)context;
    (void)step;
}

static void rome2_100ed3c0_nonempty_noop_suffix_step(
    void *context,
    rome2_100df270_suffix_step step)
{
    (void)context;
    (void)step;
}

static rome2_100f1bb0_owned_grant_result
rome2_100ed3c0_nonempty_deny_allocate(
    void *context,
    uint32_t byte_count,
    uint32_t allocation_class,
    rome2_100f1bb0_owned_grant *grant_out)
{
    rome2_100ed3c0_nonempty_deny_context *state =
        (rome2_100ed3c0_nonempty_deny_context *)context;

    state->call_count += UINT32_C(1);
    state->requested_bytes = byte_count;
    state->requested_class = allocation_class;
    (void)grant_out;
    return ROME2_100F1BB0_OWNED_GRANT_DENIED;
}

static void rome2_100ed3c0_nonempty_noop_release(
    void *context,
    uint64_t token,
    rome2_guest_addr32 raw_base,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    rome2_100ed3c0_nonempty_deny_context *state =
        (rome2_100ed3c0_nonempty_deny_context *)context;

    state->release_count += UINT32_C(1);
    (void)token;
    (void)raw_base;
    (void)byte_count;
    (void)allocation_class;
}

static rome2_guest_status rome2_100ed3c0_nonempty_noop_delegate(
    void *context,
    rome2_guest_addr32 guest_destination,
    rome2_guest_addr32 guest_source)
{
    rome2_100ed3c0_nonempty_noop_delegate_context *state =
        (rome2_100ed3c0_nonempty_noop_delegate_context *)context;

    state->call_count += UINT32_C(1);
    if (state->call_count != UINT32_C(1) ||
        guest_destination.value != state->expected_destination.value ||
        guest_source.value != state->expected_source.value) {
        state->mismatch = UINT32_C(1);
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    return ROME2_GUEST_OK;
}

static rome2_guest_status rome2_100ed3c0_nonempty_execute_first_use(
    void *context,
    rome2_guest_addr32 guest_destination,
    rome2_guest_addr32 guest_source)
{
    rome2_100ed3c0_nonempty_owned_delegate_context *state =
        (rome2_100ed3c0_nonempty_owned_delegate_context *)context;

    state->call_count += UINT32_C(1);
    if (state->call_count != UINT32_C(1) ||
        guest_destination.value != state->expected_destination.value ||
        guest_source.value != state->expected_source.value) {
        state->owned_status =
            ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    state->owned_status = rome2_port_100f2750_first_use_owned(
        state->persistent_descriptor_view,
        state->temporary_descriptor_view,
        guest_source,
        state->temporary_heap_view,
        state->persistent_heap_view,
        state->effects,
        state->temporary_owner,
        state->persistent_owner_work,
        state->lifecycle_work,
        &state->guest_return);
    if (state->owned_status != ROME2_100F1BB0_OWNED_OK) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (state->guest_return.value != guest_destination.value) {
        state->owned_status =
            ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    *state->persistent_owner_external = *state->persistent_owner_work;
    *state->lifecycle_external = *state->lifecycle_work;
    return ROME2_GUEST_OK;
}

static rome2_100f1bb0_owned_status rome2_100ed3c0_nonempty_add(
    rome2_guest_addr32 base,
    uint32_t offset,
    rome2_guest_addr32 *result)
{
    return rome2_100ed3c0_nonempty_from_guest(
        rome2_guest_add_checked(base, offset, result));
}

static rome2_100f1bb0_owned_status
rome2_100ed3c0_nonempty_validate_heap_capacity(
    const rome2_guest_write_view *view,
    uint32_t allocation_bytes)
{
    uint64_t available = view->byte_count;

    if (view->guest_base == UINT32_C(0)) {
        if (available == UINT64_C(0)) {
            return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
        }
        --available;
    }
    if (available < (uint64_t)allocation_bytes) {
        return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

rome2_100f1bb0_owned_status rome2_port_100ed3c0_run_nonempty_preloop(
    const rome2_guest_write_view *frame_view,
    rome2_guest_addr32 guest_frame,
    uint32_t argument_position1,
    const rome2_guest_read_view *text_view,
    rome2_guest_addr32 argument_position3_text,
    uint32_t text_max_units,
    const rome2_guest_write_view *selector_view,
    const rome2_guest_write_view *temporary_heap_view,
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_guest_write_view *persistent_heap_view,
    const rome2_100ed3c0_nonempty_effects *effects,
    rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_100ed3c0_preloop_result *result_out)
{
    rome2_100ed3c0_nonempty_private state = {0};
    rome2_100ed3c0_nonempty_host_span controls[
        ROME2_100ED3C0_NONEMPTY_EXTERNAL_CONTROL_COUNT];
    rome2_100ed3c0_nonempty_backing backings[
        ROME2_100ED3C0_NONEMPTY_BACKING_COUNT];
    rome2_100ed3c0_nonempty_host_span backing_spans[
        ROME2_100ED3C0_NONEMPTY_BACKING_COUNT];
    rome2_100ed3c0_nonempty_host_span contexts[
        ROME2_100ED3C0_NONEMPTY_CONTEXT_COUNT];
    rome2_100ed3c0_nonempty_host_span private_span;
    rome2_100ed3c0_nonempty_step step;
    rome2_100f1bb0_owned_status owned_status;
    rome2_guest_status guest_status;
    uint8_t *frame_bytes;
    const uint8_t *persistent_descriptor_bytes;
    size_t index;

    owned_status = rome2_100ed3c0_nonempty_validate_object(
        frame_view, sizeof(*frame_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_object(
        text_view, sizeof(*text_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_object(
        selector_view, sizeof(*selector_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_object(
        temporary_heap_view, sizeof(*temporary_heap_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_object(
        persistent_descriptor_view, sizeof(*persistent_descriptor_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_object(
        persistent_heap_view, sizeof(*persistent_heap_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_object(
        effects, sizeof(*effects));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_object(
        temporary_owner, sizeof(*temporary_owner));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_object(
        persistent_owner, sizeof(*persistent_owner));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_object(
        lifecycle, sizeof(*lifecycle));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_object(
        result_out, sizeof(*result_out));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;

    if ((uintptr_t)frame_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)text_view % _Alignof(rome2_guest_read_view) != 0U ||
        (uintptr_t)selector_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)temporary_heap_view %
            _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)persistent_descriptor_view %
            _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)persistent_heap_view %
            _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)effects %
            _Alignof(rome2_100ed3c0_nonempty_effects) != 0U ||
        (uintptr_t)temporary_owner %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)persistent_owner %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)lifecycle %
            _Alignof(rome2_100f2750_first_use_lifecycle) != 0U ||
        (uintptr_t)result_out %
            _Alignof(rome2_100ed3c0_preloop_result) != 0U) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    controls[0].start = (uint64_t)(uintptr_t)frame_view;
    controls[0].byte_count = sizeof(*frame_view);
    controls[1].start = (uint64_t)(uintptr_t)text_view;
    controls[1].byte_count = sizeof(*text_view);
    controls[2].start = (uint64_t)(uintptr_t)selector_view;
    controls[2].byte_count = sizeof(*selector_view);
    controls[3].start = (uint64_t)(uintptr_t)temporary_heap_view;
    controls[3].byte_count = sizeof(*temporary_heap_view);
    controls[4].start = (uint64_t)(uintptr_t)persistent_descriptor_view;
    controls[4].byte_count = sizeof(*persistent_descriptor_view);
    controls[5].start = (uint64_t)(uintptr_t)persistent_heap_view;
    controls[5].byte_count = sizeof(*persistent_heap_view);
    controls[6].start = (uint64_t)(uintptr_t)effects;
    controls[6].byte_count = sizeof(*effects);
    controls[7].start = (uint64_t)(uintptr_t)temporary_owner;
    controls[7].byte_count = sizeof(*temporary_owner);
    controls[8].start = (uint64_t)(uintptr_t)persistent_owner;
    controls[8].byte_count = sizeof(*persistent_owner);
    controls[9].start = (uint64_t)(uintptr_t)lifecycle;
    controls[9].byte_count = sizeof(*lifecycle);
    controls[10].start = (uint64_t)(uintptr_t)result_out;
    controls[10].byte_count = sizeof(*result_out);
    if (rome2_100ed3c0_nonempty_host_spans_overlap(
            controls, ROME2_100ED3C0_NONEMPTY_EXTERNAL_CONTROL_COUNT)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.frame_view = *frame_view;
    state.text_view = *text_view;
    state.selector_view = *selector_view;
    state.temporary_heap_view = *temporary_heap_view;
    state.persistent_descriptor_view = *persistent_descriptor_view;
    state.persistent_heap_view = *persistent_heap_view;
    state.effects = *effects;
    state.temporary_owner_initial = *temporary_owner;
    state.persistent_owner_initial = *persistent_owner;
    state.lifecycle_initial = *lifecycle;
    state.temporary_owner_work = state.temporary_owner_initial;
    state.persistent_owner_work = state.persistent_owner_initial;
    state.lifecycle_work = state.lifecycle_initial;

    owned_status = rome2_100ed3c0_nonempty_validate_view(
        state.frame_view.host_base,
        state.frame_view.guest_base,
        state.frame_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_view(
        state.text_view.host_base,
        state.text_view.guest_base,
        state.text_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_view(
        state.selector_view.host_base,
        state.selector_view.guest_base,
        state.selector_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_view(
        state.temporary_heap_view.host_base,
        state.temporary_heap_view.guest_base,
        state.temporary_heap_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_view(
        state.persistent_descriptor_view.host_base,
        state.persistent_descriptor_view.guest_base,
        state.persistent_descriptor_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_view(
        state.persistent_heap_view.host_base,
        state.persistent_heap_view.guest_base,
        state.persistent_heap_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    if (state.frame_view.guest_base != guest_frame.value ||
        state.frame_view.byte_count !=
            ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    backings[0].guest_start = state.frame_view.guest_base;
    backings[0].host_start =
        (uint64_t)(uintptr_t)state.frame_view.host_base;
    backings[0].byte_count = state.frame_view.byte_count;
    backings[1].guest_start = state.text_view.guest_base;
    backings[1].host_start =
        (uint64_t)(uintptr_t)state.text_view.host_base;
    backings[1].byte_count = state.text_view.byte_count;
    backings[2].guest_start = state.selector_view.guest_base;
    backings[2].host_start =
        (uint64_t)(uintptr_t)state.selector_view.host_base;
    backings[2].byte_count = state.selector_view.byte_count;
    backings[3].guest_start = state.temporary_heap_view.guest_base;
    backings[3].host_start =
        (uint64_t)(uintptr_t)state.temporary_heap_view.host_base;
    backings[3].byte_count = state.temporary_heap_view.byte_count;
    backings[4].guest_start = state.persistent_descriptor_view.guest_base;
    backings[4].host_start =
        (uint64_t)(uintptr_t)state.persistent_descriptor_view.host_base;
    backings[4].byte_count = state.persistent_descriptor_view.byte_count;
    backings[5].guest_start = state.persistent_heap_view.guest_base;
    backings[5].host_start =
        (uint64_t)(uintptr_t)state.persistent_heap_view.host_base;
    backings[5].byte_count = state.persistent_heap_view.byte_count;
    for (index = 0U; index < ROME2_100ED3C0_NONEMPTY_BACKING_COUNT;
            ++index) {
        backing_spans[index].start = backings[index].host_start;
        backing_spans[index].byte_count = backings[index].byte_count;
    }
    private_span.start = (uint64_t)(uintptr_t)&state;
    private_span.byte_count = sizeof(state);
    if (rome2_100ed3c0_nonempty_backings_overlap(
            backings, ROME2_100ED3C0_NONEMPTY_BACKING_COUNT) ||
        rome2_100ed3c0_nonempty_sets_overlap(
            backing_spans,
            ROME2_100ED3C0_NONEMPTY_BACKING_COUNT,
            controls,
            ROME2_100ED3C0_NONEMPTY_EXTERNAL_CONTROL_COUNT) ||
        rome2_100ed3c0_nonempty_sets_overlap(
            backing_spans,
            ROME2_100ED3C0_NONEMPTY_BACKING_COUNT,
            &private_span,
            1U) ||
        rome2_100ed3c0_nonempty_sets_overlap(
            controls,
            ROME2_100ED3C0_NONEMPTY_EXTERNAL_CONTROL_COUNT,
            &private_span,
            1U)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    if (state.effects.emit_step == NULL ||
        state.effects.child_prefix.emit_step == NULL ||
        state.effects.child_suffix.emit_step == NULL ||
        state.effects.temporary_owned.allocate == NULL ||
        state.effects.temporary_owned.release == NULL ||
        state.effects.persistent_owned.allocate == NULL ||
        state.effects.persistent_owned.release == NULL ||
        state.effects.child_suffix.result_100e8240.value !=
            ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    contexts[0].start = (uint64_t)(uintptr_t)state.effects.context;
    contexts[0].byte_count = state.effects.context_byte_count;
    contexts[1].start =
        (uint64_t)(uintptr_t)state.effects.child_prefix.context;
    contexts[1].byte_count =
        state.effects.child_prefix_context_byte_count;
    contexts[2].start =
        (uint64_t)(uintptr_t)state.effects.child_suffix.context;
    contexts[2].byte_count =
        state.effects.child_suffix_context_byte_count;
    contexts[3].start =
        (uint64_t)(uintptr_t)state.effects.temporary_owned.context;
    contexts[3].byte_count =
        state.effects.temporary_owned.context_byte_count;
    contexts[4].start =
        (uint64_t)(uintptr_t)state.effects.persistent_owned.context;
    contexts[4].byte_count =
        state.effects.persistent_owned.context_byte_count;
    for (index = 0U; index < ROME2_100ED3C0_NONEMPTY_CONTEXT_COUNT;
            ++index) {
        owned_status = rome2_100ed3c0_nonempty_validate_host_interval(
            (const void *)(uintptr_t)contexts[index].start,
            contexts[index].byte_count);
        if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    }
    if (rome2_100ed3c0_nonempty_contexts_partially_overlap(
            contexts, ROME2_100ED3C0_NONEMPTY_CONTEXT_COUNT) ||
        rome2_100ed3c0_nonempty_sets_overlap(
            contexts,
            ROME2_100ED3C0_NONEMPTY_CONTEXT_COUNT,
            controls,
            ROME2_100ED3C0_NONEMPTY_EXTERNAL_CONTROL_COUNT) ||
        rome2_100ed3c0_nonempty_sets_overlap(
            contexts,
            ROME2_100ED3C0_NONEMPTY_CONTEXT_COUNT,
            backing_spans,
            ROME2_100ED3C0_NONEMPTY_BACKING_COUNT) ||
        rome2_100ed3c0_nonempty_sets_overlap(
            contexts,
            ROME2_100ED3C0_NONEMPTY_CONTEXT_COUNT,
            &private_span,
            1U)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    if (!rome2_100ed3c0_nonempty_owner_is_empty(
            &state.temporary_owner_initial) ||
        !rome2_100ed3c0_nonempty_owner_is_empty(
            &state.persistent_owner_initial) ||
        state.lifecycle_initial.phase !=
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL ||
        state.lifecycle_initial.reserved != UINT32_C(0)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    owned_status = rome2_100ed3c0_nonempty_resolve_span(
        state.frame_view.host_base,
        state.frame_view.guest_base,
        state.frame_view.byte_count,
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES,
        &state.frame_span);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_resolve_span(
        state.persistent_descriptor_view.host_base,
        state.persistent_descriptor_view.guest_base,
        state.persistent_descriptor_view.byte_count,
        (rome2_guest_addr32){ROME2_PORT_100F2750_FIRST_USE_DESTINATION},
        UINT32_C(12),
        &state.persistent_descriptor_span);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_resolve_span(
        state.selector_view.host_base,
        state.selector_view.guest_base,
        state.selector_view.byte_count,
        state.effects.child_suffix.first_selector_result,
        UINT32_C(4),
        &state.first_selector_span);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_resolve_span(
        state.selector_view.host_base,
        state.selector_view.guest_base,
        state.selector_view.byte_count,
        state.effects.child_suffix.second_selector_result,
        UINT32_C(4),
        &state.second_selector_span);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;

    persistent_descriptor_bytes =
        state.persistent_descriptor_view.host_base +
        (size_t)state.persistent_descriptor_span.view_offset;
    if (rome2_100ed3c0_nonempty_read_u32_le(
            persistent_descriptor_bytes) != UINT32_C(0) ||
        rome2_100ed3c0_nonempty_read_u32_le(
            persistent_descriptor_bytes + 4U) != UINT32_C(0) ||
        rome2_100ed3c0_nonempty_read_u32_le(
            persistent_descriptor_bytes + 8U) !=
            ROME2_PORT_100F2750_FIRST_USE_SENTINEL) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }

    owned_status = rome2_100ed3c0_nonempty_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_TRIPLET0_OFFSET,
        &state.guest_triplet0);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_TRIPLET1_OFFSET,
        &state.guest_triplet1);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET,
        &state.guest_descriptor);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET,
        &state.guest_packet);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_COPY0_OFFSET,
        &state.guest_copy0);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_COPY1_OFFSET,
        &state.guest_copy1);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET,
        &state.guest_receiver);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;

    if (text_max_units <
            ROME2_PORT_100ED3C0_NONEMPTY_MIN_TEXT_UNITS ||
        text_max_units >
            ROME2_PORT_100ED3C0_NONEMPTY_MAX_TEXT_UNITS) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    state.text_length = UINT32_MAX;
    guest_status = rome2_port_100f1bb0_measure_utf16(
        &state.text_view,
        argument_position3_text,
        text_max_units,
        &state.text_length);
    if (guest_status != ROME2_GUEST_OK) {
        return rome2_100ed3c0_nonempty_from_guest(guest_status);
    }
    if (state.text_length == UINT32_C(0) ||
        state.text_length >= text_max_units ||
        state.text_length >= ROME2_PORT_100F1BB0_OWNED_MAX_UNITS) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    state.allocation_bytes =
        state.text_length * UINT32_C(2) + UINT32_C(10);
    owned_status = rome2_100ed3c0_nonempty_validate_heap_capacity(
        &state.temporary_heap_view, state.allocation_bytes);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_nonempty_validate_heap_capacity(
        &state.persistent_heap_view, state.allocation_bytes);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;

    state.owned_deny_effects.allocate =
        rome2_100ed3c0_nonempty_deny_allocate;
    state.owned_deny_effects.release =
        rome2_100ed3c0_nonempty_noop_release;
    state.owned_deny_effects.release_hook = NULL;
    state.owned_deny_effects.context = &state.deny_context;
    state.owned_deny_effects.context_byte_count = sizeof(state.deny_context);
    state.preflight_return.value = UINT32_C(0xdeadbeef);
    owned_status = rome2_port_100f1bb0_build_owned_utf16(
        &state.frame_view,
        state.guest_descriptor,
        &state.text_view,
        argument_position3_text,
        text_max_units,
        &state.temporary_heap_view,
        &state.owned_deny_effects,
        &state.preflight_owner,
        &state.preflight_return);
    if (owned_status != ROME2_100F1BB0_OWNED_ALLOCATION_DENIED) {
        return owned_status == ROME2_100F1BB0_OWNED_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : owned_status;
    }
    if (state.deny_context.call_count != UINT32_C(1) ||
        state.deny_context.release_count != UINT32_C(0) ||
        state.deny_context.requested_bytes != state.allocation_bytes ||
        state.deny_context.requested_class !=
            ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS ||
        !rome2_100ed3c0_nonempty_owner_is_empty(
            &state.preflight_owner) ||
        state.preflight_return.value != UINT32_C(0xdeadbeef)) {
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }

    memcpy(
        state.frame_preview,
        state.frame_view.host_base + (size_t)state.frame_span.view_offset,
        ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES);
    state.frame_preview_view.host_base = state.frame_preview;
    state.frame_preview_view.guest_base = guest_frame.value;
    state.frame_preview_view.byte_count =
        ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES;
    rome2_100ed3c0_nonempty_stage_scalar_fields(
        state.frame_preview, argument_position1);
    state.preflight_return.value = UINT32_C(0);
    guest_status = rome2_port_100f1c10_initialize_triplet(
        &state.frame_preview_view,
        state.guest_triplet0,
        &state.preflight_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.preflight_return.value != state.guest_triplet0.value) {
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }
    state.preflight_return.value = UINT32_C(0);
    guest_status = rome2_port_100f1c10_initialize_triplet(
        &state.frame_preview_view,
        state.guest_triplet1,
        &state.preflight_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.preflight_return.value != state.guest_triplet1.value) {
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }
    state.preflight_return.value = UINT32_C(0);
    guest_status = rome2_port_100f1aa0_copy_empty_source(
        &state.frame_preview_view,
        state.guest_copy0,
        state.guest_triplet0,
        &state.preflight_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.preflight_return.value != state.guest_copy0.value) {
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }
    state.preflight_return.value = UINT32_C(0);
    guest_status = rome2_port_100f1aa0_copy_empty_source(
        &state.frame_preview_view,
        state.guest_copy1,
        state.guest_triplet1,
        &state.preflight_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.preflight_return.value != state.guest_copy1.value) {
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }

    state.prefix_preflight = state.effects.child_prefix;
    state.prefix_preflight.emit_step =
        rome2_100ed3c0_nonempty_noop_prefix_step;
    state.prefix_preflight.context = &state.preview_observer_context;
    state.preflight_return.value = UINT32_C(0);
    guest_status = rome2_port_100df270_run_platform_prefix_transcript(
        &state.frame_preview_view,
        state.guest_receiver,
        state.guest_packet,
        &state.prefix_preflight,
        &state.preflight_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.preflight_return.value != state.guest_receiver.value) {
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }
    state.preflight_return.value = UINT32_C(0);
    guest_status = rome2_port_100df270_project_headless_empty_state(
        &state.frame_preview_view,
        state.guest_receiver,
        state.guest_packet,
        &state.preflight_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.preflight_return.value != state.guest_receiver.value) {
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }

    state.first_selector_value = rome2_100ed3c0_nonempty_read_u32_le(
        state.selector_view.host_base +
        (size_t)state.first_selector_span.view_offset);
    memset(state.selector_preview, 0xa5, sizeof(state.selector_preview));
    rome2_100ed3c0_nonempty_write_u32_le(
        state.selector_preview, state.first_selector_value);
    state.selector_preview_view.host_base = state.selector_preview;
    state.selector_preview_view.guest_base = UINT32_C(0x1000);
    state.selector_preview_view.byte_count = sizeof(state.selector_preview);
    state.suffix_preflight = state.effects.child_suffix;
    state.suffix_preflight.emit_step =
        rome2_100ed3c0_nonempty_noop_suffix_step;
    state.suffix_preflight.context = &state.preview_observer_context;
    state.suffix_preflight.first_selector_result.value = UINT32_C(0x1000);
    state.suffix_preflight.second_selector_result.value =
        state.effects.child_suffix.first_selector_result.value ==
            state.effects.child_suffix.second_selector_result.value
        ? UINT32_C(0x1000)
        : UINT32_C(0x1004);
    state.noop_delegate_context.expected_destination.value =
        ROME2_PORT_100F2750_FIRST_USE_DESTINATION;
    state.noop_delegate_context.expected_source = state.guest_descriptor;
    state.suffix_noop_delegate.execute =
        rome2_100ed3c0_nonempty_noop_delegate;
    state.suffix_noop_delegate.context = &state.noop_delegate_context;
    state.suffix_noop_delegate.context_byte_count =
        sizeof(state.noop_delegate_context);
    state.preflight_return.value = UINT32_C(0);
    guest_status = rome2_port_100df270_run_suffix_transcript_delegated(
        &state.selector_preview_view,
        state.guest_receiver,
        state.guest_descriptor,
        &state.suffix_preflight,
        &state.suffix_noop_delegate,
        &state.preflight_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.preflight_return.value != state.guest_receiver.value ||
        state.noop_delegate_context.call_count != UINT32_C(1) ||
        state.noop_delegate_context.mismatch != UINT32_C(0)) {
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }

    frame_bytes =
        state.frame_view.host_base + (size_t)state.frame_span.view_offset;
    rome2_100ed3c0_nonempty_clear_step(
        &step,
        ROME2_100ED3C0_NONEMPTY_STEP_WRITE_GLOBAL_119F31C8);
    step.argument_count = UINT32_C(2);
    step.argument0 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_ORIGINAL_IDENTITY,
        ROME2_PORT_100ED3C0_PRELOOP_GLOBAL_119F31C8);
    step.argument1 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_SCALAR, UINT32_C(1));
    state.effects.emit_step(state.effects.context, step);

    rome2_100ed3c0_nonempty_clear_step(
        &step,
        ROME2_100ED3C0_NONEMPTY_STEP_WRITE_GLOBAL_119F31C5);
    step.argument_count = UINT32_C(2);
    step.argument0 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_ORIGINAL_IDENTITY,
        ROME2_PORT_100ED3C0_PRELOOP_GLOBAL_119F31C5);
    step.argument1 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_SCALAR, UINT32_C(1));
    state.effects.emit_step(state.effects.context, step);

    rome2_100ed3c0_nonempty_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_ZERO_OFFSET,
        UINT32_C(0));
    rome2_100ed3c0_nonempty_clear_step(
        &step, ROME2_100ED3C0_NONEMPTY_STEP_INIT_TRIPLET0);
    step.argument_count = UINT32_C(1);
    step.argument0 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        state.guest_triplet0.value);
    state.effects.emit_step(state.effects.context, step);
    state.leaf_return.value = UINT32_C(0);
    guest_status = rome2_port_100f1c10_initialize_triplet(
        &state.frame_view, state.guest_triplet0, &state.leaf_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.leaf_return.value != state.guest_triplet0.value) {
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }

    rome2_100ed3c0_nonempty_clear_step(
        &step, ROME2_100ED3C0_NONEMPTY_STEP_INIT_TRIPLET1);
    step.argument_count = UINT32_C(1);
    step.argument0 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        state.guest_triplet1.value);
    state.effects.emit_step(state.effects.context, step);
    state.leaf_return.value = UINT32_C(0);
    guest_status = rome2_port_100f1c10_initialize_triplet(
        &state.frame_view, state.guest_triplet1, &state.leaf_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.leaf_return.value != state.guest_triplet1.value) {
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }

    rome2_100ed3c0_nonempty_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_ARGUMENT_COPY_OFFSET,
        argument_position1);
    rome2_100ed3c0_nonempty_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET,
        argument_position1);
    rome2_100ed3c0_nonempty_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET + 4U,
        UINT32_C(0));
    frame_bytes[ROME2_PORT_100ED3C0_PRELOOP_ZERO_BYTE_OFFSET] = UINT8_C(0);
    rome2_100ed3c0_nonempty_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_ZERO_DWORD_OFFSET,
        UINT32_C(0));

    rome2_100ed3c0_nonempty_clear_step(
        &step, ROME2_100ED3C0_NONEMPTY_STEP_COPY_EMPTY0);
    step.argument_count = UINT32_C(2);
    step.argument0 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        state.guest_copy0.value);
    step.argument1 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        state.guest_triplet0.value);
    state.effects.emit_step(state.effects.context, step);
    state.leaf_return.value = UINT32_C(0);
    guest_status = rome2_port_100f1aa0_copy_empty_source(
        &state.frame_view,
        state.guest_copy0,
        state.guest_triplet0,
        &state.leaf_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.leaf_return.value != state.guest_copy0.value) {
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }

    rome2_100ed3c0_nonempty_clear_step(
        &step, ROME2_100ED3C0_NONEMPTY_STEP_COPY_EMPTY1);
    step.argument_count = UINT32_C(2);
    step.argument0 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        state.guest_copy1.value);
    step.argument1 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        state.guest_triplet1.value);
    state.effects.emit_step(state.effects.context, step);
    state.leaf_return.value = UINT32_C(0);
    guest_status = rome2_port_100f1aa0_copy_empty_source(
        &state.frame_view,
        state.guest_copy1,
        state.guest_triplet1,
        &state.leaf_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.leaf_return.value != state.guest_copy1.value) {
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }

    rome2_100ed3c0_nonempty_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_PACKET_ARGUMENT_OFFSET,
        argument_position1);
    frame_bytes[ROME2_PORT_100ED3C0_PRELOOP_PACKET_BYTE_OFFSET] = UINT8_C(0);
    rome2_100ed3c0_nonempty_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_PACKET_DWORD_OFFSET,
        UINT32_C(0));
    frame_bytes[ROME2_PORT_100ED3C0_PRELOOP_PACKET_FLAG_OFFSET] = UINT8_C(0);

    rome2_100ed3c0_nonempty_clear_step(
        &step, ROME2_100ED3C0_NONEMPTY_STEP_BUILD_OWNED_DESCRIPTOR);
    step.argument_count = UINT32_C(3);
    step.argument0 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        state.guest_descriptor.value);
    step.argument1 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_GUEST_IDENTITY,
        argument_position3_text.value);
    step.argument2 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_SCALAR,
        state.text_length);
    step.result_count = UINT32_C(1);
    step.result0 = step.argument0;
    state.effects.emit_step(state.effects.context, step);
    state.leaf_return.value = UINT32_C(0);
    owned_status = rome2_port_100f1bb0_build_owned_utf16(
        &state.frame_view,
        state.guest_descriptor,
        &state.text_view,
        argument_position3_text,
        text_max_units,
        &state.temporary_heap_view,
        &state.effects.temporary_owned,
        &state.temporary_owner_work,
        &state.leaf_return);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) {
        *temporary_owner = state.temporary_owner_initial;
        *persistent_owner = state.persistent_owner_initial;
        *lifecycle = state.lifecycle_initial;
        return owned_status;
    }
    if (state.leaf_return.value != state.guest_descriptor.value) {
        *temporary_owner = state.temporary_owner_work;
        *persistent_owner = state.persistent_owner_initial;
        *lifecycle = state.lifecycle_initial;
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }
    *temporary_owner = state.temporary_owner_work;

    rome2_100ed3c0_nonempty_clear_step(
        &step, ROME2_100ED3C0_NONEMPTY_STEP_RUN_100DF270);
    step.argument_count = UINT32_C(3);
    step.argument0 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        state.guest_receiver.value);
    step.argument1 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        state.guest_packet.value);
    step.argument2 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        state.guest_descriptor.value);
    state.effects.emit_step(state.effects.context, step);

    state.child_return.value = UINT32_C(0);
    guest_status = rome2_port_100df270_run_platform_prefix_transcript(
        &state.frame_view,
        state.guest_receiver,
        state.guest_packet,
        &state.effects.child_prefix,
        &state.child_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.child_return.value != state.guest_receiver.value) {
        *temporary_owner = state.temporary_owner_work;
        *persistent_owner = state.persistent_owner_initial;
        *lifecycle = state.lifecycle_initial;
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }
    state.child_return.value = UINT32_C(0);
    guest_status = rome2_port_100df270_project_headless_empty_state(
        &state.frame_view,
        state.guest_receiver,
        state.guest_packet,
        &state.child_return);
    if (guest_status != ROME2_GUEST_OK ||
        state.child_return.value != state.guest_receiver.value) {
        *temporary_owner = state.temporary_owner_work;
        *persistent_owner = state.persistent_owner_initial;
        *lifecycle = state.lifecycle_initial;
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }

    state.owned_delegate_context.persistent_descriptor_view =
        &state.persistent_descriptor_view;
    state.owned_delegate_context.temporary_descriptor_view =
        &state.frame_view;
    state.owned_delegate_context.temporary_heap_view =
        &state.temporary_heap_view;
    state.owned_delegate_context.persistent_heap_view =
        &state.persistent_heap_view;
    state.owned_delegate_context.effects =
        &state.effects.persistent_owned;
    state.owned_delegate_context.temporary_owner =
        &state.temporary_owner_work;
    state.owned_delegate_context.persistent_owner_work =
        &state.persistent_owner_work;
    state.owned_delegate_context.lifecycle_work = &state.lifecycle_work;
    state.owned_delegate_context.persistent_owner_external = persistent_owner;
    state.owned_delegate_context.lifecycle_external = lifecycle;
    state.owned_delegate_context.expected_destination.value =
        ROME2_PORT_100F2750_FIRST_USE_DESTINATION;
    state.owned_delegate_context.expected_source = state.guest_descriptor;
    state.owned_delegate_context.guest_return.value = UINT32_C(0xdeadbeef);
    state.owned_delegate_context.owned_status =
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    state.suffix_owned_delegate.execute =
        rome2_100ed3c0_nonempty_execute_first_use;
    state.suffix_owned_delegate.context = &state.owned_delegate_context;
    state.suffix_owned_delegate.context_byte_count =
        sizeof(state.owned_delegate_context);
    state.child_return.value = UINT32_C(0);
    guest_status = rome2_port_100df270_run_suffix_transcript_delegated(
        &state.selector_view,
        state.guest_receiver,
        state.guest_descriptor,
        &state.effects.child_suffix,
        &state.suffix_owned_delegate,
        &state.child_return);
    if (state.owned_delegate_context.call_count == UINT32_C(1) &&
        state.owned_delegate_context.owned_status !=
            ROME2_100F1BB0_OWNED_OK) {
        *temporary_owner = state.temporary_owner_work;
        *persistent_owner = state.persistent_owner_work;
        *lifecycle = state.lifecycle_work;
        return state.owned_delegate_context.owned_status;
    }
    if (guest_status != ROME2_GUEST_OK ||
        state.child_return.value != state.guest_receiver.value ||
        state.owned_delegate_context.call_count != UINT32_C(1)) {
        *temporary_owner = state.temporary_owner_work;
        *persistent_owner = state.persistent_owner_work;
        *lifecycle = state.lifecycle_work;
        return guest_status == ROME2_GUEST_OK
            ? ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID
            : rome2_100ed3c0_nonempty_from_guest(guest_status);
    }

    rome2_100ed3c0_nonempty_clear_step(
        &step, ROME2_100ED3C0_NONEMPTY_STEP_CLEANUP_OWNED_DESCRIPTOR);
    step.argument_count = UINT32_C(1);
    step.argument0 = rome2_100ed3c0_nonempty_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        state.guest_descriptor.value);
    state.effects.emit_step(state.effects.context, step);
    owned_status = rome2_port_100f1cc0_cleanup_owned_utf16(
        &state.frame_view,
        state.guest_descriptor,
        &state.temporary_heap_view,
        &state.effects.temporary_owned,
        temporary_owner);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) {
        state.temporary_owner_work = *temporary_owner;
        *persistent_owner = state.persistent_owner_work;
        *lifecycle = state.lifecycle_work;
        return owned_status;
    }

    state.temporary_owner_work = *temporary_owner;
    *persistent_owner = state.persistent_owner_work;
    *lifecycle = state.lifecycle_work;
    result_out->child_receiver = state.guest_receiver;
    result_out->child_packet = state.guest_packet;
    result_out->child_argument = state.guest_descriptor;
    result_out->next_original_pc = ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC;
    return ROME2_100F1BB0_OWNED_OK;
}

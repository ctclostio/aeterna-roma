#include "ported_100df270_platform_prefix_transcript.h"

#include <stddef.h>
#include <stdint.h>

#define ROME2_100DF270_PREFIX_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)

typedef struct rome2_100df270_prefix_span {
    uint64_t guest_start;
    uintptr_t host_start;
    uint64_t byte_count;
    uint64_t view_offset;
} rome2_100df270_prefix_span;

static rome2_guest_status rome2_100df270_prefix_validate_object(
    const void *object,
    size_t byte_count)
{
    uintptr_t address;

    if (object == NULL || byte_count == 0U) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    address = (uintptr_t)object;
    if (byte_count - 1U > UINTPTR_MAX - address) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    return ROME2_GUEST_OK;
}

static int rome2_100df270_prefix_ranges_overlap(
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

static rome2_guest_status rome2_100df270_prefix_validate_interval(
    const rome2_guest_write_view *view)
{
    uintptr_t host_address;

    if (view->host_base == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (view->byte_count > ROME2_100DF270_PREFIX_ADDRESS_SPACE_SIZE ||
        (uint64_t)view->guest_base + view->byte_count >
            ROME2_100DF270_PREFIX_ADDRESS_SPACE_SIZE) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    host_address = (uintptr_t)view->host_base;
    if (view->byte_count != 0 &&
        view->byte_count - UINT64_C(1) >
            (uint64_t)(UINTPTR_MAX - host_address)) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    return ROME2_GUEST_OK;
}

static int rome2_100df270_prefix_controls_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_100df270_prefix_effects *effects,
    const rome2_guest_addr32 *return_receiver_out)
{
    return
        rome2_100df270_prefix_ranges_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100df270_prefix_ranges_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)return_receiver_out,
            sizeof(*return_receiver_out)) ||
        rome2_100df270_prefix_ranges_overlap(
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects),
            (uint64_t)(uintptr_t)return_receiver_out,
            sizeof(*return_receiver_out));
}

static int rome2_100df270_prefix_backing_overlaps_controls(
    const rome2_guest_write_view *view,
    const rome2_guest_write_view *state_view,
    const rome2_100df270_prefix_effects *effects,
    const rome2_guest_addr32 *return_receiver_out)
{
    uint64_t host_start = (uint64_t)(uintptr_t)view->host_base;

    return
        rome2_100df270_prefix_ranges_overlap(
            host_start,
            view->byte_count,
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100df270_prefix_ranges_overlap(
            host_start,
            view->byte_count,
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100df270_prefix_ranges_overlap(
            host_start,
            view->byte_count,
            (uint64_t)(uintptr_t)return_receiver_out,
            sizeof(*return_receiver_out));
}

static rome2_guest_status rome2_100df270_prefix_resolve_span(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_start,
    uint32_t byte_count,
    rome2_100df270_prefix_span *span_out)
{
    uint64_t offset;

    if (span_out == NULL || byte_count == 0) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (guest_start.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if ((uint64_t)byte_count >
        ROME2_100DF270_PREFIX_ADDRESS_SPACE_SIZE -
            (uint64_t)guest_start.value) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    if (guest_start.value < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    offset = (uint64_t)guest_start.value - (uint64_t)view->guest_base;
    if (offset > view->byte_count ||
        (uint64_t)byte_count > view->byte_count - offset ||
        offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    span_out->guest_start = (uint64_t)guest_start.value;
    span_out->host_start =
        (uintptr_t)view->host_base + (uintptr_t)offset;
    span_out->byte_count = (uint64_t)byte_count;
    span_out->view_offset = offset;
    return ROME2_GUEST_OK;
}

static uint32_t rome2_100df270_prefix_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100df270_prefix_write_u32_le(
    uint8_t *bytes,
    uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static rome2_100df270_prefix_value rome2_100df270_prefix_make_value(
    rome2_100df270_prefix_value_kind kind,
    uint32_t value)
{
    rome2_100df270_prefix_value result;

    result.kind = kind;
    result.value = value;
    return result;
}

static void rome2_100df270_prefix_clear_step(
    rome2_100df270_prefix_step *step,
    rome2_100df270_prefix_step_kind kind)
{
    step->kind = kind;
    step->argument_count = UINT32_C(0);
    step->argument0 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_NONE, UINT32_C(0));
    step->argument1 = step->argument0;
    step->argument2 = step->argument0;
    step->argument3 = step->argument0;
    step->result_count = UINT32_C(0);
    step->result0 = step->argument0;
}

rome2_guest_status rome2_port_100df270_run_platform_prefix_transcript(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_packet,
    const rome2_100df270_prefix_effects *effects,
    rome2_guest_addr32 *return_receiver_out)
{
    rome2_guest_write_view state_snapshot;
    rome2_100df270_prefix_effects effects_snapshot;
    rome2_100df270_prefix_span receiver_span;
    rome2_100df270_prefix_span packet_span;
    rome2_100df270_prefix_step step;
    rome2_guest_addr32 guest_name;
    rome2_guest_addr32 guest_title;
    rome2_guest_addr32 guest_mutex;
    rome2_guest_status status;
    uint32_t instance_value;
    uint8_t allow_duplicate;

    status = rome2_100df270_prefix_validate_object(
        state_view, sizeof(*state_view));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100df270_prefix_validate_object(effects, sizeof(*effects));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100df270_prefix_validate_object(
        return_receiver_out, sizeof(*return_receiver_out));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if ((uintptr_t)state_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)effects % _Alignof(rome2_100df270_prefix_effects) != 0U ||
        (uintptr_t)return_receiver_out % _Alignof(rome2_guest_addr32) != 0U ||
        rome2_100df270_prefix_controls_overlap(
            state_view, effects, return_receiver_out)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    state_snapshot = *state_view;
    status = rome2_100df270_prefix_validate_interval(&state_snapshot);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if (rome2_100df270_prefix_backing_overlaps_controls(
            &state_snapshot, state_view, effects, return_receiver_out)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    effects_snapshot = *effects;
    if (effects_snapshot.emit_step == NULL ||
        effects_snapshot.context == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    status = rome2_100df270_prefix_resolve_span(
        &state_snapshot,
        guest_receiver,
        ROME2_PORT_100DF270_PREFIX_RECEIVER_BYTES,
        &receiver_span);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100df270_prefix_resolve_span(
        &state_snapshot,
        guest_packet,
        ROME2_PORT_100DF270_PREFIX_PACKET_BYTES,
        &packet_span);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if (rome2_100df270_prefix_ranges_overlap(
            receiver_span.guest_start,
            receiver_span.byte_count,
            packet_span.guest_start,
            packet_span.byte_count) ||
        rome2_100df270_prefix_ranges_overlap(
            (uint64_t)receiver_span.host_start,
            receiver_span.byte_count,
            (uint64_t)packet_span.host_start,
            packet_span.byte_count)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    status = rome2_guest_add_checked(
        guest_receiver,
        ROME2_PORT_100DF270_PREFIX_NAME_OFFSET,
        &guest_name);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_guest_add_checked(
        guest_receiver,
        ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET,
        &guest_title);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_guest_add_checked(
        guest_receiver,
        ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET,
        &guest_mutex);
    if (status != ROME2_GUEST_OK) {
        return status;
    }

    instance_value = rome2_100df270_prefix_read_u32_le(
        state_snapshot.host_base + (size_t)packet_span.view_offset);
    allow_duplicate = state_snapshot.host_base[
        (size_t)packet_span.view_offset +
        (size_t)ROME2_PORT_100DF270_PREFIX_ALLOW_DUPLICATE_OFFSET];

    rome2_100df270_prefix_write_u32_le(
        state_snapshot.host_base + (size_t)receiver_span.view_offset +
            (size_t)ROME2_PORT_100DF270_PREFIX_INSTANCE_OFFSET,
        instance_value);
    rome2_100df270_prefix_write_u32_le(
        state_snapshot.host_base + (size_t)receiver_span.view_offset,
        ROME2_PORT_100DF270_PREFIX_INITIAL_VTABLE);

    rome2_100df270_prefix_clear_step(
        &step, ROME2_100DF270_PREFIX_STEP_LOAD_TITLE);
    step.argument_count = UINT32_C(4);
    step.argument0 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_OPAQUE32, instance_value);
    step.argument1 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR,
        ROME2_PORT_100DF270_PREFIX_RESOURCE_TITLE);
    step.argument2 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY, guest_title.value);
    step.argument3 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR,
        ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_prefix_clear_step(
        &step, ROME2_100DF270_PREFIX_STEP_LOAD_NAME);
    step.argument_count = UINT32_C(4);
    step.argument0 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_OPAQUE32, instance_value);
    step.argument1 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR,
        ROME2_PORT_100DF270_PREFIX_RESOURCE_NAME);
    step.argument2 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY, guest_name.value);
    step.argument3 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR,
        ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_prefix_clear_step(
        &step, ROME2_100DF270_PREFIX_STEP_FORMAT_MUTEX_NAME);
    step.argument_count = UINT32_C(4);
    step.argument0 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER,
        ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID);
    step.argument1 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR,
        ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY);
    step.argument2 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
        ROME2_PORT_100DF270_PREFIX_MUTEX_FORMAT);
    step.argument3 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY, guest_name.value);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_prefix_clear_step(
        &step, ROME2_100DF270_PREFIX_STEP_CREATE_MUTEX);
    step.argument_count = UINT32_C(3);
    step.argument0 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0));
    step.argument1 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(1));
    step.argument2 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER,
        ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID);
    step.result_count = UINT32_C(1);
    step.result0 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_OPAQUE32,
        effects_snapshot.created_mutex);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_prefix_write_u32_le(
        state_snapshot.host_base + (size_t)receiver_span.view_offset +
            (size_t)ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET,
        effects_snapshot.created_mutex);

    rome2_100df270_prefix_clear_step(
        &step, ROME2_100DF270_PREFIX_STEP_GET_LAST_ERROR);
    step.result_count = UINT32_C(1);
    step.result0 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR,
        effects_snapshot.last_error);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    if (effects_snapshot.last_error ==
            ROME2_PORT_100DF270_PREFIX_ERROR_ALREADY_EXISTS &&
        allow_duplicate == UINT8_C(0)) {
        rome2_100df270_prefix_clear_step(
            &step, ROME2_100DF270_PREFIX_STEP_FORMAT_DUPLICATE_MESSAGE);
        step.argument_count = UINT32_C(4);
        step.argument0 = rome2_100df270_prefix_make_value(
            ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER,
            ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID);
        step.argument1 = rome2_100df270_prefix_make_value(
            ROME2_100DF270_PREFIX_VALUE_SCALAR,
            ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY);
        step.argument2 = rome2_100df270_prefix_make_value(
            ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
            ROME2_PORT_100DF270_PREFIX_DUPLICATE_FORMAT);
        step.argument3 = rome2_100df270_prefix_make_value(
            ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY, guest_name.value);
        effects_snapshot.emit_step(effects_snapshot.context, step);

        rome2_100df270_prefix_clear_step(
            &step, ROME2_100DF270_PREFIX_STEP_SHOW_DUPLICATE_MESSAGE);
        step.argument_count = UINT32_C(4);
        step.argument0 = rome2_100df270_prefix_make_value(
            ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0));
        step.argument1 = rome2_100df270_prefix_make_value(
            ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER,
            ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID);
        step.argument2 = rome2_100df270_prefix_make_value(
            ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
            ROME2_PORT_100DF270_PREFIX_MUTEX_CAPTION);
        step.argument3 = rome2_100df270_prefix_make_value(
            ROME2_100DF270_PREFIX_VALUE_SCALAR,
            ROME2_PORT_100DF270_PREFIX_MESSAGEBOX_FLAGS);
        effects_snapshot.emit_step(effects_snapshot.context, step);

        rome2_100df270_prefix_clear_step(
            &step, ROME2_100DF270_PREFIX_STEP_TERMINATE_PROCESS);
        effects_snapshot.emit_step(effects_snapshot.context, step);
    }

    rome2_100df270_prefix_clear_step(
        &step, ROME2_100DF270_PREFIX_STEP_GET_MOUSE_TRAILS);
    step.argument_count = UINT32_C(4);
    step.argument0 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR,
        ROME2_PORT_100DF270_PREFIX_SPI_GETMOUSETRAILS);
    step.argument1 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0));
    step.argument2 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
        ROME2_PORT_100DF270_PREFIX_MOUSE_TRAILS_GLOBAL);
    step.argument3 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0));
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_prefix_clear_step(
        &step, ROME2_100DF270_PREFIX_STEP_SET_MOUSE_TRAILS);
    step.argument_count = UINT32_C(4);
    step.argument0 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR,
        ROME2_PORT_100DF270_PREFIX_SPI_SETMOUSETRAILS);
    step.argument1 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0));
    step.argument2 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0));
    step.argument3 = rome2_100df270_prefix_make_value(
        ROME2_100DF270_PREFIX_VALUE_SCALAR, UINT32_C(0));
    effects_snapshot.emit_step(effects_snapshot.context, step);

    return_receiver_out->value = guest_receiver.value;
    return ROME2_GUEST_OK;
}

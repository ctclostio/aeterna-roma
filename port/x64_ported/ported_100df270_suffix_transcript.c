#include "ported_100df270_suffix_transcript.h"

#include <stddef.h>
#include <stdint.h>

#define ROME2_100DF270_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100DF270_RESULT_CELL_BYTES UINT64_C(4)

typedef struct rome2_100df270_span {
    uint64_t guest_start;
    uintptr_t host_start;
    uint64_t byte_count;
    uint64_t view_offset;
} rome2_100df270_span;

static rome2_guest_status rome2_100df270_validate_object(
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

static int rome2_100df270_ranges_overlap(
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

static rome2_guest_status rome2_100df270_validate_interval(
    const rome2_guest_write_view *view)
{
    uintptr_t host_address;

    if (view->host_base == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (view->byte_count > ROME2_100DF270_ADDRESS_SPACE_SIZE ||
        (uint64_t)view->guest_base + view->byte_count >
            ROME2_100DF270_ADDRESS_SPACE_SIZE) {
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

static int rome2_100df270_control_objects_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_100df270_suffix_effects *effects,
    const rome2_guest_addr32 *return_receiver_out)
{
    return
        rome2_100df270_ranges_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100df270_ranges_overlap(
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view),
            (uint64_t)(uintptr_t)return_receiver_out,
            sizeof(*return_receiver_out)) ||
        rome2_100df270_ranges_overlap(
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects),
            (uint64_t)(uintptr_t)return_receiver_out,
            sizeof(*return_receiver_out));
}

static int rome2_100df270_host_interval_overlaps_controls(
    const rome2_guest_write_view *view,
    const rome2_guest_write_view *state_view,
    const rome2_100df270_suffix_effects *effects,
    const rome2_guest_addr32 *return_receiver_out)
{
    uint64_t host_start = (uint64_t)(uintptr_t)view->host_base;

    return
        rome2_100df270_ranges_overlap(
            host_start,
            view->byte_count,
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100df270_ranges_overlap(
            host_start,
            view->byte_count,
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100df270_ranges_overlap(
            host_start,
            view->byte_count,
            (uint64_t)(uintptr_t)return_receiver_out,
            sizeof(*return_receiver_out));
}

static int rome2_100df270_delegated_controls_overlap(
    const rome2_guest_write_view *state_view,
    const rome2_100df270_suffix_effects *effects,
    const rome2_100df270_suffix_100f2750_delegate *delegate,
    const rome2_guest_addr32 *return_receiver_out)
{
    return
        rome2_100df270_control_objects_overlap(
            state_view, effects, return_receiver_out) ||
        rome2_100df270_ranges_overlap(
            (uint64_t)(uintptr_t)delegate,
            sizeof(*delegate),
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100df270_ranges_overlap(
            (uint64_t)(uintptr_t)delegate,
            sizeof(*delegate),
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100df270_ranges_overlap(
            (uint64_t)(uintptr_t)delegate,
            sizeof(*delegate),
            (uint64_t)(uintptr_t)return_receiver_out,
            sizeof(*return_receiver_out));
}

static int rome2_100df270_delegated_state_overlaps_controls(
    const rome2_guest_write_view *view,
    const rome2_guest_write_view *state_view,
    const rome2_100df270_suffix_effects *effects,
    const rome2_100df270_suffix_100f2750_delegate *delegate,
    const rome2_guest_addr32 *return_receiver_out)
{
    return
        rome2_100df270_host_interval_overlaps_controls(
            view, state_view, effects, return_receiver_out) ||
        rome2_100df270_ranges_overlap(
            (uint64_t)(uintptr_t)view->host_base,
            view->byte_count,
            (uint64_t)(uintptr_t)delegate,
            sizeof(*delegate));
}

static rome2_guest_status rome2_100df270_validate_delegate_context(
    const rome2_100df270_suffix_100f2750_delegate *delegate_snapshot,
    const rome2_100df270_suffix_100f2750_delegate *delegate_control,
    const rome2_guest_write_view *view,
    const rome2_guest_write_view *state_view,
    const rome2_100df270_suffix_effects *effects,
    const rome2_guest_addr32 *return_receiver_out)
{
    uint64_t context_start;

    if (delegate_snapshot->execute == NULL ||
        delegate_snapshot->context == NULL ||
        delegate_snapshot->context_byte_count == 0) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    context_start = (uint64_t)(uintptr_t)delegate_snapshot->context;
    if (delegate_snapshot->context_byte_count - UINT64_C(1) >
        (uint64_t)(UINTPTR_MAX - (uintptr_t)delegate_snapshot->context)) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    if (rome2_100df270_ranges_overlap(
            context_start,
            delegate_snapshot->context_byte_count,
            (uint64_t)(uintptr_t)view->host_base,
            view->byte_count) ||
        rome2_100df270_ranges_overlap(
            context_start,
            delegate_snapshot->context_byte_count,
            (uint64_t)(uintptr_t)state_view,
            sizeof(*state_view)) ||
        rome2_100df270_ranges_overlap(
            context_start,
            delegate_snapshot->context_byte_count,
            (uint64_t)(uintptr_t)effects,
            sizeof(*effects)) ||
        rome2_100df270_ranges_overlap(
            context_start,
            delegate_snapshot->context_byte_count,
            (uint64_t)(uintptr_t)delegate_control,
            sizeof(*delegate_control)) ||
        rome2_100df270_ranges_overlap(
            context_start,
            delegate_snapshot->context_byte_count,
            (uint64_t)(uintptr_t)return_receiver_out,
            sizeof(*return_receiver_out))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    return ROME2_GUEST_OK;
}

static rome2_guest_status rome2_100df270_resolve_result_cell(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_cell,
    rome2_100df270_span *span_out)
{
    uint64_t offset;

    if (span_out == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (guest_cell.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (ROME2_100DF270_RESULT_CELL_BYTES >
        ROME2_100DF270_ADDRESS_SPACE_SIZE - (uint64_t)guest_cell.value) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    if (guest_cell.value < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    offset = (uint64_t)guest_cell.value - (uint64_t)view->guest_base;
    if (offset > view->byte_count ||
        ROME2_100DF270_RESULT_CELL_BYTES > view->byte_count - offset ||
        offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    span_out->guest_start = (uint64_t)guest_cell.value;
    span_out->host_start =
        (uintptr_t)view->host_base + (uintptr_t)offset;
    span_out->byte_count = ROME2_100DF270_RESULT_CELL_BYTES;
    span_out->view_offset = offset;
    return ROME2_GUEST_OK;
}

static uint32_t rome2_100df270_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100df270_write_u32_le(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void rome2_100df270_clear_step(rome2_100df270_suffix_step *step)
{
    step->argument_count = UINT32_C(0);
    step->argument0 = UINT32_C(0);
    step->argument1 = UINT32_C(0);
    step->result_count = UINT32_C(0);
    step->result0 = UINT32_C(0);
    step->dispatch_vtable = UINT32_C(0);
    step->dispatch_slot_offset = UINT32_C(0);
    step->observed_value = UINT32_C(0);
}

static void rome2_100df270_emit_conditional_call(
    const rome2_100df270_suffix_effects *effects,
    rome2_100df270_suffix_step *step,
    uint32_t argument)
{
    rome2_100df270_clear_step(step);
    step->kind = ROME2_100DF270_SUFFIX_STEP_CALL_101046D0;
    step->argument_count = UINT32_C(1);
    step->argument0 = argument;
    effects->emit_step(effects->context, *step);
}

rome2_guest_status rome2_port_100df270_run_suffix_transcript(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100df270_suffix_effects *effects,
    rome2_guest_addr32 *return_receiver_out)
{
    rome2_guest_write_view state_snapshot;
    rome2_100df270_suffix_effects effects_snapshot;
    rome2_100df270_suffix_step step;
    rome2_100df270_span first_result_span;
    rome2_100df270_span second_result_span;
    rome2_guest_addr32 adjusted_100e8240_result;
    rome2_guest_addr32 owner_field;
    rome2_guest_status status;
    uint32_t first_result_value;

    status = rome2_100df270_validate_object(
        state_view, sizeof(*state_view));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100df270_validate_object(effects, sizeof(*effects));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100df270_validate_object(
        return_receiver_out, sizeof(*return_receiver_out));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if ((uintptr_t)state_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)effects %
            _Alignof(rome2_100df270_suffix_effects) != 0U ||
        (uintptr_t)return_receiver_out % _Alignof(rome2_guest_addr32) != 0U ||
        rome2_100df270_control_objects_overlap(
            state_view, effects, return_receiver_out)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    state_snapshot = *state_view;
    status = rome2_100df270_validate_interval(&state_snapshot);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if (rome2_100df270_host_interval_overlaps_controls(
            &state_snapshot, state_view, effects, return_receiver_out)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    effects_snapshot = *effects;
    if (effects_snapshot.emit_step == NULL ||
        effects_snapshot.context == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (effects_snapshot.result_100e8240.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (effects_snapshot.result_100e8240.value !=
        ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    status = rome2_guest_add_checked(
        effects_snapshot.result_100e8240,
        ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET,
        &adjusted_100e8240_result);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_guest_add_checked(
        guest_receiver,
        ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET,
        &owner_field);
    if (status != ROME2_GUEST_OK) {
        return status;
    }

    status = rome2_100df270_resolve_result_cell(
        &state_snapshot,
        effects_snapshot.first_selector_result,
        &first_result_span);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100df270_resolve_result_cell(
        &state_snapshot,
        effects_snapshot.second_selector_result,
        &second_result_span);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    first_result_value = rome2_100df270_read_u32_le(
        state_snapshot.host_base + (size_t)first_result_span.view_offset);

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_PUBLISH_RECEIVER;
    step.argument_count = UINT32_C(2);
    step.argument0 = ROME2_PORT_100DF270_SUFFIX_GLOBAL_RECEIVER;
    step.argument1 = guest_receiver.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_CALL_100E8240;
    step.argument_count = UINT32_C(1);
    step.argument0 = guest_argument.value;
    step.result_count = UINT32_C(1);
    step.result0 = effects_snapshot.result_100e8240.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_CALL_100F2750;
    step.argument_count = UINT32_C(2);
    step.argument0 = adjusted_100e8240_result.value;
    step.argument1 = guest_argument.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0;
    step.argument_count = UINT32_C(1);
    step.argument0 = guest_receiver.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_FIRST;
    step.argument_count = UINT32_C(2);
    step.argument0 = owner_field.value;
    step.argument1 = ROME2_PORT_100DF270_SUFFIX_SELECTOR;
    step.result_count = UINT32_C(1);
    step.result0 = effects_snapshot.first_selector_result.value;
    step.dispatch_vtable = ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE;
    step.dispatch_slot_offset =
        ROME2_PORT_100DF270_SUFFIX_VIRTUAL_SLOT_OFFSET;
    step.observed_value = first_result_value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    if (first_result_value != ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER) {
        rome2_100df270_emit_conditional_call(
            &effects_snapshot, &step, UINT32_C(0x2d));
        rome2_100df270_emit_conditional_call(
            &effects_snapshot, &step, UINT32_C(0x12));
        rome2_100df270_emit_conditional_call(
            &effects_snapshot, &step, UINT32_C(0x16));
        rome2_100df270_emit_conditional_call(
            &effects_snapshot, &step, UINT32_C(0x21));
    }

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_SECOND;
    step.argument_count = UINT32_C(2);
    step.argument0 = owner_field.value;
    step.argument1 = ROME2_PORT_100DF270_SUFFIX_SELECTOR;
    step.result_count = UINT32_C(1);
    step.result0 = effects_snapshot.second_selector_result.value;
    step.dispatch_vtable = ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE;
    step.dispatch_slot_offset =
        ROME2_PORT_100DF270_SUFFIX_VIRTUAL_SLOT_OFFSET;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_write_u32_le(
        state_snapshot.host_base + (size_t)second_result_span.view_offset,
        ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER);

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER;
    step.argument_count = UINT32_C(2);
    step.argument0 = effects_snapshot.second_selector_result.value;
    step.argument1 = ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    return_receiver_out->value = guest_receiver.value;
    return ROME2_GUEST_OK;
}

rome2_guest_status rome2_port_100df270_run_suffix_transcript_delegated(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100df270_suffix_effects *effects,
    const rome2_100df270_suffix_100f2750_delegate *delegate,
    rome2_guest_addr32 *return_receiver_out)
{
    rome2_guest_write_view state_snapshot;
    rome2_100df270_suffix_effects effects_snapshot;
    rome2_100df270_suffix_100f2750_delegate delegate_snapshot;
    rome2_100df270_suffix_step step;
    rome2_100df270_span first_result_span;
    rome2_100df270_span second_result_span;
    rome2_guest_addr32 adjusted_100e8240_result;
    rome2_guest_addr32 owner_field;
    rome2_guest_status status;
    uint32_t first_result_value;

    status = rome2_100df270_validate_object(
        state_view, sizeof(*state_view));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100df270_validate_object(effects, sizeof(*effects));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100df270_validate_object(delegate, sizeof(*delegate));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100df270_validate_object(
        return_receiver_out, sizeof(*return_receiver_out));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if ((uintptr_t)state_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)effects %
            _Alignof(rome2_100df270_suffix_effects) != 0U ||
        (uintptr_t)delegate %
            _Alignof(rome2_100df270_suffix_100f2750_delegate) != 0U ||
        (uintptr_t)return_receiver_out % _Alignof(rome2_guest_addr32) != 0U ||
        rome2_100df270_delegated_controls_overlap(
            state_view, effects, delegate, return_receiver_out)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    state_snapshot = *state_view;
    status = rome2_100df270_validate_interval(&state_snapshot);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if (rome2_100df270_delegated_state_overlaps_controls(
            &state_snapshot,
            state_view,
            effects,
            delegate,
            return_receiver_out)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    effects_snapshot = *effects;
    if (effects_snapshot.emit_step == NULL ||
        effects_snapshot.context == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (effects_snapshot.result_100e8240.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (effects_snapshot.result_100e8240.value !=
        ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    delegate_snapshot = *delegate;
    status = rome2_100df270_validate_delegate_context(
        &delegate_snapshot,
        delegate,
        &state_snapshot,
        state_view,
        effects,
        return_receiver_out);
    if (status != ROME2_GUEST_OK) {
        return status;
    }

    status = rome2_guest_add_checked(
        effects_snapshot.result_100e8240,
        ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET,
        &adjusted_100e8240_result);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_guest_add_checked(
        guest_receiver,
        ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET,
        &owner_field);
    if (status != ROME2_GUEST_OK) {
        return status;
    }

    status = rome2_100df270_resolve_result_cell(
        &state_snapshot,
        effects_snapshot.first_selector_result,
        &first_result_span);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100df270_resolve_result_cell(
        &state_snapshot,
        effects_snapshot.second_selector_result,
        &second_result_span);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    first_result_value = rome2_100df270_read_u32_le(
        state_snapshot.host_base + (size_t)first_result_span.view_offset);

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_PUBLISH_RECEIVER;
    step.argument_count = UINT32_C(2);
    step.argument0 = ROME2_PORT_100DF270_SUFFIX_GLOBAL_RECEIVER;
    step.argument1 = guest_receiver.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_CALL_100E8240;
    step.argument_count = UINT32_C(1);
    step.argument0 = guest_argument.value;
    step.result_count = UINT32_C(1);
    step.result0 = effects_snapshot.result_100e8240.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_CALL_100F2750;
    step.argument_count = UINT32_C(2);
    step.argument0 = adjusted_100e8240_result.value;
    step.argument1 = guest_argument.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);
    status = delegate_snapshot.execute(
        delegate_snapshot.context,
        adjusted_100e8240_result,
        guest_argument);
    if (status != ROME2_GUEST_OK) {
        return status;
    }

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0;
    step.argument_count = UINT32_C(1);
    step.argument0 = guest_receiver.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_FIRST;
    step.argument_count = UINT32_C(2);
    step.argument0 = owner_field.value;
    step.argument1 = ROME2_PORT_100DF270_SUFFIX_SELECTOR;
    step.result_count = UINT32_C(1);
    step.result0 = effects_snapshot.first_selector_result.value;
    step.dispatch_vtable = ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE;
    step.dispatch_slot_offset =
        ROME2_PORT_100DF270_SUFFIX_VIRTUAL_SLOT_OFFSET;
    step.observed_value = first_result_value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    if (first_result_value != ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER) {
        rome2_100df270_emit_conditional_call(
            &effects_snapshot, &step, UINT32_C(0x2d));
        rome2_100df270_emit_conditional_call(
            &effects_snapshot, &step, UINT32_C(0x12));
        rome2_100df270_emit_conditional_call(
            &effects_snapshot, &step, UINT32_C(0x16));
        rome2_100df270_emit_conditional_call(
            &effects_snapshot, &step, UINT32_C(0x21));
    }

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_SECOND;
    step.argument_count = UINT32_C(2);
    step.argument0 = owner_field.value;
    step.argument1 = ROME2_PORT_100DF270_SUFFIX_SELECTOR;
    step.result_count = UINT32_C(1);
    step.result0 = effects_snapshot.second_selector_result.value;
    step.dispatch_vtable = ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE;
    step.dispatch_slot_offset =
        ROME2_PORT_100DF270_SUFFIX_VIRTUAL_SLOT_OFFSET;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100df270_write_u32_le(
        state_snapshot.host_base + (size_t)second_result_span.view_offset,
        ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER);

    rome2_100df270_clear_step(&step);
    step.kind = ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER;
    step.argument_count = UINT32_C(2);
    step.argument0 = effects_snapshot.second_selector_result.value;
    step.argument1 = ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    return_receiver_out->value = guest_receiver.value;
    return ROME2_GUEST_OK;
}

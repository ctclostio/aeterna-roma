#include "ported_100ed471_ordinary_lifecycle.h"

#include <stddef.h>
#include <stdint.h>

#define ROME2_100ED471_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100ED471_EXTERNAL_CONTROL_COUNT 4U
#define ROME2_100ED471_PRIVATE_CONTROL_COUNT 18U
#define ROME2_100ED471_CLEANUP_COUNT 4U

typedef struct rome2_100ed471_host_span {
    uint64_t start;
    uint64_t byte_count;
} rome2_100ed471_host_span;

static rome2_guest_status rome2_100ed471_validate_object(
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

static int rome2_100ed471_ranges_overlap(
    uint64_t first_start,
    uint64_t first_size,
    uint64_t second_start,
    uint64_t second_size)
{
    if (first_size == 0U || second_size == 0U) {
        return 0;
    }
    if (first_start >= second_start) {
        return first_start - second_start < second_size;
    }
    return second_start - first_start < first_size;
}

static rome2_guest_status rome2_100ed471_validate_interval(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100ED471_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100ED471_ADDRESS_SPACE_SIZE) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    host_address = (uintptr_t)host_base;
    if (byte_count != 0U &&
        byte_count - UINT64_C(1) >
            (uint64_t)(UINTPTR_MAX - host_address)) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    return ROME2_GUEST_OK;
}

static int rome2_100ed471_controls_overlap(
    const rome2_100ed471_host_span *controls,
    size_t count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < count; ++first) {
        for (second = first + 1U; second < count; ++second) {
            if (rome2_100ed471_ranges_overlap(
                    controls[first].start,
                    controls[first].byte_count,
                    controls[second].start,
                    controls[second].byte_count)) {
                return 1;
            }
        }
    }
    return 0;
}

static int rome2_100ed471_span_overlaps_controls(
    const rome2_100ed471_host_span *span,
    const rome2_100ed471_host_span *controls,
    size_t count)
{
    size_t index;

    for (index = 0U; index < count; ++index) {
        if (rome2_100ed471_ranges_overlap(
                span->start,
                span->byte_count,
                controls[index].start,
                controls[index].byte_count)) {
            return 1;
        }
    }
    return 0;
}

static int rome2_100ed471_context_overlaps(
    const void *context,
    const rome2_100ed471_host_span *frame_backing,
    const rome2_100ed471_host_span *dispatch_backing,
    const rome2_100ed471_host_span *controls,
    size_t control_count)
{
    rome2_100ed471_host_span point;

    point.start = (uint64_t)(uintptr_t)context;
    point.byte_count = UINT64_C(1);
    return
        rome2_100ed471_ranges_overlap(
            point.start,
            point.byte_count,
            frame_backing->start,
            frame_backing->byte_count) ||
        rome2_100ed471_ranges_overlap(
            point.start,
            point.byte_count,
            dispatch_backing->start,
            dispatch_backing->byte_count) ||
        rome2_100ed471_span_overlaps_controls(
            &point, controls, control_count);
}

static uint32_t rome2_100ed471_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100ed471_write_u32_le(
    uint8_t *bytes,
    uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void rome2_100ed471_clear_step(
    rome2_100ed471_step *step,
    rome2_100ed471_step_kind kind)
{
    step->kind = kind;
    step->argument_count = UINT32_C(0);
    step->argument0 = UINT32_C(0);
    step->argument1 = UINT32_C(0);
    step->argument2 = UINT32_C(0);
    step->result_count = UINT32_C(0);
    step->result0 = UINT32_C(0);
    step->result1 = UINT32_C(0);
    step->dispatch_vtable = UINT32_C(0);
    step->dispatch_slot_offset = UINT32_C(0);
    step->dispatch_target = UINT32_C(0);
}

static int rome2_100ed471_empty_descriptor(
    const uint8_t *frame,
    uint32_t offset)
{
    return
        rome2_100ed471_read_u32_le(frame + offset) == UINT32_C(0) &&
        rome2_100ed471_read_u32_le(frame + offset + UINT32_C(4)) ==
            UINT32_C(0) &&
        rome2_100ed471_read_u32_le(frame + offset + UINT32_C(8)) ==
            ROME2_PORT_100F1CC0_SENTINEL;
}

static rome2_guest_status rome2_100ed471_add(
    rome2_guest_addr32 base,
    uint32_t offset,
    rome2_guest_addr32 *result)
{
    return rome2_guest_add_checked(base, offset, result);
}

rome2_guest_status rome2_port_100ed471_run_ordinary_lifecycle(
    const rome2_guest_write_view *frame_view,
    rome2_guest_addr32 guest_frame,
    const rome2_guest_read_view *dispatch_view,
    rome2_guest_addr32 dispatch_receiver,
    uint32_t max_poll_calls,
    const rome2_100ed471_lifecycle_effects *effects,
    rome2_100ed471_lifecycle_result *result_out)
{
    static const uint32_t cleanup_offsets[ROME2_100ED471_CLEANUP_COUNT] = {
        ROME2_PORT_100ED471_CLEANUP0_OFFSET,
        ROME2_PORT_100ED471_CLEANUP1_OFFSET,
        ROME2_PORT_100ED471_CLEANUP2_OFFSET,
        ROME2_PORT_100ED471_CLEANUP3_OFFSET
    };
    rome2_guest_write_view frame_snapshot;
    rome2_guest_read_view dispatch_snapshot;
    rome2_100ed471_lifecycle_effects effects_snapshot;
    rome2_100ed471_lifecycle_result result;
    rome2_100ed471_host_span
        controls[ROME2_100ED471_EXTERNAL_CONTROL_COUNT];
    rome2_100ed471_host_span
        private_controls[ROME2_100ED471_PRIVATE_CONTROL_COUNT];
    rome2_100ed471_host_span frame_backing;
    rome2_100ed471_host_span dispatch_backing;
    rome2_guest_addr32 guest_receiver;
    rome2_guest_addr32 guest_timestamp;
    rome2_guest_addr32 guest_timestamp_copy;
    rome2_guest_addr32 guest_cleanup[ROME2_100ED471_CLEANUP_COUNT];
    rome2_guest_addr32 dispatch_vtable;
    rome2_guest_addr32 dispatch_slot;
    rome2_guest_addr32 dispatch_target;
    rome2_guest_addr32 dispatch_receiver_snapshot;
    rome2_100ed471_lifecycle_result *result_destination;
    rome2_100ed471_step step;
    rome2_guest_status status;
    uint8_t *frame;
    uint32_t poll_index;
    size_t cleanup_index;

    status = rome2_100ed471_validate_object(frame_view, sizeof(*frame_view));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed471_validate_object(
        dispatch_view, sizeof(*dispatch_view));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed471_validate_object(effects, sizeof(*effects));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed471_validate_object(result_out, sizeof(*result_out));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if ((uintptr_t)frame_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)dispatch_view % _Alignof(rome2_guest_read_view) != 0U ||
        (uintptr_t)effects % _Alignof(rome2_100ed471_lifecycle_effects) != 0U ||
        (uintptr_t)result_out % _Alignof(rome2_100ed471_lifecycle_result) !=
            0U) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    controls[0].start = (uint64_t)(uintptr_t)frame_view;
    controls[0].byte_count = sizeof(*frame_view);
    controls[1].start = (uint64_t)(uintptr_t)dispatch_view;
    controls[1].byte_count = sizeof(*dispatch_view);
    controls[2].start = (uint64_t)(uintptr_t)effects;
    controls[2].byte_count = sizeof(*effects);
    controls[3].start = (uint64_t)(uintptr_t)result_out;
    controls[3].byte_count = sizeof(*result_out);
    if (rome2_100ed471_controls_overlap(
            controls, ROME2_100ED471_EXTERNAL_CONTROL_COUNT)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    frame_snapshot = *frame_view;
    dispatch_snapshot = *dispatch_view;
    effects_snapshot = *effects;
    dispatch_receiver_snapshot = dispatch_receiver;
    result_destination = result_out;
    status = rome2_100ed471_validate_interval(
        frame_snapshot.host_base,
        frame_snapshot.guest_base,
        frame_snapshot.byte_count);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed471_validate_interval(
        dispatch_snapshot.host_base,
        dispatch_snapshot.guest_base,
        dispatch_snapshot.byte_count);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if (guest_frame.value == UINT32_C(0) ||
        dispatch_receiver_snapshot.value == UINT32_C(0) ||
        frame_snapshot.guest_base != guest_frame.value ||
        frame_snapshot.byte_count != ROME2_PORT_100ED471_FRAME_BYTES ||
        max_poll_calls == UINT32_C(0) ||
        max_poll_calls > ROME2_PORT_100ED471_MAX_POLL_CALLS ||
        effects_snapshot.emit_step == NULL ||
        effects_snapshot.context == NULL ||
        effects_snapshot.poll_result_count == UINT32_C(0) ||
        effects_snapshot.poll_result_count > max_poll_calls) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    for (poll_index = UINT32_C(0);
         poll_index < effects_snapshot.poll_result_count;
         ++poll_index) {
        const uint32_t expected =
            poll_index + UINT32_C(1) ==
                    effects_snapshot.poll_result_count
                ? UINT32_C(2)
                : UINT32_C(0);
        if (effects_snapshot.poll_results[poll_index] != expected) {
            return ROME2_GUEST_BAD_ARGUMENT;
        }
    }

    frame_backing.start = (uint64_t)(uintptr_t)frame_snapshot.host_base;
    frame_backing.byte_count = frame_snapshot.byte_count;
    dispatch_backing.start =
        (uint64_t)(uintptr_t)dispatch_snapshot.host_base;
    dispatch_backing.byte_count = dispatch_snapshot.byte_count;
    if (rome2_100ed471_ranges_overlap(
            frame_backing.start,
            frame_backing.byte_count,
            dispatch_backing.start,
            dispatch_backing.byte_count) ||
        rome2_100ed471_ranges_overlap(
            (uint64_t)frame_snapshot.guest_base,
            frame_snapshot.byte_count,
            (uint64_t)dispatch_snapshot.guest_base,
            dispatch_snapshot.byte_count) ||
        rome2_100ed471_span_overlaps_controls(
            &frame_backing,
            controls,
            ROME2_100ED471_EXTERNAL_CONTROL_COUNT) ||
        rome2_100ed471_span_overlaps_controls(
            &dispatch_backing,
            controls,
            ROME2_100ED471_EXTERNAL_CONTROL_COUNT) ||
        rome2_100ed471_context_overlaps(
            effects_snapshot.context,
            &frame_backing,
            &dispatch_backing,
            controls,
            ROME2_100ED471_EXTERNAL_CONTROL_COUNT)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    private_controls[0].start =
        (uint64_t)(uintptr_t)&frame_snapshot;
    private_controls[0].byte_count = sizeof(frame_snapshot);
    private_controls[1].start =
        (uint64_t)(uintptr_t)&dispatch_snapshot;
    private_controls[1].byte_count = sizeof(dispatch_snapshot);
    private_controls[2].start =
        (uint64_t)(uintptr_t)&effects_snapshot;
    private_controls[2].byte_count = sizeof(effects_snapshot);
    private_controls[3].start = (uint64_t)(uintptr_t)&result;
    private_controls[3].byte_count = sizeof(result);
    private_controls[4].start = (uint64_t)(uintptr_t)&guest_receiver;
    private_controls[4].byte_count = sizeof(guest_receiver);
    private_controls[5].start = (uint64_t)(uintptr_t)&guest_timestamp;
    private_controls[5].byte_count = sizeof(guest_timestamp);
    private_controls[6].start =
        (uint64_t)(uintptr_t)&guest_timestamp_copy;
    private_controls[6].byte_count = sizeof(guest_timestamp_copy);
    private_controls[7].start = (uint64_t)(uintptr_t)guest_cleanup;
    private_controls[7].byte_count = sizeof(guest_cleanup);
    private_controls[8].start = (uint64_t)(uintptr_t)&dispatch_vtable;
    private_controls[8].byte_count = sizeof(dispatch_vtable);
    private_controls[9].start = (uint64_t)(uintptr_t)&dispatch_slot;
    private_controls[9].byte_count = sizeof(dispatch_slot);
    private_controls[10].start = (uint64_t)(uintptr_t)&dispatch_target;
    private_controls[10].byte_count = sizeof(dispatch_target);
    private_controls[11].start = (uint64_t)(uintptr_t)&step;
    private_controls[11].byte_count = sizeof(step);
    private_controls[12].start = (uint64_t)(uintptr_t)&status;
    private_controls[12].byte_count = sizeof(status);
    private_controls[13].start = (uint64_t)(uintptr_t)&frame;
    private_controls[13].byte_count = sizeof(frame);
    private_controls[14].start = (uint64_t)(uintptr_t)&poll_index;
    private_controls[14].byte_count = sizeof(poll_index);
    private_controls[15].start = (uint64_t)(uintptr_t)&cleanup_index;
    private_controls[15].byte_count = sizeof(cleanup_index);
    private_controls[16].start =
        (uint64_t)(uintptr_t)&dispatch_receiver_snapshot;
    private_controls[16].byte_count = sizeof(dispatch_receiver_snapshot);
    private_controls[17].start =
        (uint64_t)(uintptr_t)&result_destination;
    private_controls[17].byte_count = sizeof(result_destination);
    if (rome2_100ed471_span_overlaps_controls(
            &frame_backing,
            private_controls,
            ROME2_100ED471_PRIVATE_CONTROL_COUNT) ||
        rome2_100ed471_span_overlaps_controls(
            &dispatch_backing,
            private_controls,
            ROME2_100ED471_PRIVATE_CONTROL_COUNT)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    {
        rome2_100ed471_host_span context_point;

        context_point.start =
            (uint64_t)(uintptr_t)effects_snapshot.context;
        context_point.byte_count = UINT64_C(1);
        if (rome2_100ed471_span_overlaps_controls(
                &context_point,
                private_controls,
                ROME2_100ED471_PRIVATE_CONTROL_COUNT)) {
            return ROME2_GUEST_BAD_ARGUMENT;
        }
    }

    status = rome2_guest_read_addr32_le(
        &dispatch_snapshot, dispatch_receiver_snapshot, &dispatch_vtable);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed471_add(
        dispatch_vtable,
        ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET,
        &dispatch_slot);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_guest_read_addr32_le(
        &dispatch_snapshot, dispatch_slot, &dispatch_target);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if (!(
            (dispatch_vtable.value == ROME2_PORT_100ED471_LOCAL_VTABLE &&
                dispatch_target.value == ROME2_PORT_100ED471_LOCAL_METHOD) ||
            (dispatch_receiver_snapshot.value ==
                    ROME2_PORT_100ED471_FALLBACK_OBJECT &&
                dispatch_vtable.value ==
                    ROME2_PORT_100ED471_FALLBACK_VTABLE &&
                dispatch_target.value ==
                    ROME2_PORT_100ED471_FALLBACK_METHOD))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    status = rome2_100ed471_add(
        guest_frame,
        ROME2_PORT_100ED471_RECEIVER_OFFSET,
        &guest_receiver);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed471_add(
        guest_frame,
        ROME2_PORT_100ED471_TIMESTAMP_OFFSET,
        &guest_timestamp);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed471_add(
        guest_frame,
        ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET,
        &guest_timestamp_copy);
    if (status != ROME2_GUEST_OK) return status;
    for (cleanup_index = 0U;
         cleanup_index < ROME2_100ED471_CLEANUP_COUNT;
         ++cleanup_index) {
        status = rome2_100ed471_add(
            guest_frame,
            cleanup_offsets[cleanup_index],
            &guest_cleanup[cleanup_index]);
        if (status != ROME2_GUEST_OK) return status;
    }

    frame = frame_snapshot.host_base;
    for (cleanup_index = 0U;
         cleanup_index < ROME2_100ED471_CLEANUP_COUNT;
         ++cleanup_index) {
        if (!rome2_100ed471_empty_descriptor(
                frame, cleanup_offsets[cleanup_index])) {
            return ROME2_GUEST_BAD_ARGUMENT;
        }
        status = rome2_port_100f1cc0_accept_nonowning_noop(
            (rome2_guest_addr32){ROME2_PORT_100F1CC0_SENTINEL});
        if (status != ROME2_GUEST_OK) {
            return status;
        }
    }

    rome2_100ed471_clear_step(
        &step, ROME2_100ED471_STEP_CALL_100EA060);
    step.argument_count = UINT32_C(1);
    step.argument0 = guest_receiver.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100ed471_clear_step(
        &step, ROME2_100ED471_STEP_CALL_112DCAF0);
    step.argument_count = UINT32_C(3);
    step.argument0 = ROME2_PORT_100ED471_LOG_MESSAGE;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100ed471_clear_step(
        &step, ROME2_100ED471_STEP_CALL_100D6560);
    step.argument_count = UINT32_C(1);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100ed471_clear_step(
        &step, ROME2_100ED471_STEP_CALL_112E3D20);
    step.result_count = UINT32_C(1);
    step.result0 = dispatch_receiver_snapshot.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100ed471_clear_step(
        &step, ROME2_100ED471_STEP_INDIRECT_SLOT_54);
    step.argument_count = UINT32_C(2);
    step.argument0 = dispatch_receiver_snapshot.value;
    step.dispatch_vtable = dispatch_vtable.value;
    step.dispatch_slot_offset = ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET;
    step.dispatch_target = dispatch_target.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100ed471_clear_step(
        &step, ROME2_100ED471_STEP_CALL_112E2BB0);
    step.argument_count = UINT32_C(1);
    step.argument0 = guest_timestamp.value;
    step.result_count = UINT32_C(2);
    step.result0 = effects_snapshot.timestamp_low;
    step.result1 = effects_snapshot.timestamp_high;
    effects_snapshot.emit_step(effects_snapshot.context, step);
    rome2_100ed471_write_u32_le(
        frame + ROME2_PORT_100ED471_TIMESTAMP_OFFSET,
        effects_snapshot.timestamp_low);
    rome2_100ed471_write_u32_le(
        frame + ROME2_PORT_100ED471_TIMESTAMP_OFFSET + UINT32_C(4),
        effects_snapshot.timestamp_high);
    rome2_100ed471_write_u32_le(
        frame + ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET,
        effects_snapshot.timestamp_low);
    rome2_100ed471_write_u32_le(
        frame + ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET + UINT32_C(4),
        effects_snapshot.timestamp_high);

    for (poll_index = UINT32_C(0);
         poll_index < effects_snapshot.poll_result_count;
         ++poll_index) {
        rome2_100ed471_clear_step(
            &step, ROME2_100ED471_STEP_CALL_100EC5C0);
        step.argument_count = UINT32_C(1);
        step.argument0 = guest_receiver.value;
        step.result_count = UINT32_C(1);
        step.result0 = effects_snapshot.poll_results[poll_index];
        effects_snapshot.emit_step(effects_snapshot.context, step);
    }

    rome2_100ed471_clear_step(
        &step, ROME2_100ED471_STEP_CALL_100E0650);
    step.argument_count = UINT32_C(1);
    step.argument0 = guest_receiver.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    for (cleanup_index = 0U;
         cleanup_index < ROME2_100ED471_CLEANUP_COUNT;
         ++cleanup_index) {
        rome2_100ed471_clear_step(
            &step, ROME2_100ED471_STEP_CALL_100F1CC0);
        step.argument_count = UINT32_C(1);
        step.argument0 = guest_cleanup[cleanup_index].value;
        effects_snapshot.emit_step(effects_snapshot.context, step);
        status = rome2_port_100f1cc0_accept_nonowning_noop(
            (rome2_guest_addr32){ROME2_PORT_100F1CC0_SENTINEL});
        if (status != ROME2_GUEST_OK) {
            return status;
        }
    }

    result.dispatch_receiver = dispatch_receiver_snapshot;
    result.dispatch_vtable = dispatch_vtable;
    result.dispatch_target = dispatch_target;
    result.poll_calls = effects_snapshot.poll_result_count;
    result.terminal_poll_result = UINT32_C(2);
    result.timestamp_low = effects_snapshot.timestamp_low;
    result.timestamp_high = effects_snapshot.timestamp_high;
    result.return_original_pc = ROME2_PORT_100ED471_RETURN_PC;
    *result_destination = result;
    return ROME2_GUEST_OK;
}

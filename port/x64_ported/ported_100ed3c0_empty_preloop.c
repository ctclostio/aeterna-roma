#include "ported_100ed3c0_empty_preloop.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ROME2_100ED3C0_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100ED3C0_EXTERNAL_CONTROL_COUNT 5U
#define ROME2_100ED3C0_PRIVATE_CONTROL_COUNT 16U

typedef struct rome2_100ed3c0_span {
    uint64_t guest_start;
    uintptr_t host_start;
    uint64_t byte_count;
    uint64_t view_offset;
} rome2_100ed3c0_span;

typedef struct rome2_100ed3c0_host_span {
    uint64_t start;
    uint64_t byte_count;
} rome2_100ed3c0_host_span;

static rome2_guest_status rome2_100ed3c0_validate_object(
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

static int rome2_100ed3c0_ranges_overlap(
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

static rome2_guest_status rome2_100ed3c0_validate_interval(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100ED3C0_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100ED3C0_ADDRESS_SPACE_SIZE) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    host_address = (uintptr_t)host_base;
    if (byte_count != 0 &&
        byte_count - UINT64_C(1) >
            (uint64_t)(UINTPTR_MAX - host_address)) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    return ROME2_GUEST_OK;
}

static rome2_guest_status rome2_100ed3c0_resolve_span(
    const void *host_base,
    uint32_t guest_base,
    uint64_t view_byte_count,
    rome2_guest_addr32 guest_start,
    uint32_t span_byte_count,
    rome2_100ed3c0_span *span_out)
{
    uint64_t offset;

    if (span_out == NULL || span_byte_count == 0) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (guest_start.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if ((uint64_t)span_byte_count >
        ROME2_100ED3C0_ADDRESS_SPACE_SIZE -
            (uint64_t)guest_start.value) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    if (guest_start.value < guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    offset = (uint64_t)guest_start.value - (uint64_t)guest_base;
    if (offset > view_byte_count ||
        (uint64_t)span_byte_count > view_byte_count - offset ||
        offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    span_out->guest_start = (uint64_t)guest_start.value;
    span_out->host_start = (uintptr_t)host_base + (uintptr_t)offset;
    span_out->byte_count = (uint64_t)span_byte_count;
    span_out->view_offset = offset;
    return ROME2_GUEST_OK;
}

static int rome2_100ed3c0_span_overlaps(
    const rome2_100ed3c0_span *first,
    const rome2_100ed3c0_span *second)
{
    return
        rome2_100ed3c0_ranges_overlap(
            first->guest_start,
            first->byte_count,
            second->guest_start,
            second->byte_count) ||
        rome2_100ed3c0_ranges_overlap(
            (uint64_t)first->host_start,
            first->byte_count,
            (uint64_t)second->host_start,
            second->byte_count);
}

static int rome2_100ed3c0_controls_overlap(
    const rome2_100ed3c0_host_span *controls,
    size_t control_count)
{
    size_t first;
    size_t second;

    for (first = 0; first < control_count; ++first) {
        for (second = first + 1U; second < control_count; ++second) {
            if (rome2_100ed3c0_ranges_overlap(
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

static int rome2_100ed3c0_backings_overlap_controls(
    const rome2_100ed3c0_host_span *backings,
    size_t backing_count,
    const rome2_100ed3c0_host_span *controls,
    size_t control_count)
{
    size_t backing;
    size_t control;

    for (backing = 0; backing < backing_count; ++backing) {
        for (control = 0; control < control_count; ++control) {
            if (rome2_100ed3c0_ranges_overlap(
                    backings[backing].start,
                    backings[backing].byte_count,
                    controls[control].start,
                    controls[control].byte_count)) {
                return 1;
            }
        }
    }
    return 0;
}

static int rome2_100ed3c0_backings_overlap(
    const rome2_100ed3c0_host_span *backings,
    size_t backing_count)
{
    size_t first;
    size_t second;

    for (first = 0; first < backing_count; ++first) {
        for (second = first + 1U; second < backing_count; ++second) {
            if (rome2_100ed3c0_ranges_overlap(
                    backings[first].start,
                    backings[first].byte_count,
                    backings[second].start,
                    backings[second].byte_count)) {
                return 1;
            }
        }
    }
    return 0;
}

static uint32_t rome2_100ed3c0_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100ed3c0_write_u32_le(
    uint8_t *bytes,
    uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void rome2_100ed3c0_stage_scalar_fields(
    uint8_t *frame,
    uint32_t argument_position1)
{
    rome2_100ed3c0_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_ZERO_OFFSET,
        UINT32_C(0));
    rome2_100ed3c0_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_ARGUMENT_COPY_OFFSET,
        argument_position1);
    rome2_100ed3c0_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET,
        argument_position1);
    rome2_100ed3c0_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET + 4,
        UINT32_C(0));
    frame[ROME2_PORT_100ED3C0_PRELOOP_ZERO_BYTE_OFFSET] = UINT8_C(0);
    rome2_100ed3c0_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_ZERO_DWORD_OFFSET,
        UINT32_C(0));
    rome2_100ed3c0_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_PACKET_ARGUMENT_OFFSET,
        argument_position1);
    frame[ROME2_PORT_100ED3C0_PRELOOP_PACKET_BYTE_OFFSET] = UINT8_C(0);
    rome2_100ed3c0_write_u32_le(
        frame + ROME2_PORT_100ED3C0_PRELOOP_PACKET_DWORD_OFFSET,
        UINT32_C(0));
    frame[ROME2_PORT_100ED3C0_PRELOOP_PACKET_FLAG_OFFSET] = UINT8_C(0);
}

static rome2_100ed3c0_preloop_value rome2_100ed3c0_make_value(
    rome2_100ed3c0_preloop_value_kind kind,
    uint32_t value)
{
    rome2_100ed3c0_preloop_value result;

    result.kind = kind;
    result.value = value;
    return result;
}

static void rome2_100ed3c0_clear_step(
    rome2_100ed3c0_preloop_step *step,
    rome2_100ed3c0_preloop_step_kind kind)
{
    step->kind = kind;
    step->argument_count = UINT32_C(0);
    step->argument0 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_NONE, UINT32_C(0));
    step->argument1 = step->argument0;
    step->argument2 = step->argument0;
    step->result_count = UINT32_C(0);
    step->result0 = step->argument0;
}

static void rome2_100ed3c0_noop_prefix_step(
    void *context,
    rome2_100df270_prefix_step step)
{
    (void)context;
    (void)step;
}

static void rome2_100ed3c0_noop_suffix_step(
    void *context,
    rome2_100df270_suffix_step step)
{
    (void)context;
    (void)step;
}

static rome2_guest_status rome2_100ed3c0_add(
    rome2_guest_addr32 base,
    uint32_t offset,
    rome2_guest_addr32 *result)
{
    return rome2_guest_add_checked(base, offset, result);
}

rome2_guest_status rome2_port_100ed3c0_run_empty_preloop(
    const rome2_guest_write_view *frame_view,
    rome2_guest_addr32 guest_frame,
    uint32_t argument_position1,
    const rome2_guest_read_view *text_view,
    rome2_guest_addr32 argument_position3_text,
    uint32_t text_max_units,
    const rome2_guest_write_view *selector_view,
    const rome2_100ed3c0_preloop_effects *effects,
    rome2_100ed3c0_preloop_result *result_out)
{
    rome2_guest_write_view frame_snapshot;
    rome2_guest_read_view text_snapshot;
    rome2_guest_write_view selector_snapshot;
    rome2_100ed3c0_preloop_effects effects_snapshot;
    rome2_100df270_prefix_effects prefix_preflight;
    rome2_100df270_suffix_effects suffix_preflight;
    rome2_100ed3c0_host_span controls[ROME2_100ED3C0_EXTERNAL_CONTROL_COUNT];
    rome2_100ed3c0_host_span
        private_controls[ROME2_100ED3C0_PRIVATE_CONTROL_COUNT];
    rome2_100ed3c0_host_span backings[3];
    rome2_100ed3c0_span frame_span;
    rome2_100ed3c0_span text_unit_span;
    rome2_100ed3c0_span first_selector_span;
    rome2_100ed3c0_span second_selector_span;
    rome2_100ed3c0_preloop_step step;
    rome2_guest_addr32 guest_triplet0;
    rome2_guest_addr32 guest_triplet1;
    rome2_guest_addr32 guest_argument_copy;
    rome2_guest_addr32 guest_zero_byte;
    rome2_guest_addr32 guest_zero_dword;
    rome2_guest_addr32 guest_descriptor;
    rome2_guest_addr32 guest_packet;
    rome2_guest_addr32 guest_copy0;
    rome2_guest_addr32 guest_copy1;
    rome2_guest_addr32 guest_packet_argument;
    rome2_guest_addr32 guest_packet_byte;
    rome2_guest_addr32 guest_packet_dword;
    rome2_guest_addr32 guest_packet_flag;
    rome2_guest_addr32 guest_receiver;
    rome2_guest_addr32 guest_owner;
    rome2_guest_addr32 adjusted_crash_record;
    rome2_guest_addr32 child_return;
    rome2_guest_addr32 preview_return;
    rome2_guest_addr32 leaf_return;
    rome2_guest_write_view frame_preview_view;
    rome2_guest_write_view selector_preview_view;
    rome2_guest_status status;
    uint8_t frame_preview[ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES];
    uint8_t selector_preview[8];
    uint8_t preview_context;
    uint8_t *frame_bytes;
    uint32_t text_length;
    uint32_t first_selector_value;

    status = rome2_100ed3c0_validate_object(frame_view, sizeof(*frame_view));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed3c0_validate_object(text_view, sizeof(*text_view));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed3c0_validate_object(
        selector_view, sizeof(*selector_view));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed3c0_validate_object(effects, sizeof(*effects));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed3c0_validate_object(result_out, sizeof(*result_out));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if ((uintptr_t)frame_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)text_view % _Alignof(rome2_guest_read_view) != 0U ||
        (uintptr_t)selector_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)effects % _Alignof(rome2_100ed3c0_preloop_effects) != 0U ||
        (uintptr_t)result_out % _Alignof(rome2_100ed3c0_preloop_result) != 0U) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    controls[0].start = (uint64_t)(uintptr_t)frame_view;
    controls[0].byte_count = sizeof(*frame_view);
    controls[1].start = (uint64_t)(uintptr_t)text_view;
    controls[1].byte_count = sizeof(*text_view);
    controls[2].start = (uint64_t)(uintptr_t)selector_view;
    controls[2].byte_count = sizeof(*selector_view);
    controls[3].start = (uint64_t)(uintptr_t)effects;
    controls[3].byte_count = sizeof(*effects);
    controls[4].start = (uint64_t)(uintptr_t)result_out;
    controls[4].byte_count = sizeof(*result_out);
    if (rome2_100ed3c0_controls_overlap(
            controls, ROME2_100ED3C0_EXTERNAL_CONTROL_COUNT)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    frame_snapshot = *frame_view;
    text_snapshot = *text_view;
    selector_snapshot = *selector_view;
    status = rome2_100ed3c0_validate_interval(
        frame_snapshot.host_base,
        frame_snapshot.guest_base,
        frame_snapshot.byte_count);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if (frame_snapshot.guest_base != guest_frame.value ||
        frame_snapshot.byte_count !=
            ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    status = rome2_100ed3c0_validate_interval(
        text_snapshot.host_base,
        text_snapshot.guest_base,
        text_snapshot.byte_count);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed3c0_validate_interval(
        selector_snapshot.host_base,
        selector_snapshot.guest_base,
        selector_snapshot.byte_count);
    if (status != ROME2_GUEST_OK) {
        return status;
    }

    backings[0].start = (uint64_t)(uintptr_t)frame_snapshot.host_base;
    backings[0].byte_count = frame_snapshot.byte_count;
    backings[1].start = (uint64_t)(uintptr_t)text_snapshot.host_base;
    backings[1].byte_count = text_snapshot.byte_count;
    backings[2].start = (uint64_t)(uintptr_t)selector_snapshot.host_base;
    backings[2].byte_count = selector_snapshot.byte_count;
    if (rome2_100ed3c0_backings_overlap(backings, 3U) ||
        rome2_100ed3c0_backings_overlap_controls(
            backings,
            3U,
            controls,
            ROME2_100ED3C0_EXTERNAL_CONTROL_COUNT)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    effects_snapshot = *effects;
    if (effects_snapshot.emit_step == NULL ||
        effects_snapshot.context == NULL ||
        effects_snapshot.child_prefix.emit_step == NULL ||
        effects_snapshot.child_prefix.context == NULL ||
        effects_snapshot.child_suffix.emit_step == NULL ||
        effects_snapshot.child_suffix.context == NULL ||
        effects_snapshot.child_suffix.result_100e8240.value !=
            ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    private_controls[0].start = (uint64_t)(uintptr_t)&frame_snapshot;
    private_controls[0].byte_count = sizeof(frame_snapshot);
    private_controls[1].start = (uint64_t)(uintptr_t)&text_snapshot;
    private_controls[1].byte_count = sizeof(text_snapshot);
    private_controls[2].start = (uint64_t)(uintptr_t)&selector_snapshot;
    private_controls[2].byte_count = sizeof(selector_snapshot);
    private_controls[3].start = (uint64_t)(uintptr_t)&effects_snapshot;
    private_controls[3].byte_count = sizeof(effects_snapshot);
    private_controls[4].start = (uint64_t)(uintptr_t)&prefix_preflight;
    private_controls[4].byte_count = sizeof(prefix_preflight);
    private_controls[5].start = (uint64_t)(uintptr_t)&suffix_preflight;
    private_controls[5].byte_count = sizeof(suffix_preflight);
    private_controls[6].start = (uint64_t)(uintptr_t)&child_return;
    private_controls[6].byte_count = sizeof(child_return);
    private_controls[7].start = (uint64_t)(uintptr_t)&leaf_return;
    private_controls[7].byte_count = sizeof(leaf_return);
    private_controls[8].start = (uint64_t)(uintptr_t)&preview_return;
    private_controls[8].byte_count = sizeof(preview_return);
    private_controls[9].start = (uint64_t)(uintptr_t)&frame_preview_view;
    private_controls[9].byte_count = sizeof(frame_preview_view);
    private_controls[10].start =
        (uint64_t)(uintptr_t)&selector_preview_view;
    private_controls[10].byte_count = sizeof(selector_preview_view);
    private_controls[11].start = (uint64_t)(uintptr_t)&text_length;
    private_controls[11].byte_count = sizeof(text_length);
    private_controls[12].start = (uint64_t)(uintptr_t)&step;
    private_controls[12].byte_count = sizeof(step);
    private_controls[13].start = (uint64_t)(uintptr_t)frame_preview;
    private_controls[13].byte_count = sizeof(frame_preview);
    private_controls[14].start = (uint64_t)(uintptr_t)selector_preview;
    private_controls[14].byte_count = sizeof(selector_preview);
    private_controls[15].start = (uint64_t)(uintptr_t)&preview_context;
    private_controls[15].byte_count = sizeof(preview_context);
    if (rome2_100ed3c0_backings_overlap_controls(
            backings,
            3U,
            private_controls,
            ROME2_100ED3C0_PRIVATE_CONTROL_COUNT)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    status = rome2_100ed3c0_resolve_span(
        frame_snapshot.host_base,
        frame_snapshot.guest_base,
        frame_snapshot.byte_count,
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES,
        &frame_span);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed3c0_resolve_span(
        text_snapshot.host_base,
        text_snapshot.guest_base,
        text_snapshot.byte_count,
        argument_position3_text,
        UINT32_C(2),
        &text_unit_span);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed3c0_resolve_span(
        selector_snapshot.host_base,
        selector_snapshot.guest_base,
        selector_snapshot.byte_count,
        effects_snapshot.child_suffix.first_selector_result,
        UINT32_C(4),
        &first_selector_span);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100ed3c0_resolve_span(
        selector_snapshot.host_base,
        selector_snapshot.guest_base,
        selector_snapshot.byte_count,
        effects_snapshot.child_suffix.second_selector_result,
        UINT32_C(4),
        &second_selector_span);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if (rome2_100ed3c0_span_overlaps(&frame_span, &text_unit_span) ||
        rome2_100ed3c0_span_overlaps(&frame_span, &first_selector_span) ||
        rome2_100ed3c0_span_overlaps(&frame_span, &second_selector_span) ||
        rome2_100ed3c0_span_overlaps(&text_unit_span, &first_selector_span) ||
        rome2_100ed3c0_span_overlaps(&text_unit_span, &second_selector_span)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_TRIPLET0_OFFSET,
        &guest_triplet0);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_TRIPLET1_OFFSET,
        &guest_triplet1);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_ARGUMENT_COPY_OFFSET,
        &guest_argument_copy);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_ZERO_BYTE_OFFSET,
        &guest_zero_byte);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_ZERO_DWORD_OFFSET,
        &guest_zero_dword);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET,
        &guest_descriptor);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET,
        &guest_packet);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_COPY0_OFFSET,
        &guest_copy0);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_COPY1_OFFSET,
        &guest_copy1);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_PACKET_ARGUMENT_OFFSET,
        &guest_packet_argument);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_PACKET_BYTE_OFFSET,
        &guest_packet_byte);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_PACKET_DWORD_OFFSET,
        &guest_packet_dword);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_PACKET_FLAG_OFFSET,
        &guest_packet_flag);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_frame,
        ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET,
        &guest_receiver);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        guest_receiver,
        ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET,
        &guest_owner);
    if (status != ROME2_GUEST_OK) return status;
    status = rome2_100ed3c0_add(
        effects_snapshot.child_suffix.result_100e8240,
        ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET,
        &adjusted_crash_record);
    if (status != ROME2_GUEST_OK) return status;
    (void)guest_argument_copy;
    (void)guest_zero_byte;
    (void)guest_zero_dword;
    (void)guest_packet_argument;
    (void)guest_packet_byte;
    (void)guest_packet_dword;
    (void)guest_packet_flag;
    (void)guest_owner;
    (void)adjusted_crash_record;

    if (text_max_units != ROME2_PORT_100ED3C0_PRELOOP_TEXT_UNITS) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    text_length = UINT32_MAX;
    status = rome2_port_100f1bb0_measure_utf16(
        &text_snapshot,
        argument_position3_text,
        text_max_units,
        &text_length);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if (text_length != UINT32_C(0)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    memcpy(
        frame_preview,
        frame_snapshot.host_base + (size_t)frame_span.view_offset,
        ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES);
    frame_preview_view.host_base = frame_preview;
    frame_preview_view.guest_base = guest_frame.value;
    frame_preview_view.byte_count = ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES;
    rome2_100ed3c0_stage_scalar_fields(frame_preview, argument_position1);
    preview_return.value = UINT32_C(0);
    status = rome2_port_100f1c10_initialize_triplet(
        &frame_preview_view, guest_triplet0, &preview_return);
    if (status != ROME2_GUEST_OK || preview_return.value != guest_triplet0.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }
    preview_return.value = UINT32_C(0);
    status = rome2_port_100f1c10_initialize_triplet(
        &frame_preview_view, guest_triplet1, &preview_return);
    if (status != ROME2_GUEST_OK || preview_return.value != guest_triplet1.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }
    preview_return.value = UINT32_C(0);
    status = rome2_port_100f1aa0_copy_empty_source(
        &frame_preview_view, guest_copy0, guest_triplet0, &preview_return);
    if (status != ROME2_GUEST_OK || preview_return.value != guest_copy0.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }
    preview_return.value = UINT32_C(0);
    status = rome2_port_100f1aa0_copy_empty_source(
        &frame_preview_view, guest_copy1, guest_triplet1, &preview_return);
    if (status != ROME2_GUEST_OK || preview_return.value != guest_copy1.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }
    preview_return.value = UINT32_C(0);
    status = rome2_port_100f1c10_initialize_triplet(
        &frame_preview_view, guest_descriptor, &preview_return);
    if (status != ROME2_GUEST_OK ||
        preview_return.value != guest_descriptor.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }
    preview_context = UINT8_C(0);
    prefix_preflight = effects_snapshot.child_prefix;
    prefix_preflight.emit_step = rome2_100ed3c0_noop_prefix_step;
    prefix_preflight.context = &preview_context;
    preview_return.value = UINT32_C(0);
    status = rome2_port_100df270_run_platform_prefix_transcript(
        &frame_preview_view,
        guest_receiver,
        guest_packet,
        &prefix_preflight,
        &preview_return);
    if (status != ROME2_GUEST_OK || preview_return.value != guest_receiver.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }
    preview_return.value = UINT32_C(0);
    status = rome2_port_100df270_project_headless_empty_state(
        &frame_preview_view,
        guest_receiver,
        guest_packet,
        &preview_return);
    if (status != ROME2_GUEST_OK || preview_return.value != guest_receiver.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }

    first_selector_value = rome2_100ed3c0_read_u32_le(
        selector_snapshot.host_base +
            (size_t)first_selector_span.view_offset);
    memset(selector_preview, 0xa5, sizeof(selector_preview));
    rome2_100ed3c0_write_u32_le(selector_preview, first_selector_value);
    selector_preview_view.host_base = selector_preview;
    selector_preview_view.guest_base = UINT32_C(0x1000);
    selector_preview_view.byte_count = sizeof(selector_preview);
    suffix_preflight = effects_snapshot.child_suffix;
    suffix_preflight.emit_step = rome2_100ed3c0_noop_suffix_step;
    suffix_preflight.context = &preview_context;
    suffix_preflight.first_selector_result.value = UINT32_C(0x1000);
    suffix_preflight.second_selector_result.value =
        effects_snapshot.child_suffix.first_selector_result.value ==
            effects_snapshot.child_suffix.second_selector_result.value
        ? UINT32_C(0x1000)
        : UINT32_C(0x1004);
    preview_return.value = UINT32_C(0);
    status = rome2_port_100df270_run_suffix_transcript(
        &selector_preview_view,
        guest_receiver,
        guest_descriptor,
        &suffix_preflight,
        &preview_return);
    if (status != ROME2_GUEST_OK || preview_return.value != guest_receiver.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }

    frame_bytes =
        frame_snapshot.host_base + (size_t)frame_span.view_offset;
    rome2_100ed3c0_clear_step(
        &step, ROME2_100ED3C0_PRELOOP_STEP_WRITE_GLOBAL_119F31C8);
    step.argument_count = UINT32_C(2);
    step.argument0 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_ORIGINAL_IDENTITY,
        ROME2_PORT_100ED3C0_PRELOOP_GLOBAL_119F31C8);
    step.argument1 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_SCALAR, UINT32_C(1));
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100ed3c0_clear_step(
        &step, ROME2_100ED3C0_PRELOOP_STEP_WRITE_GLOBAL_119F31C5);
    step.argument_count = UINT32_C(2);
    step.argument0 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_ORIGINAL_IDENTITY,
        ROME2_PORT_100ED3C0_PRELOOP_GLOBAL_119F31C5);
    step.argument1 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_SCALAR, UINT32_C(1));
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100ed3c0_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_ZERO_OFFSET,
        UINT32_C(0));
    rome2_100ed3c0_clear_step(
        &step, ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET0);
    step.argument_count = UINT32_C(1);
    step.argument0 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        guest_triplet0.value);
    effects_snapshot.emit_step(effects_snapshot.context, step);
    leaf_return.value = UINT32_C(0);
    status = rome2_port_100f1c10_initialize_triplet(
        &frame_snapshot, guest_triplet0, &leaf_return);
    if (status != ROME2_GUEST_OK || leaf_return.value != guest_triplet0.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }

    rome2_100ed3c0_clear_step(
        &step, ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET1);
    step.argument_count = UINT32_C(1);
    step.argument0 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        guest_triplet1.value);
    effects_snapshot.emit_step(effects_snapshot.context, step);
    leaf_return.value = UINT32_C(0);
    status = rome2_port_100f1c10_initialize_triplet(
        &frame_snapshot, guest_triplet1, &leaf_return);
    if (status != ROME2_GUEST_OK || leaf_return.value != guest_triplet1.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }

    rome2_100ed3c0_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_ARGUMENT_COPY_OFFSET,
        argument_position1);
    rome2_100ed3c0_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET,
        argument_position1);
    rome2_100ed3c0_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET + 4,
        UINT32_C(0));
    frame_bytes[ROME2_PORT_100ED3C0_PRELOOP_ZERO_BYTE_OFFSET] = UINT8_C(0);
    rome2_100ed3c0_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_ZERO_DWORD_OFFSET,
        UINT32_C(0));

    rome2_100ed3c0_clear_step(
        &step, ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY0);
    step.argument_count = UINT32_C(2);
    step.argument0 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        guest_copy0.value);
    step.argument1 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        guest_triplet0.value);
    effects_snapshot.emit_step(effects_snapshot.context, step);
    leaf_return.value = UINT32_C(0);
    status = rome2_port_100f1aa0_copy_empty_source(
        &frame_snapshot, guest_copy0, guest_triplet0, &leaf_return);
    if (status != ROME2_GUEST_OK || leaf_return.value != guest_copy0.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }

    rome2_100ed3c0_clear_step(
        &step, ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY1);
    step.argument_count = UINT32_C(2);
    step.argument0 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        guest_copy1.value);
    step.argument1 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        guest_triplet1.value);
    effects_snapshot.emit_step(effects_snapshot.context, step);
    leaf_return.value = UINT32_C(0);
    status = rome2_port_100f1aa0_copy_empty_source(
        &frame_snapshot, guest_copy1, guest_triplet1, &leaf_return);
    if (status != ROME2_GUEST_OK || leaf_return.value != guest_copy1.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }

    rome2_100ed3c0_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_PACKET_ARGUMENT_OFFSET,
        argument_position1);
    frame_bytes[ROME2_PORT_100ED3C0_PRELOOP_PACKET_BYTE_OFFSET] = UINT8_C(0);
    rome2_100ed3c0_write_u32_le(
        frame_bytes + ROME2_PORT_100ED3C0_PRELOOP_PACKET_DWORD_OFFSET,
        UINT32_C(0));
    frame_bytes[ROME2_PORT_100ED3C0_PRELOOP_PACKET_FLAG_OFFSET] = UINT8_C(0);

    rome2_100ed3c0_clear_step(
        &step, ROME2_100ED3C0_PRELOOP_STEP_BUILD_EMPTY_DESCRIPTOR);
    step.argument_count = UINT32_C(2);
    step.argument0 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        guest_descriptor.value);
    step.argument1 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_GUEST_IDENTITY,
        argument_position3_text.value);
    step.result_count = UINT32_C(1);
    step.result0 = step.argument0;
    effects_snapshot.emit_step(effects_snapshot.context, step);
    /* This is equivalent empty-descriptor materialization after the admitted
     * zero-length 0x100f1bb0 branch, not a third original 0x100f1c10 call. */
    leaf_return.value = UINT32_C(0);
    status = rome2_port_100f1c10_initialize_triplet(
        &frame_snapshot, guest_descriptor, &leaf_return);
    if (status != ROME2_GUEST_OK ||
        leaf_return.value != guest_descriptor.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }

    rome2_100ed3c0_clear_step(
        &step, ROME2_100ED3C0_PRELOOP_STEP_RUN_100DF270);
    step.argument_count = UINT32_C(3);
    step.argument0 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        guest_receiver.value);
    step.argument1 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        guest_packet.value);
    step.argument2 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        guest_descriptor.value);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    child_return.value = UINT32_C(0);
    status = rome2_port_100df270_run_platform_prefix_transcript(
        &frame_snapshot,
        guest_receiver,
        guest_packet,
        &effects_snapshot.child_prefix,
        &child_return);
    if (status != ROME2_GUEST_OK || child_return.value != guest_receiver.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }
    child_return.value = UINT32_C(0);
    status = rome2_port_100df270_project_headless_empty_state(
        &frame_snapshot,
        guest_receiver,
        guest_packet,
        &child_return);
    if (status != ROME2_GUEST_OK || child_return.value != guest_receiver.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }
    child_return.value = UINT32_C(0);
    status = rome2_port_100df270_run_suffix_transcript(
        &selector_snapshot,
        guest_receiver,
        guest_descriptor,
        &effects_snapshot.child_suffix,
        &child_return);
    if (status != ROME2_GUEST_OK || child_return.value != guest_receiver.value) {
        return status == ROME2_GUEST_OK ? ROME2_GUEST_BAD_ARGUMENT : status;
    }

    rome2_100ed3c0_clear_step(
        &step, ROME2_100ED3C0_PRELOOP_STEP_CLEANUP_DESCRIPTOR);
    step.argument_count = UINT32_C(1);
    step.argument0 = rome2_100ed3c0_make_value(
        ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
        guest_descriptor.value);
    effects_snapshot.emit_step(effects_snapshot.context, step);
    status = rome2_port_100f1cc0_accept_nonowning_noop(
        (rome2_guest_addr32){ROME2_PORT_100F1CC0_SENTINEL});
    if (status != ROME2_GUEST_OK) {
        return status;
    }

    result_out->child_receiver = guest_receiver;
    result_out->child_packet = guest_packet;
    result_out->child_argument = guest_descriptor;
    result_out->next_original_pc = ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC;
    return ROME2_GUEST_OK;
}

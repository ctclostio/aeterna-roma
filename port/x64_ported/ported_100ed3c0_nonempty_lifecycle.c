#include "ported_100ed3c0_nonempty_lifecycle.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ROME2_100ED3C0_LIFECYCLE_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100ED3C0_LIFECYCLE_CONTROL_COUNT 12U
#define ROME2_100ED3C0_LIFECYCLE_BACKING_COUNT 7U
#define ROME2_100ED3C0_LIFECYCLE_CONTEXT_COUNT 6U
#define ROME2_100ED3C0_LIFECYCLE_CLEANUP_COUNT 4U

typedef struct rome2_100ed3c0_lifecycle_host_span {
    uint64_t start;
    uint64_t byte_count;
} rome2_100ed3c0_lifecycle_host_span;

typedef struct rome2_100ed3c0_lifecycle_backing {
    uint64_t host_start;
    uint64_t guest_start;
    uint64_t byte_count;
} rome2_100ed3c0_lifecycle_backing;

typedef struct rome2_100ed3c0_lifecycle_preview_trace {
    uint32_t step_count;
    uint32_t reserved;
} rome2_100ed3c0_lifecycle_preview_trace;

typedef struct rome2_100ed3c0_lifecycle_private {
    rome2_guest_write_view frame_view;
    rome2_guest_read_view text_view;
    rome2_guest_write_view selector_view;
    rome2_guest_write_view temporary_heap_view;
    rome2_guest_write_view persistent_descriptor_view;
    rome2_guest_write_view persistent_heap_view;
    rome2_guest_read_view dispatch_view;
    rome2_100ed3c0_nonempty_lifecycle_effects effects;
    rome2_100ed3c0_nonempty_lifecycle_result combined_result;
    rome2_100ed3c0_preloop_result preloop_result;
    rome2_100ed471_lifecycle_result ordinary_result;
    rome2_100ed471_lifecycle_result preview_result;
    rome2_100ed471_lifecycle_effects preview_effects;
    rome2_guest_write_view preview_frame_view;
    rome2_100ed3c0_lifecycle_preview_trace preview_trace;
    rome2_100ed3c0_lifecycle_host_span
        controls[ROME2_100ED3C0_LIFECYCLE_CONTROL_COUNT];
    rome2_100ed3c0_lifecycle_backing
        backings[ROME2_100ED3C0_LIFECYCLE_BACKING_COUNT];
    rome2_100ed3c0_lifecycle_host_span
        backing_spans[ROME2_100ED3C0_LIFECYCLE_BACKING_COUNT];
    rome2_100ed3c0_lifecycle_host_span
        contexts[ROME2_100ED3C0_LIFECYCLE_CONTEXT_COUNT];
    uint8_t preview_frame[ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_FRAME_BYTES];
} rome2_100ed3c0_lifecycle_private;

_Static_assert(
    ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES ==
        ROME2_PORT_100ED471_FRAME_BYTES,
    "the two admitted children must share one exact frame");
_Static_assert(
    ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC ==
        ROME2_PORT_100ED471_START_PC,
    "the admitted child boundaries must be contiguous");
_Static_assert(
    ROME2_PORT_100ED471_RETURN_PC ==
        ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_RETURN_PC,
    "the composition must stop at the authenticated parent return");
_Static_assert(
    ROME2_PORT_100ED471_CLEANUP0_OFFSET ==
            ROME2_PORT_100ED3C0_PRELOOP_COPY1_OFFSET &&
        ROME2_PORT_100ED471_CLEANUP1_OFFSET ==
            ROME2_PORT_100ED3C0_PRELOOP_COPY0_OFFSET &&
        ROME2_PORT_100ED471_CLEANUP2_OFFSET ==
            ROME2_PORT_100ED3C0_PRELOOP_TRIPLET1_OFFSET &&
        ROME2_PORT_100ED471_CLEANUP3_OFFSET ==
            ROME2_PORT_100ED3C0_PRELOOP_TRIPLET0_OFFSET,
    "the lifecycle cleanups must consume the preloop sentinel triplets");

static rome2_100f1bb0_owned_status rome2_100ed3c0_lifecycle_from_guest(
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

static rome2_100f1bb0_owned_status rome2_100ed3c0_lifecycle_validate_object(
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

static rome2_100f1bb0_owned_status rome2_100ed3c0_lifecycle_validate_view(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100ED3C0_LIFECYCLE_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100ED3C0_LIFECYCLE_ADDRESS_SPACE_SIZE) {
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
rome2_100ed3c0_lifecycle_validate_host_interval(
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

static int rome2_100ed3c0_lifecycle_ranges_overlap(
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

static int rome2_100ed3c0_lifecycle_host_spans_overlap(
    const rome2_100ed3c0_lifecycle_host_span *spans,
    size_t count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < count; ++first) {
        for (second = first + 1U; second < count; ++second) {
            if (rome2_100ed3c0_lifecycle_ranges_overlap(
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

static int rome2_100ed3c0_lifecycle_backings_overlap(
    const rome2_100ed3c0_lifecycle_backing *backings,
    size_t count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < count; ++first) {
        for (second = first + 1U; second < count; ++second) {
            if (rome2_100ed3c0_lifecycle_ranges_overlap(
                    backings[first].host_start,
                    backings[first].byte_count,
                    backings[second].host_start,
                    backings[second].byte_count) ||
                rome2_100ed3c0_lifecycle_ranges_overlap(
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

static int rome2_100ed3c0_lifecycle_sets_overlap(
    const rome2_100ed3c0_lifecycle_host_span *first,
    size_t first_count,
    const rome2_100ed3c0_lifecycle_host_span *second,
    size_t second_count)
{
    size_t first_index;
    size_t second_index;

    for (first_index = 0U; first_index < first_count; ++first_index) {
        for (second_index = 0U; second_index < second_count; ++second_index) {
            if (rome2_100ed3c0_lifecycle_ranges_overlap(
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

static int rome2_100ed3c0_lifecycle_contexts_partially_overlap(
    const rome2_100ed3c0_lifecycle_host_span *contexts,
    size_t count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < count; ++first) {
        for (second = first + 1U; second < count; ++second) {
            if (rome2_100ed3c0_lifecycle_ranges_overlap(
                    contexts[first].start,
                    contexts[first].byte_count,
                    contexts[second].start,
                    contexts[second].byte_count) &&
                (contexts[first].start != contexts[second].start ||
                 contexts[first].byte_count != contexts[second].byte_count)) {
                return 1;
            }
        }
    }
    return 0;
}

static uint32_t rome2_100ed3c0_lifecycle_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100ed3c0_lifecycle_write_u32_le(
    uint8_t *bytes,
    uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void rome2_100ed3c0_lifecycle_write_empty_descriptor(uint8_t *bytes)
{
    rome2_100ed3c0_lifecycle_write_u32_le(bytes, UINT32_C(0));
    rome2_100ed3c0_lifecycle_write_u32_le(bytes + 4U, UINT32_C(0));
    rome2_100ed3c0_lifecycle_write_u32_le(
        bytes + 8U, ROME2_PORT_100F1CC0_SENTINEL);
}

static int rome2_100ed3c0_lifecycle_is_empty_descriptor(
    const uint8_t *bytes)
{
    return
        rome2_100ed3c0_lifecycle_read_u32_le(bytes) == UINT32_C(0) &&
        rome2_100ed3c0_lifecycle_read_u32_le(bytes + 4U) == UINT32_C(0) &&
        rome2_100ed3c0_lifecycle_read_u32_le(bytes + 8U) ==
            ROME2_PORT_100F1CC0_SENTINEL;
}

static void rome2_100ed3c0_lifecycle_preview_emit(
    void *context,
    rome2_100ed471_step step)
{
    rome2_100ed3c0_lifecycle_preview_trace *trace =
        (rome2_100ed3c0_lifecycle_preview_trace *)context;

    (void)step;
    ++trace->step_count;
}

rome2_100f1bb0_owned_status rome2_port_100ed3c0_run_nonempty_lifecycle(
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
    const rome2_guest_read_view *dispatch_view,
    rome2_guest_addr32 dispatch_receiver,
    uint32_t max_poll_calls,
    const rome2_100ed3c0_nonempty_lifecycle_effects *effects,
    rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_100ed3c0_nonempty_lifecycle_result *result_out)
{
    static const uint32_t cleanup_offsets[
        ROME2_100ED3C0_LIFECYCLE_CLEANUP_COUNT] = {
            ROME2_PORT_100ED471_CLEANUP0_OFFSET,
            ROME2_PORT_100ED471_CLEANUP1_OFFSET,
            ROME2_PORT_100ED471_CLEANUP2_OFFSET,
            ROME2_PORT_100ED471_CLEANUP3_OFFSET
        };
    rome2_100ed3c0_lifecycle_private state = {0};
    rome2_100ed3c0_lifecycle_host_span private_span;
    rome2_100f1bb0_owned_status owned_status;
    rome2_guest_status guest_status;
    size_t index;

    owned_status = rome2_100ed3c0_lifecycle_validate_object(
        frame_view, sizeof(*frame_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_object(
        text_view, sizeof(*text_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_object(
        selector_view, sizeof(*selector_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_object(
        temporary_heap_view, sizeof(*temporary_heap_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_object(
        persistent_descriptor_view, sizeof(*persistent_descriptor_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_object(
        persistent_heap_view, sizeof(*persistent_heap_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_object(
        dispatch_view, sizeof(*dispatch_view));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_object(
        effects, sizeof(*effects));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_object(
        temporary_owner, sizeof(*temporary_owner));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_object(
        persistent_owner, sizeof(*persistent_owner));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_object(
        lifecycle, sizeof(*lifecycle));
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_object(
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
        (uintptr_t)dispatch_view % _Alignof(rome2_guest_read_view) != 0U ||
        (uintptr_t)effects %
            _Alignof(rome2_100ed3c0_nonempty_lifecycle_effects) != 0U ||
        (uintptr_t)temporary_owner %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)persistent_owner %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)lifecycle %
            _Alignof(rome2_100f2750_first_use_lifecycle) != 0U ||
        (uintptr_t)result_out %
            _Alignof(rome2_100ed3c0_nonempty_lifecycle_result) != 0U) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.controls[0].start = (uint64_t)(uintptr_t)frame_view;
    state.controls[0].byte_count = sizeof(*frame_view);
    state.controls[1].start = (uint64_t)(uintptr_t)text_view;
    state.controls[1].byte_count = sizeof(*text_view);
    state.controls[2].start = (uint64_t)(uintptr_t)selector_view;
    state.controls[2].byte_count = sizeof(*selector_view);
    state.controls[3].start = (uint64_t)(uintptr_t)temporary_heap_view;
    state.controls[3].byte_count = sizeof(*temporary_heap_view);
    state.controls[4].start =
        (uint64_t)(uintptr_t)persistent_descriptor_view;
    state.controls[4].byte_count = sizeof(*persistent_descriptor_view);
    state.controls[5].start = (uint64_t)(uintptr_t)persistent_heap_view;
    state.controls[5].byte_count = sizeof(*persistent_heap_view);
    state.controls[6].start = (uint64_t)(uintptr_t)dispatch_view;
    state.controls[6].byte_count = sizeof(*dispatch_view);
    state.controls[7].start = (uint64_t)(uintptr_t)effects;
    state.controls[7].byte_count = sizeof(*effects);
    state.controls[8].start = (uint64_t)(uintptr_t)temporary_owner;
    state.controls[8].byte_count = sizeof(*temporary_owner);
    state.controls[9].start = (uint64_t)(uintptr_t)persistent_owner;
    state.controls[9].byte_count = sizeof(*persistent_owner);
    state.controls[10].start = (uint64_t)(uintptr_t)lifecycle;
    state.controls[10].byte_count = sizeof(*lifecycle);
    state.controls[11].start = (uint64_t)(uintptr_t)result_out;
    state.controls[11].byte_count = sizeof(*result_out);
    if (rome2_100ed3c0_lifecycle_host_spans_overlap(
            state.controls, ROME2_100ED3C0_LIFECYCLE_CONTROL_COUNT)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.frame_view = *frame_view;
    state.text_view = *text_view;
    state.selector_view = *selector_view;
    state.temporary_heap_view = *temporary_heap_view;
    state.persistent_descriptor_view = *persistent_descriptor_view;
    state.persistent_heap_view = *persistent_heap_view;
    state.dispatch_view = *dispatch_view;
    state.effects = *effects;

    owned_status = rome2_100ed3c0_lifecycle_validate_view(
        state.frame_view.host_base,
        state.frame_view.guest_base,
        state.frame_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_view(
        state.text_view.host_base,
        state.text_view.guest_base,
        state.text_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_view(
        state.selector_view.host_base,
        state.selector_view.guest_base,
        state.selector_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_view(
        state.temporary_heap_view.host_base,
        state.temporary_heap_view.guest_base,
        state.temporary_heap_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_view(
        state.persistent_descriptor_view.host_base,
        state.persistent_descriptor_view.guest_base,
        state.persistent_descriptor_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_view(
        state.persistent_heap_view.host_base,
        state.persistent_heap_view.guest_base,
        state.persistent_heap_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    owned_status = rome2_100ed3c0_lifecycle_validate_view(
        state.dispatch_view.host_base,
        state.dispatch_view.guest_base,
        state.dispatch_view.byte_count);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    if (state.frame_view.guest_base != guest_frame.value ||
        state.frame_view.byte_count !=
            ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_FRAME_BYTES) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.backings[0].host_start =
        (uint64_t)(uintptr_t)state.frame_view.host_base;
    state.backings[0].guest_start = state.frame_view.guest_base;
    state.backings[0].byte_count = state.frame_view.byte_count;
    state.backings[1].host_start =
        (uint64_t)(uintptr_t)state.text_view.host_base;
    state.backings[1].guest_start = state.text_view.guest_base;
    state.backings[1].byte_count = state.text_view.byte_count;
    state.backings[2].host_start =
        (uint64_t)(uintptr_t)state.selector_view.host_base;
    state.backings[2].guest_start = state.selector_view.guest_base;
    state.backings[2].byte_count = state.selector_view.byte_count;
    state.backings[3].host_start =
        (uint64_t)(uintptr_t)state.temporary_heap_view.host_base;
    state.backings[3].guest_start = state.temporary_heap_view.guest_base;
    state.backings[3].byte_count = state.temporary_heap_view.byte_count;
    state.backings[4].host_start =
        (uint64_t)(uintptr_t)state.persistent_descriptor_view.host_base;
    state.backings[4].guest_start =
        state.persistent_descriptor_view.guest_base;
    state.backings[4].byte_count =
        state.persistent_descriptor_view.byte_count;
    state.backings[5].host_start =
        (uint64_t)(uintptr_t)state.persistent_heap_view.host_base;
    state.backings[5].guest_start = state.persistent_heap_view.guest_base;
    state.backings[5].byte_count = state.persistent_heap_view.byte_count;
    state.backings[6].host_start =
        (uint64_t)(uintptr_t)state.dispatch_view.host_base;
    state.backings[6].guest_start = state.dispatch_view.guest_base;
    state.backings[6].byte_count = state.dispatch_view.byte_count;
    for (index = 0U; index < ROME2_100ED3C0_LIFECYCLE_BACKING_COUNT;
            ++index) {
        state.backing_spans[index].start = state.backings[index].host_start;
        state.backing_spans[index].byte_count =
            state.backings[index].byte_count;
    }
    private_span.start = (uint64_t)(uintptr_t)&state;
    private_span.byte_count = sizeof(state);
    if (rome2_100ed3c0_lifecycle_backings_overlap(
            state.backings, ROME2_100ED3C0_LIFECYCLE_BACKING_COUNT) ||
        rome2_100ed3c0_lifecycle_sets_overlap(
            state.backing_spans,
            ROME2_100ED3C0_LIFECYCLE_BACKING_COUNT,
            state.controls,
            ROME2_100ED3C0_LIFECYCLE_CONTROL_COUNT) ||
        rome2_100ed3c0_lifecycle_sets_overlap(
            state.backing_spans,
            ROME2_100ED3C0_LIFECYCLE_BACKING_COUNT,
            &private_span,
            1U) ||
        rome2_100ed3c0_lifecycle_sets_overlap(
            state.controls,
            ROME2_100ED3C0_LIFECYCLE_CONTROL_COUNT,
            &private_span,
            1U)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    if (state.effects.preloop.emit_step == NULL ||
        state.effects.preloop.child_prefix.emit_step == NULL ||
        state.effects.preloop.child_suffix.emit_step == NULL ||
        state.effects.preloop.temporary_owned.allocate == NULL ||
        state.effects.preloop.temporary_owned.release == NULL ||
        state.effects.preloop.persistent_owned.allocate == NULL ||
        state.effects.preloop.persistent_owned.release == NULL ||
        state.effects.ordinary.emit_step == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    state.contexts[0].start =
        (uint64_t)(uintptr_t)state.effects.preloop.context;
    state.contexts[0].byte_count = state.effects.preloop.context_byte_count;
    state.contexts[1].start =
        (uint64_t)(uintptr_t)state.effects.preloop.child_prefix.context;
    state.contexts[1].byte_count =
        state.effects.preloop.child_prefix_context_byte_count;
    state.contexts[2].start =
        (uint64_t)(uintptr_t)state.effects.preloop.child_suffix.context;
    state.contexts[2].byte_count =
        state.effects.preloop.child_suffix_context_byte_count;
    state.contexts[3].start = (uint64_t)(uintptr_t)
        state.effects.preloop.temporary_owned.context;
    state.contexts[3].byte_count =
        state.effects.preloop.temporary_owned.context_byte_count;
    state.contexts[4].start = (uint64_t)(uintptr_t)
        state.effects.preloop.persistent_owned.context;
    state.contexts[4].byte_count =
        state.effects.preloop.persistent_owned.context_byte_count;
    state.contexts[5].start =
        (uint64_t)(uintptr_t)state.effects.ordinary.context;
    state.contexts[5].byte_count = state.effects.ordinary_context_byte_count;
    for (index = 0U; index < ROME2_100ED3C0_LIFECYCLE_CONTEXT_COUNT;
            ++index) {
        owned_status = rome2_100ed3c0_lifecycle_validate_host_interval(
            (const void *)(uintptr_t)state.contexts[index].start,
            state.contexts[index].byte_count);
        if (owned_status != ROME2_100F1BB0_OWNED_OK) return owned_status;
    }
    if (rome2_100ed3c0_lifecycle_contexts_partially_overlap(
            state.contexts, ROME2_100ED3C0_LIFECYCLE_CONTEXT_COUNT) ||
        rome2_100ed3c0_lifecycle_sets_overlap(
            state.contexts,
            ROME2_100ED3C0_LIFECYCLE_CONTEXT_COUNT,
            state.controls,
            ROME2_100ED3C0_LIFECYCLE_CONTROL_COUNT) ||
        rome2_100ed3c0_lifecycle_sets_overlap(
            state.contexts,
            ROME2_100ED3C0_LIFECYCLE_CONTEXT_COUNT,
            state.backing_spans,
            ROME2_100ED3C0_LIFECYCLE_BACKING_COUNT) ||
        rome2_100ed3c0_lifecycle_sets_overlap(
            state.contexts,
            ROME2_100ED3C0_LIFECYCLE_CONTEXT_COUNT,
            &private_span,
            1U)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    memset(state.preview_frame, 0xa5, sizeof(state.preview_frame));
    for (index = 0U; index < ROME2_100ED3C0_LIFECYCLE_CLEANUP_COUNT;
            ++index) {
        rome2_100ed3c0_lifecycle_write_empty_descriptor(
            state.preview_frame + cleanup_offsets[index]);
    }
    state.preview_frame_view.host_base = state.preview_frame;
    state.preview_frame_view.guest_base = state.frame_view.guest_base;
    state.preview_frame_view.byte_count = sizeof(state.preview_frame);
    state.preview_effects = state.effects.ordinary;
    state.preview_effects.emit_step = rome2_100ed3c0_lifecycle_preview_emit;
    state.preview_effects.context = &state.preview_trace;
    guest_status = rome2_port_100ed471_run_ordinary_lifecycle(
        &state.preview_frame_view,
        guest_frame,
        &state.dispatch_view,
        dispatch_receiver,
        max_poll_calls,
        &state.preview_effects,
        &state.preview_result);
    if (guest_status != ROME2_GUEST_OK) {
        return rome2_100ed3c0_lifecycle_from_guest(guest_status);
    }
    if (state.preview_trace.step_count !=
            ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_FIXED_TAIL_EVENTS +
                state.effects.ordinary.poll_result_count ||
        state.preview_result.poll_calls !=
            state.effects.ordinary.poll_result_count ||
        state.preview_result.terminal_poll_result != UINT32_C(2) ||
        state.preview_result.timestamp_low !=
            state.effects.ordinary.timestamp_low ||
        state.preview_result.timestamp_high !=
            state.effects.ordinary.timestamp_high ||
        state.preview_result.return_original_pc !=
            ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_RETURN_PC) {
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }
    for (index = 0U; index < ROME2_100ED3C0_LIFECYCLE_CLEANUP_COUNT;
            ++index) {
        if (!rome2_100ed3c0_lifecycle_is_empty_descriptor(
                state.preview_frame + cleanup_offsets[index])) {
            return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
        }
    }

    owned_status = rome2_port_100ed3c0_run_nonempty_preloop(
        &state.frame_view,
        guest_frame,
        argument_position1,
        &state.text_view,
        argument_position3_text,
        text_max_units,
        &state.selector_view,
        &state.temporary_heap_view,
        &state.persistent_descriptor_view,
        &state.persistent_heap_view,
        &state.effects.preloop,
        temporary_owner,
        persistent_owner,
        lifecycle,
        &state.preloop_result);
    if (owned_status != ROME2_100F1BB0_OWNED_OK) {
        return owned_status;
    }
    if (state.preloop_result.next_original_pc !=
            ROME2_PORT_100ED471_START_PC ||
        temporary_owner->phase !=
            ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED ||
        persistent_owner->phase != ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||
        lifecycle->phase !=
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE) {
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }

    guest_status = rome2_port_100ed471_run_ordinary_lifecycle(
        &state.frame_view,
        guest_frame,
        &state.dispatch_view,
        dispatch_receiver,
        max_poll_calls,
        &state.effects.ordinary,
        &state.ordinary_result);
    if (guest_status != ROME2_GUEST_OK) {
        return rome2_100ed3c0_lifecycle_from_guest(guest_status);
    }
    if (memcmp(
            &state.ordinary_result,
            &state.preview_result,
            sizeof(state.ordinary_result)) != 0 ||
        state.ordinary_result.return_original_pc !=
            ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_RETURN_PC) {
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }

    state.combined_result.preloop = state.preloop_result;
    state.combined_result.ordinary = state.ordinary_result;
    *result_out = state.combined_result;
    return ROME2_100F1BB0_OWNED_OK;
}


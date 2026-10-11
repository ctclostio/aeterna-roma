#include "ported_100edd70_entry_decision.h"

#include <stddef.h>
#include <stdint.h>

#define ROME2_100EDD70_ENTRY_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100EDD70_ENTRY_CONTROL_COUNT 14U
#define ROME2_100EDD70_ENTRY_BACKING_COUNT 7U
#define ROME2_100EDD70_ENTRY_CONTEXT_COUNT 8U

typedef struct rome2_100edd70_entry_host_span {
    uint64_t start;
    uint64_t byte_count;
} rome2_100edd70_entry_host_span;

typedef struct rome2_100edd70_entry_backing {
    uint64_t host_start;
    uint64_t guest_start;
    uint64_t byte_count;
} rome2_100edd70_entry_backing;

typedef struct rome2_100edd70_entry_private {
    uint32_t caller_position1;
    uint32_t caller_position2;
    rome2_guest_addr32 caller_position3_text;
    uint32_t caller_position4;
    rome2_guest_addr32 guest_frame;
    rome2_guest_addr32 dispatch_receiver;
    uint32_t text_max_units;
    uint32_t max_poll_calls;
    rome2_guest_write_view frame_view;
    rome2_guest_read_view text_view;
    rome2_guest_write_view selector_view;
    rome2_guest_write_view temporary_heap_view;
    rome2_guest_write_view persistent_descriptor_view;
    rome2_guest_write_view persistent_heap_view;
    rome2_guest_read_view dispatch_view;
    rome2_100ed3c0_nonempty_lifecycle_effects parent_effects;
    rome2_100edd70_caller_closure_effects continuation_effects;
    rome2_100edd70_registration_effects registration_effects;
    rome2_invalid_parameter_policy policy;
    rome2_100edd70_registration_step registration[
        ROME2_PORT_100EDD70_REGISTRATION_RECORD_COUNT];
    rome2_100edd70_caller_closure_result child_result;
    rome2_100edd70_entry_decision_result combined_result;
    rome2_100edd70_entry_host_span
        controls[ROME2_100EDD70_ENTRY_CONTROL_COUNT];
    rome2_100edd70_entry_backing
        backings[ROME2_100EDD70_ENTRY_BACKING_COUNT];
    rome2_100edd70_entry_host_span
        backing_spans[ROME2_100EDD70_ENTRY_BACKING_COUNT];
    rome2_100edd70_entry_host_span
        contexts[ROME2_100EDD70_ENTRY_CONTEXT_COUNT];
} rome2_100edd70_entry_private;

_Static_assert(
    ROME2_PORT_100EDD70_SELECTOR_END_PC -
            ROME2_PORT_100EDD70_SELECTOR_START_PC == UINT32_C(57),
    "the authenticated selector interval changed");
_Static_assert(
    ROME2_PORT_100EDD70_REGISTRATION_END_PC -
            ROME2_PORT_100EDD70_REGISTRATION_START_PC == UINT32_C(27),
    "the authenticated registration interval changed");
_Static_assert(
    ROME2_PORT_100EDD70_REGISTRATION_RECORD_COUNT == UINT32_C(4),
    "the registration transcript must have four records");
_Static_assert(
    ROME2_PORT_100EDD70_REGISTRATION_CLEANUP_BYTES ==
            ROME2_PORT_100EDD70_REGISTRATION_WIDTH,
    "the registration argument, cleanup, and stores are four bytes");
_Static_assert(sizeof(rome2_100edd70_registration_step) == 32U,
    "the registration record must have a stable native layout");

static rome2_100f1bb0_owned_status rome2_100edd70_entry_validate_object(
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

static rome2_100f1bb0_owned_status rome2_100edd70_entry_validate_view(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100EDD70_ENTRY_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100EDD70_ENTRY_ADDRESS_SPACE_SIZE) {
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
rome2_100edd70_entry_validate_host_interval(
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

static int rome2_100edd70_entry_ranges_overlap(
    uint64_t first_start,
    uint64_t first_size,
    uint64_t second_start,
    uint64_t second_size)
{
    if (first_size == UINT64_C(0) || second_size == UINT64_C(0)) return 0;
    if (first_start >= second_start) {
        return first_start - second_start < second_size;
    }
    return second_start - first_start < first_size;
}

static int rome2_100edd70_entry_host_spans_overlap(
    const rome2_100edd70_entry_host_span *spans,
    size_t count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < count; ++first) {
        for (second = first + 1U; second < count; ++second) {
            if (rome2_100edd70_entry_ranges_overlap(
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

static int rome2_100edd70_entry_backings_overlap(
    const rome2_100edd70_entry_backing *backings,
    size_t count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < count; ++first) {
        for (second = first + 1U; second < count; ++second) {
            if (rome2_100edd70_entry_ranges_overlap(
                    backings[first].host_start,
                    backings[first].byte_count,
                    backings[second].host_start,
                    backings[second].byte_count) ||
                rome2_100edd70_entry_ranges_overlap(
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

static int rome2_100edd70_entry_sets_overlap(
    const rome2_100edd70_entry_host_span *first,
    size_t first_count,
    const rome2_100edd70_entry_host_span *second,
    size_t second_count)
{
    size_t first_index;
    size_t second_index;

    for (first_index = 0U; first_index < first_count; ++first_index) {
        for (second_index = 0U; second_index < second_count; ++second_index) {
            if (rome2_100edd70_entry_ranges_overlap(
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

static int rome2_100edd70_entry_contexts_partially_overlap(
    const rome2_100edd70_entry_host_span *contexts,
    size_t count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < count; ++first) {
        for (second = first + 1U; second < count; ++second) {
            if (rome2_100edd70_entry_ranges_overlap(
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

static int rome2_100edd70_entry_owner_is_empty(
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

static uint32_t rome2_100edd70_entry_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static rome2_100f1bb0_owned_status
rome2_100edd70_entry_validate_ownership_prestate(
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_100f1bb0_owned_owner *temporary_owner,
    const rome2_100f1bb0_owned_owner *persistent_owner,
    const rome2_100f2750_first_use_lifecycle *lifecycle)
{
    const uint8_t *descriptor;
    uint64_t offset;

    if (!rome2_100edd70_entry_owner_is_empty(temporary_owner) ||
        !rome2_100edd70_entry_owner_is_empty(persistent_owner) ||
        lifecycle->phase !=
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL ||
        lifecycle->reserved != UINT32_C(0)) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }
    if (ROME2_PORT_100F2750_FIRST_USE_DESTINATION <
        persistent_descriptor_view->guest_base) {
        return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
    }
    offset = (uint64_t)ROME2_PORT_100F2750_FIRST_USE_DESTINATION -
        persistent_descriptor_view->guest_base;
    if (offset > persistent_descriptor_view->byte_count ||
        UINT64_C(12) > persistent_descriptor_view->byte_count - offset) {
        return ROME2_100F1BB0_OWNED_OUT_OF_RANGE;
    }
    descriptor = persistent_descriptor_view->host_base + (size_t)offset;
    if (rome2_100edd70_entry_read_u32_le(descriptor) != UINT32_C(0) ||
        rome2_100edd70_entry_read_u32_le(descriptor + 4U) != UINT32_C(0) ||
        rome2_100edd70_entry_read_u32_le(descriptor + 8U) !=
            ROME2_PORT_100F2750_FIRST_USE_SENTINEL) {
        return ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID;
    }
    return ROME2_100F1BB0_OWNED_OK;
}

static rome2_100f1bb0_owned_status rome2_100edd70_entry_map_guest_status(
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

static rome2_100edd70_registration_step rome2_100edd70_entry_make_step(
    rome2_100edd70_registration_step_kind kind,
    uint32_t instruction_pc,
    uint32_t push_pc,
    uint32_t callee_pc,
    uint32_t handler_argument,
    int32_t frame_displacement,
    uint32_t value,
    uint32_t width_or_cleanup_bytes)
{
    rome2_100edd70_registration_step step;

    step.kind = kind;
    step.instruction_original_pc = instruction_pc;
    step.push_original_pc = push_pc;
    step.callee_original_pc = callee_pc;
    step.handler_argument = handler_argument;
    step.frame_displacement = frame_displacement;
    step.value = value;
    step.width_or_cleanup_bytes = width_or_cleanup_bytes;
    return step;
}

rome2_100f1bb0_owned_status rome2_port_100edd70_run_selected_route(
    uint32_t caller_position1,
    uint32_t caller_position2,
    rome2_guest_addr32 caller_position3_text,
    uint32_t caller_position4,
    const rome2_guest_write_view *frame_view,
    rome2_guest_addr32 guest_frame,
    const rome2_guest_read_view *text_view,
    uint32_t text_max_units,
    const rome2_guest_write_view *selector_view,
    const rome2_guest_write_view *temporary_heap_view,
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_guest_write_view *persistent_heap_view,
    const rome2_guest_read_view *dispatch_view,
    rome2_guest_addr32 dispatch_receiver,
    uint32_t max_poll_calls,
    const rome2_100ed3c0_nonempty_lifecycle_effects *parent_effects,
    const rome2_100edd70_caller_closure_effects *continuation_effects,
    const rome2_100edd70_registration_effects *registration_effects,
    rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_100edd70_entry_decision_result *result_out)
{
    rome2_100edd70_entry_private state = {0};
    rome2_100edd70_entry_host_span private_span;
    rome2_100f1bb0_owned_status status;
    rome2_guest_status guest_status;
    size_t index;

#define ROME2_VALIDATE_ENTRY_OBJECT(object_) \
    do { \
        status = rome2_100edd70_entry_validate_object( \
            (object_), sizeof(*(object_))); \
        if (status != ROME2_100F1BB0_OWNED_OK) return status; \
    } while (0)
    ROME2_VALIDATE_ENTRY_OBJECT(frame_view);
    ROME2_VALIDATE_ENTRY_OBJECT(text_view);
    ROME2_VALIDATE_ENTRY_OBJECT(selector_view);
    ROME2_VALIDATE_ENTRY_OBJECT(temporary_heap_view);
    ROME2_VALIDATE_ENTRY_OBJECT(persistent_descriptor_view);
    ROME2_VALIDATE_ENTRY_OBJECT(persistent_heap_view);
    ROME2_VALIDATE_ENTRY_OBJECT(dispatch_view);
    ROME2_VALIDATE_ENTRY_OBJECT(parent_effects);
    ROME2_VALIDATE_ENTRY_OBJECT(continuation_effects);
    ROME2_VALIDATE_ENTRY_OBJECT(registration_effects);
    ROME2_VALIDATE_ENTRY_OBJECT(temporary_owner);
    ROME2_VALIDATE_ENTRY_OBJECT(persistent_owner);
    ROME2_VALIDATE_ENTRY_OBJECT(lifecycle);
    ROME2_VALIDATE_ENTRY_OBJECT(result_out);
#undef ROME2_VALIDATE_ENTRY_OBJECT

    if ((uintptr_t)frame_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)text_view % _Alignof(rome2_guest_read_view) != 0U ||
        (uintptr_t)selector_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)temporary_heap_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)persistent_descriptor_view %
            _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)persistent_heap_view % _Alignof(rome2_guest_write_view) != 0U ||
        (uintptr_t)dispatch_view % _Alignof(rome2_guest_read_view) != 0U ||
        (uintptr_t)parent_effects %
            _Alignof(rome2_100ed3c0_nonempty_lifecycle_effects) != 0U ||
        (uintptr_t)continuation_effects %
            _Alignof(rome2_100edd70_caller_closure_effects) != 0U ||
        (uintptr_t)registration_effects %
            _Alignof(rome2_100edd70_registration_effects) != 0U ||
        (uintptr_t)temporary_owner %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)persistent_owner %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)lifecycle %
            _Alignof(rome2_100f2750_first_use_lifecycle) != 0U ||
        (uintptr_t)result_out %
            _Alignof(rome2_100edd70_entry_decision_result) != 0U) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

#define ROME2_SET_ENTRY_CONTROL(index_, object_) \
    do { \
        state.controls[(index_)].start = (uint64_t)(uintptr_t)(object_); \
        state.controls[(index_)].byte_count = sizeof(*(object_)); \
    } while (0)
    ROME2_SET_ENTRY_CONTROL(0U, frame_view);
    ROME2_SET_ENTRY_CONTROL(1U, text_view);
    ROME2_SET_ENTRY_CONTROL(2U, selector_view);
    ROME2_SET_ENTRY_CONTROL(3U, temporary_heap_view);
    ROME2_SET_ENTRY_CONTROL(4U, persistent_descriptor_view);
    ROME2_SET_ENTRY_CONTROL(5U, persistent_heap_view);
    ROME2_SET_ENTRY_CONTROL(6U, dispatch_view);
    ROME2_SET_ENTRY_CONTROL(7U, parent_effects);
    ROME2_SET_ENTRY_CONTROL(8U, continuation_effects);
    ROME2_SET_ENTRY_CONTROL(9U, registration_effects);
    ROME2_SET_ENTRY_CONTROL(10U, temporary_owner);
    ROME2_SET_ENTRY_CONTROL(11U, persistent_owner);
    ROME2_SET_ENTRY_CONTROL(12U, lifecycle);
    ROME2_SET_ENTRY_CONTROL(13U, result_out);
#undef ROME2_SET_ENTRY_CONTROL
    if (rome2_100edd70_entry_host_spans_overlap(
            state.controls, ROME2_100EDD70_ENTRY_CONTROL_COUNT)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.caller_position1 = caller_position1;
    state.caller_position2 = caller_position2;
    state.caller_position3_text = caller_position3_text;
    state.caller_position4 = caller_position4;
    state.guest_frame = guest_frame;
    state.dispatch_receiver = dispatch_receiver;
    state.text_max_units = text_max_units;
    state.max_poll_calls = max_poll_calls;
    state.frame_view = *frame_view;
    state.text_view = *text_view;
    state.selector_view = *selector_view;
    state.temporary_heap_view = *temporary_heap_view;
    state.persistent_descriptor_view = *persistent_descriptor_view;
    state.persistent_heap_view = *persistent_heap_view;
    state.dispatch_view = *dispatch_view;
    state.parent_effects = *parent_effects;
    state.continuation_effects = *continuation_effects;
    state.registration_effects = *registration_effects;

#define ROME2_VALIDATE_ENTRY_VIEW(view_) \
    do { \
        status = rome2_100edd70_entry_validate_view( \
            (view_).host_base, (view_).guest_base, (view_).byte_count); \
        if (status != ROME2_100F1BB0_OWNED_OK) return status; \
    } while (0)
    ROME2_VALIDATE_ENTRY_VIEW(state.frame_view);
    ROME2_VALIDATE_ENTRY_VIEW(state.text_view);
    ROME2_VALIDATE_ENTRY_VIEW(state.selector_view);
    ROME2_VALIDATE_ENTRY_VIEW(state.temporary_heap_view);
    ROME2_VALIDATE_ENTRY_VIEW(state.persistent_descriptor_view);
    ROME2_VALIDATE_ENTRY_VIEW(state.persistent_heap_view);
    ROME2_VALIDATE_ENTRY_VIEW(state.dispatch_view);
#undef ROME2_VALIDATE_ENTRY_VIEW
    if (state.frame_view.guest_base != state.guest_frame.value ||
        state.frame_view.byte_count !=
            ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_FRAME_BYTES ||
        state.text_max_units < UINT32_C(2) ||
        state.text_max_units > ROME2_PORT_100F1BB0_OWNED_MAX_UNITS ||
        state.max_poll_calls == UINT32_C(0) ||
        state.max_poll_calls > ROME2_PORT_100ED471_MAX_POLL_CALLS) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

#define ROME2_SET_ENTRY_BACKING(index_, view_) \
    do { \
        state.backings[(index_)].host_start = \
            (uint64_t)(uintptr_t)(view_).host_base; \
        state.backings[(index_)].guest_start = (view_).guest_base; \
        state.backings[(index_)].byte_count = (view_).byte_count; \
    } while (0)
    ROME2_SET_ENTRY_BACKING(0U, state.frame_view);
    ROME2_SET_ENTRY_BACKING(1U, state.text_view);
    ROME2_SET_ENTRY_BACKING(2U, state.selector_view);
    ROME2_SET_ENTRY_BACKING(3U, state.temporary_heap_view);
    ROME2_SET_ENTRY_BACKING(4U, state.persistent_descriptor_view);
    ROME2_SET_ENTRY_BACKING(5U, state.persistent_heap_view);
    ROME2_SET_ENTRY_BACKING(6U, state.dispatch_view);
#undef ROME2_SET_ENTRY_BACKING
    for (index = 0U; index < ROME2_100EDD70_ENTRY_BACKING_COUNT; ++index) {
        state.backing_spans[index].start = state.backings[index].host_start;
        state.backing_spans[index].byte_count = state.backings[index].byte_count;
    }
    private_span.start = (uint64_t)(uintptr_t)&state;
    private_span.byte_count = sizeof(state);
    if (rome2_100edd70_entry_backings_overlap(
            state.backings, ROME2_100EDD70_ENTRY_BACKING_COUNT) ||
        rome2_100edd70_entry_sets_overlap(
            state.backing_spans,
            ROME2_100EDD70_ENTRY_BACKING_COUNT,
            state.controls,
            ROME2_100EDD70_ENTRY_CONTROL_COUNT) ||
        rome2_100edd70_entry_sets_overlap(
            state.backing_spans,
            ROME2_100EDD70_ENTRY_BACKING_COUNT,
            &private_span,
            1U) ||
        rome2_100edd70_entry_sets_overlap(
            state.controls,
            ROME2_100EDD70_ENTRY_CONTROL_COUNT,
            &private_span,
            1U)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    if (state.parent_effects.preloop.emit_step == NULL ||
        state.parent_effects.preloop.child_prefix.emit_step == NULL ||
        state.parent_effects.preloop.child_suffix.emit_step == NULL ||
        state.parent_effects.preloop.temporary_owned.allocate == NULL ||
        state.parent_effects.preloop.temporary_owned.release == NULL ||
        state.parent_effects.preloop.persistent_owned.allocate == NULL ||
        state.parent_effects.preloop.persistent_owned.release == NULL ||
        state.parent_effects.ordinary.emit_step == NULL ||
        state.continuation_effects.emit_step == NULL ||
        state.registration_effects.emit_step == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.contexts[0].start =
        (uint64_t)(uintptr_t)state.parent_effects.preloop.context;
    state.contexts[0].byte_count =
        state.parent_effects.preloop.context_byte_count;
    state.contexts[1].start = (uint64_t)(uintptr_t)
        state.parent_effects.preloop.child_prefix.context;
    state.contexts[1].byte_count =
        state.parent_effects.preloop.child_prefix_context_byte_count;
    state.contexts[2].start = (uint64_t)(uintptr_t)
        state.parent_effects.preloop.child_suffix.context;
    state.contexts[2].byte_count =
        state.parent_effects.preloop.child_suffix_context_byte_count;
    state.contexts[3].start = (uint64_t)(uintptr_t)
        state.parent_effects.preloop.temporary_owned.context;
    state.contexts[3].byte_count =
        state.parent_effects.preloop.temporary_owned.context_byte_count;
    state.contexts[4].start = (uint64_t)(uintptr_t)
        state.parent_effects.preloop.persistent_owned.context;
    state.contexts[4].byte_count =
        state.parent_effects.preloop.persistent_owned.context_byte_count;
    state.contexts[5].start =
        (uint64_t)(uintptr_t)state.parent_effects.ordinary.context;
    state.contexts[5].byte_count =
        state.parent_effects.ordinary_context_byte_count;
    state.contexts[6].start =
        (uint64_t)(uintptr_t)state.continuation_effects.context;
    state.contexts[6].byte_count =
        state.continuation_effects.context_byte_count;
    state.contexts[7].start =
        (uint64_t)(uintptr_t)state.registration_effects.context;
    state.contexts[7].byte_count =
        state.registration_effects.context_byte_count;
    for (index = 0U; index < ROME2_100EDD70_ENTRY_CONTEXT_COUNT; ++index) {
        status = rome2_100edd70_entry_validate_host_interval(
            (const void *)(uintptr_t)state.contexts[index].start,
            state.contexts[index].byte_count);
        if (status != ROME2_100F1BB0_OWNED_OK) return status;
    }
    if (rome2_100edd70_entry_contexts_partially_overlap(
            state.contexts, ROME2_100EDD70_ENTRY_CONTEXT_COUNT) ||
        rome2_100edd70_entry_sets_overlap(
            state.contexts,
            ROME2_100EDD70_ENTRY_CONTEXT_COUNT,
            state.controls,
            ROME2_100EDD70_ENTRY_CONTROL_COUNT) ||
        rome2_100edd70_entry_sets_overlap(
            state.contexts,
            ROME2_100EDD70_ENTRY_CONTEXT_COUNT,
            state.backing_spans,
            ROME2_100EDD70_ENTRY_BACKING_COUNT) ||
        rome2_100edd70_entry_sets_overlap(
            state.contexts,
            ROME2_100EDD70_ENTRY_CONTEXT_COUNT,
            &private_span,
            1U)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    status = rome2_100edd70_entry_validate_ownership_prestate(
        &state.persistent_descriptor_view,
        temporary_owner,
        persistent_owner,
        lifecycle);
    if (status != ROME2_100F1BB0_OWNED_OK) return status;

    guest_status = rome2_port_100edd70_select_invalid_parameter_policy(
        &state.text_view,
        state.caller_position3_text,
        &state.policy);
    if (guest_status != ROME2_GUEST_OK) {
        return rome2_100edd70_entry_map_guest_status(guest_status);
    }
    if (state.policy != ROME2_INVALID_PARAMETER_INSTALL_HANDLER &&
        state.policy != ROME2_INVALID_PARAMETER_SKIP_HANDLER) {
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }

    if (state.policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER) {
        state.registration[0] = rome2_100edd70_entry_make_step(
            ROME2_100EDD70_REGISTRATION_STEP_REGISTER_HANDLER_CALL,
            ROME2_PORT_100EDD70_REGISTRATION_CALL_PC,
            ROME2_PORT_100EDD70_REGISTRATION_PUSH_PC,
            ROME2_PORT_100EDD70_REGISTRATION_CALLEE_PC,
            ROME2_PORT_100EDD70_REGISTRATION_HANDLER_ARGUMENT,
            INT32_C(0),
            UINT32_C(0),
            ROME2_PORT_100EDD70_REGISTRATION_WIDTH);
        state.registration[1] = rome2_100edd70_entry_make_step(
            ROME2_100EDD70_REGISTRATION_STEP_CLEANUP_4,
            ROME2_PORT_100EDD70_REGISTRATION_CLEANUP_PC,
            UINT32_C(0),
            UINT32_C(0),
            UINT32_C(0),
            INT32_C(0),
            UINT32_C(0),
            ROME2_PORT_100EDD70_REGISTRATION_CLEANUP_BYTES);
        state.registration[2] = rome2_100edd70_entry_make_step(
            ROME2_100EDD70_REGISTRATION_STEP_FRAME_STORE,
            ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_20_PC,
            UINT32_C(0),
            UINT32_C(0),
            UINT32_C(0),
            ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_20,
            ROME2_PORT_100EDD70_REGISTRATION_STORE_VALUE,
            ROME2_PORT_100EDD70_REGISTRATION_WIDTH);
        state.registration[3] = rome2_100edd70_entry_make_step(
            ROME2_100EDD70_REGISTRATION_STEP_FRAME_STORE,
            ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_04_PC,
            UINT32_C(0),
            UINT32_C(0),
            UINT32_C(0),
            ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_04,
            ROME2_PORT_100EDD70_REGISTRATION_STORE_VALUE,
            ROME2_PORT_100EDD70_REGISTRATION_WIDTH);
        for (index = 0U;
                index < ROME2_PORT_100EDD70_REGISTRATION_RECORD_COUNT;
                ++index) {
            state.registration_effects.emit_step(
                state.registration_effects.context,
                state.registration[index]);
        }
    }

    status = rome2_port_100edd70_run_caller_closure(
        state.policy,
        state.caller_position1,
        state.caller_position2,
        state.caller_position3_text,
        state.caller_position4,
        &state.frame_view,
        state.guest_frame,
        &state.text_view,
        state.text_max_units,
        &state.selector_view,
        &state.temporary_heap_view,
        &state.persistent_descriptor_view,
        &state.persistent_heap_view,
        &state.dispatch_view,
        state.dispatch_receiver,
        state.max_poll_calls,
        &state.parent_effects,
        &state.continuation_effects,
        temporary_owner,
        persistent_owner,
        lifecycle,
        &state.child_result);
    if (status != ROME2_100F1BB0_OWNED_OK) return status;

    state.combined_result.policy = state.policy;
    state.combined_result.registration_record_count =
        state.policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER ?
            ROME2_PORT_100EDD70_REGISTRATION_RECORD_COUNT : UINT32_C(0);
    for (index = 0U;
            index < ROME2_PORT_100EDD70_REGISTRATION_RECORD_COUNT;
            ++index) {
        state.combined_result.registration[index] = state.registration[index];
    }
    state.combined_result.child = state.child_result;
    *result_out = state.combined_result;
    return ROME2_100F1BB0_OWNED_OK;
}

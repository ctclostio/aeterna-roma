#include "ported_100edd70_caller_closure.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ROME2_100EDD70_CLOSURE_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_100EDD70_CLOSURE_CONTROL_COUNT 13U
#define ROME2_100EDD70_CLOSURE_BACKING_COUNT 7U
#define ROME2_100EDD70_CLOSURE_CONTEXT_COUNT 7U

typedef struct rome2_100edd70_closure_host_span {
    uint64_t start;
    uint64_t byte_count;
} rome2_100edd70_closure_host_span;

typedef struct rome2_100edd70_closure_backing {
    uint64_t host_start;
    uint64_t guest_start;
    uint64_t byte_count;
} rome2_100edd70_closure_backing;

typedef struct rome2_100edd70_closure_private {
    rome2_invalid_parameter_policy policy;
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
    rome2_100ed3c0_nonempty_lifecycle_result parent_result;
    rome2_100edd70_caller_closure_result combined_result;
    rome2_100edd70_closure_host_span
        controls[ROME2_100EDD70_CLOSURE_CONTROL_COUNT];
    rome2_100edd70_closure_backing
        backings[ROME2_100EDD70_CLOSURE_BACKING_COUNT];
    rome2_100edd70_closure_host_span
        backing_spans[ROME2_100EDD70_CLOSURE_BACKING_COUNT];
    rome2_100edd70_closure_host_span
        contexts[ROME2_100EDD70_CLOSURE_CONTEXT_COUNT];
} rome2_100edd70_closure_private;

_Static_assert(
    ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_RETURN_PC == UINT32_C(0x100ed550),
    "the caller closure must bind the frozen parent return");
_Static_assert(
    ROME2_PORT_100EDD70_CALLER_CLEANUP_BYTES ==
        (ROME2_PORT_100EDD70_CALLER_PUSH_COUNT + UINT32_C(2)) * UINT32_C(4),
    "the grouped cleanup must discard four parent and two keeper pushes");

static rome2_100f1bb0_owned_status rome2_100edd70_closure_validate_object(
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

static rome2_100f1bb0_owned_status rome2_100edd70_closure_validate_view(
    const void *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    uintptr_t host_address;

    if (host_base == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    if (byte_count > ROME2_100EDD70_CLOSURE_ADDRESS_SPACE_SIZE ||
        (uint64_t)guest_base + byte_count >
            ROME2_100EDD70_CLOSURE_ADDRESS_SPACE_SIZE) {
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
rome2_100edd70_closure_validate_host_interval(
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

static int rome2_100edd70_closure_ranges_overlap(
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

static int rome2_100edd70_closure_host_spans_overlap(
    const rome2_100edd70_closure_host_span *spans,
    size_t count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < count; ++first) {
        for (second = first + 1U; second < count; ++second) {
            if (rome2_100edd70_closure_ranges_overlap(
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

static int rome2_100edd70_closure_backings_overlap(
    const rome2_100edd70_closure_backing *backings,
    size_t count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < count; ++first) {
        for (second = first + 1U; second < count; ++second) {
            if (rome2_100edd70_closure_ranges_overlap(
                    backings[first].host_start,
                    backings[first].byte_count,
                    backings[second].host_start,
                    backings[second].byte_count) ||
                rome2_100edd70_closure_ranges_overlap(
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

static int rome2_100edd70_closure_sets_overlap(
    const rome2_100edd70_closure_host_span *first,
    size_t first_count,
    const rome2_100edd70_closure_host_span *second,
    size_t second_count)
{
    size_t first_index;
    size_t second_index;

    for (first_index = 0U; first_index < first_count; ++first_index) {
        for (second_index = 0U; second_index < second_count; ++second_index) {
            if (rome2_100edd70_closure_ranges_overlap(
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

static int rome2_100edd70_closure_contexts_partially_overlap(
    const rome2_100edd70_closure_host_span *contexts,
    size_t count)
{
    size_t first;
    size_t second;

    for (first = 0U; first < count; ++first) {
        for (second = first + 1U; second < count; ++second) {
            if (rome2_100edd70_closure_ranges_overlap(
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

static void rome2_100edd70_closure_set_push(
    rome2_100edd70_caller_push *push,
    uint32_t instruction_pc,
    uint32_t machine_order,
    uint32_t callee_position,
    uint32_t value)
{
    push->instruction_original_pc = instruction_pc;
    push->machine_order = machine_order;
    push->callee_position = callee_position;
    push->value = value;
}

static rome2_100edd70_caller_closure_step
rome2_100edd70_closure_make_step(
    rome2_100edd70_caller_closure_step_kind kind,
    uint32_t instruction_pc,
    uint32_t target_pc,
    uint32_t destination,
    uint32_t value,
    uint32_t width_or_cleanup_bytes)
{
    rome2_100edd70_caller_closure_step step;

    step.kind = kind;
    step.instruction_original_pc = instruction_pc;
    step.target_original_pc = target_pc;
    step.destination_identity = destination;
    step.value = value;
    step.width_or_cleanup_bytes = width_or_cleanup_bytes;
    return step;
}

rome2_100f1bb0_owned_status rome2_port_100edd70_run_caller_closure(
    rome2_invalid_parameter_policy policy,
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
    rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_100edd70_caller_closure_result *result_out)
{
    rome2_100edd70_closure_private state = {0};
    rome2_100edd70_closure_host_span private_span;
    rome2_100f1bb0_owned_status status;
    uint32_t push_base;
    uint32_t byte_call_pc;
    uint32_t dword_call_pc;
    uint32_t cleanup_pc;
    size_t index;

    if (policy != ROME2_INVALID_PARAMETER_INSTALL_HANDLER &&
        policy != ROME2_INVALID_PARAMETER_SKIP_HANDLER) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

#define ROME2_VALIDATE_CLOSURE_OBJECT(object_) \
    do { \
        status = rome2_100edd70_closure_validate_object( \
            (object_), sizeof(*(object_))); \
        if (status != ROME2_100F1BB0_OWNED_OK) return status; \
    } while (0)
    ROME2_VALIDATE_CLOSURE_OBJECT(frame_view);
    ROME2_VALIDATE_CLOSURE_OBJECT(text_view);
    ROME2_VALIDATE_CLOSURE_OBJECT(selector_view);
    ROME2_VALIDATE_CLOSURE_OBJECT(temporary_heap_view);
    ROME2_VALIDATE_CLOSURE_OBJECT(persistent_descriptor_view);
    ROME2_VALIDATE_CLOSURE_OBJECT(persistent_heap_view);
    ROME2_VALIDATE_CLOSURE_OBJECT(dispatch_view);
    ROME2_VALIDATE_CLOSURE_OBJECT(parent_effects);
    ROME2_VALIDATE_CLOSURE_OBJECT(continuation_effects);
    ROME2_VALIDATE_CLOSURE_OBJECT(temporary_owner);
    ROME2_VALIDATE_CLOSURE_OBJECT(persistent_owner);
    ROME2_VALIDATE_CLOSURE_OBJECT(lifecycle);
    ROME2_VALIDATE_CLOSURE_OBJECT(result_out);
#undef ROME2_VALIDATE_CLOSURE_OBJECT

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
        (uintptr_t)temporary_owner %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)persistent_owner %
            _Alignof(rome2_100f1bb0_owned_owner) != 0U ||
        (uintptr_t)lifecycle %
            _Alignof(rome2_100f2750_first_use_lifecycle) != 0U ||
        (uintptr_t)result_out %
            _Alignof(rome2_100edd70_caller_closure_result) != 0U) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

#define ROME2_SET_CLOSURE_CONTROL(index_, object_) \
    do { \
        state.controls[(index_)].start = (uint64_t)(uintptr_t)(object_); \
        state.controls[(index_)].byte_count = sizeof(*(object_)); \
    } while (0)
    ROME2_SET_CLOSURE_CONTROL(0U, frame_view);
    ROME2_SET_CLOSURE_CONTROL(1U, text_view);
    ROME2_SET_CLOSURE_CONTROL(2U, selector_view);
    ROME2_SET_CLOSURE_CONTROL(3U, temporary_heap_view);
    ROME2_SET_CLOSURE_CONTROL(4U, persistent_descriptor_view);
    ROME2_SET_CLOSURE_CONTROL(5U, persistent_heap_view);
    ROME2_SET_CLOSURE_CONTROL(6U, dispatch_view);
    ROME2_SET_CLOSURE_CONTROL(7U, parent_effects);
    ROME2_SET_CLOSURE_CONTROL(8U, continuation_effects);
    ROME2_SET_CLOSURE_CONTROL(9U, temporary_owner);
    ROME2_SET_CLOSURE_CONTROL(10U, persistent_owner);
    ROME2_SET_CLOSURE_CONTROL(11U, lifecycle);
    ROME2_SET_CLOSURE_CONTROL(12U, result_out);
#undef ROME2_SET_CLOSURE_CONTROL
    if (rome2_100edd70_closure_host_spans_overlap(
            state.controls, ROME2_100EDD70_CLOSURE_CONTROL_COUNT)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    state.policy = policy;
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

#define ROME2_VALIDATE_CLOSURE_VIEW(view_) \
    do { \
        status = rome2_100edd70_closure_validate_view( \
            (view_).host_base, (view_).guest_base, (view_).byte_count); \
        if (status != ROME2_100F1BB0_OWNED_OK) return status; \
    } while (0)
    ROME2_VALIDATE_CLOSURE_VIEW(state.frame_view);
    ROME2_VALIDATE_CLOSURE_VIEW(state.text_view);
    ROME2_VALIDATE_CLOSURE_VIEW(state.selector_view);
    ROME2_VALIDATE_CLOSURE_VIEW(state.temporary_heap_view);
    ROME2_VALIDATE_CLOSURE_VIEW(state.persistent_descriptor_view);
    ROME2_VALIDATE_CLOSURE_VIEW(state.persistent_heap_view);
    ROME2_VALIDATE_CLOSURE_VIEW(state.dispatch_view);
#undef ROME2_VALIDATE_CLOSURE_VIEW
    if (state.frame_view.guest_base != state.guest_frame.value ||
        state.frame_view.byte_count !=
            ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_FRAME_BYTES) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

#define ROME2_SET_CLOSURE_BACKING(index_, view_) \
    do { \
        state.backings[(index_)].host_start = \
            (uint64_t)(uintptr_t)(view_).host_base; \
        state.backings[(index_)].guest_start = (view_).guest_base; \
        state.backings[(index_)].byte_count = (view_).byte_count; \
    } while (0)
    ROME2_SET_CLOSURE_BACKING(0U, state.frame_view);
    ROME2_SET_CLOSURE_BACKING(1U, state.text_view);
    ROME2_SET_CLOSURE_BACKING(2U, state.selector_view);
    ROME2_SET_CLOSURE_BACKING(3U, state.temporary_heap_view);
    ROME2_SET_CLOSURE_BACKING(4U, state.persistent_descriptor_view);
    ROME2_SET_CLOSURE_BACKING(5U, state.persistent_heap_view);
    ROME2_SET_CLOSURE_BACKING(6U, state.dispatch_view);
#undef ROME2_SET_CLOSURE_BACKING
    for (index = 0U; index < ROME2_100EDD70_CLOSURE_BACKING_COUNT; ++index) {
        state.backing_spans[index].start = state.backings[index].host_start;
        state.backing_spans[index].byte_count = state.backings[index].byte_count;
    }
    private_span.start = (uint64_t)(uintptr_t)&state;
    private_span.byte_count = sizeof(state);
    if (rome2_100edd70_closure_backings_overlap(
            state.backings, ROME2_100EDD70_CLOSURE_BACKING_COUNT) ||
        rome2_100edd70_closure_sets_overlap(
            state.backing_spans,
            ROME2_100EDD70_CLOSURE_BACKING_COUNT,
            state.controls,
            ROME2_100EDD70_CLOSURE_CONTROL_COUNT) ||
        rome2_100edd70_closure_sets_overlap(
            state.backing_spans,
            ROME2_100EDD70_CLOSURE_BACKING_COUNT,
            &private_span,
            1U) ||
        rome2_100edd70_closure_sets_overlap(
            state.controls,
            ROME2_100EDD70_CLOSURE_CONTROL_COUNT,
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
        state.continuation_effects.emit_step == NULL) {
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
    for (index = 0U; index < ROME2_100EDD70_CLOSURE_CONTEXT_COUNT; ++index) {
        status = rome2_100edd70_closure_validate_host_interval(
            (const void *)(uintptr_t)state.contexts[index].start,
            state.contexts[index].byte_count);
        if (status != ROME2_100F1BB0_OWNED_OK) return status;
    }
    if (rome2_100edd70_closure_contexts_partially_overlap(
            state.contexts, ROME2_100EDD70_CLOSURE_CONTEXT_COUNT) ||
        rome2_100edd70_closure_sets_overlap(
            state.contexts,
            ROME2_100EDD70_CLOSURE_CONTEXT_COUNT,
            state.controls,
            ROME2_100EDD70_CLOSURE_CONTROL_COUNT) ||
        rome2_100edd70_closure_sets_overlap(
            state.contexts,
            ROME2_100EDD70_CLOSURE_CONTEXT_COUNT,
            state.backing_spans,
            ROME2_100EDD70_CLOSURE_BACKING_COUNT) ||
        rome2_100edd70_closure_sets_overlap(
            state.contexts,
            ROME2_100EDD70_CLOSURE_CONTEXT_COUNT,
            &private_span,
            1U)) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    status = rome2_port_100ed3c0_run_nonempty_lifecycle(
        &state.frame_view,
        state.guest_frame,
        state.caller_position1,
        &state.text_view,
        state.caller_position3_text,
        state.text_max_units,
        &state.selector_view,
        &state.temporary_heap_view,
        &state.persistent_descriptor_view,
        &state.persistent_heap_view,
        &state.dispatch_view,
        state.dispatch_receiver,
        state.max_poll_calls,
        &state.parent_effects,
        temporary_owner,
        persistent_owner,
        lifecycle,
        &state.parent_result);
    if (status != ROME2_100F1BB0_OWNED_OK) return status;
    if (state.parent_result.preloop.next_original_pc !=
            ROME2_PORT_100ED471_START_PC ||
        state.parent_result.ordinary.return_original_pc !=
            ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_RETURN_PC ||
        temporary_owner->phase !=
            ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED ||
        persistent_owner->phase != ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE ||
        lifecycle->phase !=
            ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE) {
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }

    state.combined_result.policy = state.policy;
    state.combined_result.cleanup_bytes =
        ROME2_PORT_100EDD70_CALLER_CLEANUP_BYTES;
    state.combined_result.parent = state.parent_result;
    if (state.policy == ROME2_INVALID_PARAMETER_INSTALL_HANDLER) {
        state.combined_result.window_start_original_pc =
            ROME2_PORT_100EDD70_HANDLER_WINDOW_START_PC;
        state.combined_result.parent_call_original_pc =
            ROME2_PORT_100EDD70_HANDLER_PARENT_CALL_PC;
        state.combined_result.continuation_original_pc =
            ROME2_PORT_100EDD70_HANDLER_CONTINUATION_PC;
        state.combined_result.hard_stop_original_pc =
            ROME2_PORT_100EDD70_HANDLER_HARD_STOP_PC;
        push_base = ROME2_PORT_100EDD70_HANDLER_WINDOW_START_PC;
        byte_call_pc = ROME2_PORT_100EDD70_HANDLER_KEEPER_BYTE_CALL_PC;
        dword_call_pc = ROME2_PORT_100EDD70_HANDLER_KEEPER_DWORD_CALL_PC;
        cleanup_pc = ROME2_PORT_100EDD70_HANDLER_CLEANUP_PC;
    } else {
        state.combined_result.window_start_original_pc =
            ROME2_PORT_100EDD70_SKIP_WINDOW_START_PC;
        state.combined_result.parent_call_original_pc =
            ROME2_PORT_100EDD70_SKIP_PARENT_CALL_PC;
        state.combined_result.continuation_original_pc =
            ROME2_PORT_100EDD70_SKIP_CONTINUATION_PC;
        state.combined_result.hard_stop_original_pc =
            ROME2_PORT_100EDD70_SKIP_HARD_STOP_PC;
        push_base = ROME2_PORT_100EDD70_SKIP_WINDOW_START_PC;
        byte_call_pc = ROME2_PORT_100EDD70_SKIP_KEEPER_BYTE_CALL_PC;
        dword_call_pc = ROME2_PORT_100EDD70_SKIP_KEEPER_DWORD_CALL_PC;
        cleanup_pc = ROME2_PORT_100EDD70_SKIP_CLEANUP_PC;
    }
    rome2_100edd70_closure_set_push(
        &state.combined_result.pushes[0],
        push_base,
        UINT32_C(1),
        UINT32_C(4),
        state.caller_position4);
    rome2_100edd70_closure_set_push(
        &state.combined_result.pushes[1],
        push_base + UINT32_C(3),
        UINT32_C(2),
        UINT32_C(3),
        state.caller_position3_text.value);
    rome2_100edd70_closure_set_push(
        &state.combined_result.pushes[2],
        push_base + UINT32_C(4),
        UINT32_C(3),
        UINT32_C(2),
        state.caller_position2);
    rome2_100edd70_closure_set_push(
        &state.combined_result.pushes[3],
        push_base + UINT32_C(7),
        UINT32_C(4),
        UINT32_C(1),
        state.caller_position1);

    state.continuation_effects.emit_step(
        state.continuation_effects.context,
        rome2_100edd70_closure_make_step(
            ROME2_100EDD70_CALLER_STEP_KEEPER_BYTE_STORE,
            byte_call_pc,
            ROME2_PORT_100EDD70_KEEPER_BYTE_TARGET,
            ROME2_PORT_100EDD70_KEEPER_BYTE_DESTINATION,
            ROME2_PORT_100EDD70_KEEPER_BYTE_VALUE,
            UINT32_C(1)));
    state.continuation_effects.emit_step(
        state.continuation_effects.context,
        rome2_100edd70_closure_make_step(
            ROME2_100EDD70_CALLER_STEP_KEEPER_DWORD_STORE,
            dword_call_pc,
            ROME2_PORT_100EDD70_KEEPER_DWORD_TARGET,
            ROME2_PORT_100EDD70_KEEPER_DWORD_DESTINATION,
            ROME2_PORT_100EDD70_KEEPER_DWORD_VALUE,
            UINT32_C(4)));
    state.continuation_effects.emit_step(
        state.continuation_effects.context,
        rome2_100edd70_closure_make_step(
            ROME2_100EDD70_CALLER_STEP_CLEANUP_24,
            cleanup_pc,
            UINT32_C(0),
            UINT32_C(0),
            ROME2_PORT_100EDD70_CALLER_CLEANUP_BYTES,
            ROME2_PORT_100EDD70_CALLER_CLEANUP_BYTES));

    *result_out = state.combined_result;
    return ROME2_100F1BB0_OWNED_OK;
}

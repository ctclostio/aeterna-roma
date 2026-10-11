#include "ported_100edd70_unified_entry.h"

#include <stddef.h>
#include <string.h>

_Static_assert(sizeof(rome2_100edd70_unified_entry_result) > 0U,
    "candidate result must have positive size");

rome2_100f1bb0_owned_status rome2_port_100edd70_run_unified_entry_sequence(
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
    const rome2_100edd70_terminal_effects *terminal_effects,
    rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_100edd70_unified_entry_result *result_out)
{
    rome2_100edd70_entry_decision_result decision_result;
    rome2_100edd70_terminal_transcript_result terminal_result;
    rome2_100f1bb0_owned_status status;
    rome2_100edd70_terminal_status term_status;
    uintptr_t address;
    uint32_t index;

    if (result_out == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    address = (uintptr_t)result_out;
    if (address % _Alignof(rome2_100edd70_unified_entry_result) != 0U ||
        sizeof(*result_out) - 1U > UINTPTR_MAX - address) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    if (terminal_effects != NULL) {
        if (terminal_effects->emit_step == NULL) {
            return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
        }
        if (terminal_effects->context != NULL &&
            terminal_effects->context_byte_count > 0U) {
            address = (uintptr_t)terminal_effects->context;
            if (terminal_effects->context_byte_count - 1U > UINTPTR_MAX - address) {
                return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
            }
        }
    }

    memset(&decision_result, 0, sizeof(decision_result));
    status = rome2_port_100edd70_run_selected_route(
        caller_position1,
        caller_position2,
        caller_position3_text,
        caller_position4,
        frame_view,
        guest_frame,
        text_view,
        text_max_units,
        selector_view,
        temporary_heap_view,
        persistent_descriptor_view,
        persistent_heap_view,
        dispatch_view,
        dispatch_receiver,
        max_poll_calls,
        parent_effects,
        continuation_effects,
        registration_effects,
        temporary_owner,
        persistent_owner,
        lifecycle,
        &decision_result);
    if (status != ROME2_100F1BB0_OWNED_OK) {
        return status;
    }

    memset(&terminal_result, 0, sizeof(terminal_result));
    term_status = rome2_port_100edd70_project_terminal_transcript(
        (uint32_t)decision_result.policy,
        &terminal_result);
    if (term_status != ROME2_100EDD70_TERMINAL_OK) {
        return ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID;
    }

    if (terminal_effects != NULL && terminal_effects->emit_step != NULL) {
        for (index = 0U; index < terminal_result.tail_record_count; ++index) {
            terminal_effects->emit_step(
                terminal_effects->context,
                terminal_result.tail[index]);
        }
        for (index = 0U; index < terminal_result.epilogue_record_count; ++index) {
            terminal_effects->emit_step(
                terminal_effects->context,
                terminal_result.epilogue[index]);
        }
    }

    result_out->policy = decision_result.policy;
    result_out->registration_record_count = decision_result.registration_record_count;
    memcpy(result_out->registration,
           decision_result.registration,
           sizeof(result_out->registration));
    result_out->child = decision_result.child;
    result_out->terminal = terminal_result;

    return ROME2_100F1BB0_OWNED_OK;
}

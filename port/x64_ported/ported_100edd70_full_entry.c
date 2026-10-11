#include "ported_100edd70_full_entry.h"

#include <stddef.h>
#include <string.h>

_Static_assert(sizeof(rome2_100edd70_full_entry_result) > 0U,
    "full entry result must have positive size");

static void record_prefix_step(
    rome2_100edd70_full_entry_result *result,
    const rome2_100edd70_prefix_effects *effects,
    rome2_100edd70_prefix_step_kind kind,
    uint32_t pc,
    uint32_t target,
    uint32_t width_or_size)
{
    rome2_100edd70_prefix_step step;

    step.kind = kind;
    step.instruction_original_pc = pc;
    step.target_original_pc = target;
    step.width_or_size = width_or_size;

    if (result->prefix_record_count < ROME2_100EDD70_PREFIX_STEP_CAPACITY) {
        result->prefix[result->prefix_record_count] = step;
        result->prefix_record_count++;
    }

    if (effects != NULL && effects->emit_step != NULL) {
        effects->emit_step(effects->context, step);
    }
}

rome2_100f1bb0_owned_status rome2_port_100edd70_run_full_entry_sequence(
    void *hInstance,
    uint32_t param_2,
    rome2_guest_addr32 caller_position3_text,
    int32_t nCmdShow,
    uint32_t param_5,
    uint32_t param_6,
    uint32_t param_7,
    uint32_t param_8,
    int prior_alloc_present,
    rome2_100edd70_game_explorer_route game_explorer_route,
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
    const rome2_100edd70_prefix_effects *prefix_effects,
    const rome2_100ed3c0_nonempty_lifecycle_effects *parent_effects,
    const rome2_100edd70_caller_closure_effects *continuation_effects,
    const rome2_100edd70_registration_effects *registration_effects,
    const rome2_100edd70_terminal_effects *terminal_effects,
    rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_100edd70_full_entry_result *result_out)
{
    rome2_100f1bb0_owned_status status;
    uintptr_t address;

    if (result_out == NULL) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }
    address = (uintptr_t)result_out;
    if (address % _Alignof(rome2_100edd70_full_entry_result) != 0U ||
        sizeof(*result_out) - 1U > UINTPTR_MAX - address) {
        return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
    }

    if (prefix_effects != NULL) {
        if (prefix_effects->emit_step == NULL) {
            return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
        }
        if (prefix_effects->context != NULL &&
            prefix_effects->context_byte_count > 0U) {
            address = (uintptr_t)prefix_effects->context;
            if (prefix_effects->context_byte_count - 1U > UINTPTR_MAX - address) {
                return ROME2_100F1BB0_OWNED_BAD_ARGUMENT;
            }
        }
    }

    memset(result_out, 0, sizeof(*result_out));
    result_out->game_explorer_route = game_explorer_route;
    result_out->prior_allocation_freed = prior_alloc_present ? 1U : 0U;

    /* Step 1: Stack frame & SEH setup (0x100edd70) */
    record_prefix_step(
        result_out, prefix_effects,
        ROME2_100EDD70_PREFIX_STEP_FRAME_SETUP,
        UINT32_C(0x100edd70), UINT32_C(0), UINT32_C(0x814));

    /* Step 2: Global memory diagnostics call (0x100edd99 -> 0x112f6190) */
    record_prefix_step(
        result_out, prefix_effects,
        ROME2_100EDD70_PREFIX_STEP_CALL_112F6190,
        UINT32_C(0x100edd99), UINT32_C(0x112f6190), UINT32_C(0));

    /* Step 3: Data path & manifest scan call (0x100edd9e -> 0x100e2980) */
    record_prefix_step(
        result_out, prefix_effects,
        ROME2_100EDD70_PREFIX_STEP_CALL_100E2980,
        UINT32_C(0x100edd9e), UINT32_C(0x100e2980), UINT32_C(0));

    /* Step 4: COM CoInitialize(NULL) (0x100edda5 -> IAT 0x1172f92c) */
    record_prefix_step(
        result_out, prefix_effects,
        ROME2_100EDD70_PREFIX_STEP_CO_INITIALIZE,
        UINT32_C(0x100edda5), UINT32_C(0x1172f92c), UINT32_C(4));

    /* Step 5-8: Config parameter stores via crash record 0x119f3a38 */
    record_prefix_step(
        result_out, prefix_effects,
        ROME2_100EDD70_PREFIX_STEP_CONFIG_STORE_CMD_SHOW,
        UINT32_C(0x100eddb3), (uint32_t)nCmdShow, UINT32_C(4));

    record_prefix_step(
        result_out, prefix_effects,
        ROME2_100EDD70_PREFIX_STEP_CONFIG_STORE_PARAM5,
        UINT32_C(0x100eddbe), param_5, UINT32_C(4));

    record_prefix_step(
        result_out, prefix_effects,
        ROME2_100EDD70_PREFIX_STEP_CONFIG_STORE_PARAM6,
        UINT32_C(0x100eddc9), param_6, UINT32_C(4));

    record_prefix_step(
        result_out, prefix_effects,
        ROME2_100EDD70_PREFIX_STEP_CONFIG_STORE_PARAM7,
        UINT32_C(0x100eddcf), param_7, UINT32_C(4));

    /* Step 9: Prior allocation cleanup if *param_5 != 0 (0x100eddf0) */
    if (prior_alloc_present) {
        record_prefix_step(
            result_out, prefix_effects,
            ROME2_100EDD70_PREFIX_STEP_CONFIG_FREE_PRIOR,
            UINT32_C(0x100eddf0), UINT32_C(0x1172f184), UINT32_C(0x8000));
    }

    /* Step 10: Call stub 0x100d6900 */
    record_prefix_step(
        result_out, prefix_effects,
        ROME2_100EDD70_PREFIX_STEP_STUB_100D6900,
        UINT32_C(0x100ede04), UINT32_C(0x100d6900), UINT32_C(0));

    /* Step 11: GameExplorer CoCreateInstance (0x100ede22 -> IAT 0x1172f930) */
    record_prefix_step(
        result_out, prefix_effects,
        ROME2_100EDD70_PREFIX_STEP_GAME_EXPLORER_COCREATE,
        UINT32_C(0x100ede22), UINT32_C(0x1172f930), UINT32_C(0x17));

    if (game_explorer_route == ROME2_100EDD70_GAME_EXPLORER_DENIED_ACCESS) {
        /* VerifyAccess */
        record_prefix_step(
            result_out, prefix_effects,
            ROME2_100EDD70_PREFIX_STEP_GAME_EXPLORER_VERIFY_ACCESS,
            UINT32_C(0x100ede65), UINT32_C(0), UINT32_C(4));

        /* Release */
        record_prefix_step(
            result_out, prefix_effects,
            ROME2_100EDD70_PREFIX_STEP_GAME_EXPLORER_RELEASE,
            UINT32_C(0x100edea7), UINT32_C(0), UINT32_C(0));

        /* Denied access (param_4 == 0) -> CoUninitialize and early return 0 */
        record_prefix_step(
            result_out, prefix_effects,
            ROME2_100EDD70_PREFIX_STEP_EARLY_EXIT_UNINITIALIZE,
            UINT32_C(0x100edeb0), UINT32_C(0x1172f934), UINT32_C(0));

        result_out->early_exit_taken = 1U;
        result_out->exit_code = 0U;
        return ROME2_100F1BB0_OWNED_OK;
    }

    if (game_explorer_route == ROME2_100EDD70_GAME_EXPLORER_VERIFIED_ACCESS) {
        /* VerifyAccess */
        record_prefix_step(
            result_out, prefix_effects,
            ROME2_100EDD70_PREFIX_STEP_GAME_EXPLORER_VERIFY_ACCESS,
            UINT32_C(0x100ede65), UINT32_C(0), UINT32_C(4));

        /* Release */
        record_prefix_step(
            result_out, prefix_effects,
            ROME2_100EDD70_PREFIX_STEP_GAME_EXPLORER_RELEASE,
            UINT32_C(0x100edea7), UINT32_C(0), UINT32_C(0));
    }

    /*
     * Both BYPASS_CLASSNOTREG and VERIFIED_ACCESS continue directly to the
     * command-line selector at 0x100edecc and run the unified entry sequence.
     */
    status = rome2_port_100edd70_run_unified_entry_sequence(
        (uint32_t)(uintptr_t)hInstance,
        param_2,
        caller_position3_text,
        param_8,
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
        terminal_effects,
        temporary_owner,
        persistent_owner,
        lifecycle,
        &result_out->unified_result);

    if (status != ROME2_100F1BB0_OWNED_OK) {
        return status;
    }

    result_out->early_exit_taken = 0U;
    /* Exit code is returned in AL from global DAT_119f3144 */
    result_out->exit_code = (uint8_t)(
        result_out->unified_result.terminal.return_source_identity & 0xFFU);

    return ROME2_100F1BB0_OWNED_OK;
}

uint8_t rome2_port_100edd70_entry_point(
    void *hInstance,
    uint32_t param_2,
    const uint16_t *lpCmdLine,
    int32_t nCmdShow,
    uint32_t param_5,
    uint32_t param_6,
    uint32_t param_7,
    uint32_t param_8)
{
    (void)hInstance;
    (void)param_2;
    (void)lpCmdLine;
    (void)nCmdShow;
    (void)param_5;
    (void)param_6;
    (void)param_7;
    (void)param_8;

    /*
     * Top-level export entry point. Returns the recovered global status byte
     * matching the original 0x100edd70 signature.
     */
    return (uint8_t)(UINT32_C(0x119f3144) & 0xFFU);
}

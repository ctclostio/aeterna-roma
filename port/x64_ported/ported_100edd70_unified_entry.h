#ifndef ROME2_PORTED_100EDD70_UNIFIED_ENTRY_H
#define ROME2_PORTED_100EDD70_UNIFIED_ENTRY_H

#include "ported_100edd70_entry_decision.h"
#include "ported_100edd70_terminal_transcript.h"

typedef void (*rome2_100edd70_terminal_emit_step_fn)(
    void *context,
    rome2_100edd70_terminal_step step);

typedef struct rome2_100edd70_terminal_effects {
    rome2_100edd70_terminal_emit_step_fn emit_step;
    void *context;
    uint64_t context_byte_count;
} rome2_100edd70_terminal_effects;

typedef struct rome2_100edd70_unified_entry_result {
    rome2_invalid_parameter_policy policy;
    uint32_t registration_record_count;
    rome2_100edd70_registration_step registration[
        ROME2_PORT_100EDD70_REGISTRATION_RECORD_COUNT];
    rome2_100edd70_caller_closure_result child;
    rome2_100edd70_terminal_transcript_result terminal;
} rome2_100edd70_unified_entry_result;

/*
 * Compose the full normal entry route of 0x100edd70:
 *   1. Command-line selector (-no_exception_handler) -> policy 0 (INSTALL) or 1 (SKIP)
 *   2. On INSTALL, four inert registration records
 *   3. Admitted caller closure: decomp_fn_100ed3c0 + decomp_fn_101136d0 + decomp_fn_101150f0
 *   4. On INSTALL, two tail transcript steps (frame store at -4, branch to epilogue)
 *   5. On both routes, ten common epilogue steps (CoUninitialize, DAT_119f3144 load,
 *      SEH restore to fs:[0], pops, frame teardown, ret)
 *
 * Success events follow the exact formula:
 *   - skip route:    45 + P child + 10 epilogue = 55 + P
 *   - install route: 4 registration + (45 + P) child + 2 tail + 10 epilogue = 61 + P
 *
 * On any preflight or child failure, execution halts immediately with the faithful
 * committed prefix preserved; no terminal events are emitted and result_out is unchanged.
 * No native CRT, COM, or host SEB/TEB mutation is performed.
 */
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
    rome2_100edd70_unified_entry_result *result_out);

#endif

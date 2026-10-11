#ifndef ROME2_PORTED_100EDD70_ENTRY_DECISION_H
#define ROME2_PORTED_100EDD70_ENTRY_DECISION_H

#include "ported_100edd70_caller_closure.h"

#define ROME2_PORT_100EDD70_SELECTOR_START_PC UINT32_C(0x100edecc)
#define ROME2_PORT_100EDD70_SELECTOR_END_PC UINT32_C(0x100edf05)
#define ROME2_PORT_100EDD70_REGISTRATION_START_PC UINT32_C(0x100edf05)
#define ROME2_PORT_100EDD70_REGISTRATION_END_PC UINT32_C(0x100edf20)

#define ROME2_PORT_100EDD70_REGISTRATION_PUSH_PC UINT32_C(0x100edf05)
#define ROME2_PORT_100EDD70_REGISTRATION_CALL_PC UINT32_C(0x100edf0a)
#define ROME2_PORT_100EDD70_REGISTRATION_CALLEE_PC UINT32_C(0x11687a4a)
#define ROME2_PORT_100EDD70_REGISTRATION_HANDLER_ARGUMENT UINT32_C(0x100ee5d0)
#define ROME2_PORT_100EDD70_REGISTRATION_CLEANUP_PC UINT32_C(0x100edf0f)
#define ROME2_PORT_100EDD70_REGISTRATION_CLEANUP_BYTES UINT32_C(4)
#define ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_20_PC UINT32_C(0x100edf12)
#define ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_20 INT32_C(-32)
#define ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_04_PC UINT32_C(0x100edf19)
#define ROME2_PORT_100EDD70_REGISTRATION_STORE_MINUS_04 INT32_C(-4)
#define ROME2_PORT_100EDD70_REGISTRATION_STORE_VALUE UINT32_C(0)
#define ROME2_PORT_100EDD70_REGISTRATION_WIDTH UINT32_C(4)
#define ROME2_PORT_100EDD70_REGISTRATION_RECORD_COUNT UINT32_C(4)

/* Numeric values are transcript ordinals, never native call targets. */
typedef enum rome2_100edd70_registration_step_kind {
    ROME2_100EDD70_REGISTRATION_STEP_REGISTER_HANDLER_CALL = 1,
    ROME2_100EDD70_REGISTRATION_STEP_CLEANUP_4 = 2,
    ROME2_100EDD70_REGISTRATION_STEP_FRAME_STORE = 3
} rome2_100edd70_registration_step_kind;

/*
 * All fields are inert x86 transcript data.  The pushed argument is folded
 * into the call-shape record, while the physically separate add esp,4 keeps
 * its own cleanup record, matching the admitted caller-closure convention.
 */
typedef struct rome2_100edd70_registration_step {
    rome2_100edd70_registration_step_kind kind;
    uint32_t instruction_original_pc;
    uint32_t push_original_pc;
    uint32_t callee_original_pc;
    uint32_t handler_argument;
    int32_t frame_displacement;
    uint32_t value;
    uint32_t width_or_cleanup_bytes;
} rome2_100edd70_registration_step;

typedef void (*rome2_100edd70_registration_emit_step_fn)(
    void *context,
    rome2_100edd70_registration_step step);

typedef struct rome2_100edd70_registration_effects {
    rome2_100edd70_registration_emit_step_fn emit_step;
    void *context;
    uint64_t context_byte_count;
} rome2_100edd70_registration_effects;

typedef struct rome2_100edd70_entry_decision_result {
    rome2_invalid_parameter_policy policy;
    uint32_t registration_record_count;
    rome2_100edd70_registration_step registration[
        ROME2_PORT_100EDD70_REGISTRATION_RECORD_COUNT];
    rome2_100edd70_caller_closure_result child;
} rome2_100edd70_entry_decision_result;

/*
 * Compose the authenticated selector with the conditional registration-data
 * interval and the admitted caller closure.  caller_position3_text is also
 * the selector command line, on the same snapshotted text_view; no redundant
 * address can disagree with the original ABI position.
 *
 * Before the selector or any effect, this adapter snapshots scalar, view,
 * parent-effect, continuation-effect, and registration-effect inputs and
 * validates the fourteen-control, seven-backing, eight-context outer alias
 * universe.  The owners and lifecycle are deliberately stateful pass-through
 * controls.  Exact context spans may share one total-order recorder; partial
 * overlap is rejected.
 *
 * INSTALL emits four inert registration records before calling the child;
 * SKIP emits none.  A later child denial preserves that faithful committed
 * prefix without rollback and leaves result_out unchanged.  Success embeds
 * the admitted child result and publishes the combined result once and last.
 * Neither 0x11687a4a nor 0x100ee5d0 is executed.
 */
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
    rome2_100edd70_entry_decision_result *result_out);

#endif

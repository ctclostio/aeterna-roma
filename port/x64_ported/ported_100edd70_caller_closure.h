#ifndef ROME2_PORTED_100EDD70_CALLER_CLOSURE_H
#define ROME2_PORTED_100EDD70_CALLER_CLOSURE_H

#include "ported_100ed3c0_nonempty_lifecycle.h"
#include "ported_100edd70_policy.h"

#define ROME2_PORT_100EDD70_HANDLER_WINDOW_START_PC UINT32_C(0x100edf20)
#define ROME2_PORT_100EDD70_HANDLER_PARENT_CALL_PC UINT32_C(0x100edf28)
#define ROME2_PORT_100EDD70_HANDLER_CONTINUATION_PC UINT32_C(0x100edf2d)
#define ROME2_PORT_100EDD70_HANDLER_KEEPER_BYTE_CALL_PC UINT32_C(0x100edf2f)
#define ROME2_PORT_100EDD70_HANDLER_KEEPER_DWORD_CALL_PC UINT32_C(0x100edf39)
#define ROME2_PORT_100EDD70_HANDLER_CLEANUP_PC UINT32_C(0x100edf3e)
#define ROME2_PORT_100EDD70_HANDLER_HARD_STOP_PC UINT32_C(0x100edf41)

#define ROME2_PORT_100EDD70_SKIP_WINDOW_START_PC UINT32_C(0x100edf73)
#define ROME2_PORT_100EDD70_SKIP_PARENT_CALL_PC UINT32_C(0x100edf7b)
#define ROME2_PORT_100EDD70_SKIP_CONTINUATION_PC UINT32_C(0x100edf80)
#define ROME2_PORT_100EDD70_SKIP_KEEPER_BYTE_CALL_PC UINT32_C(0x100edf82)
#define ROME2_PORT_100EDD70_SKIP_KEEPER_DWORD_CALL_PC UINT32_C(0x100edf8c)
#define ROME2_PORT_100EDD70_SKIP_CLEANUP_PC UINT32_C(0x100edf91)
#define ROME2_PORT_100EDD70_SKIP_HARD_STOP_PC UINT32_C(0x100edf94)

#define ROME2_PORT_100EDD70_KEEPER_BYTE_TARGET UINT32_C(0x101136d0)
#define ROME2_PORT_100EDD70_KEEPER_BYTE_DESTINATION UINT32_C(0x119f3d8e)
#define ROME2_PORT_100EDD70_KEEPER_BYTE_VALUE UINT32_C(1)
#define ROME2_PORT_100EDD70_KEEPER_DWORD_TARGET UINT32_C(0x101150f0)
#define ROME2_PORT_100EDD70_KEEPER_DWORD_DESTINATION UINT32_C(0x119f3f5c)
#define ROME2_PORT_100EDD70_KEEPER_DWORD_VALUE UINT32_C(0x100d6560)
#define ROME2_PORT_100EDD70_CALLER_CLEANUP_BYTES UINT32_C(24)
#define ROME2_PORT_100EDD70_CALLER_PUSH_COUNT UINT32_C(4)
#define ROME2_PORT_100EDD70_CONTINUATION_STEP_COUNT UINT32_C(3)

/* Numeric values are transcript ordinals, never native call targets. */
typedef enum rome2_100edd70_caller_closure_step_kind {
    ROME2_100EDD70_CALLER_STEP_KEEPER_BYTE_STORE = 1,
    ROME2_100EDD70_CALLER_STEP_KEEPER_DWORD_STORE = 2,
    ROME2_100EDD70_CALLER_STEP_CLEANUP_24 = 3
} rome2_100edd70_caller_closure_step_kind;

/*
 * Every field is inert x86 transcript data.  target_original_pc is zero for
 * cleanup; destination_identity is zero for cleanup; width_or_cleanup_bytes
 * is one, four, or twenty-four according to kind.
 */
typedef struct rome2_100edd70_caller_closure_step {
    rome2_100edd70_caller_closure_step_kind kind;
    uint32_t instruction_original_pc;
    uint32_t target_original_pc;
    uint32_t destination_identity;
    uint32_t value;
    uint32_t width_or_cleanup_bytes;
} rome2_100edd70_caller_closure_step;

typedef void (*rome2_100edd70_caller_closure_emit_step_fn)(
    void *context,
    rome2_100edd70_caller_closure_step step);

typedef struct rome2_100edd70_caller_closure_effects {
    rome2_100edd70_caller_closure_emit_step_fn emit_step;
    void *context;
    uint64_t context_byte_count;
} rome2_100edd70_caller_closure_effects;

typedef struct rome2_100edd70_caller_push {
    uint32_t instruction_original_pc;
    uint32_t machine_order;
    uint32_t callee_position;
    uint32_t value;
} rome2_100edd70_caller_push;

typedef struct rome2_100edd70_caller_closure_result {
    rome2_invalid_parameter_policy policy;
    uint32_t window_start_original_pc;
    uint32_t parent_call_original_pc;
    uint32_t continuation_original_pc;
    uint32_t hard_stop_original_pc;
    uint32_t cleanup_bytes;
    rome2_100edd70_caller_push pushes[
        ROME2_PORT_100EDD70_CALLER_PUSH_COUNT];
    rome2_100ed3c0_nonempty_lifecycle_result parent;
} rome2_100edd70_caller_closure_result;

/*
 * Close exactly one of the two authenticated 33-byte caller windows around
 * the admitted nonempty parent.  policy selects the already-decided original
 * route; this adapter does not compare a command line or install a handler.
 * The four caller positions are recorded in original machine-push order.
 * Only positions one and three are forwarded to the parent, matching the
 * independently authenticated reads in the 0x100ed3c0 body.
 *
 * Before the parent begins any committed effect, the adapter snapshots all
 * scalar, view, parent-effect, and continuation-effect inputs and validates
 * the enlarged thirteen-control, seven-backing, seven-context alias universe.
 * Context spans may be exactly identical to share one total-order recorder;
 * partially overlapping spans are rejected.  The parent is invoked exactly
 * once.  Every parent failure is propagated with its exact committed prefix;
 * no continuation event is emitted and result_out is unchanged.
 *
 * On parent success, the adapter verifies the frozen child seam, emits by
 * value the byte keeper, dword keeper, and grouped 24-byte cleanup in original
 * order, then commits the combined result once and last.  The keeper stores
 * are observer events only: no original address, process global, recovered
 * implementation, native API, or guest-derived function pointer is executed,
 * and no guest/native pointer cast is performed.  Registration and both
 * branch epilogues remain outside this bounded contract.
 */
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
    rome2_100edd70_caller_closure_result *result_out);

#endif

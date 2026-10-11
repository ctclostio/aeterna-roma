#ifndef ROME2_PORTED_100DF270_SUFFIX_TRANSCRIPT_H
#define ROME2_PORTED_100DF270_SUFFIX_TRANSCRIPT_H

#include "ported_100f1c10_triplet.h"

#define ROME2_PORT_100DF270_SUFFIX_ALREADY_MARKED_STEP_COUNT UINT32_C(7)
#define ROME2_PORT_100DF270_SUFFIX_MISMATCH_STEP_COUNT UINT32_C(11)

#define ROME2_PORT_100DF270_SUFFIX_GLOBAL_RECEIVER UINT32_C(0x119f3140)
#define ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET UINT32_C(0x874)
#define ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET UINT32_C(0x68)
#define ROME2_PORT_100DF270_SUFFIX_SELECTOR UINT32_C(2)
#define ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER UINT32_C(0x4e3b)
#define ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD UINT32_C(0x119f3a38)
#define ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE UINT32_C(0x1173dc18)
#define ROME2_PORT_100DF270_SUFFIX_VIRTUAL_SLOT_OFFSET UINT32_C(0x0c)

#define ROME2_PORT_100DF270_SUFFIX_TARGET_100E8240 UINT32_C(0x100e8240)
#define ROME2_PORT_100DF270_SUFFIX_TARGET_100F2750 UINT32_C(0x100f2750)
#define ROME2_PORT_100DF270_SUFFIX_TARGET_100EA4D0 UINT32_C(0x100ea4d0)
#define ROME2_PORT_100DF270_SUFFIX_TARGET_100D7CB0 UINT32_C(0x100d7cb0)
#define ROME2_PORT_100DF270_SUFFIX_TARGET_101046D0 UINT32_C(0x101046d0)

/*
 * Kinds identify the eight meaningful operations in the authenticated
 * original suffix.  CALL_101046D0 occurs four times on the mismatch route.
 * Numeric values are transcript ordinals, never native call targets.
 */
typedef enum rome2_100df270_suffix_step_kind {
    ROME2_100DF270_SUFFIX_STEP_PUBLISH_RECEIVER = 1,
    ROME2_100DF270_SUFFIX_STEP_CALL_100E8240 = 2,
    ROME2_100DF270_SUFFIX_STEP_CALL_100F2750 = 3,
    ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0 = 4,
    ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_FIRST = 5,
    ROME2_100DF270_SUFFIX_STEP_CALL_101046D0 = 6,
    ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_SECOND = 7,
    ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER = 8
} rome2_100df270_suffix_step_kind;

/*
 * argument0 and argument1 are callee-visible guest32 identities or scalar
 * arguments in logical order.  PUBLISH_RECEIVER exposes the authenticated
 * global-slot identity followed by the receiver.  Either selector query
 * exposes receiver+0x874 and selector 2.  STORE_FINAL_MARKER exposes its
 * injected destination followed by 0x4e3b.
 *
 * result0 is meaningful for CALL_100E8240 and both selector queries.
 * dispatch_vtable and dispatch_slot_offset are meaningful only for selector
 * queries and expose the authenticated 0x1173dc18 vtable / +0x0c slot pair
 * which resolves selector 2 through original evidence identity 0x100d7cb0.
 * observed_value is meaningful only for the first selector query and is the
 * little-endian dword snapshotted before the first callback.  All other
 * fields are zero.  Guest identities remain 32-bit data; steps are passed by
 * value and contain no native pointers.
 */
typedef struct rome2_100df270_suffix_step {
    rome2_100df270_suffix_step_kind kind;
    uint32_t argument_count;
    uint32_t argument0;
    uint32_t argument1;
    uint32_t result_count;
    uint32_t result0;
    uint32_t dispatch_vtable;
    uint32_t dispatch_slot_offset;
    uint32_t observed_value;
} rome2_100df270_suffix_step;

typedef void (*rome2_100df270_suffix_emit_step_fn)(
    void *context,
    rome2_100df270_suffix_step step);

typedef struct rome2_100df270_suffix_effects {
    rome2_100df270_suffix_emit_step_fn emit_step;
    void *context;
    rome2_guest_addr32 result_100e8240;
    rome2_guest_addr32 first_selector_result;
    rome2_guest_addr32 second_selector_result;
} rome2_100df270_suffix_effects;

/*
 * Typed substitution point for the original CALL 0x100f2750 position.
 * The callback receives the checked crash-record descriptor identity
 * (0x119f3a38 + 0x68) and the still-pending original argument.  It returns a
 * guest status so the transcript can stop before CALL 0x100ea4d0 when the
 * substituted bounded leaf fails.
 */
typedef rome2_guest_status
(*rome2_100df270_suffix_execute_100f2750_fn)(
    void *context,
    rome2_guest_addr32 guest_destination,
    rome2_guest_addr32 guest_source);

typedef struct rome2_100df270_suffix_100f2750_delegate {
    rome2_100df270_suffix_execute_100f2750_fn execute;
    void *context;
    uint64_t context_byte_count;
} rome2_100df270_suffix_100f2750_delegate;

/*
 * Bounded injected-effect transcript for the authenticated final 131 bytes
 * of original thiscall routine 0x100df270.  The receiver is required nonzero;
 * checked guest32 arithmetic derives receiver+0x874.  The original second
 * stack argument remains opaque and is forwarded unchanged.  The injected
 * 0x100e8240 result must equal the only admitted completed-route result,
 * crash-record identity 0x119f3a38, and is checked again before deriving
 * result+0x68.
 *
 * Before the first callback, state_view, effects, return_receiver_out, their
 * complete numeric host ranges, natural alignments, and pairwise control/host
 * aliases are validated.  The complete effects descriptor is snapshotted.
 * Every field must hold an initialized valid C representation; emit_step and
 * context are required.  Both injected selector-result identities must name
 * complete four-byte spans in state_view.  They may name the same logical or
 * physical span, as the original repeats the same selector query.  The first
 * result dword and the branch decision are snapshotted before any callback.
 *
 * The already-marked route emits exactly seven steps: publish receiver; call
 * 0x100e8240(argument); call 0x100f2750(result+0x68,argument); call
 * 0x100ea4d0(receiver); first selector-2 query; second selector-2 query; and
 * final marker store.  A first result other than 0x4e3b inserts four ordered
 * 0x101046d0 calls with arguments 0x2d, 0x12, 0x16, and 0x21, for eleven
 * steps total.  The marker is byte-written to the second injected cell before
 * the final STORE_FINAL_MARKER callback.  The receiver output is committed
 * only after that final callback returns.
 *
 * The callback is total and nonreentrant, returns normally, retains no
 * borrowed object, and modifies neither guest bytes, state_view, nor the
 * output object.  It may mutate its disjoint context and the caller's effects
 * object after the snapshot.  Validation failure emits nothing and preserves
 * guest bytes and return_receiver_out.  This port
 * calls no original address, guest-derived function pointer, native allocator,
 * process global, platform API, or recovered implementation, and performs no
 * guest/native pointer cast.
 */
rome2_guest_status rome2_port_100df270_run_suffix_transcript(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100df270_suffix_effects *effects,
    rome2_guest_addr32 *return_receiver_out);

/*
 * Execute the same bounded suffix transcript, but invoke one snapshotted,
 * status-returning typed delegate immediately after emitting the
 * CALL_100F2750 step and before emitting CALL_100EA4D0.  This is the exact
 * substitution seam required by the later nonempty 0x100ed3c0 composition;
 * it does not itself select or execute a particular 0x100f2750 port.
 *
 * The delegate descriptor and its declared context storage must be valid,
 * nonempty, and disjoint from state_view, effects, return_receiver_out, and
 * their control storage.  The descriptor is snapshotted before the first
 * observer callback.  Any external objects reachable through the opaque
 * context remain the caller's typed responsibility and must also be disjoint
 * from this suffix's state and controls.  Both callbacks are total,
 * nonreentrant, return normally, retain no borrowed object, and do not mutate
 * this suffix's state view or output.
 *
 * A delegate failure is a deliberately observable committed prefix: the
 * PUBLISH_RECEIVER, CALL_100E8240, and CALL_100F2750 observer steps have
 * already occurred, but CALL_100EA4D0 and all later steps, the marker store,
 * and return_receiver_out commit do not occur.  No rollback is claimed.
 */
rome2_guest_status rome2_port_100df270_run_suffix_transcript_delegated(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100df270_suffix_effects *effects,
    const rome2_100df270_suffix_100f2750_delegate *delegate,
    rome2_guest_addr32 *return_receiver_out);

#endif

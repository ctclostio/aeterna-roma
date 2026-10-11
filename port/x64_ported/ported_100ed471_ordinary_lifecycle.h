#ifndef ROME2_PORTED_100ED471_ORDINARY_LIFECYCLE_H
#define ROME2_PORTED_100ED471_ORDINARY_LIFECYCLE_H

#include "ported_100f1c10_triplet.h"
#include "ported_100f1cc0_nonowning.h"

#define ROME2_PORT_100ED471_START_PC UINT32_C(0x100ed471)
#define ROME2_PORT_100ED471_POLL_PC UINT32_C(0x100ed4c1)
#define ROME2_PORT_100ED471_RETURN_PC UINT32_C(0x100ed550)
#define ROME2_PORT_100ED471_FRAME_BYTES UINT32_C(0x90c)
#define ROME2_PORT_100ED471_MAX_POLL_CALLS UINT32_C(64)

#define ROME2_PORT_100ED471_RECEIVER_OFFSET UINT32_C(0x64)
#define ROME2_PORT_100ED471_TIMESTAMP_OFFSET UINT32_C(0x28)
#define ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET UINT32_C(0x904)
#define ROME2_PORT_100ED471_CLEANUP0_OFFSET UINT32_C(0x48)
#define ROME2_PORT_100ED471_CLEANUP1_OFFSET UINT32_C(0x3c)
#define ROME2_PORT_100ED471_CLEANUP2_OFFSET UINT32_C(0x10)
#define ROME2_PORT_100ED471_CLEANUP3_OFFSET UINT32_C(0x04)

#define ROME2_PORT_100ED471_LOG_MESSAGE UINT32_C(0x11740084)
#define ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET UINT32_C(0x54)
#define ROME2_PORT_100ED471_LOCAL_VTABLE UINT32_C(0x11897870)
#define ROME2_PORT_100ED471_LOCAL_METHOD UINT32_C(0x112e2cd0)
#define ROME2_PORT_100ED471_FALLBACK_OBJECT UINT32_C(0x119e1004)
#define ROME2_PORT_100ED471_FALLBACK_VTABLE UINT32_C(0x1189791c)
#define ROME2_PORT_100ED471_FALLBACK_METHOD UINT32_C(0x100f3d00)

#define ROME2_PORT_100ED471_TARGET_100EA060 UINT32_C(0x100ea060)
#define ROME2_PORT_100ED471_TARGET_112DCAF0 UINT32_C(0x112dcaf0)
#define ROME2_PORT_100ED471_TARGET_100D6560 UINT32_C(0x100d6560)
#define ROME2_PORT_100ED471_TARGET_112E3D20 UINT32_C(0x112e3d20)
#define ROME2_PORT_100ED471_TARGET_112E2BB0 UINT32_C(0x112e2bb0)
#define ROME2_PORT_100ED471_TARGET_100EC5C0 UINT32_C(0x100ec5c0)
#define ROME2_PORT_100ED471_TARGET_100E0650 UINT32_C(0x100e0650)
#define ROME2_PORT_100ED471_TARGET_100F1CC0 UINT32_C(0x100f1cc0)

/* Numeric values are transcript ordinals, never native call targets. */
typedef enum rome2_100ed471_step_kind {
    ROME2_100ED471_STEP_CALL_100EA060 = 1,
    ROME2_100ED471_STEP_CALL_112DCAF0 = 2,
    ROME2_100ED471_STEP_CALL_100D6560 = 3,
    ROME2_100ED471_STEP_CALL_112E3D20 = 4,
    ROME2_100ED471_STEP_INDIRECT_SLOT_54 = 5,
    ROME2_100ED471_STEP_CALL_112E2BB0 = 6,
    ROME2_100ED471_STEP_CALL_100EC5C0 = 7,
    ROME2_100ED471_STEP_CALL_100E0650 = 8,
    ROME2_100ED471_STEP_CALL_100F1CC0 = 9
} rome2_100ed471_step_kind;

/*
 * Arguments and results are opaque 32-bit x86 values or guest identities.
 * The dispatch fields are meaningful only for INDIRECT_SLOT_54.  Every step
 * is passed by value and contains no native pointer.  For CALL_112E2BB0,
 * result0/result1 are the injected low/high dwords written through argument0;
 * they do not model EAX's returned destination identity.
 */
typedef struct rome2_100ed471_step {
    rome2_100ed471_step_kind kind;
    uint32_t argument_count;
    uint32_t argument0;
    uint32_t argument1;
    uint32_t argument2;
    uint32_t result_count;
    uint32_t result0;
    uint32_t result1;
    uint32_t dispatch_vtable;
    uint32_t dispatch_slot_offset;
    uint32_t dispatch_target;
} rome2_100ed471_step;

typedef void (*rome2_100ed471_emit_step_fn)(
    void *context,
    rome2_100ed471_step step);

typedef struct rome2_100ed471_lifecycle_effects {
    rome2_100ed471_emit_step_fn emit_step;
    void *context;
    uint32_t timestamp_low;
    uint32_t timestamp_high;
    uint32_t poll_result_count;
    uint32_t poll_results[ROME2_PORT_100ED471_MAX_POLL_CALLS];
} rome2_100ed471_lifecycle_effects;

typedef struct rome2_100ed471_lifecycle_result {
    rome2_guest_addr32 dispatch_receiver;
    rome2_guest_addr32 dispatch_vtable;
    rome2_guest_addr32 dispatch_target;
    uint32_t poll_calls;
    uint32_t terminal_poll_result;
    uint32_t timestamp_low;
    uint32_t timestamp_high;
    uint32_t return_original_pc;
} rome2_100ed471_lifecycle_result;

/*
 * Model the authenticated ordinary domain of original interval
 * [0x100ed471,0x100ed550).  frame_view must name exactly the 0x90c-byte frame
 * produced by the admitted empty-preloop adapter.  dispatch_view supplies
 * read-only guest32 cells for dispatch_receiver, its vtable, and vtable+0x54;
 * the recovered method is represented only as checked transcript data and is
 * never called.  Only the two authenticated vtable/method pairs above are
 * admitted, with the fallback pair additionally requiring its fixed object.
 *
 * The six setup call shapes are emitted in original order.  The injected
 * timestamp pair is byte-written at frame+0x28 and copied to frame+0x904.
 * The snapshotted finite poll transcript is then emitted as checked
 * 0x100ec5c0 call shapes.  It must contain zero or more zero results followed
 * by one terminal two, with no trailing values, and its count must not exceed
 * max_poll_calls.  Result one, any other value, a zero-only transcript, and
 * budget exhaustion all fail during preflight before any callback or write.
 *
 * On result two, the injected 0x100e0650 shape is emitted and the four empty
 * descriptors at +0x48,+0x3c,+0x10,+0x04 are admitted through the existing
 * nonowning 0x100f1cc0 no-op in exact order.  The result commits last.
 * Result one, its list loop, outer backedge, and second indirect call remain
 * excluded by the separately authenticated ordinary-return proof.
 *
 * Before the first callback or write, all borrowed objects, numeric host and
 * guest ranges, alignment, aliases, dispatch cells/pair, full poll transcript,
 * poll bound, and four empty descriptors are validated and snapshotted.
 * Preflight failure emits nothing and preserves frame bytes and result_out.
 * The observer callback is total, nonreentrant, returns normally, retains no
 * borrowed object, modifies no guest byte or control object, and may mutate
 * only its disjoint context.
 *
 * This adapter allocates nothing, calls no platform API or original address,
 * uses no guest-derived native function pointer, and performs no guest/native
 * pointer cast.
 */
rome2_guest_status rome2_port_100ed471_run_ordinary_lifecycle(
    const rome2_guest_write_view *frame_view,
    rome2_guest_addr32 guest_frame,
    const rome2_guest_read_view *dispatch_view,
    rome2_guest_addr32 dispatch_receiver,
    uint32_t max_poll_calls,
    const rome2_100ed471_lifecycle_effects *effects,
    rome2_100ed471_lifecycle_result *result_out);

#endif

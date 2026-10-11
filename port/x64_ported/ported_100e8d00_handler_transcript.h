#ifndef ROME2_PORTED_100E8D00_HANDLER_TRANSCRIPT_H
#define ROME2_PORTED_100E8D00_HANDLER_TRANSCRIPT_H

#include "guest32.h"

#define ROME2_PORT_100E8D00_AL UINT8_C(1)
#define ROME2_PORT_100E8D00_STEP_COUNT UINT32_C(6)

#define ROME2_PORT_100E8D00_TARGET_10CB6160 UINT32_C(0x10cb6160)
#define ROME2_PORT_100E8D00_TARGET_10115D40 UINT32_C(0x10115d40)
#define ROME2_PORT_100E8D00_TARGET_112DC9F0 UINT32_C(0x112dc9f0)
#define ROME2_PORT_100E8D00_TARGET_101150A0 UINT32_C(0x101150a0)
#define ROME2_PORT_100E8D00_TARGET_101151D0 UINT32_C(0x101151d0)
#define ROME2_PORT_100E8D00_TARGET_112E2CB0 UINT32_C(0x112e2cb0)

#define ROME2_PORT_100E8D00_PRE_DB_APP_INIT_IDENTITY UINT32_C(0x1173fb44)

/*
 * Each kind identifies one authenticated direct call in original 0x100e8d00.
 * The numeric values describe transcript order, not original executable VAs.
 */
typedef enum rome2_100e8d00_step_kind {
    ROME2_100E8D00_STEP_CALL_10CB6160 = 1,
    ROME2_100E8D00_STEP_CALL_10115D40 = 2,
    ROME2_100E8D00_STEP_CALL_112DC9F0 = 3,
    ROME2_100E8D00_STEP_CALL_101150A0 = 4,
    ROME2_100E8D00_STEP_CALL_101151D0 = 5,
    ROME2_100E8D00_STEP_CALL_112E2CB0 = 6
} rome2_100e8d00_step_kind;

/*
 * argument0 and argument1 are the callee-visible 32-bit stack arguments in
 * logical order.  Unused fields are zero.  Thus the original right-to-left
 * push stream is reversed for each two-argument call:
 *
 *   10cb6160: pushes 1, 0; callback arguments are (0, 1)
 *   112dc9f0: pushes 0, 1173fb44; callback arguments are (1173fb44, 0)
 *
 * The 1173fb44 value is an authenticated guest identity for the original
 * "PRE_DB_APP_INIT" object.  It is data, never converted to a host pointer.
 */
typedef struct rome2_100e8d00_step {
    rome2_100e8d00_step_kind kind;
    uint32_t argument_count;
    uint32_t argument0;
    uint32_t argument1;
} rome2_100e8d00_step;

/*
 * A transcript callback is required to be total and nonreentrant: it returns
 * normally for every step, does not call this adapter recursively, does not
 * retain borrowed host objects, and does not modify return_al_out.  The step
 * is passed by value.  The callback may mutate its context, including an
 * underlying non-const effects object; the adapter snapshots both callback
 * and context before emitting the first step.
 */
typedef void (*rome2_100e8d00_emit_step_fn)(
    void *context,
    rome2_100e8d00_step step);

typedef struct rome2_100e8d00_transcript_effects {
    rome2_100e8d00_emit_step_fn emit_step;
    void *context;
} rome2_100e8d00_transcript_effects;

/*
 * Model original thiscall handler 0x100e8d00 as a bounded effect transcript.
 * The receiver and sole stack argument are opaque guest identities; every
 * 32-bit pattern is accepted because the authenticated body ignores both.
 *
 * effects and return_al_out are required borrowed objects with valid numeric
 * host spans and must not overlap.  effects->emit_step and effects->context
 * are both required.  Validation failure emits nothing and leaves the output
 * unchanged.  Success emits exactly six steps and publishes AL=1 only after
 * the sixth callback returns.  The port performs no allocation, platform or
 * original-image call, guest dereference, or guest/native pointer cast.
 */
rome2_guest_status rome2_port_100e8d00_run_handler_transcript(
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100e8d00_transcript_effects *effects,
    uint8_t *return_al_out);

#endif

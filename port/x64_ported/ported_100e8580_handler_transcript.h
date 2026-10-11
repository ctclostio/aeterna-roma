#ifndef ROME2_PORTED_100E8580_HANDLER_TRANSCRIPT_H
#define ROME2_PORTED_100E8580_HANDLER_TRANSCRIPT_H

#include "guest32.h"

#define ROME2_PORT_100E8580_AL UINT8_C(1)
#define ROME2_PORT_100E8580_STEP_COUNT UINT32_C(9)
#define ROME2_PORT_100E8580_RESULT_DISPLACEMENT UINT32_C(0x68)

#define ROME2_PORT_100E8580_TARGET_100D6560 UINT32_C(0x100d6560)
#define ROME2_PORT_100E8580_TARGET_112D0510 UINT32_C(0x112d0510)
#define ROME2_PORT_100E8580_TARGET_112E0950 UINT32_C(0x112e0950)
#define ROME2_PORT_100E8580_TARGET_100D9810 UINT32_C(0x100d9810)
#define ROME2_PORT_100E8580_TARGET_100DDF50 UINT32_C(0x100ddf50)
#define ROME2_PORT_100E8580_TARGET_100E8240 UINT32_C(0x100e8240)
#define ROME2_PORT_100E8580_TARGET_112BFEE0 UINT32_C(0x112bfee0)
#define ROME2_PORT_100E8580_TARGET_112DCAF0 UINT32_C(0x112dcaf0)

#define ROME2_PORT_100E8580_FINISHED_RUN_VARS_IDENTITY UINT32_C(0x1173fb54)

typedef enum rome2_100e8580_step_kind {
    ROME2_100E8580_STEP_CALL_100D6560 = 1,
    ROME2_100E8580_STEP_CALL_112D0510 = 2,
    ROME2_100E8580_STEP_CALL_112E0950_ONE = 3,
    ROME2_100E8580_STEP_CALL_100D9810 = 4,
    ROME2_100E8580_STEP_CALL_100DDF50 = 5,
    ROME2_100E8580_STEP_CALL_112E0950_ZERO = 6,
    ROME2_100E8580_STEP_CALL_100E8240 = 7,
    ROME2_100E8580_STEP_CALL_112BFEE0 = 8,
    ROME2_100E8580_STEP_CALL_112DCAF0 = 9
} rome2_100e8580_step_kind;

/*
 * Arguments are callee-visible 32-bit values in logical order.  Unused
 * fields are zero.  has_guest_result is one only for CALL_100E8240, whose
 * returned_guest_identity is the explicit injected dependency consumed by
 * the following checked +0x68 operation.  Steps are passed by value.
 */
typedef struct rome2_100e8580_step {
    rome2_100e8580_step_kind kind;
    uint32_t argument_count;
    uint32_t argument0;
    uint32_t argument1;
    uint32_t argument2;
    uint32_t has_guest_result;
    rome2_guest_addr32 returned_guest_identity;
} rome2_100e8580_step;

typedef void (*rome2_100e8580_emit_step_fn)(
    void *context,
    rome2_100e8580_step step);

typedef struct rome2_100e8580_transcript_effects {
    rome2_100e8580_emit_step_fn emit_step;
    void *context;
    rome2_guest_addr32 result_100e8240;
} rome2_100e8580_transcript_effects;

/*
 * Model original thiscall handler 0x100e8580 as a bounded injected-effect
 * transcript.  The receiver and sole stack argument are opaque guest values;
 * every bit pattern is admitted because the authenticated body ignores both.
 * The adapter never calls any recovered address.  result_100e8240 supplies
 * the guest identity that the original dependent call returned in EAX.
 *
 * effects and return_al_out are required, valid, disjoint borrowed objects.
 * The callback and context are required.  The complete effects object is
 * snapshotted before the first callback.  The callback must be total and
 * nonreentrant, return normally, not retain borrowed objects, and not modify
 * return_al_out.
 *
 * Borrowed-object validation failure emits nothing and preserves the output.
 * After the first seven steps, result_100e8240 is checked with guest32 +0x68.
 * A null identity returns NULL_ADDRESS; overflow returns RANGE_OVERFLOW.  In
 * either case those seven prefix effects remain committed, steps eight and
 * nine are not emitted, and return_al_out remains unchanged.  Success emits
 * both suffix steps and publishes AL=1 only after the ninth callback returns.
 * No guest value is cast to or dereferenced as a host pointer.
 */
rome2_guest_status rome2_port_100e8580_run_handler_transcript(
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100e8580_transcript_effects *effects,
    uint8_t *return_al_out);

#endif

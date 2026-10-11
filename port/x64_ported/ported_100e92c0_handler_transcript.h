#ifndef ROME2_PORTED_100E92C0_HANDLER_TRANSCRIPT_H
#define ROME2_PORTED_100E92C0_HANDLER_TRANSCRIPT_H

#include "guest32.h"

#define ROME2_PORT_100E92C0_AL UINT8_C(1)
#define ROME2_PORT_100E92C0_FIRST_FALSE_STEP_COUNT UINT32_C(3)
#define ROME2_PORT_100E92C0_SECOND_FALSE_STEP_COUNT UINT32_C(4)
#define ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT UINT32_C(6)

#define ROME2_PORT_100E92C0_TARGET_100D6970 UINT32_C(0x100d6970)
#define ROME2_PORT_100E92C0_TARGET_10FDE370 UINT32_C(0x10fde370)
#define ROME2_PORT_100E92C0_TARGET_10FDE9D0 UINT32_C(0x10fde9d0)
#define ROME2_PORT_100E92C0_TARGET_10FDE270 UINT32_C(0x10fde270)
#define ROME2_PORT_100E92C0_TARGET_10FDE990 UINT32_C(0x10fde990)
#define ROME2_PORT_100E92C0_TARGET_100D5150 UINT32_C(0x100d5150)

/*
 * Kinds identify the six possible calls in authenticated original order.
 * Numeric values are transcript ordinals, never native call targets.
 */
typedef enum rome2_100e92c0_step_kind {
    ROME2_100E92C0_STEP_CALL_100D6970 = 1,
    ROME2_100E92C0_STEP_CALL_10FDE370 = 2,
    ROME2_100E92C0_STEP_CALL_10FDE9D0 = 3,
    ROME2_100E92C0_STEP_CALL_10FDE270 = 4,
    ROME2_100E92C0_STEP_CALL_10FDE990 = 5,
    ROME2_100E92C0_STEP_CALL_100D5150 = 6
} rome2_100e92c0_step_kind;

/*
 * argument0..argument3 are callee-visible 32-bit stack arguments in logical
 * order.  Only CALL_100D5150 exposes arguments; native pointers to the
 * original stack-local pair are deliberately suppressed on the getter steps.
 *
 * result_count is one for either predicate, two for either getter, and zero
 * otherwise.  local_before/after describe the two-word stack-local value
 * passed by address to the getter calls without exposing its native address.
 * The first getter's second result word is authenticated as zero.  The second
 * getter observes the first result as its local_before value and replaces it.
 * All fields not meaningful for a kind are zero.  Steps are passed by value.
 */
typedef struct rome2_100e92c0_step {
    rome2_100e92c0_step_kind kind;
    uint32_t argument_count;
    uint32_t argument0;
    uint32_t argument1;
    uint32_t argument2;
    uint32_t argument3;
    uint32_t result_count;
    uint32_t result0;
    uint32_t result1;
    uint32_t local_before0;
    uint32_t local_before1;
    uint32_t local_after0;
    uint32_t local_after1;
} rome2_100e92c0_step;

typedef void (*rome2_100e92c0_emit_step_fn)(
    void *context,
    rome2_100e92c0_step step);

typedef struct rome2_100e92c0_transcript_effects {
    rome2_100e92c0_emit_step_fn emit_step;
    void *context;
    uint32_t predicate_10fde370;
    uint32_t predicate_10fde9d0;
    uint32_t result_10fde270_low;
    uint32_t result_10fde990_low;
    uint32_t result_10fde990_high;
} rome2_100e92c0_transcript_effects;

/*
 * Model original thiscall handler 0x100e92c0 as a bounded injected-effect
 * transcript.  Its receiver and sole stack argument are ignored by the
 * authenticated body, so every guest32 bit pattern is admitted.
 *
 * Both predicate fields must be zero or one.  They represent the exact AL
 * outcomes observed after CALL_100D6970 returns normally.  If the first is
 * zero, the second predicate and both getters are inactive.  If the first is
 * one and the second is zero, both getters are inactive.  Either false route
 * calls 0x100d5150 with four zeros.  When both are one, the getter results are
 * forwarded as (result_10fde270_low, 0, result_10fde990_low,
 * result_10fde990_high).  The adapter publishes AL=1 only after that final
 * injected call returns.
 *
 * effects and return_al_out are required valid, disjoint borrowed objects;
 * effects must satisfy its natural alignment.  The complete effects object
 * is snapshotted before the first callback.  The callback and context are
 * required.  The callback is total and nonreentrant, returns normally, does
 * not retain borrowed objects, and does not modify return_al_out.  It may
 * mutate its context or the caller's effects object after the snapshot.
 *
 * Validation failure emits nothing and preserves return_al_out.  This port
 * admits only normally completed injected calls and readable getter results.
 * It does not reproduce original faults or exceptions.  It calls no original
 * address, platform API, Steam API, allocator, TLS routine, or global state;
 * it performs no guest dereference or guest/native pointer cast.
 */
rome2_guest_status rome2_port_100e92c0_run_handler_transcript(
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100e92c0_transcript_effects *effects,
    uint8_t *return_al_out);

#endif

#ifndef ROME2_PORTED_100E9340_HANDLER_TRANSCRIPT_H
#define ROME2_PORTED_100E9340_HANDLER_TRANSCRIPT_H

#include "guest32.h"

#define ROME2_PORT_100E9340_AL UINT8_C(1)
#define ROME2_PORT_100E9340_STEP_COUNT UINT32_C(4)

#define ROME2_PORT_100E9340_SELECTOR_DWORD UINT32_C(0x12)
#define ROME2_PORT_100E9340_SELECTOR_BYTE UINT32_C(0x49)
#define ROME2_PORT_100E9340_TARGET_112E1830 UINT32_C(0x112e1830)
#define ROME2_PORT_100E9340_TARGET_112CBBB0 UINT32_C(0x112cbbb0)

/*
 * The first two kinds stand for the authenticated indirect virtual calls
 * through global object 0x119f3140 + 0x874.  The latter two stand for the
 * exact direct-call suffix.  Numeric kind values describe transcript order,
 * not callable native addresses.
 */
typedef enum rome2_100e9340_step_kind {
    ROME2_100E9340_STEP_LOOKUP_DWORD_12 = 1,
    ROME2_100E9340_STEP_LOOKUP_BYTE_49 = 2,
    ROME2_100E9340_STEP_CALL_112E1830 = 3,
    ROME2_100E9340_STEP_CALL_112CBBB0 = 4
} rome2_100e9340_step_kind;

/*
 * Arguments are callee-visible 32-bit stack values in logical order.
 * result_width_bytes is four for the injected first lookup, one for the
 * injected second lookup, and zero otherwise.  result_u32 carries the exact
 * injected bits and is zero when no portable result is exposed.
 *
 * CALL_112E1830 deliberately exposes no result: the original return is a
 * process-global native singleton pointer used as ECX by CALL_112CBBB0.  The
 * next step records the helper's three stack arguments but never represents,
 * stores, or casts that native pointer.
 */
typedef struct rome2_100e9340_step {
    rome2_100e9340_step_kind kind;
    uint32_t argument_count;
    uint32_t argument0;
    uint32_t argument1;
    uint32_t argument2;
    uint32_t result_width_bytes;
    uint32_t result_u32;
} rome2_100e9340_step;

typedef void (*rome2_100e9340_emit_step_fn)(
    void *context,
    rome2_100e9340_step step);

typedef struct rome2_100e9340_transcript_effects {
    rome2_100e9340_emit_step_fn emit_step;
    void *context;
    uint32_t selected_dword_12;
    uint32_t selected_byte_49;
} rome2_100e9340_transcript_effects;

/*
 * Model original thiscall handler 0x100e9340 as a bounded injected-effect
 * transcript.  The stack argument is ignored by the authenticated body.  The
 * receiver is never dereferenced, but its upper 24 bits are preserved when
 * selected_byte_49 replaces its low byte.  Therefore every guest32 receiver
 * and argument bit pattern, including zero, is admitted.
 *
 * selected_dword_12 supplies the four bytes loaded through the result of the
 * selector-0x12 virtual call.  selected_byte_49 must be in [0,255] and
 * supplies the byte loaded through the selector-0x49 result.  Supplying the
 * already-loaded values deliberately admits only the completed lookup path;
 * original null/unreadable result pointers and their x86 faults have no safe
 * executable representation here.  Likewise, the singleton-getter step
 * represents only a normally completed getter/helper suffix.  Success emits:
 *
 *   lookup(0x12) -> selected_dword_12;
 *   lookup(0x49) -> selected_byte_49;
 *   call 0x112e1830 (native singleton result suppressed);
 *   call 0x112cbbb0(selected_dword_12, patched_receiver, 0).
 *
 * effects and return_al_out are required valid, disjoint borrowed objects;
 * effects must satisfy its natural alignment.  The complete effects object
 * is snapshotted before emission.  The callback and context are required.
 * The callback is total and nonreentrant, returns normally, does not retain
 * borrowed objects, and does not modify return_al_out.  It may mutate its
 * context and the caller's effects object because the snapshot is already
 * complete.
 *
 * Validation failure emits nothing and leaves return_al_out unchanged.
 * Success publishes only AL=1 after the fourth callback.  The original
 * `mov al,1` did not define upper EAX, and this API invents no full return.
 * The port calls no recovered address, allocator, platform API, TLS API, or
 * global singleton; it performs no guest dereference or guest/native cast.
 */
rome2_guest_status rome2_port_100e9340_run_handler_transcript(
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100e9340_transcript_effects *effects,
    uint8_t *return_al_out);

#endif

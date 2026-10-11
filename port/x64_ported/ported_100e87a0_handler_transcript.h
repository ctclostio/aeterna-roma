#ifndef ROME2_PORTED_100E87A0_HANDLER_TRANSCRIPT_H
#define ROME2_PORTED_100E87A0_HANDLER_TRANSCRIPT_H

#include "ported_100f1c10_triplet.h"

#define ROME2_PORT_100E87A0_AL UINT8_C(1)
#define ROME2_PORT_100E87A0_LISTENER_BYTES UINT32_C(4)
#define ROME2_PORT_100E87A0_ALLOCATION_CLASS UINT32_C(0)
#define ROME2_PORT_100E87A0_LISTENER_VTABLE UINT32_C(0x1173ff28)
#define ROME2_PORT_100E87A0_LOG_LEVEL UINT32_C(6)

#define ROME2_PORT_100E87A0_POLICY_TYPE UINT32_C(2)
#define ROME2_PORT_100E87A0_POLICY_TRACK_ALLOCATIONS UINT32_C(1)
#define ROME2_PORT_100E87A0_POLICY_ALLOCATE_IDENTITY UINT32_C(0x100d12b0)
#define ROME2_PORT_100E87A0_POLICY_ALLOCATE_DEBUG_IDENTITY UINT32_C(0x100e2190)
#define ROME2_PORT_100E87A0_POLICY_FREE_IDENTITY UINT32_C(0x100e21a0)

typedef enum rome2_100e87a0_status {
    ROME2_100E87A0_OK = ROME2_GUEST_OK,
    ROME2_100E87A0_BAD_ARGUMENT = ROME2_GUEST_BAD_ARGUMENT,
    ROME2_100E87A0_NULL_ADDRESS = ROME2_GUEST_NULL_ADDRESS,
    ROME2_100E87A0_RANGE_OVERFLOW = ROME2_GUEST_RANGE_OVERFLOW,
    ROME2_100E87A0_OUT_OF_RANGE = ROME2_GUEST_OUT_OF_RANGE,
    ROME2_100E87A0_ALLOCATION_RESULT_INVALID = 5
} rome2_100e87a0_status;

/*
 * A typed, pointer-free representation of the five meaningful fields in the
 * original 20-byte FaceFX allocation-policy local.  The original bool at
 * offset four is widened to an exact 0/1 value.  The three callback fields
 * remain authenticated guest identities and are never native call targets.
 */
typedef struct rome2_100e87a0_memory_policy {
    uint32_t allocation_type;
    uint32_t track_allocations;
    uint32_t allocate_identity;
    uint32_t allocate_debug_identity;
    uint32_t free_identity;
} rome2_100e87a0_memory_policy;

_Static_assert(sizeof(rome2_100e87a0_memory_policy) == 20U,
    "the portable FaceFX policy transcript must remain five guest32 fields");

typedef rome2_guest_addr32 (*rome2_100e87a0_allocate_effect_fn)(
    void *context,
    uint32_t byte_count,
    uint32_t allocation_class);

typedef void (*rome2_100e87a0_publish_effect_fn)(
    void *context,
    rome2_guest_addr32 listener);

typedef void (*rome2_100e87a0_facefx_startup_effect_fn)(
    void *context,
    rome2_100e87a0_memory_policy policy,
    rome2_guest_addr32 listener,
    uint32_t log_level);

typedef struct rome2_100e87a0_effects {
    rome2_100e87a0_allocate_effect_fn allocate_listener;
    rome2_100e87a0_publish_effect_fn publish_listener;
    rome2_100e87a0_facefx_startup_effect_fn startup_facefx;
    void *context;
} rome2_100e87a0_effects;

/*
 * Bounded injected-effect transcript for original thiscall handler
 * 0x100e87a0.  The receiver and sole stack argument are authenticated as
 * unused and are accepted as opaque all-bit guest identities.
 *
 * Before the first effect, state_view, effects, return_al_out, their numeric
 * host ranges, alignments, and every control/host overlap are validated.  The
 * entire effects object is then snapshotted.  Every callback pointer field
 * must contain an initialized valid C representation; all three callbacks
 * and context are required.  Callbacks are total and nonreentrant, return
 * normally, retain no borrowed object, do not modify return_al_out or guest
 * bytes, and may mutate only disjoint context storage.
 *
 * The exact admitted effect order is:
 *
 *   allocate_listener(context,4,0);
 *   if nonnull, store guest32 vtable identity 0x1173ff28;
 *   publish_listener(context,listener);
 *   startup_facefx(context,policy,listener,6);
 *   publish AL=1.
 *
 * A null allocation is an authenticated normal route: it performs no guest
 * store but still publishes null and invokes FaceFX.  A nonnull result must
 * name a complete four-byte span in state_view.  Failure to do so returns
 * ALLOCATION_RESULT_INVALID after the allocation effect only; no vtable
 * store, publication, startup, or AL write occurs.  Thus effects and guest
 * mutation are prefix-committing and are never rolled back.
 *
 * The no-op policy constructor/destructor are represented by the exact typed
 * policy value and elided cleanup.  No original address, native allocator,
 * process global, FaceFX implementation, platform API, or guest-derived
 * function pointer is called or cast by this port.
 */
rome2_100e87a0_status rome2_port_100e87a0_run_handler_transcript(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100e87a0_effects *effects,
    uint8_t *return_al_out);

#endif

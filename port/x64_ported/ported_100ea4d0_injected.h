#ifndef ROME2_PORTED_100EA4D0_INJECTED_H
#define ROME2_PORTED_100EA4D0_INJECTED_H

#include "ported_100e2460_router.h"

#define ROME2_PORT_100EA4D0_REGISTRATION_COUNT UINT32_C(6)
#define ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_BYTES UINT32_C(4)
#define ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_CLASS UINT32_C(0)
#define ROME2_PORT_100EA4D0_ARGUMENT_OFFSET UINT32_C(0x824)
#define ROME2_PORT_100EA4D0_VECTOR_OFFSET UINT32_C(0x854)

typedef enum rome2_100ea4d0_status {
    ROME2_100EA4D0_OK = ROME2_GUEST_OK,
    ROME2_100EA4D0_BAD_ARGUMENT = ROME2_GUEST_BAD_ARGUMENT,
    ROME2_100EA4D0_NULL_ADDRESS = ROME2_GUEST_NULL_ADDRESS,
    ROME2_100EA4D0_RANGE_OVERFLOW = ROME2_GUEST_RANGE_OVERFLOW,
    ROME2_100EA4D0_OUT_OF_RANGE = ROME2_GUEST_OUT_OF_RANGE,
    ROME2_100EA4D0_ALLOCATION_RESULT_INVALID = 5,
    ROME2_100EA4D0_ROUTER_FAILED = 6,
    ROME2_100EA4D0_ROUTER_RETURNED_ZERO = 7,
    ROME2_100EA4D0_HANDLER_GRAPH_CORRUPTED = 8
} rome2_100ea4d0_status;

typedef rome2_guest_addr32 (*rome2_100ea4d0_handler_allocate_effect_fn)(
    void *context,
    uint32_t byte_count,
    uint32_t allocation_class);

typedef struct rome2_100ea4d0_effects {
    void *allocation_context;
    rome2_100ea4d0_handler_allocate_effect_fn allocate_handler;
    rome2_100e2460_growth_effects router_effects;
} rome2_100ea4d0_effects;

/*
 * Bounded injected-allocation composition of original 0x100ea4d0.  The
 * receiver remains an opaque guest32 identity.  Checked arithmetic derives
 * the original common router receiver at receiver+0x854 and dispatch argument
 * at receiver+0x824.  No guest identity is converted to a native pointer.
 *
 * After all descriptors, mapped intervals, the full outer effects object,
 * the derived vector, their control/host aliases, and the nonzero Peek budget
 * are validated, the complete effects object is snapshotted.  The total outer
 * allocation callback is validated from that snapshot and never reread from
 * caller storage.  Every field, including a route-inactive callback, must
 * therefore hold an initialized valid C representation.  Six iterations then
 * follow the authenticated original order.  Each calls
 * allocate_handler(allocation_context,4,0), validates the returned four-byte
 * guest span, rejects logical or physical alias with the vector, derived
 * argument cell, complete current capacity*4 backing span, vtable view, or an
 * earlier handler allocation, stores the corresponding original vtable
 * identity, and invokes the unified 0x100e2460 router.  After every router
 * return it verifies that every registered handler still contains its exact
 * vtable identity; this catches router storage returned on top of an earlier
 * handler, which the per-call router cannot know.  Router success with a zero
 * AL is an explicit outer failure in place of the original null-write trap.
 * Six nonzero router results return only ROME2_100EA4D0_OK; the original
 * routine had no native return value and this API invents none.
 *
 * The safety envelope deliberately rejects a handler allocation that aliases
 * the complete vector header, argument cell, active capacity-sized backing,
 * or any part of the read-only vtable mapping, even where a narrower route
 * might not touch every aliased byte.  Requiring the argument cell and full
 * active backing to be mapped is also a deliberate narrowing.  These are
 * fail-closed policies, not claims about additional original x86 checks.
 *
 * Effects are prefix-committing, as in the original.  An invalid allocation
 * result leaves its allocation effect and every earlier registration
 * committed, but performs no current vtable store or router call.  Invalid
 * current backing state after an outer allocation returns ROUTER_FAILED with
 * that allocation effect only.  A failure returned by the router leaves the
 * current allocation and vtable store plus any partial router commits in
 * place.  HANDLER_GRAPH_CORRUPTED means a router return damaged an
 * earlier/current handler; all router and outer effects through that point
 * remain committed.  A zero returned AL means the current registration and
 * its router effects completed before the outer failure.  The function never
 * rolls back guest bytes, allocation/release effects, dispatch, or Peek.
 *
 * The caller grants an exclusive non-reentrant borrow for the whole call.
 * The outer allocator is total, may mutate only disjoint allocation-context
 * storage, and may neither retain nor modify the views, effects, or guest
 * bytes.  Router callbacks inherit their existing contracts.  This port calls
 * no original/native allocator, release routine, handler, platform API, or
 * guest-derived function pointer.
 */
rome2_100ea4d0_status rome2_port_100ea4d0_run_injected(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_receiver,
    const rome2_100ea4d0_effects *effects,
    uint32_t max_peek_calls);

#endif

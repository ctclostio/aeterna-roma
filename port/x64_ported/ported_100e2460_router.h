#ifndef ROME2_PORTED_100E2460_ROUTER_H
#define ROME2_PORTED_100E2460_ROUTER_H

#include "ported_100e2460_growth_branch.h"

/*
 * Route one bounded append through the three admitted paths of original
 * 0x100e2460.  The router validates the borrowed descriptors, the complete
 * growth-effects superset, the output object, and only the vector capacity
 * and count cells needed for unsigned route selection.  It then delegates:
 *
 *   count < capacity         preallocated branch
 *   count >= capacity,
 *     capacity == 0          capacity-zero branch
 *   count >= capacity,
 *     capacity != 0          growth branch
 *
 * The selected delegate remains the authority for all route-specific
 * validation, effects, commit order, failure status, bounded Peek drain, and
 * AL publication.  In particular, count > capacity reaches the growth
 * delegate and zero capacity with nonzero count reaches the capacity-zero
 * delegate; both fail there without the router inventing another route.
 *
 * effects is always the full growth superset.  Every field is snapshotted
 * after full control/host alias validation, before a route adapter is built.
 * The preallocated route does not use allocate or release; the capacity-zero
 * route does not use release; the growth route uses both.  These inactive
 * callbacks may be null, but their storage is still part of the exclusive
 * borrowed effects object and cannot be hidden from alias checks by the
 * smaller delegate adapters.  Because the whole object is snapshotted, every
 * field must hold an initialized, valid C representation even when inactive;
 * an inactive callback may be null, but it must never be indeterminate.
 *
 * The caller grants the same exclusive, non-reentrant borrow required by the
 * branch APIs.  No callback may modify or retain the views, effects object,
 * guest bytes, or output except for the mutations explicitly admitted by its
 * selected delegate contract.  The router performs no native allocation,
 * release, platform call, dynamic dispatch, or guest-to-host pointer cast.
 */
rome2_100e2460_branch_status rome2_port_100e2460_run_router(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_handler,
    rome2_guest_addr32 guest_argument,
    const rome2_100e2460_growth_effects *effects,
    uint32_t max_peek_calls,
    uint8_t *return_al_out);

#endif

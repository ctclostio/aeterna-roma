#ifndef ROME2_PORTED_100E2460_GROWTH_BRANCH_H
#define ROME2_PORTED_100E2460_GROWTH_BRANCH_H

#include "ported_100e2460_capacity_zero_branch.h"

#define ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS UINT32_C(0)
#define ROME2_PORT_100E2460_GROWTH_MAX_SAFE_OLD_CAPACITY \
    UINT32_C(0x1fffffff)

/*
 * Total semantic adapter for the original release of the superseded backing
 * allocation.  The allocation remains an opaque guest32 identity and is
 * never converted to a host pointer.  Like the allocation adapter, release
 * may mutate only disjoint context storage and must not re-enter this API.
 */
typedef void (*rome2_100e2460_release_effect_fn)(
    void *context,
    rome2_guest_addr32 allocation);

typedef struct rome2_100e2460_growth_effects {
    rome2_100e2460_effects tail_effects;
    rome2_100e2460_allocate_effect_fn allocate;
    rome2_100e2460_release_effect_fn release;
} rome2_100e2460_growth_effects;

/*
 * Complete the memory-safe normal growth route of original 0x100e2460:
 * 0x100e24a5-0x100e252c followed by the common indirect-dispatch and
 * PeekMessageW-shaped tail.  The admitted entry state has capacity > 0,
 * count == capacity, and a nonzero old backing identity whose count*4-byte
 * span is fully mapped.  Capacity is limited to UINT32_MAX/8 so doubling it
 * and expressing the new_capacity*4 allocation request remain checked guest
 * arithmetic.
 *
 * Every descriptor, control object, output, callback, handler/vtable method,
 * old buffer, and known logical/physical alias is validated before commit.
 * Success preserves the original observable sequence: snapshot old backing,
 * store doubled capacity, allocate(new_capacity*4, 0), store the returned
 * backing, copy exactly count guest cells old-to-new in ascending order,
 * append the by-value guest_handler identity, release the old backing, store
 * count+1, dispatch through the prevalidated method identity, and perform the
 * bounded at-least-once Peek-shaped drain.  Only a terminating false Peek
 * publishes the saved dispatch AL; exhaustion returns DRAIN_LIMIT with the
 * preceding guest and injected effects committed and leaves return_al_out
 * unchanged.
 *
 * The allocation result is necessarily validated after its total effect.  A
 * null, overflowing, unmapped, truncated, or aliasing full-capacity result
 * returns ALLOCATION_RESULT_INVALID with only the doubled-capacity store and
 * allocation effect committed.  Backing, old cells, count, release,
 * dispatch, Peek, and return_al_out remain untouched in that case.
 *
 * Original x86 has an adjustment for the special case in which &param_2, its
 * native stack slot, aliases the old backing array.  This API receives only a
 * by-value guest_handler identity and intentionally has no native-stack guest
 * identity to compare; that self-alias route is unrepresentable and excluded.
 * The admitted normal route always appends the supplied guest_handler bits.
 *
 * The caller grants an exclusive, non-reentrant borrow for the whole call.
 * Allocation and release are total and may mutate only context storage that
 * is disjoint from all borrowed objects.  Dispatch and Peek inherit the
 * preallocated-branch adapter contract.  No callback may retain or modify a
 * view descriptor, the effects table, guest bytes, or the output object.
 * Callback identities and context are snapshotted before the first commit;
 * no native allocator, free routine, USER32 routine, or guest-to-host pointer
 * cast is used by this port.
 */
rome2_100e2460_branch_status rome2_port_100e2460_run_growth_branch(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_handler,
    rome2_guest_addr32 guest_argument,
    const rome2_100e2460_growth_effects *effects,
    uint32_t max_peek_calls,
    uint8_t *return_al_out);

#endif

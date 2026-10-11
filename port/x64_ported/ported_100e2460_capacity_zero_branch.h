#ifndef ROME2_PORTED_100E2460_CAPACITY_ZERO_BRANCH_H
#define ROME2_PORTED_100E2460_CAPACITY_ZERO_BRANCH_H

#include "ported_100e2460_preallocated_branch.h"

#define ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_BYTES UINT32_C(4)
#define ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_CLASS UINT32_C(0)

/*
 * Total semantic adapter for original allocator 0x100fcc80(4, 0).  The
 * returned value remains a guest32 identity and is never cast to a host
 * pointer.  The adapter may mutate only its context, which must be storage
 * disjoint from every borrowed object; it must not modify guest bytes, either
 * view, the effects table, or the output object, and it must not re-enter this
 * API.
 */
typedef rome2_guest_addr32 (*rome2_100e2460_allocate_effect_fn)(
    void *context,
    uint32_t byte_count,
    uint32_t allocation_class);

typedef struct rome2_100e2460_capacity_zero_effects {
    rome2_100e2460_effects tail_effects;
    rome2_100e2460_allocate_effect_fn allocate;
} rome2_100e2460_capacity_zero_effects;

/*
 * Complete the intended capacity == 0, count == 0, backing == 0 return path
 * of original
 * 0x100e2460 using a total injected allocation effect and the already-gated
 * dispatch/Peek tail.  The state view contains the vector, handler, and a
 * pre-provisioned four-byte region selected by the allocation adapter.
 *
 * All input, handler, method, control-object, and known-write validation is
 * precommit.  Success then preserves the original observable order:
 * capacity=1, allocate(context,4,0), backing=returned identity, append/count,
 * dispatch, and the bounded Peek-shaped drain.
 *
 * The allocation result cannot be validated before the effect.  A null,
 * unmapped, truncated, or aliasing result therefore returns
 * ALLOCATION_RESULT_INVALID after capacity=1 and the allocation effect have
 * committed; backing, count, return_al_out, dispatch, and Peek remain
 * unchanged.  Requiring a null old backing identity is an ownership-safety
 * invariant: the original does not inspect or free it before overwriting it.
 * DRAIN_LIMIT has the same postcommit semantics as the
 * preallocated branch.  A nonzero count with zero capacity is rejected before
 * mutation because the original allocates four bytes and then indexes by that
 * count, which is not a memory-safe route to admit.
 *
 * The caller grants an exclusive, non-reentrant borrow for the entire call.
 * The allocation adapter obeys the stricter allocator-only rule above.  After
 * allocation has returned, dispatch and Peek inherit the preallocated branch
 * contract: they may mutate their modeled context/state, but must not retain
 * or modify either view descriptor, the effects table, or the output object.
 */
rome2_100e2460_branch_status rome2_port_100e2460_run_capacity_zero_branch(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_handler,
    rome2_guest_addr32 guest_argument,
    const rome2_100e2460_capacity_zero_effects *effects,
    uint32_t max_peek_calls,
    uint8_t *return_al_out);

#endif

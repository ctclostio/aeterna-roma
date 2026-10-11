#ifndef ROME2_PORTED_100E2460_PREALLOCATED_BRANCH_H
#define ROME2_PORTED_100E2460_PREALLOCATED_BRANCH_H

#include "ported_100e2460_append_prefix.h"

#define ROME2_PORT_100E2460_PM_REMOVE UINT32_C(1)

typedef enum rome2_100e2460_branch_status {
    ROME2_100E2460_BRANCH_OK = ROME2_GUEST_OK,
    ROME2_100E2460_BRANCH_BAD_ARGUMENT = ROME2_GUEST_BAD_ARGUMENT,
    ROME2_100E2460_BRANCH_NULL_ADDRESS = ROME2_GUEST_NULL_ADDRESS,
    ROME2_100E2460_BRANCH_RANGE_OVERFLOW = ROME2_GUEST_RANGE_OVERFLOW,
    ROME2_100E2460_BRANCH_OUT_OF_RANGE = ROME2_GUEST_OUT_OF_RANGE,
    ROME2_100E2460_BRANCH_DRAIN_LIMIT = 5,
    ROME2_100E2460_BRANCH_ALLOCATION_RESULT_INVALID = 6
} rome2_100e2460_branch_status;

/*
 * Semantic adapters for the original indirect thiscall and PeekMessageW.
 * Guest receiver/method/argument identities remain opaque 32-bit values.
 * Adapters are total: they return normally with the modeled EAX/BOOL value.
 */
typedef uint32_t (*rome2_100e2460_dispatch_effect_fn)(
    void *context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 method,
    rome2_guest_addr32 argument);

typedef uint32_t (*rome2_100e2460_peek_effect_fn)(
    void *context,
    rome2_guest_addr32 message,
    rome2_guest_addr32 window,
    uint32_t filter_min,
    uint32_t filter_max,
    uint32_t remove_flags);

typedef struct rome2_100e2460_effects {
    void *context;
    rome2_100e2460_dispatch_effect_fn dispatch;
    rome2_100e2460_peek_effect_fn peek;
} rome2_100e2460_effects;

/*
 * Complete the allocation-free count < capacity branch of original
 * 0x100e2460.  state_view maps the vector, backing array, and handler object;
 * vtable_view maps the handler vtable's +4 method cell.  The method identity
 * is resolved as guest data and passed to dispatch; it is never cast to a
 * native function pointer.
 *
 * All safety-relevant address, alias, effect-table, method, and budget
 * validation completes before the existing append prefix commits its two
 * guest writes.  The read-only vtable interval may otherwise overlap the
 * state interval or effects storage; the resolved method cell is checked
 * against both pending write cells before commit.  Validation
 * failures call no adapter and preserve guest bytes and return_al_out.  The
 * queue budget counts every Peek-shaped call, including the terminating zero.
 * A zero budget is a precommit BAD_ARGUMENT failure.
 * A nonzero result on the final allowed call returns DRAIN_LIMIT: the append,
 * count increment, dispatch effect, and prior queue effects remain committed,
 * while return_al_out remains unchanged.  A terminating zero publishes only
 * the dispatch result's low byte.
 *
 * The caller grants an exclusive, non-reentrant borrow for the duration.
 * Adapters may mutate their modeled context/state as the original effects may,
 * but must not retain or modify the view descriptors, effects table, or output
 * object.  The finite drain bound and precommit rejection of malformed guest
 * method data are explicit safety divergences from the original x86 routine.
 */
rome2_100e2460_branch_status rome2_port_100e2460_run_preallocated_branch(
    const rome2_guest_write_view *state_view,
    const rome2_guest_read_view *vtable_view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_handler,
    rome2_guest_addr32 guest_argument,
    const rome2_100e2460_effects *effects,
    uint32_t max_peek_calls,
    uint8_t *return_al_out);

#endif

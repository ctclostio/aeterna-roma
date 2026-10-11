#ifndef ROME2_PORTED_100ED3C0_NONEMPTY_LIFECYCLE_H
#define ROME2_PORTED_100ED3C0_NONEMPTY_LIFECYCLE_H

#include "ported_100ed3c0_nonempty_preloop.h"
#include "ported_100ed471_ordinary_lifecycle.h"

#define ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_START_PC UINT32_C(0x100ed3c0)
#define ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_RETURN_PC UINT32_C(0x100ed550)
#define ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_FRAME_BYTES UINT32_C(0x90c)
#define ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_MISMATCH_PRELOOP_EVENTS \
    UINT32_C(31)
#define ROME2_PORT_100ED3C0_NONEMPTY_LIFECYCLE_FIXED_TAIL_EVENTS UINT32_C(11)

/*
 * ordinary_context_byte_count completes the pointer-only observer contract of
 * the frozen ordinary-lifecycle leaf.  The five preloop context sizes remain
 * inside preloop.  Across all six contexts, exactly identical spans may share
 * one total-order recorder; partially overlapping spans are rejected.
 */
typedef struct rome2_100ed3c0_nonempty_lifecycle_effects {
    rome2_100ed3c0_nonempty_effects preloop;
    rome2_100ed471_lifecycle_effects ordinary;
    uint64_t ordinary_context_byte_count;
} rome2_100ed3c0_nonempty_lifecycle_effects;

typedef struct rome2_100ed3c0_nonempty_lifecycle_result {
    rome2_100ed3c0_preloop_result preloop;
    rome2_100ed471_lifecycle_result ordinary;
} rome2_100ed3c0_nonempty_lifecycle_result;

/*
 * Compose the admitted nonempty [0x100ed3c0,0x100ed471) route and admitted
 * finite ordinary-domain [0x100ed471,0x100ed550) route on one exact 0x90c
 * frame.  The seam is the original fallthrough: the preloop next identity
 * must equal the lifecycle start identity, and the final result stops at the
 * original return only as data.
 *
 * Before the first external callback, allocation, release, hook, or guest
 * write, this adapter snapshots every input, validates the enlarged seven-
 * backing/six-context alias universe, and runs the frozen lifecycle once on a
 * private scratch frame with a private observer/result.  The scratch frame is
 * seeded with the four sentinel descriptors guaranteed by a successful
 * preloop.  This private preview settles all deterministic dispatch, poll,
 * cleanup, range, and lifecycle validation before the nonempty leaf can begin
 * committed effects.  It publishes nothing and is discarded.
 *
 * The real order is then exactly one nonempty-preloop call followed, only on
 * success, by exactly one ordinary-lifecycle call.  Registration and
 * persistent teardown remain outside this interval.  A successful call leaves
 * temporary_owner CONSUMED, persistent_owner LIVE, and lifecycle
 * REGISTERED_LIVE.  The combined result commits once and last.  A nonempty
 * failure preserves that leaf's exact committed-prefix and escaped-owner
 * contract and never starts the real lifecycle.  A defensive failure after a
 * successful preloop performs no rollback: the persistent authority remains
 * live for explicit teardown and the combined result stays unchanged.
 *
 * The adapter executes no original address, native allocator, platform API,
 * CRT registration, process global, guest-derived function pointer, or
 * recovered implementation, and performs no guest/native pointer cast.
 */
rome2_100f1bb0_owned_status rome2_port_100ed3c0_run_nonempty_lifecycle(
    const rome2_guest_write_view *frame_view,
    rome2_guest_addr32 guest_frame,
    uint32_t argument_position1,
    const rome2_guest_read_view *text_view,
    rome2_guest_addr32 argument_position3_text,
    uint32_t text_max_units,
    const rome2_guest_write_view *selector_view,
    const rome2_guest_write_view *temporary_heap_view,
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_guest_write_view *persistent_heap_view,
    const rome2_guest_read_view *dispatch_view,
    rome2_guest_addr32 dispatch_receiver,
    uint32_t max_poll_calls,
    const rome2_100ed3c0_nonempty_lifecycle_effects *effects,
    rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_100ed3c0_nonempty_lifecycle_result *result_out);

#endif

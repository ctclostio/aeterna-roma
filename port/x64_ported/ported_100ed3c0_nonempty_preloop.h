#ifndef ROME2_PORTED_100ED3C0_NONEMPTY_PRELOOP_H
#define ROME2_PORTED_100ED3C0_NONEMPTY_PRELOOP_H

#include "ported_100ed3c0_empty_preloop.h"
#include "ported_100f1bb0_owned_utf16.h"
#include "ported_100f2750_first_use_owned.h"

#define ROME2_PORT_100ED3C0_NONEMPTY_STEP_COUNT UINT32_C(9)
#define ROME2_PORT_100ED3C0_NONEMPTY_MIN_TEXT_UNITS UINT32_C(2)
#define ROME2_PORT_100ED3C0_NONEMPTY_MAX_TEXT_UNITS \
    ROME2_PORT_100F1BB0_OWNED_MAX_UNITS

/* Numeric values are parent transcript ordinals, never native call targets. */
typedef enum rome2_100ed3c0_nonempty_step_kind {
    ROME2_100ED3C0_NONEMPTY_STEP_WRITE_GLOBAL_119F31C8 = 1,
    ROME2_100ED3C0_NONEMPTY_STEP_WRITE_GLOBAL_119F31C5 = 2,
    ROME2_100ED3C0_NONEMPTY_STEP_INIT_TRIPLET0 = 3,
    ROME2_100ED3C0_NONEMPTY_STEP_INIT_TRIPLET1 = 4,
    ROME2_100ED3C0_NONEMPTY_STEP_COPY_EMPTY0 = 5,
    ROME2_100ED3C0_NONEMPTY_STEP_COPY_EMPTY1 = 6,
    ROME2_100ED3C0_NONEMPTY_STEP_BUILD_OWNED_DESCRIPTOR = 7,
    ROME2_100ED3C0_NONEMPTY_STEP_RUN_100DF270 = 8,
    ROME2_100ED3C0_NONEMPTY_STEP_CLEANUP_OWNED_DESCRIPTOR = 9
} rome2_100ed3c0_nonempty_step_kind;

typedef struct rome2_100ed3c0_nonempty_step {
    rome2_100ed3c0_nonempty_step_kind kind;
    uint32_t argument_count;
    rome2_100ed3c0_preloop_value argument0;
    rome2_100ed3c0_preloop_value argument1;
    rome2_100ed3c0_preloop_value argument2;
    uint32_t result_count;
    rome2_100ed3c0_preloop_value result0;
} rome2_100ed3c0_nonempty_step;

typedef void (*rome2_100ed3c0_nonempty_emit_step_fn)(
    void *context,
    rome2_100ed3c0_nonempty_step step);

/*
 * The three observer context sizes complete the otherwise pointer-only parent,
 * prefix, and suffix callback contracts.  Every declared callback context must
 * be disjoint from all controls and guest backings.  Context spans may be
 * exactly identical, which permits one recorder to capture the total order;
 * partially overlapping spans are rejected.  The two owned-effect descriptors
 * retain their independently declared context sizes and follow the same rule.
 */
typedef struct rome2_100ed3c0_nonempty_effects {
    rome2_100ed3c0_nonempty_emit_step_fn emit_step;
    void *context;
    uint64_t context_byte_count;
    rome2_100df270_prefix_effects child_prefix;
    uint64_t child_prefix_context_byte_count;
    rome2_100df270_suffix_effects child_suffix;
    uint64_t child_suffix_context_byte_count;
    rome2_100f1bb0_owned_effects temporary_owned;
    rome2_100f1bb0_owned_effects persistent_owned;
} rome2_100ed3c0_nonempty_effects;

/*
 * Compose the bounded nonempty route through original interval
 * [0x100ed3c0,0x100ed471).  The frame layout, two inert global identities,
 * sentinel triplets, empty packet copies, and hard stop are shared with the
 * independently frozen empty adapter.  text_max_units includes the terminator
 * and must be in [2,32768], with the first zero following 1..32767 opaque
 * UTF-16LE units.
 *
 * temporary_owner must begin canonical EMPTY.  On a successful temporary
 * allocation it becomes LIVE before the child begins and is consumed only at
 * the original 0x100ed46c cleanup position.  persistent_descriptor_view must
 * contain {0,0,0x11af4090} at 0x119f3aa0, persistent_owner must be EMPTY, and
 * lifecycle must already be REGISTERED_SENTINEL.  The delegated child suffix
 * binds its exact CALL_100F2750 position to the admitted first-use owned leaf.
 * Success leaves the persistent owner LIVE and lifecycle REGISTERED_LIVE;
 * persistent teardown remains outside this interval.
 *
 * All deterministic object, alignment, range, containment, alias, descriptor,
 * ownership, callback, and child-route checks complete on private scratch
 * before the first external observer or guest write.  The six guest views are
 * pairwise host/logically disjoint, every control is disjoint, and all views,
 * effects, identities, and entry ownership records are snapshotted.  External
 * callbacks are total, nonreentrant, return normally, retain no borrowed
 * object, and mutate only their declared context spans.
 *
 * After observation starts, writes and effects are an ordered committed
 * prefix.  A temporary allocation failure leaves both owners unchanged.  A
 * delegated persistent failure leaves temporary_owner LIVE for explicit
 * caller cleanup, emits no later suffix or parent steps, preserves the marker
 * cell and result_out, and performs no implicit rollback.  result_out is
 * committed only after successful temporary cleanup.  Owned status values are
 * propagated exactly.
 *
 * This adapter calls no original address, native allocator, CRT registration,
 * process global, platform API, guest-derived function pointer, or recovered
 * implementation, and performs no guest/native pointer cast.
 */
rome2_100f1bb0_owned_status rome2_port_100ed3c0_run_nonempty_preloop(
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
    const rome2_100ed3c0_nonempty_effects *effects,
    rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_100ed3c0_preloop_result *result_out);

#endif

#ifndef ROME2_PORTED_100F1BB0_OWNED_UTF16_H
#define ROME2_PORTED_100F1BB0_OWNED_UTF16_H

#include "ported_100f1c10_triplet.h"

#define ROME2_PORT_100F1BB0_OWNED_MAX_UNITS UINT32_C(32768)
#define ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS UINT32_C(0)
#define ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE UINT32_C(1)
#define ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED UINT32_C(2)

typedef enum rome2_100f1bb0_owned_status {
    ROME2_100F1BB0_OWNED_OK = ROME2_GUEST_OK,
    ROME2_100F1BB0_OWNED_BAD_ARGUMENT = ROME2_GUEST_BAD_ARGUMENT,
    ROME2_100F1BB0_OWNED_NULL_ADDRESS = ROME2_GUEST_NULL_ADDRESS,
    ROME2_100F1BB0_OWNED_RANGE_OVERFLOW = ROME2_GUEST_RANGE_OVERFLOW,
    ROME2_100F1BB0_OWNED_OUT_OF_RANGE = ROME2_GUEST_OUT_OF_RANGE,
    ROME2_100F1BB0_OWNED_ALLOCATION_DENIED = 5,
    ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID = 6,
    ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID = 7,
    ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID = 8,
    ROME2_100F1BB0_OWNED_ALREADY_CONSUMED = 9
} rome2_100f1bb0_owned_status;

typedef enum rome2_100f1bb0_owned_grant_result {
    ROME2_100F1BB0_OWNED_GRANT_DENIED = 0,
    ROME2_100F1BB0_OWNED_GRANT_GRANTED = 1
} rome2_100f1bb0_owned_grant_result;

/*
 * Private authority returned by the injected allocator.  raw_base remains a
 * guest32 identity.  token is host-side authority and is never written into
 * guest memory or exposed to an original-address transcript.
 */
typedef struct rome2_100f1bb0_owned_grant {
    uint64_t token;
    rome2_guest_addr32 raw_base;
    uint32_t reserved;
} rome2_100f1bb0_owned_grant;

/*
 * One-shot ownership record committed only after a complete valid build.
 * The caller keeps it outside every guest backing and passes the same record
 * to the owning cleanup.  Other than phase, cleanup preserves the record for
 * auditability.
 */
typedef struct rome2_100f1bb0_owned_owner {
    uint64_t token;
    rome2_guest_addr32 raw_base;
    rome2_guest_addr32 payload;
    uint32_t allocation_bytes;
    uint32_t length_units;
    uint32_t phase;
    uint32_t reserved;
} rome2_100f1bb0_owned_owner;

_Static_assert(sizeof(rome2_100f1bb0_owned_grant) == 16U,
    "the UTF-16 allocation grant must have a stable native layout");
_Static_assert(sizeof(rome2_100f1bb0_owned_owner) == 32U,
    "the UTF-16 ownership record must have a stable native layout");

/*
 * allocate receives a zeroed grant and may modify only that grant and the
 * declared context span.  A conforming denial leaves the grant zero.  Any
 * callback-written nonzero token is fresh one-shot release authority even if
 * paired with an inconsistent result discriminator; it must never be stale or
 * reused.  release consumes the exact tuple once, including compensation for
 * any rejected nonzero-token result or a grant whose guest mapping fails.
 * release_hook models the optional original global callback `(raw_base, 0)`
 * and is never used for compensation.
 *
 * Every callback is total, non-reentrant, returns normally, retains no
 * borrowed address, and does not inspect or mutate any guest/control/output
 * storage.  context and context_byte_count describe the complete mutable
 * callback state and must be disjoint from all other objects.
 */
typedef rome2_100f1bb0_owned_grant_result
    (*rome2_100f1bb0_owned_allocate_effect_fn)(
        void *context,
        uint32_t byte_count,
        uint32_t allocation_class,
        rome2_100f1bb0_owned_grant *grant_out);

typedef void (*rome2_100f1bb0_owned_release_effect_fn)(
    void *context,
    uint64_t token,
    rome2_guest_addr32 raw_base,
    uint32_t byte_count,
    uint32_t allocation_class);

typedef void (*rome2_100f1bb0_owned_release_hook_effect_fn)(
    void *context,
    rome2_guest_addr32 raw_base,
    uint32_t zero_argument);

typedef struct rome2_100f1bb0_owned_effects {
    rome2_100f1bb0_owned_allocate_effect_fn allocate;
    rome2_100f1bb0_owned_release_effect_fn release;
    rome2_100f1bb0_owned_release_hook_effect_fn release_hook;
    void *context;
    uint64_t context_byte_count;
} rome2_100f1bb0_owned_effects;

/*
 * Bounded nonempty route through original 0x100f1bb0 -> 0x100ef330.
 * max_units includes the terminator and must be in [2,32768]; the first zero
 * must follow 1..32767 opaque UTF-16LE units.  The descriptor, text, and heap
 * views model disjoint guest and native intervals; heap_view is a containing
 * arena, not a promise that its whole interval is one allocation.  The
 * injected allocator is asked for exactly length*2+10 bytes in class zero.
 * owner_out must begin as the canonical all-zero EMPTY record.  The
 * descriptor is unowned placement scratch and may contain arbitrary bytes.
 *
 * A denied allocation changes only callback context.  A malformed or
 * unmapped nonzero-token grant is consumed immediately by release, without
 * the optional hook.  Both cases preserve all guest bytes and outputs.  A
 * valid grant commits the hidden raw-base cell, exact payload, literal zero
 * terminator, descriptor `{length,length,payload}`, LIVE owner, and descriptor
 * return.  The original allocator and every original address remain inert.
 */
rome2_100f1bb0_owned_status rome2_port_100f1bb0_build_owned_utf16(
    const rome2_guest_write_view *descriptor_view,
    rome2_guest_addr32 guest_descriptor,
    const rome2_guest_read_view *text_view,
    rome2_guest_addr32 guest_text,
    uint32_t max_units,
    const rome2_guest_write_view *heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    rome2_100f1bb0_owned_owner *owner_out,
    rome2_guest_addr32 *guest_return_out);

/*
 * Owning route through original 0x100f1cc0.  The private LIVE owner is the
 * release authority; guest payload-4 is evidence, never authority.  Before
 * the first effect this verifies the exact descriptor, allocation formula,
 * payload alignment, hidden raw-base cell, mapped allocation, and terminator.
 * It marks the owner CONSUMED before relinquishing authority to release, then
 * invokes the optional `(raw,0)` hook.  Guest bytes are intentionally left
 * unchanged, matching the original dangling local.  A consumed owner cannot
 * run twice.
 */
rome2_100f1bb0_owned_status rome2_port_100f1cc0_cleanup_owned_utf16(
    const rome2_guest_write_view *descriptor_view,
    rome2_guest_addr32 guest_descriptor,
    const rome2_guest_write_view *heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    rome2_100f1bb0_owned_owner *owner);

#endif

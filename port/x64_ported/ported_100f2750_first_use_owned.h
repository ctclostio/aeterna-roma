#ifndef ROME2_PORTED_100F2750_FIRST_USE_OWNED_H
#define ROME2_PORTED_100F2750_FIRST_USE_OWNED_H

#include "ported_100f1bb0_owned_utf16.h"

#define ROME2_PORT_100F2750_FIRST_USE_DESTINATION UINT32_C(0x119f3aa0)
#define ROME2_PORT_100F2750_FIRST_USE_SENTINEL UINT32_C(0x11af4090)
#define ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_EMPTY UINT32_C(0)
#define ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_SENTINEL \
    UINT32_C(1)
#define ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_REGISTERED_LIVE \
    UINT32_C(2)
#define ROME2_PORT_100F2750_FIRST_USE_LIFECYCLE_CONSUMED UINT32_C(3)

/*
 * Pointer-free typed registration state kept outside every guest backing and
 * callback context.  The canonical all-zero representation is unregistered.
 * Only the APIs below may advance it through REGISTERED_SENTINEL,
 * REGISTERED_LIVE, and CONSUMED.
 */
typedef struct rome2_100f2750_first_use_lifecycle {
    uint32_t phase;
    uint32_t reserved;
} rome2_100f2750_first_use_lifecycle;

_Static_assert(sizeof(rome2_100f2750_first_use_lifecycle) == 8U,
    "the persistent first-use lifecycle must have a stable native layout");

/*
 * Establish typed host-owned teardown registration without calling a native
 * CRT or any original address.  The fixed descriptor must be the exact
 * sentinel, persistent_owner must be canonical EMPTY, and lifecycle_out must
 * be canonical all-zero.  Success changes only lifecycle_out to
 * REGISTERED_SENTINEL; every failure preserves all storage.
 */
rome2_100f1bb0_owned_status rome2_port_100f2750_register_first_use_owned(
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle_out);

/*
 * Authenticated first-use projection of original 0x100f2750.  The temporary
 * descriptor and its private LIVE owner remain borrowed and unchanged.  The
 * fixed persistent descriptor must begin as {0,0,0x11af4090}, while
 * persistent_owner_out must be the canonical all-zero EMPTY record and the
 * lifecycle must be REGISTERED_SENTINEL.
 *
 * The two heap views are separate nonoverlapping bounded guest32 subarenas;
 * callers may carve them from one larger containing arena.  Before the first
 * effect this function authenticates the temporary descriptor, exact LIVE
 * owner, allocation extent, hidden raw-base header, payload, and terminator;
 * validates the fixed persistent descriptor and EMPTY owner; and proves that
 * every control, backing, callback context, guest interval, and output is
 * disjoint.  It then requests exactly 2*N+10 bytes in allocation class zero,
 * writes the aligned owned copy, commits {N,N,payload}, commits the persistent
 * LIVE owner, and finally returns 0x119f3aa0.
 *
 * A malformed nonzero-token destination grant is compensating-released under
 * the established owned UTF-16 protocol.  The sole exception is a grant token
 * equal to the still-LIVE temporary token: that is a protocol error with no
 * release, because the colliding token may still authorize the source.
 */
rome2_100f1bb0_owned_status rome2_port_100f2750_first_use_owned(
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_guest_write_view *temporary_descriptor_view,
    rome2_guest_addr32 guest_temporary_descriptor,
    const rome2_guest_write_view *temporary_heap_view,
    const rome2_guest_write_view *persistent_heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    const rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner_out,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_guest_addr32 *guest_return_out);

/*
 * Explicit one-shot teardown for the fixed persistent descriptor.  A
 * REGISTERED_SENTINEL lifecycle with canonical EMPTY owner and exact sentinel
 * descriptor advances directly to CONSUMED without an effect.  For
 * REGISTERED_LIVE, this wrapper authenticates the complete cleanup contract,
 * advances the lifecycle to CONSUMED, and delegates to the established
 * 0x100f1cc0 owning cleanup, which consumes the owner before release and then
 * may emit the typed (raw,0) hook.  Guest bytes remain unchanged.  A repeated
 * teardown returns ALREADY_CONSUMED without another effect.
 */
rome2_100f1bb0_owned_status
rome2_port_100f2750_teardown_first_use_owned(
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_guest_write_view *persistent_heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle);

#endif

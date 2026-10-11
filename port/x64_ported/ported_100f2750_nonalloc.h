#ifndef ROME2_PORTED_100F2750_NONALLOC_H
#define ROME2_PORTED_100F2750_NONALLOC_H

#include "ported_100f1c10_triplet.h"

/*
 * Original 0x116bde50 takes its stateful/optimized routes at 32 bytes.
 * The copied width is 2 * (source_count + 1), so a terminator-inclusive
 * bound of 15 units keeps every admitted copy strictly below that boundary.
 */
#define ROME2_PORT_100F2750_MAX_UNITS UINT32_C(15)

/*
 * Port only the nonallocating branch of original 0x100f2750 for a short,
 * forward, disjoint payload copy.  Each descriptor is three little-endian
 * guest32 cells: {count, capacity/comparison value, payload identity}.
 * max_units is terminator-inclusive and must be in [1, 15]; source count must
 * be smaller than max_units and no larger than the destination comparison
 * value.  The copied bytes are exactly 2 * (source_count + 1), matching the
 * original call to 0x116bde50; the final unit is copied but not interpreted.
 *
 * Equal descriptor identities preserve the authenticated original no-op
 * after the count/capacity decisions.  Distinct descriptors and their two
 * payload spans must be pairwise disjoint and fully contained in the borrowed
 * writable guest32 view.  Allocation, release, callbacks, overlap handling,
 * and the helper's >=32-byte CPU-feature paths are rejected.  Every failure
 * preserves the view, all guest bytes, and guest_return_out byte-for-byte.
 */
rome2_guest_status rome2_port_100f2750_copy_nonallocating_short(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_destination_descriptor,
    rome2_guest_addr32 guest_source_descriptor,
    uint32_t max_units,
    rome2_guest_addr32 *guest_return_out);

#endif

#ifndef ROME2_PORTED_100E2460_APPEND_PREFIX_H
#define ROME2_PORTED_100E2460_APPEND_PREFIX_H

#include "ported_100f1c10_triplet.h"

#define ROME2_PORT_100E2460_VECTOR_BYTES UINT32_C(0x10)
#define ROME2_PORT_100E2460_ELEMENT_BYTES UINT32_C(4)

/*
 * Project only the allocation-free append prefix of original 0x100e2460.
 * The admitted branch requires count < capacity, where the vector cells at
 * guest_vector + {4, 8, 12} are {capacity, count, backing identity}.
 * The opaque 32-bit guest_element bits are written to backing[count], then
 * count is incremented.  A zero guest_element is representable and is not
 * dereferenced by this prefix.
 *
 * This is not a completed call to 0x100e2460.  The capacity-zero allocator,
 * growth/copy/free route, subsequent vtable-slot-4 dispatch, PeekMessageW
 * drain, and original return byte are excluded.  Every failure preserves the
 * borrowed view and every guest byte.  Success writes exactly two 32-bit
 * little-endian cells: the append slot first and the count cell second.
 */
rome2_guest_status rome2_port_100e2460_append_preallocated_prefix(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_element);

#endif

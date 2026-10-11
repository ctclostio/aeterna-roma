#ifndef ROME2_PORTED_100F1AA0_EMPTY_H
#define ROME2_PORTED_100F1AA0_EMPTY_H

#include "ported_100f1c10_triplet.h"

/*
 * Port only the empty-source path through original
 * 0x100f1aa0 -> 0x100ef330.  Both guest spans are exactly 12 bytes inside
 * one borrowed writable view and must not overlap.  A nonzero little-endian
 * count in the first source cell is outside this contract and is rejected.
 *
 * All validation finishes before the accepted 0x100f1c10 triplet writer is
 * called.  The entire view and guest_return_out remain unchanged on failure.
 */
rome2_guest_status rome2_port_100f1aa0_copy_empty_source(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_destination,
    rome2_guest_addr32 guest_source,
    rome2_guest_addr32 *guest_return_out);

#endif

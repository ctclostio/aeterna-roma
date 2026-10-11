#ifndef ROME2_PORTED_100F1C10_TRIPLET_H
#define ROME2_PORTED_100F1C10_TRIPLET_H

#include "guest32.h"

/* A borrowed, writable host interval addressed with guest32 coordinates. */
typedef struct rome2_guest_write_view {
    uint8_t *host_base;
    uint32_t guest_base;
    uint64_t byte_count;
} rome2_guest_write_view;

_Static_assert(sizeof(((rome2_guest_write_view *)0)->guest_base) == 4,
    "guest write-view bases must remain exactly 32 bits");

/*
 * Port only original leaf 0x100f1c10: write three little-endian guest cells
 * {0, 0, 0x11af4090} and return the unchanged guest destination.
 *
 * The host interval and guest_return_out are borrowed writable storage and
 * must not overlap.  Every validation failure preserves both byte-for-byte.
 */
rome2_guest_status rome2_port_100f1c10_initialize_triplet(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_destination,
    rome2_guest_addr32 *guest_return_out);

#endif

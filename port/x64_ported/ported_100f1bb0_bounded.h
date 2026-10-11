#ifndef ROME2_PORTED_100F1BB0_BOUNDED_H
#define ROME2_PORTED_100F1BB0_BOUNDED_H

#include "guest32.h"

/* Explicit native containment bound; the original x86 loop is unbounded. */
#define ROME2_PORT_100F1BB0_MAX_UNITS UINT32_C(32768)

/*
 * Port only the UTF-16LE terminator scan and length calculation at original
 * 0x100f1bc0-0x100f1bd1.  The allocator-capable copy beginning at 0x100f1bd2
 * is not called or modeled.  max_units includes the terminator slot.
 *
 * A terminator absent from the declared bound returns OUT_OF_RANGE.  Zero or
 * over-limit bounds return BAD_ARGUMENT.  *length_out is unchanged on every
 * failure and receives the number of nonzero units only on success.
 */
rome2_guest_status rome2_port_100f1bb0_measure_utf16(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 guest_text,
    uint32_t max_units,
    uint32_t *length_out);

#endif

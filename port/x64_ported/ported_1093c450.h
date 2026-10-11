#ifndef ROME2_PORTED_1093C450_H
#define ROME2_PORTED_1093C450_H

#include "guest32.h"

/* Port-layer behavior for original target 0x100e81a0: return guest this + 4. */
rome2_guest_status rome2_port_100e81a0_get_cstr(
    rome2_guest_addr32 stream,
    rome2_guest_addr32 *result_out);

/*
 * Port-layer behavior for original thunk 0x1093c450:
 * load the four-byte guest pointer at outer+0, then tail-forward to 100e81a0.
 */
rome2_guest_status rome2_port_1093c450_forward_get_cstr(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 outer,
    rome2_guest_addr32 *result_out);

#endif

#ifndef ROME2_PORTED_100DF270_HEADLESS_H
#define ROME2_PORTED_100DF270_HEADLESS_H

#include "ported_100f1c10_triplet.h"

/* Exact guest spans required by the authenticated deterministic projection. */
#define ROME2_PORT_100DF270_OBJECT_BYTES UINT32_C(0x8a8)
#define ROME2_PORT_100DF270_PACKET_BYTES UINT32_C(0x2d)

/*
 * Project only the deterministic field writes at original
 * 0x100df343-0x100df46c.  Both embedded sequence descriptors in the input
 * packet (at +0x08 and +0x14) must have zero counts.  The complete object and
 * packet spans must be disjoint and contained in one borrowed guest32 view.
 *
 * This is not a call or simulation of full 0x100df270.  In particular it does
 * not load resources, create a mutex, alter system parameters, publish a
 * global object, run initializers, allocate, terminate a process, or perform
 * indirect dispatch.  Bytes not written by the authenticated slice are left
 * unchanged.  Every failure preserves the view and guest_return_out.
 */
rome2_guest_status rome2_port_100df270_project_headless_empty_state(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_object,
    rome2_guest_addr32 guest_packet,
    rome2_guest_addr32 *guest_return_out);

#endif

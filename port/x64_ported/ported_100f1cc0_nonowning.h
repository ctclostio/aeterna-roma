#ifndef ROME2_PORTED_100F1CC0_NONOWNING_H
#define ROME2_PORTED_100F1CC0_NONOWNING_H

#include "guest32.h"

#define ROME2_PORT_100F1CC0_SENTINEL UINT32_C(0x11af4090)

/*
 * Admit only the two no-op branches at original 0x100f1cc4-0x100f1ccf.
 * Null and the fixed guest sentinel return OK without dereference or mutation.
 * Every other value belongs to the excluded owning/callback path and fails.
 */
rome2_guest_status rome2_port_100f1cc0_accept_nonowning_noop(
    rome2_guest_addr32 guest_storage);

#endif

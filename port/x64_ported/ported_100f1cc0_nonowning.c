#include "ported_100f1cc0_nonowning.h"

rome2_guest_status rome2_port_100f1cc0_accept_nonowning_noop(
    rome2_guest_addr32 guest_storage)
{
    if (guest_storage.value == 0 ||
        guest_storage.value == ROME2_PORT_100F1CC0_SENTINEL) {
        return ROME2_GUEST_OK;
    }
    return ROME2_GUEST_BAD_ARGUMENT;
}

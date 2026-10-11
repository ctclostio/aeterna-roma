#include "ported_100e85d0_normal_adapter.h"

rome2_guest_status rome2_port_100e85d0_normal_adapter(
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    uint8_t *return_al_out)
{
    if (return_al_out == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    /* The authenticated original handler does not inspect either identity. */
    (void)guest_receiver;
    (void)guest_argument;
    *return_al_out = ROME2_PORT_100E85D0_NORMAL_AL;
    return ROME2_GUEST_OK;
}

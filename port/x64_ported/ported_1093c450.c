#include "ported_1093c450.h"

rome2_guest_status rome2_port_100e81a0_get_cstr(
    rome2_guest_addr32 stream,
    rome2_guest_addr32 *result_out)
{
    return rome2_guest_add_checked(stream, UINT32_C(4), result_out);
}

rome2_guest_status rome2_port_1093c450_forward_get_cstr(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 outer,
    rome2_guest_addr32 *result_out)
{
    rome2_guest_addr32 stream;
    rome2_guest_status status;

    if (result_out == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    status = rome2_guest_read_addr32_le(view, outer, &stream);
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    return rome2_port_100e81a0_get_cstr(stream, result_out);
}

#include "ported_100f1bb0_bounded.h"

rome2_guest_status rome2_port_100f1bb0_measure_utf16(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 guest_text,
    uint32_t max_units,
    uint32_t *length_out)
{
    rome2_guest_addr32 cursor;
    rome2_guest_status status;
    uint16_t unit;
    uint32_t index;

    if (length_out == NULL || max_units == 0 ||
        max_units > ROME2_PORT_100F1BB0_MAX_UNITS) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    cursor = guest_text;
    for (index = 0; index < max_units; ++index) {
        status = rome2_guest_read_u16_le(view, cursor, &unit);
        if (status != ROME2_GUEST_OK) {
            return status;
        }
        if (unit == 0) {
            *length_out = index;
            return ROME2_GUEST_OK;
        }
        if (index + UINT32_C(1) < max_units) {
            status = rome2_guest_add_checked(cursor, UINT32_C(2), &cursor);
            if (status != ROME2_GUEST_OK) {
                return status;
            }
        }
    }
    return ROME2_GUEST_OUT_OF_RANGE;
}

#include "ported_100f1c10_triplet.h"

#include <limits.h>

#define ROME2_GUEST_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_STARTUP_TRIPLET_BYTES UINT64_C(12)

rome2_guest_status rome2_port_100f1c10_initialize_triplet(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_destination,
    rome2_guest_addr32 *guest_return_out)
{
    uint8_t *destination;
    uintptr_t host_address;
    uintptr_t output_address;
    uint64_t offset;

    if (view == NULL || guest_return_out == NULL || view->host_base == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (view->byte_count > ROME2_GUEST_ADDRESS_SPACE_SIZE ||
        (uint64_t)view->guest_base + view->byte_count >
            ROME2_GUEST_ADDRESS_SPACE_SIZE) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }

    host_address = (uintptr_t)view->host_base;
    if (view->byte_count != 0 &&
        view->byte_count - UINT64_C(1) >
            (uint64_t)(UINTPTR_MAX - host_address)) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    output_address = (uintptr_t)guest_return_out;
    if (sizeof(*guest_return_out) - 1 > UINTPTR_MAX - output_address) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }

    if (view->byte_count != 0 &&
        ((output_address >= host_address &&
          (uint64_t)(output_address - host_address) < view->byte_count) ||
         (host_address > output_address &&
          host_address - output_address < sizeof(*guest_return_out)))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (guest_destination.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (guest_destination.value < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    offset =
        (uint64_t)guest_destination.value - (uint64_t)view->guest_base;
    if (offset > view->byte_count ||
        ROME2_STARTUP_TRIPLET_BYTES > view->byte_count - offset ||
        offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    destination = view->host_base + (size_t)offset;
    destination[0] = 0;
    destination[1] = 0;
    destination[2] = 0;
    destination[3] = 0;
    destination[4] = 0;
    destination[5] = 0;
    destination[6] = 0;
    destination[7] = 0;
    destination[8] = UINT8_C(0x90);
    destination[9] = UINT8_C(0x40);
    destination[10] = UINT8_C(0xaf);
    destination[11] = UINT8_C(0x11);
    guest_return_out->value = guest_destination.value;
    return ROME2_GUEST_OK;
}

#include "ported_100f1aa0_empty.h"

#include <limits.h>

#define ROME2_GUEST_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_EMPTY_SEQUENCE_BYTES UINT64_C(12)

rome2_guest_status rome2_port_100f1aa0_copy_empty_source(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_destination,
    rome2_guest_addr32 guest_source,
    rome2_guest_addr32 *guest_return_out)
{
    const uint8_t *source_bytes;
    uintptr_t host_address;
    uintptr_t output_address;
    uintptr_t view_address;
    uint64_t destination_offset;
    uint64_t source_offset;
    uint32_t source_count;

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
    view_address = (uintptr_t)view;
    if (sizeof(*view) - 1 > UINTPTR_MAX - view_address) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }

    if (view->byte_count != 0 &&
        ((output_address >= host_address &&
          (uint64_t)(output_address - host_address) < view->byte_count) ||
         (host_address > output_address &&
          host_address - output_address < sizeof(*guest_return_out)))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if ((output_address >= view_address &&
         output_address - view_address < sizeof(*view)) ||
        (view_address > output_address &&
         view_address - output_address < sizeof(*guest_return_out))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (view->byte_count != 0 &&
        ((view_address >= host_address &&
          (uint64_t)(view_address - host_address) < view->byte_count) ||
         (host_address > view_address &&
          host_address - view_address < sizeof(*view)))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    if (guest_destination.value == 0 || guest_source.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (guest_destination.value < view->guest_base ||
        guest_source.value < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    destination_offset =
        (uint64_t)guest_destination.value - (uint64_t)view->guest_base;
    source_offset =
        (uint64_t)guest_source.value - (uint64_t)view->guest_base;
    if (destination_offset > view->byte_count ||
        ROME2_EMPTY_SEQUENCE_BYTES >
            view->byte_count - destination_offset ||
        destination_offset > (uint64_t)SIZE_MAX ||
        source_offset > view->byte_count ||
        ROME2_EMPTY_SEQUENCE_BYTES > view->byte_count - source_offset ||
        source_offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    if ((destination_offset >= source_offset &&
         destination_offset - source_offset < ROME2_EMPTY_SEQUENCE_BYTES) ||
        (source_offset > destination_offset &&
         source_offset - destination_offset < ROME2_EMPTY_SEQUENCE_BYTES)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    source_bytes = view->host_base + (size_t)source_offset;
    source_count =
        (uint32_t)source_bytes[0] |
        ((uint32_t)source_bytes[1] << 8) |
        ((uint32_t)source_bytes[2] << 16) |
        ((uint32_t)source_bytes[3] << 24);
    if (source_count != 0) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    return rome2_port_100f1c10_initialize_triplet(
        view, guest_destination, guest_return_out);
}

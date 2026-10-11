#include "ported_100f2750_nonalloc.h"

#include <limits.h>

#define ROME2_GUEST_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_PORT_100F2750_DESCRIPTOR_BYTES UINT64_C(12)

static uint32_t rome2_100f2750_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100f2750_write_u32_le(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static int rome2_100f2750_spans_overlap(
    uint64_t first_offset,
    uint64_t first_size,
    uint64_t second_offset,
    uint64_t second_size)
{
    if (first_offset >= second_offset) {
        return first_offset - second_offset < second_size;
    }
    return second_offset - first_offset < first_size;
}

rome2_guest_status rome2_port_100f2750_copy_nonallocating_short(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_destination_descriptor,
    rome2_guest_addr32 guest_source_descriptor,
    uint32_t max_units,
    rome2_guest_addr32 *guest_return_out)
{
    const uint8_t *source_descriptor;
    const uint8_t *source_payload;
    uint8_t *destination_descriptor;
    uint8_t *destination_payload;
    uintptr_t host_address;
    uintptr_t output_address;
    uintptr_t view_address;
    uint64_t copy_bytes;
    uint64_t destination_descriptor_offset;
    uint64_t destination_payload_offset;
    uint64_t source_descriptor_offset;
    uint64_t source_payload_offset;
    uint32_t destination_capacity;
    uint32_t destination_payload_guest;
    uint32_t source_count;
    uint32_t source_payload_guest;
    size_t index;

    if (view == NULL || guest_return_out == NULL || view->host_base == NULL ||
        max_units == 0 || max_units > ROME2_PORT_100F2750_MAX_UNITS) {
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

    if (guest_destination_descriptor.value == 0 ||
        guest_source_descriptor.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (guest_destination_descriptor.value < view->guest_base ||
        guest_source_descriptor.value < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    destination_descriptor_offset =
        (uint64_t)guest_destination_descriptor.value -
        (uint64_t)view->guest_base;
    source_descriptor_offset =
        (uint64_t)guest_source_descriptor.value -
        (uint64_t)view->guest_base;
    if (destination_descriptor_offset > view->byte_count ||
        ROME2_PORT_100F2750_DESCRIPTOR_BYTES >
            view->byte_count - destination_descriptor_offset ||
        destination_descriptor_offset > (uint64_t)SIZE_MAX ||
        source_descriptor_offset > view->byte_count ||
        ROME2_PORT_100F2750_DESCRIPTOR_BYTES >
            view->byte_count - source_descriptor_offset ||
        source_descriptor_offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    if (destination_descriptor_offset != source_descriptor_offset &&
        rome2_100f2750_spans_overlap(
            destination_descriptor_offset,
            ROME2_PORT_100F2750_DESCRIPTOR_BYTES,
            source_descriptor_offset,
            ROME2_PORT_100F2750_DESCRIPTOR_BYTES)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    destination_descriptor =
        view->host_base + (size_t)destination_descriptor_offset;
    source_descriptor =
        view->host_base + (size_t)source_descriptor_offset;
    source_count = rome2_100f2750_read_u32_le(source_descriptor);
    destination_capacity =
        rome2_100f2750_read_u32_le(destination_descriptor + 4);
    if (source_count >= max_units || destination_capacity < source_count) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    if (destination_descriptor_offset == source_descriptor_offset) {
        guest_return_out->value = guest_destination_descriptor.value;
        return ROME2_GUEST_OK;
    }

    destination_payload_guest =
        rome2_100f2750_read_u32_le(destination_descriptor + 8);
    source_payload_guest =
        rome2_100f2750_read_u32_le(source_descriptor + 8);
    if (destination_payload_guest == 0 || source_payload_guest == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (destination_payload_guest < view->guest_base ||
        source_payload_guest < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    copy_bytes = ((uint64_t)source_count + UINT64_C(1)) * UINT64_C(2);
    destination_payload_offset =
        (uint64_t)destination_payload_guest - (uint64_t)view->guest_base;
    source_payload_offset =
        (uint64_t)source_payload_guest - (uint64_t)view->guest_base;
    if (destination_payload_offset > view->byte_count ||
        copy_bytes > view->byte_count - destination_payload_offset ||
        destination_payload_offset > (uint64_t)SIZE_MAX ||
        source_payload_offset > view->byte_count ||
        copy_bytes > view->byte_count - source_payload_offset ||
        source_payload_offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    if (rome2_100f2750_spans_overlap(
            destination_payload_offset,
            copy_bytes,
            source_payload_offset,
            copy_bytes) ||
        rome2_100f2750_spans_overlap(
            destination_payload_offset,
            copy_bytes,
            destination_descriptor_offset,
            ROME2_PORT_100F2750_DESCRIPTOR_BYTES) ||
        rome2_100f2750_spans_overlap(
            destination_payload_offset,
            copy_bytes,
            source_descriptor_offset,
            ROME2_PORT_100F2750_DESCRIPTOR_BYTES) ||
        rome2_100f2750_spans_overlap(
            source_payload_offset,
            copy_bytes,
            destination_descriptor_offset,
            ROME2_PORT_100F2750_DESCRIPTOR_BYTES) ||
        rome2_100f2750_spans_overlap(
            source_payload_offset,
            copy_bytes,
            source_descriptor_offset,
            ROME2_PORT_100F2750_DESCRIPTOR_BYTES)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    destination_payload =
        view->host_base + (size_t)destination_payload_offset;
    source_payload = view->host_base + (size_t)source_payload_offset;
    for (index = 0; index < (size_t)copy_bytes; ++index) {
        destination_payload[index] = source_payload[index];
    }
    rome2_100f2750_write_u32_le(destination_descriptor, source_count);
    guest_return_out->value = guest_destination_descriptor.value;
    return ROME2_GUEST_OK;
}

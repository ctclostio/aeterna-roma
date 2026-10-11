#include "ported_100e2460_append_prefix.h"

#include <limits.h>

#define ROME2_GUEST_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)

static uint32_t rome2_100e2460_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_100e2460_write_u32_le(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static int rome2_100e2460_spans_overlap(
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

rome2_guest_status rome2_port_100e2460_append_preallocated_prefix(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_vector,
    rome2_guest_addr32 guest_element)
{
    uint8_t *append_cell;
    uint8_t *count_cell;
    const uint8_t *vector;
    uintptr_t host_address;
    uintptr_t view_address;
    uint64_t append_guest;
    uint64_t append_offset;
    uint64_t element_displacement;
    uint64_t vector_offset;
    uint32_t backing_guest;
    uint32_t capacity;
    uint32_t count;

    if (view == NULL || view->host_base == NULL) {
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
    view_address = (uintptr_t)view;
    if (sizeof(*view) - 1 > UINTPTR_MAX - view_address) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    if (view->byte_count != 0 &&
        ((view_address >= host_address &&
          (uint64_t)(view_address - host_address) < view->byte_count) ||
         (host_address > view_address &&
          host_address - view_address < sizeof(*view)))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    if (guest_vector.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (guest_vector.value >
        UINT32_MAX - (ROME2_PORT_100E2460_VECTOR_BYTES - UINT32_C(1))) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    if (guest_vector.value < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    vector_offset =
        (uint64_t)guest_vector.value - (uint64_t)view->guest_base;
    if (vector_offset > view->byte_count ||
        ROME2_PORT_100E2460_VECTOR_BYTES >
            view->byte_count - vector_offset ||
        vector_offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    vector = view->host_base + (size_t)vector_offset;
    capacity = rome2_100e2460_read_u32_le(vector + 4);
    count = rome2_100e2460_read_u32_le(vector + 8);
    backing_guest = rome2_100e2460_read_u32_le(vector + 12);

    if (count >= capacity) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (backing_guest == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (backing_guest < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    element_displacement = (uint64_t)count * UINT64_C(4);
    if (element_displacement > UINT32_MAX) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    append_guest = (uint64_t)backing_guest + element_displacement;
    if (append_guest > UINT32_MAX) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }

    append_offset = append_guest - (uint64_t)view->guest_base;
    if (append_offset > view->byte_count ||
        ROME2_PORT_100E2460_ELEMENT_BYTES >
            view->byte_count - append_offset ||
        append_offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    if (rome2_100e2460_spans_overlap(
            vector_offset,
            ROME2_PORT_100E2460_VECTOR_BYTES,
            append_offset,
            ROME2_PORT_100E2460_ELEMENT_BYTES)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    append_cell = view->host_base + (size_t)append_offset;
    count_cell = view->host_base + (size_t)vector_offset + 8;
    rome2_100e2460_write_u32_le(append_cell, guest_element.value);
    rome2_100e2460_write_u32_le(count_cell, count + UINT32_C(1));
    return ROME2_GUEST_OK;
}

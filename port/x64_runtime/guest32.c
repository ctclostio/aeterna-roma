#include "guest32.h"

#include <limits.h>

#define ROME2_GUEST_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)

static rome2_guest_status rome2_guest_read_offset(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 cell,
    size_t width,
    size_t *offset_out)
{
    uintptr_t host_address;
    uint64_t offset;

    if (view == NULL || offset_out == NULL || view->host_base == NULL) {
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
    if (cell.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (cell.value < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    offset = (uint64_t)cell.value - (uint64_t)view->guest_base;
    if (offset > view->byte_count ||
        (uint64_t)width > view->byte_count - offset ||
        offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    *offset_out = (size_t)offset;
    return ROME2_GUEST_OK;
}

rome2_guest_status rome2_guest_read_addr32_le(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 cell,
    rome2_guest_addr32 *value_out)
{
    const uint8_t *bytes;
    rome2_guest_addr32 value;
    rome2_guest_status status;
    size_t offset;

    if (view == NULL || value_out == NULL || view->host_base == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    status = rome2_guest_read_offset(view, cell, 4, &offset);
    if (status != ROME2_GUEST_OK) {
        return status;
    }

    bytes = view->host_base + offset;
    value.value =
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
    *value_out = value;
    return ROME2_GUEST_OK;
}

rome2_guest_status rome2_guest_read_u16_le(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 unit,
    uint16_t *value_out)
{
    const uint8_t *bytes;
    rome2_guest_status status;
    uint16_t value;
    size_t offset;

    if (view == NULL || value_out == NULL || view->host_base == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    status = rome2_guest_read_offset(view, unit, 2, &offset);
    if (status != ROME2_GUEST_OK) {
        return status;
    }

    bytes = view->host_base + offset;
    value = (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
    *value_out = value;
    return ROME2_GUEST_OK;
}

rome2_guest_status rome2_guest_add_checked(
    rome2_guest_addr32 address,
    uint32_t displacement,
    rome2_guest_addr32 *result_out)
{
    uint64_t result;
    rome2_guest_addr32 value;

    if (result_out == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (address.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }

    result = (uint64_t)address.value + (uint64_t)displacement;
    if (result > UINT32_MAX) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }

    value.value = (uint32_t)result;
    *result_out = value;
    return ROME2_GUEST_OK;
}

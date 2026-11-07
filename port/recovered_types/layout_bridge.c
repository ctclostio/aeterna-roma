#include "layout_bridge.h"

#include <limits.h>
#include <string.h>

static rome2_layout_status read_word(const rome2_guest_read_view *view,
    rome2_guest_addr32 base, uint32_t offset, uint32_t *out)
{
    rome2_guest_addr32 cell, value;
    if (rome2_guest_add_checked(base, offset, &cell) != ROME2_GUEST_OK
        || rome2_guest_read_addr32_le(view, cell, &value) != ROME2_GUEST_OK) {
        return ROME2_LAYOUT_RANGE_ERROR;
    }
    *out = value.value;
    return ROME2_LAYOUT_OK;
}

rome2_layout_status rome2_read_string8_layout32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 address,
    rome2_string8_layout32 *output)
{
    rome2_string8_layout32 result;
    uint32_t length, capacity;
    if (descriptors == NULL || output == NULL) {
        return ROME2_LAYOUT_BAD_ARGUMENT;
    }
    if (read_word(descriptors, address, 0, &length) != ROME2_LAYOUT_OK
        || read_word(descriptors, address, 4, &capacity) != ROME2_LAYOUT_OK
        || read_word(descriptors, address, 8, &result.data) != ROME2_LAYOUT_OK) {
        return ROME2_LAYOUT_RANGE_ERROR;
    }
    /* Reject unsupported signed representations before conversion. */
    if (length > (uint32_t)INT32_MAX || capacity > (uint32_t)INT32_MAX
        || length > capacity) {
        return ROME2_LAYOUT_INVALID_DESCRIPTOR;
    }
    result.length = (int32_t)length;
    result.capacity = (int32_t)capacity;
    *output = result;
    return ROME2_LAYOUT_OK;
}

static rome2_layout_status payload_span(const rome2_guest_read_view *view,
    uint32_t address, uint64_t size, const uint8_t **output)
{
    uint64_t delta;
    uintptr_t host;
    if (view == NULL || view->host_base == NULL || address == 0u) {
        return ROME2_LAYOUT_RANGE_ERROR;
    }
    if (view->byte_count > UINT64_C(0x100000000) - view->guest_base
        || view->byte_count > (uint64_t)SIZE_MAX
        || address < view->guest_base) {
        return ROME2_LAYOUT_RANGE_ERROR;
    }
    delta = (uint64_t)address - view->guest_base;
    if (delta > view->byte_count || size > view->byte_count - delta) {
        return ROME2_LAYOUT_RANGE_ERROR;
    }
    host = (uintptr_t)view->host_base;
    if (view->byte_count != 0u
        && view->byte_count - 1u > (uint64_t)(UINTPTR_MAX - host)) {
        return ROME2_LAYOUT_RANGE_ERROR;
    }
    *output = view->host_base + (size_t)delta;
    return ROME2_LAYOUT_OK;
}

static rome2_layout_status borrow_descriptor(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 address,
    const rome2_guest_read_view *payloads, uint32_t max_length, uint32_t width,
    const uint8_t **data, uint32_t *length)
{
    rome2_string8_layout32 descriptor;
    rome2_layout_status status;
    status = rome2_read_string8_layout32(descriptors, address, &descriptor);
    if (status != ROME2_LAYOUT_OK) {
        return status;
    }
    if ((uint32_t)descriptor.length > max_length) {
        return ROME2_LAYOUT_INVALID_DESCRIPTOR;
    }
    if (descriptor.length == 0) {
        *data = NULL;
        *length = 0;
        return ROME2_LAYOUT_OK;
    }
    status = payload_span(payloads, descriptor.data,
        (uint64_t)(uint32_t)descriptor.length * width, data);
    if (status == ROME2_LAYOUT_OK) {
        *length = (uint32_t)descriptor.length;
    }
    return status;
}

rome2_layout_status rome2_borrow_string8_layout32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 address,
    const rome2_guest_read_view *payloads, uint32_t max_length,
    rome2_borrowed_string8 *output)
{
    rome2_borrowed_string8 result;
    const uint8_t *data;
    rome2_layout_status status;
    if (output == NULL) {
        return ROME2_LAYOUT_BAD_ARGUMENT;
    }
    status = borrow_descriptor(descriptors, address, payloads, max_length, 1,
        &data, &result.length);
    if (status == ROME2_LAYOUT_OK) {
        result.data = (const char *)data;
        *output = result;
    }
    return status;
}

rome2_layout_status rome2_borrow_string16_layout32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 address,
    const rome2_guest_read_view *payloads, uint32_t max_units,
    rome2_borrowed_utf16le *output)
{
    rome2_borrowed_utf16le result;
    rome2_layout_status status;
    if (output == NULL) {
        return ROME2_LAYOUT_BAD_ARGUMENT;
    }
    status = borrow_descriptor(descriptors, address, payloads, max_units, 2,
        &result.bytes, &result.length_units);
    if (status == ROME2_LAYOUT_OK) {
        *output = result;
    }
    return status;
}

#include "ported_100e8240_fastpath.h"

#define ROME2_GUEST_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_PORT_100E8240_CELL_BYTES UINT64_C(4)
#define ROME2_PORT_100E8240_MAX_TLS_INDEX UINT32_C(0x3fffffff)

static uint32_t rome2_100e8240_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static int rome2_100e8240_spans_overlap(
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

static int rome2_100e8240_signed_le(uint32_t first, uint32_t second)
{
    return
        (first ^ UINT32_C(0x80000000)) <=
        (second ^ UINT32_C(0x80000000));
}

rome2_guest_status rome2_port_100e8240_crash_record_fastpath(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 guest_tls_vector,
    rome2_guest_addr32 guest_tls_index_cell,
    rome2_guest_addr32 guest_threshold_cell,
    rome2_guest_addr32 *guest_record_out)
{
    const uint8_t *index_bytes;
    const uint8_t *slot_bytes;
    const uint8_t *threshold_bytes;
    const uint8_t *tls_value_bytes;
    uintptr_t host_address;
    uintptr_t output_address;
    uintptr_t view_address;
    uint64_t index_offset;
    uint64_t slot_offset;
    uint64_t threshold_offset;
    uint64_t tls_value_offset;
    uint32_t slot_displacement;
    uint32_t slot_guest;
    uint32_t threshold;
    uint32_t tls_data;
    uint32_t tls_index;
    uint32_t tls_value;

    if (view == NULL || guest_record_out == NULL || view->host_base == NULL) {
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
    output_address = (uintptr_t)guest_record_out;
    if (sizeof(*guest_record_out) - 1 > UINTPTR_MAX - output_address) {
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
          host_address - output_address < sizeof(*guest_record_out)))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if ((output_address >= view_address &&
         output_address - view_address < sizeof(*view)) ||
        (view_address > output_address &&
         view_address - output_address < sizeof(*guest_record_out))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    if (view->byte_count != 0 &&
        ((view_address >= host_address &&
          (uint64_t)(view_address - host_address) < view->byte_count) ||
         (host_address > view_address &&
          host_address - view_address < sizeof(*view)))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    if (guest_tls_vector.value == 0 ||
        guest_tls_index_cell.value == 0 ||
        guest_threshold_cell.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (guest_tls_index_cell.value < view->guest_base ||
        guest_threshold_cell.value < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    index_offset =
        (uint64_t)guest_tls_index_cell.value - (uint64_t)view->guest_base;
    threshold_offset =
        (uint64_t)guest_threshold_cell.value - (uint64_t)view->guest_base;
    if (index_offset > view->byte_count ||
        ROME2_PORT_100E8240_CELL_BYTES > view->byte_count - index_offset ||
        index_offset > (uint64_t)SIZE_MAX ||
        threshold_offset > view->byte_count ||
        ROME2_PORT_100E8240_CELL_BYTES >
            view->byte_count - threshold_offset ||
        threshold_offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    if (rome2_100e8240_spans_overlap(
            index_offset,
            ROME2_PORT_100E8240_CELL_BYTES,
            threshold_offset,
            ROME2_PORT_100E8240_CELL_BYTES)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    index_bytes = view->host_base + (size_t)index_offset;
    threshold_bytes = view->host_base + (size_t)threshold_offset;
    tls_index = rome2_100e8240_read_u32_le(index_bytes);
    if (tls_index > ROME2_PORT_100E8240_MAX_TLS_INDEX) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }

    slot_displacement = tls_index * UINT32_C(4);
    if (guest_tls_vector.value > UINT32_MAX - slot_displacement) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    slot_guest = guest_tls_vector.value + slot_displacement;
    if (slot_guest < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    slot_offset = (uint64_t)slot_guest - (uint64_t)view->guest_base;
    if (slot_offset > view->byte_count ||
        ROME2_PORT_100E8240_CELL_BYTES > view->byte_count - slot_offset ||
        slot_offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    if (rome2_100e8240_spans_overlap(
            index_offset,
            ROME2_PORT_100E8240_CELL_BYTES,
            slot_offset,
            ROME2_PORT_100E8240_CELL_BYTES) ||
        rome2_100e8240_spans_overlap(
            threshold_offset,
            ROME2_PORT_100E8240_CELL_BYTES,
            slot_offset,
            ROME2_PORT_100E8240_CELL_BYTES)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    slot_bytes = view->host_base + (size_t)slot_offset;
    tls_data = rome2_100e8240_read_u32_le(slot_bytes);
    if (tls_data == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (tls_data < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    if (tls_data > UINT32_MAX - UINT32_C(4)) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    tls_value_offset =
        (uint64_t)tls_data + UINT64_C(4) - (uint64_t)view->guest_base;
    if (tls_value_offset > view->byte_count ||
        ROME2_PORT_100E8240_CELL_BYTES >
            view->byte_count - tls_value_offset ||
        tls_value_offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    if (rome2_100e8240_spans_overlap(
            index_offset,
            ROME2_PORT_100E8240_CELL_BYTES,
            tls_value_offset,
            ROME2_PORT_100E8240_CELL_BYTES) ||
        rome2_100e8240_spans_overlap(
            slot_offset,
            ROME2_PORT_100E8240_CELL_BYTES,
            tls_value_offset,
            ROME2_PORT_100E8240_CELL_BYTES) ||
        rome2_100e8240_spans_overlap(
            threshold_offset,
            ROME2_PORT_100E8240_CELL_BYTES,
            tls_value_offset,
            ROME2_PORT_100E8240_CELL_BYTES)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    threshold = rome2_100e8240_read_u32_le(threshold_bytes);
    tls_value_bytes = view->host_base + (size_t)tls_value_offset;
    tls_value = rome2_100e8240_read_u32_le(tls_value_bytes);
    if (rome2_100e8240_signed_le(threshold, tls_value)) {
        guest_record_out->value = ROME2_PORT_100E8240_CRASH_RECORD;
        return ROME2_GUEST_OK;
    }
    return ROME2_GUEST_BAD_ARGUMENT;
}

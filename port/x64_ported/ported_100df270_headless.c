#include "ported_100df270_headless.h"

#include <limits.h>

#define ROME2_GUEST_ADDRESS_SPACE_SIZE UINT64_C(0x100000000)
#define ROME2_PORT_100DF270_RUNTIME_VTABLE UINT32_C(0x1173f2f4)
#define ROME2_PORT_100DF270_SUBOBJECT_VTABLE UINT32_C(0x11741e08)
#define ROME2_PORT_100DF270_DISPATCH_VTABLE UINT32_C(0x1173dc18)
#define ROME2_PORT_100DF270_EMPTY_SENTINEL UINT32_C(0x11af4090)

static uint32_t rome2_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_write_u32_le(uint8_t *bytes, size_t offset, uint32_t value)
{
    bytes[offset] = (uint8_t)value;
    bytes[offset + 1] = (uint8_t)(value >> 8);
    bytes[offset + 2] = (uint8_t)(value >> 16);
    bytes[offset + 3] = (uint8_t)(value >> 24);
}

static void rome2_write_empty_sequence(uint8_t *bytes, size_t offset)
{
    rome2_write_u32_le(bytes, offset, 0);
    rome2_write_u32_le(bytes, offset + 4, 0);
    rome2_write_u32_le(
        bytes, offset + 8, ROME2_PORT_100DF270_EMPTY_SENTINEL);
}

rome2_guest_status rome2_port_100df270_project_headless_empty_state(
    const rome2_guest_write_view *view,
    rome2_guest_addr32 guest_object,
    rome2_guest_addr32 guest_packet,
    rome2_guest_addr32 *guest_return_out)
{
    const uint8_t *packet;
    uint8_t *object;
    uintptr_t host_address;
    uintptr_t output_address;
    uintptr_t view_address;
    uint64_t object_offset;
    uint64_t packet_offset;

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

    if (guest_object.value == 0 || guest_packet.value == 0) {
        return ROME2_GUEST_NULL_ADDRESS;
    }
    if (guest_object.value < view->guest_base ||
        guest_packet.value < view->guest_base) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }

    object_offset =
        (uint64_t)guest_object.value - (uint64_t)view->guest_base;
    packet_offset =
        (uint64_t)guest_packet.value - (uint64_t)view->guest_base;
    if (object_offset > view->byte_count ||
        ROME2_PORT_100DF270_OBJECT_BYTES >
            view->byte_count - object_offset ||
        object_offset > (uint64_t)SIZE_MAX ||
        packet_offset > view->byte_count ||
        ROME2_PORT_100DF270_PACKET_BYTES >
            view->byte_count - packet_offset ||
        packet_offset > (uint64_t)SIZE_MAX) {
        return ROME2_GUEST_OUT_OF_RANGE;
    }
    if ((object_offset >= packet_offset &&
         object_offset - packet_offset < ROME2_PORT_100DF270_PACKET_BYTES) ||
        (packet_offset > object_offset &&
         packet_offset - object_offset < ROME2_PORT_100DF270_OBJECT_BYTES)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    packet = view->host_base + (size_t)packet_offset;
    if (rome2_read_u32_le(packet + 0x08) != 0 ||
        rome2_read_u32_le(packet + 0x14) != 0) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    object = view->host_base + (size_t)object_offset;
    rome2_write_u32_le(object, 0x000, ROME2_PORT_100DF270_RUNTIME_VTABLE);
    rome2_write_u32_le(object, 0x80c, ROME2_PORT_100DF270_SUBOBJECT_VTABLE);
    rome2_write_u32_le(object, 0x810, 0);
    rome2_write_u32_le(object, 0x814, 0);
    rome2_write_u32_le(object, 0x81c, 0);
    rome2_write_u32_le(object, 0x820, 0);
    rome2_write_u32_le(object, 0x824, rome2_read_u32_le(packet + 0x00));
    rome2_write_u32_le(object, 0x828, rome2_read_u32_le(packet + 0x04));
    rome2_write_empty_sequence(object, 0x82c);
    rome2_write_empty_sequence(object, 0x838);
    rome2_write_u32_le(object, 0x844, rome2_read_u32_le(packet + 0x20));
    object[0x848] = packet[0x24];
    rome2_write_u32_le(object, 0x84c, rome2_read_u32_le(packet + 0x28));
    object[0x850] = packet[0x2c];
    rome2_write_u32_le(object, 0x854, guest_object.value);
    rome2_write_u32_le(object, 0x858, 0);
    rome2_write_u32_le(object, 0x85c, 0);
    rome2_write_u32_le(object, 0x860, 0);
    rome2_write_u32_le(object, 0x864, guest_object.value);
    rome2_write_u32_le(object, 0x868, 0);
    rome2_write_u32_le(object, 0x86c, 0);
    rome2_write_u32_le(object, 0x870, 0);
    rome2_write_u32_le(object, 0x874, ROME2_PORT_100DF270_DISPATCH_VTABLE);
    rome2_write_u32_le(object, 0x878, 0);
    rome2_write_u32_le(object, 0x87c, 0);
    rome2_write_u32_le(object, 0x880, 0);
    rome2_write_u32_le(object, 0x888, 0);
    rome2_write_u32_le(object, 0x88c, 0);
    rome2_write_u32_le(object, 0x894, 0);
    rome2_write_u32_le(object, 0x898, UINT32_MAX);
    rome2_write_u32_le(object, 0x89c, 0);
    rome2_write_u32_le(object, 0x8a0, 0);
    rome2_write_u32_le(object, 0x8a4, 0);

    guest_return_out->value = guest_object.value;
    return ROME2_GUEST_OK;
}

#include "layout_bridge.h"
#include "image_defaults.h"
#include "../../src/include/ghidra_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); \
    exit(1); } } while (0)

static void put32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

int main(void)
{
    const rome2_initial_global_snapshot initial = rome2_recovered_image_defaults();
    uint32_t float_bits;
    uint8_t descriptor_bytes[14] = {0};
    uint8_t payload[8] = {0x41, 0, 0x00, 0xd8, 0x42, 0, 0, 0};
    rome2_guest_read_view descriptors = {descriptor_bytes, 0x1000u, 14};
    rome2_guest_read_view payloads = {payload, 0x80000000u, 8};
    rome2_guest_addr32 descriptor = {0x1001u};
    rome2_string8_layout32 original = {0};
    rome2_borrowed_string8 narrow = {0}, before;
    rome2_borrowed_utf16le wide = {0};
    uint8_t *wire = descriptor_bytes + 1;

    CHECK(initial.narrow_terminator == 0 && initial.wide_empty_unit == 0);
    CHECK(initial.allocation_observer == 0);
    CHECK(initial.unit_colour_a == 0.0f && initial.entity_grid_max == 0.0f);
    memcpy(&float_bits, &initial.unit_grid_min, sizeof float_bits);
    CHECK(float_bits == UINT32_C(0xbf800000));

    /* Unaligned 12-byte guest layout; a host pointer would require 16 bytes. */
    put32(wire, 3); put32(wire + 4, 3); put32(wire + 8, 0x80000001u);
    CHECK(rome2_read_string8_layout32(&descriptors, descriptor, &original)
        == ROME2_LAYOUT_OK);
    CHECK(original.data == 0x80000001u && original.length == 3);
    CHECK(rome2_borrow_string8_layout32(&descriptors, descriptor, &payloads, 3,
        &narrow) == ROME2_LAYOUT_OK);
    CHECK(narrow.data == (const char *)(payload + 1) && narrow.length == 3);
    CHECK(narrow.data[0] == 0 && (unsigned char)narrow.data[2] == 0xd8);
    CHECK(rome2_borrow_string16_layout32(&descriptors, descriptor, &payloads,
        3, &wide) == ROME2_LAYOUT_OK);
    CHECK(wide.bytes == payload + 1 && wide.length_units == 3);

    before = narrow;
    put32(wire, 4); put32(wire + 4, 3);
    CHECK(rome2_borrow_string8_layout32(&descriptors, descriptor, &payloads, 4,
        &narrow) == ROME2_LAYOUT_INVALID_DESCRIPTOR);
    CHECK(narrow.data == before.data && narrow.length == before.length);
    put32(wire, UINT32_MAX); put32(wire + 4, UINT32_MAX);
    CHECK(rome2_read_string8_layout32(&descriptors, descriptor, &original)
        == ROME2_LAYOUT_INVALID_DESCRIPTOR);
    put32(wire, 3); put32(wire + 4, 3);
    CHECK(rome2_borrow_string8_layout32(&descriptors, descriptor, &payloads, 2,
        &narrow) == ROME2_LAYOUT_INVALID_DESCRIPTOR);
    put32(wire + 8, 0xfffffffdu);
    CHECK(rome2_borrow_string16_layout32(&descriptors, descriptor, &payloads,
        3, &wide) == ROME2_LAYOUT_RANGE_ERROR);
    CHECK(wide.bytes == payload + 1 && wide.length_units == 3);
    put32(wire + 8, 0);
    CHECK(rome2_borrow_string8_layout32(&descriptors, descriptor, &payloads,
        3, &narrow) == ROME2_LAYOUT_RANGE_ERROR);

    /* Empty descriptors need no readable mapping of an image sentinel. */
    put32(wire, 0); put32(wire + 4, 0); put32(wire + 8, 0x11af408eu);
    CHECK(rome2_borrow_string8_layout32(&descriptors, descriptor, NULL, 0,
        &narrow) == ROME2_LAYOUT_OK);
    CHECK(narrow.length == 0 && narrow.data == NULL);
    descriptors.byte_count = 12;
    CHECK(rome2_read_string8_layout32(&descriptors, descriptor, &original)
        == ROME2_LAYOUT_RANGE_ERROR);
    CHECK(rome2_borrow_string8_layout32(NULL, descriptor, NULL, 0, &narrow)
        == ROME2_LAYOUT_BAD_ARGUMENT);
    puts("layout bridge: guest widths, unaligned decoding, bounds and failure atomicity passed");
    return 0;
}

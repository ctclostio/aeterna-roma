#ifndef ROME2_RECOVERED_LAYOUT_BRIDGE_H
#define ROME2_RECOVERED_LAYOUT_BRIDGE_H

#include "guest32_layouts.h"
#include "../x64_runtime/guest32.h"

typedef enum rome2_layout_status {
    ROME2_LAYOUT_OK = 0,
    ROME2_LAYOUT_BAD_ARGUMENT,
    ROME2_LAYOUT_INVALID_DESCRIPTOR,
    ROME2_LAYOUT_RANGE_ERROR
} rome2_layout_status;

/* Host views borrow payload bytes; they never own them. A zero-length result
 * has NULL data and needs no sentinel mapping. UTF-16 remains LE bytes, since
 * guest payloads need not have host uint16_t alignment or byte order.
 */
typedef struct rome2_borrowed_string8 {
    const char *data;
    uint32_t length;
} rome2_borrowed_string8;

typedef struct rome2_borrowed_utf16le {
    const uint8_t *bytes;
    uint32_t length_units;
} rome2_borrowed_utf16le;

/* Views and destination objects must be valid non-overlapping host objects.
 * They remain borrowed and stable for this call. Failure preserves output.
 * This is a checked host adaptation, not an execution of an original routine.
 */
rome2_layout_status rome2_read_string8_layout32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 address,
    rome2_string8_layout32 *output);
rome2_layout_status rome2_borrow_string8_layout32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 address,
    const rome2_guest_read_view *payloads, uint32_t max_length,
    rome2_borrowed_string8 *output);
rome2_layout_status rome2_borrow_string16_layout32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 address,
    const rome2_guest_read_view *payloads, uint32_t max_units,
    rome2_borrowed_utf16le *output);

#endif

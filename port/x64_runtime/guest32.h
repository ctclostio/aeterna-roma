#ifndef ROME2_GUEST32_H
#define ROME2_GUEST32_H

#include <stddef.h>
#include <stdint.h>

/*
 * A guest address is an x86 value, not a native host pointer.  Keeping it in
 * a one-field structure prevents accidental pointer arithmetic and implicit
 * conversion at the x64 boundary.
 */
typedef struct rome2_guest_addr32 {
    uint32_t value;
} rome2_guest_addr32;

/* A borrowed, read-only host view of one contiguous guest-address interval. */
typedef struct rome2_guest_read_view {
    const uint8_t *host_base;
    uint32_t guest_base;
    uint64_t byte_count;
} rome2_guest_read_view;

typedef enum rome2_guest_status {
    ROME2_GUEST_OK = 0,
    ROME2_GUEST_BAD_ARGUMENT = 1,
    ROME2_GUEST_NULL_ADDRESS = 2,
    ROME2_GUEST_RANGE_OVERFLOW = 3,
    ROME2_GUEST_OUT_OF_RANGE = 4
} rome2_guest_status;

_Static_assert(sizeof(rome2_guest_addr32) == 4,
    "guest addresses must remain exactly 32 bits");
_Static_assert(sizeof(void *) == 8,
    "the guest32 runtime must be compiled for an x64 host");

/*
 * Read one unaligned little-endian guest-address cell.  The view denotes the
 * half-open interval [guest_base, guest_base + byte_count); an end exactly at
 * 2^32 is valid.  The output is unchanged on failure.  A zero value stored in
 * a valid cell is returned successfully because null is a representable guest
 * value; dereferencing or adding to it is a separate policy decision.
 */
rome2_guest_status rome2_guest_read_addr32_le(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 cell,
    rome2_guest_addr32 *value_out);

/*
 * Read one unaligned little-endian 16-bit guest unit.  Same view, numeric
 * host-range, null-address, status, and unchanged-output rules as
 * rome2_guest_read_addr32_le; the value is byte-assembled, so neither host
 * alignment nor endianness is assumed.
 */
rome2_guest_status rome2_guest_read_u16_le(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 unit,
    uint16_t *value_out);

/* Checked guest-address arithmetic.  Null and 32-bit overflow fail closed. */
rome2_guest_status rome2_guest_add_checked(
    rome2_guest_addr32 address,
    uint32_t displacement,
    rome2_guest_addr32 *result_out);

#endif

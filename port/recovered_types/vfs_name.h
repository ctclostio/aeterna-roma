#ifndef ROME2_RECOVERED_VFS_NAME_H
#define ROME2_RECOVERED_VFS_NAME_H

#include "layout_bridge.h"
#include <stdbool.h>

/* Bounded adaptation of FUN_100f3040. Until the first NUL or span end,
 * accumulate alternating signed bytes into independent 16-bit sums. Even
 * positions form the low half, odd positions the high half. No case folding,
 * path normalization, interning, allocation or global locale is involved.
 * NULL with size=0 hashes as empty; NULL with nonzero size or NULL output
 * fails without changing output. Valid non-overlapping host objects/backing
 * bytes remain borrowed and stable throughout the call. */
bool rome2_vfs_hash_name_bytes(const unsigned char *bytes, size_t size,
    uint32_t *output);

typedef enum rome2_vfs_name_status {
    ROME2_VFS_NAME_OK = 0,
    ROME2_VFS_NAME_NOT_FOUND,
    ROME2_VFS_NAME_BAD_ARGUMENT,
    ROME2_VFS_NAME_INVALID_TABLE,
    ROME2_VFS_NAME_RANGE_ERROR,
    ROME2_VFS_NAME_PROBE_LIMIT
} rome2_vfs_name_status;

typedef struct rome2_vfs_name_match32 {
    rome2_guest_addr32 value_address;
    rome2_data_address32 value;
    uint32_t slot_index;
    uint32_t probes;
} rome2_vfs_name_match32;

/* Checked adaptation of FUN_112c1130's probe order. The caller supplies a
 * precomputed hash and opaque name identity; this does not intern or normalize
 * names. Read descriptor items/count/empty identity, then probe 8-byte slots
 * from hash%count to the end and wrap once. Match precedes empty-key testing,
 * including when name==empty_name. A matched value can be NULL and is not a
 * proof of an available file, ownership, or a callable native interface.
 *
 * max_probes>0 bounds host work; exhaustion before a full scan is PROBE_LIMIT,
 * not NOT_FOUND. Zero buckets/items are INVALID_TABLE. Descriptor/array guest
 * numeric bounds and visited cell mappings are checked; the entire array need
 * not be mapped. Nonmatching/empty slots need only their key word; matched
 * slots also require the value word. Every non-OK result preserves output.
 * NULL views/output, zero descriptor address or zero budget are BAD_ARGUMENT.
 * All host objects/backing bytes remain valid, non-overlapping, borrowed and
 * immutable throughout the call. No allocation, callbacks, I/O, locking or
 * handle lifetime changes occur. No guest identity is a native pointer. */
rome2_vfs_name_status rome2_vfs_probe_name32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 descriptor,
    const rome2_guest_read_view *slots, uint32_t name, uint32_t hash,
    uint32_t max_probes, rome2_vfs_name_match32 *output);

#endif

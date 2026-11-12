#ifndef ROME2_RECOVERED_VFS_NAME_ASSIGN_H
#define ROME2_RECOVERED_VFS_NAME_ASSIGN_H

#include "vfs_name.h"

/* Borrowed writable bytes covering one contiguous guest interval. This is
 * specific to name-table assignment; it does not permit executing guest code
 * or treating an identity as a native pointer. */
typedef struct rome2_vfs_name_write_view32 {
    unsigned char *host_base;
    uint32_t guest_base;
    uint64_t byte_count;
} rome2_vfs_name_write_view32;

typedef struct rome2_vfs_name_assignment32 {
    rome2_guest_addr32 value_address;
    uint32_t slot_index;
    uint32_t probes;
    bool matched_key;
} rome2_vfs_name_assignment32;

/* Fixed-capacity adaptation of FUN_112ddee0's assignment loop. Descriptor and
 * slot layout, supplied hash/name compatibility, numeric extent validation,
 * visited-cell mapping and probe order follow rome2_vfs_probe_name32.
 * The first equal key wins over the empty marker at the same slot: replace
 * only its value. At the first unequal empty marker, write the name and value.
 * Other cells and the descriptor are preserved. New values, including zero,
 * are opaque 32-bit words; no old-value release or new-value retain is done.
 *
 * matched_key reports equality, not live occupancy: name==empty_name is
 * supported and may update an empty-marked slot's stale value. Callers that
 * need a live entry must reserve the descriptor's empty-name identity.
 *
 * Only the visited keys and selected slot's value must be mapped. Preflight
 * completes before the first write; every non-OK result preserves all backing
 * bytes and output. A complete scan with no equal/empty key is TABLE_FULL;
 * stopping earlier is PROBE_LIMIT. The original grows to 2*count+1 and rehashes
 * on a full scan; this API performs no growth, allocation or callbacks.
 * NULL views/output, zero descriptor or budget are BAD_ARGUMENT; invalid
 * items/count and guest/host mapping bounds use the probe API's statuses.
 *
 * All host objects/backings must be valid, mutually non-overlapping and stable
 * for the call, with exclusive access to slot bytes. This is not an atomic
 * concurrent operation. No interning, normalization, file I/O, mount priority,
 * manager locking, ownership or original exception behavior is established. */
rome2_vfs_name_status rome2_vfs_assign_name32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 descriptor,
    const rome2_vfs_name_write_view32 *slots, uint32_t name, uint32_t hash,
    rome2_data_address32 value, uint32_t max_probes,
    rome2_vfs_name_assignment32 *output);

#endif

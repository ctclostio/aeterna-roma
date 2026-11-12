#ifndef ROME2_RECOVERED_VFS_ARCHIVE_TREE_H
#define ROME2_RECOVERED_VFS_ARCHIVE_TREE_H

#include "vfs_name.h"

typedef enum rome2_vfs_tree_status {
    ROME2_VFS_TREE_OK = 0,
    ROME2_VFS_TREE_NOT_FOUND,
    ROME2_VFS_TREE_BAD_ARGUMENT,
    ROME2_VFS_TREE_INVALID_TREE,
    ROME2_VFS_TREE_RANGE_ERROR,
    ROME2_VFS_TREE_STEP_LIMIT
} rome2_vfs_tree_status;

typedef struct rome2_vfs_archive_tree_match32 {
    rome2_guest_addr32 node_address;
    uint32_t key_name;
    rome2_data_address32 candidate_set;
    rome2_data_address32 winner_node;
    rome2_data_address32 archive;
    rome2_guest_addr32 archive_table;
    uint32_t steps;
} rome2_vfs_archive_tree_match32;

/* Checked adaptation of FUN_101206f0 -> FUN_100f2fe0 -> FUN_100f7040.
 * Zero left-hand identity returns true immediately (even when rhs_name==0);
 * nonzero left-hand with zero right-hand returns false immediately; neither
 * case reads descriptor or payload bytes. When both identities are nonzero,
 * read only +0 (length) and +8 (data) of each narrow string descriptor (+4
 * capacity is untouched), compare min(len_lhs, len_rhs) bytes as signed 8-bit
 * values, and tie-break by unsigned length (len_lhs < len_rhs) when all shared
 * prefix bytes match. When min(len_lhs, len_rhs)==0, no payload byte is read.
 *
 * If min(len_lhs, len_rhs) exceeds max_bytes, return STEP_LIMIT. NULL views or
 * output return BAD_ARGUMENT; unmapped descriptor words or shared-prefix
 * payload bytes return RANGE_ERROR. Every non-OK result preserves output. */
rome2_vfs_tree_status rome2_vfs_compare_name_less32(
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    uint32_t lhs_name, uint32_t rhs_name,
    uint32_t max_bytes, bool *is_less);

/* Checked adaptation of FUN_112c0250's archive-name red-black tree lookup and
 * FUN_112ce0c0's winning-archive table resolution (0x112ce0f2..0x112ce105).
 * Read sentinel head at header+0, require head's is_nil flag at +0xd to be
 * nonzero, and traverse from root=[head+4] while node+0xd==0 up to max_steps:
 * step right ([node+8]) when compare(node.key, query_name) is true, otherwise
 * record candidate=node and step left ([node+0]). After reaching a nil node,
 * require candidate!=head and !compare(query_name, candidate.key). Because
 * compare(0, rhs) is always true, query_name==0 never matches any tree node.
 *
 * When resolve_archive_table is true, also follow candidate_set=[candidate+0x14],
 * set_head=[candidate_set+4], winner_node=[set_head+0], archive=[winner_node+0x10],
 * and archive_table=archive+4, requiring set_head to be nil-marked and
 * winner_node to be a non-nil node distinct from set_head with nonzero archive.
 * When resolve_archive_table is false, candidate_sets and candidate_nodes may
 * be NULL and winner_node/archive/archive_table are zeroed in output.
 *
 * NULL required views/output, zero header address or zero max_steps return
 * BAD_ARGUMENT. Zero head/node pointers, a non-nil head, or a nil-unmarked loop
 * back to head return INVALID_TREE. Exhausting max_steps before a nil node or
 * exceeding max_name_bytes during string comparison returns STEP_LIMIT. Every
 * non-OK result preserves output. All views remain borrowed and immutable. */
rome2_vfs_tree_status rome2_vfs_search_archive_tree32(
    const rome2_guest_read_view *headers, rome2_guest_addr32 header,
    const rome2_guest_read_view *tree_nodes,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    const rome2_guest_read_view *candidate_sets,
    const rome2_guest_read_view *candidate_nodes,
    uint32_t query_name, uint32_t max_steps, uint32_t max_name_bytes,
    bool resolve_archive_table, rome2_vfs_archive_tree_match32 *output);

#endif

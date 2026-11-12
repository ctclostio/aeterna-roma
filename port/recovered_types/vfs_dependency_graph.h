#ifndef ROME2_RECOVERED_VFS_DEPENDENCY_GRAPH_H
#define ROME2_RECOVERED_VFS_DEPENDENCY_GRAPH_H

#include "vfs_name.h"

#define ROME2_VFS_DEP_MAX_DEPTH_CAP 64u

typedef enum rome2_vfs_dep_status {
    ROME2_VFS_DEP_OK = 0,
    ROME2_VFS_DEP_NOT_FOUND,
    ROME2_VFS_DEP_BAD_ARGUMENT,
    ROME2_VFS_DEP_INVALID_GRAPH,
    ROME2_VFS_DEP_RANGE_ERROR,
    ROME2_VFS_DEP_STEP_LIMIT
} rome2_vfs_dep_status;

typedef struct rome2_vfs_dep_limits {
    uint32_t max_chain_steps;
    uint32_t max_tree_steps;
    uint32_t max_depth;
    uint32_t max_visits;
    uint32_t max_name_bytes;
} rome2_vfs_dep_limits;

typedef struct rome2_vfs_dep_hashmap_match32 {
    rome2_data_address32 node;
    rome2_data_address32 list_head;
    uint32_t bucket_index;
    uint32_t chain_steps;
} rome2_vfs_dep_hashmap_match32;

/* Checked adaptation of FUN_100f28a0 (`string8` equality).
 * Read only +0 (length) and +8 (data) of each 12-byte string8 descriptor (+4
 * capacity is untouched). Unequal lengths return false immediately without
 * dereferencing either data pointer; equal zero lengths return true immediately
 * without dereferencing either data pointer. Equal nonzero lengths above
 * max_bytes return STEP_LIMIT; otherwise both payload spans must be mapped
 * and are compared byte-for-byte. Every non-OK result preserves output. */
rome2_vfs_dep_status rome2_vfs_string8_equals32(
    const rome2_guest_read_view *lhs_descriptors, rome2_guest_addr32 lhs,
    const rome2_guest_read_view *rhs_descriptors, rome2_guest_addr32 rhs,
    const rome2_guest_read_view *payloads, uint32_t max_bytes, bool *is_equal);

/* Checked adaptation of FUN_112afff0 (`std::unordered_map::find` over
 * string8 keys via FUN_10101a40 -> FUN_100f3040 and FUN_100f28a0).
 * Read the NUL-terminated C-string pointer at [query_str + 8] up to
 * max_name_bytes (failing with STEP_LIMIT if non-NUL exceeds max_name_bytes),
 * compute rome2_vfs_hash_name_bytes, select bucket = (hash & mask) * 8 at
 * [map + 0x0c], and test [first .. last] against [map + 0x04] (list_head),
 * stopping cleanly after checking bucket.last. Every non-OK result (including
 * NOT_FOUND) preserves output. */
rome2_vfs_dep_status rome2_vfs_dep_hashmap_find32(
    const rome2_guest_read_view *maps, rome2_guest_addr32 map_addr,
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *buckets,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 query_str, uint32_t max_chain_steps,
    uint32_t max_name_bytes, rome2_vfs_dep_hashmap_match32 *output);

/* Checked adaptation of FUN_112ac2d0 (`_Tree_unchecked_const_iterator::operator++`)
 * over 28-byte dependency edge RB-tree nodes (+0 left, +4 parent, +8 right,
 * +0x0d is_nil). Bounded by max_tree_steps against cyclic links. Every non-OK
 * result preserves output. */
rome2_vfs_dep_status rome2_vfs_dep_edge_next32(
    const rome2_guest_read_view *edge_nodes, rome2_guest_addr32 current,
    uint32_t max_tree_steps, rome2_guest_addr32 *next_node,
    uint32_t *steps_used);

/* Checked adaptation of FUN_112d59f0 -> FUN_112b5090 (DFS dependency reachability
 * testing whether target_str is reachable from source_str through source's
 * +0x1c dependency RB-tree and map at graph + 0x18). Identical keys or either
 * key missing from the map return OK with *is_reachable=false. Unlike the
 * original binary, cycles and oversize graphs fail closed with STEP_LIMIT once
 * limits (max_chain_steps, max_tree_steps, max_depth <= 64, max_visits,
 * max_name_bytes) are exceeded. Every non-OK result preserves output. */
rome2_vfs_dep_status rome2_vfs_dep_reachable32(
    const rome2_guest_read_view *maps, rome2_guest_addr32 hashmap_addr,
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *buckets,
    const rome2_guest_read_view *edge_nodes,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 source_str, rome2_guest_addr32 target_str,
    const rome2_vfs_dep_limits *limits, bool *is_reachable);

/* Checked adaptation of FUN_112e1500 (`candidate_a < candidate_b` comparator
 * registered in candidate sets). Returns true when candidate_b depends on
 * candidate_a (`reachable(b+0x14, a+0x14)`), false when candidate_a depends on
 * candidate_b (`reachable(a+0x14, b+0x14)`), and otherwise compares low-nibble
 * priority `((*(*a))[0x1c] & 0xf) > ((*(*b))[0x1c] & 0xf)`. Pack properties
 * are read lazily only when neither candidate depends on the other. Every
 * non-OK result preserves output. */
rome2_vfs_dep_status rome2_vfs_compare_archive_candidates32(
    const rome2_guest_read_view *maps, rome2_guest_addr32 hashmap_addr,
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *buckets,
    const rome2_guest_read_view *edge_nodes,
    const rome2_guest_read_view *candidates,
    const rome2_guest_read_view *pack_props,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 candidate_a, rome2_guest_addr32 candidate_b,
    const rome2_vfs_dep_limits *limits, bool *lhs_less_than_rhs);

#endif

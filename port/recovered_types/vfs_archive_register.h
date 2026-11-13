#ifndef ROME2_RECOVERED_VFS_ARCHIVE_REGISTER_H
#define ROME2_RECOVERED_VFS_ARCHIVE_REGISTER_H

#include "vfs_dependency_graph.h"

typedef enum rome2_vfs_reg_status {
    ROME2_VFS_REG_OK = 0,
    ROME2_VFS_REG_NOT_FOUND,
    ROME2_VFS_REG_BAD_ARGUMENT,
    ROME2_VFS_REG_INVALID_STATE,
    ROME2_VFS_REG_RANGE_ERROR,
    ROME2_VFS_REG_STEP_LIMIT
} rome2_vfs_reg_status;

typedef enum rome2_vfs_reg_precondition_code {
    ROME2_VFS_REG_ELIGIBLE = 0,
    ROME2_VFS_REG_ALREADY_REGISTERED = 1,
    ROME2_VFS_REG_BLACKLISTED = 2,
    ROME2_VFS_REG_PACK_NOT_OPEN = 3,
    ROME2_VFS_REG_NEW_CANDIDATE_REJECTED = 8
} rome2_vfs_reg_precondition_code;

typedef struct rome2_vfs_open_pack_match32 {
    rome2_guest_addr32 slot_address;
    rome2_guest_addr32 payload_address;
    uint32_t slot_index;
    uint32_t probes;
} rome2_vfs_open_pack_match32;

typedef struct rome2_vfs_reg_precondition_result32 {
    rome2_vfs_reg_precondition_code code;
    rome2_guest_addr32 open_pack_payload;
    rome2_data_address32 registered_archive;
} rome2_vfs_reg_precondition_result32;

typedef struct rome2_vfs_candidate_probe_result32 {
    rome2_vfs_reg_precondition_code code;
    bool would_insert;
    bool becomes_winner;
    bool insert_left;
    rome2_guest_addr32 parent_node;
    rome2_guest_addr32 existing_node;
    rome2_data_address32 existing_archive;
    rome2_guest_addr32 displaced_winner_node;
    rome2_data_address32 displaced_winner_archive;
} rome2_vfs_candidate_probe_result32;

/* Checked adaptation of FUN_112c13f0 over 0x120329e0's open-pack hash table
 * (20-byte slots of {string8 name, 8-byte payload}). Hashes [query_str+8] via
 * rome2_vfs_hash_name_bytes, starts at hash % bucket_count, and linear-probes
 * with single wraparound. At each slot, match precedes empty_key comparison.
 * Matches return OK with payload_address = slot_address + 0x0c; empty_key stops
 * probing and returns NOT_FOUND. Every non-OK result preserves output. */
rome2_vfs_reg_status rome2_vfs_open_pack_find32(
    const rome2_guest_read_view *tables, rome2_guest_addr32 table_addr,
    const rome2_guest_read_view *slots,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 query_str, uint32_t max_probes,
    uint32_t max_name_bytes, rome2_vfs_open_pack_match32 *output);

/* Checked adaptation of FUN_112a4c00 over the archive blacklist RB-tree head
 * ([0x12032a40 + 0x10]). Traverses from head->left to head via
 * rome2_vfs_dep_edge_next32, comparing each node's +0x10 string8 against
 * query_str via rome2_vfs_string8_equals32. Every non-OK result preserves
 * output. */
rome2_vfs_reg_status rome2_vfs_blacklist_contains32(
    const rome2_guest_read_view *edge_nodes, rome2_guest_addr32 blacklist_head,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 query_str, uint32_t max_tree_steps,
    uint32_t max_name_bytes, bool *is_blacklisted);

/* Checked adaptation of FUN_112cfc10's ordered registration precondition gates:
 * (1) probe archive_name_id/hash in registered-archive hash table 0x12032a1c
 *     via rome2_vfs_probe_name32 -> ROME2_VFS_REG_ALREADY_REGISTERED (1);
 * (2) scan blacklist tree 0x12032a40+0x10 -> ROME2_VFS_REG_BLACKLISTED (2);
 * (3) lookup archive_string8 in open-pack table 0x120329e0 ->
 *     ROME2_VFS_REG_PACK_NOT_OPEN (3) on miss, or ROME2_VFS_REG_ELIGIBLE (0)
 *     with open_pack_payload on hit.
 * Every non-OK status preserves output. */
rome2_vfs_reg_status rome2_vfs_check_registration_preconditions32(
    const rome2_guest_read_view *reg_tables, rome2_guest_addr32 reg_table_addr,
    const rome2_guest_read_view *reg_slots,
    const rome2_guest_read_view *blacklist_nodes,
    rome2_guest_addr32 blacklist_head,
    const rome2_guest_read_view *open_tables, rome2_guest_addr32 open_table_addr,
    const rome2_guest_read_view *open_slots,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    uint32_t archive_name_id, uint32_t archive_name_hash,
    rome2_guest_addr32 archive_string8,
    uint32_t max_probes, uint32_t max_tree_steps, uint32_t max_name_bytes,
    rome2_vfs_reg_precondition_result32 *output);

/* Checked adaptation of FUN_112cfc10's candidate-set unique-key probe and
 * leftmost winner displacement check (FUN_112a30b0 + FUN_112e1500 + param_2).
 * Evaluates where new_candidate would land in candidate_set_addr without
 * mutating guest memory. When would_insert && only_update_existing (param_2),
 * sets code = ROME2_VFS_REG_NEW_CANDIDATE_REJECTED (8); otherwise code = 0.
 * When would_insert && parent_node == head->left, becomes_winner is true and
 * any prior leftmost node/archive is recorded as displaced_winner_*.
 * Every non-OK result preserves output. */
rome2_vfs_reg_status rome2_vfs_probe_candidate_insert32(
    const rome2_guest_read_view *candidate_sets,
    rome2_guest_addr32 candidate_set_addr,
    const rome2_guest_read_view *candidate_nodes,
    const rome2_guest_read_view *maps, rome2_guest_addr32 hashmap_addr,
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *buckets,
    const rome2_guest_read_view *edge_nodes,
    const rome2_guest_read_view *candidates,
    const rome2_guest_read_view *pack_props,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 new_candidate, bool only_update_existing,
    const rome2_vfs_dep_limits *limits,
    rome2_vfs_candidate_probe_result32 *output);

#endif

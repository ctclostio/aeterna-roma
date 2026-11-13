#ifndef ROME2_RECOVERED_VFS_ARCHIVE_MOUNT_STEP_H
#define ROME2_RECOVERED_VFS_ARCHIVE_MOUNT_STEP_H

#include <stddef.h>
#include "vfs_archive_register.h"

typedef struct rome2_vfs_pack_props_gate32 {
    rome2_data_address32 pack_props_addr;
    uint8_t low_nibble_01c;
    bool is_type3;
    bool is_type4;
} rome2_vfs_pack_props_gate32;

typedef struct rome2_vfs_carrier_slot_match32 {
    rome2_guest_addr32 slot_address;
    uint32_t slot_index;
    uint32_t name_id;
    rome2_data_address32 entry_ptr;
} rome2_vfs_carrier_slot_match32;

/* Checked adaptation of FUN_112a9560's archive leaf-name extraction
 * (FUN_101141f0 backward search for '\\' at 0x1173dfac + FUN_101155a0).
 * If '\\' appears in path[0..path_len), selects [pos + 1 .. path_len);
 * otherwise selects [0 .. path_len). Preserves outputs on non-OK status. */
rome2_vfs_reg_status rome2_vfs_archive_leaf_name(
    const char *path, size_t path_len, uint32_t max_bytes,
    size_t *out_offset, size_t *out_length);

/* Checked adaptation of FUN_112cfc10's directory-prefix normalization
 * (FUN_101141f0 backward search for '\\' + FUN_10113c10 resize).
 * If '\\' appears at pos, sets *out_has_dir = true and *out_prefix_length = pos;
 * otherwise sets *out_has_dir = false and *out_prefix_length = 0 (signaling
 * fallback to global sentinel 0x12032960). Preserves outputs on non-OK. */
rome2_vfs_reg_status rome2_vfs_entry_dir_prefix(
    const char *entry_path, size_t path_len, uint32_t max_bytes,
    size_t *out_prefix_length, bool *out_has_dir);

/* Checked adaptation of FUN_112cfc10 (0x112cfe83..0x112cfe8d) and
 * FUN_112a9560 (0x112a9b22..0x112a9b2c) reading *carrier->pack_props+0x1c & 0xf.
 * Every non-OK result preserves output. */
rome2_vfs_reg_status rome2_vfs_carrier_pack_props_gate32(
    const rome2_guest_read_view *candidates, rome2_guest_addr32 carrier_addr,
    const rome2_guest_read_view *pack_props,
    rome2_vfs_pack_props_gate32 *output);

/* Checked adaptation of FUN_112c0bb0 + FUN_101206e0 over an archive carrier's
 * +0x04 VFS name table (8-byte {uint32_t name, uint32_t entry_ptr} slots).
 * Scans slot indices [start_index .. bucket_count) bounded by max_slots,
 * skipping slots whose name matches name_table.empty_name via 0x101206e0.
 * Returns NOT_FOUND when no non-empty slot remains; non-OK preserves output. */
rome2_vfs_reg_status rome2_vfs_carrier_next_nonempty_slot32(
    const rome2_guest_read_view *candidates, rome2_guest_addr32 carrier_addr,
    const rome2_guest_read_view *slots,
    uint32_t start_index, uint32_t max_slots,
    rome2_vfs_carrier_slot_match32 *output);

/* Checked adaptation of FUN_112cfc10's recursive-dependency scan
 * (0x112cfcb9..0x112cfe28): walks open-pack table 0x120329e0 in FUN_112c0b20
 * slot order, skips empty_key slots via FUN_100f28a0, and collects open packs
 * reachable from pack_string8 in the transitive dependency graph (`descriptors`
 * covers both open-pack slots and pack_string8). Uses two passes so any non-OK
 * status (including buffer overflow -> RANGE_ERROR) preserves out_deps and
 * *out_count completely. */
rome2_vfs_reg_status rome2_vfs_collect_pending_deps32(
    const rome2_guest_read_view *maps, rome2_guest_addr32 hashmap_addr,
    const rome2_guest_read_view *nodes,
    const rome2_guest_read_view *buckets,
    const rome2_guest_read_view *edge_nodes,
    const rome2_guest_read_view *open_tables,
    rome2_guest_addr32 open_table_addr,
    const rome2_guest_read_view *descriptors,
    const rome2_guest_read_view *payloads,
    rome2_guest_addr32 pack_string8,
    const rome2_vfs_dep_limits *limits,
    uint32_t max_open_buckets,
    rome2_vfs_open_pack_match32 *out_deps,
    size_t max_deps,
    size_t *out_count);

/* Exact gate from FUN_112cfc10 (0x112cfe00..0x112cfe0c): recursive dependency
 * registration continues only when the child returns 0 or 1; any other code
 * unwinds and propagates. */
bool rome2_vfs_dep_status_acceptable(uint32_t recursive_reg_code);

#endif

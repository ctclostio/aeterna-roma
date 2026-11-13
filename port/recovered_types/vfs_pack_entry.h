#ifndef ROME2_RECOVERED_VFS_PACK_ENTRY_H
#define ROME2_RECOVERED_VFS_PACK_ENTRY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "vfs_archive_register.h"

/* Runtime vtable address assigned at 0x112a9963 to each 0x28-byte pack entry. */
#define ROME2_VFS_PACK_ENTRY_VTABLE32 0x118976c0u

typedef struct rome2_vfs_pack_props_prefix_info32 {
    uint32_t file_handle;
    uint32_t last_error;
    uint32_t flags;
    uint8_t low_nibble_01c;
    bool has_per_entry_meta;
    bool open_ok;
    uint32_t header_base;
    uint32_t entry_count;
    uint32_t index_bytes;
    uint32_t default_entry_meta;
    rome2_data_address32 pack_path_ptr;
    uint32_t pack_path_len;
    uint32_t pack_path_cap;
    uint8_t flag_040;
} rome2_vfs_pack_props_prefix_info32;

typedef struct rome2_vfs_pack_index_record32 {
    uint32_t byte_size;
    uint32_t entry_meta;
    uint64_t data_offset;
    size_t path_offset;
    size_t path_length;
    size_t next_cursor;
} rome2_vfs_pack_index_record32;

typedef struct rome2_vfs_pack_entry_info32 {
    rome2_vtable_address32 vtable;
    uint32_t name_id;
    uint32_t byte_size;
    uint64_t data_offset;
    uint32_t entry_meta;
    rome2_data_address32 carrier;
    rome2_data_address32 stream_state;
    uint8_t winner_notified;
} rome2_vfs_pack_entry_info32;

/* Borrowed mutable host window covering one contiguous guest-address interval
 * for checked adaptation of vtable mutators (e.g. 0x112d2900 at +0x34). */
typedef struct rome2_vfs_guest_write_view32 {
    uint8_t *host_base;
    uint32_t guest_base;
    uint64_t byte_count;
} rome2_vfs_guest_write_view32;

/* Checked adaptation of FUN_112a9560's pack-index entry decoder
 * (0x112a97d0..0x112a9831 & data-offset accumulation at 0x112a99c0..0x112a99d8):
 * reads LE u32 byte_size, optional LE u32 entry_meta when (pack_flags & 0x40)
 * != 0 (otherwise default_entry_meta), skips leading 0x00 padding bytes, scans
 * a NUL-terminated path bounded by max_path_bytes, and checks 64-bit cumulative
 * *io_data_offset += byte_size. Preserves *out_record and *io_data_offset on
 * any non-OK return. */
rome2_vfs_reg_status rome2_vfs_decode_pack_index_record(
    const uint8_t *index_buf, size_t index_bytes, size_t cursor,
    uint32_t pack_flags, uint32_t default_entry_meta, uint32_t max_path_bytes,
    uint64_t *io_data_offset, rome2_vfs_pack_index_record32 *out_record);

/* Reads a 0x44-byte rome2_vfs_pack_props_prefix32 over a checked guest view.
 * Preserves *output on any non-OK status. */
rome2_vfs_reg_status rome2_vfs_pack_props_read_prefix32(
    const rome2_guest_read_view *view, rome2_guest_addr32 pack_props_addr,
    rome2_vfs_pack_props_prefix_info32 *output);

/* Reads a 0x28-byte pack-entry object at entry_addr, validating vtable ==
 * ROME2_VFS_PACK_ENTRY_VTABLE32 (0x118976c0). Preserves *output on failure. */
rome2_vfs_reg_status rome2_vfs_entry_read32(
    const rome2_guest_read_view *view, rome2_guest_addr32 entry_addr,
    rome2_vfs_pack_entry_info32 *output);

/* Checked adaptation of vtable 0x118976c0 slot +0x34 (0x112d2900:
 * `mov byte ptr [ecx+0x24], 1; ret`): validates bounds and vtable ==
 * 0x118976c0 before writing winner_notified = 1. Writes nothing on non-OK. */
rome2_vfs_reg_status rome2_vfs_entry_notify_winner32(
    const rome2_vfs_guest_write_view32 *view, rome2_guest_addr32 entry_addr);

#endif

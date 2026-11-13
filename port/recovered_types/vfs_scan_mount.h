#ifndef ROME2_RECOVERED_VFS_SCAN_MOUNT_H
#define ROME2_RECOVERED_VFS_SCAN_MOUNT_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_archive_register.h"

/* Layer 17 recovered open-bucket map hash, load-factor rehash, 0x50-byte
 * ref-pack block, post-scan 0x3cb table, and stream wrapper constants.
 */
#define ROME2_VFS_THREAD_HASH_XOR32       0x4a545eedu /* 0x101f4f90 */
#define ROME2_VFS_REF_PACK_VTABLE32       0x1189a424u /* 0x112d4160 */
#define ROME2_VFS_REF_PACK_BLOCK_BYTES    0x50u       /* 0x112d4160 */
#define ROME2_VFS_POST_SCAN_SLOTS         0x3cbu      /* 971 (0x112baf90) */
#define ROME2_VFS_ROOT_VECTOR_BYTES       0x180u      /* 0x112d4c50 */
#define ROME2_VFS_STREAM_WRAP_A_VTABLE32  0x118977ecu /* 0x112a7ae0 */
#define ROME2_VFS_STREAM_WRAP_B_VTABLE32  0x11897790u /* 0x112a94d0 */

/*
 * Compute the bucket index `(thread_id ^ 0x4a545eed) % bucket_count` used by
 * `0x101f4f90`; preserves `*out_bucket` on invalid `bucket_count`.
 */
rome2_vfs_reg_status rome2_vfs_thread_bucket_hash32(
    uint32_t thread_id,
    uint32_t bucket_count,
    uint32_t *out_bucket);

/*
 * Walk a `rome2_vfs_open_bucket_map32` bucket chain matching `0x101f4f90` for
 * `thread_id`, returning the matched `rome2_vfs_thread_node32` guest address or
 * `0` when absent. Stops cleanly at `bucket + 0x04` sentinel and rejects cycles
 * exceeding `step_limit`.
 */
rome2_vfs_reg_status rome2_vfs_thread_bucket_lookup32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 map_addr,
    uint32_t thread_id,
    uint32_t step_limit,
    rome2_guest_addr32 *out_node_addr);

/*
 * Decide whether `next_element_count / bucket_count > max_load_factor` matching
 * `0x112cbe10` and compute `new_buckets = bucket_count * 2 + 1` with overflow
 * validation; rejects non-finite or non-positive `max_load_factor`.
 */
rome2_vfs_reg_status rome2_vfs_bucket_map_should_rehash32(
    uint32_t next_element_count,
    uint32_t bucket_count,
    float max_load_factor,
    uint32_t *out_should_rehash,
    uint32_t *out_new_buckets);

/*
 * Decode the 12-byte ref-counted control header of a 0x50-byte block allocated
 * by `0x112d4160` plus its embedded `pack_props` flags/error fields at `+0x0c`.
 */
rome2_vfs_reg_status rome2_vfs_decode_ref_pack_block32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 block_addr,
    rome2_vfs_ref_pack_block_header32 *out_header,
    uint32_t *out_embedded_last_error,
    uint32_t *out_embedded_entry_count);

/*
 * Decode a `rome2_vfs_post_scan_table32` (`0x120329c8`, `0x112baf90`) and sweep
 * its 8-byte slot array matching `0x112b5450`, counting slots different from
 * `table.default_entry` over a bounded read-only view.
 */
rome2_vfs_reg_status rome2_vfs_scan_post_mount_mismatches32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 table_addr,
    uint32_t max_slots,
    rome2_vfs_post_scan_table32 *out_table,
    uint32_t *out_mismatch_count);

/*
 * Validate post-constructor zero-initialized fields and vtable identity of
 * stream wrapper A (`0x112a7ae0`, `0x118977ec`) or B (`0x112a94d0`, `0x11897790`).
 */
rome2_vfs_reg_status rome2_vfs_validate_stream_wrap_a32(
    const rome2_vfs_stream_wrap_a32 *wrap);

rome2_vfs_reg_status rome2_vfs_validate_stream_wrap_b32(
    const rome2_vfs_stream_wrap_b32 *wrap);

#endif

#ifndef ROME2_RECOVERED_VFS_POOL_SLAB_H
#define ROME2_RECOVERED_VFS_POOL_SLAB_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_archive_register.h"

/* Layer 15 recovered pool-slab, archive-name disposer, VFS mutex, global
 * registry map, base pack-entry vtable, and setting-flag constants. */
#define ROME2_VFS_PACK_ENTRY_BASE_VTABLE32 0x11849278u
#define ROME2_VFS_PURECALL32               0x116bd8afu
#define ROME2_VFS_ARCHIVE_DISPOSER_VT32    0x1189a434u
#define ROME2_VFS_ARCHIVE_WRAPPER_VT32     0x1189a444u

#define ROME2_VFS_POOL_HEADER_0_32         0x119344f4u /* 0x10106000 */
#define ROME2_VFS_POOL_HEADER_1_32         0x11934500u /* 0x10106060 */
#define ROME2_VFS_POOL_HEADER_2_32         0x1193450cu /* 0x101060c0 */
#define ROME2_VFS_POOL_HEADER_3_32         0x11934518u /* 0x10106120 */

#define ROME2_VFS_MUTEX_BOX_ADDR32         0x12032b10u /* 0x112bff80 */
#define ROME2_VFS_GLOBAL_MAP_ADDR32        0x12032bf4u /* 0x112e32b0 */

#define ROME2_VFS_SLAB_NODE_STRIDE         0x1cu       /* 28 bytes (0x10328250) */
#define ROME2_VFS_MAP_BUCKET_STRIDE        0x10u       /* 16 bytes (0x112e32b0) */
#define ROME2_VFS_BASE_VTABLE_SLOT_COUNT   15u
#define ROME2_VFS_BASE_PURECALL_PREFIX     11u
#define ROME2_VFS_BASE_CONCRETE_SLOTS      4u

/*
 * Decode a 12-byte freelist pool header (`0x119344f4..0x11934518`) returned
 * by `0x10106000..0x10106120`.
 */
rome2_vfs_reg_status rome2_vfs_decode_freelist_pool_header32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 pool_addr,
    rome2_vfs_freelist_pool_header32 *out_header);

/*
 * Decode an 8-byte slab descriptor written by `0x10328250(count, next_slab)`.
 */
rome2_vfs_reg_status rome2_vfs_decode_slab_descriptor32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 desc_addr,
    rome2_vfs_slab_descriptor32 *out_desc);

/*
 * Compute `node_count * 0x1c` (`(node_count * 8 - node_count) << 2`) with
 * 32-bit unsigned overflow checking matching `0x10328250`.
 */
rome2_vfs_reg_status rome2_vfs_stride28_slab_byte_size(
    uint32_t node_count,
    uint32_t *out_bytes);

/*
 * Populate a caller-provided guest-endian slab buffer of `node_count`
 * 28-byte nodes anchored at `slab_guest_base`, matching the singly-linked
 * `node[i].next` layout written by `0x10328250`.
 */
rome2_vfs_reg_status rome2_vfs_init_stride28_slab(
    uint8_t *slab_bytes,
    size_t slab_byte_capacity,
    rome2_guest_addr32 slab_guest_base,
    uint32_t node_count);

/*
 * Verify `node_count` 28-byte stride freelist links in read-only guest view
 * memory and return the tail node's `next` link (0 for a well-formed slab).
 */
rome2_vfs_reg_status rome2_vfs_verify_stride28_slab_chain(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 slab_guest_base,
    uint32_t node_count,
    rome2_guest_addr32 *out_last_next);

/*
 * Decode the 24-byte archive-name node disposer (`0x1189a434`) referenced by
 * `0x112afd00`, `0x112afbf0`, and `0x112acd70`.
 */
rome2_vfs_reg_status rome2_vfs_decode_archive_disposer32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 obj_addr,
    rome2_vfs_archive_name_disposer32 *out_disposer);

/*
 * Validate and extract the 15-slot base pack-entry vtable (`0x11849278`):
 * 11 `__purecall` (`0x116bd8af`) entries followed by 4 concrete virtual slots.
 */
rome2_vfs_reg_status rome2_vfs_decode_pack_entry_base_vtable32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    uint32_t out_concrete_slots[ROME2_VFS_BASE_CONCRETE_SLOTS]);

/*
 * Decode the 28-byte VFS critical-section wrapper (`0x12032b10`) returned by
 * `0x112bff80`.
 */
rome2_vfs_reg_status rome2_vfs_decode_mutex_box32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 box_addr,
    rome2_vfs_mutex_box32 *out_box);

/*
 * Decode the 36-byte global UTF-16LE registry hash table (`0x12032bf4`)
 * initialized by `0x112e32b0` and probed by `0x112c02e0`, also validating
 * `bucket_count * 16` without 32-bit overflow.
 */
rome2_vfs_reg_status rome2_vfs_decode_global_map32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 map_addr,
    rome2_vfs_global_map32 *out_map,
    uint32_t *out_bucket_bytes);

/*
 * Compute the next 4-bit setting flag state from `0x11346530`
 * (`0x11346596..0x113465ce`) given `[vb+0x04]` (`existing_flags`), `[vb+0x14]`
 * (`vb_ptr_val`), caller flag argument (`arg_flags`), and resolver status.
 */
rome2_vfs_reg_status rome2_vfs_setting_flags_compute32(
    uint32_t existing_flags,
    uint32_t vb_ptr_val,
    uint32_t arg_flags,
    uint32_t resolved_status,
    uint32_t *out_next_flags);

#endif

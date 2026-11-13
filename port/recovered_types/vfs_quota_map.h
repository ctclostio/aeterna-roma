#ifndef ROME2_RECOVERED_VFS_QUOTA_MAP_H
#define ROME2_RECOVERED_VFS_QUOTA_MAP_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_archive_register.h"

/* Layer 16 recovered global-map hash, .pack wire header, RB teardown, thread
 * quota frame, and stream slice view constants. */
#define ROME2_VFS_HASH_SEED32            0xf73a51c9u /* 0x100d79c0 */
#define ROME2_VFS_PACK_WIRE_HDR_BYTES    0x1cu       /* 0x112a9bc0 */
#define ROME2_VFS_ERROR_HANDLE_EOF       0x26u       /* 38 */
#define ROME2_VFS_STREAM_ALLOC_BYTES     0x3cu       /* 60 (0x112ba6c0) */
#define ROME2_VFS_RB_NODE_BYTES          0x14u       /* 20 (0x112e3eb0) */
#define ROME2_VFS_SINGLETON_HEAD32       0x12032944u /* 0x112e3eb0 */
#define ROME2_VFS_MAX_RB_STACK_DEPTH     64u

/*
 * Compute the 32-bit reverse rotate-XOR UTF-16LE hash used by `0x100d79c0`
 * (`seed = 0xf73a51c9u`, scanning `unit_count - 1` down to `0`).
 */
rome2_vfs_reg_status rome2_vfs_hash_utf16_key32(
    const uint16_t *units,
    size_t unit_count,
    uint32_t *out_hash);

/*
 * Linear-probe a `rome2_vfs_global_map32` (`0x112e32b0` / `0x100d79c0`) in a
 * read-only guest view and return the guest address of the matching bucket's
 * 32-bit payload (`slot + 0x0c`), stopping cleanly on `unused_key`.
 */
rome2_vfs_reg_status rome2_vfs_global_map_probe32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 map_addr,
    const uint16_t *key_units,
    size_t key_unit_count,
    rome2_guest_addr32 *out_value_slot_addr);

/*
 * Decode the 28-byte little-endian `.pack` header (`0x112a9bc0`'s `ReadFile`
 * into `pack_props + 0x18..+0x33`); short reads preserve `out_header`.
 */
rome2_vfs_reg_status rome2_vfs_pack_header_decode32(
    const uint8_t *header_bytes,
    size_t byte_count,
    rome2_vfs_pack_header_wire32 *out_header);

/*
 * Check and reserve one VFS operation + `byte_delta` against `io_frame`
 * matching `0x112a45c0` without unsigned overflow; rejected reservations keep
 * `io_frame` unchanged and store `0` into `out_accepted`.
 */
rome2_vfs_reg_status rome2_vfs_quota_check_and_reserve(
    rome2_vfs_quota_frame32 *io_frame,
    uint32_t byte_delta,
    uint32_t *out_accepted);

/*
 * Traverse non-nil (`is_nil == 0`) 20-byte RB-tree nodes matching `0x10cf4d20`
 * iteratively using bounded stack depth, preserving `out_node_count` on error.
 */
rome2_vfs_reg_status rome2_vfs_count_rb_live_nodes32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 root_addr,
    uint32_t step_limit,
    uint32_t *out_node_count);

/*
 * Validate and copy a 16-byte stream slice descriptor matching `0x112aa5d0`.
 */
rome2_vfs_reg_status rome2_vfs_build_stream_slice_view32(
    const rome2_vfs_stream_slice_view32 *src,
    rome2_vfs_stream_slice_view32 *out_dst);

#endif

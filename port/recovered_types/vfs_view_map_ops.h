#ifndef ROME2_RECOVERED_VFS_VIEW_MAP_OPS_H
#define ROME2_RECOVERED_VFS_VIEW_MAP_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_adj_open_ops.h"
#include "vfs_archive_register.h"

/* Layer 22 recovered constants, vtable identities, and dtor sizes. */
#define ROME2_VFS_ALIGNED_ALLOC_THRESHOLD      0x1000u     /* 0x101d9910 / 0x112afb90 */
#define ROME2_VFS_ALIGNED_ALLOC_PAD            0x23u       /* +0x23 alignment slack + raw header */
#define ROME2_VFS_ALIGNED_ALLOC_MAX_GAP        0x1fu       /* 0x112afb90 invalid_parameter guard */
#define ROME2_VFS_TELEMETRY_BUCKETS            0x3e5u      /* 997 hash buckets in 0x112e1830 */

#define ROME2_VFS_REF_BLOCK_D_VTABLE32         0x1189a444u /* 0x2cB (0x112acd30 / 0x112a7860) */
#define ROME2_VFS_TELEMETRY_MGR_VTABLE32       0x118976a4u /* 0x6cB (0x112e1830) */
#define ROME2_VFS_PACK_ENTRY_76C0_VTABLE32     0x118976c0u /* 0x28B (0x112ad1b0) */
#define ROME2_VFS_PACK_ENTRY_BASE_VTABLE32     0x11849278u /* base vtable written by 0x112ad1b0 */

#define ROME2_VFS_DTOR_112ACCD0                0x112accd0u /* 0x38B deleting dtor */
#define ROME2_VFS_DTOR_112ACCF0                0x112accf0u /* 0x20B deleting dtor */
#define ROME2_VFS_DTOR_112ACD10                0x112acd10u /* 0x1cB deleting dtor */
#define ROME2_VFS_DTOR_112ACD30                0x112acd30u /* 0x2cB deleting dtor */
#define ROME2_VFS_DTOR_112ACD50                0x112acd50u /* 0x50B deleting dtor */
#define ROME2_VFS_DTOR_112ACD70                0x112acd70u /* 0x18B deleting dtor */
#define ROME2_VFS_DTOR_112AD1B0                0x112ad1b0u /* 0x28B deleting dtor (resets vtable) */

/*
 * Plan raw allocation size and 32-byte-alignment mode for `0x101d9910`:
 * rejects `element_count > 0x3fffffff` or `payload + 0x23` overflow with
 * `RANGE_ERROR`; outputs `raw_bytes = 0, use_aligned32 = 0` for `0` elements,
 * exact `payload` for `< 0x1000` bytes, and `payload + 0x23` with aligned mode
 * for `>= 0x1000` bytes. Preserves caller outputs on failure.
 */
rome2_vfs_reg_status rome2_vfs_plan_u32_aligned_alloc32(
    uint32_t element_count,
    uint32_t *out_raw_bytes,
    int *out_use_aligned32);

/*
 * Model `0x112afb90`: validates old `rome2_vfs_u32_ptr_vec32` free policy
 * (for `byte_cap >= 0x1000`, reads `[first - 4]` raw allocation pointer from
 * `view` and checks `(first - 4 - raw_ptr) <= 0x1f`) and builds the rebound
 * `{new_first, new_last, new_end}` triple. Preserves all outputs on error.
 */
rome2_vfs_reg_status rome2_vfs_u32_vec_plan_rebind32(
    const rome2_guest_read_view *view,
    const rome2_vfs_u32_ptr_vec32 *old_vec,
    rome2_guest_addr32 new_first,
    uint32_t new_size,
    uint32_t new_cap,
    int *out_needs_free,
    rome2_guest_addr32 *out_free_addr,
    uint32_t *out_free_bytes,
    rome2_vfs_u32_ptr_vec32 *out_new_vec);

/*
 * Plan the granularity-aligned view mapping window matching `0x10102f90`:
 * validates power-of-two `alloc_granularity`, aligns `file_offset` downward,
 * checks 32-bit mapping extent (`sub_offset + requested_bytes`) and granularity
 * probe rounding, and outputs `{aligned_lo, aligned_hi, sub_offset, map_bytes,
 * probe_bytes}` without mutating outputs on failure.
 */
rome2_vfs_reg_status rome2_vfs_plan_view_map_window32(
    uint64_t file_offset,
    uint32_t requested_bytes,
    uint32_t alloc_granularity,
    uint32_t *out_aligned_lo,
    uint32_t *out_aligned_hi,
    uint32_t *out_sub_offset,
    uint32_t *out_map_bytes,
    uint32_t *out_probe_bytes);

/*
 * Decode one 44-byte (`0x2c`B) `rome2_vfs_state_ref_block32` (`0x1189a444`,
 * constructed in `0x112a7860`) from a checked guest view without mutating
 * `*out_block` on failure.
 */
rome2_vfs_reg_status rome2_vfs_decode_state_ref_block32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_state_ref_block32 *out_block);

/*
 * Decode one 108-byte (`0x6c`B) `rome2_vfs_pack_telemetry_mgr32` (`0x118976a4`
 * at `0x12032e68`, lazily built in `0x112e1830`) without mutating `*out_mgr`.
 */
rome2_vfs_reg_status rome2_vfs_decode_pack_telemetry_mgr32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_pack_telemetry_mgr32 *out_mgr);

/*
 * Bounded substring search matching `0x10e13a60`: returns `*out_found = 0`
 * whenever `*haystack == '\0'` (even if `*needle == '\0'`), `*out_found = 1`
 * when `*haystack != '\0' && *needle == '\0'`, or `1`/`0` for needle match
 * within `[0, *_max]`. Preserves `*out_found` on error.
 */
rome2_vfs_reg_status rome2_vfs_ascii_contains_bounded(
    const char *haystack,
    size_t haystack_max,
    const char *needle,
    size_t needle_max,
    int *out_found);

/*
 * Bounded page-touch byte accumulator matching `0x10115900`: steps `i` by
 * `page_stride` over `[0, byte_len)` summing `(uint8_t)buf[i]` modulo `2^32`.
 * Rejects `page_stride == 0` and preserves `*out_acc` on error.
 */
rome2_vfs_reg_status rome2_vfs_prefetch_pages_sum32(
    const uint8_t *buf,
    uint32_t byte_len,
    uint32_t page_stride,
    uint32_t initial_acc,
    uint32_t *out_acc);

/*
 * Traverse `entry[+0x1c] -> [carrier+0x00] -> ([inner+0x1c] >> 6) & 1`
 * matching `0x112c9540` (`0x118976c0 +0x18`), failing with `INVALID_STATE` on
 * null pointers and preserving `*out_bit` on error.
 */
rome2_vfs_reg_status rome2_vfs_pack_entry_read_archive_bit6_32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 entry_addr,
    uint8_t *out_bit);

/*
 * Resolve deallocation size (`0x50`, `0x18`, `0x38`, `0x20`, `0x1c`, `0x2c`, or
 * `0x28`, or `0` when `(delete_flags & 1) == 0`) and base vtable reset
 * (`0x11849278` for `0x112ad1b0`, `0` otherwise) across all 7 recovered scalar
 * deleting destructors. Preserves outputs on error (`BAD_ARGUMENT` or
 * `INVALID_STATE` for unknown dtor address).
 */
rome2_vfs_reg_status rome2_vfs_deleting_dtor_size32(
    rome2_code_address32 dtor_addr,
    uint8_t delete_flags,
    uint32_t *out_free_bytes,
    rome2_vtable_address32 *out_reset_vtable);

#endif

#ifndef ROME2_RECOVERED_VFS_RB_BUCKET_OPS_H
#define ROME2_RECOVERED_VFS_RB_BUCKET_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_dep_rehash.h"

/* Layer 19 recovered RB/hash container bounds and allocator constants. */
#define ROME2_VFS_DEP_RB_MAX_NODES             0x06666665u /* 0x112a3320: max_size (0xffffffff / 0x28) */
#define ROME2_VFS_HASH_MAX_BUCKETS             0x10000000u /* 0x112b0070: 1 << BSR(0x1fffffff) */
#define ROME2_VFS_HASH_MIN_BUCKETS             8u          /* 0x112afc10 */
#define ROME2_VFS_HASH_SMALL_GROW_CAP          0x200u      /* 0x112afc10 */
#define ROME2_VFS_STREAM_HANDLE_BOX_BYTES      0x14u       /* 20 (0x112ac430) */
#define ROME2_VFS_BUCKET_SLOT_BYTES            0x0cu       /* 12 (0x112d8550 / 0x112dbe10) */
#define ROME2_VFS_VEC_ALIGN_THRESHOLD_BYTES    0x1000u     /* 0x112ab420 / 0x112b0070 */
#define ROME2_VFS_VEC_ALIGN_ADJUST_BYTES       0x23u       /* 35 (0x112ab420 / 0x112b0070) */
#define ROME2_VFS_VEC_ALIGN_HEADER_MAX_GAP     0x1fu       /* 31 (0x112ab420 / 0x112b0070) */

/*
 * Check `0x112a3320`'s 0x28-byte node count ceiling (`current_count < 0x06666665`)
 * and compute `current_count + 1` without mutating `*out_next_count` on failure.
 */
rome2_vfs_reg_status rome2_vfs_dep_rb_can_allocate32(
    uint32_t current_count,
    uint32_t *out_next_count);

/*
 * Compute next-power-of-two bucket count (and `2 * buckets` pointer slot count)
 * matching `0x112b0070`, rejecting `0` (`BAD_ARGUMENT`) and `> 0x10000000`
 * (`RANGE_ERROR`, "invalid hash bucket count") without mutating outputs.
 */
rome2_vfs_reg_status rome2_vfs_hash_next_power_of_2_buckets32(
    uint32_t requested_buckets,
    uint32_t *out_bucket_count,
    uint32_t *out_pointer_slots);

/*
 * Compute desired bucket count matching `0x112afc10`: ceil(elements / max_load),
 * clamped up to 8, keeping `current_buckets` if sufficient or scaling small maps
 * (`current_buckets < 0x200`) by `8x`. Preserves `*out_buckets` on error.
 */
rome2_vfs_reg_status rome2_vfs_hash_desired_buckets32(
    uint32_t element_count,
    uint32_t max_load_factor_bits,
    uint32_t current_buckets,
    uint32_t *out_buckets);

/*
 * Decode one 20-byte `rome2_vfs_stream_handle_box32` (`0x112ac430`) from a
 * read-only guest view; preserves `*out_box` on failure.
 */
rome2_vfs_reg_status rome2_vfs_decode_stream_handle_box32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 box_addr,
    rome2_vfs_stream_handle_box32 *out_box);

/*
 * Decode one 12-byte `rome2_vfs_bucket_vec_header32` (`0x112d8550` / `0x112dbe10`),
 * enforcing `count <= capacity`; preserves `*out_header` on failure.
 */
rome2_vfs_reg_status rome2_vfs_decode_bucket_vec_header32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 header_addr,
    rome2_vfs_bucket_vec_header32 *out_header);

/*
 * Compute growth capacity (`max(min_required, capacity == 0 ? 1 : capacity * 2)`)
 * and byte size (`new_capacity * 0x0c`) matching `0x112d8550` / `0x112dbe10`'s
 * signed-nonnegative capacity check (`<= INT32_MAX`). Preserves outputs on error.
 */
rome2_vfs_reg_status rome2_vfs_bucket_vec_next_capacity32(
    uint32_t current_capacity,
    uint32_t min_required,
    uint32_t *out_new_capacity,
    uint32_t *out_alloc_bytes);

/*
 * Validate MSVC large-allocation vector deallocation header (`0x112ab420` /
 * `0x112b0070`): computes dword-aligned `size = (vec_cap - vec_begin) & ~3u`;
 * when `size >= 0x1000`, validates `(vec_begin - backing_base - 4) <= 0x1f` and
 * returns `size + 0x23`. Preserves `*out_free_bytes` on error.
 */
rome2_vfs_reg_status rome2_vfs_validate_aligned_vec_free32(
    uint32_t vec_begin,
    uint32_t vec_cap,
    uint32_t backing_base,
    uint32_t *out_free_bytes);

#endif

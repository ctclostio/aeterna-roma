#ifndef ROME2_RECOVERED_VFS_ADJ_OPEN_OPS_H
#define ROME2_RECOVERED_VFS_ADJ_OPEN_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_archive_register.h"

/* Layer 21 recovered container ceilings, step limits, and ref-block sizes. */
#define ROME2_VFS_ADJ_HASH_MAX_NODES           0x071c71c7u /* 0x112a2910: 0xffffffff / 0x24 */
#define ROME2_VFS_U32_VEC_MAX_ELEMENTS         0x3fffffffu /* 0x112d8c50: 0xffffffff / 4 */
#define ROME2_VFS_FLAG_CHAIN_MAX_STEPS         4096u       /* 0x112cd4c0 bounded walk */
#define ROME2_VFS_ADJ_HASH_NODE_BYTES          0x24u       /* 36 (0x112ac1a0) */
#define ROME2_VFS_REF_BLOCK_A_VTABLE32         0x1189a424u /* 0x50B (0x112acd50) */
#define ROME2_VFS_REF_BLOCK_B_VTABLE32         0x1189a434u /* 0x18B (0x112acd70) */
#define ROME2_VFS_REF_BLOCK_C_VTABLE32         0x1189a454u /* 0x38B (0x112accd0) */
#define ROME2_VFS_REF_BLOCK_A_BYTES            0x50u
#define ROME2_VFS_REF_BLOCK_B_BYTES            0x18u
#define ROME2_VFS_REF_BLOCK_C_BYTES            0x38u

/*
 * Check `0x112a2910`'s 0x24-byte adjacency hash-list node count ceiling
 * (`current_count < 0x071c71c7`) and compute `current_count + 1` without
 * mutating `*out_next_count` on failure (`BAD_ARGUMENT` or `RANGE_ERROR`).
 */
rome2_vfs_reg_status rome2_vfs_adj_hash_can_allocate32(
    uint32_t current_count,
    uint32_t *out_next_count);

/*
 * Decode one 36-byte (0x24B) `rome2_vfs_adj_hash_node32` (`0x112ac1a0`) from
 * a checked guest read view without mutating `*out_node` on error.
 */
rome2_vfs_reg_status rome2_vfs_decode_adj_hash_node32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 addr,
    rome2_vfs_adj_hash_node32 *out_node);

/*
 * Plan a `push_back` on a 12-byte pointer-triple `rome2_vfs_u32_ptr_vec32`
 * matching `0x112d8c50`: validates `first <= last <= end` and 4-byte aligned
 * spans, rejects `size >= 0x3fffffff` (`RANGE_ERROR`), and computes 1.5x
 * growth (`cap + (cap >> 1)`) clamped to `[size + 1, 0x3fffffff]`.
 * Preserves all caller outputs on failure.
 */
rome2_vfs_reg_status rome2_vfs_u32_vec_plan_push32(
    const rome2_vfs_u32_ptr_vec32 *vec,
    uint32_t *out_size,
    uint32_t *out_next_capacity,
    int *out_needs_grow);

/*
 * Model `0x112c0c60` stream-state wait & recursive VFS mutex unwind plan:
 * when `state->eof_or_closed_00c == 0`, waiting temporarily unwinds all
 * `current_lock_depth + 1` critical-section acquisitions (`LeaveCriticalSection`)
 * and later re-acquires `current_lock_depth` levels (`EnterCriticalSection`)
 * before releasing its own entry lock. Rejects `current_lock_depth == UINT32_MAX`
 * with `RANGE_ERROR` and preserves all caller outputs on failure.
 */
rome2_vfs_reg_status rome2_vfs_state_wait_plan32(
    const rome2_vfs_stream_state_prefix32 *state,
    uint32_t current_lock_depth,
    int *out_should_wait,
    uint32_t *out_leaves_needed,
    uint32_t *out_reenters_needed);

/*
 * Model the shared slice-reentry validation in `0x112d8d30` (`stream_wrap_a`
 * `+0x04`) and `0x112d8e20` (`stream_wrap_b` `+0x04`): when `ref_count != 0`,
 * requires `(cur_lo == req_lo && cur_hi == req_hi) || is_normals_prefix != 0`,
 * failing with `INVALID_STATE` otherwise, and rejecting `ref_count == UINT32_MAX`
 * with `RANGE_ERROR`. Preserves `*out_next_ref_count` on failure.
 */
rome2_vfs_reg_status rome2_vfs_stream_wrap_check_open_reentry32(
    uint32_t ref_count,
    uint32_t cur_lo,
    uint32_t cur_hi,
    uint32_t req_lo,
    uint32_t req_hi,
    int is_normals_prefix,
    uint32_t *out_next_ref_count);

/*
 * Bounded iterative clear matching `0x112cd4c0` (`if (next) next->clear();
 * flag_004 = 0`): traverses `nodes[0..node_count-1]` starting at `head_idx`
 * (`UINT32_MAX` denotes null). Validates chain bounds and acyclicity before
 * clearing `flag_004 = 0`, preserving `nodes` and `*out_cleared_count` on error.
 */
rome2_vfs_reg_status rome2_vfs_clear_flag_chain_bounded(
    rome2_vfs_flag_chain_node32 *nodes,
    size_t node_count,
    uint32_t head_idx,
    size_t *out_cleared_count);

/*
 * Resolve deallocation byte size (`0x50`, `0x18`, or `0x38`, or `0` when delete
 * flag bit 0 is clear) for ref-block scalar deleting destructors `0x112acd50`,
 * `0x112acd70`, and `0x112accd0`. Returns `INVALID_STATE` for unknown vtable
 * and preserves `*out_free_bytes` on error.
 */
rome2_vfs_reg_status rome2_vfs_ref_block_delete_size32(
    rome2_vtable_address32 vtable,
    uint8_t delete_flags,
    uint32_t *out_free_bytes);

#endif

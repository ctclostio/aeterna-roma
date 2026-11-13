#ifndef ROME2_RECOVERED_VFS_DEP_REHASH_H
#define ROME2_RECOVERED_VFS_DEP_REHASH_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_quota_map.h"

/* Layer 18 recovered ref-block, stream-wrapper, dependency RB, and rehash constants. */
#define ROME2_VFS_REF_PACK_BLOCK_BYTES      0x50u  /* 80 (0x112acd50) */
#define ROME2_VFS_STREAM_WRAP_A_BYTES       0x38u  /* 56 (0x112acde0) */
#define ROME2_VFS_STREAM_WRAP_B_BYTES       0x3cu  /* 60 (0x112ad0f0) */
#define ROME2_VFS_DEP_RB_NODE_BYTES         0x28u  /* 40 (0x112a7700 / 0x112be300) */
#define ROME2_VFS_CYCLE_RB_SENTINEL_BYTES   0x1cu  /* 28 (0x112e3ae0) */
#define ROME2_VFS_OPEN_PACK_SLOT_STRIDE     0x14u  /* 20 (0x112ddb30) */
#define ROME2_VFS_MAX_DEP_RB_VISIT          256u

/* Strict weak ordering callback comparing two 12-byte guest key triplets (0x100f2fe0). */
typedef int (*rome2_vfs_key12_less_fn)(
    const uint32_t lhs[3],
    const uint32_t rhs[3],
    void *ctx,
    int *out_is_less);

/*
 * Compute the bucket target chosen by `0x112d9e20`:
 * `needed = ceilf((float)(double)element_count / max_load_factor)`, and when
 * `(float)(double)requested_buckets < needed`, raise `requested_buckets` to
 * `(uint32_t)needed`. Rejects non-positive / non-finite load factors and values
 * outside `[0, 2^32)` without mutating `*out_bucket_count`.
 */
rome2_vfs_reg_status rome2_vfs_compute_rehash_target32(
    uint32_t requested_buckets,
    uint32_t element_count,
    uint32_t max_load_factor_bits,
    uint32_t *out_bucket_count);

/*
 * Decode one 40-byte `rome2_vfs_dep_rb_node32` (`0x112a7700` / `0x112a2760`)
 * from a read-only guest view; preserves `*out_node` on any failure.
 */
rome2_vfs_reg_status rome2_vfs_decode_dep_rb_node32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 node_addr,
    rome2_vfs_dep_rb_node32 *out_node);

/*
 * Count interior nodes of a `rome2_vfs_dep_rb_node32` RB tree starting at
 * `head_addr`'s root (`head.parent`), following `0x112a2760`'s right-push /
 * left-descend order with bounded depth (`ROME2_VFS_MAX_RB_STACK_DEPTH`) and
 * visit cap `max_steps`. Preserves `*out_node_count` on error.
 */
rome2_vfs_reg_status rome2_vfs_count_dep_rb_nodes32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 head_addr,
    size_t max_steps,
    uint32_t *out_node_count);

/*
 * Lexicographically compare two `(name_a, name_b)` 12-byte key pairs as ordered
 * by `0x112a4090` and `0x112a4b60`: `out_order` receives `-1` (`lhs < rhs`),
 * `0` (`lhs ~= rhs`), or `+1` (`rhs < lhs`). Preserves `*out_order` on error.
 */
rome2_vfs_reg_status rome2_vfs_dep_pair_compare32(
    const uint32_t lhs_a[3],
    const uint32_t lhs_b[3],
    const uint32_t rhs_a[3],
    const uint32_t rhs_b[3],
    rome2_vfs_key12_less_fn less_fn,
    void *ctx,
    int32_t *out_order);

/*
 * Decode the 4-slot 16-byte `0x1189a424` vtable (`rome2_vfs_ref_block_vtable32`);
 * rejects any null code slot and preserves `*out_vtable` on error.
 */
rome2_vfs_reg_status rome2_vfs_decode_ref_block_vtable32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_ref_block_vtable32 *out_vtable);

/*
 * Decode the 8-slot 32-byte vtable prefix shared by `0x118977ec` (`stream_wrap_a`)
 * and `0x11897790` (`stream_wrap_b`); rejects any null code slot and preserves
 * `*out_prefix` on error.
 */
rome2_vfs_reg_status rome2_vfs_decode_stream_wrap_vtable_prefix32(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_stream_wrap_vtable_prefix32 *out_prefix);

/*
 * Compute the `0x14`-byte-strided linear-probe byte offset in `0x112ddb30`:
 * `((hash_value % bucket_count) + probe_step) % bucket_count * 0x14u`,
 * rejecting zero `bucket_count`, `probe_step >= bucket_count`, or `uint32_t`
 * byte-offset overflow without mutating `*out_byte_offset`.
 */
rome2_vfs_reg_status rome2_vfs_open_pack_stride20_slot_offset32(
    uint32_t bucket_count,
    uint32_t hash_value,
    uint32_t probe_step,
    uint32_t *out_byte_offset);

#endif

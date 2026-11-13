#ifndef ROME2_RECOVERED_VFS_STREAM_WRAP_OPS_H
#define ROME2_RECOVERED_VFS_STREAM_WRAP_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_archive_register.h"

/* Layer 20 recovered slot/tree constants. */
#define ROME2_VFS_RB_MAX_WALK_STEPS            4096u
#define ROME2_VFS_STREAM_STATE_SLOT_008_OFF    0x08u

/*
 * Resolved dispatch metadata for `0x112badf0` (`stream_wrap_a` vtable `+0x1c`).
 * `has_state == 0` mirrors the null-handle early `return 0` path.
 */
typedef struct rome2_vfs_stream_wrap_a_slot1c_plan32 {
    int has_state;
    int needs_sync_call;
    rome2_data_address32 state_addr;
    rome2_code_address32 tail_slot_008_vtable_offset;
} rome2_vfs_stream_wrap_a_slot1c_plan32;

/*
 * Decrement `wrap->zero_02c` (`ref_count`) matching `0x112da9f0` (`0x118977ec`
 * slot `+0x10`). When it drops to 0, zeroes `+0x20..+0x28` low byte and `+0x30`,
 * returning the captured handle box address in `*out_released_handle`.
 * Preserves all caller outputs (and `wrap`) on error (`BAD_ARGUMENT` or
 * `INVALID_STATE` when `ref_count == 0`).
 */
rome2_vfs_reg_status rome2_vfs_stream_wrap_a_release_ref32(
    rome2_vfs_stream_wrap_a32 *wrap,
    uint32_t *out_remaining_refs,
    int *out_should_release_handle,
    rome2_data_address32 *out_released_handle);

/*
 * Decrement `wrap->zero_038` (`ref_count`) matching `0x112dab00` (`0x11897790`
 * slot `+0x10`). When it drops to 0, clears `+0x20..+0x34` state fields and
 * captures any non-null `rome2_vfs_stream_view_box32` address to unmap/free.
 * Preserves all caller outputs (and `wrap`) on error.
 */
rome2_vfs_reg_status rome2_vfs_stream_wrap_b_release_ref32(
    rome2_vfs_stream_wrap_b32 *wrap,
    uint32_t *out_remaining_refs,
    int *out_should_free_view,
    rome2_data_address32 *out_view_box_addr);

/*
 * Slot `+0x14` of `0x118977ec` (`0x112c8b80`): returns `(wrap->zero_030 != 0)`
 * in `*out_has_handle` without mutating outputs on error.
 */
rome2_vfs_reg_status rome2_vfs_stream_wrap_a_has_handle32(
    const rome2_vfs_stream_wrap_a32 *wrap,
    int *out_has_handle);

/*
 * Slot `+0x18` of `0x118977ec` (`0x112d9860`): safely traverses
 * `handle_box -> sentinel_or_state -> eof_or_closed_00c` inside `view`, setting
 * `*out_is_open` to 1 iff handle, state, and `eof_or_closed_00c == 0` hold.
 */
rome2_vfs_reg_status rome2_vfs_stream_wrap_a_is_open32(
    const rome2_guest_read_view *view,
    const rome2_vfs_stream_wrap_a32 *wrap,
    int *out_is_open);

/*
 * Slot `+0x1c` of `0x118977ec` (`0x112badf0`): safely resolves `handle_box` and
 * `rome2_vfs_stream_state_prefix32` from `view`, identifying whether `0x112c0c60`
 * sync runs (`eof_or_closed_00c == 0`) before tail-calling `[state.vtable + 0x08]`.
 */
rome2_vfs_reg_status rome2_vfs_stream_wrap_a_plan_slot1c32(
    const rome2_guest_read_view *view,
    const rome2_vfs_stream_wrap_a32 *wrap,
    rome2_vfs_stream_wrap_a_slot1c_plan32 *out_plan);

/*
 * Slot `+0x18` of `0x11897790` (`0x10369160`): returns `(wrap->zero_020[0] != 0)`
 * in `*out_has_view` without mutating outputs on error.
 */
rome2_vfs_reg_status rome2_vfs_stream_wrap_b_has_view32(
    const rome2_vfs_stream_wrap_b32 *wrap,
    int *out_has_view);

/*
 * Slot `+0x14` of `0x11897790` (`0x112c8bc0`): checks `view_box != 0 &&
 * tag_00c != 0`, selects `target = (zero_020[2] != 0) ? zero_020[2] : tag_00c`,
 * and sets `*out_is_at_bound = (zero_020[1] == target)`.
 */
rome2_vfs_reg_status rome2_vfs_stream_wrap_b_is_at_bound32(
    const rome2_vfs_stream_wrap_b32 *wrap,
    int *out_is_at_bound);

/*
 * Slot `+0x1c` of `0x11897790` (`0x112baef0`): reads the 8-byte
 * `rome2_vfs_stream_view_box32` at `wrap->zero_020[0]` from `view` (rejecting
 * NULL view_box with `INVALID_STATE`) and stores it into `*out_box`.
 */
rome2_vfs_reg_status rome2_vfs_stream_wrap_b_read_view_box32(
    const rome2_guest_read_view *view,
    const rome2_vfs_stream_wrap_b32 *wrap,
    rome2_vfs_stream_view_box32 *out_box);

/*
 * RB-tree leftmost (`0x112b0780`) and rightmost (`0x112b0760`) walk over an
 * indexed `rome2_vfs_rb_sentinel_node32` array where child indices are stored
 * in `left`/`right` with `is_nil != 0` terminating descent (bounded by
 * `node_count` and `ROME2_VFS_RB_MAX_WALK_STEPS`).
 */
rome2_vfs_reg_status rome2_vfs_rb_find_extreme_index(
    const rome2_vfs_rb_sentinel_node32 *nodes,
    size_t node_count,
    uint32_t start_idx,
    int walk_right,
    uint32_t *out_extreme_idx);

/*
 * Perform an RB-tree rotation (`rotate_left != 0` matches `0x112b0710`,
 * `rotate_left == 0` matches `0x112b07a0`) on `nodes[0..node_count-1]` using
 * `sentinel_idx` as the tree sentinel node (`sentinel.parent` holds root index),
 * and refresh `sentinel.left`/`sentinel.right` like `0x112a2470`.
 */
rome2_vfs_reg_status rome2_vfs_rb_rotate_and_refresh_extremes(
    rome2_vfs_rb_sentinel_node32 *nodes,
    size_t node_count,
    uint32_t sentinel_idx,
    uint32_t pivot_idx,
    int rotate_left);

#endif

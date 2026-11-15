#ifndef ROME2_RECOVERED_VFS_SUBSTREAM_LOOSE_OPS_H
#define ROME2_RECOVERED_VFS_SUBSTREAM_LOOSE_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_archive_register.h"
#include "vfs_handle_lifecycle_ops.h"

/* Layer 26 recovered constants and vtable identities. */
#define ROME2_VFS_STD_EXCEPTION_VTABLE32       0x11741d58u /* std::exception base vtable */
#define ROME2_VFS_STD_EXCEPTION_UNKNOWN32      0x11741d64u /* "unknown exception" */
#define ROME2_VFS_LOOSE_VTABLE_7710_VTABLE32   0x11897710u /* 20-slot loose-file entry vtable */
#define ROME2_VFS_PACK_WRAP_7760_VTABLE32      0x11897760u /* 12-slot pack wrapper vtable */

#define ROME2_VFS_CREATE_FILE_GENERIC_READ32   0x80000000u
#define ROME2_VFS_CREATE_FILE_SHARE_RW32       0x00000003u
#define ROME2_VFS_CREATE_FILE_OPEN_EXISTING32  0x00000003u
#define ROME2_VFS_CREATE_FILE_ATTR_BUFFERED32  0x08000001u
#define ROME2_VFS_CREATE_FILE_ATTR_ASYNC_DIRECT32 0x68000001u

/*
 * Close `handle` via `ops->close_handle` and normalize `CloseHandle == 1`
 * matching `0x100f6fd0`. Preserves `*out_closed_ok` on `BAD_ARGUMENT`.
 */
rome2_vfs_reg_status rome2_vfs_close_handle_bool_6fd0(
    const rome2_vfs_win32_handle_ops *ops,
    uint32_t handle,
    int *out_closed_ok);

/*
 * Compute `CreateFileA` access, share, disposition, and flags-and-attributes
 * arguments matching `0x10104cc0`: `0x80000000`, `3`, `3`, and `0x68000001`
 * when `unbuffered_or_async != 0`, else `0x08000001`.
 */
rome2_vfs_reg_status rome2_vfs_create_file_flags_4cc0(
    uint8_t unbuffered_or_async,
    uint32_t *out_desired_access,
    uint32_t *out_share_mode,
    uint32_t *out_creation_disposition,
    uint32_t *out_flags_and_attrs);

/*
 * Zero-initialize the active fields of a 20B `rome2_vfs_file_stat20_32`
 * struct matching `0x1011fda0` while preserving `pad_11`.
 */
rome2_vfs_reg_status rome2_vfs_file_stat20_zero_fda0(
    rome2_vfs_file_stat20_32 *stat_out);

/*
 * Check 16-byte guest alignment `(dst | src | count) & 0xf == 0` matching
 * `0x112b43d0`, validate non-NULL non-overlapping host buffers, and copy
 * `byte_count` bytes while recording whether the aligned fast path applied.
 */
rome2_vfs_reg_status rome2_vfs_aligned16_or_memcpy_43d0(
    uintptr_t dst_guest_addr,
    uintptr_t src_guest_addr,
    uint8_t *dst_buf,
    const uint8_t *src_buf,
    size_t byte_count,
    int *out_used_aligned16);

/*
 * Return `exc->what_str_04` or `0x11741d64` ("unknown exception") when NULL
 * matching `std::exception::what` (`0x10115df0`).
 */
rome2_vfs_reg_status rome2_vfs_std_exception_what_5df0(
    const rome2_vfs_bad_alloc_exc8_32 *exc,
    uint32_t *out_what_addr);

/*
 * Clamp a loose-file read window against `entry->file_size_14` matching
 * `0x112d0bf0` / `0x112d0d20`: rejects `req_offset > file_size_14` with
 * `RANGE_ERROR`, otherwise clamps `rem` to `req_length` when non-zero.
 */
rome2_vfs_reg_status rome2_vfs_loose_entry_clamp_window_0d20(
    const rome2_vfs_loose_file_entry32 *entry,
    uint32_t req_length,
    uint32_t req_offset,
    uint32_t *out_clamped_length,
    uint32_t *out_offset);

/*
 * Clear `backing_view_1c = 0`, close `file_handle_0c` via `0x100f6fd0`, and
 * reset `file_handle_0c` and `aux_handle_10` to `-1` matching `0x112daa40`.
 */
rome2_vfs_reg_status rome2_vfs_loose_entry_teardown_handles_aa40(
    const rome2_vfs_win32_handle_ops *ops,
    rome2_vfs_loose_file_entry32 *entry,
    int *out_closed_ok);

/*
 * Decode 20 slots from `view` at `vtable_addr` and verify exact equality with
 * `0x11897710`. Preserves outputs on `BAD_ARGUMENT` or `RANGE_ERROR`.
 */
rome2_vfs_reg_status rome2_vfs_loose_vtable_7710_matches(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_loose_vtable_7710_20slot32 *out_vt,
    int *out_matches);

/*
 * Decode 12 slots from `view` at `vtable_addr` and verify exact equality with
 * `0x11897760`. Preserves outputs on `BAD_ARGUMENT` or `RANGE_ERROR`.
 */
rome2_vfs_reg_status rome2_vfs_pack_wrap_vtable_7760_matches(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_pack_wrap_vtable_7760_12slot32 *out_vt,
    int *out_matches);

/*
 * Evaluate `[obj + 0x18]` bit-6 wrapper flag matching `0x112c9520`: returns
 * `1` when `[obj + 0x18] == 0`, else reads `*([obj + 0x18])` `+0x1c` bit 6.
 */
rome2_vfs_reg_status rome2_vfs_pack_wrap_flag_bit6_9520(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 obj_addr,
    uint8_t *out_bit);

/*
 * Decode 8 slots from `view` at `vtable_addr` and verify exact equality with
 * `0x11897c24`. Preserves outputs on `BAD_ARGUMENT` or `RANGE_ERROR`.
 */
rome2_vfs_reg_status rome2_vfs_substream_vtable_7c24_matches(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_substream_vtable_7c24_8slot32 *out_vt,
    int *out_matches);

/*
 * Evaluate buffered substream readiness `eof == 0 && err == 0 && parent_ready`
 * matching `0x11897c24` slot `+0x04` (`0x112c8c40`).
 */
rome2_vfs_reg_status rome2_vfs_substream_can_read_8c40(
    const rome2_vfs_buffered_substream40_32 *sub,
    int parent_ready,
    int *out_can_read);

/*
 * Update `sub->eof_flag_24 = (sub->stream_pos_10 >= parent_size)` matching
 * `0x11897c24` slot `+0x1c` (`0x112d57d0`).
 */
rome2_vfs_reg_status rome2_vfs_substream_refresh_eof_57d0(
    rome2_vfs_buffered_substream40_32 *sub,
    uint32_t parent_size);

/*
 * Model `0x11897c24` slot `+0x0c` (`0x112c0cf0`): resets to
 * `initial_pos_or_cursor_1c` on `delta == 0`, else advances in-window or remaps
 * on overflow-checked `window_offset_0c + delta` and `stream_pos_10 + delta`.
 */
rome2_vfs_reg_status rome2_vfs_substream_advance_0cf0(
    rome2_vfs_buffered_substream40_32 *sub,
    uint32_t delta,
    uint32_t new_window_base,
    uint32_t new_window_size,
    int *out_remapped);

/*
 * Model `0x11897c24` slot `+0x10` (`0x112dc1a0`): resets to
 * `initial_pos_or_cursor_1c` on `delta == 0`, else rejects `delta > stream_pos`
 * and rewinds in-window (`window_offset >= delta`) or remaps.
 */
rome2_vfs_reg_status rome2_vfs_substream_rewind_c1a0(
    rome2_vfs_buffered_substream40_32 *sub,
    uint32_t delta,
    uint32_t new_window_base,
    uint32_t new_window_size,
    int *out_remapped);

#endif

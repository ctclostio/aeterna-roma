#ifndef ROME2_RECOVERED_VFS_STREAM_MUX_ASYNC_OPS_H
#define ROME2_RECOVERED_VFS_STREAM_MUX_ASYNC_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_archive_register.h"

/* Layer 27 recovered vtable, COM HRESULT, and _stat64i32 constants. */
#define ROME2_VFS_DUAL_SLOT_VIEW_VTABLE32       0x11897818u /* 11-slot dual-slot backing view */
#define ROME2_VFS_CIPHER_MEM_VIEW_VTABLE32      0x11897844u /* 9-slot cipher-memory backing view */
#define ROME2_VFS_STREAM_DELEGATE_VTABLE32      0x11897c90u /* 15-slot delegating stream adapter */
#define ROME2_VFS_STREAM_ADAPTER_BASE_VTABLE32  0x1173db9cu /* 15-slot base adapter vtable */
#define ROME2_VFS_BACKING_VIEW_BASE_VTABLE32    0x11849278u /* base vtable reset in destructors */
#define ROME2_VFS_E_NOINTERFACE32               0x80040002u /* E_NOINTERFACE from 0x101d3b10 */
#define ROME2_VFS_STAT_REG_OR_READ_MASK32       0x00008100u /* _S_IFREG | _S_IREAD gate */

/*
 * Zero-initialize a 16B `rome2_vfs_dual_slot_entry32` matching `0x112a2090`.
 * Preserves `pad_0d` and returns `BAD_ARGUMENT` on NULL.
 */
rome2_vfs_reg_status rome2_vfs_dual_slot_entry_zero_init(
    rome2_vfs_dual_slot_entry32 *entry);

/*
 * Initialize an 84B `rome2_vfs_dual_slot_view32` with vtable `0x11897818`,
 * file handles, size, chunk cap, cipher flags, and zeroed dual slots matching
 * the `chunk_cap != 0` branch of `0x112ba840`. Rejects `chunk_cap == 0`.
 */
rome2_vfs_reg_status rome2_vfs_dual_slot_view_init(
    rome2_vfs_dual_slot_view32 *view,
    uint32_t name_str_addr,
    uint32_t path_str_addr,
    uint32_t total_size,
    uint32_t file_handle,
    uint32_t aux_handle,
    uint32_t chunk_cap,
    uint32_t cipher_flags);

/*
 * Teardown a `rome2_vfs_dual_slot_view32` matching `0x112ad210` + `0x112ab500`:
 * clears slot task pointers and relative offsets and resets vtable to
 * `0x11849278` (reporting count of released non-null task handles in `out_released_tasks`).
 */
rome2_vfs_reg_status rome2_vfs_dual_slot_view_destroy(
    rome2_vfs_dual_slot_view32 *view,
    uint32_t *out_released_tasks);

/*
 * Evaluate active slot non-null predicate matching `0x11897818` slot `+0x14`
 * (`0x112c8c30`): sets `*out_has_task = 1` when active slot `task_ptr_00 != 0`.
 */
rome2_vfs_reg_status rome2_vfs_dual_slot_view_has_active_task(
    const rome2_vfs_dual_slot_view32 *view,
    int *out_has_task);

/*
 * Evaluate active task completion predicate matching `0x11897818` slot `+0x18`
 * (`0x112d98a0`): reads `inner_0c = *(task_ptr_00 + 0xc)` and `*(inner_0c + 0xc)`
 * from `guest_mem` when active `task_ptr_00 != 0`.
 */
rome2_vfs_reg_status rome2_vfs_dual_slot_view_is_active_task_ready(
    const rome2_vfs_dual_slot_view32 *view,
    const rome2_guest_read_view *guest_mem,
    int *out_ready);

/*
 * Compute remaining bytes in the active slot matching `0x11897818` slot `+0x20`
 * (`0x112ce900`): `*(uint32_t *)task_ptr_00 - slot_rel_off` or `0` when null.
 */
rome2_vfs_reg_status rome2_vfs_dual_slot_view_active_remaining_bytes(
    const rome2_vfs_dual_slot_view32 *view,
    const rome2_guest_read_view *guest_mem,
    uint32_t *out_remaining);

/*
 * Evaluate `active_ref_count_24 != 0` matching `0x11897818` slot `+0x24`
 * (`0x105df630`).
 */
rome2_vfs_reg_status rome2_vfs_dual_slot_view_has_active_refs(
    const rome2_vfs_dual_slot_view32 *view,
    int *out_has_refs);

/*
 * Decrement `active_ref_count_24` matching `0x11897818` slot `+0x10`
 * (`0x112dabd0`); when it reaches `0`, clears both slot task pointers and
 * resets `slot0_rel_off_48` / `slot1_rel_off_4c` to `0`.
 */
rome2_vfs_reg_status rome2_vfs_dual_slot_view_release_ref(
    rome2_vfs_dual_slot_view32 *view,
    uint32_t *out_new_ref_count,
    uint32_t *out_released_tasks);

/*
 * Evaluate window cache miss predicate matching `0x11897818` slot `+0x28`
 * (`0x112b31c0`): returns `*out_is_miss = 0` when `req_offset` hits the active
 * slot or alternate slot window, else `1`.
 */
rome2_vfs_reg_status rome2_vfs_dual_slot_view_is_window_cache_miss(
    const rome2_vfs_dual_slot_view32 *view,
    uint32_t req_offset,
    int *out_is_miss);

/*
 * Host state-machine model of `0x11897818` slot `+0x04` (`0x112d8f50`):
 * increments `active_ref_count_24`, checks active slot hit, toggles
 * `active_slot_idx_50 ^= 1` to check alternate slot hit (triggering next-window
 * prefetch when hitting via toggle or miss), or maps `[req_offset, min(req_len,
 * chunk_cap_1c)]` into the newly toggled active slot and prefetches the next
 * slice `[window_off + window_len, rem]` into the alternate slot when remaining
 * file bytes `> 0`. Assigns `next_task_id` / `next_task_id + 1` to loaded slots.
 */
rome2_vfs_reg_status rome2_vfs_dual_slot_view_map_and_prefetch(
    rome2_vfs_dual_slot_view32 *view,
    uint32_t req_length,
    uint32_t req_offset,
    uint32_t next_task_id,
    int *out_toggled,
    int *out_prefetched);

/*
 * Initialize a 32B `rome2_vfs_cipher_mem_view32` with vtable `0x11897844`,
 * name string word, cipher flags, `valid_flag_10 = 1`, `ready_flag_11 = 0`,
 * matching `0x112dc8db`.
 */
rome2_vfs_reg_status rome2_vfs_cipher_mem_view_init(
    rome2_vfs_cipher_mem_view32 *view,
    uint32_t name_str_addr,
    uint32_t cipher_flags);

/*
 * Increment `active_ref_count_1c` matching `0x11897844` slot `+0x04` (`0x112d8e10`).
 */
rome2_vfs_reg_status rome2_vfs_cipher_mem_view_inc_ref(
    rome2_vfs_cipher_mem_view32 *view);

/*
 * Saturating decrement of `active_ref_count_1c` matching `0x11897844` slot `+0x10`
 * (`0x1074b430`).
 */
rome2_vfs_reg_status rome2_vfs_cipher_mem_view_dec_ref(
    rome2_vfs_cipher_mem_view32 *view,
    uint32_t *out_new_ref_count);

/*
 * Return `view->valid_flag_10` matching `0x11897844` slot `+0x14` (`0x105d0b30`).
 */
rome2_vfs_reg_status rome2_vfs_cipher_mem_view_is_valid(
    const rome2_vfs_cipher_mem_view32 *view,
    uint8_t *out_valid);

/*
 * Return `view->ready_flag_11` matching `0x11897844` slot `+0x18` (`0x105d1200`).
 */
rome2_vfs_reg_status rome2_vfs_cipher_mem_view_is_ready(
    const rome2_vfs_cipher_mem_view32 *view,
    uint8_t *out_ready);

/*
 * Install buffer state matching `0x11897844` slot `+0x0c` (`0x112bff30`):
 * when `buf_guest_addr == 0`, clears `valid_flag_10 = 0` and sets
 * `ready_flag_11 = 1` without touching `buffer_ptr_14` or `buffer_size_18`;
 * otherwise XOR-deciphers `host_buf` via `0x100fcfd0` (`key = 0`) when
 * `cipher_flags_0c & 1`, stores `buffer_ptr_14` and `buffer_size_18`, and
 * sets `ready_flag_11 = 1`.
 */
rome2_vfs_reg_status rome2_vfs_cipher_mem_view_install_buffer(
    rome2_vfs_cipher_mem_view32 *view,
    uint32_t buf_guest_addr,
    uint8_t *host_buf,
    uint32_t buf_size);

/*
 * Resolve `buffer_ptr_14` when `ready_flag_11 != 0` matching `0x11897844`
 * slot `+0x1c` (`0x112bae20`) / `+0x08` (`0x112dd2b0`). Returns `RANGE_ERROR`
 * if called while `ready_flag_11 == 0`.
 */
rome2_vfs_reg_status rome2_vfs_cipher_mem_view_get_buffer(
    const rome2_vfs_cipher_mem_view32 *view,
    uint32_t *out_buffer_ptr);

/*
 * Set base stream adapter vtable `0x1173db9c` matching `0x112a9550`.
 */
rome2_vfs_reg_status rome2_vfs_stream_delegate_adapter_init_base(
    rome2_vfs_stream_delegate_adapter32 *adapter);

/*
 * Initialize delegating stream adapter `0x11897c90` wrapping `inner_stream_addr`
 * and widened path string fields matching `0x112c6b10`.
 */
rome2_vfs_reg_status rome2_vfs_stream_delegate_adapter_init(
    rome2_vfs_stream_delegate_adapter32 *adapter,
    uint32_t inner_stream_addr,
    uint32_t wide_path_len,
    uint32_t wide_path_cap,
    uint32_t wide_path_buf_addr);

/*
 * Reset adapter vtable to base `0x1173db9c` and release wide string state
 * matching `0x112ad1e0`.
 */
rome2_vfs_reg_status rome2_vfs_stream_delegate_adapter_destroy(
    rome2_vfs_stream_delegate_adapter32 *adapter);

/*
 * Zero `*out_obj` and return `0x80040002` (`E_NOINTERFACE`) matching
 * `0x11897c90` slot `+0x04` (`0x101d3b10`).
 */
rome2_vfs_reg_status rome2_vfs_stream_delegate_adapter_query_interface(
    uint32_t *out_obj,
    uint32_t *out_hresult);

/*
 * Resolve `[adapter->inner_stream_04]->vtable[slot_offset]` from `guest_mem`
 * matching the 10 tail-jump thunks at `0x11897c90` `+0x10..+0x34`
 * (`0x11039cb0..0x112c2f90`).
 */
rome2_vfs_reg_status rome2_vfs_stream_delegate_adapter_resolve_thunk_target(
    const rome2_vfs_stream_delegate_adapter32 *adapter,
    const rome2_guest_read_view *guest_mem,
    uint32_t slot_offset,
    uint32_t *out_target_addr);

/*
 * Evaluate `_stat64i32` / `_wstat64i32` mode gate `(st_mode & 0x8100) != 0`
 * and populate `rome2_vfs_file_stat32` (`mtime`, `file_size`, `is_readable_0c`,
 * `is_writable_0d`, `is_dir_0e`) matching `0x101153f0` and `0x101154a0`.
 */
rome2_vfs_reg_status rome2_vfs_file_stat32_from_mode_and_meta(
    rome2_vfs_file_stat32 *out_stat,
    uint32_t st_mode,
    uint64_t st_mtime,
    uint32_t st_size,
    int *out_matched);

/*
 * Widen ASCII NUL-terminated bytes to UTF-16LE code units matching `0x10115540`:
 * validates `dst_cap_units` accommodates `strlen(src) + 1`, writes NUL, and
 * reports units written (excluding NUL).
 */
rome2_vfs_reg_status rome2_vfs_widen_ascii_to_utf16(
    const uint8_t *src,
    uint16_t *dst_utf16,
    size_t dst_cap_units,
    size_t *out_units_written);

#endif

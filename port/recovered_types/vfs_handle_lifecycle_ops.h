#ifndef ROME2_RECOVERED_VFS_HANDLE_LIFECYCLE_OPS_H
#define ROME2_RECOVERED_VFS_HANDLE_LIFECYCLE_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_archive_register.h"

/* Layer 25 recovered Win32 handle sentinels, error constants, and vtables. */
#define ROME2_VFS_INVALID_HANDLE32            0xffffffffu
#define ROME2_VFS_HANDLE_BOX_CLOSED_STATUS    6u          /* ERROR_INVALID_HANDLE */
#define ROME2_VFS_ERR_ALREADY_EXISTS32        0xb7u       /* 183: CreateSemaphoreA collision */
#define ROME2_VFS_OPEN_FLAG_FILE              1u          /* bit 0 of open_flags_04 */
#define ROME2_VFS_OPEN_FLAG_MAPPING           2u          /* bit 1 of open_flags_04 */
#define ROME2_VFS_OPEN_DEFAULT_ERR_FALLBACK   3u          /* stored when mapped error == 0 */

#define ROME2_VFS_BAD_ALLOC_VTABLE32          0x11741d78u /* std::bad_alloc vtable */
#define ROME2_VFS_BAD_ALLOC_WHAT32            0x11741d84u /* "bad allocation" */
#define ROME2_VFS_PACK_REF_7BE0_VTABLE32      0x11897be0u /* 17-slot pack/resource ref vtable */
#define ROME2_VFS_PACK_REF_BASE_VTABLE32      0x11849278u /* reset vtable written by 0x112acf80 */
#define ROME2_VFS_PACK_SUBSTREAM_7C24_VTABLE32 0x11897c24u /* 8-slot parent-releasing substream */
#define ROME2_VFS_PACK_SUBSTREAM_7C44_VTABLE32 0x11897c44u /* 8-slot pack/stream cursor vtable */
#define ROME2_VFS_PACK_SUBSTREAM_BASE_VTABLE32 0x11848c9cu /* reset vtable written by 0x112ad6a0/d0 */

/*
 * Mockable Win32 handle/file/mapping operations interface modeling the IAT calls
 * issued by `0x100f12c0`, `0x100f2230`, `0x100f2170`, `0x100f2350`, `0x100fcb00`,
 * and `0x10104b60`. `map_win32_error` is optional (NULL defaults to identity).
 */
typedef struct rome2_vfs_win32_handle_ops {
    void *ctx;
    uint32_t (*create_semaphore_a)(void *ctx, int32_t initial_count, int32_t max_count, const char *name);
    uint32_t (*create_file_read_a)(void *ctx, const char *path);
    uint32_t (*get_file_size)(void *ctx, uint32_t file_handle, uint32_t *out_high_size);
    uint32_t (*create_file_mapping_w)(void *ctx, uint32_t file_handle, uint32_t max_high, uint32_t max_low);
    int (*close_handle)(void *ctx, uint32_t handle);
    uint32_t (*get_last_error)(void *ctx);
    uint32_t (*map_win32_error)(void *ctx, uint32_t win32_err);
} rome2_vfs_win32_handle_ops;

/*
 * Initialize a Win32 semaphore handle matching `0x100f12c0`: calls
 * `CreateSemaphoreA(NULL, initial_count, max_count, name)` and checks
 * `GetLastError() == 0xb7` (ERROR_ALREADY_EXISTS); on collision closes the
 * handle and stores `0`, otherwise stores the returned handle.
 */
rome2_vfs_reg_status rome2_vfs_semaphore_handle_init_12c0(
    const rome2_vfs_win32_handle_ops *ops,
    int32_t initial_count,
    int32_t max_count,
    const char *name,
    uint32_t *out_handle);

/*
 * Close a semaphore handle cell matching `0x100f2230`: calls `CloseHandle`
 * when `*handle_cell != 0` without mutating `*handle_cell`.
 */
rome2_vfs_reg_status rome2_vfs_semaphore_handle_close_2230(
    const rome2_vfs_win32_handle_ops *ops,
    const uint32_t *handle_cell,
    int *out_closed);

/*
 * Default-initialize an 8B Win32 handle box matching `0x100f1080`: sets
 * `handle_00 = -1` and `last_status_04 = 6`.
 */
rome2_vfs_reg_status rome2_vfs_win32_handle_box_init_1080(
    rome2_vfs_win32_handle_box8_32 *box);

/*
 * Close and reset an 8B Win32 handle box matching `0x100f2170`: if
 * `handle_00 != -1`, closes it (probing `GetLastError()` if `CloseHandle`
 * returns FALSE), then resets `handle_00 = -1` and `last_status_04 = 6`.
 */
rome2_vfs_reg_status rome2_vfs_win32_handle_box_close_2170(
    const rome2_vfs_win32_handle_ops *ops,
    rome2_vfs_win32_handle_box8_32 *box,
    uint32_t *out_close_error);

/*
 * Default-initialize a 16B open-file/mapping box matching `0x100f1a30`: clears
 * `open_flags_04 = 0` and sets `file_handle_08 = -1`, `mapping_handle_0c = -1`,
 * leaving `last_error_00` untouched.
 */
rome2_vfs_reg_status rome2_vfs_open_file_mapping_init_1a30(
    rome2_vfs_open_file_mapping16_32 *entry);

/*
 * Close owned handles on a 16B open-file/mapping box matching `0x100f2350`:
 * closes `mapping_handle_0c` first if `!= -1 && (flags & 2)`, then
 * `file_handle_08` if `!= -1 && (flags & 1)`, clearing each flag bit and
 * resetting handles to `-1`.
 */
rome2_vfs_reg_status rome2_vfs_open_file_mapping_close_2350(
    const rome2_vfs_win32_handle_ops *ops,
    rome2_vfs_open_file_mapping16_32 *entry);

/*
 * Query file size and create a read-only file mapping matching `0x100fcb00`:
 * records mapped error on `GetFileSize == -1` (continuing to mapping) and on
 * `CreateFileMappingW == 0` returns `0ULL`; on success sets flag bit 2 and
 * outputs the 64-bit size. Preserves `*out_file_size` on API/arg error.
 */
rome2_vfs_reg_status rome2_vfs_open_file_mapping_map_cb00(
    const rome2_vfs_win32_handle_ops *ops,
    rome2_vfs_open_file_mapping16_32 *entry,
    uint64_t *out_file_size);

/*
 * Close existing handles, open `path` via `CreateFileA`, and chain `0x100fcb00`
 * matching `0x10104b60`. On `INVALID_HANDLE_VALUE` stores mapped error (or `3`
 * if mapped to `0`) and outputs `0ULL`.
 */
rome2_vfs_reg_status rome2_vfs_open_file_mapping_open_4b60(
    const rome2_vfs_win32_handle_ops *ops,
    rome2_vfs_open_file_mapping16_32 *entry,
    const char *path,
    uint64_t *out_file_size);

/*
 * Initialize an 8B `std::bad_alloc` header matching `0x100f1c50`: stores
 * `vtable_00 = 0x11741d78` and `what_str_04 = 0x11741d84`.
 */
rome2_vfs_reg_status rome2_vfs_bad_alloc_init_1c50(
    rome2_vfs_bad_alloc_exc8_32 *exc);

/*
 * Decode 17 slots from `view` at `vtable_addr` and verify exact equality with
 * `0x11897be0`. Preserves outputs on `BAD_ARGUMENT` or `RANGE_ERROR`.
 */
rome2_vfs_reg_status rome2_vfs_pack_vtable_7be0_matches(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_pack_vtable_7be0_17slot32 *out_vt,
    int *out_matches);

/*
 * Model `0x11897be0` slot `+0x24` (`0x112daae0`): decrements `*inout_ref_count`
 * (rejecting `0` with `INVALID_STATE`) and sets `*out_deleted = 1` when the
 * decremented count reaches `0`.
 */
rome2_vfs_reg_status rome2_vfs_pack_ref_release_aae0(
    uint32_t *inout_ref_count,
    int *out_deleted);

/*
 * Decode 8 slots from `view` at `vtable_addr` and verify exact equality with
 * `0x11897c44`. Preserves outputs on `BAD_ARGUMENT` or `RANGE_ERROR`.
 */
rome2_vfs_reg_status rome2_vfs_pack_vtable_7c44_matches(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 vtable_addr,
    rome2_vfs_pack_vtable_7c44_8slot32 *out_vt,
    int *out_matches);

/*
 * Evaluate `[obj + 0x14] != 0 && [obj + 0x1c] < [obj + 0x20]` matching
 * `0x11897c44` slot `+0x04` (`0x112c8c60`). Preserves `*out_can_read` on error.
 */
rome2_vfs_reg_status rome2_vfs_pack_substream_can_read_8c60(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 obj_addr,
    int *out_can_read);

/*
 * Model `0x11897c44` slot `+0x0c` (`0x112c0d90`): if `delta == 0`, clears
 * `*inout_cursor_1c = 0`; else adds `delta` with overflow check (`RANGE_ERROR`).
 */
rome2_vfs_reg_status rome2_vfs_pack_substream_advance_0d90(
    uint32_t *inout_cursor_1c,
    uint32_t delta);

/*
 * Model `0x11897c44` slot `+0x10` (`0x112dc250`): if `delta == 0`, clears
 * `*inout_cursor_1c = 0`; else subtracts `delta` with underflow check (`RANGE_ERROR`).
 */
rome2_vfs_reg_status rome2_vfs_pack_substream_rewind_c250(
    uint32_t *inout_cursor_1c,
    uint32_t delta);

#endif

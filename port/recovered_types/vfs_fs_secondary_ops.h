#ifndef ROME2_RECOVERED_VFS_FS_SECONDARY_OPS_H
#define ROME2_RECOVERED_VFS_FS_SECONDARY_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "../x64_runtime/guest32.h"
#include "guest32_layouts.h"
#include "vfs_archive_register.h"

/* Layer 28 recovered vtables, handle thresholds, and stream flag constants. */
#define ROME2_VFS_BASE_FS_PRIMARY_VTABLE32       0x1189791cu /* 30-slot BASE_FILESYSTEM primary vtable */
#define ROME2_VFS_BASE_FS_SECONDARY_VTABLE32     0x11897994u /* 13-slot BASE_FILESYSTEM secondary vtable */
#define ROME2_VFS_ACTIVE_FS_SECONDARY_VTABLE32   0x118978e8u /* 13-slot active FILESYSTEM secondary vtable */
#define ROME2_VFS_SP_CTRL_VTABLE32               0x1189a520u /* 4-slot _Ref_count_base vtable */
#define ROME2_VFS_PACK_WRAP_SINGLETON_VTABLE32   0x11897760u /* 12-slot pack-wrap vtable */
#define ROME2_VFS_LOOSE_WRAPPER_VTABLE32         0x11897c44u /* 8-slot loose-file open wrapper */
#define ROME2_VFS_EMPTY_FILE_DESC_VTABLE32       0x11897be0u /* 12-slot empty-file descriptor */
#define ROME2_VFS_DEFAULT_SINGLETON_VTABLE32     0x11897710u /* 0x112bcd80 empty wrapper vtable */
#define ROME2_VFS_DTOR_BASE_VTABLE32             0x11849278u /* atexit reset base vtable */
#define ROME2_VFS_LOOSE_HANDLE_MIN32             0x80000001u /* > 0x80000000 loose handle space */
#define ROME2_VFS_HANDLE_SENTINEL_BOUND32        0xffffffffu /* default [0x119e1000] upper sentinel */
#define ROME2_VFS_STREAM_FLAG_ENCRYPTED32        0x00000001u /* triggers 0x100fcfd0 XOR decipher */

typedef enum rome2_vfs_handle_domain {
    ROME2_VFS_HANDLE_INVALID = 0,
    ROME2_VFS_HANDLE_PACK,
    ROME2_VFS_HANDLE_LOOSE
} rome2_vfs_handle_domain;

/* Host model of static initializer `0x117240b0` for `0x119e1004` (`0x1189791c`, `0x11897994`). */
rome2_vfs_reg_status rome2_vfs_base_fs_init_static(
    rome2_vfs_base_fs_obj32 *obj);

/* Host model of `0x112acfb0`: restores both BASE_FILESYSTEM vptrs and reports deleting flag `(flags & 1)`. */
rome2_vfs_reg_status rome2_vfs_base_fs_deleting_dtor(
    rome2_vfs_base_fs_obj32 *obj,
    uint32_t flags,
    int *out_should_free);

/* Host model of `0x11002ca0`: zero-initializes an 8-byte `rome2_vfs_u64_pair32`. */
rome2_vfs_reg_status rome2_vfs_base_fs_default_pair_zero(
    rome2_vfs_u64_pair32 *pair);

/* Host model of `0x112c9550`: sets `-1/-1` sentinel bounds, interns empty name handle, and clears tail fields. */
rome2_vfs_reg_status rome2_vfs_base_fs_default_entry_info(
    rome2_vfs_entry_info32 *info,
    uint32_t empty_name_str_addr);

/* Host model of `0x112bbaf0`: computes `base_addr + count * 12` with checked uint32 arithmetic. */
rome2_vfs_reg_status rome2_vfs_vec12_end_ptr(
    uint32_t base_addr,
    uint32_t count,
    uint32_t *out_end_addr);

/* Host model of `0x112e0ed0`/`0x112ce3b0`/`0x112e0f30`/`0x112e10e0`: binds `ctrl` (`0x1189a520`) and `pair`. */
rome2_vfs_reg_status rome2_vfs_sp_ctrl_init(
    rome2_vfs_sp_ctrl_block32 *ctrl,
    uint32_t ctrl_guest_addr,
    uint32_t payload_guest_addr,
    rome2_vfs_sp_pair32 *out_pair);

/* Host model of `std::shared_ptr` strong/weak control release observed inline in `0x112e0f30`/`0x112e10e0`/`0x112ce410` + `0x112afc90`/`0x112accb0`. */
rome2_vfs_reg_status rome2_vfs_sp_ctrl_release_strong(
    rome2_vfs_sp_ctrl_block32 *ctrl,
    int *out_destroy_payload,
    int *out_delete_ctrl);

/* Host model of `shared_ptr` copy assignment updating `out_pair` and incrementing `src_ctrl->uses_04`. */
rome2_vfs_reg_status rome2_vfs_sp_pair_assign_retain(
    rome2_vfs_sp_ctrl_block32 *src_ctrl,
    uint32_t src_ctrl_addr,
    uint32_t src_ptr,
    rome2_vfs_sp_pair32 *out_pair);

/* Host model of `0x112d2980` / `0x112d2a70` / `0x112d2b60` lazy 28B pack-wrap singleton construction. */
rome2_vfs_reg_status rome2_vfs_pack_wrap_singleton_init(
    rome2_vfs_pack_wrap_singleton28_32 *singleton,
    uint32_t empty_file_str_addr);

/* Host model of `0x117246d0` / `0x117246e0`: resets singleton vtable to base `0x11849278` at exit. */
rome2_vfs_reg_status rome2_vfs_pack_wrap_singleton_atexit_reset(
    rome2_vfs_pack_wrap_singleton28_32 *singleton);

/* Host model of handle domain split in `0x112bd130` & `0x112e0f30`: `< pack_count` -> PACK; `> 0x80000000 && < sentinel_bound` with `(handle - 0x80000001) < loose_count` -> LOOSE. */
rome2_vfs_reg_status rome2_vfs_sec_classify_handle(
    uint32_t handle,
    uint32_t pack_count,
    uint32_t loose_count,
    uint32_t sentinel_bound,
    rome2_vfs_handle_domain *out_domain,
    uint32_t *out_index);

/* Host model of `0x112d9660`: checks mounted state + entry validity, copies `src_len` bytes, and invokes XOR decipher when `stream_flags & 1`. */
rome2_vfs_reg_status rome2_vfs_sec_read_whole_file_dispatch(
    uint8_t mounted,
    uint8_t entry_valid,
    uint32_t stream_flags,
    const uint8_t *src_bytes,
    uint32_t src_len,
    uint8_t *dst_buf,
    uint32_t dst_cap,
    uint32_t *out_bytes_read,
    int *out_succeeded);

/* Host model of `0x112d2bb0` telemetry quota accounting when both global flags (`0x12032738` & `0x12031ace`) and map insert succeed. */
rome2_vfs_reg_status rome2_vfs_sec_apply_quota_update(
    uint8_t flag_2738,
    uint8_t flag_1ace,
    uint8_t map_inserted,
    uint32_t file_size,
    uint32_t max_items,
    uint32_t max_bytes,
    uint32_t *io_used_items,
    uint32_t *io_used_bytes,
    int *out_updated);

/* Host model of `0x112b3040` platform capability gate + `0x12031a88` mounted guard shared by `0x112cf6c0` and `0x112e3480`. */
rome2_vfs_reg_status rome2_vfs_sec_gate_and_mounted_ready(
    uint8_t mode_flag_25e0,
    uint8_t runtime_probe_ok,
    uint8_t mounted_1a88,
    uint8_t *io_cached_flag_2af8,
    int *io_initialized,
    int *out_ready);

typedef struct rome2_vfs_dlink_node32 {
    int32_t prev_idx;
    int32_t next_idx;
    uint32_t key_id;
    uint8_t active;
    uint8_t freed;
} rome2_vfs_dlink_node32;

/* Host model of `0x112e3480` doubly-linked list removal (`head` / interior unlink + node release) guarded by `ready`. */
rome2_vfs_reg_status rome2_vfs_sec_unlink_list_node(
    int ready,
    rome2_vfs_dlink_node32 *nodes,
    size_t node_count,
    int32_t *io_head_idx,
    uint32_t target_key_id,
    int *out_removed);

#endif

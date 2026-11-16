#ifndef ROME2_VFS_FS_LEAF_CODEC_OPS_H
#define ROME2_VFS_FS_LEAF_CODEC_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_folder_tree_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Layer 34 bounded constants matching recovered leaf & dlmalloc models. */
#define ROME2_VFS_L34_DLMALLOC_SMALLBIN_MAX 0xf4u
#define ROME2_VFS_L34_DLMALLOC_ARENA_CAP 4096u
#define ROME2_VFS_L34_DLMALLOC_MAX_ALLOCS 32u

typedef struct rome2_vfs_dlmalloc_slot {
    uint8_t in_use;
    uint32_t offset;
    uint32_t size;
    uint32_t req_size;
} rome2_vfs_dlmalloc_slot;

typedef struct rome2_vfs_dlmalloc_model {
    rome2_vfs_dlmalloc_mstate448_32 mstate;
    uint32_t spin_lock;
    uint32_t arena_used;
    uint32_t alloc_count;
    rome2_vfs_dlmalloc_slot slots[ROME2_VFS_L34_DLMALLOC_MAX_ALLOCS];
    uint8_t arena[ROME2_VFS_L34_DLMALLOC_ARENA_CAP];
} rome2_vfs_dlmalloc_model;

/* `0x100f11b0` & `0x100f21c0` stream handle 36B lifecycle. */
void rome2_vfs_stream_handle36_init(rome2_vfs_stream_handle36_32 *handle);
void rome2_vfs_stream_handle36_destroy(rome2_vfs_stream_handle36_32 *handle);

/* `0x100f1b40`, `0x100f27f0`, `0x100f3260`, & `0x10113760` bounded UTF-16 string helpers. */
rome2_vfs_reg_status rome2_vfs_wstr_fill_repeat(
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t count,
    uint16_t fill_ch,
    uint32_t *out_len);

rome2_vfs_reg_status rome2_vfs_wstr_assign_raw(
    uint16_t *dst,
    uint32_t *inout_cap,
    uint32_t max_cap,
    const uint16_t *src,
    uint32_t *out_len);

rome2_vfs_reg_status rome2_vfs_wstr_append(
    uint16_t *dst,
    uint32_t *inout_len,
    uint32_t dst_cap,
    const uint16_t *suffix,
    uint32_t suffix_len);

rome2_vfs_reg_status rome2_vfs_wstr_reserve_grow(
    uint32_t current_cap,
    uint32_t required_cap,
    uint32_t *out_new_cap);

/* `0x100f29b0`, `0x100f2b20`, `0x100f31e0`, & `0x10114290` ASCII/wide string ops. */
uint8_t rome2_vfs_astr_not_equal(const char *lhs, const char *rhs);

rome2_vfs_reg_status rome2_vfs_str_concat_join(
    char *out_buf,
    uint32_t out_cap,
    const char *lhs,
    const char *rhs);

rome2_vfs_reg_status rome2_vfs_astr_append_cstr(
    char *dst,
    uint32_t *inout_len,
    uint32_t dst_cap,
    const char *suffix);

uint32_t rome2_vfs_astr_rfind_char(const char *str, char ch, uint32_t max_pos);

/* `0x101021b0` & `0x101030d0` Win32 error -> internal VFS status switch mappers. */
uint32_t rome2_vfs_map_win32_error_io(uint32_t win32_err);
uint32_t rome2_vfs_map_win32_error_stream(uint32_t win32_err);

/* `0x10102310` & `0x10103450` & `0x10114420` limit, UTF-8 bridge & event guard probes. */
uint8_t rome2_vfs_check_u64_budget_limit(
    uint32_t avail_lo,
    uint32_t avail_hi,
    uint32_t req_lo,
    uint32_t req_hi);

rome2_vfs_reg_status rome2_vfs_utf8_to_utf16_dispatch_probe(
    const char *utf8_src,
    uint16_t *utf16_out,
    uint32_t out_cap,
    uint32_t *out_len);

uint32_t rome2_vfs_wait_event_guard_probe(uint8_t init_ok, uint32_t signaled_val);

/* `0x101145e0` path separator canonicalization (`/`->`\`, collapse `\`, ASCII tolower). */
rome2_vfs_reg_status rome2_vfs_normalize_slashes_and_lower(
    const char *in_path,
    char *out_path,
    uint32_t out_cap,
    uint8_t *out_changed);

/* `0x10115050` & `0x101153c0` seek status & file size probe wrappers. */
uint32_t rome2_vfs_map_seek_result(uint8_t seek_ok, uint32_t last_error);
uint32_t rome2_vfs_probe_file_size_state(
    rome2_vfs_file_size_state8_32 *state,
    uint32_t reported_size_or_neg1,
    uint32_t last_error);

/* `0x10124e50` & `0x101254a0` bounded 8B-aligned dlmalloc mstate448 allocator model. */
void rome2_vfs_dlmalloc_model_init(rome2_vfs_dlmalloc_model *model);
uint32_t rome2_vfs_dlmalloc_request_size(uint32_t user_bytes);
uint8_t *rome2_vfs_dlmalloc_model_alloc(rome2_vfs_dlmalloc_model *model, uint32_t user_bytes);
void rome2_vfs_dlmalloc_model_free(rome2_vfs_dlmalloc_model *model, uint8_t *ptr);

#ifdef __cplusplus
}
#endif

#endif

#ifndef ROME2_VFS_FS_CODEC_VEC_OPS_H
#define ROME2_VFS_FS_CODEC_VEC_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_leaf_codec_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L35_MAX_TUPLE_ENTRIES 16u
#define ROME2_VFS_L35_HASH_BUCKET_LIMIT 0x20000000u

typedef struct rome2_vfs_tuple36_host {
    char a[48];
    char b[48];
    char c[48];
} rome2_vfs_tuple36_host;

typedef struct rome2_vfs_tuple36_vec {
    uint32_t capacity;
    uint32_t count;
    rome2_vfs_tuple36_host entries[ROME2_VFS_L35_MAX_TUPLE_ENTRIES];
} rome2_vfs_tuple36_vec;

/* `0x100ef8f0` & `0x100f2e60` & `0x100f3330` & `0x100f33b0` UTF-16 helpers. */
void rome2_vfs_fill_u16_range(uint16_t *dst, uint32_t count, uint16_t fill_ch);

rome2_vfs_reg_status rome2_vfs_wstr_concat_join(
    uint16_t *out_buf,
    uint32_t out_cap,
    uint32_t *out_len,
    const uint16_t *lhs,
    uint32_t lhs_len,
    const uint16_t *rhs,
    uint32_t rhs_len);

rome2_vfs_reg_status rome2_vfs_wstr_push_back(
    uint16_t *buf,
    uint32_t *inout_len,
    uint32_t buf_cap,
    uint16_t ch);

/* `0x100f2ac0` & `0x100f61b0` byte offset & back-char accessors. */
char rome2_vfs_cstr_offset_char(const char *str, uint32_t idx);
char rome2_vfs_cstr_back_or_nul(const char *str);

/* `0x100f60b0` & `0x100f6130` escaped '%%' format scanners. */
rome2_vfs_reg_status rome2_vfs_scan_fmt_token_ascii(
    const char *fmt,
    uint32_t *inout_idx,
    char *out_buf,
    uint32_t *inout_out_len,
    uint32_t out_cap);

rome2_vfs_reg_status rome2_vfs_scan_fmt_token_wstr(
    const uint16_t *fmt,
    uint32_t fmt_len,
    uint32_t *inout_idx,
    uint16_t *out_buf,
    uint32_t *inout_out_len,
    uint32_t out_cap);

/* `0x100fcb80`, `0x10103220`, & `0x101034b0` thread priority, mem status, & debug '%' escape. */
int32_t rome2_vfs_map_thread_priority(uint32_t idx);
void rome2_vfs_mem_status_ex64_init(rome2_vfs_mem_status_ex64_32 *status);
rome2_vfs_reg_status rome2_vfs_sanitize_debug_pct_wstr(
    const uint16_t *in_str,
    uint16_t *out_str,
    uint32_t out_cap);

/* `0x10100620` & `0x101007b0` numeric to ASCII/UTF-16 decimal formatting helpers. */
rome2_vfs_reg_status rome2_vfs_format_u32_ascii(uint32_t value, char *out_buf, uint32_t out_cap);
rome2_vfs_reg_status rome2_vfs_format_f32_ascii(
    float value,
    uint32_t precision,
    uint8_t keep_trailing_zeros,
    char *out_buf,
    uint32_t out_cap);

/* `0x101207a0`, `0x101216b0`, `0x10121bf0`, `0x10122b50`, & `0x101278d0` path/hash/skip helpers. */
rome2_vfs_reg_status rome2_vfs_hash_next_power2_buckets(uint32_t min_buckets, uint32_t *out_buckets);
uint8_t rome2_vfs_cstr_ends_with(const char *str, const char *suffix);
int32_t rome2_vfs_search_list_find_idx(const char *const *items, uint32_t count, const char *key);
rome2_vfs_reg_status rome2_vfs_normalize_all_dots(
    const char *in_path,
    char *out_path,
    uint32_t out_cap,
    uint8_t *out_changed);
uint8_t rome2_vfs_skip_ascii_ws(const char **inout_cursor);

/* `0x112d8ae0` tuple36 vector emplace & `0x112bed30..0x112e49b0` math string formatters. */
rome2_vfs_reg_status rome2_vfs_tuple36_push_back(
    rome2_vfs_tuple36_vec *vec,
    const char *a,
    const char *b,
    const char *c);

rome2_vfs_reg_status rome2_vfs_format_euler_ascii(
    float z,
    float y,
    float x,
    char *out_buf,
    uint32_t out_cap);

rome2_vfs_reg_status rome2_vfs_format_vec3_ascii(
    float x,
    float y,
    float z,
    char *out_buf,
    uint32_t out_cap);

rome2_vfs_reg_status rome2_vfs_format_vec4i_ascii(
    int32_t x,
    int32_t y,
    int32_t z,
    int32_t w,
    char *out_buf,
    uint32_t out_cap);

#ifdef __cplusplus
}
#endif

#endif

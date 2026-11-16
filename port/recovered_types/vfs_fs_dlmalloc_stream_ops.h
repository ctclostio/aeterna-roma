#ifndef ROME2_VFS_FS_DLMALLOC_STREAM_OPS_H
#define ROME2_VFS_FS_DLMALLOC_STREAM_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_leaf_codec_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/* `0x10123640`..`0x101246f0` dlmalloc mparams, treebin index, sys_trim & lock helpers. */
rome2_vfs_reg_status rome2_vfs_dlmalloc_init_mparams(
    rome2_vfs_dlmalloc_mparams28_32 *params,
    uint32_t page_size,
    uint32_t granularity,
    uint32_t tick_count);

uint32_t rome2_vfs_dlmalloc_tree_idx(uint32_t nb);
uint32_t rome2_vfs_dlmalloc_tree_step_shift(uint32_t idx);
uint8_t rome2_vfs_dlmalloc_spin_should_sleep(uint32_t iteration);
uint8_t rome2_vfs_dlmalloc_sys_trim_calc(
    uint32_t topsize,
    uint32_t pad,
    uint32_t granularity,
    uint32_t *out_extra);

/* `0x100d1790`, `0x100f3150`, `0x100f6f30`, & `0x100ffbb0` format/string/handle ops. */
rome2_vfs_reg_status rome2_vfs_scan_lfmt_token_ascii(
    const char *fmt,
    uint16_t *inout_idx,
    char *out_buf,
    uint32_t *inout_out_len,
    uint32_t out_cap,
    uint8_t *out_hit_spec);

rome2_vfs_reg_status rome2_vfs_cstr_push_back(
    char *buf,
    uint32_t *inout_len,
    uint32_t buf_cap,
    char ch);

void rome2_vfs_stream_handle36_close(rome2_vfs_stream_handle36_32 *handle);

int32_t rome2_vfs_wstr_find_wchar(
    const uint16_t *buf,
    uint32_t len,
    uint16_t needle,
    uint32_t start_pos);

/* `0x100db960`, `0x100e10c0`, `0x100e3950`, & `0x113682d0` hashes & bucket init. */
uint32_t rome2_vfs_hash_wstr_xor(const uint16_t *wstr, uint32_t len);
uint32_t rome2_vfs_hash_cstr_pairsum(const char *str);
uint32_t rome2_vfs_handle_table_bucket(uint32_t key, uint32_t bucket_count);
void rome2_vfs_bucket12_reset_empty(rome2_vfs_bucket_slot12_32 *slot, uint32_t guest_slot_va);

/* `0x11346d60`, `0x11347190`, `0x11348d50`, `0x11349790` wide stream pad & integer field parser. */
rome2_vfs_reg_status rome2_vfs_wstr_pad_write(
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t *inout_len,
    uint16_t ch,
    uint32_t field_width,
    uint16_t fill_ch);

rome2_vfs_reg_status rome2_vfs_wstreambuf_get_ifld(
    const uint16_t *wbuf,
    uint32_t len,
    uint32_t ios_flags,
    char *out_ascii,
    uint32_t out_cap,
    int32_t *out_base);

#ifdef __cplusplus
}
#endif

#endif

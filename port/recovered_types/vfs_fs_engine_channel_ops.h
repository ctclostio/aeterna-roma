#ifndef ROME2_VFS_FS_ENGINE_CHANNEL_OPS_H
#define ROME2_VFS_FS_ENGINE_CHANNEL_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_dlmalloc_stream_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L37_MAX_CHANNELS 0x14u
#define ROME2_VFS_L37_MAX_RBTREE_NODES 16u

typedef struct rome2_vfs_rbtree_node16 {
    uint32_t left;
    uint32_t parent;
    uint32_t right;
    uint8_t is_nil;
} rome2_vfs_rbtree_node16;

/* `0x10238c90`: UTF-16 '%l...' format scanner skipping repeated L'l' length prefixes. */
rome2_vfs_reg_status rome2_vfs_scan_lfmt_token_wstr(
    const uint16_t *fmt,
    uint32_t fmt_len,
    uint16_t *inout_idx,
    uint16_t *out_buf,
    uint32_t *inout_out_len,
    uint32_t out_cap,
    uint8_t *out_hit_spec);

/* `0x1039db80`: MSVC _Ref_count_base::_Decref atomic transition model. */
rome2_vfs_reg_status rome2_vfs_refcount_decref(
    rome2_vfs_refcount_ctrl12_32 *ctrl,
    uint8_t *out_destroyed,
    uint8_t *out_deleted);

/* `0x10524c30`: STL vector large-buffer (>=0x1000) aligned back-pointer unwrap check. */
rome2_vfs_reg_status rome2_vfs_aligned_buf_check_unalign(
    uint32_t ptr_va,
    uint32_t byte_len,
    uint32_t stored_base_va,
    uint32_t *out_free_va);

/* `0x1075c5a0`: link count 24B freelist slab entries cleanly by stride 0x18. */
rome2_vfs_reg_status rome2_vfs_slab24_link_links(
    uint32_t base_va,
    uint32_t count,
    uint32_t *out_links,
    uint32_t links_cap);

/* `0x107c9080`: MSVC _Tree_const_iterator::operator++ bounded node model. */
uint32_t rome2_vfs_rbtree_step_next(
    const rome2_vfs_rbtree_node16 *nodes,
    uint32_t node_count,
    uint32_t cur_idx);

/* `0x107e0650`: range find of ASCII string in slice [begin_idx, end_idx). */
uint32_t rome2_vfs_cstr_range_find_idx(
    const char *const *items,
    uint32_t begin_idx,
    uint32_t end_idx,
    const char *key);

/* `0x10cb03c0`: read 2-byte LE length prefix followed by UTF-16 units from stream. */
rome2_vfs_reg_status rome2_vfs_stream_read_u16_len_prefixed_wstr(
    const uint8_t *src,
    uint32_t src_len,
    uint32_t *inout_pos,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_chars);

/* `0x10f78370`, `0x10f89bf0`, `0x10fa5da0`, `0x10fd6c90..0x10fd9660` channel & bit helpers. */
uint8_t rome2_vfs_channel_slot_is_valid(uint32_t ch_idx, uint32_t state_word);

void rome2_vfs_channel_hdr24_copy(
    rome2_vfs_channel_slot_hdr24_32 *dst,
    const rome2_vfs_channel_slot_hdr24_32 *src);

void rome2_vfs_channel_hdr24_bind(
    rome2_vfs_channel_slot_hdr24_32 *slot,
    const rome2_vfs_channel_slot_hdr24_32 *src,
    uint8_t close_only);

rome2_vfs_reg_status rome2_vfs_bit_cursor_consume(
    rome2_vfs_bit_cursor12_32 *cur,
    uint32_t consume_bits,
    uint32_t *out_avail_before);

void rome2_vfs_bit_cursor_normalize_tail(rome2_vfs_bit_cursor12_32 *cur);

/* `0x1103d530`: reset count 12B bucket descriptors safely. */
void rome2_vfs_bucket12_reset_range(
    rome2_vfs_bucket_slot12_32 *slots,
    uint32_t count,
    uint32_t base_guest_va);

#ifdef __cplusplus
}
#endif

#endif

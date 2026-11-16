#include "vfs_fs_engine_channel_ops.h"

#include <string.h>

/* `0x10238c90`: scan UTF-16 format string stripping repeated L'l' length prefixes and '%%'. */
rome2_vfs_reg_status rome2_vfs_scan_lfmt_token_wstr(
    const uint16_t *fmt,
    uint32_t fmt_len,
    uint16_t *inout_idx,
    uint16_t *out_buf,
    uint32_t *inout_out_len,
    uint32_t out_cap,
    uint8_t *out_hit_spec) {
    if (!fmt || !inout_idx || !out_buf || !inout_out_len || !out_hit_spec || out_cap == 0u || fmt_len > 0xffffu) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_hit_spec = 0u;
    uint16_t i = *inout_idx;
    while (i < (uint16_t)fmt_len) {
        uint16_t ch = fmt[i];
        if (ch == L'%') {
            do {
                i += 1u;
                if (i >= (uint16_t)fmt_len) {
                    *inout_idx = i;
                    return ROME2_VFS_REG_NOT_FOUND;
                }
                ch = fmt[i];
            } while (ch == L'l');
            if (ch != L'%') {
                *inout_idx = i;
                *out_hit_spec = 1u;
                return ROME2_VFS_REG_OK;
            }
        }
        if (*inout_out_len + 1u >= out_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_buf[*inout_out_len] = ch;
        *inout_out_len += 1u;
        out_buf[*inout_out_len] = 0u;
        i += 1u;
    }
    *inout_idx = i;
    return ROME2_VFS_REG_OK;
}

/* `0x1039db80`: MSVC _Ref_count_base::_Decref strong/weak decrement model. */
rome2_vfs_reg_status rome2_vfs_refcount_decref(
    rome2_vfs_refcount_ctrl12_32 *ctrl,
    uint8_t *out_destroyed,
    uint8_t *out_deleted) {
    if (!ctrl || !out_destroyed || !out_deleted) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_destroyed = 0u;
    *out_deleted = 0u;
    if (ctrl->uses_04 <= 0) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    ctrl->uses_04 -= 1;
    if (ctrl->uses_04 == 0) {
        *out_destroyed = 1u;
        if (ctrl->weaks_08 > 0) {
            ctrl->weaks_08 -= 1;
            if (ctrl->weaks_08 == 0) {
                *out_deleted = 1u;
            }
        }
    }
    return ROME2_VFS_REG_OK;
}

/* `0x10524c30`: STL vector >=0x1000 alignment back-pointer sanity check. */
rome2_vfs_reg_status rome2_vfs_aligned_buf_check_unalign(
    uint32_t ptr_va,
    uint32_t byte_len,
    uint32_t stored_base_va,
    uint32_t *out_free_va) {
    if (!out_free_va || ptr_va == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    uint32_t aligned_len = byte_len & 0xfffffffcu;
    if (aligned_len >= 0x1000u) {
        if (ptr_va < stored_base_va + 4u) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        uint32_t diff = ptr_va - stored_base_va - 4u;
        if (diff > 0x1fu) {
            return ROME2_VFS_REG_INVALID_STATE;
        }
        *out_free_va = stored_base_va;
    } else {
        *out_free_va = ptr_va;
    }
    return ROME2_VFS_REG_OK;
}

/* `0x1075c5a0`: build next-pointer chain across 24B slab elements ending with 0. */
rome2_vfs_reg_status rome2_vfs_slab24_link_links(
    uint32_t base_va,
    uint32_t count,
    uint32_t *out_links,
    uint32_t links_cap) {
    if (!out_links || count > links_cap) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    for (uint32_t i = 0u; i < count; ++i) {
        out_links[i] = (i + 1u < count) ? (base_va + (i + 1u) * 0x18u) : 0u;
    }
    return ROME2_VFS_REG_OK;
}

/* `0x107c9080`: MSVC _Tree_const_iterator::operator++ bounded RB-tree traversal. */
uint32_t rome2_vfs_rbtree_step_next(
    const rome2_vfs_rbtree_node16 *nodes,
    uint32_t node_count,
    uint32_t cur_idx) {
    if (!nodes || cur_idx >= node_count) {
        return cur_idx;
    }
    if (nodes[cur_idx].is_nil != 0u) {
        return cur_idx;
    }
    uint32_t right = nodes[cur_idx].right;
    if (right < node_count && nodes[right].is_nil == 0u) {
        uint32_t walk = right;
        uint32_t steps = 0u;
        while (walk < node_count && nodes[walk].left < node_count &&
               nodes[nodes[walk].left].is_nil == 0u && steps < node_count) {
            walk = nodes[walk].left;
            steps += 1u;
        }
        return walk;
    }
    uint32_t cur = cur_idx;
    uint32_t parent = nodes[cur].parent;
    uint32_t steps = 0u;
    while (parent < node_count && nodes[parent].is_nil == 0u &&
           cur == nodes[parent].right && steps < node_count) {
        cur = parent;
        parent = nodes[cur].parent;
        steps += 1u;
    }
    if (parent < node_count) {
        return parent;
    }
    return cur_idx;
}

/* `0x107e0650`: find first matching key index in [begin_idx, end_idx) else end_idx. */
uint32_t rome2_vfs_cstr_range_find_idx(
    const char *const *items,
    uint32_t begin_idx,
    uint32_t end_idx,
    const char *key) {
    if (!items || !key || begin_idx >= end_idx) {
        return end_idx;
    }
    for (uint32_t i = begin_idx; i < end_idx; ++i) {
        if (items[i] && strcmp(items[i], key) == 0) {
            return i;
        }
    }
    return end_idx;
}

/* `0x10cb03c0`: deserialize u16-length-prefixed UTF-16LE string from byte stream. */
rome2_vfs_reg_status rome2_vfs_stream_read_u16_len_prefixed_wstr(
    const uint8_t *src,
    uint32_t src_len,
    uint32_t *inout_pos,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_chars) {
    if (!src || !inout_pos || !out_wstr || !out_chars || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    uint32_t pos = *inout_pos;
    if (pos > src_len || src_len - pos < 2u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    uint32_t count = (uint32_t)src[pos] | ((uint32_t)src[pos + 1u] << 8u);
    pos += 2u;
    if (count * 2u > src_len - pos || count + 1u > out_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (uint32_t i = 0u; i < count; ++i) {
        out_wstr[i] = (uint16_t)((uint16_t)src[pos] | ((uint16_t)src[pos + 1u] << 8u));
        pos += 2u;
    }
    out_wstr[count] = 0u;
    *inout_pos = pos;
    *out_chars = count;
    return ROME2_VFS_REG_OK;
}

/* `0x10f78370`/`0x10f89bf0`/`0x10fa5da0`: check 20-channel table bounds & active state=1. */
uint8_t rome2_vfs_channel_slot_is_valid(uint32_t ch_idx, uint32_t state_word) {
    return (ch_idx < ROME2_VFS_L37_MAX_CHANNELS && state_word == 1u) ? 1u : 0u;
}

/* `0x10fd74d0`: copy 20-byte address/socket header fields of channel_slot_hdr24_32. */
void rome2_vfs_channel_hdr24_copy(
    rome2_vfs_channel_slot_hdr24_32 *dst,
    const rome2_vfs_channel_slot_hdr24_32 *src) {
    if (!dst || !src) {
        return;
    }
    dst->addr_dword_00 = src->addr_dword_00;
    dst->port_or_tag_04 = src->port_or_tag_04;
    dst->id_lo_08 = src->id_lo_08;
    dst->id_hi_0c = src->id_hi_0c;
    dst->sock_fd_10 = src->sock_fd_10;
}

/* `0x10fd6c90`/`0x10fd7a70`/`0x10fd9660`: bind or reset channel_slot_hdr24_32 active state. */
void rome2_vfs_channel_hdr24_bind(
    rome2_vfs_channel_slot_hdr24_32 *slot,
    const rome2_vfs_channel_slot_hdr24_32 *src,
    uint8_t close_only) {
    if (!slot) {
        return;
    }
    if (close_only != 0u || !src) {
        slot->addr_dword_00 = 0u;
        slot->port_or_tag_04 = 0u;
        slot->id_lo_08 = 0u;
        slot->id_hi_0c = 0u;
        slot->sock_fd_10 = 0xffffffffu;
        slot->active_flag_14 = 0u;
        return;
    }
    rome2_vfs_channel_hdr24_copy(slot, src);
    slot->active_flag_14 = (src->sock_fd_10 != 0xffffffffu) ? 1u : 0u;
}

/* `0x10fd77f0`: compute available bits `(byte_cap_04 * 8) - bits_used_08` & consume bits. */
rome2_vfs_reg_status rome2_vfs_bit_cursor_consume(
    rome2_vfs_bit_cursor12_32 *cur,
    uint32_t consume_bits,
    uint32_t *out_avail_before) {
    if (!cur || !out_avail_before || cur->byte_cap_04 > 0x1fffffffu) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    uint32_t total_bits = cur->byte_cap_04 * 8u;
    if (cur->bits_used_08 > total_bits) {
        return ROME2_VFS_REG_INVALID_STATE;
    }
    uint32_t avail = total_bits - cur->bits_used_08;
    *out_avail_before = avail;
    if (consume_bits > cur->bits_used_08) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    cur->bits_used_08 -= consume_bits;
    return ROME2_VFS_REG_OK;
}

/* `0x10fd7b10`: fold full bytes out of bits_used_08 >= 8 matching shr 3 / and 7. */
void rome2_vfs_bit_cursor_normalize_tail(rome2_vfs_bit_cursor12_32 *cur) {
    if (!cur) {
        return;
    }
    if (cur->bits_used_08 > 7u) {
        uint32_t full_bytes = cur->bits_used_08 >> 3u;
        if (cur->byte_cap_04 >= full_bytes) {
            cur->byte_cap_04 -= full_bytes;
        } else {
            cur->byte_cap_04 = 0u;
        }
        cur->bits_used_08 &= 7u;
    }
}

/* `0x1103d530`: reset contiguous array of count 12B bucket headers to empty sentinels. */
void rome2_vfs_bucket12_reset_range(
    rome2_vfs_bucket_slot12_32 *slots,
    uint32_t count,
    uint32_t base_guest_va) {
    if (!slots) {
        return;
    }
    for (uint32_t i = 0u; i < count; ++i) {
        rome2_vfs_bucket12_reset_empty(&slots[i], base_guest_va + i * 0x0cu);
    }
}

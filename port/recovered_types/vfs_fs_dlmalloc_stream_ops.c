#include "vfs_fs_dlmalloc_stream_ops.h"

#include <string.h>

static uint8_t is_pow2_u32(uint32_t x) {
    return (x != 0u && (x & (x - 1u)) == 0u) ? 1u : 0u;
}

static uint32_t bsr_u32(uint32_t x) {
    uint32_t pos = 0u;
    while (x > 1u) {
        x >>= 1u;
        pos += 1u;
    }
    return pos;
}

/* `0x10123640`: validate power-of-2 OS page sizes and seed dlmalloc mparams28_32. */
rome2_vfs_reg_status rome2_vfs_dlmalloc_init_mparams(
    rome2_vfs_dlmalloc_mparams28_32 *params,
    uint32_t page_size,
    uint32_t granularity,
    uint32_t tick_count) {
    if (!params) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (!is_pow2_u32(page_size) || !is_pow2_u32(granularity)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (params->magic_04 == 0u) {
        params->granularity_0c = granularity;
        params->page_size_08 = page_size;
        params->mmap_threshold_10 = 0x40000u;
        params->trim_threshold_14 = 0x200000u;
        params->default_mflags_18 = 7u;
        params->magic_04 = ((tick_count ^ 0x55555550u) & 0xfffffff8u) | 8u;
    }
    params->spinlock_00 = 0u;
    return ROME2_VFS_REG_OK;
}

/* `0x101242e8..0x10124315`: dlmalloc compute_tree_index(nb) matching bsr formula. */
uint32_t rome2_vfs_dlmalloc_tree_idx(uint32_t nb) {
    uint32_t x = nb >> 8u;
    if (x == 0u) {
        return 0u;
    }
    if (x > 0xffffu) {
        return 31u;
    }
    uint32_t k = bsr_u32(x);
    uint32_t shift = k + 7u;
    uint32_t bit = (shift < 32u) ? ((nb >> shift) & 1u) : 0u;
    return (k << 1u) + bit;
}

/* `0x1012432f..0x10124341` / `0x10123d29..0x10123d3b`: treebin traversal leftshift. */
uint32_t rome2_vfs_dlmalloc_tree_step_shift(uint32_t idx) {
    if (idx == 31u) {
        return 0u;
    }
    return 25u - (idx >> 1u);
}

/* `0x10123e20..0x10123e2d`: spinlock backoff yield predicate (iter & 0x2710) == 0. */
uint8_t rome2_vfs_dlmalloc_spin_should_sleep(uint32_t iteration) {
    return (iteration & 0x2710u) == 0u ? 1u : 0u;
}

/* `0x101241b5..0x101241db`: sys_trim free-top computation aligned to allocation granularity. */
uint8_t rome2_vfs_dlmalloc_sys_trim_calc(
    uint32_t topsize,
    uint32_t pad,
    uint32_t granularity,
    uint32_t *out_extra) {
    if (out_extra) {
        *out_extra = 0u;
    }
    if (granularity == 0u || pad > 0xffffffbfu) {
        return 0u;
    }
    uint32_t keep = pad + 0x28u;
    if (topsize <= keep) {
        return 0u;
    }
    uint32_t diff = topsize - keep;
    if (diff > 0xffffffffu - (granularity - 1u)) {
        return 0u;
    }
    uint32_t aligned_up = ((diff + granularity - 1u) / granularity) * granularity;
    if (aligned_up <= granularity) {
        return 0u;
    }
    uint32_t extra = aligned_up - granularity;
    if (out_extra) {
        *out_extra = extra;
    }
    return extra != 0u ? 1u : 0u;
}

/* `0x100d1790`: scan ASCII format segment ignoring 'l' length prefixes and unescaping '%%'. */
rome2_vfs_reg_status rome2_vfs_scan_lfmt_token_ascii(
    const char *fmt,
    uint16_t *inout_idx,
    char *out_buf,
    uint32_t *inout_out_len,
    uint32_t out_cap,
    uint8_t *out_hit_spec) {
    if (!fmt || !inout_idx || !out_buf || !inout_out_len || !out_hit_spec || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_hit_spec = 0u;
    size_t slen = strlen(fmt);
    if (slen > 0xffffu) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    uint16_t fmt_len = (uint16_t)slen;
    uint16_t i = *inout_idx;
    while (i < fmt_len) {
        char ch = fmt[i];
        if (ch == '%') {
            do {
                i += 1u;
                if (i >= fmt_len) {
                    *inout_idx = i;
                    return ROME2_VFS_REG_NOT_FOUND;
                }
                ch = fmt[i];
            } while (ch == 'l');
            if (ch != '%') {
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
        out_buf[*inout_out_len] = '\0';
        i += 1u;
    }
    *inout_idx = i;
    return ROME2_VFS_REG_OK;
}

/* `0x100f3150`: push_back single byte onto bounded NUL-terminated ASCII string buffer. */
rome2_vfs_reg_status rome2_vfs_cstr_push_back(
    char *buf,
    uint32_t *inout_len,
    uint32_t buf_cap,
    char ch) {
    if (!buf || !inout_len || buf_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (*inout_len + 2u > buf_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    buf[*inout_len] = ch;
    *inout_len += 1u;
    buf[*inout_len] = '\0';
    return ROME2_VFS_REG_OK;
}

/* `0x100f6f30`: close mapped view & Win32 handles in handle36, resetting state=3. */
void rome2_vfs_stream_handle36_close(rome2_vfs_stream_handle36_32 *handle) {
    if (!handle) {
        return;
    }
    if (handle->byte_flag_1c != 0u) {
        handle->mapped_view_ptr_20 = 0u;
        if (handle->secondary_handle_0c != 0xffffffffu && (handle->owned_flags_04 & 2u) != 0u) {
            handle->owned_flags_04 ^= 2u;
            handle->secondary_handle_0c = 0xffffffffu;
        }
        if (handle->primary_handle_08 != 0xffffffffu && (handle->owned_flags_04 & 1u) != 0u) {
            handle->owned_flags_04 ^= 1u;
            handle->primary_handle_08 = 0xffffffffu;
        }
        handle->byte_flag_1c = 0u;
    }
    handle->state_words_10[0] = 0u;
    handle->state_words_10[1] = 0u;
    handle->state_words_10[2] = 0u;
    handle->state_tag_00 = 3u;
}

/* `0x100ffbb0`: forward find of single uint16_t code unit starting at clamped start_pos. */
int32_t rome2_vfs_wstr_find_wchar(
    const uint16_t *buf,
    uint32_t len,
    uint16_t needle,
    uint32_t start_pos) {
    if (!buf && len != 0u) {
        return -1;
    }
    uint32_t pos = (start_pos < len) ? start_pos : len;
    while (pos < len) {
        if (buf[pos] == needle) {
            return (int32_t)pos;
        }
        pos += 1u;
    }
    return -1;
}

/* `0x100db960`: reverse UTF-16 xor-shift hash seeded at 0xf73a51c9. */
uint32_t rome2_vfs_hash_wstr_xor(const uint16_t *wstr, uint32_t len) {
    uint32_t hash = 0xf73a51c9u;
    if (!wstr || len == 0u) {
        return hash;
    }
    uint32_t shift = 0u;
    for (uint32_t idx = len; idx > 0u; --idx) {
        uint32_t unit = (uint32_t)wstr[idx - 1u];
        hash ^= (unit << shift);
        shift = (shift + 8u) & 0x1fu;
    }
    return hash;
}

/* `0x100e10c0`: alternating signed-byte sum pair hash packed in 2x16-bit halves. */
uint32_t rome2_vfs_hash_cstr_pairsum(const char *str) {
    if (!str) {
        return 0u;
    }
    int16_t even_sum = 0;
    int16_t odd_sum = 0;
    size_t i = 0u;
    while (str[i] != '\0') {
        int8_t b0 = (int8_t)str[i];
        even_sum = (int16_t)((uint16_t)even_sum + (uint16_t)(int16_t)b0);
        i += 1u;
        if (str[i] == '\0') {
            break;
        }
        int8_t b1 = (int8_t)str[i];
        odd_sum = (int16_t)((uint16_t)odd_sum + (uint16_t)(int16_t)b1);
        i += 1u;
    }
    return ((uint32_t)(uint16_t)even_sum) | (((uint32_t)(uint16_t)odd_sum) << 16u);
}

/* `0x113682d0`: handle table bucket hash `(key ^ 0x4a545eed) % bucket_count`. */
uint32_t rome2_vfs_handle_table_bucket(uint32_t key, uint32_t bucket_count) {
    if (bucket_count == 0u) {
        return 0u;
    }
    return (key ^ 0x4a545eedu) % bucket_count;
}

/* `0x100e3950`: reset 12B intrusive bucket slot header to self-sentinel {slot+4, 0, 0}. */
void rome2_vfs_bucket12_reset_empty(rome2_vfs_bucket_slot12_32 *slot, uint32_t guest_slot_va) {
    if (!slot) {
        return;
    }
    slot->end_or_self_04 = 0u;
    slot->begin_00 = guest_slot_va + 4u;
    slot->tail_ptr_08 = 0u;
}

/* `0x11346d60`: write wchar followed by max(width-1, 0) fill_ch units. */
rome2_vfs_reg_status rome2_vfs_wstr_pad_write(
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t *inout_len,
    uint16_t ch,
    uint32_t field_width,
    uint16_t fill_ch) {
    if (!dst || !inout_len) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    uint32_t pad = (field_width > 1u) ? (field_width - 1u) : 0u;
    if (*inout_len + 1u + pad >= dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    dst[*inout_len] = ch;
    *inout_len += 1u;
    for (uint32_t i = 0u; i < pad; ++i) {
        dst[*inout_len] = fill_ch;
        *inout_len += 1u;
    }
    dst[*inout_len] = 0u;
    return ROME2_VFS_REG_OK;
}

/* `0x11348d50`: num_get<wchar_t>::_Getifld signed base-10/base-16 integer token extractor. */
rome2_vfs_reg_status rome2_vfs_wstreambuf_get_ifld(
    const uint16_t *wbuf,
    uint32_t len,
    uint32_t ios_flags,
    char *out_ascii,
    uint32_t out_cap,
    int32_t *out_base) {
    if (!wbuf || !out_ascii || !out_base || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    uint32_t pos = 0u;
    uint32_t wr = 0u;
    if (pos < len && (wbuf[pos] == L'+' || wbuf[pos] == L'-')) {
        if (wr + 1u >= out_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_ascii[wr++] = (char)wbuf[pos++];
    }
    int32_t base = ((ios_flags & 0xcu) == 8u) ? 16 : 10;
    uint8_t saw_zero = 0u;
    uint8_t non_zero = 0u;
    if (pos < len && wbuf[pos] == L'0') {
        saw_zero = 1u;
        pos += 1u;
        if (pos < len && (wbuf[pos] == L'x' || wbuf[pos] == L'X') && (ios_flags & 0xcu) == 8u) {
            base = 16;
            saw_zero = 0u;
            pos += 1u;
        }
    }
    const char *digits = "0123456789abcdefABCDEF";
    uint32_t allowed = (base == 10) ? 10u : 22u;
    while (pos < len) {
        uint16_t ch = wbuf[pos];
        if (ch > 0x7fu) {
            break;
        }
        char c = (char)ch;
        const char *hit = NULL;
        for (uint32_t k = 0u; k < allowed; ++k) {
            if (digits[k] == c) {
                hit = &digits[k];
                break;
            }
        }
        if (!hit) {
            break;
        }
        if (non_zero != 0u || c != '0') {
            if (wr + 1u < out_cap && wr < 31u) {
                out_ascii[wr++] = c;
            }
            non_zero = 1u;
        } else {
            saw_zero = 1u;
        }
        pos += 1u;
    }
    if (non_zero == 0u && saw_zero != 0u) {
        if (wr + 1u >= out_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_ascii[wr++] = '0';
    } else if (non_zero == 0u) {
        out_ascii[0] = '\0';
        *out_base = base;
        return ROME2_VFS_REG_NOT_FOUND;
    }
    out_ascii[wr] = '\0';
    *out_base = base;
    return ROME2_VFS_REG_OK;
}

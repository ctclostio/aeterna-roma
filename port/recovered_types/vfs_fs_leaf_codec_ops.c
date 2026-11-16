#include "vfs_fs_leaf_codec_ops.h"

#include <string.h>

void rome2_vfs_stream_handle36_init(rome2_vfs_stream_handle36_32 *handle) {
    if (!handle) {
        return;
    }
    handle->state_tag_00 = 3u;
    handle->owned_flags_04 = 0u;
    handle->primary_handle_08 = 0xffffffffu;
    handle->secondary_handle_0c = 0xffffffffu;
    handle->state_words_10[0] = 0u;
    handle->state_words_10[1] = 0u;
    handle->state_words_10[2] = 0u;
    handle->byte_flag_1c = 0u;
    handle->pad_1d[0] = 0u;
    handle->pad_1d[1] = 0u;
    handle->pad_1d[2] = 0u;
    handle->mapped_view_ptr_20 = 0u;
}

void rome2_vfs_stream_handle36_destroy(rome2_vfs_stream_handle36_32 *handle) {
    if (!handle) {
        return;
    }
    handle->state_tag_00 = 3u;
    handle->mapped_view_ptr_20 = 0u;
    if (handle->secondary_handle_0c != 0xffffffffu && (handle->owned_flags_04 & 2u) != 0u) {
        handle->owned_flags_04 ^= 2u;
        handle->secondary_handle_0c = 0xffffffffu;
    }
    if (handle->primary_handle_08 != 0xffffffffu && (handle->owned_flags_04 & 1u) != 0u) {
        handle->owned_flags_04 ^= 1u;
        handle->primary_handle_08 = 0xffffffffu;
    }
}

rome2_vfs_reg_status rome2_vfs_wstr_fill_repeat(
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t count,
    uint16_t fill_ch,
    uint32_t *out_len) {
    uint32_t i;
    uint32_t clipped = count & 0xffffu;
    if (!dst || dst_cap == 0u || !out_len) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (clipped + 1u > dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (i = 0u; i < clipped; ++i) {
        dst[i] = fill_ch;
    }
    dst[clipped] = 0u;
    *out_len = clipped;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_wstr_assign_raw(
    uint16_t *dst,
    uint32_t *inout_cap,
    uint32_t max_cap,
    const uint16_t *src,
    uint32_t *out_len) {
    uint32_t len = 0u;
    if (!dst || !inout_cap || !src || !out_len || max_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    while (src[len] != 0u) {
        ++len;
        if (len >= max_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
    }
    if (len + 1u > *inout_cap) {
        uint32_t grown = 0u;
        rome2_vfs_reg_status st = rome2_vfs_wstr_reserve_grow(*inout_cap, len + 1u, &grown);
        if (st != ROME2_VFS_REG_OK || grown > max_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        *inout_cap = grown;
    }
    memcpy(dst, src, ((size_t)len + 1u) * sizeof(uint16_t));
    *out_len = len;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_wstr_append(
    uint16_t *dst,
    uint32_t *inout_len,
    uint32_t dst_cap,
    const uint16_t *suffix,
    uint32_t suffix_len) {
    uint32_t base_len;
    if (!dst || !inout_len || !suffix || dst_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    base_len = *inout_len;
    if (suffix_len >= dst_cap || base_len >= dst_cap - suffix_len) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (suffix_len > 0u) {
        memcpy(dst + base_len, suffix, (size_t)suffix_len * sizeof(uint16_t));
    }
    dst[base_len + suffix_len] = 0u;
    *inout_len = base_len + suffix_len;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_wstr_reserve_grow(
    uint32_t current_cap,
    uint32_t required_cap,
    uint32_t *out_new_cap) {
    uint32_t doubled;
    if (!out_new_cap) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (required_cap <= current_cap) {
        *out_new_cap = current_cap;
        return ROME2_VFS_REG_OK;
    }
    if (current_cap > 0x7fffffffu) {
        current_cap = 0x7fffffffu;
    }
    doubled = current_cap * 2u;
    *out_new_cap = doubled < required_cap ? required_cap : doubled;
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_astr_not_equal(const char *lhs, const char *rhs) {
    size_t l_len;
    size_t r_len;
    if (!lhs || !rhs) {
        return lhs != rhs ? 1u : 0u;
    }
    l_len = strlen(lhs);
    r_len = strlen(rhs);
    if (l_len != r_len) {
        return 1u;
    }
    return memcmp(lhs, rhs, l_len) != 0 ? 1u : 0u;
}

rome2_vfs_reg_status rome2_vfs_str_concat_join(
    char *out_buf,
    uint32_t out_cap,
    const char *lhs,
    const char *rhs) {
    size_t l_len;
    size_t r_len;
    if (!out_buf || out_cap == 0u || !lhs || !rhs) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    l_len = strlen(lhs);
    r_len = strlen(rhs);
    if (l_len + 1u > (size_t)out_cap || r_len > (size_t)out_cap - l_len - 1u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memcpy(out_buf, lhs, l_len);
    memcpy(out_buf + l_len, rhs, r_len);
    out_buf[l_len + r_len] = '\0';
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_astr_append_cstr(
    char *dst,
    uint32_t *inout_len,
    uint32_t dst_cap,
    const char *suffix) {
    size_t slen;
    uint32_t base_len;
    if (!dst || !inout_len || !suffix || dst_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    base_len = *inout_len;
    slen = strlen(suffix);
    if (slen >= dst_cap || base_len >= dst_cap - (uint32_t)slen) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memcpy(dst + base_len, suffix, slen);
    dst[base_len + (uint32_t)slen] = '\0';
    *inout_len = base_len + (uint32_t)slen;
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_astr_rfind_char(const char *str, char ch, uint32_t max_pos) {
    size_t len;
    size_t pos;
    if (!str) {
        return 0xffffffffu;
    }
    len = strlen(str);
    pos = len < (size_t)max_pos ? len : (size_t)max_pos;
    while (pos > 0u) {
        --pos;
        if (str[pos] == ch) {
            return (uint32_t)pos;
        }
    }
    return 0xffffffffu;
}

uint32_t rome2_vfs_map_win32_error_io(uint32_t win32_err) {
    switch (win32_err) {
        case 0u: return 0u;
        case 2u:
        case 3u:
        case 6u: return 3u;
        case 5u:
        case 0xdu: return 7u;
        case 8u:
        case 0xeu: return 6u;
        case 0x16u: return 0x16u;
        case 0x20u: return 0x15u;
        case 0x26u: return 1u;
        case 0x57u: return 0x13u;
        case 0x7bu: return 0x14u;
        case 0xb7u: return 4u;
        case 0x3e5u: return 2u;
        case 0x3eeu: return 0x17u;
        default: return 0x18u;
    }
}

uint32_t rome2_vfs_map_win32_error_stream(uint32_t win32_err) {
    switch (win32_err) {
        case 0u: return 0u;
        case 2u:
        case 3u:
        case 6u: return 3u;
        case 5u: return 7u;
        case 0x20u: return 0x15u;
        case 0x26u: return 1u;
        case 0x57u: return 0x13u;
        case 0x7bu: return 0x14u;
        case 0xb7u: return 4u;
        case 0x3e5u: return 2u;
        case 0x3e6u: return 0x13u;
        case 0x718u: return 6u;
        default: return 0x18u;
    }
}

uint8_t rome2_vfs_check_u64_budget_limit(
    uint32_t avail_lo,
    uint32_t avail_hi,
    uint32_t req_lo,
    uint32_t req_hi) {
    if (avail_hi != req_hi) {
        return avail_hi > req_hi ? 1u : 0u;
    }
    return avail_lo >= req_lo ? 1u : 0u;
}

rome2_vfs_reg_status rome2_vfs_utf8_to_utf16_dispatch_probe(
    const char *utf8_src,
    uint16_t *utf16_out,
    uint32_t out_cap,
    uint32_t *out_len) {
    return rome2_vfs_utf8_to_utf16(utf8_src, utf16_out, out_cap, out_len);
}

uint32_t rome2_vfs_wait_event_guard_probe(uint8_t init_ok, uint32_t signaled_val) {
    return init_ok != 0u ? signaled_val : 0u;
}

rome2_vfs_reg_status rome2_vfs_normalize_slashes_and_lower(
    const char *in_path,
    char *out_path,
    uint32_t out_cap,
    uint8_t *out_changed) {
    size_t i;
    size_t len;
    uint32_t written = 0u;
    char prev_ch = '\0';
    uint8_t changed = 0u;

    if (!in_path || !out_path || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    len = strlen(in_path);
    if (len >= 0x7f0u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (i = 0u; i < len; ++i) {
        unsigned char raw = (unsigned char)in_path[i];
        char ch = (char)raw;
        if (ch == '/') {
            ch = '\\';
            changed = 1u;
        }
        if (i == 1u && written > 0u && out_path[written - 1u] == '\\' && ch != '\\') {
            written -= 1u;
        }
        if (ch == '\\' && prev_ch == '\\' && i > 1u) {
            changed = 1u;
            continue;
        }
        if ((unsigned char)(ch - 'A') <= (unsigned char)('Z' - 'A')) {
            ch = (char)(ch + 0x20);
        }
        if (written + 1u >= out_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_path[written++] = ch;
        prev_ch = ch;
    }
    out_path[written] = '\0';
    if (out_changed) {
        *out_changed = changed;
    }
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_map_seek_result(uint8_t seek_ok, uint32_t last_error) {
    return seek_ok != 0u ? 0u : rome2_vfs_map_win32_error_io(last_error);
}

uint32_t rome2_vfs_probe_file_size_state(
    rome2_vfs_file_size_state8_32 *state,
    uint32_t reported_size_or_neg1,
    uint32_t last_error) {
    if (!state) {
        return 0xffffffffu;
    }
    if (reported_size_or_neg1 == 0xffffffffu) {
        state->last_error_04 = last_error;
    } else {
        state->last_error_04 = 0u;
    }
    return reported_size_or_neg1;
}

void rome2_vfs_dlmalloc_model_init(rome2_vfs_dlmalloc_model *model) {
    if (!model) {
        return;
    }
    memset(model, 0, sizeof(*model));
    model->mstate.topsize_0c = ROME2_VFS_L34_DLMALLOC_ARENA_CAP;
    model->mstate.trim_check_1c = ROME2_VFS_L34_DLMALLOC_ARENA_CAP;
    model->mstate.least_addr_10 = 1u;
}

uint32_t rome2_vfs_dlmalloc_request_size(uint32_t user_bytes) {
    if (user_bytes < 11u) {
        return 16u;
    }
    if (user_bytes >= 0xffffffc0u) {
        return 0xffffffffu;
    }
    return (user_bytes + 11u) & ~7u;
}

uint8_t *rome2_vfs_dlmalloc_model_alloc(rome2_vfs_dlmalloc_model *model, uint32_t user_bytes) {
    uint32_t chunk_sz;
    uint32_t i;
    if (!model) {
        return NULL;
    }
    chunk_sz = rome2_vfs_dlmalloc_request_size(user_bytes);
    if (chunk_sz == 0xffffffffu) {
        return NULL;
    }
    for (i = 0u; i < model->alloc_count; ++i) {
        if (model->slots[i].in_use == 0u && model->slots[i].size >= chunk_sz) {
            uint32_t bin = model->slots[i].size >> 3u;
            model->slots[i].in_use = 1u;
            model->slots[i].req_size = chunk_sz;
            if (bin < 32u) {
                model->mstate.smallmap_00 &= ~(1u << bin);
            } else {
                model->mstate.treemap_04 &= ~(1u << (bin & 31u));
            }
            return &model->arena[model->slots[i].offset];
        }
    }
    if (model->alloc_count >= ROME2_VFS_L34_DLMALLOC_MAX_ALLOCS) {
        return NULL;
    }
    if (chunk_sz > ROME2_VFS_L34_DLMALLOC_ARENA_CAP - model->arena_used) {
        return NULL;
    }
    i = model->alloc_count++;
    model->slots[i].in_use = 1u;
    model->slots[i].offset = model->arena_used;
    model->slots[i].size = chunk_sz;
    model->slots[i].req_size = chunk_sz;
    model->arena_used += chunk_sz;
    model->mstate.topsize_0c = ROME2_VFS_L34_DLMALLOC_ARENA_CAP - model->arena_used;
    model->mstate.footprint_1b0 = model->arena_used;
    if (model->arena_used > model->mstate.max_footprint_1b4) {
        model->mstate.max_footprint_1b4 = model->arena_used;
    }
    return &model->arena[model->slots[i].offset];
}

void rome2_vfs_dlmalloc_model_free(rome2_vfs_dlmalloc_model *model, uint8_t *ptr) {
    uintptr_t base;
    uintptr_t addr;
    uint32_t off;
    uint32_t i;
    if (!model || !ptr) {
        return;
    }
    base = (uintptr_t)model->arena;
    addr = (uintptr_t)ptr;
    if (addr < base || addr >= base + ROME2_VFS_L34_DLMALLOC_ARENA_CAP) {
        return;
    }
    off = (uint32_t)(addr - base);
    for (i = 0u; i < model->alloc_count; ++i) {
        if (model->slots[i].in_use != 0u && model->slots[i].offset == off) {
            uint32_t bin = model->slots[i].size >> 3u;
            model->slots[i].in_use = 0u;
            if (bin < 32u) {
                model->mstate.smallmap_00 |= (1u << bin);
            } else {
                model->mstate.treemap_04 |= (1u << (bin & 31u));
            }
            return;
        }
    }
}

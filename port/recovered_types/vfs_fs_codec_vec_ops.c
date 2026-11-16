#include "vfs_fs_codec_vec_ops.h"

#include <stdio.h>
#include <string.h>

static rome2_vfs_reg_status vfs35_copy_str(char *dst, size_t cap, const char *src) {
    size_t len;
    if (!dst || !src || cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    len = strlen(src);
    if (len + 1u > cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memcpy(dst, src, len + 1u);
    return ROME2_VFS_REG_OK;
}

void rome2_vfs_fill_u16_range(uint16_t *dst, uint32_t count, uint16_t fill_ch) {
    uint32_t i;
    if (!dst) {
        return;
    }
    for (i = 0u; i < count; ++i) {
        dst[i] = fill_ch;
    }
}

rome2_vfs_reg_status rome2_vfs_wstr_concat_join(
    uint16_t *out_buf,
    uint32_t out_cap,
    uint32_t *out_len,
    const uint16_t *lhs,
    uint32_t lhs_len,
    const uint16_t *rhs,
    uint32_t rhs_len) {
    if (!out_buf || !out_len || !lhs || !rhs || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (lhs_len >= out_cap || rhs_len >= out_cap - lhs_len) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (lhs_len > 0u) {
        memcpy(out_buf, lhs, (size_t)lhs_len * sizeof(uint16_t));
    }
    if (rhs_len > 0u) {
        memcpy(out_buf + lhs_len, rhs, (size_t)rhs_len * sizeof(uint16_t));
    }
    out_buf[lhs_len + rhs_len] = 0u;
    *out_len = lhs_len + rhs_len;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_wstr_push_back(
    uint16_t *buf,
    uint32_t *inout_len,
    uint32_t buf_cap,
    uint16_t ch) {
    if (!buf || !inout_len || buf_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (*inout_len + 1u >= buf_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    buf[*inout_len] = ch;
    *inout_len += 1u;
    buf[*inout_len] = 0u;
    return ROME2_VFS_REG_OK;
}

char rome2_vfs_cstr_offset_char(const char *str, uint32_t idx) {
    size_t len;
    if (!str) {
        return '\0';
    }
    len = strlen(str);
    return (size_t)idx < len ? str[idx] : '\0';
}

char rome2_vfs_cstr_back_or_nul(const char *str) {
    size_t len;
    if (!str) {
        return '\0';
    }
    len = strlen(str);
    return len > 0u ? str[len - 1u] : '\0';
}

rome2_vfs_reg_status rome2_vfs_scan_fmt_token_ascii(
    const char *fmt,
    uint32_t *inout_idx,
    char *out_buf,
    uint32_t *inout_out_len,
    uint32_t out_cap) {
    size_t flen;
    uint32_t idx;
    if (!fmt || !inout_idx || !out_buf || !inout_out_len || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    flen = strlen(fmt);
    idx = *inout_idx;
    while ((size_t)idx < flen) {
        char ch = fmt[idx];
        if (ch == '%') {
            if ((size_t)(idx + 1u) < flen && fmt[idx + 1u] == '%') {
                idx += 1u;
            } else {
                break;
            }
        }
        if (*inout_out_len + 1u >= out_cap) {
            *inout_idx = idx;
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_buf[*inout_out_len] = ch;
        *inout_out_len += 1u;
        out_buf[*inout_out_len] = '\0';
        idx += 1u;
    }
    *inout_idx = idx;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_scan_fmt_token_wstr(
    const uint16_t *fmt,
    uint32_t fmt_len,
    uint32_t *inout_idx,
    uint16_t *out_buf,
    uint32_t *inout_out_len,
    uint32_t out_cap) {
    uint32_t idx;
    if (!fmt || !inout_idx || !out_buf || !inout_out_len || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    idx = *inout_idx;
    while (idx < fmt_len) {
        uint16_t ch = fmt[idx];
        if (ch == (uint16_t)'%') {
            if (idx + 1u < fmt_len && fmt[idx + 1u] == (uint16_t)'%') {
                idx += 1u;
            } else {
                break;
            }
        }
        if (*inout_out_len + 1u >= out_cap) {
            *inout_idx = idx;
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_buf[*inout_out_len] = ch;
        *inout_out_len += 1u;
        out_buf[*inout_out_len] = 0u;
        idx += 1u;
    }
    *inout_idx = idx;
    return ROME2_VFS_REG_OK;
}

int32_t rome2_vfs_map_thread_priority(uint32_t idx) {
    static const int32_t k_priorities[7] = { -15, -2, -1, 0, 1, 2, 15 };
    return idx < 7u ? k_priorities[idx] : 0;
}

void rome2_vfs_mem_status_ex64_init(rome2_vfs_mem_status_ex64_32 *status) {
    if (!status) {
        return;
    }
    memset(status, 0, sizeof(*status));
    status->dw_length_00 = (uint32_t)sizeof(*status);
}

rome2_vfs_reg_status rome2_vfs_sanitize_debug_pct_wstr(
    const uint16_t *in_str,
    uint16_t *out_str,
    uint32_t out_cap) {
    uint32_t i = 0u;
    if (!in_str || !out_str || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    while (in_str[i] != 0u) {
        if (i + 1u >= out_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_str[i] = in_str[i] == (uint16_t)'%' ? (uint16_t)'&' : in_str[i];
        ++i;
    }
    out_str[i] = 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_format_u32_ascii(uint32_t value, char *out_buf, uint32_t out_cap) {
    int n;
    if (!out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    n = snprintf(out_buf, (size_t)out_cap, "%u", value);
    if (n < 0 || (uint32_t)n >= out_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_format_f32_ascii(
    float value,
    uint32_t precision,
    uint8_t keep_trailing_zeros,
    char *out_buf,
    uint32_t out_cap) {
    int prec = (int)(precision & 0xffffu);
    int n;
    if (!out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (prec > 12) {
        prec = 12;
    }
    n = snprintf(out_buf, (size_t)out_cap, "%.*f", prec, (double)value);
    if (n < 0 || (uint32_t)n >= out_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (keep_trailing_zeros == 0u && prec > 0) {
        char *dot = strchr(out_buf, '.');
        if (dot) {
            size_t len = strlen(out_buf);
            while (len > 0u && out_buf[len - 1u] == '0') {
                out_buf[--len] = '\0';
            }
            if (len > 0u && out_buf[len - 1u] == '.') {
                out_buf[--len] = '\0';
            }
        }
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_hash_next_power2_buckets(uint32_t min_buckets, uint32_t *out_buckets) {
    uint32_t p = 1u;
    if (!out_buckets) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (min_buckets > ROME2_VFS_L35_HASH_BUCKET_LIMIT) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    while (p < min_buckets && p < ROME2_VFS_L35_HASH_BUCKET_LIMIT) {
        p <<= 1u;
    }
    *out_buckets = p;
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_cstr_ends_with(const char *str, const char *suffix) {
    size_t slen;
    size_t tlen;
    if (!str || !suffix) {
        return 0u;
    }
    slen = strlen(str);
    tlen = strlen(suffix);
    if (slen < tlen) {
        return 0u;
    }
    return memcmp(str + (slen - tlen), suffix, tlen) == 0 ? 1u : 0u;
}

int32_t rome2_vfs_search_list_find_idx(const char *const *items, uint32_t count, const char *key) {
    uint32_t i;
    if (!items || !key) {
        return -1;
    }
    for (i = 0u; i < count; ++i) {
        if (items[i] && strcmp(items[i], key) == 0) {
            return (int32_t)i;
        }
    }
    return -1;
}

rome2_vfs_reg_status rome2_vfs_normalize_all_dots(
    const char *in_path,
    char *out_path,
    uint32_t out_cap,
    uint8_t *out_changed) {
    char mid[ROME2_VFS_IDX_MAX_PATH * 2u];
    uint8_t ch1 = 0u;
    uint8_t ch2 = 0u;
    rome2_vfs_reg_status st;
    if (!in_path || !out_path || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = rome2_vfs_normalize_dot_segments(in_path, 0u, mid, sizeof(mid), &ch1);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = rome2_vfs_normalize_dot_segments(mid, 1u, out_path, out_cap, &ch2);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (out_changed) {
        *out_changed = (uint8_t)((ch1 != 0u || ch2 != 0u) ? 1u : 0u);
    }
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_skip_ascii_ws(const char **inout_cursor) {
    const char *p;
    if (!inout_cursor || !*inout_cursor) {
        return 0u;
    }
    p = *inout_cursor;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        ++p;
    }
    *inout_cursor = p;
    return *p != '\0' ? 1u : 0u;
}

rome2_vfs_reg_status rome2_vfs_tuple36_push_back(
    rome2_vfs_tuple36_vec *vec,
    const char *a,
    const char *b,
    const char *c) {
    rome2_vfs_tuple36_host *dst;
    rome2_vfs_reg_status st;
    if (!vec || !a || !b || !c) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (vec->count >= ROME2_VFS_L35_MAX_TUPLE_ENTRIES) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (vec->capacity == 0u) {
        vec->capacity = 1u;
    }
    while (vec->capacity <= vec->count && vec->capacity < ROME2_VFS_L35_MAX_TUPLE_ENTRIES) {
        vec->capacity *= 2u;
    }
    if (vec->capacity > ROME2_VFS_L35_MAX_TUPLE_ENTRIES) {
        vec->capacity = ROME2_VFS_L35_MAX_TUPLE_ENTRIES;
    }
    dst = &vec->entries[vec->count];
    st = vfs35_copy_str(dst->a, sizeof(dst->a), a);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = vfs35_copy_str(dst->b, sizeof(dst->b), b);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = vfs35_copy_str(dst->c, sizeof(dst->c), c);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    vec->count += 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_format_euler_ascii(
    float z,
    float y,
    float x,
    char *out_buf,
    uint32_t out_cap) {
    char sz[32], sy[32], sx[32];
    int n;
    if (!out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (rome2_vfs_format_f32_ascii(x, 6u, 0u, sx, sizeof(sx)) != ROME2_VFS_REG_OK ||
        rome2_vfs_format_f32_ascii(y, 6u, 0u, sy, sizeof(sy)) != ROME2_VFS_REG_OK ||
        rome2_vfs_format_f32_ascii(z, 6u, 0u, sz, sizeof(sz)) != ROME2_VFS_REG_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    n = snprintf(out_buf, (size_t)out_cap, "euler(%s,%s,%s)", sx, sy, sz);
    if (n < 0 || (uint32_t)n >= out_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_format_vec3_ascii(
    float x,
    float y,
    float z,
    char *out_buf,
    uint32_t out_cap) {
    char sx[32], sy[32], sz[32];
    int n;
    if (!out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (rome2_vfs_format_f32_ascii(x, 6u, 0u, sx, sizeof(sx)) != ROME2_VFS_REG_OK ||
        rome2_vfs_format_f32_ascii(y, 6u, 0u, sy, sizeof(sy)) != ROME2_VFS_REG_OK ||
        rome2_vfs_format_f32_ascii(z, 6u, 0u, sz, sizeof(sz)) != ROME2_VFS_REG_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    n = snprintf(out_buf, (size_t)out_cap, "vector(%s,%s,%s)", sx, sy, sz);
    if (n < 0 || (uint32_t)n >= out_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_format_vec4i_ascii(
    int32_t x,
    int32_t y,
    int32_t z,
    int32_t w,
    char *out_buf,
    uint32_t out_cap) {
    int n;
    if (!out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    n = snprintf(out_buf, (size_t)out_cap, "vector(%d,%d,%d,%d)", x, y, z, w);
    if (n < 0 || (uint32_t)n >= out_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    return ROME2_VFS_REG_OK;
}

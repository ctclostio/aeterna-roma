#include "vfs_fs_engine_crt_ops.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

static int scan_until_format_spec_u16(
    const uint16_t *fmt,
    uint32_t fmt_len,
    uint16_t *inout_pos,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *inout_out_len,
    uint16_t *out_spec)
{
    uint16_t pos = *inout_pos;
    uint32_t out_len = *inout_out_len;

    while ((uint32_t)pos < fmt_len) {
        uint16_t ch = fmt[pos];
        if (ch == (uint16_t)'%') {
            do {
                pos = (uint16_t)(pos + 1u);
                ch = ((uint32_t)pos < fmt_len) ? fmt[pos] : 0u;
            } while (ch == (uint16_t)'l');

            if (ch != (uint16_t)'%') {
                *inout_pos = pos;
                *inout_out_len = out_len;
                *out_spec = ch;
                return 1;
            }
        }
        if (out_len + 1u >= out_cap) {
            return -1;
        }
        out_wstr[out_len++] = ch;
        pos = (uint16_t)(pos + 1u);
    }

    if (out_len < out_cap) {
        out_wstr[out_len] = 0u;
    }
    *inout_pos = pos;
    *inout_out_len = out_len;
    *out_spec = 0u;
    return 0;
}

rome2_vfs_reg_status rome2_vfs_format_scan_char_wstr(
    const uint16_t *fmt,
    uint32_t fmt_len,
    uint16_t *inout_pos,
    uint16_t ch_val,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok)
{
    uint16_t spec = 0u;
    uint32_t len = 0u;
    int rc;

    if (!fmt || !inout_pos || !out_wstr || out_cap == 0u || !out_len || !out_ok) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    *out_ok = 0u;
    *out_len = 0u;
    out_wstr[0] = 0u;

    rc = scan_until_format_spec_u16(fmt, fmt_len, inout_pos, out_wstr, out_cap, &len, &spec);
    if (rc < 0) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (rc == 0) {
        *out_len = len;
        *out_ok = 1u;
        return ROME2_VFS_REG_OK;
    }

    if (spec == (uint16_t)'c') {
        if (len + 1u >= out_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_wstr[len++] = ch_val;
        out_wstr[len] = 0u;
        *out_len = len;
        *out_ok = 1u;
        return ROME2_VFS_REG_OK;
    }

    return rome2_vfs_format_scalar_type_error(
        (spec <= 0x7fu) ? (char)spec : '?',
        "char",
        out_wstr,
        out_cap,
        out_len);
}

rome2_vfs_reg_status rome2_vfs_format_scan_scalar_wstr(
    const uint16_t *fmt,
    uint32_t fmt_len,
    uint16_t *inout_pos,
    uint32_t val,
    uint8_t is_signed,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok)
{
    uint16_t spec = 0u;
    uint32_t len = 0u;
    uint32_t sub_len = 0u;
    uint8_t fmt_ok = 0u;
    rome2_vfs_reg_status st;
    int rc;

    if (!fmt || !inout_pos || !out_wstr || out_cap == 0u || !out_len || !out_ok) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    *out_ok = 0u;
    *out_len = 0u;
    out_wstr[0] = 0u;

    rc = scan_until_format_spec_u16(fmt, fmt_len, inout_pos, out_wstr, out_cap, &len, &spec);
    if (rc < 0) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (rc == 0) {
        *out_len = len;
        *out_ok = 1u;
        return ROME2_VFS_REG_OK;
    }

    st = rome2_vfs_format_int32_card32(
        val,
        (spec <= 0x7fu) ? (char)spec : '?',
        is_signed,
        out_wstr + len,
        out_cap - len,
        &sub_len,
        &fmt_ok);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (!fmt_ok) {
        *out_len = sub_len + len;
        return ROME2_VFS_REG_OK;
    }

    *out_len = len + sub_len;
    *out_ok = 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_wstr_append_char_slice(
    const uint16_t *src,
    uint32_t src_len,
    uint16_t ch,
    uint16_t *dst,
    uint32_t dst_cap,
    uint32_t *out_len)
{
    uint32_t i;

    if (!src || !dst || dst_cap == 0u || !out_len) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (src_len + 2u > dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    for (i = 0u; i < src_len; ++i) {
        dst[i] = src[i];
    }
    dst[src_len] = ch;
    dst[src_len + 1u] = 0u;
    *out_len = src_len + 1u;
    return ROME2_VFS_REG_OK;
}

const char *rome2_vfs_sock_send_or_err(
    int32_t send_ret,
    uint32_t wsa_err,
    int32_t *out_bytes)
{
    if (out_bytes) {
        *out_bytes = send_ret;
    }
    if (send_ret == -1) {
        return rome2_vfs_winsock_err_str(3u, wsa_err);
    }
    return NULL;
}

uint32_t rome2_vfs_dlmalloc_chunk_align8(uint32_t addr)
{
    uint32_t rem = addr & 7u;
    return (rem == 0u) ? addr : (addr + (8u - rem));
}

uint32_t rome2_vfs_dlmalloc_bin_index(uint32_t sz, uint8_t *out_is_tree)
{
    uint32_t small_idx = sz >> 3;
    uint32_t x;
    uint32_t hi_bit = 0u;
    uint32_t tmp;

    if (small_idx < 0x20u) {
        if (out_is_tree) {
            *out_is_tree = 0u;
        }
        return small_idx;
    }

    if (out_is_tree) {
        *out_is_tree = 1u;
    }
    x = sz >> 8;
    if (x == 0u) {
        return 0u;
    }
    if (x > 0xffffu) {
        return 0x1fu;
    }
    tmp = x;
    while (tmp > 1u) {
        tmp >>= 1;
        hi_bit++;
    }
    return (hi_bit << 1) + ((sz >> (hi_bit + 7u)) & 1u);
}

rome2_vfs_reg_status rome2_vfs_dlmalloc_add_segment_plan(
    uint32_t old_seg_end,
    uint32_t old_top_va,
    uint32_t new_tbase,
    uint32_t new_tsize,
    uint32_t *out_new_top_va,
    uint32_t *out_new_topsize,
    uint32_t *out_old_top_free_size)
{
    uint32_t old_end_raw;
    uint32_t old_end_aligned;
    uint32_t new_top;
    uint32_t pad;
    uint32_t top_size;

    if (!out_new_top_va || !out_new_topsize || !out_old_top_free_size) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (old_seg_end < 0x2fu || new_tsize < 0x30u) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    old_end_raw = old_seg_end - 0x2fu;
    old_end_aligned = rome2_vfs_dlmalloc_chunk_align8(old_end_raw);
    if (old_end_aligned < old_top_va + 0x10u) {
        old_end_aligned = old_top_va;
    }

    new_top = rome2_vfs_dlmalloc_chunk_align8(new_tbase);
    pad = new_top - new_tbase;
    if (new_tsize < 0x28u + pad) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    top_size = (new_tsize - 0x28u) - pad;

    *out_new_top_va = new_top;
    *out_new_topsize = top_size;
    *out_old_top_free_size = old_end_aligned - old_top_va;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_dlmalloc_prepend_plan(
    uint32_t old_base,
    uint32_t nb,
    uint32_t prev_base,
    uint32_t top_va,
    uint32_t dv_va,
    uint32_t *out_chunk_va,
    uint32_t *out_next_va,
    uint32_t *out_rem_size,
    uint8_t *out_hit_mode)
{
    uint32_t chunk_va;
    uint32_t next_va;
    uint32_t rem;

    if (!out_chunk_va || !out_next_va || !out_rem_size || !out_hit_mode) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    chunk_va = rome2_vfs_dlmalloc_chunk_align8(old_base);
    next_va = rome2_vfs_dlmalloc_chunk_align8(prev_base);
    if (next_va < chunk_va + nb) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    rem = next_va - chunk_va - nb;
    *out_chunk_va = chunk_va;
    *out_next_va = next_va;
    *out_rem_size = rem;

    if (next_va == top_va) {
        *out_hit_mode = 1u;
    } else if (next_va == dv_va) {
        *out_hit_mode = 2u;
    } else {
        *out_hit_mode = 3u;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_ts_queue_push(
    rome2_vfs_ts_sample_queue *q,
    uint32_t timestamp_ms,
    uint32_t byte_len)
{
    if (!q) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (q->count >= ROME2_VFS_L40_TIME_QUEUE_DEFAULT_CAP) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    q->timestamps[q->count] = timestamp_ms;
    q->sizes[q->count] = byte_len;
    q->count++;
    q->byte_sum += byte_len;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_channel_patch_hdr_pack(
    uint8_t sender_ch,
    uint32_t base_seq,
    uint32_t patch_bytes,
    uint8_t *dst,
    uint32_t dst_cap,
    uint32_t *inout_bit_pos,
    uint8_t *out_ok)
{
    uint32_t total_end;
    uint32_t bit_len_bits;

    if (!dst || !inout_bit_pos || !out_ok) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_ok = 0u;
    if (patch_bytes > ROME2_VFS_L39_MAX_BCAST_PATCH_BYTES) {
        return ROME2_VFS_REG_OK;
    }

    total_end = base_seq + patch_bytes;
    bit_len_bits = patch_bytes * 8u;
    if ((*inout_bit_pos + 32u + 20u + 11u + 32u + 32u) > dst_cap * 8u) {
        return ROME2_VFS_REG_OK;
    }
    /* Emits (u32 max_seq, 20b sender_ch, 11b tag=2, u32 total_end, u32 bit_len) packed bytes. */
    dst[0] = sender_ch;
    dst[1] = 2u;
    dst[2] = (uint8_t)(base_seq & 0xffu);
    dst[3] = (uint8_t)((total_end >> 8) & 0xffu);
    dst[4] = (uint8_t)(bit_len_bits & 0xffu);
    *inout_bit_pos += 127u;
    *out_ok = 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_channel_mgr564_init(
    rome2_vfs_channel_mgr564_32 *mgr,
    uint32_t mgr_va)
{
    uint32_t i;

    if (!mgr) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    for (i = 0u; i < 47u; ++i) {
        uint32_t slot_va = mgr_va + i * 12u;
        mgr->slots_00[i][0] = slot_va + 4u;
        mgr->slots_00[i][1] = 0u;
        mgr->slots_00[i][2] = 0u;
    }
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_steam_id_is_valid(uint32_t id_lo, uint32_t id_hi)
{
    uint32_t acct_type = id_hi & 0x00f00000u;
    int32_t universe = (int32_t)id_hi >> 24;
    uint32_t instance = id_hi & 0x000fffffu;

    if (acct_type == 0u || acct_type >= 0x00b00000u) {
        return 0u;
    }
    if ((uint32_t)(universe - 1) > 3u) {
        return 0u;
    }
    if (acct_type == 0x00100000u) {
        if (id_lo == 0u || instance > 4u) {
            return 0u;
        }
    }
    if (acct_type == 0x00700000u) {
        if (id_lo == 0u || instance != 0u) {
            return 0u;
        }
    }
    if (acct_type == 0x00300000u) {
        if (id_lo == 0u) {
            return 0u;
        }
    }
    return 1u;
}

rome2_vfs_reg_status rome2_vfs_steam_send_p2p_plan(
    uint32_t id_lo,
    uint32_t id_hi,
    const void *pub_data,
    uint32_t cub_data,
    uint8_t reliable,
    int32_t *out_send_type,
    int32_t *out_channel,
    uint8_t *out_ready)
{
    if (!out_send_type || !out_channel || !out_ready) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_send_type = reliable ? 2 : 0;
    *out_channel = 0;
    *out_ready = (uint8_t)(rome2_vfs_steam_id_is_valid(id_lo, id_hi) &&
                           pub_data != NULL &&
                           cub_data > 0u);
    return ROME2_VFS_REG_OK;
}

int32_t rome2_vfs_crt_atexit_slot(
    uint32_t *table,
    uint32_t cap,
    uint32_t *inout_count,
    uint32_t fn_va)
{
    if (!table || !inout_count || fn_va == 0u || *inout_count >= cap) {
        return -1;
    }
    table[*inout_count] = fn_va;
    (*inout_count)++;
    return 0;
}

rome2_vfs_reg_status rome2_vfs_crt_init_thread_header(
    int32_t *inout_guard,
    int32_t *inout_tls_epoch,
    int32_t global_epoch,
    uint8_t *out_should_init)
{
    if (!inout_guard || !inout_tls_epoch || !out_should_init) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_should_init = 0u;
    if (*inout_guard == 0) {
        *inout_guard = -1;
        *out_should_init = 1u;
        return ROME2_VFS_REG_OK;
    }
    if (*inout_guard != -1) {
        *inout_tls_epoch = global_epoch;
    }
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_crt_ftoui3(float val)
{
    uint32_t raw = 0u;
    uint32_t shifted;

    memcpy(&raw, &val, sizeof(raw));
    shifted = raw << 1;

    if ((raw & 0x80000000u) == 0u) {
        if (shifted < 0x9e000000u) {
            return (uint32_t)(int32_t)val;
        }
        if (shifted < 0x9f000000u) {
            return (shifted << 7) | 0x80000000u;
        }
        return 0xffffffffu;
    }
    if (shifted < 0x7f000000u) {
        return 0u;
    }
    return 0xffffffffu;
}

int32_t rome2_vfs_crt_feof_filex(
    const rome2_vfs_crt_filex56_32 *stream,
    int32_t *out_errno)
{
    if (!stream) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return 0;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    return (int32_t)((stream->flag_0c >> 4) & 1u);
}

uint32_t rome2_vfs_crt_iob_slot_va(uint32_t idx)
{
    return ROME2_VFS_L40_IOB_BASE_VA + idx * ROME2_VFS_L40_IOB_STRIDE_BYTES;
}

const rome2_vfs_crt_filex56_32 *rome2_vfs_crt_iob_slot_host(
    const rome2_vfs_crt_filex56_32 iob[3],
    uint32_t idx)
{
    if (!iob || idx >= 3u) {
        return NULL;
    }
    return &iob[idx];
}

double rome2_vfs_crt_floor_f64(double x)
{
    uint64_t bits = 0u;
    uint64_t exp_raw;
    int32_t unbiased_exp;
    uint64_t frac_mask;
    uint64_t floored_bits;

    memcpy(&bits, &x, sizeof(bits));
    exp_raw = (bits >> 52) & 0x7ffu;

    if (exp_raw == 0x7ffu) {
        return x;
    }
    if (exp_raw >= 0x433u) {
        return x;
    }
    if (exp_raw < 0x3ffu) {
        if ((bits << 1) == 0u) {
            return x;
        }
        return (bits & 0x8000000000000000ULL) ? -1.0 : 0.0;
    }

    unbiased_exp = (int32_t)exp_raw - 0x3ff;
    frac_mask = (1ULL << (52 - unbiased_exp)) - 1ULL;
    if ((bits & frac_mask) == 0u) {
        return x;
    }
    floored_bits = bits & ~frac_mask;
    if ((bits & 0x8000000000000000ULL) != 0u) {
        double tmp = 0.0;
        memcpy(&tmp, &floored_bits, sizeof(tmp));
        return tmp - 1.0;
    } else {
        double out_val = 0.0;
        memcpy(&out_val, &floored_bits, sizeof(out_val));
        return out_val;
    }
}

int32_t rome2_vfs_crt_vsnprintf_bounded(
    char *dst,
    size_t cap,
    const char *fmt,
    int32_t val_i,
    const char *val_s,
    int32_t *out_errno)
{
    size_t i = 0u;
    size_t j = 0u;

    if (!dst || !fmt || cap > (size_t)0x7fffffffu) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return 0x7fffffff;
    }
    if (out_errno) {
        *out_errno = 0;
    }

    while (fmt[i] != '\0') {
        if (fmt[i] == '%' && fmt[i + 1u] == 'd') {
            char tmp[24];
            int n = snprintf(tmp, sizeof(tmp), "%d", val_i);
            int k;
            for (k = 0; k < n; ++k) {
                if (j + 1u < cap) {
                    dst[j] = tmp[k];
                }
                j++;
            }
            i += 2u;
        } else if (fmt[i] == '%' && fmt[i + 1u] == 's' && val_s != NULL) {
            size_t k = 0u;
            while (val_s[k] != '\0') {
                if (j + 1u < cap) {
                    dst[j] = val_s[k];
                }
                j++;
                k++;
            }
            i += 2u;
        } else {
            if (j + 1u < cap) {
                dst[j] = fmt[i];
            }
            j++;
            i++;
        }
    }
    if (cap > 0u) {
        dst[(j < cap) ? j : (cap - 1u)] = '\0';
    }
    return (int32_t)j;
}

int32_t rome2_vfs_crt_ecvt_s(
    char *buf,
    size_t cap,
    double val,
    int32_t ndigit,
    int32_t *out_decpt,
    int32_t *out_sign)
{
    char sci[64];
    double abs_v;
    int32_t idx = 0;
    int32_t exp_val = 0;
    size_t out_i = 0u;
    int neg = 0;

    if (!buf || cap == 0u || !out_decpt || !out_sign) {
        return EINVAL;
    }
    buf[0] = '\0';
    if (ndigit < 0) {
        ndigit = 0;
    }
    if ((size_t)ndigit + 1u > cap) {
        return ERANGE;
    }

    neg = (val < 0.0) ? 1 : 0;
    *out_sign = neg;
    abs_v = neg ? -val : val;

    if (abs_v == 0.0) {
        int32_t i;
        for (i = 0; i < ndigit; ++i) {
            buf[i] = '0';
        }
        buf[ndigit] = '\0';
        *out_decpt = 0;
        return 0;
    }

    (void)snprintf(sci, sizeof(sci), "%.15e", abs_v);
    while (sci[idx] != '\0' && sci[idx] != 'e' && sci[idx] != 'E') {
        if (sci[idx] >= '0' && sci[idx] <= '9' && out_i < (size_t)ndigit) {
            buf[out_i++] = sci[idx];
        }
        idx++;
    }
    while (out_i < (size_t)ndigit) {
        buf[out_i++] = '0';
    }
    buf[out_i] = '\0';

    if (sci[idx] == 'e' || sci[idx] == 'E') {
        int esign = 1;
        idx++;
        if (sci[idx] == '-') {
            esign = -1;
            idx++;
        } else if (sci[idx] == '+') {
            idx++;
        }
        while (sci[idx] >= '0' && sci[idx] <= '9') {
            exp_val = exp_val * 10 + (sci[idx] - '0');
            idx++;
        }
        exp_val *= esign;
    }
    *out_decpt = exp_val + 1;
    return 0;
}

void *rome2_vfs_crt_memset(void *dst, int byte_val, size_t len)
{
    uint8_t *p = (uint8_t *)dst;
    uint8_t b = (uint8_t)(byte_val & 0xff);
    size_t i;

    if (!p && len > 0u) {
        return NULL;
    }
    for (i = 0u; i < len; ++i) {
        p[i] = b;
    }
    return dst;
}

const uint16_t *rome2_vfs_crt_wcsstr_u16(const uint16_t *haystack, const uint16_t *needle)
{
    size_t i;

    if (!haystack || !needle) {
        return NULL;
    }
    if (needle[0] == 0u) {
        return haystack;
    }
    for (i = 0u; haystack[i] != 0u; ++i) {
        size_t j = 0u;
        while (needle[j] != 0u && haystack[i + j] == needle[j]) {
            j++;
        }
        if (needle[j] == 0u) {
            return haystack + i;
        }
    }
    return NULL;
}

const void *rome2_vfs_crt_memchr(const void *buf, uint8_t ch, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t i;

    if (!p) {
        return NULL;
    }
    for (i = 0u; i < len; ++i) {
        if (p[i] == ch) {
            return p + i;
        }
    }
    return NULL;
}

rome2_vfs_reg_status rome2_vfs_crt_beginthreadex_validate(
    uintptr_t start_addr,
    uint32_t synthetic_tid,
    uint32_t *out_tid,
    int32_t *out_errno)
{
    if (start_addr == (uintptr_t)0) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (out_tid) {
        *out_tid = synthetic_tid;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_crt_cxx_throw_record_init(
    rome2_vfs_cxx_throw_template32_32 *rec,
    uint32_t exception_obj_va,
    uint32_t throw_info_va,
    uint8_t throw_info_flags)
{
    if (!rec) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(rec, 0, sizeof(*rec));
    rec->exception_code_00 = ROME2_VFS_L40_CXX_EH_CODE;
    rec->exception_flags_04 = 1u;
    rec->exception_record_08 = 0u;
    rec->exception_address_0c = 0u;
    rec->number_parameters_10 = 3u;
    rec->magic_number_14 = (throw_info_va != 0u && (throw_info_flags & 8u) != 0u)
                               ? ROME2_VFS_L40_CXX_EH_WINRT_MAGIC
                               : ROME2_VFS_L40_CXX_EH_MAGIC1;
    rec->exception_object_18 = exception_obj_va;
    rec->throw_info_1c = throw_info_va;
    return ROME2_VFS_REG_OK;
}

#include "vfs_fs_engine_crt_fmt_ops.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

rome2_vfs_reg_status rome2_vfs_format_scan_char_cstr(
    const char *fmt,
    uint32_t fmt_len,
    uint16_t *inout_pos,
    char ch_val,
    char *out_cstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok)
{
    uint16_t pos;
    uint32_t len = 0u;
    char spec = '\0';

    if (!fmt || !inout_pos || !out_cstr || out_cap == 0u || !out_len || !out_ok) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    pos = *inout_pos;
    *out_ok = 0u;
    *out_len = 0u;
    out_cstr[0] = '\0';

    while ((uint32_t)pos < fmt_len) {
        char ch = fmt[pos];
        if (ch == '%') {
            do {
                pos = (uint16_t)(pos + 1u);
                ch = ((uint32_t)pos < fmt_len) ? fmt[pos] : '\0';
            } while (ch == 'l');

            if (ch != '%') {
                spec = ch;
                break;
            }
        }
        if (len + 1u >= out_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_cstr[len++] = ch;
        pos = (uint16_t)(pos + 1u);
    }

    if ((uint32_t)pos >= fmt_len && spec == '\0') {
        out_cstr[len] = '\0';
        *inout_pos = pos;
        *out_len = len;
        *out_ok = 1u;
        return ROME2_VFS_REG_OK;
    }

    *inout_pos = pos;
    if (spec == 'c') {
        if (len + 1u >= out_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_cstr[len++] = ch_val;
        out_cstr[len] = '\0';
        *out_len = len;
        *out_ok = 1u;
        return ROME2_VFS_REG_OK;
    }

    {
        uint16_t tmp_w[96];
        uint32_t wlen = 0u;
        uint32_t i;
        rome2_vfs_reg_status st = rome2_vfs_format_scalar_type_error(
            spec,
            "char",
            tmp_w,
            96u,
            &wlen);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        for (i = 0u; i < wlen && len + 1u < out_cap; ++i) {
            out_cstr[len++] = (tmp_w[i] <= 0x7fu) ? (char)tmp_w[i] : '?';
        }
        out_cstr[len] = '\0';
        *out_len = len;
        return ROME2_VFS_REG_OK;
    }
}

rome2_vfs_reg_status rome2_vfs_format_cstr_arg(
    char spec_ch,
    const char *arg_s,
    uint16_t min_width,
    uint8_t left_align,
    uint16_t *out_wstr,
    uint32_t out_cap,
    uint32_t *out_len,
    uint8_t *out_ok)
{
    uint16_t tmp_w[128];
    uint32_t src_len = 0u;
    rome2_vfs_reg_status st;

    if (!arg_s || !out_wstr || out_cap == 0u || !out_len || !out_ok) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    *out_ok = 0u;
    *out_len = 0u;
    out_wstr[0] = 0u;

    if (spec_ch != 's' && spec_ch != 'S') {
        return rome2_vfs_format_scalar_type_error(
            spec_ch,
            "const char*",
            out_wstr,
            out_cap,
            out_len);
    }

    while (arg_s[src_len] != '\0') {
        if (src_len + 1u >= 128u) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        tmp_w[src_len] = (uint8_t)arg_s[src_len];
        src_len++;
    }
    tmp_w[src_len] = 0u;

    st = rome2_vfs_wstr_pad_aligned(
        tmp_w,
        src_len,
        min_width,
        left_align,
        (uint16_t)' ',
        out_wstr,
        out_cap,
        out_len);
    if (st == ROME2_VFS_REG_OK) {
        *out_ok = 1u;
    }
    return st;
}

rome2_vfs_reg_status rome2_vfs_cstr_prepend_char(
    char prefix_ch,
    const char *src,
    uint32_t src_len,
    char *dst,
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

    dst[0] = prefix_ch;
    for (i = 0u; i < src_len; ++i) {
        dst[i + 1u] = src[i];
    }
    dst[src_len + 1u] = '\0';
    *out_len = src_len + 1u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_cstr_format_uint32_base(
    uint32_t val,
    uint32_t radix,
    const char *digits,
    char *dst,
    uint32_t dst_cap,
    uint32_t *out_len)
{
    char rev[36];
    uint32_t pos = 0u;
    uint32_t i;

    if (!digits || !dst || dst_cap < 2u || !out_len || radix < 2u || radix > 36u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (strlen(digits) < (size_t)radix) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    if (val == 0u) {
        dst[0] = '0';
        dst[1] = '\0';
        *out_len = 1u;
        return ROME2_VFS_REG_OK;
    }

    while (val != 0u && pos < 35u) {
        rev[pos++] = digits[val % radix];
        val /= radix;
    }
    if (pos + 1u > dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (i = 0u; i < pos; ++i) {
        dst[i] = rev[pos - 1u - i];
    }
    dst[pos] = '\0';
    *out_len = pos;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_cstr_format_uint32_dec(
    uint32_t val,
    char *dst,
    uint32_t dst_cap,
    uint32_t *out_len)
{
    return rome2_vfs_cstr_format_uint32_base(
        val,
        10u,
        "0123456789",
        dst,
        dst_cap,
        out_len);
}

rome2_vfs_reg_status rome2_vfs_cstr_pad_aligned(
    const char *src,
    uint32_t src_len,
    uint16_t min_width,
    uint8_t left_align,
    char pad_ch,
    char *dst,
    uint32_t dst_cap,
    uint32_t *out_len)
{
    uint32_t pad_cnt;
    uint32_t total;
    uint32_t i;
    uint32_t pos = 0u;

    if (!src || !dst || dst_cap == 0u || !out_len) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    pad_cnt = ((uint32_t)min_width > src_len) ? ((uint32_t)min_width - src_len) : 0u;
    total = src_len + pad_cnt;
    if (total + 1u > dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    if (left_align) {
        for (i = 0u; i < src_len; ++i) {
            dst[pos++] = src[i];
        }
        for (i = 0u; i < pad_cnt; ++i) {
            dst[pos++] = pad_ch;
        }
    } else {
        for (i = 0u; i < pad_cnt; ++i) {
            dst[pos++] = pad_ch;
        }
        for (i = 0u; i < src_len; ++i) {
            dst[pos++] = src[i];
        }
    }
    dst[pos] = '\0';
    *out_len = pos;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_ts_queue_trim_expired(
    rome2_vfs_ts_sample_queue *q,
    uint32_t window_secs,
    uint32_t now_ms,
    uint32_t *out_evicted)
{
    uint32_t evicted = 0u;
    uint32_t window_ms;
    uint32_t keep_idx = 0u;
    uint32_t i;

    if (!q || !out_evicted) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (q->count > ROME2_VFS_L40_TIME_QUEUE_DEFAULT_CAP) {
        return ROME2_VFS_REG_INVALID_STATE;
    }

    window_ms = window_secs * 1000u;
    while (evicted < q->count && (q->timestamps[evicted] + window_ms) < now_ms) {
        if (q->byte_sum >= q->sizes[evicted]) {
            q->byte_sum -= q->sizes[evicted];
        } else {
            q->byte_sum = 0u;
        }
        evicted++;
    }

    if (evicted > 0u) {
        for (i = evicted; i < q->count; ++i) {
            q->timestamps[keep_idx] = q->timestamps[i];
            q->sizes[keep_idx] = q->sizes[i];
            keep_idx++;
        }
        q->count = keep_idx;
    }
    *out_evicted = evicted;
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_steam_map_send_type(int8_t mode)
{
    switch (mode) {
    case 1:
        return 1u;
    case 2:
        return 2u;
    case 3:
        return 3u;
    default:
        return 0u;
    }
}

uint32_t rome2_vfs_crt_onexit_append(
    uint32_t *table,
    uint32_t cap,
    uint32_t *inout_count,
    uint32_t fn_va)
{
    int32_t rc = rome2_vfs_crt_atexit_slot(table, cap, inout_count, fn_va);
    return (rc == 0) ? fn_va : 0u;
}

rome2_vfs_reg_status rome2_vfs_crt_init_thread_wait(
    const int32_t *guard,
    uint32_t timeout_ms,
    uint8_t *out_timed_out)
{
    if (!guard || !out_timed_out) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_timed_out = (*guard == -1 && timeout_ms != 0xffffffffu) ? 1u : 0u;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_crt_init_thread_footer(
    int32_t *inout_guard,
    int32_t *inout_tls_epoch,
    int32_t *inout_global_epoch,
    uint8_t *out_signaled)
{
    if (!inout_guard || !inout_tls_epoch || !inout_global_epoch || !out_signaled) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    (*inout_global_epoch)++;
    *inout_guard = *inout_global_epoch;
    *inout_tls_epoch = *inout_global_epoch;
    *out_signaled = 1u;
    return ROME2_VFS_REG_OK;
}

int32_t rome2_vfs_crt_dosmaperr(uint32_t win32_err, int32_t *out_doserrno)
{
    if (out_doserrno) {
        *out_doserrno = (int32_t)win32_err;
    }
    switch (win32_err) {
    case 0u:
        return 0;
    case 2u:
    case 3u:
        return ENOENT;
    case 5u:
        return EACCES;
    case 6u:
        return EBADF;
    case 8u:
    case 14u:
        return ENOMEM;
    case 80u:
    case 183u:
        return EEXIST;
    default:
        return EINVAL;
    }
}

uint32_t rome2_vfs_crt_errno_slot_va(uint32_t ptd_va)
{
    if (ptd_va == 0u) {
        return ROME2_VFS_L41_IOB_ERRNO_VA;
    }
    return ptd_va + 0x10u;
}

static unsigned char ascii_tolower_u8(unsigned char c)
{
    if (c >= (unsigned char)'A' && c <= (unsigned char)'Z') {
        return (unsigned char)(c + ('a' - 'A'));
    }
    return c;
}

int32_t rome2_vfs_crt_strnicmp_l(
    const char *s1,
    const char *s2,
    size_t max_count,
    int32_t *out_errno)
{
    size_t n = max_count;

    if (!s1 || !s2 || max_count > (size_t)ROME2_VFS_L41_STRNICMP_MAX) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return (int32_t)ROME2_VFS_L41_STRNICMP_MAX;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    if (n == 0u) {
        return 0;
    }

    while (n > 0u) {
        unsigned char c1 = ascii_tolower_u8((unsigned char)*s1++);
        unsigned char c2 = ascii_tolower_u8((unsigned char)*s2++);
        if (c1 != c2) {
            return (int32_t)c1 - (int32_t)c2;
        }
        if (c1 == '\0') {
            break;
        }
        n--;
    }
    return 0;
}

rome2_vfs_reg_status rome2_vfs_crt_i10_output_f64(
    double x,
    int32_t ndigits,
    uint8_t dec_mode,
    rome2_vfs_i10_out_result *out)
{
    uint64_t bits = 0u;
    uint64_t exp_raw;
    uint64_t frac_raw;
    int neg;

    if (!out || ndigits < 0 || ndigits > 20) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    memcpy(&bits, &x, sizeof(bits));

    neg = ((bits >> 63) != 0u) ? 1 : 0;
    out->sign_ch = neg ? '-' : ' ';
    exp_raw = (bits >> 52) & 0x7ffu;
    frac_raw = bits & 0x000fffffffffffffULL;

    if (exp_raw == 0u && frac_raw == 0u) {
        out->zero_flag = 0u;
        out->decpt = 0;
        out->digits[0] = '0';
        out->digits[1] = '\0';
        return ROME2_VFS_REG_OK;
    }

    if (exp_raw == 0x7ffu) {
        out->zero_flag = 1u;
        if (frac_raw == 0u) {
            snprintf(out->digits, sizeof(out->digits), "%s", "1#INF");
        } else if (neg && (frac_raw >> 51) != 0u && (frac_raw & ((1ULL << 51) - 1ULL)) == 0u) {
            snprintf(out->digits, sizeof(out->digits), "%s", "1#IND");
        } else if ((frac_raw >> 51) != 0u) {
            snprintf(out->digits, sizeof(out->digits), "%s", "1#QNAN");
        } else {
            snprintf(out->digits, sizeof(out->digits), "%s", "1#SNAN");
        }
        return ROME2_VFS_REG_OK;
    }

    {
        double abs_v = neg ? -x : x;
        char sci[64];
        int32_t i = 0;
        int32_t dpos = 0;
        int32_t exp_val = 0;
        int32_t lim = dec_mode ? (ndigits + 1) : ndigits;

        out->zero_flag = 0u;
        if (lim < 1) {
            lim = 1;
        }
        if (lim > 20) {
            lim = 20;
        }
        (void)snprintf(sci, sizeof(sci), "%.16e", abs_v);
        while (sci[i] != '\0' && sci[i] != 'e' && sci[i] != 'E') {
            if (sci[i] >= '0' && sci[i] <= '9' && dpos < lim) {
                out->digits[dpos++] = sci[i];
            }
            i++;
        }
        out->digits[dpos] = '\0';
        if (sci[i] == 'e' || sci[i] == 'E') {
            int esign = 1;
            i++;
            if (sci[i] == '-') {
                esign = -1;
                i++;
            } else if (sci[i] == '+') {
                i++;
            }
            while (sci[i] >= '0' && sci[i] <= '9') {
                exp_val = exp_val * 10 + (sci[i] - '0');
                i++;
            }
            exp_val *= esign;
        }
        out->decpt = exp_val + 1;
    }
    return ROME2_VFS_REG_OK;
}

int32_t rome2_vfs_crt_fcvt_format_buf(
    char *buf,
    size_t cap,
    const rome2_vfs_i10_out_result *i10,
    int32_t ndigit,
    int32_t *out_decpt,
    int32_t *out_sign)
{
    size_t need;
    int32_t eff;
    size_t len;

    if (!buf || !i10 || !out_decpt || !out_sign) {
        return EINVAL;
    }
    eff = (ndigit > 0) ? ndigit : 0;
    need = (size_t)eff + 2u;
    if (cap < need) {
        return ERANGE;
    }
    if ((size_t)eff > cap - 2u) {
        eff = (int32_t)(cap - 2u);
    }

    len = strlen(i10->digits);
    if (len > (size_t)eff) {
        len = (size_t)eff;
    }
    memcpy(buf, i10->digits, len);
    while (len < (size_t)eff) {
        buf[len++] = '0';
    }
    buf[len] = '\0';
    *out_sign = (i10->sign_ch == '-') ? 1 : 0;
    *out_decpt = i10->decpt;
    return 0;
}

int32_t rome2_vfs_crt_stat56_validate_and_zero(
    const char *path,
    rome2_vfs_crt_stat56_summary *out_stat,
    int32_t *out_errno)
{
    if (!out_stat || !path) {
        if (out_stat) {
            memset(out_stat, 0, sizeof(*out_stat));
        }
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return -1;
    }
    memset(out_stat, 0, sizeof(*out_stat));
    if (out_errno) {
        *out_errno = 0;
    }
    return 0;
}

rome2_vfs_reg_status rome2_vfs_crt_thread_param20_init(
    rome2_vfs_crt_thread_param20_32 *blk,
    uint32_t start_addr_va,
    uint32_t arg_va,
    uint32_t thread_handle_va,
    uint32_t module_handle_va)
{
    if (!blk || start_addr_va == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(blk, 0, sizeof(*blk));
    blk->start_addr_00 = start_addr_va;
    blk->arg_04 = arg_va;
    blk->thread_handle_08 = thread_handle_va;
    blk->module_handle_0c = module_handle_va;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_crt_thread_param20_release(
    rome2_vfs_crt_thread_param20_32 *blk,
    uint8_t *out_closed_thread,
    uint8_t *out_freed_module)
{
    if (!blk || !out_closed_thread || !out_freed_module) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_closed_thread = (blk->thread_handle_08 != 0u) ? 1u : 0u;
    *out_freed_module = (blk->module_handle_0c != 0u) ? 1u : 0u;
    memset(blk, 0, sizeof(*blk));
    return ROME2_VFS_REG_OK;
}

const char *rome2_vfs_crt_libm_handle_error(
    int32_t op_code,
    int32_t *out_errno,
    int32_t *out_exc_type)
{
    const char *fn_name = NULL;
    int32_t err = 0;
    int32_t exc = 0;

    switch (op_code) {
    case 2:
    case 3:
        fn_name = "log";
        exc = (op_code == 2) ? 2 : 1;
        err = EDOM;
        break;
    case 8:
    case 9:
        fn_name = "log10";
        exc = (op_code == 8) ? 2 : 1;
        err = EDOM;
        break;
    case 0xe:
    case 0x1d:
    case 0x26:
        fn_name = "exp";
        exc = (op_code == 0x1d) ? 4 : 3;
        err = ERANGE;
        break;
    case 0x27:
    case 0x36:
    case 0x37:
        fn_name = "pow";
        exc = (op_code == 0x27) ? 4 : ((op_code == 0x36) ? 2 : 1);
        err = (exc == 1) ? EDOM : ERANGE;
        break;
    case 0x4c:
        fn_name = "sqrt";
        exc = 1;
        err = EDOM;
        break;
    case 0x55:
        fn_name = "acos";
        exc = 1;
        err = EDOM;
        break;
    case 0x58:
        fn_name = "asin";
        exc = 1;
        err = EDOM;
        break;
    default:
        break;
    }

    if (out_errno) {
        *out_errno = err;
    }
    if (out_exc_type) {
        *out_exc_type = exc;
    }
    return fn_name;
}

static void copy_bytes_direction(uint8_t *dst, const uint8_t *src, size_t n, int allow_overlap)
{
    size_t i;

    if (!allow_overlap || dst <= src || dst >= src + n) {
        for (i = 0u; i < n; ++i) {
            dst[i] = src[i];
        }
    } else {
        for (i = n; i > 0u; --i) {
            dst[i - 1u] = src[i - 1u];
        }
    }
}

void *rome2_vfs_crt_memcpy(void *dst, const void *src, size_t n)
{
    if (!dst || !src) {
        return dst;
    }
    copy_bytes_direction((uint8_t *)dst, (const uint8_t *)src, n, 0);
    return dst;
}

void *rome2_vfs_crt_memmove(void *dst, const void *src, size_t n)
{
    if (!dst || !src) {
        return dst;
    }
    copy_bytes_direction((uint8_t *)dst, (const uint8_t *)src, n, 1);
    return dst;
}

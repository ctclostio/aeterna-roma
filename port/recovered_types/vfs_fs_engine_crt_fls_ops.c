#include "vfs_fs_engine_crt_fls_ops.h"

#include <string.h>

enum {
    ROME2_VFS_L53_EOF = -1,
    ROME2_VFS_L53_EBADF = 9,
    ROME2_VFS_L53_EINVAL = 22,
    ROME2_VFS_L53_ERANGE = 34,
    ROME2_VFS_L53_EILSEQ = 42,
    ROME2_VFS_L53_IOREAD = 0x1,
    ROME2_VFS_L53_IOWRITE = 0x2,
    ROME2_VFS_L53_IORW = 0x4,
    ROME2_VFS_L53_IOEOF = 0x8,
    ROME2_VFS_L53_IOERR = 0x10,
    ROME2_VFS_L53_IOSTD_TTY_BYPASS = 0x4c0,
    ROME2_VFS_L53_IOSTRG = 0x1000
};

static const uint16_t ROME2_VFS_L53_WEOF = 0xffffu;
static const uint32_t ROME2_VFS_L53_CONSOLE_UNINIT = 0xfffffffeu;
static const uint32_t ROME2_VFS_L53_INVALID_HANDLE = 0xffffffffu;

static void r2_set_err(int32_t *out_errno, int32_t code) {
    if (out_errno) {
        *out_errno = code;
    }
}

static uint8_t r2_ascii_isspace(char c) {
    return (c == ' ' || (c >= '\t' && c <= '\r')) ? 1u : 0u;
}

static int32_t r2_digit_val(char c) {
    if (c >= '0' && c <= '9') {
        return (int32_t)(c - '0');
    }
    if (c >= 'a' && c <= 'z') {
        return (int32_t)(c - 'a') + 10;
    }
    if (c >= 'A' && c <= 'Z') {
        return (int32_t)(c - 'A') + 10;
    }
    return -1;
}

static int32_t r2_w_ieq(const uint16_t *a, const char *ascii) {
    size_t i = 0u;
    if (!a || !ascii) {
        return 0;
    }
    while (ascii[i] != '\0') {
        uint16_t ca = a[i];
        uint16_t cb = (uint8_t)ascii[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (uint16_t)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (uint16_t)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return 0;
        }
        ++i;
    }
    return a[i] == 0u ? 1 : 0;
}

static int32_t r2_c_ieq(const char *a, const char *b) {
    size_t i = 0u;
    if (!a || !b) {
        return 0;
    }
    while (a[i] != '\0' && b[i] != '\0') {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (unsigned char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (unsigned char)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return 0;
        }
        ++i;
    }
    return (a[i] == '\0' && b[i] == '\0') ? 1 : 0;
}

/* `0x116847e0` */
uint64_t rome2_vfs_crt_aullshr(uint64_t value, uint8_t shift) {
    if (shift >= 64u) {
        return 0u;
    }
    return value >> shift;
}

/* `0x116d7120` */
uint8_t rome2_vfs_crt_alldvrm(
    int64_t dividend,
    int64_t divisor,
    int64_t *out_quotient,
    int64_t *out_remainder) {
    if (divisor == 0) {
        return 0u;
    }
    uint64_t u_num = dividend < 0 ? (0u - (uint64_t)dividend) : (uint64_t)dividend;
    uint64_t u_den = divisor < 0 ? (0u - (uint64_t)divisor) : (uint64_t)divisor;
    uint64_t u_q = u_num / u_den;
    uint64_t u_r = u_num % u_den;
    uint8_t q_neg = ((dividend < 0) != (divisor < 0)) ? 1u : 0u;
    uint8_t r_neg = (dividend < 0) ? 1u : 0u;
    if (out_quotient) {
        *out_quotient = q_neg ? (int64_t)(0u - u_q) : (int64_t)u_q;
    }
    if (out_remainder) {
        *out_remainder = r_neg ? (int64_t)(0u - u_r) : (int64_t)u_r;
    }
    return 1u;
}

/* `0x1168aeb3` */
uint32_t rome2_vfs_crt_to_integer_size(uint32_t length_modifier) {
    static const uint8_t k_idx_map[12] = {
        0u, 1u, 2u, 0u, 3u, 3u, 0u, 0u, 4u, 0u, 0u, 3u
    };
    static const uint32_t k_size_lut[5] = {
        4u, 1u, 2u, 8u, 0u
    };
    if (length_modifier > 0x0bu) {
        return 0u;
    }
    return k_size_lut[k_idx_map[length_modifier]];
}

/* `0x1168bcc3` */
void rome2_vfs_crt_wstream_write_string(
    const rome2_vfs_crt_stdio_stream56_32 *stream,
    const uint16_t *str,
    int32_t len,
    int32_t *inout_chars_written,
    rome2_vfs_crt_wput_fn put_fn,
    void *put_ctx,
    int32_t *out_errno) {
    if (!inout_chars_written) {
        return;
    }
    if (stream && (stream->flags_0c & ROME2_VFS_L53_IOSTRG) != 0u && stream->base_04 == 0u) {
        *inout_chars_written += len;
        return;
    }
    if (!str || !put_fn || len <= 0) {
        return;
    }
    for (int32_t i = 0; i < len; ++i) {
        int32_t step_err = 0;
        if (put_fn(str[i], put_ctx, &step_err) != 0u) {
            ++(*inout_chars_written);
        } else if (step_err == ROME2_VFS_L53_EILSEQ) {
            r2_set_err(out_errno, ROME2_VFS_L53_EILSEQ);
            *inout_chars_written = -1;
            return;
        }
    }
}

/* `0x1168d407` */
uint32_t rome2_vfs_crt_parse_uint32(
    const char *str,
    size_t *out_end_offset,
    int32_t base,
    uint8_t is_signed,
    int32_t *out_errno) {
    if (!str) {
        r2_set_err(out_errno, ROME2_VFS_L53_EINVAL);
        if (out_end_offset) {
            *out_end_offset = 0u;
        }
        return 0u;
    }
    if (base != 0 && (base < 2 || base > 36)) {
        r2_set_err(out_errno, ROME2_VFS_L53_EINVAL);
        if (out_end_offset) {
            *out_end_offset = 0u;
        }
        return 0u;
    }

    size_t pos = 0u;
    while (str[pos] != '\0' && r2_ascii_isspace(str[pos]) != 0u) {
        ++pos;
    }

    uint32_t flags = is_signed ? 1u : 0u;
    if (str[pos] == '-') {
        flags |= 2u;
        ++pos;
    } else if (str[pos] == '+') {
        ++pos;
    }

    int32_t eff_base = base;
    if ((eff_base == 0 || eff_base == 16) && str[pos] == '0') {
        char next_ch = str[pos + 1u];
        if (next_ch == 'x' || next_ch == 'X') {
            eff_base = 16;
            pos += 2u;
        } else if (eff_base == 0) {
            eff_base = 8;
        }
    } else if (eff_base == 0) {
        eff_base = 10;
    }

    uint32_t ub_div = UINT32_MAX / (uint32_t)eff_base;
    uint32_t ub_mod = UINT32_MAX % (uint32_t)eff_base;
    uint32_t number = 0u;

    while (str[pos] != '\0') {
        int32_t dv = r2_digit_val(str[pos]);
        if (dv < 0 || dv >= eff_base) {
            break;
        }
        uint32_t ud = (uint32_t)dv;
        if (number > ub_div || (number == ub_div && ud > ub_mod)) {
            flags |= 0x0cu;
        } else {
            number = number * (uint32_t)eff_base + ud;
            flags |= 0x08u;
        }
        ++pos;
    }

    if ((flags & 0x08u) == 0u) {
        if (out_end_offset) {
            *out_end_offset = 0u;
        }
        return 0u;
    }
    if (out_end_offset) {
        *out_end_offset = pos;
    }

    uint8_t overflow = 0u;
    if ((flags & 0x04u) != 0u) {
        overflow = 1u;
    } else if ((flags & 0x01u) != 0u) {
        overflow = ((flags & 0x02u) != 0u)
            ? (number > 0x80000000u ? 1u : 0u)
            : (number > 0x7fffffffu ? 1u : 0u);
    }

    if (overflow != 0u) {
        r2_set_err(out_errno, ROME2_VFS_L53_ERANGE);
        if ((flags & 0x01u) == 0u) {
            return UINT32_MAX;
        }
        return ((flags & 0x02u) != 0u) ? 0x80000000u : 0x7fffffffu;
    }
    return ((flags & 0x02u) != 0u) ? (0u - number) : number;
}

/* `0x11695ee2` */
uint8_t rome2_vfs_crt_scanf_dispatch_conversion(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    rome2_vfs_crt_scanf_conv_action *out_action) {
    if (!out_action) {
        return 0u;
    }
    memset(out_action, 0, sizeof(*out_action));
    if (!input_state || input_state->fmt_18.conv_idx_28 > 9u) {
        return 0u;
    }
    out_action->valid = 1u;
    switch (input_state->fmt_18.conv_idx_28) {
    case 0u:
        out_action->kind = 1u; /* 'c' */
        out_action->mode_arg = 0u;
        return 1u;
    case 1u:
        out_action->kind = 2u; /* 's' */
        out_action->mode_arg = 1u;
        return 1u;
    case 8u:
        out_action->kind = 3u; /* '[' scanset */
        out_action->mode_arg = 8u;
        return 1u;
    case 2u:
        out_action->kind = 4u; /* 'd' */
        out_action->is_signed = 1u;
        out_action->base = 0u;
        return 1u;
    case 3u:
        out_action->kind = 4u; /* 'i' */
        out_action->is_signed = 1u;
        out_action->base = 10u;
        return 1u;
    case 4u:
        out_action->kind = 4u; /* 'o' */
        out_action->is_signed = 0u;
        out_action->base = 8u;
        return 1u;
    case 5u:
        out_action->kind = 4u; /* 'u' */
        out_action->is_signed = 0u;
        out_action->base = 10u;
        return 1u;
    case 6u:
        out_action->kind = 4u; /* 'x'/'p' */
        out_action->is_signed = 0u;
        out_action->base = 16u;
        return 1u;
    case 7u:
        out_action->kind = 5u; /* 'e'/'f'/'g' float */
        return 1u;
    case 9u:
        out_action->kind = 6u; /* 'n' count */
        return 1u;
    default:
        out_action->valid = 0u;
        return 0u;
    }
}

/* `0x1169ecd8` */
int32_t rome2_vfs_crt_getenv_s(
    size_t *out_required_bytes,
    char *buf,
    size_t buf_cap,
    const char *varname,
    const rome2_vfs_crt_env_kv *env_entries,
    size_t env_count,
    int32_t *out_errno) {
    if (!out_required_bytes) {
        r2_set_err(out_errno, ROME2_VFS_L53_EINVAL);
        return ROME2_VFS_L53_EINVAL;
    }
    *out_required_bytes = 0u;
    if ((buf == NULL && buf_cap > 0u) || (buf != NULL && buf_cap == 0u) || !varname) {
        if (buf && buf_cap > 0u) {
            buf[0] = '\0';
        }
        r2_set_err(out_errno, ROME2_VFS_L53_EINVAL);
        return ROME2_VFS_L53_EINVAL;
    }

    const char *found = NULL;
    if (env_entries) {
        for (size_t i = 0u; i < env_count; ++i) {
            if (env_entries[i].name && r2_c_ieq(env_entries[i].name, varname) != 0) {
                found = env_entries[i].value ? env_entries[i].value : "";
                break;
            }
        }
    }

    if (!found) {
        if (buf && buf_cap > 0u) {
            buf[0] = '\0';
        }
        return 0;
    }

    size_t need = strlen(found) + 1u;
    *out_required_bytes = need;
    if (!buf) {
        return 0;
    }
    if (buf_cap < need) {
        buf[0] = '\0';
        r2_set_err(out_errno, ROME2_VFS_L53_ERANGE);
        return ROME2_VFS_L53_ERANGE;
    }
    memcpy(buf, found, need);
    return 0;
}

static uint8_t r2_fls_common_prepare(
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint8_t is_std_err_or_out_tty,
    rome2_vfs_crt_stream_seek0_fn seek_fn,
    void *ctx,
    int32_t *out_errno) {
    if ((stream->flags_0c & (ROME2_VFS_L53_IOWRITE | ROME2_VFS_L53_IORW)) == 0u) {
        r2_set_err(out_errno, ROME2_VFS_L53_EBADF);
        stream->flags_0c |= ROME2_VFS_L53_IOERR;
        return 0u;
    }
    if ((stream->flags_0c & ROME2_VFS_L53_IOSTRG) != 0u) {
        r2_set_err(out_errno, ROME2_VFS_L53_ERANGE);
        stream->flags_0c |= ROME2_VFS_L53_IOERR;
        return 0u;
    }
    if ((stream->flags_0c & ROME2_VFS_L53_IOREAD) != 0u) {
        uint8_t seek_ok = seek_fn ? seek_fn(stream, ctx) : 1u;
        stream->cnt_08 = 0;
        if (seek_ok == 0u) {
            stream->flags_0c |= ROME2_VFS_L53_IOERR;
            return 0u;
        }
        stream->ptr_00 = stream->base_04;
        stream->flags_0c &= ~((uint32_t)ROME2_VFS_L53_IOREAD);
    }
    stream->flags_0c |= ROME2_VFS_L53_IOWRITE;
    stream->flags_0c &= ~((uint32_t)ROME2_VFS_L53_IOEOF);
    stream->cnt_08 = 0;

    if ((stream->flags_0c & ROME2_VFS_L53_IOSTD_TTY_BYPASS) == 0u) {
        if (is_std_err_or_out_tty == 0u && stream->base_04 == 0u) {
            stream->bufsiz_18 = 4096;
        }
    }
    return 1u;
}

/* `0x116a5864` */
int32_t rome2_vfs_crt_flsbuf(
    int32_t ch,
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint8_t is_std_err_or_out_tty,
    rome2_vfs_crt_stream_seek0_fn seek_fn,
    rome2_vfs_crt_stream_write_unit_fn write_fn,
    void *ctx,
    int32_t *out_errno) {
    if (!stream || !write_fn) {
        r2_set_err(out_errno, ROME2_VFS_L53_EINVAL);
        return ROME2_VFS_L53_EOF;
    }
    if (r2_fls_common_prepare(stream, is_std_err_or_out_tty, seek_fn, ctx, out_errno) == 0u) {
        return ROME2_VFS_L53_EOF;
    }
    uint8_t byte_val = (uint8_t)(ch & 0xff);
    if (write_fn(stream, (uint32_t)byte_val, ctx) == 0u) {
        stream->flags_0c |= ROME2_VFS_L53_IOERR;
        return ROME2_VFS_L53_EOF;
    }
    return (int32_t)byte_val;
}

/* `0x116a586f` */
uint16_t rome2_vfs_crt_flswbuf(
    uint16_t wch,
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint8_t is_std_err_or_out_tty,
    rome2_vfs_crt_stream_seek0_fn seek_fn,
    rome2_vfs_crt_stream_write_unit_fn write_fn,
    void *ctx,
    int32_t *out_errno) {
    if (!stream || !write_fn) {
        r2_set_err(out_errno, ROME2_VFS_L53_EINVAL);
        return ROME2_VFS_L53_WEOF;
    }
    if (r2_fls_common_prepare(stream, is_std_err_or_out_tty, seek_fn, ctx, out_errno) == 0u) {
        return ROME2_VFS_L53_WEOF;
    }
    if (write_fn(stream, (uint32_t)wch, ctx) == 0u) {
        stream->flags_0c |= ROME2_VFS_L53_IOERR;
        return ROME2_VFS_L53_WEOF;
    }
    return wch;
}

/* `0x116a5b4b` */
int32_t rome2_vfs_crt_wctomb_s_l(
    int32_t *out_converted,
    uint8_t *mbchar,
    size_t size_in_bytes,
    uint16_t wchar,
    uint32_t codepage,
    uint8_t is_c_locale,
    int32_t *out_errno) {
    if (mbchar == NULL && size_in_bytes > 0u) {
        if (out_converted) {
            *out_converted = 0;
        }
        return 0;
    }
    if (out_converted) {
        *out_converted = -1;
    }
    if (size_in_bytes > 0x7fffffffu) {
        r2_set_err(out_errno, ROME2_VFS_L53_EINVAL);
        return ROME2_VFS_L53_EINVAL;
    }
    if (codepage == 0xfde9u) {
        uint8_t tmp[3] = { 0u, 0u, 0u };
        size_t need = 0u;
        if (wchar <= 0x7fu) {
            tmp[0] = (uint8_t)wchar;
            need = 1u;
        } else if (wchar <= 0x7ffu) {
            tmp[0] = (uint8_t)(0xc0u | (wchar >> 6));
            tmp[1] = (uint8_t)(0x80u | (wchar & 0x3fu));
            need = 2u;
        } else if (wchar >= 0xd800u && wchar <= 0xdfffu) {
            if (mbchar && size_in_bytes > 0u) {
                memset(mbchar, 0, size_in_bytes);
            }
            r2_set_err(out_errno, ROME2_VFS_L53_EILSEQ);
            return ROME2_VFS_L53_EILSEQ;
        } else {
            tmp[0] = (uint8_t)(0xe0u | (wchar >> 12));
            tmp[1] = (uint8_t)(0x80u | ((wchar >> 6) & 0x3fu));
            tmp[2] = (uint8_t)(0x80u | (wchar & 0x3fu));
            need = 3u;
        }
        if (mbchar != NULL) {
            if (size_in_bytes < need) {
                memset(mbchar, 0, size_in_bytes);
                r2_set_err(out_errno, ROME2_VFS_L53_ERANGE);
                return ROME2_VFS_L53_ERANGE;
            }
            memcpy(mbchar, tmp, need);
        }
        if (out_converted) {
            *out_converted = (int32_t)need;
        }
        return 0;
    }

    (void)is_c_locale;
    if (wchar > 0xffu) {
        if (mbchar && size_in_bytes > 0u) {
            memset(mbchar, 0, size_in_bytes);
        }
        r2_set_err(out_errno, ROME2_VFS_L53_EILSEQ);
        return ROME2_VFS_L53_EILSEQ;
    }
    if (mbchar != NULL) {
        if (size_in_bytes == 0u) {
            r2_set_err(out_errno, ROME2_VFS_L53_ERANGE);
            return ROME2_VFS_L53_ERANGE;
        }
        mbchar[0] = (uint8_t)wchar;
    }
    if (out_converted) {
        *out_converted = 1;
    }
    return 0;
}

/* `0x116a613a` */
int32_t rome2_vfs_crt_fp_format_e_internal(
    char *result_buf,
    size_t buf_cap,
    int32_t precision,
    uint8_t cap_exp,
    uint32_t min_exponent_digits,
    const rome2_vfs_crt_strflt12_32 *strflt,
    const char *digits_buf,
    uint8_t g_mode,
    char decimal_point,
    int32_t *out_errno) {
    int32_t p_pos = precision > 0 ? precision : 0;
    if (!result_buf || !strflt || !digits_buf || buf_cap <= (size_t)p_pos + 9u) {
        r2_set_err(out_errno, (result_buf && strflt && digits_buf) ? ROME2_VFS_L53_ERANGE : ROME2_VFS_L53_EINVAL);
        return (result_buf && strflt && digits_buf) ? ROME2_VFS_L53_ERANGE : ROME2_VFS_L53_EINVAL;
    }

    if (g_mode != 0u) {
        size_t sign_off = (strflt->sign_00 == '-') ? 1u : 0u;
        size_t shift_amt = (precision > 0) ? 1u : 0u;
        if (shift_amt > 0u) {
            size_t len = strlen(result_buf);
            if (len + shift_amt + 1u > buf_cap) {
                r2_set_err(out_errno, ROME2_VFS_L53_ERANGE);
                return ROME2_VFS_L53_ERANGE;
            }
            memmove(result_buf + sign_off + shift_amt, result_buf + sign_off, (len - sign_off) + 1u);
        }
    }

    char *cur = result_buf;
    if (strflt->sign_00 == '-') {
        *cur = '-';
        ++cur;
    }
    if (precision > 0) {
        cur[0] = cur[1];
        ++cur;
        *cur = decimal_point;
    }
    cur += (size_t)precision + (size_t)(g_mode ^ 1u);
    size_t rem_cap = buf_cap - (size_t)(cur - result_buf);
    if (rem_cap < 6u) {
        r2_set_err(out_errno, ROME2_VFS_L53_ERANGE);
        return ROME2_VFS_L53_ERANGE;
    }
    memcpy(cur, "e+000", 6u);
    char *exp_digits = cur + 2;
    if (cap_exp != 0u) {
        cur[0] = 'E';
    }
    if (digits_buf[0] != '0') {
        int32_t exp_val = strflt->decpt_04 - 1;
        if (exp_val < 0) {
            exp_val = -exp_val;
            cur[1] = '-';
        }
        if (exp_val >= 100) {
            cur[2] = (char)(cur[2] + (char)(exp_val / 100));
            exp_val %= 100;
        }
        if (exp_val >= 10) {
            cur[3] = (char)(cur[3] + (char)(exp_val / 10));
            exp_val %= 10;
        }
        cur[4] = (char)(cur[4] + (char)exp_val);
    }
    if (min_exponent_digits == 2u && exp_digits[0] == '0') {
        memmove(exp_digits, exp_digits + 1, 3u);
    }
    return 0;
}

/* `0x116a630d` */
int32_t rome2_vfs_crt_fp_format_f_internal(
    char *result_buf,
    size_t buf_cap,
    int32_t precision,
    const rome2_vfs_crt_strflt12_32 *strflt,
    uint8_t g_mode,
    char decimal_point,
    int32_t *out_errno) {
    if (!result_buf || !strflt || buf_cap == 0u) {
        r2_set_err(out_errno, ROME2_VFS_L53_EINVAL);
        return ROME2_VFS_L53_EINVAL;
    }
    int32_t dec_m1 = strflt->decpt_04 - 1;
    if (g_mode != 0u && dec_m1 == precision) {
        size_t z_off = (strflt->sign_00 == '-') ? 1u : 0u;
        size_t idx = (size_t)dec_m1 + z_off;
        if (idx + 1u < buf_cap) {
            result_buf[idx] = '0';
            result_buf[idx + 1u] = '\0';
        }
    }

    char *cur = result_buf;
    if (strflt->sign_00 == '-') {
        *cur = '-';
        ++cur;
    }

    int32_t decpt = strflt->decpt_04;
    if (decpt <= 0) {
        size_t cur_off = (size_t)(cur - result_buf);
        size_t len = strlen(cur);
        if (cur_off + len + 2u > buf_cap) {
            r2_set_err(out_errno, ROME2_VFS_L53_ERANGE);
            return ROME2_VFS_L53_ERANGE;
        }
        memmove(cur + 1, cur, len + 1u);
        cur[0] = '0';
        cur += 1;
    } else {
        cur += (size_t)decpt;
    }

    if (precision > 0) {
        size_t cur_off = (size_t)(cur - result_buf);
        size_t tail_len = strlen(cur);
        if (cur_off + tail_len + 2u > buf_cap) {
            r2_set_err(out_errno, ROME2_VFS_L53_ERANGE);
            return ROME2_VFS_L53_ERANGE;
        }
        memmove(cur + 1, cur, tail_len + 1u);
        *cur = decimal_point;
        ++cur;

        if (decpt < 0) {
            int32_t zeros = -decpt;
            if (g_mode == 0u && zeros >= precision) {
                zeros = precision;
            }
            cur_off = (size_t)(cur - result_buf);
            tail_len = strlen(cur);
            if (cur_off + (size_t)zeros + tail_len + 1u > buf_cap) {
                r2_set_err(out_errno, ROME2_VFS_L53_ERANGE);
                return ROME2_VFS_L53_ERANGE;
            }
            memmove(cur + (size_t)zeros, cur, tail_len + 1u);
            memset(cur, '0', (size_t)zeros);
        }
    }
    return 0;
}

/* `0x116a83bd` */
uint32_t rome2_vfs_crt_try_get_lcmapstring_ex(
    rome2_vfs_crt_resolve_api_fn resolve_fn,
    void *ctx) {
    static const rome2_vfs_crt_api_mod_desc8_32 k_mods[2] = {
        { 3u, 16u }, /* 0x11914d60 */
        { 4u, 16u }, /* 0x11914d68 end sentinel */
    };
    if (!resolve_fn) {
        return 0u;
    }
    return resolve_fn(0x14u, "LCMapStringEx", &k_mods[0], &k_mods[1], ctx);
}

/* `0x116a8a8d` */
uint32_t rome2_vfs_crt_locale_name_to_lcid(
    const uint16_t *locale_name,
    uint32_t flags,
    uint8_t has_modern_api,
    uint32_t modern_lcid,
    uint32_t downlevel_lcid) {
    (void)flags;
    if (has_modern_api != 0u) {
        return modern_lcid;
    }
    if (!locale_name) {
        return 0u;
    }
    if (r2_w_ieq(locale_name, "en-US") != 0) {
        return 0x0409u;
    }
    return downlevel_lcid;
}

/* `0x116b149d` */
uint32_t rome2_vfs_crt_return_illegal_sequence(
    rome2_vfs_crt_mbstate8_32 *ps,
    int32_t *out_errno) {
    if (ps) {
        ps->wchar_00 = 0u;
        ps->byte_04 = 0u;
        ps->state_06 = 0u;
    }
    r2_set_err(out_errno, ROME2_VFS_L53_EILSEQ);
    return 0xffffffffu;
}

/* `0x116b8215` */
uint8_t rome2_vfs_crt_get_string_type_w(
    uint32_t dw_info_type,
    const uint16_t *src_str,
    int32_t cch_src,
    uint16_t *char_type_out) {
    if (dw_info_type != 1u || !src_str || !char_type_out || cch_src <= 0) {
        return 0u;
    }
    for (int32_t i = 0; i < cch_src; ++i) {
        uint16_t ch = src_str[i];
        uint16_t bits = 0u;
        if (ch <= 0x1fu || ch == 0x7fu) {
            bits |= 0x0020u; /* C1_CNTRL */
        }
        if (ch == ' ' || ch == '\t') {
            bits |= 0x0040u; /* C1_BLANK */
        }
        if (ch == ' ' || (ch >= '\t' && ch <= '\r')) {
            bits |= 0x0008u; /* C1_SPACE */
        }
        if (ch >= '0' && ch <= '9') {
            bits |= 0x0004u | 0x0080u; /* C1_DIGIT | C1_XDIGIT */
        } else if (ch >= 'A' && ch <= 'Z') {
            bits |= 0x0001u | 0x0100u; /* C1_UPPER | C1_ALPHA */
            if (ch <= 'F') {
                bits |= 0x0080u; /* C1_XDIGIT */
            }
        } else if (ch >= 'a' && ch <= 'z') {
            bits |= 0x0002u | 0x0100u; /* C1_LOWER | C1_ALPHA */
            if (ch <= 'f') {
                bits |= 0x0080u; /* C1_XDIGIT */
            }
        } else if (ch > 0x20u && ch < 0x7fu) {
            bits |= 0x0010u; /* C1_PUNCT */
        }
        char_type_out[i] = bits;
    }
    return 1u;
}

/* `0x116bd4d3` */
void rome2_vfs_crt_console_output_init(
    uint32_t *out_console_handle,
    rome2_vfs_crt_open_conout_fn open_fn,
    void *ctx) {
    static const uint16_t k_conout[8] = { 'C', 'O', 'N', 'O', 'U', 'T', '$', 0u };
    if (!out_console_handle) {
        return;
    }
    *out_console_handle = open_fn ? open_fn(k_conout, ctx) : ROME2_VFS_L53_INVALID_HANDLE;
}

/* `0x116bd511` */
uint8_t rome2_vfs_crt_console_output_terminate(
    uint32_t console_handle,
    rome2_vfs_crt_close_handle_fn close_fn,
    void *ctx) {
    if (console_handle == ROME2_VFS_L53_INVALID_HANDLE || console_handle == ROME2_VFS_L53_CONSOLE_UNINIT) {
        return 0u;
    }
    if (!close_fn) {
        return 0u;
    }
    return close_fn(console_handle, ctx);
}

/* `0x116bf330` */
const char *rome2_vfs_crt_strrchr(
    const char *str,
    size_t max_len,
    int32_t ch,
    uint32_t isa_available) {
    (void)isa_available;
    if (!str || max_len == 0u) {
        return NULL;
    }
    uint8_t target = (uint8_t)(ch & 0xff);
    const char *last = NULL;
    for (size_t i = 0u; i < max_len; ++i) {
        uint8_t cur = (uint8_t)str[i];
        if (cur == target) {
            last = &str[i];
        }
        if (cur == 0u) {
            return last;
        }
    }
    return last;
}

#include "vfs_fs_engine_crt_fpfmt_ops.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    ROME2_VFS_L51_ENOMEM = 12,
    ROME2_VFS_L51_EACCES = 13,
    ROME2_VFS_L51_EBADF = 9,
    ROME2_VFS_L51_EINVAL = 22,
    ROME2_VFS_L51_ERANGE = 34,
    ROME2_VFS_L51_EILSEQ = 42,
    ROME2_VFS_L51_ERR_INV_DRIVE = 15,
    ROME2_VFS_L51_WEOF = 0xffffu
};

static uint8_t r2_is_digit(uint8_t ch) {
    return (ch >= (uint8_t)'0' && ch <= (uint8_t)'9') ? 1u : 0u;
}

static uint8_t r2_ascii_lower(uint8_t ch) {
    if (ch >= (uint8_t)'A' && ch <= (uint8_t)'Z') {
        return (uint8_t)(ch + 32u);
    }
    return ch;
}

static uint8_t r2_is_leap_year_crt(int32_t yr_since_1900) {
    int32_t full = yr_since_1900 + 1900;
    if ((yr_since_1900 % 4) != 0) {
        return 0u;
    }
    if ((full % 100) != 0 || (full % 400) == 0) {
        return 1u;
    }
    return 0u;
}

static int32_t r2_elapsed_leap_years_since_70(int32_t yr_since_1900) {
    int32_t ym = yr_since_1900 - 1;
    return ((yr_since_1900 + 299) / 400) - (ym / 100) + (ym / 4) - 17;
}

static void r2_emit_utf8_byte_pairs(
    uint32_t cp,
    uint8_t *out_bytes,
    size_t out_cap,
    size_t *out_len) {
    if (cp <= 0x7fu && out_cap >= 1u) {
        out_bytes[0] = (uint8_t)cp;
        *out_len = 1u;
    } else if (cp <= 0x7ffu && out_cap >= 2u) {
        out_bytes[0] = (uint8_t)(0xc0u | (cp >> 6));
        out_bytes[1] = (uint8_t)(0x80u | (cp & 0x3fu));
        *out_len = 2u;
    } else if (out_cap >= 3u) {
        out_bytes[0] = (uint8_t)(0xe0u | (cp >> 12));
        out_bytes[1] = (uint8_t)(0x80u | ((cp >> 6) & 0x3fu));
        out_bytes[2] = (uint8_t)(0x80u | (cp & 0x3fu));
        *out_len = 3u;
    } else {
        *out_len = 0u;
    }
}

static int32_t r2_decode_utf8_cp(
    const uint8_t *s,
    size_t n,
    uint32_t *out_cp) {
    uint8_t b0 = s[0];
    if (b0 < 0x80u) {
        *out_cp = (uint32_t)b0;
        return (b0 == 0u) ? 0 : 1;
    }
    if ((b0 & 0xe0u) == 0xc0u) {
        if (n < 2u || (s[1] & 0xc0u) != 0x80u) {
            return -1;
        }
        uint32_t cp = ((uint32_t)(b0 & 0x1fu) << 6) | (uint32_t)(s[1] & 0x3fu);
        if (cp < 0x80u) {
            return -1;
        }
        *out_cp = cp;
        return 2;
    }
    if ((b0 & 0xf0u) == 0xe0u) {
        if (n < 3u || (s[1] & 0xc0u) != 0x80u || (s[2] & 0xc0u) != 0x80u) {
            return -1;
        }
        uint32_t cp = ((uint32_t)(b0 & 0x0fu) << 12)
            | ((uint32_t)(s[1] & 0x3fu) << 6)
            | (uint32_t)(s[2] & 0x3fu);
        if (cp < 0x800u || (cp >= 0xd800u && cp <= 0xdfffu)) {
            return -1;
        }
        *out_cp = cp;
        return 3;
    }
    if ((b0 & 0xf8u) == 0xf0u) {
        if (n < 4u || (s[1] & 0xc0u) != 0x80u || (s[2] & 0xc0u) != 0x80u || (s[3] & 0xc0u) != 0x80u) {
            return -1;
        }
        uint32_t cp = ((uint32_t)(b0 & 0x07u) << 18)
            | ((uint32_t)(s[1] & 0x3fu) << 12)
            | ((uint32_t)(s[2] & 0x3fu) << 6)
            | (uint32_t)(s[3] & 0x3fu);
        if (cp < 0x10000u || cp > 0x10ffffu) {
            return -1;
        }
        *out_cp = cp;
        return 4;
    }
    return -1;
}

/* `0x11688991` */
uint32_t rome2_vfs_crt_fmt_buf_count_wchar(
    const rome2_vfs_crt_formatting_buffer1032_32 *fb) {
    if (!fb || fb->heap_ptr_404 == 0u) {
        return 0x200u;
    }
    return fb->allocated_bytes_400 >> 1;
}

static uint8_t r2_fmt_buf_ensure_bytes(
    rome2_vfs_crt_formatting_buffer1032_32 *fb,
    uint32_t needed_bytes,
    uint8_t alloc_succeeds,
    int32_t *out_errno) {
    if (!fb) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L51_EINVAL;
        }
        return 0u;
    }
    if (fb->heap_ptr_404 == 0u && needed_bytes <= 0x400u) {
        return 1u;
    }
    if (needed_bytes <= fb->allocated_bytes_400) {
        return 1u;
    }
    if (!alloc_succeeds) {
        return 0u;
    }
    fb->heap_ptr_404 = 1u;
    fb->allocated_bytes_400 = needed_bytes;
    return 1u;
}

/* `0x116889c2` */
uint8_t rome2_vfs_crt_fmt_buf_ensure_wchar(
    rome2_vfs_crt_formatting_buffer1032_32 *fb,
    uint32_t wchar_count,
    uint8_t alloc_succeeds,
    int32_t *out_errno) {
    if (wchar_count > 0x7fffffffu) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L51_ENOMEM;
        }
        return 0u;
    }
    return r2_fmt_buf_ensure_bytes(fb, wchar_count * 2u, alloc_succeeds, out_errno);
}

/* `0x11688a3f` */
uint8_t rome2_vfs_crt_fmt_buf_ensure_dword(
    rome2_vfs_crt_formatting_buffer1032_32 *fb,
    uint32_t dword_count,
    uint8_t alloc_succeeds,
    int32_t *out_errno) {
    if (dword_count > 0x3fffffffu) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L51_ENOMEM;
        }
        return 0u;
    }
    return r2_fmt_buf_ensure_bytes(fb, dword_count * 4u, alloc_succeeds, out_errno);
}

/* `0x11688b3c` */
uint32_t rome2_vfs_crt_fmt_buf_scratch_offset(
    const rome2_vfs_crt_formatting_buffer1032_32 *fb) {
    return rome2_vfs_crt_fmt_buf_count_wchar(fb);
}

/* `0x11688aee` */
uint8_t rome2_vfs_crt_is_wide_specifier(
    uint32_t options_lo,
    uint16_t specifier,
    int32_t length_mod) {
    if (length_mod == 2) {
        return 0u;
    }
    if (length_mod == 3 || length_mod == 12 || length_mod == 13) {
        return 1u;
    }
    uint8_t legacy = ((options_lo & 4u) != 0u) ? 1u : 0u;
    uint8_t base = (specifier == (uint16_t)'c' || specifier == (uint16_t)'s') ? 0u : 1u;
    return (uint8_t)(base ^ legacy);
}

/* `0x11688bcd` & `0x11688ce2` */
void rome2_vfs_crt_uint64_to_wstring(
    uint64_t value,
    uint64_t radix,
    uint8_t is_upper,
    int32_t *inout_min_digits,
    uint16_t *out_buf,
    size_t out_cap_wchars,
    uint32_t *out_start_index,
    uint32_t *out_written_len) {
    if (!out_buf || out_cap_wchars == 0u || radix < 2u || radix > 36u) {
        if (out_start_index) {
            *out_start_index = 0u;
        }
        if (out_written_len) {
            *out_written_len = 0u;
        }
        return;
    }
    size_t end_idx = out_cap_wchars - 1u;
    size_t cur = end_idx;
    int32_t min_d = inout_min_digits ? *inout_min_digits : 0;

    while (min_d > 0 || value != 0u) {
        --min_d;
        uint64_t rem = value % radix;
        value /= radix;
        uint16_t ch = (uint16_t)(rem + 0x30u);
        if (ch > 0x39u) {
            uint8_t delta = (uint8_t)((((is_upper ? 1u : 0u) ^ 1u) << 5) + 7u);
            ch = (uint16_t)(ch + delta);
        }
        out_buf[cur] = ch;
        if (cur == 0u) {
            if (inout_min_digits) {
                *inout_min_digits = min_d;
            }
            if (out_start_index) {
                *out_start_index = 0u;
            }
            if (out_written_len) {
                *out_written_len = (uint32_t)(end_idx + 1u);
            }
            return;
        }
        --cur;
    }

    if (inout_min_digits) {
        *inout_min_digits = min_d;
    }
    if (out_start_index) {
        *out_start_index = (uint32_t)(cur + 1u);
    }
    if (out_written_len) {
        *out_written_len = (uint32_t)(end_idx - cur);
    }
}

void rome2_vfs_crt_uint32_to_wstring(
    uint32_t value,
    uint32_t radix,
    uint8_t is_upper,
    int32_t *inout_min_digits,
    uint16_t *out_buf,
    size_t out_cap_wchars,
    uint32_t *out_start_index,
    uint32_t *out_written_len) {
    rome2_vfs_crt_uint64_to_wstring(
        (uint64_t)value,
        (uint64_t)radix,
        is_upper,
        inout_min_digits,
        out_buf,
        out_cap_wchars,
        out_start_index,
        out_written_len);
}

/* `0x11689271` */
void rome2_vfs_crt_crop_zeroes(
    char *buf,
    size_t buf_cap,
    char decimal_point) {
    if (!buf || buf_cap == 0u) {
        return;
    }
    size_t i = 0u;
    while (i < buf_cap && buf[i] != '\0' && buf[i] != decimal_point) {
        ++i;
    }
    if (i >= buf_cap || buf[i] == '\0') {
        return;
    }
    ++i;
    while (i < buf_cap && buf[i] != '\0' && buf[i] != 'e' && buf[i] != 'E') {
        ++i;
    }
    if (i >= buf_cap) {
        return;
    }
    size_t exp_pos = i;
    size_t stop_pos = exp_pos;
    if (stop_pos == 0u) {
        return;
    }
    --stop_pos;
    while (stop_pos > 0u && buf[stop_pos] == '0') {
        --stop_pos;
    }
    if (buf[stop_pos] == decimal_point && stop_pos > 0u) {
        --stop_pos;
    } else if (buf[stop_pos] == decimal_point) {
        /* Unlikely ".00" at start: drop decimal point too. */
        size_t tail_len = 0u;
        while (exp_pos + tail_len < buf_cap && buf[exp_pos + tail_len] != '\0') {
            ++tail_len;
        }
        memmove(buf, buf + exp_pos, tail_len + 1u);
        return;
    }
    size_t tail_len = 0u;
    while (exp_pos + tail_len < buf_cap && buf[exp_pos + tail_len] != '\0') {
        ++tail_len;
    }
    if (exp_pos + tail_len >= buf_cap) {
        return;
    }
    memmove(buf + stop_pos + 1u, buf + exp_pos, tail_len + 1u);
}

/* `0x116893cf` */
void rome2_vfs_crt_force_decimal_point(
    char *buf,
    size_t buf_cap,
    char decimal_point) {
    if (!buf || buf_cap == 0u) {
        return;
    }
    size_t len = 0u;
    while (len < buf_cap && buf[len] != '\0') {
        ++len;
    }
    if (len + 1u >= buf_cap) {
        return;
    }
    size_t i = 0u;
    if (r2_ascii_lower((uint8_t)buf[i]) != (uint8_t)'e') {
        do {
            ++i;
        } while (i < len && r2_is_digit((uint8_t)buf[i]));
    }
    if (i < len && r2_ascii_lower((uint8_t)buf[i]) == (uint8_t)'x') {
        i += 2u;
        if (i > len) {
            i = len;
        }
    }
    memmove(buf + i + 1u, buf + i, len - i + 1u);
    buf[i] = decimal_point;
}

/* `0x1168b801` */
int32_t rome2_vfs_crt_wprintf_mbchar_count(
    const uint8_t *str,
    size_t buf_len,
    int32_t max_chars,
    const uint8_t is_lead_table[256]) {
    if (!str || max_chars <= 0 || buf_len == 0u) {
        return 0;
    }
    int32_t chars = 0;
    size_t pos = 0u;
    while (chars < max_chars && pos < buf_len && str[pos] != 0u) {
        uint8_t b = str[pos];
        if (is_lead_table && is_lead_table[b] != 0u && pos + 1u < buf_len) {
            ++pos;
        }
        ++pos;
        ++chars;
    }
    return chars;
}

/* `0x1168d62c` */
uint32_t rome2_vfs_crt_parse_uint32_wstr(
    const uint16_t *src,
    size_t src_cap_wchars,
    size_t *out_end_index,
    int32_t base,
    uint8_t is_signed,
    int32_t *out_errno) {
    if (!src || src_cap_wchars == 0u || (base != 0 && (base < 2 || base > 36))) {
        if (out_end_index) {
            *out_end_index = 0u;
        }
        if (out_errno) {
            *out_errno = ROME2_VFS_L51_EINVAL;
        }
        return 0u;
    }

    size_t i = 0u;
    while (i < src_cap_wchars) {
        uint16_t c = src[i];
        if (c == (uint16_t)' ' || (c >= 0x09u && c <= 0x0du)) {
            ++i;
        } else {
            break;
        }
    }

    uint8_t negative = 0u;
    if (i < src_cap_wchars && (src[i] == (uint16_t)'+' || src[i] == (uint16_t)'-')) {
        negative = (src[i] == (uint16_t)'-') ? 1u : 0u;
        ++i;
    }

    if ((base == 0 || base == 16) && i + 1u < src_cap_wchars
        && src[i] == (uint16_t)'0'
        && (src[i + 1u] == (uint16_t)'x' || src[i + 1u] == (uint16_t)'X')) {
        base = 16;
        i += 2u;
    } else if (base == 0 && i < src_cap_wchars && src[i] == (uint16_t)'0') {
        base = 8;
    } else if (base == 0) {
        base = 10;
    }

    uint64_t acc = 0u;
    uint8_t saw_digit = 0u;
    uint8_t overflow = 0u;
    uint64_t cutoff = is_signed ? (negative ? 0x80000000ULL : 0x7fffffffULL) : 0xffffffffULL;

    while (i < src_cap_wchars && src[i] != 0u) {
        uint16_t c = src[i];
        int32_t digit = -1;
        if (c >= (uint16_t)'0' && c <= (uint16_t)'9') {
            digit = (int32_t)(c - (uint16_t)'0');
        } else if (c >= (uint16_t)'a' && c <= (uint16_t)'z') {
            digit = (int32_t)(c - (uint16_t)'a' + 10u);
        } else if (c >= (uint16_t)'A' && c <= (uint16_t)'Z') {
            digit = (int32_t)(c - (uint16_t)'A' + 10u);
        }
        if (digit < 0 || digit >= base) {
            break;
        }
        saw_digit = 1u;
        if (!overflow) {
            if (acc > (cutoff - (uint64_t)digit) / (uint64_t)base) {
                overflow = 1u;
                acc = cutoff;
            } else {
                acc = acc * (uint64_t)base + (uint64_t)digit;
            }
        }
        ++i;
    }

    if (!saw_digit) {
        if (out_end_index) {
            *out_end_index = 0u;
        }
        return 0u;
    }
    if (out_end_index) {
        *out_end_index = i;
    }
    if (overflow) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L51_ERANGE;
        }
        return (uint32_t)cutoff;
    }
    uint32_t val = (uint32_t)acc;
    return negative ? (uint32_t)(0u - val) : val;
}

/* `0x1169d3f9` */
size_t rome2_vfs_crt_mbsrtowcs_utf8(
    uint16_t *dst,
    const uint8_t **inout_src,
    size_t dst_cap_wchars,
    int32_t *out_errno) {
    if (!inout_src || !*inout_src) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L51_EINVAL;
        }
        return (size_t)-1;
    }
    const uint8_t *s = *inout_src;
    if (!dst) {
        size_t total = 0u;
        while (*s != 0u) {
            uint32_t cp = 0u;
            int32_t step = r2_decode_utf8_cp(s, 4u, &cp);
            if (step < 0) {
                if (out_errno) {
                    *out_errno = ROME2_VFS_L51_EILSEQ;
                }
                return (size_t)-1;
            }
            if (step == 0) {
                break;
            }
            total += (cp > 0xffffu) ? 2u : 1u;
            s += (size_t)step;
        }
        return total;
    }

    size_t rem = dst_cap_wchars;
    size_t written = 0u;
    while (rem > 0u) {
        uint32_t cp = 0u;
        if (*s == 0u) {
            dst[written] = 0u;
            *inout_src = NULL;
            return written;
        }
        int32_t step = r2_decode_utf8_cp(s, 4u, &cp);
        if (step < 0) {
            *inout_src = s;
            if (out_errno) {
                *out_errno = ROME2_VFS_L51_EILSEQ;
            }
            return (size_t)-1;
        }
        if (cp > 0xffffu) {
            if (rem <= 1u) {
                break;
            }
            cp -= 0x10000u;
            dst[written++] = (uint16_t)(0xd800u | (cp >> 10));
            dst[written++] = (uint16_t)(0xdc00u | (cp & 0x3ffu));
            rem -= 2u;
        } else {
            dst[written++] = (uint16_t)cp;
            --rem;
        }
        s += (size_t)step;
    }
    *inout_src = s;
    return written;
}

/* `0x1169e75f` */
int64_t rome2_vfs_crt_common_lseek64_nolock(
    uint8_t valid_handle,
    uint8_t seek_ok,
    int64_t new_pos,
    uint32_t win32_err,
    rome2_vfs_crt_ioinfo56_32 *io,
    int32_t *out_errno,
    int32_t *out_doserrno) {
    if (!valid_handle || !io) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L51_EBADF;
        }
        return -1;
    }
    if (!seek_ok) {
        if (out_doserrno) {
            *out_doserrno = (int32_t)win32_err;
        }
        if (out_errno) {
            *out_errno = ROME2_VFS_L51_EINVAL;
        }
        return -1;
    }
    io->osfile_28 &= (uint8_t)0xfdu;
    return new_pos;
}

/* `0x116a4118` */
size_t rome2_vfs_crt_wcsnlen(
    const uint16_t *s,
    size_t max_count) {
    if (!s) {
        return 0u;
    }
    size_t i = 0u;
    while (i < max_count && s[i] != 0u) {
        ++i;
    }
    return i;
}

/* `0x116a59ef` */
int32_t rome2_vfs_crt_mbtowc_l(
    uint16_t *pwc,
    const uint8_t *s,
    size_t n,
    uint32_t codepage,
    uint32_t *inout_mbstate_w,
    uint32_t *inout_mbstate_s,
    int32_t *out_errno) {
    if (!s || n == 0u) {
        if (inout_mbstate_w) {
            *inout_mbstate_w = 0u;
        }
        if (inout_mbstate_s) {
            *inout_mbstate_s = 0u;
        }
        return 0;
    }
    if (s[0] == 0u) {
        if (pwc) {
            *pwc = 0u;
        }
        return 0;
    }
    if (codepage == 0xfde9u) {
        uint32_t cp = 0u;
        int32_t step = r2_decode_utf8_cp(s, n, &cp);
        if (step <= 0 || cp > 0xffffu) {
            if (out_errno) {
                *out_errno = ROME2_VFS_L51_EILSEQ;
            }
            return -1;
        }
        if (pwc) {
            *pwc = (uint16_t)cp;
        }
        return step;
    }
    if (pwc) {
        *pwc = (uint16_t)s[0];
    }
    return 1;
}

/* `0x116a5b31` */
int32_t rome2_vfs_crt_mbtowc(
    uint16_t *pwc,
    const uint8_t *s,
    size_t n,
    int32_t *out_errno) {
    uint32_t st_w = 0u;
    uint32_t st_s = 0u;
    return rome2_vfs_crt_mbtowc_l(pwc, s, n, 0u, &st_w, &st_s, out_errno);
}

/* `0x116a6568` */
int32_t rome2_vfs_crt_acrt_fp_format(
    const double *val,
    char *result_buf,
    size_t result_size,
    char *scratch_buf,
    size_t scratch_size,
    int32_t format,
    int32_t precision,
    uint64_t options,
    int32_t *out_errno) {
    if (!val || !result_buf || result_size == 0u || !scratch_buf || scratch_size == 0u) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L51_EINVAL;
        }
        return ROME2_VFS_L51_EINVAL;
    }

    uint8_t caps = (format == 'A' || format == 'E' || format == 'F' || format == 'G') ? 1u : 0u;
    double d = *val;
    if ((options & 8u) == 0u && (isnan(d) || isinf(d))) {
        const char *text = isnan(d) ? (caps ? "NAN" : "nan") : (caps ? "INF" : "inf");
        int n = snprintf(result_buf, result_size, "%s%s", (signbit(d) && !isnan(d)) ? "-" : "", text);
        if (n < 0 || (size_t)n >= result_size) {
            result_buf[0] = '\0';
            return ROME2_VFS_L51_ERANGE;
        }
        return 0;
    }

    char fmt_str[16];
    char fmt_ch = (char)format;
    if (fmt_ch != 'a' && fmt_ch != 'A' && fmt_ch != 'e' && fmt_ch != 'E'
        && fmt_ch != 'f' && fmt_ch != 'F' && fmt_ch != 'g' && fmt_ch != 'G') {
        fmt_ch = 'g';
    }
    if (precision < 0) {
        precision = (fmt_ch == 'a' || fmt_ch == 'A') ? 13 : 6;
    }
    snprintf(fmt_str, sizeof(fmt_str), "%%.%d%c", precision, fmt_ch);
    int n = snprintf(scratch_buf, scratch_size, fmt_str, d);
    if (n < 0 || (size_t)n >= result_size) {
        result_buf[0] = '\0';
        if (out_errno) {
            *out_errno = ROME2_VFS_L51_ERANGE;
        }
        return ROME2_VFS_L51_ERANGE;
    }
    memcpy(result_buf, scratch_buf, (size_t)n + 1u);
    return 0;
}

/* `0x116a66d3` */
uint16_t rome2_vfs_crt_fputwc_nolock(
    uint16_t ch,
    uint32_t file_flags,
    const rome2_vfs_crt_ioinfo56_32 *io,
    uint8_t *out_bytes,
    size_t out_cap,
    size_t *out_written_bytes) {
    size_t written = 0u;
    if (!out_bytes) {
        if (out_written_bytes) {
            *out_written_bytes = 0u;
        }
        return (uint16_t)ROME2_VFS_L51_WEOF;
    }
    if (((file_flags >> 12) & 1u) != 0u
        || (io && (io->pad_29[0] == 1u || io->pad_29[0] == 2u || (io->osfile_28 & 0x80u) == 0u))) {
        if (out_cap < 2u) {
            if (out_written_bytes) {
                *out_written_bytes = 0u;
            }
            return (uint16_t)ROME2_VFS_L51_WEOF;
        }
        out_bytes[0] = (uint8_t)(ch & 0xffu);
        out_bytes[1] = (uint8_t)((ch >> 8) & 0xffu);
        written = 2u;
    } else {
        r2_emit_utf8_byte_pairs((uint32_t)ch, out_bytes, out_cap, &written);
        if (written == 0u) {
            if (out_written_bytes) {
                *out_written_bytes = 0u;
            }
            return (uint16_t)ROME2_VFS_L51_WEOF;
        }
    }
    if (out_written_bytes) {
        *out_written_bytes = written;
    }
    return ch;
}

/* `0x116a67fc` */
int32_t rome2_vfs_crt_get_printf_count_output(
    uint32_t encoded_enable_percent_n,
    uint32_t security_cookie) {
    return (encoded_enable_percent_n == (security_cookie | 1u)) ? 1 : 0;
}

/* `0x116a816e` */
void rome2_vfs_crt_sanitize_wctomb_flags(
    uint32_t codepage,
    uint32_t in_flags,
    uint8_t has_default_char,
    uint8_t has_used_default,
    uint32_t *out_flags,
    uint8_t *out_keep_default_char,
    uint8_t *out_keep_used_default) {
    uint8_t is_utf = (codepage == 0xfde8u || codepage == 0xfde9u) ? 1u : 0u;
    uint8_t keep_flags = is_utf;
    if (!keep_flags) {
        if (codepage == 0x2au || codepage == 0xc431u || codepage == 0xc433u || codepage == 0xc435u || codepage == 0xd698u) {
            keep_flags = 1u;
        } else if ((codepage >= 0xc42cu && codepage <= 0xc42eu) || (codepage >= 0xdeaau && codepage <= 0xdeb3u)) {
            keep_flags = 1u;
        }
    }
    if (out_flags) {
        *out_flags = keep_flags ? in_flags : (in_flags & ~0x80u);
    }
    if (out_keep_default_char) {
        *out_keep_default_char = is_utf ? 0u : (has_default_char ? 1u : 0u);
    }
    if (out_keep_used_default) {
        *out_keep_used_default = is_utf ? 0u : (has_used_default ? 1u : 0u);
    }
}

/* `0x116afdf6` */
uint8_t rome2_vfs_crt_tz_cvtdate(
    rome2_vfs_crt_tz_runtime_state *tz,
    int32_t transition_type,
    int32_t datetype,
    int32_t year,
    int32_t month,
    int32_t week,
    int32_t dayofweek,
    int32_t day,
    int32_t hour,
    int32_t min,
    int32_t sec,
    int32_t msec,
    int32_t std_or_dst_bias_sec) {
    static const int32_t k_days[13] = { -1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333, 364 };
    static const int32_t k_lpdays[13] = { -1, 30, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 };
    if (!tz || month < 0 || month > 11) {
        return 0u;
    }
    const int32_t *mdays = r2_is_leap_year_crt(year) ? k_lpdays : k_days;
    int32_t yd;
    if (datetype == 1) {
        int32_t jan1_doy = mdays[month] + 1;
        int32_t jan1_wday = (year * 365 + r2_elapsed_leap_years_since_70(year) + jan1_doy - 25546) % 7;
        if (jan1_wday < 0) {
            jan1_wday += 7;
        }
        yd = jan1_doy + week * 7 - jan1_wday + dayofweek;
        if (jan1_wday <= dayofweek) {
            yd -= 7;
        }
        if (week == 5 && yd > mdays[month + 1]) {
            yd -= 7;
        }
    } else {
        yd = mdays[month] + day;
    }
    int32_t ms = (((hour * 60) + min) * 60 + sec) * 1000 + msec;
    if (transition_type == 0) {
        tz->dststart.yr_00 = year;
        tz->dststart.yd_04 = yd;
        tz->dststart.ms_08 = ms;
    } else {
        ms += std_or_dst_bias_sec * 1000;
        if (ms < 0) {
            ms += 86400000;
            --yd;
        } else if (ms >= 86400000) {
            ms -= 86400000;
            ++yd;
        }
        tz->dstend.yr_00 = year;
        tz->dstend.yd_04 = yd;
        tz->dstend.ms_08 = ms;
    }
    return 1u;
}

/* `0x116aff36` */
void rome2_vfs_crt_tzset_from_env_nolock(
    rome2_vfs_crt_tz_runtime_state *tz,
    const char *tz_env) {
    if (!tz || !tz_env) {
        return;
    }
    if (tz->has_cached_tz && strcmp(tz->cached_tz_env, tz_env) == 0) {
        return;
    }
    snprintf(tz->cached_tz_env, sizeof(tz->cached_tz_env), "%s", tz_env);
    tz->has_cached_tz = 1u;

    const char *p = tz_env;
    size_t k = 0u;
    while (k < 3u && *p != '\0') {
        tz->std_name[k++] = *p++;
    }
    tz->std_name[k] = '\0';

    int32_t neg = (*p == '-') ? 1 : 0;
    if (*p == '-') {
        ++p;
    }
    int32_t offset = (int32_t)strtol(p, NULL, 10) * 3600;
    while (*p == '+' || (*p >= '0' && *p <= '9')) {
        ++p;
    }
    if (*p == ':') {
        ++p;
        offset += (int32_t)strtol(p, NULL, 10) * 60;
        while (*p >= '0' && *p <= '9') {
            ++p;
        }
        if (*p == ':') {
            ++p;
            offset += (int32_t)strtol(p, NULL, 10);
            while (*p >= '0' && *p <= '9') {
                ++p;
            }
        }
    }
    if (neg) {
        offset = -offset;
    }
    tz->timezone_sec = offset;

    if (*p != '\0') {
        k = 0u;
        while (k < 3u && *p != '\0') {
            tz->dst_name[k++] = *p++;
        }
        tz->dst_name[k] = '\0';
        tz->daylight = 1;
    } else {
        tz->dst_name[0] = '\0';
        tz->daylight = 0;
    }
}

static void r2_copy_utf16le_name64(const uint16_t src[32], char dst[64]) {
    size_t i = 0u;
    while (i < 32u && i < 63u && src[i] != 0u) {
        uint16_t c = src[i];
        dst[i] = (c < 0x80u) ? (char)c : '?';
        ++i;
    }
    dst[i] = '\0';
}

/* `0x116b0111` */
void rome2_vfs_crt_tzset_from_system_nolock(
    rome2_vfs_crt_tz_runtime_state *tz,
    uint8_t tz_api_ok,
    const rome2_vfs_crt_time_zone_info172_32 *tzi) {
    if (!tz) {
        return;
    }
    tz->cached_tz_env[0] = '\0';
    tz->has_cached_tz = 0u;
    if (!tz_api_ok || !tzi) {
        return;
    }
    tz->tz_api_used = 1;
    int32_t bias_sec = tzi->bias_00 * 60;
    if (tzi->standard_date_44[1] != 0u) {
        bias_sec += tzi->standard_bias_54 * 60;
    }
    tz->timezone_sec = bias_sec;
    if (tzi->daylight_date_98[1] != 0u && tzi->daylight_bias_a8 != 0) {
        tz->daylight = 1;
        tz->dstbias_sec = (tzi->daylight_bias_a8 - tzi->standard_bias_54) * 60;
    } else {
        tz->daylight = 0;
        tz->dstbias_sec = 0;
    }
    r2_copy_utf16le_name64(tzi->standard_name_04, tz->std_name);
    r2_copy_utf16le_name64(tzi->daylight_name_58, tz->dst_name);
}

/* `0x116b608e` */
uint16_t rome2_vfs_crt_putwch_nolock(
    uint16_t ch,
    uint8_t console_init_ok,
    uint8_t write_ok,
    uint16_t *out_written_ch) {
    if (!console_init_ok || !write_ok) {
        return (uint16_t)ROME2_VFS_L51_WEOF;
    }
    if (out_written_ch) {
        *out_written_ch = ch;
    }
    return ch;
}

/* `0x116b67f4` */
uint32_t rome2_vfs_crt_free_crt_array(
    void **slots,
    uint32_t count) {
    if (!slots || count == 0u || count > 0x3fffffffu) {
        return 0u;
    }
    uintptr_t base = (uintptr_t)slots;
    uintptr_t end = base + (uintptr_t)count * sizeof(void *);
    if (end < base) {
        return 0u;
    }
    uint32_t freed = 0u;
    for (uint32_t i = 0u; i < count; ++i) {
        free(slots[i]);
        slots[i] = NULL;
        ++freed;
    }
    return freed;
}

/* `0x116bc582` */
int32_t rome2_vfs_crt_validdrive(
    uint32_t drive,
    uint32_t win32_drive_type,
    uint16_t out_root_path[4],
    int32_t *out_errno,
    int32_t *out_doserrno) {
    if (drive > 26u) {
        if (out_doserrno) {
            *out_doserrno = ROME2_VFS_L51_ERR_INV_DRIVE;
        }
        if (out_errno) {
            *out_errno = ROME2_VFS_L51_EACCES;
        }
        return 0;
    }
    if (drive == 0u) {
        return 1;
    }
    if (out_root_path) {
        out_root_path[0] = (uint16_t)(0x40u + drive);
        out_root_path[1] = (uint16_t)':';
        out_root_path[2] = (uint16_t)'\\';
        out_root_path[3] = 0u;
    }
    return (win32_drive_type == 0u || win32_drive_type == 1u) ? 0 : 1;
}

/* `0x116bd871` */
int32_t rome2_vfs_crt_lcmap_wchar_len(
    const uint16_t *src,
    int32_t cch_src) {
    if (cch_src <= 0) {
        return cch_src;
    }
    size_t len = rome2_vfs_crt_wcsnlen(src, (size_t)cch_src);
    return (len < (size_t)cch_src) ? (int32_t)(len + 1u) : (int32_t)len;
}

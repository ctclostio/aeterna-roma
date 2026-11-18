#include "vfs_fs_engine_crt_utf8_ops.h"

#include <stdio.h>
#include <string.h>

enum {
    ROME2_VFS_L52_EOF = -1,
    ROME2_VFS_L52_EBADF = 9,
    ROME2_VFS_L52_ENOMEM = 12,
    ROME2_VFS_L52_EINVAL = 22,
    ROME2_VFS_L52_ERANGE = 34,
    ROME2_VFS_L52_EILSEQ = 42,
    ROME2_VFS_L52_STRUNCATE = 80
};

static const uint32_t ROME2_VFS_L52_ERR_INVALID_HANDLE = 6u;
static const uint32_t ROME2_VFS_L52_CONSOLE_UNINIT = 0xfffffffeu;
static const uint32_t ROME2_VFS_L52_INVALID_HANDLE = 0xffffffffu;

/* `0x116889a9` */
uint32_t rome2_vfs_crt_fmt_buf_count_wide(
    const rome2_vfs_crt_formatting_buffer1032_32 *fb) {
    if (!fb || fb->heap_ptr_404 == 0u) {
        return 0x100u;
    }
    return fb->allocated_bytes_400 >> 2;
}

/* `0x11689010` */
uint32_t rome2_vfs_crt_unique_heap_ptr_assign(
    rome2_vfs_crt_unique_heap_ptr4_32 *self,
    rome2_vfs_crt_unique_heap_ptr4_32 *rhs,
    uint32_t *out_old_freed_ptr) {
    if (out_old_freed_ptr) {
        *out_old_freed_ptr = 0u;
    }
    if (!self || !rhs) {
        return 0u;
    }
    if (out_old_freed_ptr) {
        *out_old_freed_ptr = self->ptr_00;
    }
    self->ptr_00 = rhs->ptr_00;
    rhs->ptr_00 = 0u;
    return self->ptr_00;
}

/* `0x1168d395` */
uint8_t rome2_vfs_crt_is_overflow_condition_u32(
    uint32_t flags,
    uint32_t value) {
    if ((flags & 4u) != 0u) {
        return 1u;
    }
    if ((flags & 1u) != 0u) {
        if ((flags & 2u) != 0u) {
            return (value > 0x80000000u) ? 1u : 0u;
        }
        return (value > 0x7fffffffu) ? 1u : 0u;
    }
    return 0u;
}

/* `0x1168e5d4` */
uint8_t rome2_vfs_crt_wstr_source_unget(
    const uint16_t *src,
    size_t *inout_pos,
    uint16_t expected_ch,
    int32_t *out_errno) {
    if (!src || !inout_pos || *inout_pos == 0u) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L52_EINVAL;
        }
        return 0u;
    }
    --(*inout_pos);
    if (expected_ch != 0u && src[*inout_pos] != expected_ch) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L52_EINVAL;
        }
        return 0u;
    }
    return 1u;
}

/* `0x1168e679` */
int32_t rome2_vfs_crt_atol(const char *src, size_t max_len) {
    if (!src || max_len == 0u) {
        return 0;
    }
    size_t i = 0u;
    while (i < max_len && (src[i] == ' ' || (src[i] >= '\t' && src[i] <= '\r'))) {
        ++i;
    }
    uint8_t neg = 0u;
    if (i < max_len && (src[i] == '-' || src[i] == '+')) {
        neg = (src[i] == '-') ? 1u : 0u;
        ++i;
    }
    uint64_t acc = 0u;
    uint64_t limit = neg ? 0x80000000ULL : 0x7fffffffULL;
    while (i < max_len && src[i] >= '0' && src[i] <= '9') {
        uint64_t d = (uint64_t)(src[i] - '0');
        if (acc > (limit - d) / 10ULL) {
            acc = limit;
            break;
        }
        acc = acc * 10ULL + d;
        ++i;
    }
    if (neg) {
        return (acc >= 0x80000000ULL) ? INT32_MIN : -(int32_t)acc;
    }
    return (int32_t)acc;
}

/* `0x1169d38d` */
size_t rome2_vfs_crt_utf8_lookahead_probe(const uint8_t *s, size_t max_len) {
    if (!s || max_len == 0u || s[0] == 0u) {
        return 1u;
    }
    if (max_len == 1u || s[1] == 0u) {
        return 2u;
    }
    if (max_len == 2u || s[2] == 0u) {
        return 3u;
    }
    return 4u;
}

/* `0x116b15ac` */
size_t rome2_vfs_crt_mbrtoc32_utf8(
    uint32_t *pc32,
    const uint8_t *s,
    size_t n,
    rome2_vfs_crt_mbstate8_32 *ps,
    int32_t *out_errno) {
    static const uint32_t k_min_cp[5] = { 0u, 0u, 0x80u, 0x800u, 0x10000u };
    if (!ps) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L52_EINVAL;
        }
        return (size_t)-1;
    }
    if (!s) {
        static const uint8_t k_empty[1] = { 0u };
        s = k_empty;
        n = 1u;
        pc32 = NULL;
    }
    if (n == 0u) {
        return (size_t)-2;
    }

    size_t idx = 0u;
    uint32_t cp = 0u;
    uint16_t total_len = 0u;
    uint16_t rem_len = 0u;

    if (ps->state_06 == 0u) {
        uint8_t lead = s[idx++];
        if ((lead & 0x80u) == 0u) {
            if (pc32) {
                *pc32 = (uint32_t)lead;
            }
            return (lead == 0u) ? 0u : 1u;
        }
        if ((lead & 0xe0u) == 0xc0u) {
            total_len = 2u;
            cp = (uint32_t)(lead & 0x1fu);
        } else if ((lead & 0xf0u) == 0xe0u) {
            total_len = 3u;
            cp = (uint32_t)(lead & 0x0fu);
        } else if ((lead & 0xf8u) == 0xf0u) {
            total_len = 4u;
            cp = (uint32_t)(lead & 0x07u);
        } else {
            memset(ps, 0, sizeof(*ps));
            if (out_errno) {
                *out_errno = ROME2_VFS_L52_EILSEQ;
            }
            return (size_t)-1;
        }
        rem_len = (uint16_t)(total_len - 1u);
    } else {
        total_len = ps->byte_04;
        rem_len = ps->state_06;
        cp = ps->wchar_00;
        if (total_len < 2u || total_len > 4u || rem_len == 0u || rem_len >= total_len) {
            memset(ps, 0, sizeof(*ps));
            if (out_errno) {
                *out_errno = ROME2_VFS_L52_EILSEQ;
            }
            return (size_t)-1;
        }
    }

    while (rem_len > 0u && idx < n) {
        uint8_t b = s[idx++];
        if ((b & 0xc0u) != 0x80u) {
            memset(ps, 0, sizeof(*ps));
            if (out_errno) {
                *out_errno = ROME2_VFS_L52_EILSEQ;
            }
            return (size_t)-1;
        }
        cp = (cp << 6) | (uint32_t)(b & 0x3fu);
        --rem_len;
    }

    if (rem_len > 0u) {
        ps->wchar_00 = cp;
        ps->byte_04 = total_len;
        ps->state_06 = rem_len;
        return (size_t)-2;
    }

    if ((cp >= 0xd800u && cp <= 0xdfffu) || cp > 0x10ffffu || cp < k_min_cp[total_len]) {
        memset(ps, 0, sizeof(*ps));
        if (out_errno) {
            *out_errno = ROME2_VFS_L52_EILSEQ;
        }
        return (size_t)-1;
    }

    memset(ps, 0, sizeof(*ps));
    if (pc32) {
        *pc32 = cp;
    }
    return (cp == 0u) ? 0u : idx;
}

/* `0x1169d3b9` */
size_t rome2_vfs_crt_mbrtowc_utf8(
    uint16_t *pwc,
    const uint8_t *s,
    size_t n,
    rome2_vfs_crt_mbstate8_32 *ps,
    int32_t *out_errno) {
    uint32_t c32 = 0u;
    size_t ret = rome2_vfs_crt_mbrtoc32_utf8(&c32, s, n, ps, out_errno);
    if (ret <= 4u && pwc) {
        *pwc = (c32 > 0xffffu) ? (uint16_t)0xfffdu : (uint16_t)c32;
    }
    return ret;
}

/* `0x1169e514` */
int32_t rome2_vfs_crt_fputc_nolock(
    int32_t ch,
    uint8_t *buf,
    size_t buf_cap,
    size_t *inout_pos,
    int32_t *inout_cnt,
    uint8_t flush_ok) {
    if (!buf || !inout_pos || !inout_cnt) {
        return ROME2_VFS_L52_EOF;
    }
    --(*inout_cnt);
    if (*inout_cnt < 0 || *inout_pos >= buf_cap) {
        return flush_ok ? (int32_t)(uint8_t)ch : ROME2_VFS_L52_EOF;
    }
    buf[(*inout_pos)++] = (uint8_t)ch;
    return (int32_t)(uint8_t)ch;
}

/* `0x116a66a3` */
uint16_t rome2_vfs_crt_fputwc_binary_nolock(
    uint16_t ch,
    uint8_t *buf,
    size_t buf_cap,
    size_t *inout_pos,
    int32_t *inout_cnt,
    uint8_t flush_ok) {
    if (!buf || !inout_pos || !inout_cnt) {
        return 0xffffu;
    }
    *inout_cnt -= 2;
    if (*inout_cnt < 0 || *inout_pos + 1u >= buf_cap) {
        return flush_ok ? ch : 0xffffu;
    }
    buf[(*inout_pos)++] = (uint8_t)(ch & 0xffu);
    buf[(*inout_pos)++] = (uint8_t)((ch >> 8) & 0xffu);
    return ch;
}

/* `0x116a25d6` */
uint32_t rome2_vfs_crt_lc_codepage_func(
    const rome2_vfs_crt_threadlocinfo184_32 *thread_loc,
    const rome2_vfs_crt_threadlocinfo184_32 *global_loc,
    uint8_t own_locale_enabled) {
    const rome2_vfs_crt_threadlocinfo184_32 *active = own_locale_enabled ? thread_loc : global_loc;
    return active ? active->lc_codepage_08 : 0u;
}

/* `0x116a5ca6` */
int32_t rome2_vfs_crt_wctomb_s(
    int32_t *out_converted,
    uint8_t *dst,
    size_t dst_cap,
    uint16_t wchar,
    uint32_t codepage) {
    if (!dst && dst_cap > 0u) {
        if (out_converted) {
            *out_converted = 0;
        }
        return ROME2_VFS_L52_EINVAL;
    }
    if (out_converted) {
        *out_converted = -1;
    }
    if (!dst) {
        if (out_converted) {
            *out_converted = 0;
        }
        return 0;
    }
    if (codepage == 0xfde9u) {
        if (wchar <= 0x7fu) {
            if (dst_cap < 1u) {
                return ROME2_VFS_L52_ERANGE;
            }
            dst[0] = (uint8_t)wchar;
            if (out_converted) {
                *out_converted = 1;
            }
            return 0;
        }
        if (wchar <= 0x7ffu) {
            if (dst_cap < 2u) {
                return ROME2_VFS_L52_ERANGE;
            }
            dst[0] = (uint8_t)(0xc0u | (wchar >> 6));
            dst[1] = (uint8_t)(0x80u | (wchar & 0x3fu));
            if (out_converted) {
                *out_converted = 2;
            }
            return 0;
        }
        if (dst_cap < 3u) {
            return ROME2_VFS_L52_ERANGE;
        }
        dst[0] = (uint8_t)(0xe0u | (wchar >> 12));
        dst[1] = (uint8_t)(0x80u | ((wchar >> 6) & 0x3fu));
        dst[2] = (uint8_t)(0x80u | (wchar & 0x3fu));
        if (out_converted) {
            *out_converted = 3;
        }
        return 0;
    }
    if (wchar > 0xffu) {
        return ROME2_VFS_L52_EILSEQ;
    }
    if (dst_cap < 1u) {
        return ROME2_VFS_L52_ERANGE;
    }
    dst[0] = (uint8_t)wchar;
    if (out_converted) {
        *out_converted = 1;
    }
    return 0;
}

static int32_t r2_fp_snprintf(
    char *buf,
    size_t buf_cap,
    const char *fmt,
    int32_t precision,
    double val,
    int32_t *out_errno) {
    if (!buf || buf_cap == 0u) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L52_EINVAL;
        }
        return ROME2_VFS_L52_EINVAL;
    }
    int n = snprintf(buf, buf_cap, fmt, precision, val);
    if (n < 0 || (size_t)n >= buf_cap) {
        buf[0] = '\0';
        if (out_errno) {
            *out_errno = ROME2_VFS_L52_ERANGE;
        }
        return ROME2_VFS_L52_ERANGE;
    }
    return 0;
}

/* `0x116a5d7f` */
int32_t rome2_vfs_crt_fp_format_a(
    double val,
    char *buf,
    size_t buf_cap,
    int32_t precision,
    uint8_t caps,
    uint32_t min_exp_digits,
    int32_t *out_errno) {
    (void)min_exp_digits;
    int32_t p = precision < 0 ? 0 : precision;
    if (!buf || buf_cap <= (size_t)p + 11u) {
        if (buf && buf_cap > 0u) {
            buf[0] = '\0';
        }
        if (out_errno) {
            *out_errno = ROME2_VFS_L52_ERANGE;
        }
        return ROME2_VFS_L52_ERANGE;
    }
    return r2_fp_snprintf(buf, buf_cap, caps ? "%.*A" : "%.*a", p, val, out_errno);
}

/* `0x116a6098` */
int32_t rome2_vfs_crt_fp_format_e(
    double val,
    char *buf,
    size_t buf_cap,
    int32_t precision,
    uint8_t caps,
    uint32_t min_exp_digits,
    int32_t *out_errno) {
    (void)min_exp_digits;
    int32_t p = precision < 0 ? 0 : precision;
    return r2_fp_snprintf(buf, buf_cap, caps ? "%.*E" : "%.*e", p, val, out_errno);
}

/* `0x116a6282` */
int32_t rome2_vfs_crt_fp_format_f(
    double val,
    char *buf,
    size_t buf_cap,
    int32_t precision,
    int32_t *out_errno) {
    int32_t p = precision < 0 ? 0 : precision;
    return r2_fp_snprintf(buf, buf_cap, "%.*f", p, val, out_errno);
}

/* `0x116a63de` */
int32_t rome2_vfs_crt_fp_format_g(
    double val,
    char *buf,
    size_t buf_cap,
    int32_t precision,
    uint8_t caps,
    uint32_t min_exp_digits,
    int32_t *out_errno) {
    (void)min_exp_digits;
    int32_t p = precision < 0 ? 1 : precision;
    return r2_fp_snprintf(buf, buf_cap, caps ? "%.*G" : "%.*g", p, val, out_errno);
}

/* `0x116a649f` */
int32_t rome2_vfs_crt_fp_format_nan_or_infinity(
    uint32_t fp_class,
    uint8_t is_negative,
    char *buf,
    size_t buf_cap,
    uint8_t caps,
    const rome2_vfs_crt_fp_nan_inf_table64_32 *guest_lut_addrs) {
    static const char *const k_lut[16] = {
        "INF", "INF", "inf", "inf",
        "NAN", "NAN", "nan", "nan",
        "NAN(SNAN)", "NAN", "nan(snan)", "nan",
        "NAN(IND)", "NAN", "nan(ind)", "nan"
    };
    (void)guest_lut_addrs;
    if (!buf || buf_cap < (size_t)(4u + (is_negative ? 1u : 0u))) {
        if (buf && buf_cap > 0u) {
            buf[0] = '\0';
        }
        return ROME2_VFS_L52_ENOMEM;
    }
    if (fp_class < 1u || fp_class > 4u) {
        buf[0] = '\0';
        return ROME2_VFS_L52_EINVAL;
    }
    size_t pos = 0u;
    size_t rem = buf_cap;
    if (is_negative) {
        buf[pos++] = '-';
        buf[pos] = '\0';
        --rem;
    }
    uint32_t idx = (fp_class - 1u) * 4u + ((caps ? 0u : 1u) * 2u);
    const char *label = k_lut[idx];
    size_t len = strlen(label);
    if (len + 1u > rem) {
        label = k_lut[idx + 1u];
        len = strlen(label);
    }
    if (len + 1u > rem) {
        return ROME2_VFS_L52_ENOMEM;
    }
    memcpy(buf + pos, label, len + 1u);
    return 0;
}

/* `0x116a8a30` */
uint8_t rome2_vfs_crt_lcmap_string_ex_uses_modern(uint8_t has_lcmap_ex_api) {
    return has_lcmap_ex_api ? 1u : 0u;
}

/* `0x116a8c79` */
int32_t rome2_vfs_crt_iswctype(
    uint16_t ch,
    uint16_t mask,
    const uint16_t pwctype_256[256],
    uint16_t fallback_type_bits) {
    if (ch == 0xffffu) {
        return 0;
    }
    if (ch < 0x100u && pwctype_256) {
        return (int32_t)(pwctype_256[ch] & mask);
    }
    return (int32_t)(fallback_type_bits & mask);
}

/* `0x116aea59` */
uint32_t rome2_vfs_crt_get_osfhandle(
    int32_t fh,
    int32_t nhandle,
    const rome2_vfs_crt_ioinfo56_32 *io_slots,
    int32_t *out_errno,
    int32_t *out_doserrno) {
    if (fh == -2) {
        if (out_doserrno) {
            *out_doserrno = 0;
        }
        if (out_errno) {
            *out_errno = ROME2_VFS_L52_EBADF;
        }
        return ROME2_VFS_L52_INVALID_HANDLE;
    }
    if (fh >= 0 && fh < nhandle && io_slots && (io_slots[fh].osfile_28 & 1u) != 0u) {
        return io_slots[fh].osfhnd_00;
    }
    if (out_doserrno) {
        *out_doserrno = 0;
    }
    if (out_errno) {
        *out_errno = ROME2_VFS_L52_EBADF;
    }
    return ROME2_VFS_L52_INVALID_HANDLE;
}

/* `0x116afb0a` */
int32_t rome2_vfs_crt_strncpy_s(
    char *dst,
    size_t dst_cap,
    const char *src,
    size_t max_count,
    int32_t *out_errno) {
    if (max_count == 0u && !dst && dst_cap == 0u) {
        return 0;
    }
    if (!dst || dst_cap == 0u || !src) {
        if (dst && dst_cap > 0u) {
            dst[0] = '\0';
        }
        if (out_errno) {
            *out_errno = ROME2_VFS_L52_EINVAL;
        }
        return ROME2_VFS_L52_EINVAL;
    }
    if (max_count == 0u) {
        dst[0] = '\0';
        return 0;
    }

    size_t avail = dst_cap;
    size_t i = 0u;
    if (max_count == (size_t)-1) {
        while (avail > 0u && src[i] != '\0') {
            dst[i] = src[i];
            ++i;
            --avail;
        }
        if (avail == 0u) {
            dst[dst_cap - 1u] = '\0';
            return ROME2_VFS_L52_STRUNCATE;
        }
        dst[i] = '\0';
        return 0;
    }

    size_t rem_count = max_count;
    while (avail > 0u && rem_count > 0u && src[i] != '\0') {
        dst[i] = src[i];
        ++i;
        --avail;
        --rem_count;
    }
    if (avail == 0u) {
        dst[0] = '\0';
        if (out_errno) {
            *out_errno = ROME2_VFS_L52_ERANGE;
        }
        return ROME2_VFS_L52_ERANGE;
    }
    dst[i] = '\0';
    return 0;
}

/* `0x116afb40..0x116afb52` */
int32_t *rome2_vfs_crt_tz_timezone_ptr(int32_t *tz_sec_slot) {
    return tz_sec_slot;
}

int32_t *rome2_vfs_crt_tz_dstbias_ptr(int32_t *dstbias_slot) {
    return dstbias_slot;
}

int32_t *rome2_vfs_crt_tz_daylight_ptr(int32_t *daylight_slot) {
    return daylight_slot;
}

const rome2_vfs_crt_tzname_pair8_32 *rome2_vfs_crt_tzname_base(
    const rome2_vfs_crt_tzname_pair8_32 *pair) {
    return pair;
}

/* `0x116b1572` */
int32_t rome2_vfs_crt_isleadbyte_l(
    int32_t ch,
    const uint16_t ctype_table_256[256]) {
    if (!ctype_table_256) {
        return 0;
    }
    return ((ctype_table_256[(uint8_t)ch] & 0x8000u) != 0u) ? 1 : 0;
}

/* `0x116bd4f2` */
uint8_t rome2_vfs_crt_dcrt_console_output_ready(
    uint32_t *inout_console_handle,
    uint32_t lazy_init_handle) {
    if (!inout_console_handle) {
        return 0u;
    }
    if (*inout_console_handle == ROME2_VFS_L52_CONSOLE_UNINIT) {
        *inout_console_handle = lazy_init_handle;
    }
    return (*inout_console_handle != ROME2_VFS_L52_INVALID_HANDLE) ? 1u : 0u;
}

/* `0x116bd528` */
uint8_t rome2_vfs_crt_dcrt_write_console(
    uint32_t *inout_console_handle,
    uint8_t first_write_ok,
    uint32_t first_last_error,
    uint32_t reopened_handle,
    uint8_t retry_write_ok,
    uint32_t *out_attempts) {
    uint32_t attempts = 1u;
    uint8_t ok = first_write_ok ? 1u : 0u;
    if (!ok && first_last_error == ROME2_VFS_L52_ERR_INVALID_HANDLE && inout_console_handle) {
        *inout_console_handle = reopened_handle;
        ok = retry_write_ok ? 1u : 0u;
        ++attempts;
    }
    if (out_attempts) {
        *out_attempts = attempts;
    }
    return ok;
}

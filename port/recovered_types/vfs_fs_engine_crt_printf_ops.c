#include "vfs_fs_engine_crt_printf_ops.h"

/* Exact 91-byte packed printf state table (`0x1190ec70..0x1190ecca` in empire.retail.dll). */
static const uint8_t k_wprintf_state_tbl[ROME2_VFS_L48_PRINTF_TBL_LEN] = {
    0x06u, 0x00u, 0x00u, 0x06u, 0x00u, 0x01u, 0x00u, 0x00u,
    0x10u, 0x00u, 0x03u, 0x06u, 0x00u, 0x06u, 0x02u, 0x10u,
    0x04u, 0x45u, 0x45u, 0x45u, 0x05u, 0x05u, 0x05u, 0x05u,
    0x05u, 0x35u, 0x30u, 0x00u, 0x50u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x28u, 0x20u, 0x38u, 0x50u, 0x58u, 0x07u, 0x08u,
    0x00u, 0x37u, 0x30u, 0x30u, 0x57u, 0x50u, 0x07u, 0x00u,
    0x00u, 0x20u, 0x20u, 0x08u, 0x07u, 0x00u, 0x00u, 0x00u,
    0x08u, 0x60u, 0x68u, 0x60u, 0x60u, 0x60u, 0x60u, 0x00u,
    0x00u, 0x78u, 0x70u, 0x78u, 0x78u, 0x78u, 0x78u, 0x08u,
    0x07u, 0x08u, 0x07u, 0x00u, 0x07u, 0x00u, 0x08u, 0x08u,
    0x08u, 0x00u, 0x00u, 0x08u, 0x07u, 0x08u, 0x00u, 0x07u,
    0x08u, 0x00u, 0x07u
};

static uint16_t l48_ascii_tolower_w(uint16_t ch)
{
    if (ch >= (uint16_t)'A' && ch <= (uint16_t)'Z') {
        return (uint16_t)(ch + 0x20u);
    }
    return ch;
}

uint64_t rome2_vfs_crt_aulldvrm(uint64_t dividend, uint64_t divisor, uint64_t *out_rem)
{
    if (divisor == 0u) {
        if (out_rem) {
            *out_rem = 0u;
        }
        return 0u;
    }
    if (out_rem) {
        *out_rem = dividend % divisor;
    }
    return dividend / divisor;
}

uint32_t rome2_vfs_crt_wprintf_find_next_state(uint16_t ch, uint32_t prev_state)
{
    uint32_t row = 0u;
    uint32_t idx;
    if (ch >= 0x20u && ch <= 0x7au) {
        row = (uint32_t)(k_wprintf_state_tbl[ch - 0x20u] & 0x0fu);
    }
    idx = (prev_state & 0x07u) + (row * 8u);
    if (idx >= ROME2_VFS_L48_PRINTF_TBL_LEN) {
        return 0u;
    }
    return (uint32_t)(k_wprintf_state_tbl[idx] >> 4);
}

uint8_t rome2_vfs_crt_wprintf_state_case_flag(rome2_vfs_crt_wprintf_state64_32 *st)
{
    if (!st) {
        return 0u;
    }
    switch (st->cur_ch_32) {
    case (uint16_t)' ':
        st->fmt_flags_20 |= ROME2_VFS_L48_PRINTF_FLAG_SPACE;
        break;
    case (uint16_t)'#':
        st->fmt_flags_20 |= ROME2_VFS_L48_PRINTF_FLAG_HASH;
        break;
    case (uint16_t)'+':
        st->fmt_flags_20 |= ROME2_VFS_L48_PRINTF_FLAG_PLUS;
        break;
    case (uint16_t)'-':
        st->fmt_flags_20 |= ROME2_VFS_L48_PRINTF_FLAG_MINUS;
        break;
    case (uint16_t)'0':
        st->fmt_flags_20 |= ROME2_VFS_L48_PRINTF_FLAG_ZERO;
        break;
    default:
        break;
    }
    return 1u;
}

uint8_t rome2_vfs_crt_wprintf_state_case_normal(uint8_t emitter_ok, int32_t *out_errno)
{
    if (out_errno) {
        *out_errno = emitter_ok ? 0 : ROME2_VFS_L44_EINVAL_MSVC;
    }
    return emitter_ok ? 1u : 0u;
}

uint8_t rome2_vfs_crt_wprintf_state_case_precision(
    rome2_vfs_crt_wprintf_state64_32 *st,
    int32_t va_prec,
    int32_t literal_prec,
    uint8_t literal_ok)
{
    if (!st) {
        return 0u;
    }
    if (st->cur_ch_32 == (uint16_t)'*') {
        st->valist_14 += 4u;
        st->precision_28 = (va_prec < 0) ? -1 : va_prec;
        return 1u;
    }
    if (!literal_ok) {
        return 0u;
    }
    st->precision_28 = literal_prec;
    return 1u;
}

uint8_t rome2_vfs_crt_wprintf_state_case_width(
    rome2_vfs_crt_wprintf_state64_32 *st,
    int32_t va_width,
    int32_t literal_width,
    uint8_t literal_ok)
{
    if (!st) {
        return 0u;
    }
    if (st->cur_ch_32 == (uint16_t)'*') {
        st->valist_14 += 4u;
        if (va_width < 0) {
            st->fmt_flags_20 |= ROME2_VFS_L48_PRINTF_FLAG_MINUS;
            st->width_24 = -va_width;
        } else {
            st->width_24 = va_width;
        }
        return 1u;
    }
    if (!literal_ok) {
        return 0u;
    }
    st->width_24 = literal_width;
    return 1u;
}

uint8_t rome2_vfs_crt_validate_nonnull_slot(const uint32_t *slot, int32_t *out_errno)
{
    if (!slot || *slot == 0u) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return 0u;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    return 1u;
}

int32_t rome2_vfs_crt_elapsed_leap_years(int32_t tm_year)
{
    /* Exact formula at `0x1168c168`: (y+299)/400 - (y-1)/100 + (y-1)/4 - 17. */
    return ((tm_year + 299) / 400) - ((tm_year - 1) / 100) + ((tm_year - 1) / 4) - 17;
}

uint8_t rome2_vfs_crt_is_leap_year(int32_t tm_year)
{
    if ((tm_year % 4 == 0 && tm_year % 100 != 0) || ((tm_year + 1900) % 400 == 0)) {
        return 1u;
    }
    return 0u;
}

uint8_t rome2_vfs_crt_is_valid_month_day(int32_t tm_year, int32_t tm_mon, int32_t tm_mday)
{
    static const int32_t k_cum_days[13] = {
        0, -1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333
    };
    int32_t month_len;
    if (tm_mday <= 0 || tm_mon < 0 || tm_mon > 11) {
        return 0u;
    }
    month_len = k_cum_days[tm_mon + 2] - k_cum_days[tm_mon + 1];
    if (tm_mday <= month_len) {
        return 1u;
    }
    if (rome2_vfs_crt_is_leap_year(tm_year) != 0u && tm_mon == 1 && tm_mday <= 29) {
        return 1u;
    }
    return 0u;
}

uint8_t rome2_vfs_crt_strtox_is_overflow_u64(uint8_t flags, uint64_t val)
{
    if ((flags & 4u) != 0u) {
        return 1u;
    }
    if ((flags & 1u) != 0u) {
        if ((flags & 2u) != 0u) {
            return (val > 0x8000000000000000ULL) ? 1u : 0u;
        }
        return (val > 0x7fffffffffffffffULL) ? 1u : 0u;
    }
    return 0u;
}

uint8_t rome2_vfs_crt_cstr_source_unget(
    const char **inout_cur,
    uint8_t expected_ch,
    int32_t *out_errno)
{
    const char *prev;
    if (!inout_cur || !*inout_cur) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return 0u;
    }
    prev = *inout_cur - 1;
    *inout_cur = prev;
    if (expected_ch != 0u && (uint8_t)*prev != expected_ch) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return 0u;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    return 1u;
}

int32_t rome2_vfs_crt_skip_whitespace_str(const char *s, size_t *inout_pos, const uint16_t *ctype_257)
{
    size_t pos;
    if (!s || !inout_pos || !ctype_257) {
        return -1;
    }
    pos = *inout_pos;
    for (;;) {
        uint8_t ch = (uint8_t)s[pos];
        if (ch == 0u) {
            *inout_pos = pos;
            return -1;
        }
        ++pos;
        if (rome2_vfs_crt_ischartype_l(ctype_257, 1, (int32_t)ch, 8u, 1u) == 0u) {
            *inout_pos = pos;
            return (int32_t)ch;
        }
    }
}

void rome2_vfs_crt_invert_scanset_bitmap(uint8_t bitmap_32[32])
{
    size_t i;
    if (!bitmap_32) {
        return;
    }
    for (i = 0u; i < 32u; ++i) {
        bitmap_32[i] = (uint8_t)(~bitmap_32[i]);
    }
}

uint8_t rome2_vfs_crt_process_literal_char_mb(
    const uint16_t *ctype_257,
    uint8_t ch0,
    uint8_t trail_ch,
    const char *stream_next,
    uint8_t *out_consumed)
{
    uint16_t cflag;
    if (out_consumed) {
        *out_consumed = 0u;
    }
    if (!ctype_257) {
        return 0u;
    }
    cflag = ctype_257[(size_t)ch0 + 1u];
    if ((cflag & 0x8000u) == 0u) {
        return 1u;
    }
    if (!stream_next || (uint8_t)*stream_next != trail_ch) {
        return 0u;
    }
    if (out_consumed) {
        *out_consumed = 1u;
    }
    return 1u;
}

void rome2_vfs_crt_fmt_parser_update_is_wide(rome2_vfs_crt_fmt_parser76_32 *fp)
{
    if (!fp) {
        return;
    }
    if (fp->length_idx_20 == 2u) {
        fp->is_wide_24 = 0u;
    }
    if (fp->length_idx_20 == 3u || fp->length_idx_20 == 4u || fp->length_idx_20 == 8u) {
        fp->is_wide_24 = 1u;
    }
}

uint32_t rome2_vfs_crt_lowio_fh_slot_offset(int32_t fh)
{
    return (uint32_t)((uint32_t)fh & 0x3fu) * (uint32_t)sizeof(rome2_vfs_crt_ioinfo56_32);
}

uint32_t rome2_vfs_crt_ischartype_mb_l(
    const uint16_t *ctype_257,
    int32_t ch,
    uint32_t mask,
    uint16_t mb_ctype_result,
    uint8_t get_string_type_ok,
    uint8_t *out_used_mb_api)
{
    if (out_used_mb_api) {
        *out_used_mb_api = 0u;
    }
    if (!ctype_257) {
        return 0u;
    }
    if (ch >= -1 && ch <= 0xff) {
        return (uint32_t)ctype_257[(size_t)(ch + 1)] & mask;
    }
    if (out_used_mb_api) {
        *out_used_mb_api = 1u;
    }
    if (!get_string_type_ok) {
        return 0u;
    }
    return (uint32_t)mb_ctype_result & mask;
}

int32_t rome2_vfs_crt_common_fullpath_plan(
    uint32_t gfpn_ret,
    uint32_t cap_words,
    uint32_t win32_err,
    int32_t mapped_errno,
    uint8_t is_dyn_buf,
    uint8_t resize_ok,
    uint8_t *out_retry_needed,
    uint32_t *out_new_cap,
    uint32_t *out_written_len)
{
    if (out_retry_needed) {
        *out_retry_needed = 0u;
    }
    if (out_new_cap) {
        *out_new_cap = cap_words;
    }
    if (out_written_len) {
        *out_written_len = 0u;
    }
    if (gfpn_ret == 0u) {
        (void)win32_err;
        return mapped_errno;
    }
    if (gfpn_ret <= cap_words) {
        if (out_written_len) {
            *out_written_len = gfpn_ret;
        }
        return 0;
    }
    if (!resize_ok) {
        return is_dyn_buf ? ROME2_VFS_L44_ENOMEM_MSVC : ROME2_VFS_L44_ERANGE_MSVC;
    }
    if (out_retry_needed) {
        *out_retry_needed = 1u;
    }
    if (out_new_cap) {
        *out_new_cap = gfpn_ret + 1u;
    }
    return 0;
}

uint8_t rome2_vfs_crt_win32_buffer_detach_plan(
    const rome2_vfs_crt_win32_buffer24_32 *buf,
    uint8_t *out_needs_heap_dup,
    uint32_t *out_dup_bytes)
{
    if (out_needs_heap_dup) {
        *out_needs_heap_dup = 0u;
    }
    if (out_dup_bytes) {
        *out_dup_bytes = 0u;
    }
    if (!buf || buf->data_08 == 0u || buf->size_words_10 == 0u) {
        return 0u;
    }
    if (buf->allocated_14 == 0u) {
        if (out_needs_heap_dup) {
            *out_needs_heap_dup = 1u;
        }
        if (out_dup_bytes) {
            *out_dup_bytes = buf->size_words_10 * 2u;
        }
    }
    return 1u;
}

int32_t rome2_vfs_crt_wcsicmp_l(
    const uint16_t *lhs,
    const uint16_t *rhs,
    uint8_t has_ctype_locale,
    int32_t *out_errno)
{
    if (!has_ctype_locale) {
        return rome2_vfs_crt_wcsicmp_ascii(lhs, rhs, out_errno);
    }
    if (!lhs || !rhs) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return 0x7fffffff;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    for (;;) {
        uint16_t a = l48_ascii_tolower_w(*lhs++);
        uint16_t b = l48_ascii_tolower_w(*rhs++);
        if (a != b || a == 0u) {
            return (int32_t)(uint32_t)a - (int32_t)(uint32_t)b;
        }
    }
}

static int32_t l48_read_tz_dword(int32_t val, int32_t *out_val, int32_t *out_errno)
{
    if (!out_val) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return ROME2_VFS_L44_EINVAL_MSVC;
    }
    *out_val = val;
    if (out_errno) {
        *out_errno = 0;
    }
    return 0;
}

int32_t rome2_vfs_crt_get_timezone(int32_t global_tz, int32_t *out_seconds, int32_t *out_errno)
{
    return l48_read_tz_dword(global_tz, out_seconds, out_errno);
}

int32_t rome2_vfs_crt_get_dstbias(int32_t global_dstbias, int32_t *out_seconds, int32_t *out_errno)
{
    return l48_read_tz_dword(global_dstbias, out_seconds, out_errno);
}

int32_t rome2_vfs_crt_get_daylight(int32_t global_daylight, int32_t *out_flag, int32_t *out_errno)
{
    return l48_read_tz_dword(global_daylight, out_flag, out_errno);
}

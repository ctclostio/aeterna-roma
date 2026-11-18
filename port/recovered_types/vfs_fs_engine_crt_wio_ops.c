#include "vfs_fs_engine_crt_wio_ops.h"

#include <limits.h>
#include <string.h>

uint8_t rome2_vfs_crt_freea_needs_heap_free(uint8_t has_non_null_ptr, uint32_t marker_word) {
    return (has_non_null_ptr != 0u && marker_word == 0xddddu) ? 1u : 0u;
}

uint8_t rome2_vfs_crt_stream_write_char(
    uint32_t file_flags,
    uint32_t file_ptr_or_null,
    uint16_t ch,
    uint16_t *out_slot,
    uint8_t fputwc_ok) {
    if (((file_flags >> 12) & 1u) != 0u && file_ptr_or_null == 0u) {
        return 1u;
    }
    if (fputwc_ok == 0u) {
        return 0u;
    }
    if (out_slot) {
        *out_slot = ch;
    }
    return 1u;
}

void rome2_vfs_crt_write_multiple_chars(
    uint16_t ch,
    int32_t count,
    uint16_t *out_buf,
    size_t out_cap,
    int32_t *inout_chars_written) {
    int32_t i = 0;
    if (!inout_chars_written || count <= 0) {
        return;
    }
    for (i = 0; i < count; ++i) {
        if (out_buf && *inout_chars_written >= 0 && (size_t)*inout_chars_written < out_cap) {
            out_buf[(size_t)*inout_chars_written] = ch;
            ++(*inout_chars_written);
        } else {
            *inout_chars_written = -1;
            break;
        }
    }
}

uint8_t rome2_vfs_crt_wprintf_type_z(
    rome2_vfs_crt_wprintf_state64_32 *st,
    const rome2_vfs_crt_unicode_string8_32 *ustr,
    uint8_t is_wide) {
    if (!st) {
        return 0u;
    }
    if (!ustr || ustr->buffer_04 == 0u) {
        st->cap_exp_3c = 0u;
        st->suppress_38 = 6u;
        return 1u;
    }
    st->pad_34 = ustr->buffer_04;
    if (is_wide) {
        st->cap_exp_3c = 1u;
        st->suppress_38 = (uint32_t)(ustr->length_00 >> 1);
    } else {
        st->cap_exp_3c = 0u;
        st->suppress_38 = (uint32_t)ustr->length_00;
    }
    return 1u;
}

void rome2_vfs_crt_wprintf_type_a_setup(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint8_t is_negative,
    uint8_t is_inf_or_nan) {
    if (!st) {
        return;
    }
    st->fmt_flags_20 |= 0x10u;
    if (st->precision_28 < 0) {
        st->precision_28 = (st->cur_ch_32 == (uint16_t)'a' || st->cur_ch_32 == (uint16_t)'A') ? 13 : 6;
    } else if (st->precision_28 == 0 && (st->cur_ch_32 == (uint16_t)'g' || st->cur_ch_32 == (uint16_t)'G')) {
        st->precision_28 = 1;
    }
    if (is_negative) {
        st->fmt_flags_20 |= 0x40u;
    }
    if (is_inf_or_nan) {
        st->fmt_flags_20 &= ~0x08u;
        st->cur_ch_32 = (uint16_t)'s';
    }
}

uint8_t rome2_vfs_crt_wprintf_type_c(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint8_t is_wide,
    uint8_t mbtowc_ok) {
    if (!st) {
        return 0u;
    }
    st->cap_exp_3c = 1u;
    st->suppress_38 = 1u;
    if (!is_wide && !mbtowc_ok) {
        st->byte_30 = 1u;
    }
    return 1u;
}

uint8_t rome2_vfs_crt_wprintf_type_integer(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint64_t raw_val,
    uint8_t is_signed,
    uint32_t radix,
    uint8_t is_upper,
    uint16_t out_digits[66]) {
    uint64_t mag = raw_val;
    int32_t min_digits = 1;
    uint16_t rev[66];
    uint32_t pos = 0u;
    uint32_t out_pos = 0u;

    if (!st || !out_digits || (radix != 8u && radix != 10u && radix != 16u)) {
        return 0u;
    }
    if (is_signed) {
        st->fmt_flags_20 |= 0x10u;
        if ((int64_t)raw_val < 0) {
            mag = (uint64_t)(0u - raw_val);
            st->fmt_flags_20 |= 0x40u;
        }
    }
    if (st->precision_28 < 0) {
        min_digits = 1;
        st->precision_28 = 1;
    } else {
        min_digits = st->precision_28;
        st->fmt_flags_20 &= ~0x08u;
    }
    if (mag == 0u) {
        st->fmt_flags_20 &= ~0x20u;
    }

    while (mag != 0u && pos < 64u) {
        uint32_t rem = (uint32_t)(mag % radix);
        mag /= radix;
        if (rem < 10u) {
            rev[pos++] = (uint16_t)('0' + rem);
        } else {
            rev[pos++] = (uint16_t)((is_upper ? 'A' : 'a') + (rem - 10u));
        }
    }
    while ((int32_t)pos < min_digits && pos < 64u) {
        rev[pos++] = (uint16_t)'0';
    }
    if (((st->fmt_flags_20 >> 7) & 1u) != 0u && (pos == 0u || rev[pos - 1u] != (uint16_t)'0')) {
        rev[pos++] = (uint16_t)'0';
    }

    while (pos > 0u) {
        out_digits[out_pos++] = rev[--pos];
    }
    out_digits[out_pos] = 0u;
    st->suppress_38 = out_pos;
    st->cap_exp_3c = 1u;
    return 1u;
}

uint8_t rome2_vfs_crt_wprintf_type_n(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint8_t count_output_enabled,
    int32_t length_cat,
    void *out_target,
    int32_t *out_errno) {
    if (!st) {
        return 0u;
    }
    if (!count_output_enabled || !out_target) {
        if (out_errno) {
            *out_errno = 0x16;
        }
        return 0u;
    }
    switch (length_cat) {
    case 1: {
        uint8_t v = (uint8_t)st->chars_written_18;
        memcpy(out_target, &v, sizeof(v));
        break;
    }
    case 2: {
        uint16_t v = (uint16_t)st->chars_written_18;
        memcpy(out_target, &v, sizeof(v));
        break;
    }
    case 4: {
        int32_t v = st->chars_written_18;
        memcpy(out_target, &v, sizeof(v));
        break;
    }
    case 8: {
        int64_t v = (int64_t)st->chars_written_18;
        memcpy(out_target, &v, sizeof(v));
        break;
    }
    default:
        if (out_errno) {
            *out_errno = 0x16;
        }
        return 0u;
    }
    st->byte_30 = 1u;
    return 1u;
}

void rome2_vfs_crt_wprintf_type_o_flags(rome2_vfs_crt_wprintf_state64_32 *st) {
    if (!st) {
        return;
    }
    if ((st->fmt_flags_20 >> 5) & 1u) {
        st->fmt_flags_20 |= 0x80u;
    }
}

void rome2_vfs_crt_wprintf_type_p_setup(rome2_vfs_crt_wprintf_state64_32 *st) {
    if (!st) {
        return;
    }
    st->precision_28 = 8;
    st->length_mod_2c = 0x0au;
}

void rome2_vfs_crt_wprintf_type_s_len(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint32_t bounded_len,
    uint8_t is_null_ptr,
    uint8_t is_wide) {
    if (!st) {
        return;
    }
    st->cap_exp_3c = is_wide ? 1u : 0u;
    st->suppress_38 = is_null_ptr ? 6u : bounded_len;
}

uint8_t rome2_vfs_crt_wprintf_write_stored(
    const rome2_vfs_crt_wprintf_state64_32 *st,
    const uint8_t *narrow_src,
    const uint16_t *wide_src,
    uint16_t *dst,
    size_t dst_cap,
    int32_t *inout_chars_written) {
    uint32_t i = 0u;
    if (!st || !dst || !inout_chars_written) {
        return 0u;
    }
    if (st->cap_exp_3c == 0u) {
        if (!narrow_src && st->suppress_38 > 0u) {
            return 0u;
        }
        for (i = 0u; i < st->suppress_38; ++i) {
            if (*inout_chars_written >= 0 && (size_t)*inout_chars_written < dst_cap) {
                dst[(size_t)*inout_chars_written] = (uint16_t)narrow_src[i];
                ++(*inout_chars_written);
            } else {
                *inout_chars_written = -1;
            }
        }
    } else {
        if (!wide_src && st->suppress_38 > 0u) {
            return 0u;
        }
        for (i = 0u; i < st->suppress_38; ++i) {
            if (*inout_chars_written >= 0 && (size_t)*inout_chars_written < dst_cap) {
                dst[(size_t)*inout_chars_written] = wide_src[i];
                ++(*inout_chars_written);
            } else {
                *inout_chars_written = -1;
            }
        }
    }
    return 1u;
}

int32_t rome2_vfs_crt_wcstol_ascii(
    const uint16_t *nptr,
    size_t *out_end_idx,
    int32_t base,
    int32_t *out_errno) {
    size_t i = 0u;
    size_t digit_start = 0u;
    int32_t sign = 1;
    int32_t radix = base;
    uint64_t acc = 0u;
    uint64_t limit = (uint64_t)INT32_MAX;
    uint8_t overflow = 0u;

    if (out_end_idx) {
        *out_end_idx = 0u;
    }
    if (!nptr || (base != 0 && (base < 2 || base > 36))) {
        if (out_errno) {
            *out_errno = 0x16;
        }
        return 0;
    }
    while (nptr[i] == (uint16_t)' ' || (nptr[i] >= 0x09u && nptr[i] <= 0x0du)) {
        ++i;
    }
    if (nptr[i] == (uint16_t)'-') {
        sign = -1;
        limit = (uint64_t)INT32_MAX + 1u;
        ++i;
    } else if (nptr[i] == (uint16_t)'+') {
        ++i;
    }
    if ((radix == 0 || radix == 16) && nptr[i] == (uint16_t)'0' &&
        (nptr[i + 1u] == (uint16_t)'x' || nptr[i + 1u] == (uint16_t)'X')) {
        radix = 16;
        i += 2u;
    } else if (radix == 0) {
        radix = (nptr[i] == (uint16_t)'0') ? 8 : 10;
    }

    digit_start = i;
    while (nptr[i] != 0u) {
        uint16_t ch = nptr[i];
        int32_t d = -1;
        if (ch >= (uint16_t)'0' && ch <= (uint16_t)'9') {
            d = (int32_t)(ch - (uint16_t)'0');
        } else if (ch >= (uint16_t)'a' && ch <= (uint16_t)'z') {
            d = 10 + (int32_t)(ch - (uint16_t)'a');
        } else if (ch >= (uint16_t)'A' && ch <= (uint16_t)'Z') {
            d = 10 + (int32_t)(ch - (uint16_t)'A');
        }
        if (d < 0 || d >= radix) {
            break;
        }
        if (!overflow) {
            if (acc > (limit - (uint64_t)d) / (uint64_t)radix) {
                overflow = 1u;
            } else {
                acc = acc * (uint64_t)radix + (uint64_t)d;
            }
        }
        ++i;
    }
    if (out_end_idx) {
        *out_end_idx = (i > digit_start) ? i : 0u;
    }
    if (overflow) {
        if (out_errno) {
            *out_errno = 0x22;
        }
        return sign < 0 ? INT32_MIN : INT32_MAX;
    }
    return sign < 0 ? (acc == (uint64_t)INT32_MAX + 1u ? INT32_MIN : -(int32_t)acc) : (int32_t)acc;
}

int64_t rome2_vfs_crt_lseeki64_clamp(
    int64_t cur_pos,
    int64_t end_pos,
    int64_t offset,
    uint32_t origin,
    int32_t *out_errno) {
    int64_t base_pos = 0;
    int64_t target = 0;
    switch (origin) {
    case 0u:
        base_pos = 0;
        break;
    case 1u:
        base_pos = cur_pos;
        break;
    case 2u:
        base_pos = end_pos;
        break;
    default:
        if (out_errno) {
            *out_errno = 0x16;
        }
        return -1;
    }
    if ((offset > 0 && base_pos > INT64_MAX - offset) ||
        (offset < 0 && base_pos < INT64_MIN - offset)) {
        if (out_errno) {
            *out_errno = 0x16;
        }
        return -1;
    }
    target = base_pos + offset;
    if (target < 0) {
        if (out_errno) {
            *out_errno = 0x16;
        }
        return -1;
    }
    return target;
}

uint8_t rome2_vfs_crt_raise_exc_default_flag(void) {
    return 0u;
}

int32_t rome2_vfs_crt_utf8_seq_bytes(uint8_t lead_byte, const int8_t *lookuptrailbytes_256) {
    if (!lookuptrailbytes_256) {
        return 1;
    }
    return (int32_t)lookuptrailbytes_256[lead_byte] + 1;
}

uint8_t rome2_vfs_crt_write_requires_double_translation(
    uint8_t is_tty,
    const rome2_vfs_crt_ioinfo56_32 *ioinfo,
    uint8_t has_ctype_locale,
    uint8_t get_console_mode_ok) {
    if (!is_tty || !ioinfo) {
        return 0u;
    }
    if ((int8_t)ioinfo->osfile_28 >= 0) {
        return 0u;
    }
    if (!has_ctype_locale && ioinfo->pad_29[0] == 0u) {
        return 0u;
    }
    return get_console_mode_ok ? 1u : 0u;
}

void rome2_vfs_crt_write_text_ansi_lf_expand(
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t dst_cap,
    size_t *out_dst_len,
    rome2_vfs_crt_lowio_write_result12_32 *out_res) {
    size_t i = 0u;
    size_t j = 0u;
    if (out_res) {
        memset(out_res, 0, sizeof(*out_res));
    }
    if (out_dst_len) {
        *out_dst_len = 0u;
    }
    if (!src || !dst || !out_res) {
        return;
    }
    for (i = 0u; i < src_len && j < dst_cap; ++i) {
        uint8_t b = src[i];
        if (b == 0x0au) {
            if (j + 2u > dst_cap) {
                break;
            }
            dst[j++] = 0x0du;
            dst[j++] = 0x0au;
            ++out_res->extra_lf_or_chars_08;
        } else {
            dst[j++] = b;
        }
        ++out_res->bytes_written_04;
    }
    if (out_dst_len) {
        *out_dst_len = j;
    }
}

void rome2_vfs_crt_write_text_utf16_lf_expand(
    const uint16_t *src,
    size_t src_words,
    uint16_t *dst,
    size_t dst_words_cap,
    size_t *out_dst_words,
    rome2_vfs_crt_lowio_write_result12_32 *out_res) {
    size_t i = 0u;
    size_t j = 0u;
    if (out_res) {
        memset(out_res, 0, sizeof(*out_res));
    }
    if (out_dst_words) {
        *out_dst_words = 0u;
    }
    if (!src || !dst || !out_res) {
        return;
    }
    for (i = 0u; i < src_words && j < dst_words_cap; ++i) {
        uint16_t w = src[i];
        if (w == 0x000au) {
            if (j + 2u > dst_words_cap) {
                break;
            }
            dst[j++] = 0x000du;
            dst[j++] = 0x000au;
            out_res->extra_lf_or_chars_08 += 2u;
        } else {
            dst[j++] = w;
        }
        out_res->bytes_written_04 += 2u;
    }
    if (out_dst_words) {
        *out_dst_words = j;
    }
}

void rome2_vfs_crt_win32_buffer_deallocate(rome2_vfs_crt_win32_buffer24_32 *buf, uint8_t *out_freed) {
    if (out_freed) {
        *out_freed = 0u;
    }
    if (!buf) {
        return;
    }
    if (buf->allocated_14 != 0u) {
        buf->allocated_14 = 0u;
        buf->data_08 = 0u;
        if (out_freed) {
            *out_freed = 1u;
        }
    }
}

int32_t rome2_vfs_crt_win32_buffer_dyn_alloc_status(uint32_t alloc_ptr, uint32_t *out_ptr) {
    if (out_ptr) {
        *out_ptr = alloc_ptr;
    }
    return alloc_ptr != 0u ? 0 : 0x0c;
}

int32_t rome2_vfs_crt_isindst_compare_hemisphere(
    const rome2_vfs_crt_tz_transition_date12_32 *start_d,
    const rome2_vfs_crt_tz_transition_date12_32 *end_d,
    int32_t tm_yday,
    int32_t ms_of_day) {
    if (!start_d || !end_d) {
        return 0;
    }
    if (start_d->yd_04 < end_d->yd_04) {
        if (tm_yday < start_d->yd_04 || tm_yday > end_d->yd_04) {
            return 0;
        }
        if (tm_yday > start_d->yd_04 && tm_yday < end_d->yd_04) {
            return 1;
        }
    } else {
        if (tm_yday < end_d->yd_04 || tm_yday > start_d->yd_04) {
            return 1;
        }
        if (tm_yday > end_d->yd_04 && tm_yday < start_d->yd_04) {
            return 0;
        }
    }
    if (tm_yday == start_d->yd_04) {
        return ms_of_day >= start_d->ms_08 ? 1 : 0;
    }
    return ms_of_day < end_d->ms_08 ? 1 : 0;
}

void rome2_vfs_crt_tzset_nolock_reset(
    rome2_vfs_crt_tz_transition_date12_32 *start_d,
    rome2_vfs_crt_tz_transition_date12_32 *end_d,
    int32_t *out_tz_api_used) {
    if (start_d) {
        start_d->yr_00 = -1;
    }
    if (end_d) {
        end_d->yr_00 = -1;
    }
    if (out_tz_api_used) {
        *out_tz_api_used = 0;
    }
}

uint32_t rome2_vfs_crt_unlock6_index(void) {
    return ROME2_VFS_L50_LOCK_TZ;
}

uint32_t rome2_vfs_crt_lc_time_free_slot_count(void) {
    return (7u + 7u + 12u + 12u + 2u + 3u) + (7u + 7u + 12u + 12u + 2u + 4u);
}

uint8_t rome2_vfs_crt_wgetdcwd_validate_args(
    int32_t drive,
    int32_t max_len,
    uint8_t drive_valid,
    int32_t *out_errno,
    int32_t *out_doserrno) {
    if (max_len < 0) {
        if (out_errno) {
            *out_errno = 0x16;
        }
        return 0u;
    }
    if (drive != 0 && !drive_valid) {
        if (out_doserrno) {
            *out_doserrno = 0x0f;
        }
        if (out_errno) {
            *out_errno = 0x0d;
        }
        return 0u;
    }
    return 1u;
}

uint16_t rome2_vfs_crt_towlower_full_l(
    uint16_t ch,
    uint8_t has_ctype_handle,
    const uint8_t *clmap_256,
    const uint16_t *lcmap_high_256) {
    if (ch == 0xffffu) {
        return 0xffffu;
    }
    if (ch < 0x100u) {
        if (ch >= (uint16_t)'A' && ch <= (uint16_t)'Z') {
            if (clmap_256) {
                return clmap_256[ch];
            }
            return (uint16_t)(ch + ('a' - 'A'));
        }
        return ch;
    }
    if (!has_ctype_handle) {
        return ch;
    }
    if (lcmap_high_256 && ch < 0x200u) {
        return lcmap_high_256[ch - 0x100u];
    }
    return ch;
}

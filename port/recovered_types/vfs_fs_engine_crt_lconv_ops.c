#include "vfs_fs_engine_crt_lconv_ops.h"

#include <limits.h>
#include <string.h>

static uint8_t rome2_l49_is_ascii_upper(uint16_t ch) {
    return (ch >= (uint16_t)'A' && ch <= (uint16_t)'Z') ? 1u : 0u;
}

static size_t rome2_l49_collect_lconv_ptrs(
    const rome2_vfs_crt_lconv80_32 *lconv,
    const rome2_vfs_crt_lconv80_32 *c_defaults,
    const size_t *offsets,
    size_t offset_count,
    uint32_t *out_ptrs) {
    size_t found = 0u;
    size_t i = 0u;
    const uint8_t *src = (const uint8_t *)lconv;
    const uint8_t *def = (const uint8_t *)c_defaults;
    if (!lconv || !c_defaults || !out_ptrs) {
        return 0u;
    }
    for (i = 0u; i < offset_count; ++i) {
        uint32_t val = 0u;
        uint32_t def_val = 0u;
        memcpy(&val, src + offsets[i], sizeof(val));
        memcpy(&def_val, def + offsets[i], sizeof(def_val));
        if (val != def_val) {
            out_ptrs[found++] = val;
        }
    }
    return found;
}

uint8_t rome2_vfs_crt_wprintf_parse_decimal_param(
    const uint16_t *fmt_base,
    uint32_t *inout_fmt_off_words,
    int32_t *inout_cached_errno,
    int32_t *out_val) {
    int32_t saved_errno = 0;
    uint32_t start_off = 0u;
    uint32_t cur = 0u;
    int32_t sign = 1;
    uint64_t acc = 0u;
    uint64_t limit = (uint64_t)INT32_MAX;
    uint8_t any_digit = 0u;
    uint8_t overflow = 0u;

    if (!fmt_base || !inout_fmt_off_words || !inout_cached_errno || !out_val) {
        return 0u;
    }
    if (*inout_fmt_off_words == 0u) {
        return 0u;
    }

    saved_errno = *inout_cached_errno;
    *inout_cached_errno = 0;
    start_off = *inout_fmt_off_words - 1u;
    cur = start_off;

    if (fmt_base[cur] == (uint16_t)'-') {
        sign = -1;
        limit = (uint64_t)INT32_MAX + 1u;
        ++cur;
    } else if (fmt_base[cur] == (uint16_t)'+') {
        ++cur;
    }

    while (fmt_base[cur] >= (uint16_t)'0' && fmt_base[cur] <= (uint16_t)'9') {
        uint32_t d = (uint32_t)(fmt_base[cur] - (uint16_t)'0');
        any_digit = 1u;
        if (!overflow) {
            if (acc > (limit - d) / 10u) {
                overflow = 1u;
            } else {
                acc = acc * 10u + d;
            }
        }
        ++cur;
    }

    if (!any_digit) {
        cur = start_off;
    }
    if (overflow) {
        *inout_cached_errno = 0x22;
        *out_val = sign < 0 ? INT32_MIN : INT32_MAX;
    } else if (sign < 0) {
        *out_val = (acc == (uint64_t)INT32_MAX + 1u) ? INT32_MIN : -(int32_t)acc;
    } else {
        *out_val = (int32_t)acc;
    }

    {
        uint8_t ok = (*inout_cached_errno != 0x22 && cur >= *inout_fmt_off_words) ? 1u : 0u;
        if (ok) {
            *inout_fmt_off_words = cur;
        }
        if (*inout_cached_errno == 0 && saved_errno != 0) {
            *inout_cached_errno = saved_errno;
        }
        return ok;
    }
}

uint8_t rome2_vfs_crt_wprintf_emit_normal_char(
    rome2_vfs_crt_wprintf_state64_32 *st,
    uint16_t *out_buf,
    size_t out_cap) {
    if (!st) {
        return 0u;
    }
    st->cap_exp_3c = 1u;
    if (out_buf && st->chars_written_18 >= 0 && (size_t)st->chars_written_18 < out_cap) {
        out_buf[(size_t)st->chars_written_18] = st->cur_ch_32;
        ++st->chars_written_18;
    } else {
        st->chars_written_18 = -1;
    }
    return 1u;
}

static uint8_t rome2_l49_is_valid_wprintf_spec(uint16_t ch, uint8_t *out_add_signed_flag) {
    *out_add_signed_flag = 0u;
    switch (ch) {
    case (uint16_t)'d':
    case (uint16_t)'i':
        *out_add_signed_flag = 1u;
        return 1u;
    case (uint16_t)'A':
    case (uint16_t)'C':
    case (uint16_t)'E':
    case (uint16_t)'F':
    case (uint16_t)'G':
    case (uint16_t)'S':
    case (uint16_t)'X':
    case (uint16_t)'Z':
    case (uint16_t)'a':
    case (uint16_t)'c':
    case (uint16_t)'e':
    case (uint16_t)'f':
    case (uint16_t)'g':
    case (uint16_t)'n':
    case (uint16_t)'o':
    case (uint16_t)'p':
    case (uint16_t)'s':
    case (uint16_t)'u':
    case (uint16_t)'x':
        return 1u;
    default:
        return 0u;
    }
}

uint8_t rome2_vfs_crt_wprintf_format_specifier_plan(
    const rome2_vfs_crt_wprintf_state64_32 *st,
    uint8_t subhandler_ok,
    uint32_t *out_eff_flags,
    int32_t *out_lead_spaces,
    int32_t *out_zero_pad,
    int32_t *out_trail_spaces,
    uint16_t out_prefix[2],
    uint32_t *out_prefix_len) {
    uint8_t add_signed = 0u;
    uint32_t flags = 0u;
    uint32_t plen = 0u;
    int32_t pad = 0;

    if (!st || !out_eff_flags || !out_lead_spaces || !out_zero_pad ||
        !out_trail_spaces || !out_prefix || !out_prefix_len) {
        return 0u;
    }
    *out_eff_flags = st->fmt_flags_20;
    *out_lead_spaces = 0;
    *out_zero_pad = 0;
    *out_trail_spaces = 0;
    out_prefix[0] = 0u;
    out_prefix[1] = 0u;
    *out_prefix_len = 0u;

    if (!rome2_l49_is_valid_wprintf_spec(st->cur_ch_32, &add_signed)) {
        return 0u;
    }
    if (add_signed) {
        *out_eff_flags |= 0x10u;
    }
    if (!subhandler_ok) {
        return 0u;
    }
    if (st->byte_30 != 0u) {
        return 1u;
    }

    flags = *out_eff_flags;
    if ((flags >> 4) & 1u) {
        if ((flags >> 6) & 1u) {
            out_prefix[plen++] = (uint16_t)'-';
        } else if (flags & 1u) {
            out_prefix[plen++] = (uint16_t)'+';
        } else if ((flags >> 1) & 1u) {
            out_prefix[plen++] = (uint16_t)' ';
        }
    }
    {
        uint8_t is_hex_alt = ((st->cur_ch_32 == (uint16_t)'x' || st->cur_ch_32 == (uint16_t)'X') &&
                              ((flags >> 5) & 1u))
                                 ? 1u
                                 : 0u;
        uint8_t is_hex_fp = (st->cur_ch_32 == (uint16_t)'a' || st->cur_ch_32 == (uint16_t)'A') ? 1u : 0u;
        if (is_hex_alt || is_hex_fp) {
            out_prefix[plen++] = (uint16_t)'0';
            out_prefix[plen++] = (st->cur_ch_32 == (uint16_t)'X' || st->cur_ch_32 == (uint16_t)'A')
                                     ? (uint16_t)'X'
                                     : (uint16_t)'x';
        }
    }
    *out_prefix_len = plen;

    pad = st->width_24 - (int32_t)st->suppress_38 - (int32_t)plen;
    if (pad > 0) {
        if ((flags & 0x0cu) == 0u) {
            *out_lead_spaces = pad;
        }
        if (((flags >> 3) & 1u) && (((flags >> 2) & 1u) == 0u)) {
            *out_zero_pad = pad;
        }
        if (st->chars_written_18 >= 0 && ((flags >> 2) & 1u)) {
            *out_trail_spaces = pad;
        }
    }
    return 1u;
}

uint32_t rome2_vfs_crt_win32_buffer_set_range_error(
    rome2_vfs_crt_win32_buffer24_32 *buf,
    int32_t *out_errno) {
    if (buf) {
        buf->allocated_14 = 0u;
        buf->capacity_words_0c = 0u;
    }
    if (out_errno) {
        *out_errno = 0x22;
    }
    return 0x22u;
}

int32_t rome2_vfs_crt_win32_buffer_alloc_words(
    rome2_vfs_crt_win32_buffer24_32 *buf,
    uint32_t word_count,
    uint32_t new_guest_ptr,
    uint8_t alloc_ok) {
    if (!buf) {
        return 0x16;
    }
    buf->size_words_10 = 0u;
    if (!alloc_ok || word_count > (UINT32_MAX / 2u)) {
        buf->data_08 = 0u;
        buf->capacity_words_0c = 0u;
        buf->allocated_14 = 0u;
        return 0x0c;
    }
    buf->data_08 = new_guest_ptr;
    buf->capacity_words_0c = word_count;
    buf->allocated_14 = 1u;
    return 0;
}

int32_t rome2_vfs_crt_write_nolock_plan(
    const rome2_vfs_crt_ioinfo56_32 *ioinfo,
    const void *buf,
    uint32_t cnt,
    uint8_t is_tty,
    uint32_t win32_bytes_written,
    uint32_t win32_err,
    int32_t mapped_errno,
    uint8_t *out_seek_append,
    uint8_t *out_path_kind,
    int32_t *out_errno,
    int32_t *out_doserrno) {
    uint8_t textmode = 0u;
    uint8_t osfile = 0u;

    if (out_seek_append) {
        *out_seek_append = 0u;
    }
    if (out_path_kind) {
        *out_path_kind = ROME2_VFS_L49_WRITE_PATH_NONE;
    }
    if (cnt == 0u) {
        return 0;
    }
    if (!ioinfo || !buf) {
        if (out_doserrno) {
            *out_doserrno = 0;
        }
        if (out_errno) {
            *out_errno = 0x16;
        }
        return -1;
    }

    osfile = ioinfo->osfile_28;
    textmode = ioinfo->pad_29[0];
    if ((textmode == 2u || textmode == 1u) && (cnt & 1u) != 0u) {
        if (out_doserrno) {
            *out_doserrno = 0;
        }
        if (out_errno) {
            *out_errno = 0x16;
        }
        return -1;
    }
    if ((osfile & 0x20u) != 0u && out_seek_append) {
        *out_seek_append = 1u;
    }

    if (out_path_kind) {
        if (is_tty) {
            *out_path_kind = (textmode == 1u || textmode == 2u)
                                 ? ROME2_VFS_L49_WRITE_PATH_TTY_WIDE
                                 : ROME2_VFS_L49_WRITE_PATH_TTY_ANSI;
        } else if ((osfile & 0x80u) != 0u) {
            if (textmode == 2u) {
                *out_path_kind = ROME2_VFS_L49_WRITE_PATH_TEXT_UTF16;
            } else if (textmode == 1u) {
                *out_path_kind = ROME2_VFS_L49_WRITE_PATH_TEXT_UTF8;
            } else if (textmode == 0u) {
                *out_path_kind = ROME2_VFS_L49_WRITE_PATH_TEXT_ANSI;
            }
        } else {
            *out_path_kind = ROME2_VFS_L49_WRITE_PATH_BINARY;
        }
    }

    if (win32_bytes_written == 0u) {
        if (win32_err != 0u) {
            if (win32_err == 5u) {
                if (out_errno) {
                    *out_errno = 9;
                }
                if (out_doserrno) {
                    *out_doserrno = 5;
                }
            } else {
                if (out_doserrno) {
                    *out_doserrno = (int32_t)win32_err;
                }
                if (out_errno) {
                    *out_errno = mapped_errno;
                }
            }
            return -1;
        }
        if ((osfile & 0x40u) != 0u && ((const uint8_t *)buf)[0] == 0x1au) {
            return 0;
        }
        if (out_errno) {
            *out_errno = 0x1c;
        }
        if (out_doserrno) {
            *out_doserrno = 0;
        }
        return -1;
    }

    return (int32_t)win32_bytes_written;
}

uint32_t rome2_vfs_crt_lowio_unlock_fh_offset(int32_t fh) {
    if (fh < 0) {
        return UINT32_MAX;
    }
    return (uint32_t)(fh & 0x3f) * (uint32_t)sizeof(rome2_vfs_crt_ioinfo56_32);
}

uint16_t rome2_vfs_crt_towlower_l(
    uint16_t ch,
    uint8_t has_custom_clmap,
    const uint8_t *clmap_256,
    const uint16_t *fallback_map_256) {
    if (ch < 0x100u) {
        uint8_t c = (uint8_t)ch;
        if (rome2_l49_is_ascii_upper(ch)) {
            if (has_custom_clmap && clmap_256) {
                return clmap_256[c];
            }
            return (uint16_t)(c + ('a' - 'A'));
        }
        return c;
    }
    if (fallback_map_256 && ch < 0x200u) {
        return fallback_map_256[ch - 0x100u];
    }
    return ch;
}

uint8_t rome2_vfs_crt_get_string_type_a_plan(
    uint32_t requested_cp,
    uint32_t locale_cp,
    uint8_t b_error,
    uint32_t wchar_count,
    uint32_t *out_effective_cp,
    uint32_t *out_mb_flags,
    uint32_t *out_alloc_bytes,
    uint8_t *out_uses_heap) {
    uint32_t raw_bytes = 0u;
    uint32_t total = 0u;
    if (!out_effective_cp || !out_mb_flags || !out_alloc_bytes || !out_uses_heap) {
        return 0u;
    }
    *out_effective_cp = requested_cp != 0u ? requested_cp : locale_cp;
    *out_mb_flags = b_error ? 9u : 1u;
    *out_alloc_bytes = 0u;
    *out_uses_heap = 0u;
    if (wchar_count == 0u || wchar_count > (UINT32_MAX - 8u) / 2u) {
        return 0u;
    }
    raw_bytes = wchar_count * 2u;
    total = raw_bytes + 8u;
    *out_alloc_bytes = total;
    *out_uses_heap = total > 0x400u ? 1u : 0u;
    return 1u;
}

void rome2_vfs_crt_tzset_once(int32_t *tzset_called, uint8_t *out_ran_init) {
    if (out_ran_init) {
        *out_ran_init = 0u;
    }
    if (!tzset_called) {
        return;
    }
    if (*tzset_called == 0) {
        ++(*tzset_called);
        if (out_ran_init) {
            *out_ran_init = 1u;
        }
    }
}

int32_t rome2_vfs_crt_isindst_locked(int32_t tm_year, int32_t daylight_flag, uint8_t has_dst_rule) {
    (void)tm_year;
    if (daylight_flag == 0) {
        return 0;
    }
    return has_dst_rule ? 1 : 0;
}

uint32_t rome2_vfs_crt_unlock_index_for_helper(uint32_t helper_va) {
    static const struct {
        uint32_t va;
        uint32_t lock_idx;
    } k_unlock_helpers[3] = {
        { 0x116b5877u, ROME2_VFS_L49_LOCK_EXIT },
        { 0x116b5fc7u, ROME2_VFS_L49_LOCK_SETLOCALE },
        { 0x116b4bcfu, ROME2_VFS_L49_LOCK_MBCP },
    };
    size_t i = 0u;
    for (i = 0u; i < sizeof(k_unlock_helpers) / sizeof(k_unlock_helpers[0]); ++i) {
        if (k_unlock_helpers[i].va == helper_va) {
            return k_unlock_helpers[i].lock_idx;
        }
    }
    return UINT32_MAX;
}

int32_t rome2_vfs_crt_lc_time_add_ref(rome2_vfs_crt_lc_time_data180_32 *p, uint8_t is_static_c) {
    if (!p || is_static_c) {
        return INT32_MAX;
    }
    return ++p->refcount_b0;
}

int32_t rome2_vfs_crt_lc_time_release_ref(rome2_vfs_crt_lc_time_data180_32 *p, uint8_t is_static_c) {
    if (!p || is_static_c) {
        return INT32_MAX;
    }
    return --p->refcount_b0;
}

uint8_t rome2_vfs_crt_lc_time_should_free(const rome2_vfs_crt_lc_time_data180_32 *p, uint8_t is_static_c) {
    return (p && !is_static_c && p->refcount_b0 == 0) ? 1u : 0u;
}

uint32_t rome2_vfs_crt_updatetlocinfo_nolock(
    uint32_t *inout_dst_va,
    uint32_t new_loc_va,
    int32_t *new_refcount,
    int32_t *old_refcount,
    uint32_t static_initiallocinfo_va,
    uint8_t *out_should_free_old) {
    uint32_t old_va = 0u;
    if (out_should_free_old) {
        *out_should_free_old = 0u;
    }
    if (!inout_dst_va || new_loc_va == 0u) {
        return 0u;
    }
    old_va = *inout_dst_va;
    if (old_va == new_loc_va) {
        return new_loc_va;
    }
    *inout_dst_va = new_loc_va;
    if (new_refcount) {
        ++(*new_refcount);
    }
    if (old_va != 0u && old_refcount) {
        --(*old_refcount);
        if (*old_refcount == 0 && old_va != static_initiallocinfo_va && out_should_free_old) {
            *out_should_free_old = 1u;
        }
    }
    return new_loc_va;
}

size_t rome2_vfs_crt_free_lconv_mon_collect(
    const rome2_vfs_crt_lconv80_32 *lconv,
    const rome2_vfs_crt_lconv80_32 *c_defaults,
    uint32_t out_ptrs[13]) {
    static const size_t k_mon_offsets[13] = {
        offsetof(rome2_vfs_crt_lconv80_32, int_curr_symbol_0c),
        offsetof(rome2_vfs_crt_lconv80_32, currency_symbol_10),
        offsetof(rome2_vfs_crt_lconv80_32, mon_decimal_point_14),
        offsetof(rome2_vfs_crt_lconv80_32, mon_thousands_sep_18),
        offsetof(rome2_vfs_crt_lconv80_32, mon_grouping_1c),
        offsetof(rome2_vfs_crt_lconv80_32, positive_sign_20),
        offsetof(rome2_vfs_crt_lconv80_32, negative_sign_24),
        offsetof(rome2_vfs_crt_lconv80_32, w_int_curr_symbol_38),
        offsetof(rome2_vfs_crt_lconv80_32, w_currency_symbol_3c),
        offsetof(rome2_vfs_crt_lconv80_32, w_mon_decimal_point_40),
        offsetof(rome2_vfs_crt_lconv80_32, w_mon_thousands_sep_44),
        offsetof(rome2_vfs_crt_lconv80_32, w_positive_sign_48),
        offsetof(rome2_vfs_crt_lconv80_32, w_negative_sign_4c),
    };
    return rome2_l49_collect_lconv_ptrs(lconv, c_defaults, k_mon_offsets, 13u, out_ptrs);
}

size_t rome2_vfs_crt_free_lconv_num_collect(
    const rome2_vfs_crt_lconv80_32 *lconv,
    const rome2_vfs_crt_lconv80_32 *c_defaults,
    uint32_t out_ptrs[5]) {
    static const size_t k_num_offsets[5] = {
        offsetof(rome2_vfs_crt_lconv80_32, decimal_point_00),
        offsetof(rome2_vfs_crt_lconv80_32, thousands_sep_04),
        offsetof(rome2_vfs_crt_lconv80_32, grouping_08),
        offsetof(rome2_vfs_crt_lconv80_32, w_decimal_point_30),
        offsetof(rome2_vfs_crt_lconv80_32, w_thousands_sep_34),
    };
    return rome2_l49_collect_lconv_ptrs(lconv, c_defaults, k_num_offsets, 5u, out_ptrs);
}

void rome2_vfs_crt_wgetcwd_default_drive_probe(uint8_t drive_num, uint16_t out_probe[4]) {
    if (!out_probe) {
        return;
    }
    if (drive_num == 0u) {
        out_probe[0] = (uint16_t)'.';
        out_probe[1] = 0u;
        out_probe[2] = 0u;
        out_probe[3] = 0u;
    } else {
        out_probe[0] = (uint16_t)(0x40u + drive_num);
        out_probe[1] = (uint16_t)':';
        out_probe[2] = (uint16_t)'.';
        out_probe[3] = 0u;
    }
}

void rome2_vfs_crt_raise_matherr_plan(
    int32_t opcode,
    const rome2_vfs_crt_math_exception32_32 *exc,
    uint8_t handle_exc_handled,
    uint8_t has_user_matherr,
    uint8_t *out_exc_flag,
    uint8_t *out_call_raise_exc,
    uint8_t *out_set_fp_value,
    uint8_t *out_call_user_matherr,
    int32_t *out_fallback_errno) {
    uint8_t flag = 0u;
    uint8_t valid = 1u;

    if (out_exc_flag) {
        *out_exc_flag = 0u;
    }
    if (out_call_raise_exc) {
        *out_call_raise_exc = 0u;
    }
    if (out_set_fp_value) {
        *out_set_fp_value = 0u;
    }
    if (out_call_user_matherr) {
        *out_call_user_matherr = 0u;
    }
    if (out_fallback_errno) {
        *out_fallback_errno = 0;
    }
    if (!exc) {
        return;
    }

    switch (exc->type_00) {
    case 1:
    case 5:
        flag = 0x08u;
        break;
    case 2:
        flag = 0x04u;
        break;
    case 3:
        flag = 0x11u;
        break;
    case 4:
        flag = 0x12u;
        break;
    case 8:
        flag = 0x10u;
        break;
    default:
        valid = 0u;
        break;
    }

    if (out_exc_flag) {
        *out_exc_flag = flag;
    }
    if (valid && !handle_exc_handled) {
        if (out_call_raise_exc) {
            *out_call_raise_exc = 1u;
        }
        if (out_set_fp_value && (opcode == 0x10 || opcode == 0x16 || opcode == 0x1d)) {
            *out_set_fp_value = 1u;
        }
    }

    if (exc->type_00 != 8 && has_user_matherr) {
        if (out_call_user_matherr) {
            *out_call_user_matherr = 1u;
        }
        return;
    }
    if (out_fallback_errno) {
        if (exc->type_00 == 1) {
            *out_fallback_errno = 0x21;
        } else if (exc->type_00 == 2 || exc->type_00 == 3) {
            *out_fallback_errno = 0x22;
        }
    }
}

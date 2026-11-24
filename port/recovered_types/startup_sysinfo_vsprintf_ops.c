#include "startup_sysinfo_vsprintf_ops.h"
#include "vfs_fs_engine_crt_fls_ops.h"
#include "vfs_fs_engine_crt_printf_ops.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROME2_L63_EINVAL 22
#define ROME2_L63_ERANGE 34

/* 91-byte UCRT state transition LUT at 0x1190ec70 (high nibble = next state, low nibble = char class). */
static uint8_t l63_find_next_state_fallback(uint8_t ch, uint32_t prev_state) {
    if (prev_state == 0u) {
        return (ch == (uint8_t)'%') ? 1u : 0u;
    }
    if (prev_state == 1u && ch == (uint8_t)'%') {
        return 0u;
    }
    if (prev_state <= 2u &&
        (ch == (uint8_t)'+' || ch == (uint8_t)'-' || ch == (uint8_t)' ' ||
         ch == (uint8_t)'#' || ch == (uint8_t)'0')) {
        return 2u;
    }
    if (prev_state <= 3u && ((ch >= (uint8_t)'0' && ch <= (uint8_t)'9') || ch == (uint8_t)'*')) {
        return 3u;
    }
    if (prev_state <= 4u && ch == (uint8_t)'.') {
        return 4u;
    }
    if ((prev_state == 4u || prev_state == 5u) &&
        ((ch >= (uint8_t)'0' && ch <= (uint8_t)'9') || ch == (uint8_t)'*')) {
        return 5u;
    }
    if (prev_state <= 6u &&
        (ch == (uint8_t)'F' || ch == (uint8_t)'I' || ch == (uint8_t)'L' ||
         ch == (uint8_t)'N' || ch == (uint8_t)'T' || ch == (uint8_t)'h' ||
         ch == (uint8_t)'j' || ch == (uint8_t)'l' || ch == (uint8_t)'t' ||
         ch == (uint8_t)'w' || ch == (uint8_t)'z')) {
        return 6u;
    }
    return 7u;
}

static uintptr_t l63_next_arg(rome2_startup_nprintf_processor *proc) {
    if (!proc || !proc->args || proc->arg_idx >= proc->arg_count) {
        return 0u;
    }
    return proc->args[proc->arg_idx++];
}

static void l63_sync_target_guest(rome2_startup_nprintf_target *target) {
    if (!target) {
        return;
    }
    target->guest16.buffer_cursor_00 = (target->buf != NULL) ? target->written_chars : 0u;
    target->guest16.max_chars_04 = target->max_chars;
    target->guest16.written_chars_08 = target->written_chars;
    target->guest16.continue_on_truncation_0c = target->continue_on_truncation;
}

static void l63_sync_proc_guest(rome2_startup_nprintf_processor *proc) {
    if (!proc) {
        return;
    }
    proc->guest_state.core_00.flags_opt_00 = (uint32_t)(proc->options & 0xffffffffULL);
    proc->guest_state.core_00.locinfo_04 = (uint32_t)proc->has_locale;
    proc->guest_state.core_00.adapter_08 = proc->target ? 1u : 0u;
    proc->guest_state.core_00.fmt_ptr_10 = proc->fmt_cursor ? 1u : 0u;
    proc->guest_state.core_00.valist_14 = (uint32_t)proc->arg_idx;
    proc->guest_state.core_00.chars_written_18 = proc->characters_written;
    proc->guest_state.core_00.fsm_state_1c = (uint32_t)proc->state;
    proc->guest_state.core_00.fmt_flags_20 = proc->flags;
    proc->guest_state.core_00.width_24 = proc->field_width;
    proc->guest_state.core_00.precision_28 = proc->precision;
    proc->guest_state.core_00.length_mod_2c = proc->length_mod;
    proc->guest_state.core_00.byte_30 = proc->suppress_output;
    proc->guest_state.core_00.pad_31 = proc->current_ch;
    proc->guest_state.core_00.pad_34 = (proc->narrow_ptr != NULL || proc->wide_ptr != NULL) ? 1u : 0u;
    proc->guest_state.core_00.suppress_38 = (uint32_t)proc->str_len;
    proc->guest_state.core_00.cap_exp_3c = proc->is_wide;
    proc->guest_state.adapter_ptr_448 = proc->target ? 1u : 0u;
}

static size_t l63_u16_len(const uint16_t *s) {
    size_t n = 0u;
    if (!s) {
        return 0u;
    }
    while (s[n] != 0u) {
        ++n;
    }
    return n;
}

static size_t l63_bounded_strlen(const char *s, int32_t max_chars) {
    size_t limit = (max_chars < 0) ? 0x7fffffffu : (size_t)max_chars;
    size_t n = 0u;
    if (!s) {
        return 0u;
    }
    while (n < limit && s[n] != '\0') {
        ++n;
    }
    return n;
}

static void l63_safe_copy_cstr(char *dst, size_t dst_cap, const char *src) {
    size_t i = 0u;
    if (!dst || dst_cap == 0u) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }
    while (i + 1u < dst_cap && src[i] != '\0') {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}

/* `0x1169de89` */
int32_t rome2_startup_crt_strtol_1169de89(
    const char *nptr,
    const char **out_endptr,
    int32_t base,
    int32_t *out_errno) {
    const char *p = nptr;
    char *end = NULL;
    uint32_t acc = 0u;
    uint32_t cutoff = 0u;
    uint32_t cutlim = 0u;
    uint8_t negative = 0u;
    uint8_t overflow = 0u;
    uint8_t any = 0u;
    int32_t radix = base;

    if (out_endptr) {
        *out_endptr = nptr;
    }
    if (!nptr || (radix != 0 && (radix < 2 || radix > 36))) {
        if (out_errno) {
            *out_errno = ROME2_L63_EINVAL;
        }
        return 0;
    }
    while (*p != '\0' && isspace((uint8_t)*p)) {
        ++p;
    }
    if (*p == '-') {
        negative = 1u;
        ++p;
    } else if (*p == '+') {
        ++p;
    }
    if ((radix == 0 || radix == 16) && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
        radix = 16;
    } else if (radix == 0) {
        radix = (*p == '0') ? 8 : 10;
    }

    cutoff = negative ? 0x80000000u : 0x7fffffffu;
    cutlim = cutoff % (uint32_t)radix;
    cutoff /= (uint32_t)radix;

    while (*p != '\0') {
        uint8_t c = (uint8_t)*p;
        int32_t d = -1;
        if (c >= (uint8_t)'0' && c <= (uint8_t)'9') {
            d = (int32_t)(c - (uint8_t)'0');
        } else if (c >= (uint8_t)'a' && c <= (uint8_t)'z') {
            d = (int32_t)(c - (uint8_t)'a') + 10;
        } else if (c >= (uint8_t)'A' && c <= (uint8_t)'Z') {
            d = (int32_t)(c - (uint8_t)'A') + 10;
        }
        if (d < 0 || d >= radix) {
            break;
        }
        any = 1u;
        if (acc > cutoff || (acc == cutoff && (uint32_t)d > cutlim)) {
            overflow = 1u;
        } else {
            acc = acc * (uint32_t)radix + (uint32_t)d;
        }
        ++p;
    }
    end = (char *)(uintptr_t)(any ? p : nptr);
    if (out_endptr) {
        *out_endptr = end;
    }
    if (overflow) {
        if (out_errno) {
            *out_errno = ROME2_L63_ERANGE;
        }
        return negative ? (-2147483647 - 1) : 2147483647;
    }
    if (!any) {
        return 0;
    }
    return negative ? (int32_t)(0u - acc) : (int32_t)acc;
}

/* `0x1168942b` */
uint8_t rome2_startup_nprintf_parse_int_1168942b(
    rome2_startup_nprintf_processor *proc,
    int32_t *out_val) {
    const char *start = NULL;
    const char *end = NULL;
    int32_t parse_err = 0;
    int32_t val = 0;
    if (!proc || !out_val || !proc->fmt_cursor) {
        return 0u;
    }
    /* Match 0x1168944f: dec eax before passing start of digit run */
    start = proc->fmt_cursor - 1;
    val = rome2_startup_crt_strtol_1169de89(start, &end, 10, &parse_err);
    *out_val = val;
    if (parse_err == ROME2_L63_ERANGE || !end || end < proc->fmt_cursor) {
        return 0u;
    }
    proc->fmt_cursor = end;
    l63_sync_proc_guest(proc);
    return 1u;
}

/* `0x11688abd` */
uint8_t rome2_startup_nprintf_is_wide_specifier_11688abd(
    uint64_t options,
    uint8_t specifier,
    int32_t length_mod) {
    (void)options;
    if (length_mod == 2 || length_mod == 1) {
        return 0u;
    }
    if (length_mod == 3 || length_mod == 12) {
        return 1u;
    }
    if (length_mod == 13) {
        return 0u;
    }
    if (specifier == (uint8_t)'c' || specifier == (uint8_t)'s') {
        return 0u;
    }
    return 1u;
}

/* `0x11689311` */
uint32_t rome2_startup_nprintf_find_next_state_11689311(
    uint8_t ch,
    uint32_t prev_state) {
    return (uint32_t)l63_find_next_state_fallback(ch, prev_state);
}

/* `0x11688e5c` */
void rome2_startup_nprintf_common_data_init_11688e5c(
    rome2_startup_nprintf_processor *proc) {
    if (!proc) {
        return;
    }
    memset(proc, 0, sizeof(*proc));
}

/* `0x11688eeb` */
void rome2_startup_nprintf_adapter_data_init_11688eeb(
    rome2_startup_nprintf_processor *proc,
    rome2_startup_nprintf_target *target,
    uint64_t options,
    const char *fmt,
    uint8_t has_locale,
    const uintptr_t *args,
    size_t arg_count) {
    if (!proc) {
        return;
    }
    rome2_startup_nprintf_common_data_init_11688e5c(proc);
    proc->options = options;
    proc->has_locale = has_locale;
    proc->fmt_cursor = fmt;
    proc->args = args;
    proc->arg_count = arg_count;
    proc->target = target;
    proc->precision = -1;
    l63_sync_proc_guest(proc);
}

/* `0x1168b92d` */
uint8_t rome2_startup_nprintf_write_char_1168b92d(
    rome2_startup_nprintf_target *target,
    char ch,
    int32_t *written_inout) {
    if (!target || !written_inout) {
        return 0u;
    }
    if (target->written_chars == target->max_chars) {
        if (target->continue_on_truncation == 0u) {
            *written_inout = -1;
        } else {
            *written_inout += 1;
        }
        l63_sync_target_guest(target);
        return target->continue_on_truncation;
    }
    if (target->buf && target->written_chars < target->max_chars) {
        target->buf[target->written_chars] = ch;
    }
    target->written_chars += 1u;
    *written_inout += 1;
    l63_sync_target_guest(target);
    return 1u;
}

/* `0x1168bcef` */
void rome2_startup_nprintf_write_string_1168bcef(
    rome2_startup_nprintf_target *target,
    const char *s,
    int32_t len,
    int32_t *written_inout) {
    uint32_t rem = 0u;
    uint32_t copy_len = 0u;
    if (!target || !written_inout || len <= 0) {
        return;
    }
    if (target->written_chars == target->max_chars) {
        if (target->continue_on_truncation == 0u) {
            *written_inout = -1;
            l63_sync_target_guest(target);
            return;
        }
        *written_inout += len;
        return;
    }
    rem = target->max_chars - target->written_chars;
    copy_len = ((uint32_t)len <= rem) ? (uint32_t)len : rem;
    if (target->buf && s && copy_len > 0u) {
        memcpy(target->buf + target->written_chars, s, copy_len);
    }
    target->written_chars += copy_len;
    l63_sync_target_guest(target);
    if (target->continue_on_truncation != 0u || copy_len == (uint32_t)len) {
        *written_inout += len;
    } else {
        *written_inout = -1;
    }
}

/* `0x11688dff` */
void rome2_startup_nprintf_write_multi_chars_11688dff(
    rome2_startup_nprintf_target *target,
    char ch,
    int32_t count,
    int32_t *written_inout) {
    int32_t i = 0;
    if (!target || !written_inout || count <= 0) {
        return;
    }
    for (i = 0; i < count; ++i) {
        (void)rome2_startup_nprintf_write_char_1168b92d(target, ch, written_inout);
        if (*written_inout == -1) {
            return;
        }
    }
}

/* `0x1168baca` */
uint8_t rome2_startup_nprintf_write_stored_tchar_1168baca(
    rome2_startup_nprintf_processor *proc) {
    if (!proc || !proc->target) {
        return 0u;
    }
    if (proc->is_wide == 0u) {
        if (proc->str_len > 0 && proc->narrow_ptr != NULL) {
            rome2_startup_nprintf_write_string_1168bcef(
                proc->target,
                proc->narrow_ptr,
                proc->str_len,
                &proc->characters_written);
        }
    } else if (proc->str_len > 0 && proc->wide_ptr != NULL) {
        int32_t i = 0;
        for (i = 0; i < proc->str_len; ++i) {
            uint16_t wc = proc->wide_ptr[i];
            if (wc <= 0x7fu) {
                (void)rome2_startup_nprintf_write_char_1168b92d(
                    proc->target,
                    (char)(uint8_t)wc,
                    &proc->characters_written);
            } else if (wc <= 0x7ffu) {
                (void)rome2_startup_nprintf_write_char_1168b92d(
                    proc->target,
                    (char)(uint8_t)(0xC0u | (wc >> 6)),
                    &proc->characters_written);
                (void)rome2_startup_nprintf_write_char_1168b92d(
                    proc->target,
                    (char)(uint8_t)(0x80u | (wc & 0x3Fu)),
                    &proc->characters_written);
            } else {
                (void)rome2_startup_nprintf_write_char_1168b92d(
                    proc->target,
                    (char)(uint8_t)(0xE0u | (wc >> 12)),
                    &proc->characters_written);
                (void)rome2_startup_nprintf_write_char_1168b92d(
                    proc->target,
                    (char)(uint8_t)(0x80u | ((wc >> 6) & 0x3Fu)),
                    &proc->characters_written);
                (void)rome2_startup_nprintf_write_char_1168b92d(
                    proc->target,
                    (char)(uint8_t)(0x80u | (wc & 0x3Fu)),
                    &proc->characters_written);
            }
            if (proc->characters_written == -1) {
                break;
            }
        }
    }
    l63_sync_proc_guest(proc);
    return 1u;
}

/* `0x11689ce5` */
uint8_t rome2_startup_nprintf_state_flag_11689ce5(
    rome2_startup_nprintf_processor *proc) {
    if (!proc) {
        return 0u;
    }
    if (proc->current_ch == (uint8_t)'+') {
        proc->flags |= 0x01u;
    } else if (proc->current_ch == (uint8_t)' ') {
        proc->flags |= 0x02u;
    } else if (proc->current_ch == (uint8_t)'-') {
        proc->flags |= 0x04u;
    } else if (proc->current_ch == (uint8_t)'0') {
        proc->flags |= 0x08u;
    } else if (proc->current_ch == (uint8_t)'#') {
        proc->flags |= 0x20u;
    }
    l63_sync_proc_guest(proc);
    return 1u;
}

/* `0x1168ae5c` */
uint8_t rome2_startup_nprintf_state_width_1168ae5c(
    rome2_startup_nprintf_processor *proc) {
    if (!proc) {
        return 0u;
    }
    if (proc->current_ch == (uint8_t)'*') {
        int32_t w = (int32_t)l63_next_arg(proc);
        if (w < 0) {
            proc->flags |= 0x04u;
            w = (w == (-2147483647 - 1)) ? 2147483647 : -w;
        }
        proc->field_width = w;
        l63_sync_proc_guest(proc);
        return 1u;
    }
    return rome2_startup_nprintf_parse_int_1168942b(proc, &proc->field_width);
}

/* `0x11689f55` */
uint8_t rome2_startup_nprintf_state_precision_11689f55(
    rome2_startup_nprintf_processor *proc) {
    if (!proc) {
        return 0u;
    }
    if (proc->current_ch == (uint8_t)'*') {
        int32_t p = (int32_t)l63_next_arg(proc);
        proc->precision = (p < 0) ? -1 : p;
        l63_sync_proc_guest(proc);
        return 1u;
    }
    return rome2_startup_nprintf_parse_int_1168942b(proc, &proc->precision);
}

/* `0x1168a0f0` */
uint8_t rome2_startup_nprintf_state_size_1168a0f0(
    rome2_startup_nprintf_processor *proc) {
    uint8_t ch = 0u;
    if (!proc) {
        return 0u;
    }
    ch = proc->current_ch;
    if (ch == (uint8_t)'F') {
        if ((proc->options & ROME2_STARTUP_WPRINTF_OPT_DISABLE_FN) == 0ULL) {
            proc->state = 7;
            return rome2_startup_nprintf_state_type_1168a760(proc);
        }
        return 1u;
    }
    if (ch == (uint8_t)'N') {
        if ((proc->options & ROME2_STARTUP_WPRINTF_OPT_DISABLE_FN) == 0ULL) {
            proc->state = 8;
            proc->last_errno = ROME2_L63_EINVAL;
            proc->invalid_param_count += 1u;
            l63_sync_proc_guest(proc);
            return 0u;
        }
        return 1u;
    }
    if (proc->length_mod != 0u) {
        proc->last_errno = ROME2_L63_EINVAL;
        proc->invalid_param_count += 1u;
        l63_sync_proc_guest(proc);
        return 0u;
    }
    if (ch == (uint8_t)'j') {
        proc->length_mod = 5u;
    } else if (ch == (uint8_t)'I') {
        if (proc->fmt_cursor && proc->fmt_cursor[0] == '3' && proc->fmt_cursor[1] == '2') {
            proc->length_mod = 10u;
            proc->fmt_cursor += 2;
        } else if (proc->fmt_cursor && proc->fmt_cursor[0] == '6' && proc->fmt_cursor[1] == '4') {
            proc->length_mod = 11u;
            proc->fmt_cursor += 2;
        } else if (proc->fmt_cursor &&
                   (proc->fmt_cursor[0] == 'd' || proc->fmt_cursor[0] == 'i' ||
                    proc->fmt_cursor[0] == 'o' || proc->fmt_cursor[0] == 'u' ||
                    proc->fmt_cursor[0] == 'x' || proc->fmt_cursor[0] == 'X')) {
            proc->length_mod = 9u;
        }
    } else if (ch == (uint8_t)'L') {
        proc->length_mod = 8u;
    } else if (ch == (uint8_t)'T') {
        proc->length_mod = 13u;
    } else if (ch == (uint8_t)'h') {
        if (proc->fmt_cursor && proc->fmt_cursor[0] == 'h') {
            proc->fmt_cursor += 1;
            proc->length_mod = 1u;
        } else {
            proc->length_mod = 2u;
        }
    } else if (ch == (uint8_t)'l') {
        if (proc->fmt_cursor && proc->fmt_cursor[0] == 'l') {
            proc->fmt_cursor += 1;
            proc->length_mod = 4u;
        } else {
            proc->length_mod = 3u;
        }
    } else if (ch == (uint8_t)'t') {
        proc->length_mod = 7u;
    } else if (ch == (uint8_t)'w') {
        proc->length_mod = 12u;
    } else if (ch == (uint8_t)'z') {
        proc->length_mod = 6u;
    }
    l63_sync_proc_guest(proc);
    return 1u;
}

/* `0x11689ef1` */
uint8_t rome2_startup_nprintf_state_normal_tchar_11689ef1(
    rome2_startup_nprintf_processor *proc) {
    uint8_t is_lead = 0u;
    if (!proc || !proc->target) {
        return 0u;
    }
    proc->is_wide = 0u;
    if (proc->lead_table != NULL) {
        is_lead = (proc->lead_table[proc->current_ch] != 0u) ? 1u : 0u;
    }
    if (is_lead != 0u) {
        (void)rome2_startup_nprintf_write_char_1168b92d(
            proc->target,
            (char)proc->current_ch,
            &proc->characters_written);
        if (!proc->fmt_cursor || proc->fmt_cursor[0] == '\0') {
            proc->last_errno = ROME2_L63_EINVAL;
            proc->invalid_param_count += 1u;
            l63_sync_proc_guest(proc);
            return 0u;
        }
        proc->current_ch = (uint8_t)(*proc->fmt_cursor++);
    }
    return 1u;
}

/* `0x11689e15` */
uint8_t rome2_startup_nprintf_state_normal_common_11689e15(
    rome2_startup_nprintf_processor *proc) {
    if (!proc || !proc->target) {
        return 0u;
    }
    if (rome2_startup_nprintf_state_normal_tchar_11689ef1(proc) == 0u) {
        return 0u;
    }
    (void)rome2_startup_nprintf_write_char_1168b92d(
        proc->target,
        (char)proc->current_ch,
        &proc->characters_written);
    l63_sync_proc_guest(proc);
    return 1u;
}

/* `0x11689d7e` */
uint8_t rome2_startup_nprintf_state_normal_11689d7e(
    rome2_startup_nprintf_processor *proc) {
    if (!proc) {
        return 0u;
    }
    if (rome2_startup_nprintf_state_normal_common_11689e15(proc) == 0u) {
        proc->last_errno = ROME2_L63_EINVAL;
        proc->invalid_param_count += 1u;
        l63_sync_proc_guest(proc);
        return 0u;
    }
    return 1u;
}

/* `0x11688b5a` */
void rome2_startup_nprintf_int32_into_buf_11688b5a(
    rome2_startup_nprintf_processor *proc,
    uint32_t val,
    uint32_t radix,
    uint8_t is_upper) {
    const char *digits = NULL;
    char tmp[64];
    int32_t n = 0;
    int32_t min_digits = 0;
    int32_t pos = 0;
    if (!proc || radix < 2u || radix > 36u) {
        return;
    }
    digits = is_upper ? "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "0123456789abcdefghijklmnopqrstuvwxyz";
    min_digits = proc->precision;
    while (min_digits > 0 || val != 0u) {
        tmp[n++] = digits[val % radix];
        val /= radix;
        if (min_digits > 0) {
            --min_digits;
        }
        if (n >= 63) {
            break;
        }
    }
    while (n > 0 && pos < (int32_t)(sizeof(proc->narrow_buf) - 1u)) {
        proc->narrow_buf[pos++] = tmp[--n];
    }
    proc->narrow_buf[pos] = '\0';
    proc->precision = 0;
    proc->narrow_ptr = proc->narrow_buf;
    proc->str_len = pos;
    l63_sync_proc_guest(proc);
}

/* `0x11688c54` */
void rome2_startup_nprintf_int64_into_buf_11688c54(
    rome2_startup_nprintf_processor *proc,
    uint64_t val,
    uint64_t radix,
    uint8_t is_upper) {
    const char *digits = NULL;
    char tmp[96];
    int32_t n = 0;
    int32_t min_digits = 0;
    int32_t pos = 0;
    if (!proc || radix < 2ULL || radix > 36ULL) {
        return;
    }
    digits = is_upper ? "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "0123456789abcdefghijklmnopqrstuvwxyz";
    min_digits = proc->precision;
    while (min_digits > 0 || val != 0ULL) {
        uint64_t rem = 0ULL;
        val = rome2_vfs_crt_aulldvrm(val, radix, &rem);
        tmp[n++] = digits[(size_t)rem];
        if (min_digits > 0) {
            --min_digits;
        }
        if (n >= 95) {
            break;
        }
    }
    while (n > 0 && pos < (int32_t)(sizeof(proc->narrow_buf) - 1u)) {
        proc->narrow_buf[pos++] = tmp[--n];
    }
    proc->narrow_buf[pos] = '\0';
    proc->precision = 0;
    proc->narrow_ptr = proc->narrow_buf;
    proc->str_len = pos;
    l63_sync_proc_guest(proc);
}

/* `0x1168b395` */
uint8_t rome2_startup_nprintf_type_integer_1168b395(
    rome2_startup_nprintf_processor *proc,
    uint32_t radix,
    uint8_t is_upper) {
    int32_t sz_cat = 0;
    uint64_t uval = 0ULL;
    uint8_t is_signed = 0u;
    if (!proc) {
        return 0u;
    }
    sz_cat = rome2_vfs_crt_to_integer_size(proc->length_mod);
    if (sz_cat != 1 && sz_cat != 2 && sz_cat != 4 && sz_cat != 8) {
        proc->last_errno = ROME2_L63_EINVAL;
        proc->invalid_param_count += 1u;
        l63_sync_proc_guest(proc);
        return 0u;
    }
    is_signed = ((proc->flags & 0x10u) != 0u) ? 1u : 0u;
    {
        uintptr_t raw = l63_next_arg(proc);
        if (sz_cat == 8) {
            uval = (uint64_t)raw;
        } else if (sz_cat == 4) {
            uval = is_signed ? (uint64_t)(int64_t)(int32_t)raw : (uint64_t)(uint32_t)raw;
        } else if (sz_cat == 2) {
            uval = is_signed ? (uint64_t)(int64_t)(int16_t)(raw & 0xffffu) : (uint64_t)(uint16_t)(raw & 0xffffu);
        } else {
            uval = is_signed ? (uint64_t)(int64_t)(int8_t)(raw & 0xffu) : (uint64_t)(uint8_t)(raw & 0xffu);
        }
    }
    if (is_signed && (int64_t)uval < 0) {
        uval = (uint64_t)(-(int64_t)(uval + 1ULL)) + 1ULL;
        proc->flags |= 0x40u;
    }
    if (proc->precision < 0) {
        proc->precision = 1;
    } else {
        proc->flags &= ~0x08u;
    }
    if (uval == 0ULL) {
        proc->flags &= ~0x20u;
    }
    proc->is_wide = 0u;
    if (sz_cat == 8) {
        rome2_startup_nprintf_int64_into_buf_11688c54(proc, uval, (uint64_t)radix, is_upper);
    } else {
        rome2_startup_nprintf_int32_into_buf_11688b5a(proc, (uint32_t)uval, radix, is_upper);
    }
    if ((proc->flags & ROME2_STARTUP_SYSINFO_FLAG_ALT) != 0u) {
        if (proc->str_len == 0 || proc->narrow_buf[0] != '0') {
            if ((size_t)proc->str_len + 1u < sizeof(proc->narrow_buf)) {
                memmove(proc->narrow_buf + 1, proc->narrow_buf, (size_t)proc->str_len + 1u);
                proc->narrow_buf[0] = '0';
                proc->str_len += 1;
            }
        }
    }
    l63_sync_proc_guest(proc);
    return 1u;
}

/* `0x1168b6af` */
uint8_t rome2_startup_nprintf_type_o_1168b6af(
    rome2_startup_nprintf_processor *proc) {
    if (!proc) {
        return 0u;
    }
    if ((proc->flags & ROME2_STARTUP_SYSINFO_FLAG_HASH) != 0u) {
        proc->flags |= ROME2_STARTUP_SYSINFO_FLAG_ALT;
    }
    return rome2_startup_nprintf_type_integer_1168b395(proc, 8u, 0u);
}

/* `0x1168b6ed` */
uint8_t rome2_startup_nprintf_type_p_1168b6ed(
    rome2_startup_nprintf_processor *proc) {
    if (!proc) {
        return 0u;
    }
    proc->precision = 8;
    proc->length_mod = 10u;
    return rome2_startup_nprintf_type_integer_1168b395(proc, 16u, 1u);
}

/* `0x1168af07` */
uint8_t rome2_startup_nprintf_type_Z_1168af07(
    rome2_startup_nprintf_processor *proc) {
    const rome2_startup_nprintf_unicode_view *uview = NULL;
    if (!proc) {
        return 0u;
    }
    uview = (const rome2_startup_nprintf_unicode_view *)(uintptr_t)l63_next_arg(proc);
    if (!uview || (uview->narrow_buf == NULL && uview->wide_buf == NULL && uview->guest8.buffer_04 == 0u)) {
        proc->narrow_ptr = "(null)";
        proc->wide_ptr = NULL;
        proc->str_len = 6;
        proc->is_wide = 0u;
    } else if (rome2_startup_nprintf_is_wide_specifier_11688abd(proc->options, proc->current_ch, (int32_t)proc->length_mod) != 0u) {
        proc->is_wide = 1u;
        proc->str_len = (int32_t)(uview->guest8.length_00 >> 1);
        proc->narrow_ptr = NULL;
        proc->wide_ptr = uview->wide_buf;
        if (!proc->wide_ptr) {
            proc->narrow_ptr = "(null)";
            proc->str_len = 6;
            proc->is_wide = 0u;
        }
    } else {
        proc->is_wide = 0u;
        proc->str_len = (int32_t)uview->guest8.length_00;
        proc->narrow_ptr = uview->narrow_buf;
        proc->wide_ptr = NULL;
        if (!proc->narrow_ptr) {
            proc->narrow_ptr = "(null)";
            proc->str_len = 6;
        }
    }
    l63_sync_proc_guest(proc);
    return 1u;
}

/* `0x1168b71d` */
uint8_t rome2_startup_nprintf_type_s_1168b71d(
    rome2_startup_nprintf_processor *proc) {
    uintptr_t raw = 0u;
    int32_t max_chars = 0;
    if (!proc) {
        return 0u;
    }
    raw = l63_next_arg(proc);
    max_chars = (proc->precision == -1) ? 0x7fffffff : proc->precision;
    if (rome2_startup_nprintf_is_wide_specifier_11688abd(proc->options, proc->current_ch, (int32_t)proc->length_mod) != 0u) {
        static const uint16_t k_null_w[] = { '(', 'n', 'u', 'l', 'l', ')', 0 };
        const uint16_t *ws = (const uint16_t *)raw;
        size_t len = 0u;
        if (!ws) {
            ws = k_null_w;
        }
        len = l63_u16_len(ws);
        if (len > (size_t)max_chars) {
            len = (size_t)max_chars;
        }
        proc->is_wide = 1u;
        proc->wide_ptr = ws;
        proc->narrow_ptr = NULL;
        proc->str_len = (int32_t)len;
    } else {
        const char *ns = (const char *)raw;
        if (!ns) {
            ns = "(null)";
        }
        proc->is_wide = 0u;
        proc->narrow_ptr = ns;
        proc->wide_ptr = NULL;
        proc->str_len = (int32_t)l63_bounded_strlen(ns, max_chars);
    }
    l63_sync_proc_guest(proc);
    return 1u;
}

/* `0x1168b26f` */
uint8_t rome2_startup_nprintf_type_c_tchar_1168b26f(
    rome2_startup_nprintf_processor *proc) {
    uintptr_t raw = 0u;
    if (!proc) {
        return 0u;
    }
    raw = l63_next_arg(proc);
    if (rome2_startup_nprintf_is_wide_specifier_11688abd(proc->options, proc->current_ch, (int32_t)proc->length_mod) != 0u) {
        uint16_t wch = (uint16_t)(raw & 0xffffu);
        int32_t out_len = 0;
        if (wch <= 0x7fu) {
            proc->narrow_buf[0] = (char)(uint8_t)wch;
            out_len = 1;
        } else {
            proc->suppress_output = 1u;
        }
        proc->str_len = out_len;
    } else {
        proc->narrow_buf[0] = (char)(uint8_t)(raw & 0xffu);
        proc->str_len = 1;
    }
    proc->narrow_buf[proc->str_len] = '\0';
    proc->is_wide = 0u;
    proc->narrow_ptr = proc->narrow_buf;
    proc->wide_ptr = NULL;
    l63_sync_proc_guest(proc);
    return 1u;
}

/* `0x1168afbb` */
uint8_t rome2_startup_nprintf_type_a_1168afbb(
    rome2_startup_nprintf_processor *proc) {
    uintptr_t raw = 0u;
    uint64_t bits = 0ULL;
    double val = 0.0;
    char scratch[128];
    int32_t prec = 0;
    int32_t ferr = 0;
    if (!proc) {
        return 0u;
    }
    proc->flags |= 0x10u;
    prec = proc->precision;
    if (prec < 0) {
        prec = ((proc->current_ch == (uint8_t)'a' || proc->current_ch == (uint8_t)'A') ? 13 : 6);
        proc->precision = prec;
    } else if (prec == 0 && (proc->current_ch == (uint8_t)'g' || proc->current_ch == (uint8_t)'G')) {
        prec = 1;
        proc->precision = 1;
    }
    raw = l63_next_arg(proc);
    bits = (uint64_t)raw;
    memcpy(&val, &bits, sizeof(double));
    memset(proc->narrow_buf, 0, sizeof(proc->narrow_buf));
    memset(scratch, 0, sizeof(scratch));
    (void)rome2_vfs_crt_acrt_fp_format(
        &val,
        proc->narrow_buf,
        sizeof(proc->narrow_buf),
        scratch,
        sizeof(scratch),
        (int32_t)proc->current_ch,
        prec,
        proc->options,
        &ferr);
    if (proc->narrow_buf[0] == '-') {
        proc->flags |= 0x40u;
        memmove(proc->narrow_buf, proc->narrow_buf + 1, strlen(proc->narrow_buf));
    }
    if ((proc->flags & ROME2_STARTUP_SYSINFO_FLAG_HASH) != 0u && proc->precision == 0) {
        rome2_vfs_crt_force_decimal_point(proc->narrow_buf, sizeof(proc->narrow_buf), '.');
    } else if ((proc->current_ch == (uint8_t)'g' || proc->current_ch == (uint8_t)'G') &&
               (proc->flags & ROME2_STARTUP_SYSINFO_FLAG_HASH) == 0u) {
        rome2_vfs_crt_crop_zeroes(proc->narrow_buf, sizeof(proc->narrow_buf), '.');
    }
    proc->is_wide = 0u;
    proc->narrow_ptr = proc->narrow_buf;
    proc->wide_ptr = NULL;
    proc->str_len = (int32_t)strlen(proc->narrow_buf);
    l63_sync_proc_guest(proc);
    return 1u;
}

/* `0x1168a760` */
uint8_t rome2_startup_nprintf_state_type_1168a760(
    rome2_startup_nprintf_processor *proc) {
    uint8_t ch = 0u;
    uint8_t ok = 1u;
    char prefix[4];
    int32_t prefix_len = 0;
    int32_t pad_len = 0;
    if (!proc || !proc->target) {
        return 0u;
    }
    ch = proc->current_ch;
    proc->suppress_output = 0u;
    proc->narrow_ptr = NULL;
    proc->wide_ptr = NULL;
    proc->str_len = 0;

    if (ch == (uint8_t)'d' || ch == (uint8_t)'i') {
        proc->flags |= 0x10u;
        ok = rome2_startup_nprintf_type_integer_1168b395(proc, 10u, 0u);
    } else if (ch == (uint8_t)'u') {
        ok = rome2_startup_nprintf_type_integer_1168b395(proc, 10u, 0u);
    } else if (ch == (uint8_t)'x' || ch == (uint8_t)'X') {
        ok = rome2_startup_nprintf_type_integer_1168b395(proc, 16u, (ch == (uint8_t)'X') ? 1u : 0u);
    } else if (ch == (uint8_t)'o') {
        ok = rome2_startup_nprintf_type_o_1168b6af(proc);
    } else if (ch == (uint8_t)'p') {
        ok = rome2_startup_nprintf_type_p_1168b6ed(proc);
    } else if (ch == (uint8_t)'s' || ch == (uint8_t)'S') {
        ok = rome2_startup_nprintf_type_s_1168b71d(proc);
    } else if (ch == (uint8_t)'Z') {
        ok = rome2_startup_nprintf_type_Z_1168af07(proc);
    } else if (ch == (uint8_t)'c' || ch == (uint8_t)'C') {
        ok = rome2_startup_nprintf_type_c_tchar_1168b26f(proc);
    } else if (ch == (uint8_t)'a' || ch == (uint8_t)'A' ||
               ch == (uint8_t)'e' || ch == (uint8_t)'E' ||
               ch == (uint8_t)'f' || ch == (uint8_t)'F' ||
               ch == (uint8_t)'g' || ch == (uint8_t)'G') {
        ok = rome2_startup_nprintf_type_a_1168afbb(proc);
    } else if (ch == (uint8_t)'n') {
        void *n_ptr = (void *)l63_next_arg(proc);
        proc->suppress_output = 1u;
        if (!n_ptr || (proc->options & ROME2_STARTUP_WPRINTF_OPT_DISABLE_FN) == 0ULL) {
            proc->last_errno = ROME2_L63_EINVAL;
            proc->invalid_param_count += 1u;
            ok = 0u;
        } else {
            int32_t sz_n = (int32_t)rome2_vfs_crt_to_integer_size(proc->length_mod);
            if (sz_n == 1) {
                *(int8_t *)n_ptr = (int8_t)proc->characters_written;
            } else if (sz_n == 2) {
                *(int16_t *)n_ptr = (int16_t)proc->characters_written;
            } else if (sz_n == 8) {
                *(int64_t *)n_ptr = (int64_t)proc->characters_written;
            } else {
                *(int32_t *)n_ptr = proc->characters_written;
            }
            ok = 1u;
        }
    } else {
        ok = 0u;
    }

    if (!ok || proc->suppress_output != 0u) {
        return ok;
    }
    if ((proc->flags & 0x10u) != 0u) {
        if ((proc->flags & 0x40u) != 0u) {
            prefix[prefix_len++] = '-';
        } else if ((proc->flags & 0x01u) != 0u) {
            prefix[prefix_len++] = '+';
        } else if ((proc->flags & 0x02u) != 0u) {
            prefix[prefix_len++] = ' ';
        }
    }
    if ((ch == (uint8_t)'x' || ch == (uint8_t)'X') && (proc->flags & 0x20u) != 0u) {
        prefix[prefix_len++] = '0';
        prefix[prefix_len++] = (char)ch;
    }
    pad_len = proc->field_width - proc->str_len - prefix_len;
    if ((proc->flags & 0x0Cu) == 0u && pad_len > 0) {
        rome2_startup_nprintf_write_multi_chars_11688dff(
            proc->target, ' ', pad_len, &proc->characters_written);
    }
    if (prefix_len > 0) {
        rome2_startup_nprintf_write_string_1168bcef(
            proc->target, prefix, prefix_len, &proc->characters_written);
    }
    if ((proc->flags & 0x08u) != 0u && (proc->flags & 0x04u) == 0u && pad_len > 0) {
        rome2_startup_nprintf_write_multi_chars_11688dff(
            proc->target, '0', pad_len, &proc->characters_written);
    }
    (void)rome2_startup_nprintf_write_stored_tchar_1168baca(proc);
    if (proc->characters_written >= 0 && (proc->flags & 0x04u) != 0u && pad_len > 0) {
        rome2_startup_nprintf_write_multi_chars_11688dff(
            proc->target, ' ', pad_len, &proc->characters_written);
    }
    l63_sync_proc_guest(proc);
    return 1u;
}

/* `0x11689871` */
int32_t rome2_startup_nprintf_process_11689871(
    rome2_startup_nprintf_processor *proc) {
    if (!proc || !proc->target) {
        return -1;
    }
    if (!proc->fmt_cursor) {
        proc->last_errno = ROME2_L63_EINVAL;
        proc->invalid_param_count += 1u;
        return -1;
    }
    for (;;) {
        proc->passes += 1;
        if (proc->passes == 2) {
            return proc->characters_written;
        }
        proc->str_len = 0;
        proc->state = 0;
        while (*proc->fmt_cursor != '\0') {
            uint8_t step_ok = 1u;
            proc->current_ch = (uint8_t)(*proc->fmt_cursor++);
            if (proc->characters_written < 0) {
                break;
            }
            proc->state = (int32_t)rome2_startup_nprintf_find_next_state_11689311(
                proc->current_ch, (uint32_t)proc->state);
            if (proc->state == 8) {
                return -1;
            }
            switch (proc->state) {
            case 0:
                step_ok = rome2_startup_nprintf_state_normal_11689d7e(proc);
                break;
            case 1:
                proc->precision = -1;
                proc->field_width = 0;
                proc->suppress_output = 0u;
                proc->flags = 0u;
                proc->length_mod = 0u;
                proc->is_wide = 0u;
                break;
            case 2:
                step_ok = rome2_startup_nprintf_state_flag_11689ce5(proc);
                break;
            case 3:
                step_ok = rome2_startup_nprintf_state_width_1168ae5c(proc);
                break;
            case 4:
                proc->precision = 0;
                break;
            case 5:
                step_ok = rome2_startup_nprintf_state_precision_11689f55(proc);
                break;
            case 6:
                step_ok = rome2_startup_nprintf_state_size_1168a0f0(proc);
                break;
            case 7:
                step_ok = rome2_startup_nprintf_state_type_1168a760(proc);
                proc->state = 0;
                break;
            default:
                return -1;
            }
            if (!step_ok) {
                return -1;
            }
        }
        proc->fmt_cursor += 1;
    }
}

/* `0x1168859a` */
int32_t rome2_startup_crt_common_vsprintf_char_1168859a(
    uint64_t options,
    char *buf,
    uint32_t max_chars,
    const char *fmt,
    uint8_t has_locale,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno) {
    rome2_startup_nprintf_target target;
    rome2_startup_nprintf_processor proc;
    int32_t res = 0;

    if (!fmt || (buf == NULL && max_chars != 0u)) {
        if (out_errno) {
            *out_errno = ROME2_L63_EINVAL;
        }
        return -1;
    }
    if (buf != NULL && max_chars == 0u && (options & ROME2_STARTUP_WPRINTF_OPT_STANDARD_SNPRINTF) == 0ULL) {
        if (out_errno) {
            *out_errno = ROME2_L63_EINVAL;
        }
        return -1;
    }
    memset(&target, 0, sizeof(target));
    target.buf = buf;
    if (max_chars == 0u) {
        target.max_chars = 0u;
    } else if (max_chars == 0xffffffffu) {
        target.max_chars = 0xffffffffu;
    } else {
        target.max_chars = max_chars - 1u;
    }
    target.continue_on_truncation =
        ((options & ROME2_STARTUP_WPRINTF_OPT_STANDARD_SNPRINTF) != 0ULL) ? 1u : 0u;
    l63_sync_target_guest(&target);

    rome2_startup_nprintf_adapter_data_init_11688eeb(
        &proc, &target, options, fmt, has_locale, args, arg_count);
    res = rome2_startup_nprintf_process_11689871(&proc);
    if (out_errno && proc.last_errno != 0) {
        *out_errno = proc.last_errno;
    }

    if ((options & ROME2_STARTUP_WPRINTF_OPT_STANDARD_SNPRINTF) != 0ULL) {
        if (max_chars == 0u && buf == NULL) {
            return res;
        }
        if (buf != NULL && max_chars > 0u) {
            if (res >= 0 && target.written_chars < max_chars) {
                buf[target.written_chars] = '\0';
            } else {
                buf[max_chars - 1u] = '\0';
            }
        }
        return res;
    }

    if ((options & ROME2_STARTUP_WPRINTF_OPT_LEGACY_NULL_TERM) != 0ULL) {
        if (buf != NULL && max_chars > 0u) {
            if (res < 0) {
                buf[0] = '\0';
            } else if (target.written_chars < max_chars) {
                buf[target.written_chars] = '\0';
            } else {
                buf[max_chars - 1u] = '\0';
            }
        }
        return res;
    }

    if (max_chars == 0u) {
        return -1;
    }
    if (buf != NULL) {
        if (proc.invalid_param_count > 0u) {
            buf[0] = '\0';
            return -1;
        }
        if (res < 0 || res >= (int32_t)max_chars) {
            if (target.written_chars == target.max_chars) {
                buf[max_chars - 1u] = '\0';
                return -2;
            }
            buf[0] = '\0';
            return -1;
        }
        buf[target.written_chars] = '\0';
    }
    return res;
}

/* `0x1168c0d8` */
int32_t rome2_startup_stdio_common_vsprintf_1168c0d8(
    uint64_t options,
    char *buf,
    uint32_t max_chars,
    const char *fmt,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno) {
    return rome2_startup_crt_common_vsprintf_char_1168859a(
        options, buf, max_chars, fmt, 0u, args, arg_count, out_errno);
}

/* `0x10126cd0` */
int32_t rome2_startup_crt_sprintf_10126cd0(
    char *buf,
    const char *fmt,
    const uintptr_t *args,
    size_t arg_count) {
    int32_t err = 0;
    int32_t res = rome2_startup_stdio_common_vsprintf_1168c0d8(
        ROME2_STARTUP_WPRINTF_OPT_STANDARD_SNPRINTF,
        buf,
        0xffffffffu,
        fmt,
        args,
        arg_count,
        &err);
    return (res < 0) ? -1 : res;
}

/* `0x112f6190` */
void rome2_startup_os_build_system_info_string_112f6190(
    rome2_startup_sysinfo_env *env) {
    uint64_t phys_bytes = 0ULL;
    uint64_t page_bytes = 0ULL;
    uint64_t vrt_bytes = 0ULL;
    uintptr_t mem_args[3];
    size_t last_slash = 0u;
    uint8_t has_slash = 0u;
    size_t i = 0u;

    if (!env) {
        return;
    }
    env->mem_status.dw_length_00 = 0x40u;
    phys_bytes = ((uint64_t)env->mem_status.total_phys_hi_0c << 32) | (uint64_t)env->mem_status.total_phys_lo_08;
    page_bytes = ((uint64_t)env->mem_status.total_page_file_hi_1c << 32) | (uint64_t)env->mem_status.total_page_file_lo_18;
    vrt_bytes = ((uint64_t)env->mem_status.total_virtual_hi_2c << 32) | (uint64_t)env->mem_status.total_virtual_lo_28;

    mem_args[0] = (uintptr_t)(uint32_t)(phys_bytes >> 20);
    mem_args[1] = (uintptr_t)(uint32_t)(page_bytes >> 20);
    mem_args[2] = (uintptr_t)(uint32_t)(vrt_bytes >> 20);
    (void)rome2_startup_crt_sprintf_10126cd0(
        env->global_mem_info_12033e68,
        "Total Phys Mem %u MB, Total Page File %u MB, Total Vrt Mem %u MB",
        mem_args,
        3u);

    l63_safe_copy_cstr(
        env->global_exe_data_12034268,
        sizeof(env->global_exe_data_12034268),
        env->module_file_name_a);

    if (env->global_exe_data_12034268[0] != '\0') {
        for (i = 0u; i + 1u < sizeof(env->global_exe_data_12034268) && env->global_exe_data_12034268[i] != '\0'; ++i) {
            if (env->global_exe_data_12034268[i] == '\\') {
                last_slash = i;
                has_slash = 1u;
            }
        }
    }

    if (has_slash != 0u) {
        char search_pat[ROME2_STARTUP_SYSINFO_PATH_CAP];
        char suffix_buf[64];
        size_t cur_len = 0u;
        size_t suf_len = 0u;
        size_t j = 0u;

        l63_safe_copy_cstr(search_pat, sizeof(search_pat), env->global_exe_data_12034268);
        if (last_slash + 8u < sizeof(search_pat)) {
            search_pat[last_slash + 1u] = '\0';
            memcpy(search_pat + last_slash + 1u, "data\\*", 7u);
        }
        l63_safe_copy_cstr(env->last_search_pattern, sizeof(env->last_search_pattern), search_pat);

        cur_len = strlen(env->global_exe_data_12034268);
        if (env->find_first_succeeds != 0u) {
            int32_t dir_count = 0;
            uint32_t limit = (env->data_entry_count <= ROME2_STARTUP_SYSINFO_MAX_ENTRIES)
                ? env->data_entry_count
                : ROME2_STARTUP_SYSINFO_MAX_ENTRIES;
            for (j = 0u; j < limit; ++j) {
                const rome2_startup_sysinfo_find_entry *ent = &env->data_entries[j];
                if (strcmp(ent->file_name, ".") != 0 &&
                    strcmp(ent->file_name, "..") != 0 &&
                    (ent->file_attributes & 0x10u) != 0u) {
                    ++dir_count;
                }
            }
            env->find_close_calls += 1u;
            env->counted_data_dirs = dir_count;
            {
                uintptr_t d_args[1];
                d_args[0] = (uintptr_t)(uint32_t)dir_count;
                (void)rome2_startup_crt_sprintf_10126cd0(suffix_buf, ", data dirs: %d", d_args, 1u);
            }
        } else {
            env->counted_data_dirs = 0;
            l63_safe_copy_cstr(suffix_buf, sizeof(suffix_buf), ", data dir not found");
        }
        suf_len = strlen(suffix_buf);
        if (cur_len + suf_len < sizeof(env->global_exe_data_12034268)) {
            memcpy(env->global_exe_data_12034268 + cur_len, suffix_buf, suf_len + 1u);
        }
    }

    if (env->get_locale_info_succeeds != 0u) {
        l63_safe_copy_cstr(
            env->global_locale_12034b88,
            sizeof(env->global_locale_12034b88),
            env->locale_lang_in);
    } else {
        env->global_locale_12034b88[0] = '\0';
    }
}

#include "startup_app_ctor_timing_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void l60_copy_u16_bounded(uint16_t *dst, size_t dst_cap, const uint16_t *src) {
    size_t i = 0u;
    if (!dst || dst_cap == 0u) {
        return;
    }
    if (!src) {
        dst[0] = 0u;
        return;
    }
    while (i + 1u < dst_cap && src[i] != 0u) {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = 0u;
}

static size_t l60_u16_len(const uint16_t *s) {
    size_t n = 0u;
    if (!s) {
        return 0u;
    }
    while (s[n] != 0u) {
        ++n;
    }
    return n;
}

static void l60_ascii_to_u16(const char *src, uint16_t *dst, size_t dst_cap) {
    size_t i = 0u;
    if (!dst || dst_cap == 0u) {
        return;
    }
    if (!src) {
        dst[0] = 0u;
        return;
    }
    while (i + 1u < dst_cap && src[i] != '\0') {
        dst[i] = (uint16_t)(uint8_t)src[i];
        ++i;
    }
    dst[i] = 0u;
}

static void l60_u16_to_ascii(const uint16_t *src, char *dst, size_t dst_cap) {
    size_t i = 0u;
    if (!dst || dst_cap == 0u) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }
    while (i + 1u < dst_cap && src[i] != 0u) {
        uint16_t ch = src[i];
        dst[i] = (ch <= 0x7fu) ? (char)ch : '?';
        ++i;
    }
    dst[i] = '\0';
}

static void l60_sync_adapter_guest(rome2_startup_wprintf_target *target) {
    if (!target) {
        return;
    }
    target->guest16.buffer_cursor_00 = (target->buf != NULL) ? (uint32_t)(target->written_chars * 2u) : 0u;
    target->guest16.max_chars_04 = target->max_chars;
    target->guest16.written_chars_08 = target->written_chars;
    target->guest16.continue_on_truncation_0c = target->continue_on_truncation;
}

uint8_t rome2_startup_wprintf_write_char_1168b96f(
    rome2_startup_wprintf_target *target,
    uint16_t ch,
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
        l60_sync_adapter_guest(target);
        return target->continue_on_truncation;
    }
    if (target->buf && target->written_chars < target->max_chars) {
        target->buf[target->written_chars] = ch;
    }
    target->written_chars += 1u;
    *written_inout += 1;
    l60_sync_adapter_guest(target);
    return 1u;
}

void rome2_startup_wprintf_write_string_1168bd56(
    rome2_startup_wprintf_target *target,
    const uint16_t *s,
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
            l60_sync_adapter_guest(target);
            return;
        }
    } else {
        rem = (target->written_chars < target->max_chars) ? (target->max_chars - target->written_chars) : 0u;
        copy_len = ((uint32_t)len <= rem) ? (uint32_t)len : rem;
        if (target->buf && s && copy_len > 0u) {
            memcpy(target->buf + target->written_chars, s, (size_t)copy_len * sizeof(uint16_t));
        }
        target->written_chars += copy_len;
        l60_sync_adapter_guest(target);
        if (target->continue_on_truncation == 0u) {
            if (copy_len == (uint32_t)len) {
                *written_inout += (int32_t)copy_len;
            } else {
                *written_inout = -1;
            }
            return;
        }
    }
    *written_inout += len;
}

void rome2_startup_wprintf_write_multi_chars_11688e2b(
    rome2_startup_wprintf_target *target,
    char ch,
    int32_t count,
    int32_t *written_inout) {
    int32_t i = 0;
    if (!target || !written_inout) {
        return;
    }
    for (i = 0; i < count; ++i) {
        (void)rome2_startup_wprintf_write_char_1168b96f(target, (uint16_t)(uint8_t)ch, written_inout);
        if (*written_inout == -1) {
            return;
        }
    }
}

uint8_t rome2_startup_wprintf_write_stored_tchar_1168bc04(
    rome2_startup_wprintf_processor *proc,
    uint16_t unused_ch) {
    (void)unused_ch;
    if (!proc || !proc->target) {
        return 0u;
    }
    if (proc->is_wide == 0u && proc->str_len > 0 && proc->narrow_ptr != NULL) {
        int32_t i = 0;
        const char *p = proc->narrow_ptr;
        while (i < proc->str_len && *p != '\0') {
            uint8_t byte_val = (uint8_t)*p;
            uint16_t wch = 0u;
            if (byte_val < 0x80u) {
                wch = (uint16_t)byte_val;
                ++p;
            } else {
                /* Multi-byte UTF-8 sequence decode fallback or invalid marker */
                if ((byte_val & 0xE0u) == 0xC0u && p[1] != '\0') {
                    wch = (uint16_t)(((uint32_t)(byte_val & 0x1Fu) << 6) | ((uint8_t)p[1] & 0x3Fu));
                    p += 2;
                } else {
                    proc->characters_written = -1;
                    return 1u;
                }
            }
            (void)rome2_startup_wprintf_write_char_1168b96f(proc->target, wch, &proc->characters_written);
            ++i;
        }
    } else if (proc->wide_ptr != NULL && proc->str_len > 0) {
        rome2_startup_wprintf_write_string_1168bd56(
            proc->target,
            proc->wide_ptr,
            proc->str_len,
            &proc->characters_written);
    }
    return 1u;
}

uint8_t rome2_startup_wprintf_state_normal_common_11689e69(
    rome2_startup_wprintf_processor *proc) {
    if (!proc || !proc->target) {
        return 0u;
    }
    proc->is_wide = 1u;
    (void)rome2_startup_wprintf_write_char_1168b96f(
        proc->target,
        proc->current_ch,
        &proc->characters_written);
    return 1u;
}

uint8_t rome2_startup_wprintf_state_normal_11689dbc(
    rome2_startup_wprintf_processor *proc) {
    if (!proc) {
        return 0u;
    }
    if (rome2_startup_wprintf_state_normal_common_11689e69(proc) == 0u) {
        proc->last_errno = 22;
        proc->invalid_param_count += 1u;
        return 0u;
    }
    return 1u;
}

uint8_t rome2_startup_wprintf_state_size_1168a3b6(
    rome2_startup_wprintf_processor *proc) {
    uint16_t ch = 0u;
    if (!proc) {
        return 0u;
    }
    ch = proc->current_ch;
    if (ch == (uint16_t)'F') {
        if ((proc->options & ROME2_STARTUP_WPRINTF_OPT_DISABLE_FN) == 0ULL) {
            proc->state = 7;
            return rome2_startup_wprintf_state_type_1168abf7(proc);
        }
        return 1u;
    }
    if (ch == (uint16_t)'N') {
        if ((proc->options & ROME2_STARTUP_WPRINTF_OPT_DISABLE_FN) == 0ULL) {
            proc->state = 8;
            proc->last_errno = 22;
            proc->invalid_param_count += 1u;
            return 0u;
        }
        return 1u;
    }
    if (proc->length_mod != 0u) {
        proc->last_errno = 22;
        proc->invalid_param_count += 1u;
        return 0u;
    }
    if (ch == (uint16_t)'j') {
        proc->length_mod = 5u;
    } else if (ch == (uint16_t)'I') {
        if (proc->fmt_cursor && proc->fmt_cursor[0] == (uint16_t)'3' && proc->fmt_cursor[1] == (uint16_t)'2') {
            proc->length_mod = 10u;
            proc->fmt_cursor += 2;
        } else if (proc->fmt_cursor && proc->fmt_cursor[0] == (uint16_t)'6' && proc->fmt_cursor[1] == (uint16_t)'4') {
            proc->length_mod = 11u;
            proc->fmt_cursor += 2;
        } else if (proc->fmt_cursor &&
                   (proc->fmt_cursor[0] == (uint16_t)'d' || proc->fmt_cursor[0] == (uint16_t)'i' ||
                    proc->fmt_cursor[0] == (uint16_t)'o' || proc->fmt_cursor[0] == (uint16_t)'u' ||
                    proc->fmt_cursor[0] == (uint16_t)'x' || proc->fmt_cursor[0] == (uint16_t)'X')) {
            proc->length_mod = 9u;
        }
    } else if (ch == (uint16_t)'L') {
        proc->length_mod = 8u;
    } else if (ch == (uint16_t)'T') {
        proc->length_mod = 13u;
    } else if (ch == (uint16_t)'h') {
        if (proc->fmt_cursor && proc->fmt_cursor[0] == (uint16_t)'h') {
            proc->fmt_cursor += 1;
            proc->length_mod = 1u;
        } else {
            proc->length_mod = 2u;
        }
    } else if (ch == (uint16_t)'l') {
        if (proc->fmt_cursor && proc->fmt_cursor[0] == (uint16_t)'l') {
            proc->fmt_cursor += 1;
            proc->length_mod = 4u;
        } else {
            proc->length_mod = 3u;
        }
    } else if (ch == (uint16_t)'t') {
        proc->length_mod = 7u;
    } else if (ch == (uint16_t)'w') {
        proc->length_mod = 12u;
    } else if (ch == (uint16_t)'z') {
        proc->length_mod = 6u;
    }
    return 1u;
}

static uintptr_t l60_next_arg(rome2_startup_wprintf_processor *proc) {
    if (!proc || !proc->args || proc->arg_idx >= proc->arg_count) {
        return 0u;
    }
    return proc->args[proc->arg_idx++];
}

static void l60_format_u64_digits(
    uint64_t val,
    uint32_t base,
    uint8_t upper,
    int32_t precision,
    uint16_t *out_u16,
    int32_t *out_len) {
    char tmp[32];
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    int32_t n = 0;
    int32_t pad_zeros = 0;
    int32_t pos = 0;
    if (val == 0ULL && precision == 0) {
        *out_len = 0;
        out_u16[0] = 0u;
        return;
    }
    do {
        tmp[n++] = digits[val % base];
        val /= base;
    } while (val != 0ULL && n < 31);
    if (precision > n) {
        pad_zeros = precision - n;
        if (pad_zeros + n > 90) {
            pad_zeros = 90 - n;
        }
    }
    while (pad_zeros > 0 && pos < 95) {
        out_u16[pos++] = (uint16_t)'0';
        --pad_zeros;
    }
    while (n > 0 && pos < 95) {
        out_u16[pos++] = (uint16_t)(uint8_t)tmp[--n];
    }
    out_u16[pos] = 0u;
    *out_len = pos;
}

uint8_t rome2_startup_wprintf_state_type_1168abf7(
    rome2_startup_wprintf_processor *proc) {
    uint16_t ch = 0u;
    uint16_t prefix[4];
    int32_t prefix_len = 0;
    int32_t pad_len = 0;
    uint8_t ok = 1u;
    if (!proc || !proc->target) {
        return 0u;
    }
    ch = proc->current_ch;
    proc->suppress_output = 0u;
    proc->narrow_ptr = NULL;
    proc->wide_ptr = NULL;
    proc->str_len = 0;

    if (ch == (uint16_t)'s' || ch == (uint16_t)'S') {
        uintptr_t raw = l60_next_arg(proc);
        uint8_t want_wide = 1u;
        if (proc->length_mod == 2u || proc->length_mod == 1u) {
            want_wide = 0u;
        } else if (proc->length_mod == 3u || proc->length_mod == 12u) {
            want_wide = 1u;
        } else if (ch == (uint16_t)'S') {
            want_wide = 0u;
        }
        if (want_wide) {
            const uint16_t *ws = (const uint16_t *)raw;
            static const uint16_t k_null_w[] = { '(','n','u','l','l',')',0 };
            size_t len = 0u;
            if (!ws) {
                ws = k_null_w;
            }
            len = l60_u16_len(ws);
            if (proc->precision >= 0 && (size_t)proc->precision < len) {
                len = (size_t)proc->precision;
            }
            proc->is_wide = 1u;
            proc->wide_ptr = ws;
            proc->str_len = (int32_t)len;
        } else {
            const char *ns = (const char *)raw;
            size_t len = 0u;
            if (!ns) {
                ns = "(null)";
            }
            len = strlen(ns);
            if (proc->precision >= 0 && (size_t)proc->precision < len) {
                len = (size_t)proc->precision;
            }
            proc->is_wide = 0u;
            proc->narrow_ptr = ns;
            proc->str_len = (int32_t)len;
        }
    } else if (ch == (uint16_t)'c' || ch == (uint16_t)'C') {
        uintptr_t raw = l60_next_arg(proc);
        uint8_t want_wide = (ch == (uint16_t)'c') ? 1u : 0u;
        if (proc->length_mod == 2u) {
            want_wide = 0u;
        } else if (proc->length_mod == 3u || proc->length_mod == 12u) {
            want_wide = 1u;
        }
        if (want_wide) {
            proc->wide_buf[0] = (uint16_t)(raw & 0xFFFFu);
            proc->wide_buf[1] = 0u;
            proc->is_wide = 1u;
            proc->wide_ptr = proc->wide_buf;
            proc->str_len = 1;
        } else {
            proc->narrow_buf[0] = (char)(raw & 0xFFu);
            proc->narrow_buf[1] = '\0';
            proc->is_wide = 0u;
            proc->narrow_ptr = proc->narrow_buf;
            proc->str_len = 1;
        }
    } else if (ch == (uint16_t)'d' || ch == (uint16_t)'i') {
        uintptr_t raw = l60_next_arg(proc);
        int64_t sval = (proc->length_mod == 4u || proc->length_mod == 11u) ? (int64_t)raw : (int64_t)(int32_t)raw;
        uint64_t mag = 0ULL;
        proc->flags |= 0x10u;
        if (sval < 0) {
            proc->flags |= 0x40u;
            mag = (uint64_t)(-(sval + 1)) + 1ULL;
        } else {
            mag = (uint64_t)sval;
        }
        proc->is_wide = 1u;
        l60_format_u64_digits(mag, 10u, 0u, proc->precision, proc->wide_buf, &proc->str_len);
        proc->wide_ptr = proc->wide_buf;
    } else if (ch == (uint16_t)'u' || ch == (uint16_t)'o' || ch == (uint16_t)'x' || ch == (uint16_t)'X') {
        uintptr_t raw = l60_next_arg(proc);
        uint64_t uval = (proc->length_mod == 4u || proc->length_mod == 11u) ? (uint64_t)raw : (uint64_t)(uint32_t)raw;
        uint32_t base = (ch == (uint16_t)'o') ? 8u : ((ch == (uint16_t)'u') ? 10u : 16u);
        uint8_t upper = (ch == (uint16_t)'X') ? 1u : 0u;
        proc->is_wide = 1u;
        l60_format_u64_digits(uval, base, upper, proc->precision, proc->wide_buf, &proc->str_len);
        proc->wide_ptr = proc->wide_buf;
    } else if (ch == (uint16_t)'p') {
        uintptr_t raw = l60_next_arg(proc);
        proc->is_wide = 1u;
        l60_format_u64_digits((uint64_t)(uint32_t)raw, 16u, 1u, 8, proc->wide_buf, &proc->str_len);
        proc->wide_ptr = proc->wide_buf;
    } else {
        ok = 0u;
    }

    if (!ok || proc->suppress_output != 0u) {
        return ok;
    }

    if ((proc->flags & 0x10u) != 0u) {
        if ((proc->flags & 0x40u) != 0u) {
            prefix[prefix_len++] = (uint16_t)'-';
        } else if ((proc->flags & 0x01u) != 0u) {
            prefix[prefix_len++] = (uint16_t)'+';
        } else if ((proc->flags & 0x02u) != 0u) {
            prefix[prefix_len++] = (uint16_t)' ';
        }
    }
    if ((ch == (uint16_t)'x' || ch == (uint16_t)'X') && (proc->flags & 0x20u) != 0u) {
        prefix[prefix_len++] = (uint16_t)'0';
        prefix[prefix_len++] = ch;
    }
    pad_len = proc->field_width - proc->str_len - prefix_len;
    if ((proc->flags & 0x0Cu) == 0u && pad_len > 0) {
        rome2_startup_wprintf_write_multi_chars_11688e2b(proc->target, ' ', pad_len, &proc->characters_written);
    }
    if (prefix_len > 0) {
        rome2_startup_wprintf_write_string_1168bd56(proc->target, prefix, prefix_len, &proc->characters_written);
    }
    if ((proc->flags & 0x08u) != 0u && (proc->flags & 0x04u) == 0u && pad_len > 0) {
        rome2_startup_wprintf_write_multi_chars_11688e2b(proc->target, '0', pad_len, &proc->characters_written);
    }
    (void)rome2_startup_wprintf_write_stored_tchar_1168bc04(proc, 0u);
    if (proc->characters_written >= 0 && (proc->flags & 0x04u) != 0u && pad_len > 0) {
        rome2_startup_wprintf_write_multi_chars_11688e2b(proc->target, ' ', pad_len, &proc->characters_written);
    }
    return 1u;
}

static int32_t l60_find_next_state(uint16_t ch, int32_t cur_state) {
    if (cur_state == 0) {
        return (ch == (uint16_t)'%') ? 1 : 0;
    }
    if (cur_state == 1 && ch == (uint16_t)'%') {
        return 0;
    }
    if (cur_state <= 2 && (ch == (uint16_t)'+' || ch == (uint16_t)'-' || ch == (uint16_t)' ' ||
                          ch == (uint16_t)'#' || ch == (uint16_t)'0')) {
        return 2;
    }
    if (cur_state <= 3 && ((ch >= (uint16_t)'0' && ch <= (uint16_t)'9') || ch == (uint16_t)'*')) {
        return 3;
    }
    if (cur_state <= 4 && ch == (uint16_t)'.') {
        return 4;
    }
    if ((cur_state == 4 || cur_state == 5) &&
        ((ch >= (uint16_t)'0' && ch <= (uint16_t)'9') || ch == (uint16_t)'*')) {
        return 5;
    }
    if (cur_state <= 6 &&
        (ch == (uint16_t)'h' || ch == (uint16_t)'l' || ch == (uint16_t)'L' || ch == (uint16_t)'j' ||
         ch == (uint16_t)'z' || ch == (uint16_t)'t' || ch == (uint16_t)'w' || ch == (uint16_t)'I' ||
         ch == (uint16_t)'F' || ch == (uint16_t)'N' || ch == (uint16_t)'T')) {
        return 6;
    }
    return 7;
}

int32_t rome2_startup_wprintf_process_11689bc9(
    rome2_startup_wprintf_processor *proc) {
    if (!proc || !proc->target) {
        return -1;
    }
    if (!proc->fmt_cursor) {
        proc->last_errno = 22;
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
        while (*proc->fmt_cursor != 0u) {
            uint8_t step_ok = 1u;
            proc->current_ch = *proc->fmt_cursor++;
            if (proc->characters_written < 0) {
                break;
            }
            proc->state = l60_find_next_state(proc->current_ch, proc->state);
            if (proc->state == 8) {
                return -1;
            }
            switch (proc->state) {
            case 0:
                step_ok = rome2_startup_wprintf_state_normal_11689dbc(proc);
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
                if (proc->current_ch == (uint16_t)'+') {
                    proc->flags |= 0x01u;
                } else if (proc->current_ch == (uint16_t)' ') {
                    proc->flags |= 0x02u;
                } else if (proc->current_ch == (uint16_t)'-') {
                    proc->flags |= 0x04u;
                } else if (proc->current_ch == (uint16_t)'0') {
                    proc->flags |= 0x08u;
                } else if (proc->current_ch == (uint16_t)'#') {
                    proc->flags |= 0x20u;
                }
                break;
            case 3:
                if (proc->current_ch == (uint16_t)'*') {
                    int32_t w = (int32_t)l60_next_arg(proc);
                    if (w < 0) {
                        proc->flags |= 0x04u;
                        w = -w;
                    }
                    proc->field_width = w;
                } else {
                    proc->field_width = proc->field_width * 10 + (int32_t)(proc->current_ch - (uint16_t)'0');
                }
                break;
            case 4:
                proc->precision = 0;
                break;
            case 5:
                if (proc->current_ch == (uint16_t)'*') {
                    proc->precision = (int32_t)l60_next_arg(proc);
                    if (proc->precision < 0) {
                        proc->precision = -1;
                    }
                } else {
                    proc->precision = proc->precision * 10 + (int32_t)(proc->current_ch - (uint16_t)'0');
                }
                break;
            case 6:
                step_ok = rome2_startup_wprintf_state_size_1168a3b6(proc);
                break;
            case 7:
                step_ok = rome2_startup_wprintf_state_type_1168abf7(proc);
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

int32_t rome2_startup_crt_common_vsprintf_wide_11688718(
    uint64_t options,
    uint16_t *buf,
    uint32_t max_chars,
    const uint16_t *fmt,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno) {
    rome2_startup_wprintf_target target;
    rome2_startup_wprintf_processor proc;
    int32_t res = 0;

    if (!fmt || (max_chars != 0u && !buf)) {
        if (out_errno) {
            *out_errno = 22;
        }
        return -1;
    }

    memset(&target, 0, sizeof(target));
    target.buf = buf;
    target.max_chars = max_chars;
    target.written_chars = 0u;
    target.continue_on_truncation = ((options & ROME2_STARTUP_WPRINTF_OPT_LEGACY_NULL_TERM) != 0ULL || buf == NULL) ? 1u : 0u;
    l60_sync_adapter_guest(&target);

    memset(&proc, 0, sizeof(proc));
    proc.options = options;
    proc.fmt_cursor = fmt;
    proc.precision = -1;
    proc.target = &target;
    proc.args = args;
    proc.arg_count = arg_count;

    res = rome2_startup_wprintf_process_11689bc9(&proc);
    if (out_errno && proc.last_errno != 0) {
        *out_errno = proc.last_errno;
    }

    if (buf != NULL) {
        if ((options & ROME2_STARTUP_WPRINTF_OPT_STANDARD_SNPRINTF) != 0ULL) {
            if (max_chars == 0u) {
                if (res != 0) {
                    res = -1;
                }
            } else if (target.written_chars != max_chars) {
                buf[target.written_chars] = 0u;
            } else if (res < 0 || (uint32_t)res > max_chars) {
                res = -1;
            }
        } else if ((options & ROME2_STARTUP_WPRINTF_OPT_LEGACY_NULL_TERM) == 0ULL) {
            if (max_chars == 0u) {
                res = -1;
            } else if (res >= 0 && target.written_chars != max_chars) {
                buf[target.written_chars] = 0u;
            } else {
                buf[max_chars - 1u] = 0u;
                res = -2;
            }
        } else if (max_chars != 0u) {
            if (res < 0) {
                buf[0] = 0u;
            } else if (target.written_chars == max_chars) {
                buf[max_chars - 1u] = 0u;
            } else {
                buf[target.written_chars] = 0u;
            }
        }
    }
    return res;
}

int32_t rome2_startup_stdio_common_vswprintf_1168c120(
    uint64_t options,
    uint16_t *buf,
    uint32_t max_chars,
    const uint16_t *fmt,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno) {
    return rome2_startup_crt_common_vsprintf_wide_11688718(
        options, buf, max_chars, fmt, args, arg_count, out_errno);
}

int32_t rome2_startup_wide_vswprintf_100edfe0(
    uint16_t *dst,
    uint32_t max_chars,
    const uint16_t *fmt,
    const uintptr_t *args,
    size_t arg_count) {
    int32_t err = 0;
    int32_t r = rome2_startup_stdio_common_vswprintf_1168c120(
        0ULL, dst, max_chars, fmt, args, arg_count, &err);
    return (r < 0) ? -1 : r;
}

/* -------------------------------------------------------------------------
 * 0x11687a4a, 0x100f4a10, 0x101032a0, 0x100de6d0
 * ------------------------------------------------------------------------- */
static uint32_t l60_ror32(uint32_t v, uint32_t shift) {
    uint32_t s = shift & 31u;
    return (s == 0u) ? v : ((v >> s) | (v << (32u - s)));
}

static uint32_t l60_rol32(uint32_t v, uint32_t shift) {
    uint32_t s = shift & 31u;
    return (s == 0u) ? v : ((v << s) | (v >> (32u - s)));
}

uint32_t rome2_startup_crt_set_invalid_parameter_handler_11687a4a(
    uint32_t *encoded_slot_inout,
    uint32_t security_cookie,
    uint32_t new_handler) {
    uint32_t prev_raw = 0u;
    uint32_t prev_decoded = 0u;
    if (!encoded_slot_inout) {
        return 0u;
    }
    prev_raw = *encoded_slot_inout;
    prev_decoded = l60_ror32(prev_raw ^ security_cookie, security_cookie);
    *encoded_slot_inout = l60_rol32(new_handler, security_cookie) ^ security_cookie;
    return prev_decoded;
}

uint8_t rome2_startup_format_void_ptr_100f4a10(
    uintptr_t ptr_val,
    char spec_char,
    char *out_buf,
    size_t out_cap,
    size_t *out_len,
    char *diag_buf,
    size_t diag_cap) {
    static const char k_lower[] = "0123456789abcdef";
    static const char k_upper[] = "0123456789ABCDEF";
    const char *digits = NULL;
    char rev[24];
    size_t raw_len = 0u;
    size_t zeros = 0u;
    size_t pos = 0u;
    uintptr_t v = ptr_val;

    if (out_len) {
        *out_len = 0u;
    }
    if (!out_buf || out_cap == 0u) {
        return 0u;
    }
    out_buf[0] = '\0';

    if (spec_char == 'P' || spec_char == 'X') {
        digits = k_upper;
    } else if (spec_char == 'p' || spec_char == 'x') {
        digits = k_lower;
    } else {
        if (diag_buf && diag_cap > 0u) {
            (void)snprintf(diag_buf, diag_cap, "Unexpected format %%%c used with type void*", spec_char);
        }
        return 0u;
    }

    do {
        rev[raw_len++] = digits[v & 0xFu];
        v >>= 4;
    } while (v != 0u && raw_len < sizeof(rev));

    zeros = (raw_len < 8u) ? (8u - raw_len) : 0u;
    while (zeros > 0u && pos + 1u < out_cap) {
        out_buf[pos++] = '0';
        --zeros;
    }
    while (raw_len > 0u && pos + 1u < out_cap) {
        out_buf[pos++] = rev[--raw_len];
    }
    out_buf[pos] = '\0';
    if (out_len) {
        *out_len = pos;
    }
    return 1u;
}

void rome2_startup_terminate_zero_10102850(rome2_startup_abort_env *env) {
    if (!env) {
        return;
    }
    env->terminate_called = 1u;
    env->terminate_exit_code = 0u;
}

uint8_t rome2_startup_prompt_fatal_abort_101032a0(
    rome2_startup_abort_env *env,
    uint8_t is_nonfatal,
    const uint16_t *wide_msg) {
    int32_t resp = 0;
    if (!env || !wide_msg) {
        return 0u;
    }
    if (env->diag_cb) {
        uint8_t cb_cont = 0u;
        uint8_t ok = env->diag_cb(is_nonfatal, wide_msg, &cb_cont, env->diag_ctx);
        if (!ok) {
            return cb_cont;
        }
    }
    env->debug_output_calls += 1u;
    l60_copy_u16_bounded(env->last_debug_msg_u16, ROME2_STARTUP_MAX_PATH_U16, wide_msg);
    if (env->cached_hwnd == 0u) {
        env->cached_hwnd = env->active_hwnd;
    }
    for (;;) {
        env->msgbox_calls += 1u;
        if (env->prompt_response_cursor < env->prompt_response_count &&
            env->prompt_response_cursor < ROME2_STARTUP_MAX_ABORT_RESPONSES) {
            resp = env->prompt_responses[env->prompt_response_cursor++];
        } else {
            resp = ROME2_STARTUP_MB_CANCEL;
        }
        if (resp != ROME2_STARTUP_MB_ABORT) {
            break;
        }
        /* Confirmation prompt "Last chance..." / "Are you sure you want to abort the process?" */
        env->msgbox_calls += 1u;
        if (env->prompt_response_cursor < env->prompt_response_count &&
            env->prompt_response_cursor < ROME2_STARTUP_MAX_ABORT_RESPONSES) {
            int32_t confirm = env->prompt_responses[env->prompt_response_cursor++];
            if (confirm == ROME2_STARTUP_MB_OK) {
                rome2_startup_terminate_zero_10102850(env);
                return 0u;
            }
        }
    }
    return (resp == ROME2_STARTUP_MB_CANCEL || resp == ROME2_STARTUP_MB_RETRY) ? 1u : 0u;
}

uint8_t rome2_startup_format_fatal_diag_100de6d0(
    rome2_startup_abort_env *env,
    uint8_t is_nonfatal,
    const char *fmt_a,
    uintptr_t ptr_val,
    uint8_t *reentrancy_guard) {
    char msg_a[256];
    uint16_t msg_u16[ROME2_STARTUP_MAX_PATH_U16];
    size_t i = 0u;
    size_t out_pos = 0u;
    uint8_t ret = 0u;

    if (!env || !fmt_a || !reentrancy_guard) {
        return 0u;
    }
    if (*reentrancy_guard != 0u) {
        return 0u;
    }
    *reentrancy_guard = 1u;

    while (fmt_a[i] != '\0' && out_pos + 1u < sizeof(msg_a)) {
        if (fmt_a[i] == '%') {
            do {
                ++i;
            } while (fmt_a[i] == 'l');
            if (fmt_a[i] == '\0') {
                break;
            }
            if (fmt_a[i] != '%') {
                char ptr_buf[24];
                size_t ptr_len = 0u;
                uint8_t fmt_ok = rome2_startup_format_void_ptr_100f4a10(
                    ptr_val,
                    fmt_a[i],
                    ptr_buf,
                    sizeof(ptr_buf),
                    &ptr_len,
                    env->last_diag_error_a,
                    sizeof(env->last_diag_error_a));
                if (!fmt_ok) {
                    break;
                }
                ++i;
                if (ptr_len > 0u && out_pos + ptr_len < sizeof(msg_a)) {
                    memcpy(msg_a + out_pos, ptr_buf, ptr_len);
                    out_pos += ptr_len;
                }
                while (fmt_a[i] != '\0' && out_pos + 1u < sizeof(msg_a)) {
                    msg_a[out_pos++] = fmt_a[i++];
                }
                break;
            }
        }
        msg_a[out_pos++] = fmt_a[i++];
    }
    msg_a[out_pos] = '\0';

    l60_ascii_to_u16(msg_a, msg_u16, ROME2_STARTUP_MAX_PATH_U16);
    ret = rome2_startup_prompt_fatal_abort_101032a0(env, is_nonfatal, msg_u16);
    *reentrancy_guard = 0u;
    return ret;
}

/* -------------------------------------------------------------------------
 * 0x10122e40, 0x100fe770, 0x101046d0, 0x100f0eb0, 0x1014d170, 0x100df270
 * ------------------------------------------------------------------------- */
const char *rome2_startup_get_user_folder_col0_prefix_10122e40(uint32_t category_idx) {
    static const char *const k_col0_prefixes[ROME2_STARTUP_USER_FOLDER_COUNT] = {
        ".save",
        ".save_multiplayer",
        ".replay",
        ".log.txt",
        ".ai_history.html",
        ".ai_history.xml",
        ".ai_log.xml",
        ".ai_world_state.html",
        ".script.txt",
        ".battle_editor",
        ".cinematic_editor",
        ".screenshot.tga",
        ".movie.avi",
        ".sound.wav",
        ".keys.xml",
        ".battle_preferences",
        ".army_setup",
        ".crash",
        ".fxc",
        ".fxc",
        ".advice",
        ".ai_tech.txt",
        ".ui_cache",
        ".ai_seq_log.txt",
        ".cdir.txt",
        ".cdir.csv",
        ".ai_hit_log.txt",
        "",
        ".officer.unit_variant",
        ".officer.unit_variant",
        ".mpcampaign",
        ".csv",
        "",
        ".temp",
        ".camera_bookmarks",
        ".txt",
        ".html",
        ".tga",
        ".png",
        ".ai_perf_log.txt",
        ".benchmark",
        "",
        ".tilebattle_log",
        "",
        ".csv",
        ".txdb",
        ".dat",
        ".csv",
        ".reg",
        "",
    };
    if (category_idx >= ROME2_STARTUP_USER_FOLDER_COUNT) {
        return NULL;
    }
    return k_col0_prefixes[category_idx];
}

static uint8_t l60_wildcard_match_ci(const char *pat, const char *str) {
    if (!pat || !str) {
        return 0u;
    }
    if (strcmp(pat, "*") == 0) {
        return 1u;
    }
    if (pat[0] == '*' && pat[1] == '.') {
        size_t slen = strlen(str);
        size_t elen = strlen(pat + 1);
        if (slen >= elen) {
            return (_stricmp(str + (slen - elen), pat + 1) == 0) ? 1u : 0u;
        }
        return 0u;
    }
    return (_stricmp(pat, str) == 0) ? 1u : 0u;
}

static void l60_norm_dir_ascii(const char *in, char *out, size_t out_cap) {
    size_t len = 0u;
    if (!out || out_cap == 0u) {
        return;
    }
    if (!in) {
        out[0] = '\0';
        return;
    }
    (void)snprintf(out, out_cap, "%s", in);
    len = strlen(out);
    while (len > 0u && (out[len - 1u] == '\\' || out[len - 1u] == '/')) {
        out[--len] = '\0';
    }
}

rome2_vfs_reg_status rome2_startup_dir_enum_and_clean_100fe770(
    rome2_startup_fs_mock_env *fs_env,
    rome2_startup_dir_enum_cb cb,
    const uint16_t *dir_u16,
    const uint16_t *pattern_u16,
    void *cb_ctx,
    uint8_t recurse) {
    char dir_a[260];
    char dir_norm[260];
    char pat_a[64];
    uint32_t i = 0u;
    uint32_t found_pass1 = 0u;

    if (!fs_env || !cb || !dir_u16 || !pattern_u16) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    l60_u16_to_ascii(dir_u16, dir_a, sizeof(dir_a));
    l60_norm_dir_ascii(dir_a, dir_norm, sizeof(dir_norm));
    l60_u16_to_ascii(pattern_u16, pat_a, sizeof(pat_a));

    fs_env->find_first_calls += 1u;
    for (i = 0u; i < fs_env->entry_count && i < ROME2_STARTUP_MAX_FS_ENTRIES; ++i) {
        const rome2_startup_fs_mock_entry *ent = &fs_env->entries[i];
        char parent_norm[260];
        l60_norm_dir_ascii(ent->parent_rel, parent_norm, sizeof(parent_norm));
        if (!ent->deleted && strcmp(parent_norm, dir_norm) == 0 && l60_wildcard_match_ci(pat_a, ent->name)) {
            rome2_startup_enum_entry_info info;
            uint16_t name_u16[128];
            found_pass1 = 1u;
            memset(&info, 0, sizeof(info));
            info.raw_attributes_34 = ent->file_attributes;
            info.size_lo = ent->size_lo;
            /* Match 0x100fe770 FILETIME division + 0x49ef7d10 bias */
            info.converted_unix_time_2c =
                (uint32_t)((ent->write_time_100ns / UINT64_C(10000000)) + UINT64_C(0x49ef7d10));
            info.is_present_28 = 1u;
            info.is_readonly_27 = (uint8_t)(~(uint8_t)ent->file_attributes & 1u);
            info.is_dir_26 = (uint8_t)((ent->file_attributes >> 4) & 1u);
            info.is_hidden_25 = (uint8_t)((ent->file_attributes >> 1) & 1u);
            l60_ascii_to_u16(ent->name, name_u16, 128u);
            cb(dir_u16, name_u16, pattern_u16, &info, cb_ctx);
        }
    }
    if (found_pass1) {
        fs_env->find_close_calls += 1u;
    }

    if (recurse != 0u) {
        uint32_t found_sub = 0u;
        fs_env->find_first_calls += 1u;
        for (i = 0u; i < fs_env->entry_count && i < ROME2_STARTUP_MAX_FS_ENTRIES; ++i) {
            const rome2_startup_fs_mock_entry *ent = &fs_env->entries[i];
            char parent_norm[260];
            l60_norm_dir_ascii(ent->parent_rel, parent_norm, sizeof(parent_norm));
            if (!ent->deleted && (ent->file_attributes & 0x10u) != 0u &&
                strcmp(parent_norm, dir_norm) == 0 &&
                strcmp(ent->name, ".") != 0 && strcmp(ent->name, "..") != 0) {
                char sub_a[260];
                uint16_t sub_u16[260];
                found_sub = 1u;
                (void)snprintf(sub_a, sizeof(sub_a), "%s\\%s\\", dir_norm, ent->name);
                l60_ascii_to_u16(sub_a, sub_u16, 260u);
                (void)rome2_startup_dir_enum_and_clean_100fe770(
                    fs_env, cb, sub_u16, pattern_u16, cb_ctx, 1u);
            }
        }
        if (found_sub) {
            fs_env->find_close_calls += 1u;
        }
    }
    return ROME2_VFS_REG_OK;
}

static void l60_clean_entry_cb(
    const uint16_t *dir_u16,
    const uint16_t *name_u16,
    const uint16_t *pattern_u16,
    const rome2_startup_enum_entry_info *info,
    void *ctx) {
    rome2_startup_fs_mock_env *fs_env = (rome2_startup_fs_mock_env *)ctx;
    char dir_norm[260];
    char dir_a[260];
    char name_a[128];
    uint32_t i = 0u;
    (void)pattern_u16;
    if (!fs_env || !dir_u16 || !name_u16 || !info || info->is_dir_26 != 0u) {
        return;
    }
    l60_u16_to_ascii(dir_u16, dir_a, sizeof(dir_a));
    l60_norm_dir_ascii(dir_a, dir_norm, sizeof(dir_norm));
    l60_u16_to_ascii(name_u16, name_a, sizeof(name_a));
    for (i = 0u; i < fs_env->entry_count && i < ROME2_STARTUP_MAX_FS_ENTRIES; ++i) {
        char pnorm[260];
        l60_norm_dir_ascii(fs_env->entries[i].parent_rel, pnorm, sizeof(pnorm));
        if (!fs_env->entries[i].deleted &&
            strcmp(pnorm, dir_norm) == 0 &&
            strcmp(fs_env->entries[i].name, name_a) == 0) {
            fs_env->entries[i].deleted = 1u;
            fs_env->deleted_count += 1u;
            break;
        }
    }
}

rome2_vfs_reg_status rome2_startup_clean_user_category_dir_101046d0(
    rome2_startup_path_env *path_env,
    rome2_startup_fs_mock_env *fs_env,
    uint32_t category_idx) {
    static const uint16_t k_star[2] = { (uint16_t)'*', 0u };
    uint16_t dir_u16[ROME2_STARTUP_MAX_PATH_U16];
    size_t dir_len = 0u;
    rome2_vfs_reg_status st = ROME2_VFS_REG_OK;

    if (!path_env || !fs_env || !rome2_startup_get_user_folder_col0_prefix_10122e40(category_idx)) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = rome2_startup_resolve_appdata_dir_101016c0(
        path_env, category_idx, dir_u16, ROME2_STARTUP_MAX_PATH_U16, &dir_len);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    return rome2_startup_dir_enum_and_clean_100fe770(
        fs_env, l60_clean_entry_cb, dir_u16, k_star, fs_env, 0u);
}

rome2_startup_observer_node12_32 *rome2_startup_init_observer_node_100f0eb0(
    rome2_startup_observer_node12_32 *node,
    uint32_t owner_va) {
    if (!node) {
        return NULL;
    }
    node->vtable_00 = 0x11741e08u;
    node->state_04 = 0u;
    node->owner_08 = owner_va;
    return node;
}

rome2_startup_pair8_32 *rome2_startup_init_zero_pair8_1014d170(
    rome2_startup_pair8_32 *pair) {
    if (!pair) {
        return NULL;
    }
    pair->lo_00 = 0u;
    pair->hi_04 = 0u;
    return pair;
}

rome2_vfs_reg_status rome2_startup_app_ctor_100df270(
    rome2_startup_app_state *app,
    rome2_startup_app_host_env *host,
    const rome2_startup_app_params *params) {
    static const uint16_t k_mutex_fmt[] = {
        '%','s',' ','i','n','s','t','a','n','c','e',' ','v','e','r','i','f','i','c','a','t','i','o','n',' ','m','u','t','e','x',0
    };
    static const uint16_t k_running_fmt[] = {
        'A','n','o','t','h','e','r',' ','i','n','s','t','a','n','c','e',' ','o','f',' ','%','s',
        ' ','i','s',' ','r','u','n','n','i','n','g','.','\n',
        'T','h','i','s',' ','i','n','s','t','a','n','c','e',' ','w','i','l','l',' ','t','e','r','m','i','n','a','t','e','.',0
    };
    static const uint16_t k_mutex_err[] = { 'M','u','t','e','x',' ','e','r','r','o','r',0 };
    static const uint32_t k_temp_cats[4] = { 0x2du, 0x12u, 0x16u, 0x21u };
    uint16_t local_400[512];
    uintptr_t fmt_arg = 0u;

    if (!app || !host || !params) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(app, 0, sizeof(*app));
    app->hinstance_04 = params->hinstance;
    app->vtable_00 = 0x1173f208u;
    app->vtable_history[app->vtable_history_count++] = 0x1173f208u;

    l60_copy_u16_bounded(app->string_6d, 64u, host->res_string_6d);
    l60_copy_u16_bounded(app->string_67, 64u, host->res_string_67);

    fmt_arg = (uintptr_t)app->string_67;
    (void)rome2_startup_wide_vswprintf_100edfe0(local_400, 512u, k_mutex_fmt, &fmt_arg, 1u);
    app->mutex_handle_808 = host->mutex_handle_value;
    app->mutex_already_existed = host->simulate_already_exists;

    if (host->simulate_already_exists != 0u && params->allow_multi_instance_2c == 0u) {
        (void)rome2_startup_wide_vswprintf_100edfe0(local_400, 512u, k_running_fmt, &fmt_arg, 1u);
        app->mutex_error_msgbox_calls += 1u;
        l60_copy_u16_bounded(app->mutex_msgbox_text, 96u, local_400);
        l60_copy_u16_bounded(app->mutex_msgbox_title, 32u, k_mutex_err);
        rome2_startup_terminate_zero_10102850(host->abort_env);
        return ROME2_VFS_REG_OK;
    }

    app->spi_calls[0] = ROME2_STARTUP_SPI_GETMOUSETRAILS;
    app->spi_saved_mouse_trails = host->initial_mouse_trails;
    app->spi_calls[1] = ROME2_STARTUP_SPI_SETMOUSETRAILS;

    app->vtable_00 = 0x1173f2f4u;
    app->vtable_history[app->vtable_history_count++] = 0x1173f2f4u;
    (void)rome2_startup_init_observer_node_100f0eb0(&app->observer, 0u);
    app->allow_multi_instance_copy = params->allow_multi_instance_2c;
    app->embedded_cfg_vtable_874 = 0x1173dc18u;
    (void)rome2_startup_init_zero_pair8_1014d170(&app->pair_tail);
    app->global_app_ptr = 0x119f3140u;

    if (host->crash_singleton) {
        (void)rome2_startup_crash_reporter_instance_100e8240(
            host->crash_singleton, host->path_env, host->tls_epoch);
    }
    if (host->handler_queue) {
        rome2_vfs_reg_status hst = rome2_startup_register_handlers_part2_100ea4d0(host->handler_queue);
        if (hst != ROME2_VFS_REG_OK) {
            return hst;
        }
    }

    if (host->persistent_cache_magic != ROME2_STARTUP_CACHE_MAGIC_INITIALIZED && host->path_env && host->fs_env) {
        size_t k = 0u;
        for (k = 0u; k < 4u; ++k) {
            (void)rome2_startup_clean_user_category_dir_101046d0(
                host->path_env, host->fs_env, k_temp_cats[k]);
            if (app->cleaned_category_count < 8u) {
                app->cleaned_categories[app->cleaned_category_count++] = k_temp_cats[k];
            }
        }
    }
    host->persistent_cache_magic = ROME2_STARTUP_CACHE_MAGIC_INITIALIZED;
    app->cache_magic = host->persistent_cache_magic;
    return ROME2_VFS_REG_OK;
}

/* -------------------------------------------------------------------------
 * 0x10115800, 0x10115810, 0x112e2bb0, 0x106b91a0, 0x112b2d40, 0x112dcaf0
 * ------------------------------------------------------------------------- */
uint32_t rome2_startup_winmm_time_begin_period_10115800(
    rome2_startup_winmm_env *env,
    uint32_t period_ms) {
    if (!env) {
        return 0u;
    }
    env->begin_calls += 1u;
    env->last_period_ms = period_ms;
    return 0u;
}

uint32_t rome2_startup_winmm_time_end_period_10115810(
    rome2_startup_winmm_env *env,
    uint32_t period_ms) {
    if (!env) {
        return 0u;
    }
    env->end_calls += 1u;
    env->last_period_ms = period_ms;
    return 0u;
}

rome2_vfs_reg_status rome2_startup_query_high_res_us_112e2bb0(
    rome2_startup_winmm_env *env,
    uint64_t *out_us) {
    uint64_t now_us = 0ULL;
    if (!env || !out_us) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    (void)rome2_startup_winmm_time_begin_period_10115800(env, 1u);
    now_us = (uint64_t)env->current_time_ms * UINT64_C(1000);
    (void)rome2_startup_winmm_time_end_period_10115810(env, 1u);
    *out_us = now_us - env->baseline_us;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_startup_format_two_strings_106b91a0(
    const uint16_t *fmt_u16,
    const char *s1,
    const char *s2,
    char *out_buf,
    size_t out_cap,
    size_t *out_len) {
    const char *args[2];
    char diag[96];
    size_t pos = 0u;
    size_t cur = 0u;
    size_t arg_idx = 0u;

    if (!fmt_u16 || !out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    args[0] = s1 ? s1 : "";
    args[1] = s2 ? s2 : "";
    out_buf[0] = '\0';

    /* Mirror binary 0x106b91a0: two 0x100de500 passes across fmt_u16 followed by literal tail 0x100f60b0. */
    while (fmt_u16[pos] != 0u) {
        uint8_t ch = (uint8_t)(fmt_u16[pos] & 0xffu);
        if (ch == '%' && arg_idx < 2u) {
            do {
                pos += 1u;
                ch = (uint8_t)(fmt_u16[pos] & 0xffu);
            } while (ch == 'l');
            if (ch == '\0') {
                break;
            }
            if (ch != '%') {
                if (!rome2_startup_format_const_char_spec_100f4920(
                        args[arg_idx], (char)ch, out_buf, out_cap, &cur, diag, sizeof(diag))) {
                    if (out_len) {
                        *out_len = cur;
                    }
                    return ROME2_VFS_REG_BAD_ARGUMENT;
                }
                arg_idx += 1u;
                pos += 1u;
                continue;
            }
        }
        if (cur + 2u > out_cap) {
            if (out_len) {
                *out_len = cur;
            }
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        out_buf[cur++] = (char)ch;
        out_buf[cur] = '\0';
        pos += 1u;
    }
    if (out_len) {
        *out_len = cur;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_startup_record_sorted_timing_slot_112b2d40(
    rome2_startup_timing_report_env *env,
    uint32_t label_ptr_va,
    uint32_t delta_ms,
    uint32_t detail_tag,
    uint32_t detail_arg) {
    uint32_t cap_limit = 0u;
    uint32_t count = 0u;
    uint32_t low = 0u;
    uint32_t len = 0u;
    uint32_t insert_idx = 0u;
    uint32_t i = 0u;

    if (!env || !env->base) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    cap_limit = env->base->max_cap_param;
    if (cap_limit == 0u) {
        return ROME2_VFS_REG_OK;
    }
    if (cap_limit >= ROME2_STARTUP_MAX_TIMING_SLOTS) {
        cap_limit = ROME2_STARTUP_MAX_TIMING_SLOTS - 1u;
    }
    count = env->vec_header.count_04;
    if (count > cap_limit) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (count >= cap_limit && count > 0u &&
        delta_ms <= env->base->slots[count - 1u].start_ms_04) {
        return ROME2_VFS_REG_OK;
    }

    /* Binary search lower bound for descending order on start_ms_04 (delta_ms). */
    low = 0u;
    len = count;
    while (len > 0u) {
        uint32_t half = len >> 1;
        uint32_t mid = low + half;
        if (delta_ms < env->base->slots[mid].start_ms_04) {
            low = mid + 1u;
            len = len - 1u - half;
        } else {
            len = half;
        }
    }
    insert_idx = low;
    if (insert_idx > count || insert_idx >= ROME2_STARTUP_MAX_TIMING_SLOTS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    if (count == env->vec_header.cap_00) {
        uint32_t new_cap = (env->vec_header.cap_00 == 0u) ? 1u : (env->vec_header.cap_00 * 2u);
        if (new_cap > ROME2_STARTUP_MAX_TIMING_SLOTS) {
            new_cap = ROME2_STARTUP_MAX_TIMING_SLOTS;
        }
        if (count >= new_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        env->vec_header.cap_00 = new_cap;
        env->base->alloc_cap = new_cap;
    }

    for (i = count; i > insert_idx && i > 0u && i < ROME2_STARTUP_MAX_TIMING_SLOTS; --i) {
        env->base->slots[i] = env->base->slots[i - 1u];
    }
    env->base->slots[insert_idx].label_ptr_00 = label_ptr_va;
    env->base->slots[insert_idx].start_ms_04 = delta_ms;
    env->base->slots[insert_idx].elapsed_ms_08 = detail_tag;
    env->base->slots[insert_idx].flags_0c = detail_arg;
    count += 1u;
    if (count > cap_limit) {
        count = cap_limit;
    }
    env->vec_header.count_04 = count;
    env->base->active_count = count;
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_startup_report_section_timing_done_112dcaf0(
    rome2_startup_timing_report_env *env,
    const char *subsection,
    int32_t detail_tag,
    const char *detail_arg) {
    uint32_t now_ms = 0u;
    uint32_t delta_ms = 0u;
    uint32_t total_ms = 0u;
    uint32_t alloc_total = 0u;
    int32_t alloc_delta = 0;
    uint32_t alloc_mb = 0u;
    const char *active = NULL;
    rome2_vfs_reg_status st = ROME2_VFS_REG_OK;

    if (!env || !env->base || !env->winmm) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    now_ms = env->winmm->current_time_ms;
    delta_ms = now_ms - env->last_reported_ms;
    total_ms = now_ms - env->base->init_start_ms;
    alloc_total = env->alloc_tbl ? rome2_startup_get_allocator_slot_100fcc30(env->alloc_tbl, 3) : 0u;
    alloc_delta = (int32_t)(alloc_total - env->last_reported_alloc);
    alloc_mb = alloc_total >> 20;

    st = rome2_startup_record_sorted_timing_slot_112b2d40(
        env,
        0x119e0ff0u,
        delta_ms,
        (uint32_t)detail_tag,
        detail_arg ? 1u : 0u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }

    active = (env->base->active_label[0] != '\0') ? env->base->active_label : "NO_SECTIONS_STARTED";
    if (detail_tag == 0) {
        (void)snprintf(
            env->primary_banner,
            sizeof(env->primary_banner),
            "%s: Done %s (%ums delta, %ums total, %uMB allocated total, %d bytes delta allocated, total UniStrings:%d)\n",
            active,
            subsection ? subsection : "",
            delta_ms,
            total_ms,
            alloc_mb,
            alloc_delta,
            0);
        env->secondary_banner[0] = '\0';
    } else {
        static const uint16_t k_done_fmt[] = { '%','s',':',' ','D','o','n','e',' ','%','s',0 };
        size_t len = 0u;
        (void)rome2_startup_format_two_strings_106b91a0(
            k_done_fmt, active, subsection ? subsection : "", env->primary_banner, sizeof(env->primary_banner), &len);
        (void)snprintf(
            env->secondary_banner,
            sizeof(env->secondary_banner),
            "%ums delta, %ums total, %uMB allocated total, %d bytes delta allocated, total UniStrings:%d)\n",
            delta_ms,
            total_ms,
            alloc_mb,
            alloc_delta,
            0);
    }

    env->last_reported_ms = now_ms;
    env->last_reported_alloc = alloc_total;
    return ROME2_VFS_REG_OK;
}

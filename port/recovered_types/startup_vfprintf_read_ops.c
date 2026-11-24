#include "startup_vfprintf_read_ops.h"

#include <errno.h>
#include <string.h>

/* 0x1190ecd0 (91 bytes): __acrt_printf_lookup_table_second used by 0x116892d1.
 * Low nibble indexes row via [ch + 0x1190ecb0] for ch in [' ', 'x']; high nibble stores next state.
 */
static const uint8_t ROME2_L64_PRINTF_STATE_TBL[ROME2_STARTUP_L64_PRINTF_TBL_LEN] = {
    0x06, 0x80, 0x80, 0x86, 0x80, 0x81, 0x80, 0x00, 0x00, 0x10, 0x03, 0x86, 0x80, 0x86, 0x82, 0x80,
    0x14, 0x05, 0x05, 0x45, 0x45, 0x45, 0x85, 0x85, 0x85, 0x05, 0x00, 0x00, 0x30, 0x30, 0x80, 0x50,
    0x80, 0x88, 0x00, 0x08, 0x00, 0x28, 0x27, 0x38, 0x50, 0x57, 0x80, 0x00, 0x07, 0x00, 0x37, 0x30,
    0x30, 0x50, 0x50, 0x88, 0x07, 0x00, 0x00, 0x20, 0x28, 0x80, 0x88, 0x80, 0x80, 0x00, 0x00, 0x00,
    0x60, 0x68, 0x60, 0x68, 0x68, 0x68, 0x08, 0x08, 0x07, 0x78, 0x77, 0x70, 0x77, 0x70, 0x70, 0x08,
    0x08, 0x00, 0x00, 0x08, 0x07, 0x08, 0x00, 0x07, 0x08, 0x00, 0x07
};

static int32_t l64_utf8_trail_count(uint8_t b)
{
    if (b < 0x80u) {
        return 0;
    }
    if ((b & 0xe0u) == 0xc0u) {
        return 1;
    }
    if ((b & 0xf0u) == 0xe0u) {
        return 2;
    }
    if ((b & 0xf8u) == 0xf0u) {
        return 3;
    }
    return 0;
}

/* `0x116892d1`: find_next_state (0x1190ecd0). */
uint32_t rome2_startup_fprintf_find_next_state_116892d1(uint8_t ch, uint32_t prev_state)
{
    uint32_t col = 0u;
    uint32_t clamped_prev = prev_state < 9u ? prev_state : 0u;
    if (ch >= 0x20u && (uint32_t)(ch - 0x20u) <= 0x5au) {
        col = (uint32_t)(ROME2_L64_PRINTF_STATE_TBL[ch - 0x20u] & 0x0fu);
    }
    size_t idx = (size_t)col * 9u + (size_t)clamped_prev;
    if (idx >= ROME2_STARTUP_L64_PRINTF_TBL_LEN) {
        return 8u;
    }
    return (uint32_t)(ROME2_L64_PRINTF_STATE_TBL[idx] >> 4);
}

/* `0x1168b8a6`: verify stream flags/textmode permit narrow output. */
uint8_t rome2_startup_fprintf_validate_stream_flags_1168b8a6(
    const rome2_startup_fprintf_stream *stream,
    int32_t *out_errno,
    uint32_t *out_invalid_param)
{
    if (stream == NULL) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        if (out_invalid_param != NULL) {
            (*out_invalid_param)++;
        }
        return 0u;
    }
    if ((stream->flags & ROME2_STARTUP_L64_IOSTRG) != 0u) {
        return 1u;
    }
    if (stream->textmode != 0u || (stream->utf8_crlf_flags & 1u) != 0u) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        if (out_invalid_param != NULL) {
            (*out_invalid_param)++;
        }
        return 0u;
    }
    return 1u;
}

/* `0x1168b848`: validate stream adapter target. */
uint8_t rome2_startup_fprintf_validate_adapter_1168b848(
    const rome2_startup_fprintf_processor *proc,
    int32_t *out_errno,
    uint32_t *out_invalid_param)
{
    if (proc == NULL || proc->stream == NULL) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        if (out_invalid_param != NULL) {
            (*out_invalid_param)++;
        }
        return 0u;
    }
    return rome2_startup_fprintf_validate_stream_flags_1168b8a6(
        proc->stream, out_errno, out_invalid_param);
}

/* `0x1168b884`: format_validation_base post-EOS state validation (0 or 7). */
uint8_t rome2_startup_fprintf_validate_size_1168b884(
    const rome2_startup_fprintf_processor *proc,
    int32_t *out_errno,
    uint32_t *out_invalid_param)
{
    if (proc == NULL) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        if (out_invalid_param != NULL) {
            (*out_invalid_param)++;
        }
        return 0u;
    }
    if (proc->base.state == 0 || proc->base.state == 7) {
        return 1u;
    }
    if (out_errno != NULL) {
        *out_errno = EINVAL;
    }
    if (out_invalid_param != NULL) {
        (*out_invalid_param)++;
    }
    return 0u;
}

/* `0x1168b9b4`: stream_output_adapter<char>::write_character. */
uint8_t rome2_startup_fprintf_write_char_1168b9b4(
    rome2_startup_fprintf_stream *stream,
    char ch)
{
    if (stream == NULL) {
        return 0u;
    }
    if ((stream->flags & ROME2_STARTUP_L64_IOSTRG) != 0u && stream->has_buffer == 0u) {
        return 1u;
    }
    if (stream->fail_next_write != 0u) {
        stream->fail_next_write = 0u;
        return 0u;
    }
    if (stream->out_buf != NULL && stream->out_len < stream->out_cap) {
        stream->out_buf[stream->out_len] = ch;
    }
    stream->out_len++;
    return 1u;
}

/* `0x11688d84`: write_multiple_characters<stream_output_adapter<char>, char>. */
void rome2_startup_fprintf_write_multi_chars_11688d84(
    rome2_startup_fprintf_stream *stream,
    char ch,
    int32_t count,
    int32_t *written_inout)
{
    if (written_inout == NULL) {
        return;
    }
    for (int32_t i = 0; i < count; ++i) {
        if (rome2_startup_fprintf_write_char_1168b9b4(stream, ch) != 0u) {
            (*written_inout)++;
        } else {
            *written_inout = -1;
        }
        if (*written_inout == -1) {
            break;
        }
    }
}

/* `0x1168bdc7`: stream_output_adapter<char>::write_string_impl. */
void rome2_startup_fprintf_write_string_1168bdc7(
    rome2_startup_fprintf_stream *stream,
    const char *s,
    int32_t len,
    int32_t *written_inout,
    int32_t *err_inout)
{
    int32_t saved_err = err_inout != NULL ? *err_inout : 0;
    if (err_inout != NULL) {
        *err_inout = 0;
    }
    if (written_inout == NULL) {
        return;
    }
    for (int32_t i = 0; i < len; ++i) {
        char c = s != NULL ? s[i] : '\0';
        if (rome2_startup_fprintf_write_char_1168b9b4(stream, c) != 0u) {
            (*written_inout)++;
        } else {
            if (err_inout != NULL && stream != NULL && stream->simulated_write_errno != 0) {
                *err_inout = stream->simulated_write_errno;
                stream->simulated_write_errno = 0;
            }
            if (err_inout != NULL && *err_inout == EILSEQ) {
                /* Per 0x1168be28: fall back cleanly to replacement '?' when EILSEQ occurs. */
                (void)rome2_startup_fprintf_write_char_1168b9b4(stream, '?');
                (*written_inout)++;
            } else {
                *written_inout = -1;
                break;
            }
        }
    }
    if (err_inout != NULL && *err_inout == 0 && saved_err != 0) {
        *err_inout = saved_err;
    }
}

/* `0x1168bc97`: stream_output_adapter<char>::write_string fast counting / fallback dispatch. */
void rome2_startup_fprintf_write_string_dispatch_1168bc97(
    rome2_startup_fprintf_stream *stream,
    const char *s,
    int32_t len,
    int32_t *written_inout,
    int32_t *err_inout)
{
    if (stream == NULL || written_inout == NULL) {
        return;
    }
    if ((stream->flags & ROME2_STARTUP_L64_IOSTRG) != 0u && stream->has_buffer == 0u) {
        *written_inout += len;
        return;
    }
    rome2_startup_fprintf_write_string_1168bdc7(stream, s, len, written_inout, err_inout);
}

/* `0x1168ba23`: stream write_stored_string_tchar<char>. */
uint8_t rome2_startup_fprintf_write_stored_tchar_1168ba23(
    rome2_startup_fprintf_processor *proc)
{
    if (proc == NULL || proc->stream == NULL) {
        return 0u;
    }
    if (proc->base.is_wide != 0u && proc->base.str_len > 0 && proc->base.wide_ptr != NULL) {
        for (int32_t i = 0; i < proc->base.str_len; ++i) {
            uint16_t wc = proc->base.wide_ptr[i];
            if (wc > 0x7fu && proc->base.has_locale == 0u) {
                proc->base.characters_written = -1;
                break;
            }
            char ch = (wc <= 0xffu) ? (char)(wc & 0xffu) : '?';
            rome2_startup_fprintf_write_string_dispatch_1168bc97(
                proc->stream, &ch, 1, &proc->base.characters_written, &proc->base.last_errno);
            if (proc->base.characters_written < 0) {
                break;
            }
        }
    } else if (proc->base.str_len > 0) {
        const char *src = proc->base.narrow_ptr != NULL ? proc->base.narrow_ptr : proc->base.narrow_buf;
        rome2_startup_fprintf_write_string_dispatch_1168bc97(
            proc->stream, src, proc->base.str_len, &proc->base.characters_written, &proc->base.last_errno);
    }
    return 1u;
}

/* `0x11689e84`: state_case_normal_tchar (stream). */
uint8_t rome2_startup_fprintf_state_normal_tchar_11689e84(
    rome2_startup_fprintf_processor *proc)
{
    if (proc == NULL || proc->stream == NULL || proc->base.fmt_cursor == NULL) {
        return 0u;
    }
    uint8_t ch = proc->base.current_ch;
    proc->base.is_wide = 0u;
    uint8_t is_lead = (proc->base.lead_table != NULL && (proc->base.lead_table[ch] & 0x80u) != 0u) ? 1u : 0u;
    if (rome2_startup_fprintf_write_char_1168b9b4(proc->stream, (char)ch) != 0u) {
        proc->base.characters_written++;
    } else {
        proc->base.characters_written = -1;
    }
    if (is_lead != 0u) {
        uint8_t trail = (uint8_t)*proc->base.fmt_cursor;
        proc->base.fmt_cursor++;
        proc->base.current_ch = trail;
        if (trail == 0u) {
            proc->base.last_errno = EINVAL;
            proc->base.invalid_param_count++;
            return 0u;
        }
        /* Paired lead/trail write completes cleanly in non-legacy paths; legacy flags fail if trail nul. */
        if (proc->legacy_mb_leadbyte_fail == 0u) {
            if (rome2_startup_fprintf_write_char_1168b9b4(proc->stream, (char)trail) != 0u) {
                proc->base.characters_written++;
            } else {
                proc->base.characters_written = -1;
            }
        }
    }
    return 1u;
}

/* `0x11689ddb`: state_case_normal_common (stream). */
uint8_t rome2_startup_fprintf_state_normal_common_11689ddb(
    rome2_startup_fprintf_processor *proc)
{
    if (proc == NULL) {
        return 0u;
    }
    return rome2_startup_fprintf_state_normal_tchar_11689e84(proc);
}

/* `0x11689d5f`: format_validation_base::state_case_normal (stream). */
uint8_t rome2_startup_fprintf_state_normal_11689d5f(
    rome2_startup_fprintf_processor *proc)
{
    if (proc == NULL) {
        return 0u;
    }
    if (rome2_startup_fprintf_state_normal_common_11689ddb(proc) != 0u) {
        return 1u;
    }
    proc->base.last_errno = EINVAL;
    proc->base.invalid_param_count++;
    return 0u;
}

/* `0x11689fa2`: format_validation_base::state_case_size (stream). */
uint8_t rome2_startup_fprintf_state_size_11689fa2(
    rome2_startup_fprintf_processor *proc)
{
    if (proc == NULL || proc->base.fmt_cursor == NULL) {
        return 0u;
    }
    uint8_t ch = proc->base.current_ch;
    if (ch == 'F') {
        if ((proc->base.options & 8u) == 0u) {
            proc->base.state = 7;
            return rome2_startup_fprintf_state_type_1168a52e(proc);
        }
        return 1u;
    }
    if (ch == 'N') {
        if ((proc->base.options & 8u) == 0u) {
            proc->base.state = 8;
            proc->base.last_errno = EINVAL;
            proc->base.invalid_param_count++;
            return 0u;
        }
        return 1u;
    }
    if (proc->base.length_mod != 0u) {
        proc->base.last_errno = EINVAL;
        proc->base.invalid_param_count++;
        return 0u;
    }
    return rome2_startup_nprintf_state_size_1168a0f0(&proc->base);
}

/* `0x1168a52e`: format_validation_base::state_case_type (stream). */
uint8_t rome2_startup_fprintf_state_type_1168a52e(
    rome2_startup_fprintf_processor *proc)
{
    if (proc == NULL || proc->stream == NULL) {
        return 0u;
    }
    uint8_t spec = proc->base.current_ch;
    uint8_t ok = 0u;
    proc->base.suppress_output = 0u;
    switch (spec) {
    case 'd':
    case 'i':
        proc->base.flags |= 0x10u;
        ok = rome2_startup_nprintf_type_integer_1168b395(&proc->base, 10u, 0u);
        break;
    case 'u':
        ok = rome2_startup_nprintf_type_integer_1168b395(&proc->base, 10u, 0u);
        break;
    case 'o':
        ok = rome2_startup_nprintf_type_o_1168b6af(&proc->base);
        break;
    case 'x':
        ok = rome2_startup_nprintf_type_integer_1168b395(&proc->base, 16u, 0u);
        break;
    case 'X':
        ok = rome2_startup_nprintf_type_integer_1168b395(&proc->base, 16u, 1u);
        break;
    case 'p':
        ok = rome2_startup_nprintf_type_p_1168b6ed(&proc->base);
        break;
    case 'c':
    case 'C':
        ok = rome2_startup_nprintf_type_c_tchar_1168b26f(&proc->base);
        break;
    case 's':
    case 'S':
        ok = rome2_startup_nprintf_type_s_1168b71d(&proc->base);
        break;
    case 'Z':
        ok = rome2_startup_nprintf_type_Z_1168af07(&proc->base);
        break;
    case 'a':
    case 'A':
    case 'e':
    case 'E':
    case 'f':
    case 'F':
    case 'g':
    case 'G':
        ok = rome2_startup_nprintf_type_a_1168afbb(&proc->base);
        break;
    case 'n':
        if (proc->base.arg_idx < proc->base.arg_count) {
            proc->base.arg_idx++;
        }
        proc->base.suppress_output = 1u;
        ok = 1u;
        break;
    default:
        ok = 0u;
        break;
    }
    if (ok == 0u) {
        return 0u;
    }
    if (proc->base.suppress_output != 0u) {
        return 1u;
    }

    char prefix[4];
    int32_t prefix_len = 0;
    if ((proc->base.flags & 0x10u) != 0u) {
        if ((proc->base.flags & 0x40u) != 0u) {
            prefix[prefix_len++] = '-';
        } else if ((proc->base.flags & 0x01u) != 0u) {
            prefix[prefix_len++] = '+';
        } else if ((proc->base.flags & 0x02u) != 0u) {
            prefix[prefix_len++] = ' ';
        }
    }
    if (((spec == 'x' || spec == 'X') && (proc->base.flags & 0x20u) != 0u) ||
        spec == 'a' || spec == 'A') {
        prefix[prefix_len++] = '0';
        prefix[prefix_len++] = (spec == 'X' || spec == 'A') ? 'X' : 'x';
    }

    int32_t padding = proc->base.field_width - proc->base.str_len - prefix_len;
    if ((proc->base.flags & 0x0cu) == 0u) {
        rome2_startup_fprintf_write_multi_chars_11688d84(
            proc->stream, ' ', padding, &proc->base.characters_written);
    }
    if (prefix_len > 0) {
        rome2_startup_fprintf_write_string_dispatch_1168bc97(
            proc->stream, prefix, prefix_len, &proc->base.characters_written, &proc->base.last_errno);
    }
    if ((proc->base.flags & 0x08u) != 0u && (proc->base.flags & 0x04u) == 0u) {
        rome2_startup_fprintf_write_multi_chars_11688d84(
            proc->stream, '0', padding, &proc->base.characters_written);
    }
    (void)rome2_startup_fprintf_write_stored_tchar_1168ba23(proc);
    if (proc->base.characters_written >= 0 && (proc->base.flags & 0x04u) != 0u) {
        rome2_startup_fprintf_write_multi_chars_11688d84(
            proc->stream, ' ', padding, &proc->base.characters_written);
    }
    return 1u;
}

/* `0x11689515`: output_processor<char, stream_output_adapter<char>, format_validation_base>::process. */
int32_t rome2_startup_fprintf_process_11689515(
    rome2_startup_fprintf_processor *proc)
{
    if (proc == NULL || rome2_startup_fprintf_validate_adapter_1168b848(
                            proc, &proc->base.last_errno, &proc->base.invalid_param_count) == 0u) {
        return -1;
    }
    if (proc->base.fmt_cursor == NULL) {
        proc->base.last_errno = EINVAL;
        proc->base.invalid_param_count++;
        return -1;
    }
    for (;;) {
        proc->base.passes++;
        if (proc->base.passes == 2) {
            return proc->base.characters_written;
        }
        proc->base.str_len = 0;
        proc->base.state = 0;
        for (;;) {
            uint8_t ch = (uint8_t)*proc->base.fmt_cursor++;
            proc->base.current_ch = ch;
            if (ch == 0u || proc->base.characters_written < 0) {
                break;
            }
            uint32_t next_state = rome2_startup_fprintf_find_next_state_116892d1(ch, (uint32_t)proc->base.state);
            proc->base.state = (int32_t)next_state;
            if (next_state == 8u) {
                proc->base.last_errno = EINVAL;
                proc->base.invalid_param_count++;
                return -1;
            }
            if (next_state > 7u) {
                return -1;
            }
            uint8_t ok = 1u;
            switch (next_state) {
            case 0u:
                ok = rome2_startup_fprintf_state_normal_11689d5f(proc);
                break;
            case 1u:
                proc->base.precision = -1;
                proc->base.field_width = 0;
                proc->base.suppress_output = 0u;
                proc->base.flags = 0u;
                proc->base.length_mod = 0u;
                proc->base.is_wide = 0u;
                break;
            case 2u:
                ok = rome2_startup_nprintf_state_flag_11689ce5(&proc->base);
                break;
            case 3u:
                ok = rome2_startup_nprintf_state_width_1168ae5c(&proc->base);
                break;
            case 4u:
                proc->base.precision = 0;
                break;
            case 5u:
                ok = rome2_startup_nprintf_state_precision_11689f55(&proc->base);
                break;
            case 6u:
                ok = rome2_startup_fprintf_state_size_11689fa2(proc);
                break;
            case 7u:
                ok = rome2_startup_fprintf_state_type_1168a52e(proc);
                break;
            default:
                ok = 0u;
                break;
            }
            if (ok == 0u) {
                return -1;
            }
        }
        if (rome2_startup_fprintf_validate_size_1168b884(
                proc, &proc->base.last_errno, &proc->base.invalid_param_count) == 0u) {
            return -1;
        }
    }
}

/* `0x116890f3`: vfprintf guarded lambda wrapper. */
int32_t rome2_startup_vfprintf_lambda_116890f3(
    rome2_startup_fprintf_stream *stream,
    uint64_t options,
    const char *fmt,
    uint8_t has_locale,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno,
    uint32_t *out_invalid_param)
{
    rome2_startup_fprintf_processor proc;
    memset(&proc, 0, sizeof(proc));
    proc.stream = stream;
    proc.guest_adapter.stream_ptr_00 = stream != NULL ? 0x12034668u : 0u;
    proc.base.options = options;
    proc.base.has_locale = has_locale;
    proc.base.fmt_cursor = fmt;
    proc.base.args = args;
    proc.base.arg_count = arg_count;
    proc.base.precision = -1;
    proc.base.guest_state.adapter_ptr_448 = proc.guest_adapter.stream_ptr_00;

    int32_t written = rome2_startup_fprintf_process_11689515(&proc);
    if (out_errno != NULL && proc.base.last_errno != 0) {
        *out_errno = proc.base.last_errno;
    }
    if (out_invalid_param != NULL) {
        *out_invalid_param += proc.base.invalid_param_count;
    }
    return written;
}

/* `0x116880eb`: SEH unwind cleanup unlocking guest FILE*. */
void rome2_startup_vfprintf_unlock_116880eb(
    rome2_startup_fprintf_stream *stream)
{
    if (stream != NULL) {
        stream->unlock_count++;
    }
}

/* `0x1168809c`: __crt_seh_guarded_call<int>::operator() locking/unlocking FILE*. */
int32_t rome2_startup_vfprintf_guarded_lock_1168809c(
    rome2_startup_fprintf_stream *stream,
    uint64_t options,
    const char *fmt,
    uint8_t has_locale,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno,
    uint32_t *out_invalid_param)
{
    if (stream != NULL) {
        stream->lock_count++;
    }
    int32_t ret = rome2_startup_vfprintf_lambda_116890f3(
        stream, options, fmt, has_locale, args, arg_count, out_errno, out_invalid_param);
    rome2_startup_vfprintf_unlock_116880eb(stream);
    return ret;
}

/* `0x1168bfab`: common_vfprintf<format_validation_base, char>. */
int32_t rome2_startup_common_vfprintf_char_1168bfab(
    uint64_t options,
    rome2_startup_fprintf_stream *stream,
    const char *fmt,
    uint8_t has_locale,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno,
    uint32_t *out_invalid_param)
{
    if (stream == NULL || fmt == NULL) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        if (out_invalid_param != NULL) {
            (*out_invalid_param)++;
        }
        return -1;
    }
    return rome2_startup_vfprintf_guarded_lock_1168809c(
        stream, options, fmt, has_locale, args, arg_count, out_errno, out_invalid_param);
}

/* `0x100edfb0`: engine CRT fprintf wrapper forwarding [0x100de0d0] options + args. */
int32_t rome2_startup_crt_fprintf_100edfb0(
    rome2_startup_fprintf_stream *stream,
    const char *fmt,
    const uintptr_t *args,
    size_t arg_count,
    int32_t *out_errno,
    uint32_t *out_invalid_param)
{
    return rome2_startup_common_vfprintf_char_1168bfab(
        0ull, stream, fmt, 0u, args, arg_count, out_errno, out_invalid_param);
}

static uint8_t l64_read_raw_byte(rome2_startup_lowio_read_device *dev, uint8_t *out_ch)
{
    if (dev == NULL || dev->raw_bytes == NULL || dev->raw_pos >= dev->raw_len) {
        return 0u;
    }
    *out_ch = dev->raw_bytes[dev->raw_pos++];
    return 1u;
}

/* `0x116aa9e2`: narrow ANSI CR-LF -> LF and Ctrl-Z (^Z) text-mode translator. */
uint32_t rome2_startup_crt_translate_text_char_116aa9e2(
    rome2_startup_lowio_read_device *dev,
    uint8_t *buf,
    uint32_t bytes_read)
{
    if (dev == NULL || buf == NULL) {
        return 0u;
    }
    if (bytes_read != 0u && buf[0] == 0x0au) {
        dev->ioinfo.osfile_28 |= ROME2_STARTUP_LOWIO_FCRLF;
    } else {
        dev->ioinfo.osfile_28 &= (uint8_t)(~ROME2_STARTUP_LOWIO_FCRLF & 0xffu);
    }

    uint32_t p = 0u;
    uint32_t q = 0u;
    while (p < bytes_read) {
        uint8_t ch = buf[p];
        if (ch == 0x1au) {
            if ((dev->ioinfo.osfile_28 & ROME2_STARTUP_LOWIO_FDEV) == 0u) {
                dev->ioinfo.osfile_28 |= ROME2_STARTUP_LOWIO_FEOFLAG;
                break;
            }
            buf[q++] = 0x1au;
            p++;
            continue;
        }
        p++;
        if (ch != 0x0du) {
            buf[q++] = ch;
            continue;
        }
        if (p < bytes_read) {
            uint8_t next = buf[p];
            if (next == 0x0au) {
                buf[q++] = 0x0au;
                p++;
            } else {
                buf[q++] = 0x0du;
            }
        } else {
            uint8_t peek = 0u;
            if (l64_read_raw_byte(dev, &peek) != 0u) {
                if ((dev->ioinfo.osfile_28 & (ROME2_STARTUP_LOWIO_FPIPE | ROME2_STARTUP_LOWIO_FDEV)) != 0u) {
                    if (peek == 0x0au) {
                        buf[q++] = 0x0au;
                    } else {
                        buf[q++] = 0x0du;
                        dev->ioinfo.pipech2_2a[0] = peek;
                    }
                } else {
                    if (peek == 0x0au && q == 0u) {
                        buf[q++] = 0x0au;
                    } else {
                        /* Rewind regular file cursor 1 byte when peek is CR-split or non-LF at q > 0. */
                        if (dev->raw_pos > 0u) {
                            dev->raw_pos--;
                        }
                        buf[q++] = peek == 0x0au ? 0x0du : 0x0du;
                    }
                }
            } else {
                buf[q++] = 0x0du;
            }
        }
    }
    return q;
}

/* `0x116aab43`: UTF-16LE CR-LF -> LF and Ctrl-Z (^Z) text-mode translator. */
uint32_t rome2_startup_crt_translate_text_wchar_116aab43(
    rome2_startup_lowio_read_device *dev,
    uint16_t *wbuf,
    uint32_t wchar_count)
{
    if (dev == NULL || wbuf == NULL) {
        return 0u;
    }
    if (wchar_count != 0u && wbuf[0] == 0x000au) {
        dev->ioinfo.osfile_28 |= ROME2_STARTUP_LOWIO_FCRLF;
    } else {
        dev->ioinfo.osfile_28 &= (uint8_t)(~ROME2_STARTUP_LOWIO_FCRLF & 0xffu);
    }

    uint32_t p = 0u;
    uint32_t q = 0u;
    while (p < wchar_count) {
        uint16_t ch = wbuf[p];
        if (ch == 0x001au) {
            if ((dev->ioinfo.osfile_28 & ROME2_STARTUP_LOWIO_FDEV) == 0u) {
                dev->ioinfo.osfile_28 |= ROME2_STARTUP_LOWIO_FEOFLAG;
                break;
            }
            wbuf[q++] = 0x001au;
            p++;
            continue;
        }
        p++;
        if (ch != 0x000du) {
            wbuf[q++] = ch;
            continue;
        }
        if (p < wchar_count) {
            uint16_t next = wbuf[p];
            if (next == 0x000au) {
                wbuf[q++] = 0x000au;
                p++;
            } else {
                wbuf[q++] = 0x000du;
            }
        } else {
            uint8_t b0 = 0u;
            uint8_t b1 = 0u;
            if (l64_read_raw_byte(dev, &b0) != 0u && l64_read_raw_byte(dev, &b1) != 0u) {
                uint16_t peek = (uint16_t)b0 | ((uint16_t)b1 << 8);
                if ((dev->ioinfo.osfile_28 & (ROME2_STARTUP_LOWIO_FPIPE | ROME2_STARTUP_LOWIO_FDEV)) != 0u) {
                    if (peek == 0x000au) {
                        wbuf[q++] = 0x000au;
                    } else {
                        wbuf[q++] = 0x000du;
                        dev->ioinfo.pipech2_2a[0] = b0;
                        dev->ioinfo.pipech2_2a[1] = b1;
                        dev->ioinfo.pipech2_2a[2] = 0x0au;
                    }
                } else {
                    if (peek == 0x000au && q == 0u) {
                        wbuf[q++] = 0x000au;
                    } else {
                        if (dev->raw_pos >= 2u) {
                            dev->raw_pos -= 2u;
                        }
                        wbuf[q++] = 0x000du;
                    }
                }
            } else {
                wbuf[q++] = 0x000du;
            }
        }
    }
    return q * 2u;
}

/* `0x116aad14`: UTF-8 text-mode -> UTF-16LE translator splitting partial sequences across reads. */
int32_t rome2_startup_crt_translate_utf8_to_utf16_116aad14(
    rome2_startup_lowio_read_device *dev,
    uint8_t *raw_buf,
    uint32_t bytes_read,
    uint16_t *out_wbuf,
    uint32_t out_wchars)
{
    if (dev == NULL || raw_buf == NULL || out_wbuf == NULL) {
        return -1;
    }
    uint32_t trans_bytes = rome2_startup_crt_translate_text_char_116aa9e2(dev, raw_buf, bytes_read);
    if (trans_bytes == 0u) {
        return 0;
    }
    uint32_t end_bytes = trans_bytes;
    if (dev->ioinfo.textmode_29 != ROME2_STARTUP_LOWIO_TM_ANSI) {
        /* Scan backward up to 4 bytes checking for truncated multi-byte UTF-8 sequence. */
        uint32_t idx = trans_bytes - 1u;
        if ((raw_buf[idx] & 0x80u) != 0u) {
            uint32_t trail_len = 1u;
            while (trail_len <= 4u && idx > 0u && l64_utf8_trail_count(raw_buf[idx]) == 0) {
                if ((raw_buf[idx] & 0xc0u) != 0x80u) {
                    break;
                }
                idx--;
                trail_len++;
            }
            int32_t need_trail = l64_utf8_trail_count(raw_buf[idx]);
            if (need_trail == 0) {
                dev->last_errno = EILSEQ;
                return -1;
            }
            if ((uint32_t)(need_trail + 1) != trail_len) {
                if ((dev->ioinfo.osfile_28 & (ROME2_STARTUP_LOWIO_FPIPE | ROME2_STARTUP_LOWIO_FDEV)) != 0u) {
                    for (uint32_t k = 0u; k < trail_len && k < 3u; ++k) {
                        dev->ioinfo.pipech2_2a[k] = raw_buf[idx + k];
                    }
                } else {
                    if (dev->raw_pos >= (size_t)trail_len) {
                        dev->raw_pos -= (size_t)trail_len;
                    }
                }
                end_bytes = idx;
            }
        }
    }

    uint32_t wpos = 0u;
    uint32_t rpos = 0u;
    while (rpos < end_bytes && wpos < out_wchars) {
        uint8_t b0 = raw_buf[rpos++];
        uint32_t cp = b0;
        if (b0 < 0x80u) {
            out_wbuf[wpos++] = (uint16_t)cp;
        } else if ((b0 & 0xe0u) == 0xc0u && rpos < end_bytes) {
            uint8_t b1 = raw_buf[rpos++];
            if ((b1 & 0xc0u) != 0x80u) {
                dev->last_errno = EILSEQ;
                return -1;
            }
            cp = ((uint32_t)(b0 & 0x1fu) << 6) | (uint32_t)(b1 & 0x3fu);
            out_wbuf[wpos++] = (uint16_t)cp;
        } else if ((b0 & 0xf0u) == 0xe0u && rpos + 1u < end_bytes) {
            uint8_t b1 = raw_buf[rpos++];
            uint8_t b2 = raw_buf[rpos++];
            if ((b1 & 0xc0u) != 0x80u || (b2 & 0xc0u) != 0x80u) {
                dev->last_errno = EILSEQ;
                return -1;
            }
            cp = ((uint32_t)(b0 & 0x0fu) << 12) | ((uint32_t)(b1 & 0x3fu) << 6) | (uint32_t)(b2 & 0x3fu);
            out_wbuf[wpos++] = (uint16_t)cp;
        } else if ((b0 & 0xf8u) == 0xf0u && rpos + 2u < end_bytes && wpos + 1u < out_wchars) {
            uint8_t b1 = raw_buf[rpos++];
            uint8_t b2 = raw_buf[rpos++];
            uint8_t b3 = raw_buf[rpos++];
            if ((b1 & 0xc0u) != 0x80u || (b2 & 0xc0u) != 0x80u || (b3 & 0xc0u) != 0x80u) {
                dev->last_errno = EILSEQ;
                return -1;
            }
            cp = ((uint32_t)(b0 & 0x07u) << 18) | ((uint32_t)(b1 & 0x3fu) << 12) |
                 ((uint32_t)(b2 & 0x3fu) << 6) | (uint32_t)(b3 & 0x3fu);
            cp -= 0x10000u;
            out_wbuf[wpos++] = (uint16_t)(0xd800u + (cp >> 10));
            out_wbuf[wpos++] = (uint16_t)(0xdc00u + (cp & 0x3ffu));
        } else {
            dev->last_errno = EILSEQ;
            return -1;
        }
    }
    if (wpos == end_bytes) {
        dev->ioinfo.utf8_crlf_flags_2d |= 0x02u;
    } else {
        dev->ioinfo.utf8_crlf_flags_2d &= 0xfdu;
    }
    return (int32_t)(wpos * 2u);
}

/* `0x116aae6b`: ReadConsoleW UTF-16LE CR-LF -> LF / Ctrl-Z translator. */
uint32_t rome2_startup_crt_translate_utf16_crlf_116aae6b(
    rome2_startup_lowio_read_device *dev,
    uint16_t *wbuf,
    uint32_t wchar_count)
{
    if (dev == NULL || wbuf == NULL) {
        return 0u;
    }
    uint32_t p = 0u;
    uint32_t q = 0u;
    while (p < wchar_count) {
        uint16_t wc = wbuf[p];
        if (wc == 0x001au) {
            dev->ioinfo.osfile_28 |= ROME2_STARTUP_LOWIO_FEOFLAG;
            break;
        }
        if (wc == 0x000du && p + 1u < wchar_count && wbuf[p + 1u] == 0x000au) {
            wbuf[q++] = 0x000au;
            p += 2u;
        } else {
            wbuf[q++] = wc;
            p += 1u;
        }
    }
    return q * 2u;
}

/* `0x116aaffa`: __read_nolock lowio buffered / text / UTF-8 / UTF-16LE read. */
int32_t rome2_startup_crt_read_nolock_116aaffa(
    int32_t fh,
    rome2_startup_lowio_read_device *dev,
    void *dst_buf,
    uint32_t count)
{
    if (fh == -2 || fh < 0 || dev == NULL) {
        if (dev != NULL) {
            dev->last_doserrno = 0u;
            dev->last_errno = EBADF;
            dev->invalid_param_count++;
        }
        return -1;
    }
    if ((dev->ioinfo.osfile_28 & ROME2_STARTUP_LOWIO_FOPEN) == 0u) {
        dev->last_doserrno = 0u;
        dev->last_errno = EBADF;
        dev->invalid_param_count++;
        return -1;
    }
    if (count > 0x7fffffffu) {
        dev->last_doserrno = 0u;
        dev->last_errno = EINVAL;
        dev->invalid_param_count++;
        return -1;
    }
    if (count == 0u || (dev->ioinfo.osfile_28 & ROME2_STARTUP_LOWIO_FEOFLAG) != 0u) {
        return 0;
    }
    if (dst_buf == NULL) {
        dev->last_doserrno = 0u;
        dev->last_errno = EINVAL;
        dev->invalid_param_count++;
        return -1;
    }

    uint8_t textmode = dev->ioinfo.textmode_29;
    if ((textmode == ROME2_STARTUP_LOWIO_TM_UTF16LE || textmode == ROME2_STARTUP_LOWIO_TM_UTF8) &&
        (count & 1u) != 0u) {
        dev->last_doserrno = 0u;
        dev->last_errno = EINVAL;
        dev->invalid_param_count++;
        return -1;
    }

    if (dev->forced_win32_error != 0u) {
        uint32_t err = dev->forced_win32_error;
        if (err == 5u) {
            dev->last_errno = EBADF;
            dev->last_doserrno = 5u;
            return -1;
        }
        if (err == 109u) {
            return 0;
        }
        dev->last_doserrno = err;
        dev->last_errno = EINVAL;
        return -1;
    }

    uint8_t *out = (uint8_t *)dst_buf;
    uint32_t rem = count;
    uint32_t copied = 0u;
    uint8_t utf8_scratch[256];
    uint8_t *read_target = out;
    uint32_t read_cap = count;
    uint8_t used_console = 0u;

    if (textmode == ROME2_STARTUP_LOWIO_TM_UTF8) {
        uint32_t half = count / 2u;
        uint32_t want = half < 4u ? 4u : half;
        if (want > (uint32_t)sizeof(utf8_scratch)) {
            want = (uint32_t)sizeof(utf8_scratch);
        }
        dev->ioinfo.startpos_lo_20 = (uint32_t)(dev->raw_pos & 0xffffffffu);
        dev->ioinfo.startpos_hi_24 = (uint32_t)((dev->raw_pos >> 32) & 0xffffffffu);
        read_target = utf8_scratch;
        read_cap = want;
        rem = want;
    }

    if ((dev->ioinfo.osfile_28 & (ROME2_STARTUP_LOWIO_FPIPE | ROME2_STARTUP_LOWIO_FDEV)) != 0u) {
        for (uint32_t i = 0u; i < 3u; ++i) {
            if (dev->ioinfo.pipech2_2a[i] == 0x0au || rem == 0u) {
                break;
            }
            if (i == 2u && textmode != ROME2_STARTUP_LOWIO_TM_UTF8) {
                break;
            }
            read_target[copied++] = dev->ioinfo.pipech2_2a[i];
            dev->ioinfo.pipech2_2a[i] = 0x0au;
            rem--;
        }
    }

    if (dev->is_tty != 0u && (dev->ioinfo.osfile_28 & ROME2_STARTUP_LOWIO_FTEXT) != 0u &&
        dev->is_console_handle != 0u && textmode == ROME2_STARTUP_LOWIO_TM_UTF16LE) {
        used_console = 1u;
        uint32_t avail_words = rem / 2u;
        for (uint32_t w = 0u; w < avail_words; ++w) {
            if (dev->raw_pos + 1u >= dev->raw_len) {
                break;
            }
            read_target[copied++] = dev->raw_bytes[dev->raw_pos++];
            read_target[copied++] = dev->raw_bytes[dev->raw_pos++];
        }
    } else {
        while (copied < read_cap && dev->raw_pos < dev->raw_len) {
            read_target[copied++] = dev->raw_bytes[dev->raw_pos++];
        }
    }

    if ((dev->ioinfo.osfile_28 & ROME2_STARTUP_LOWIO_FTEXT) == 0u) {
        return (int32_t)copied;
    }
    if (textmode == ROME2_STARTUP_LOWIO_TM_UTF8) {
        return rome2_startup_crt_translate_utf8_to_utf16_116aad14(
            dev, utf8_scratch, copied, (uint16_t *)dst_buf, count / 2u);
    }
    if (textmode == ROME2_STARTUP_LOWIO_TM_UTF16LE) {
        if (used_console != 0u) {
            return (int32_t)rome2_startup_crt_translate_utf16_crlf_116aae6b(
                dev, (uint16_t *)dst_buf, copied / 2u);
        }
        return (int32_t)rome2_startup_crt_translate_text_wchar_116aab43(
            dev, (uint16_t *)dst_buf, copied / 2u);
    }
    return (int32_t)rome2_startup_crt_translate_text_char_116aa9e2(dev, out, copied);
}

/* `0x116aafc7`: SEH cleanup unlocking lowio handle slot. */
void rome2_startup_crt_read_unlock_116aafc7(
    rome2_startup_lowio_read_device *dev)
{
    if (dev != NULL) {
        dev->unlock_count++;
    }
}

/* `0x116aaee6`: _read locked SEH entrypoint. */
int32_t rome2_startup_crt_read_116aaee6(
    int32_t fh,
    rome2_startup_lowio_read_device *dev,
    void *dst_buf,
    uint32_t count)
{
    if (fh == -2 || fh < 0 || dev == NULL || (dev->ioinfo.osfile_28 & ROME2_STARTUP_LOWIO_FOPEN) == 0u) {
        if (dev != NULL) {
            dev->last_doserrno = 0u;
            dev->last_errno = EBADF;
            dev->invalid_param_count++;
        }
        return -1;
    }
    if (count > 0x7fffffffu) {
        dev->last_doserrno = 0u;
        dev->last_errno = EINVAL;
        dev->invalid_param_count++;
        return -1;
    }
    dev->lock_count++;
    int32_t ret = rome2_startup_crt_read_nolock_116aaffa(fh, dev, dst_buf, count);
    rome2_startup_crt_read_unlock_116aafc7(dev);
    return ret;
}

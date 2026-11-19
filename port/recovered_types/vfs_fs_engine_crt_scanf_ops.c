#include "vfs_fs_engine_crt_scanf_ops.h"

#include <string.h>

enum {
    ROME2_VFS_L54_ENOMEM = 12,
    ROME2_VFS_L54_EINVAL = 22,
    ROME2_VFS_L54_ERANGE = 34,
    ROME2_VFS_L54_EILSEQ = 42,
    ROME2_VFS_L54_IOEOF = 0x8,
    ROME2_VFS_L54_IOWRTA = 0xc0,
    ROME2_VFS_L54_IOBUFFER_CRT = 0x40,
    ROME2_VFS_L54_IOBUFFER_NONE = 0x400
};

static const uint32_t ROME2_VFS_L54_INVALID_SIZE = 0xffffffffu;

static void r2_l54_set_err(int32_t *out_errno, int32_t code) {
    if (out_errno) {
        *out_errno = code;
    }
}

static uint8_t r2_l54_isspace(char c) {
    return (c == ' ' || (c >= '\t' && c <= '\r')) ? 1u : 0u;
}

static int32_t r2_l54_digit(char c) {
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

static int32_t r2_l54_ascii_icmp_n(const char *a, const char *b, size_t n) {
    for (size_t i = 0u; i < n; ++i) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (unsigned char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (unsigned char)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
        if (ca == '\0') {
            return 0;
        }
    }
    return 0;
}

static int32_t r2_l54_wcsnicmp_85(const uint16_t *a, const uint16_t *b) {
    for (size_t i = 0u; i < 85u; ++i) {
        uint16_t ca = a[i];
        uint16_t cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (uint16_t)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (uint16_t)(cb + ('a' - 'A'));
        }
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
        if (ca == 0u) {
            return 0;
        }
    }
    return 0;
}

/* `0x1168f338` */
rome2_vfs_crt_input_char_source32_32 *rome2_vfs_crt_make_input_char_source(
    rome2_vfs_crt_input_char_source32_32 *out_src,
    uint32_t adapter_ptr,
    uint64_t width_limit,
    uint32_t ok_flag_slot) {
    if (!out_src) {
        return NULL;
    }
    memset(out_src, 0, sizeof(*out_src));
    out_src->adapter_ptr_00 = adapter_ptr;
    out_src->width_or_limit_lo_04 = (uint32_t)(width_limit & 0xffffffffULL);
    out_src->width_or_limit_hi_08 = (uint32_t)(width_limit >> 32);
    out_src->state_words_10[3] = ok_flag_slot;
    return out_src;
}

/* `0x11691750` */
uint64_t rome2_vfs_crt_parse_uint64_adapter(
    const char *str,
    size_t max_chars,
    size_t *out_consumed,
    int32_t base,
    uint8_t is_signed,
    uint8_t *out_succeeded,
    int32_t *out_errno) {
    if (out_succeeded) {
        *out_succeeded = 0u;
    }
    if (out_consumed) {
        *out_consumed = 0u;
    }
    if (!str || (base != 0 && (base < 2 || base > 36))) {
        r2_l54_set_err(out_errno, ROME2_VFS_L54_EINVAL);
        return 0ULL;
    }
    if (max_chars == 0u) {
        return 0ULL;
    }

    size_t pos = 0u;
    while (pos < max_chars && str[pos] != '\0' && r2_l54_isspace(str[pos]) != 0u) {
        ++pos;
    }
    uint32_t flags = is_signed ? 1u : 0u;
    if (pos < max_chars && str[pos] == '-') {
        flags |= 2u;
        ++pos;
    } else if (pos < max_chars && str[pos] == '+') {
        ++pos;
    }

    int32_t eff_base = base;
    if ((eff_base == 0 || eff_base == 16) && pos < max_chars && str[pos] == '0') {
        if (pos + 1u < max_chars && (str[pos + 1u] == 'x' || str[pos + 1u] == 'X')) {
            eff_base = 16;
            pos += 2u;
        } else if (eff_base == 0) {
            eff_base = 8;
        }
    } else if (eff_base == 0) {
        eff_base = 10;
    }

    uint64_t ubase = (uint64_t)(uint32_t)eff_base;
    uint64_t ub_div = UINT64_MAX / ubase;
    uint64_t ub_mod = UINT64_MAX % ubase;
    uint64_t number = 0ULL;

    while (pos < max_chars && str[pos] != '\0') {
        int32_t dv = r2_l54_digit(str[pos]);
        if (dv < 0 || dv >= eff_base) {
            break;
        }
        uint64_t ud = (uint64_t)(uint32_t)dv;
        if (number > ub_div || (number == ub_div && ud > ub_mod)) {
            flags |= 0x0cu;
        } else {
            number = number * ubase + ud;
            flags |= 0x08u;
        }
        ++pos;
    }

    if ((flags & 0x08u) == 0u) {
        return 0ULL;
    }
    if (out_consumed) {
        *out_consumed = pos;
    }
    if (out_succeeded) {
        *out_succeeded = 1u;
    }

    uint8_t overflow = 0u;
    if ((flags & 0x04u) != 0u) {
        overflow = 1u;
    } else if ((flags & 0x01u) != 0u) {
        overflow = ((flags & 0x02u) != 0u)
            ? (number > 0x8000000000000000ULL ? 1u : 0u)
            : (number > 0x7fffffffffffffffULL ? 1u : 0u);
    }

    if (overflow != 0u) {
        r2_l54_set_err(out_errno, ROME2_VFS_L54_ERANGE);
        if ((flags & 0x01u) == 0u) {
            return UINT64_MAX;
        }
        return ((flags & 0x02u) != 0u) ? 0x8000000000000000ULL : 0x7fffffffffffffffULL;
    }
    return ((flags & 0x02u) != 0u) ? (0ULL - number) : number;
}

static uint32_t r2_l54_int_length_from_mod(uint32_t len_mod) {
    switch (len_mod) {
    case 1u:
        return 1u; /* hh */
    case 2u:
        return 2u; /* h */
    case 4u:
    case 5u:
    case 6u:
    case 7u:
    case 9u:
        return 8u; /* ll / I64 / j / z / t */
    default:
        return 4u;
    }
}

static uint32_t r2_l54_float_length_from_mod(uint32_t len_mod) {
    return (len_mod == 3u || len_mod == 10u) ? 8u : 4u; /* l / L */
}

/* `0x11695bf3` */
uint32_t rome2_vfs_crt_scanf_format_length(
    const rome2_vfs_crt_fmt_parser76_32 *fmt) {
    if (!fmt) {
        return 0u;
    }
    uint32_t conv = fmt->conv_idx_28;
    if (conv <= 1u || conv == 8u) {
        return fmt->is_wide_24 != 0u ? 2u : 1u;
    }
    if ((conv >= 2u && conv <= 6u) || conv == 9u) {
        return r2_l54_int_length_from_mod(fmt->length_idx_20);
    }
    if (conv == 7u) {
        return r2_l54_float_length_from_mod(fmt->length_idx_20);
    }
    return 0u;
}

/* `0x116974ef` */
uint8_t rome2_vfs_crt_scanf_write_integer(
    const rome2_vfs_crt_fmt_parser76_32 *fmt,
    void *target_ptr,
    uint64_t value,
    int32_t *out_errno) {
    if (!target_ptr) {
        r2_l54_set_err(out_errno, ROME2_VFS_L54_EINVAL);
        return 0u;
    }
    uint32_t len = rome2_vfs_crt_scanf_format_length(fmt);
    switch (len) {
    case 1u:
        *(uint8_t *)target_ptr = (uint8_t)(value & 0xffULL);
        return 1u;
    case 2u:
        *(uint16_t *)target_ptr = (uint16_t)(value & 0xffffULL);
        return 1u;
    case 4u:
        *(uint32_t *)target_ptr = (uint32_t)(value & 0xffffffffULL);
        return 1u;
    case 8u:
        *(uint64_t *)target_ptr = value;
        return 1u;
    default:
        return 0u;
    }
}

/* `0x116960bc` */
uint8_t rome2_vfs_crt_scanf_process_integer_specifier(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    const char *stream_text,
    size_t *inout_cursor,
    size_t max_len,
    int32_t base,
    uint8_t is_signed,
    void *out_value,
    int32_t *out_errno) {
    if (!input_state || !stream_text || !inout_cursor || *inout_cursor > max_len) {
        return 0u;
    }
    size_t cur = *inout_cursor;
    while (cur < max_len && stream_text[cur] != '\0' && r2_l54_isspace(stream_text[cur]) != 0u) {
        ++cur;
    }
    size_t rem = max_len - cur;
    size_t lim = rem;
    if (input_state->fmt_18.width_18 > 0u && (size_t)input_state->fmt_18.width_18 < lim) {
        lim = (size_t)input_state->fmt_18.width_18;
    }
    size_t used = 0u;
    uint8_t ok = 0u;
    uint64_t val = rome2_vfs_crt_parse_uint64_adapter(
        stream_text + cur, lim, &used, base, is_signed, &ok, out_errno);
    if (ok == 0u) {
        return 0u;
    }
    *inout_cursor = cur + used;
    if (input_state->fmt_18.suppress_16 != 0u) {
        return 1u;
    }
    return rome2_vfs_crt_scanf_write_integer(&input_state->fmt_18, out_value, val, out_errno);
}

static uint8_t r2_l54_scanset_contains(const rome2_vfs_crt_fmt_parser76_32 *fmt, uint8_t ch) {
    uint32_t word_idx = (uint32_t)ch >> 5;
    uint32_t bit = 1u << ((uint32_t)ch & 31u);
    return (fmt->scanset_words_2c[word_idx] & bit) != 0u ? 1u : 0u;
}

/* `0x116923d9` */
uint8_t rome2_vfs_crt_scanf_process_string_narrow(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    const char *stream_text,
    size_t *inout_cursor,
    size_t max_len,
    uint32_t mode,
    uint8_t is_whitespace_delimited,
    char *out_buf,
    size_t out_cap,
    int32_t *out_errno) {
    (void)is_whitespace_delimited;
    if (!input_state || !stream_text || !inout_cursor || *inout_cursor > max_len) {
        return 0u;
    }
    if (input_state->fmt_18.suppress_16 == 0u && (!out_buf || out_cap == 0u)) {
        r2_l54_set_err(out_errno, ROME2_VFS_L54_EINVAL);
        return 0u;
    }
    size_t cur = *inout_cursor;
    size_t max_chars = max_len - cur;
    if (input_state->fmt_18.width_18 > 0u && (size_t)input_state->fmt_18.width_18 < max_chars) {
        max_chars = (size_t)input_state->fmt_18.width_18;
    } else if (mode == 0u && input_state->fmt_18.width_18 == 0u && max_chars > 1u) {
        max_chars = 1u;
    }

    size_t written = 0u;
    size_t cap_chars = input_state->fmt_18.suppress_16 == 0u
        ? (mode == 0u ? out_cap : out_cap - 1u)
        : SIZE_MAX;

    while (written < max_chars && stream_text[cur] != '\0') {
        char ch = stream_text[cur];
        if (mode == 1u && r2_l54_isspace(ch) != 0u) {
            break;
        }
        if (mode == 8u && r2_l54_scanset_contains(&input_state->fmt_18, (uint8_t)ch) == 0u) {
            break;
        }
        if (input_state->fmt_18.suppress_16 == 0u) {
            if (written >= cap_chars) {
                out_buf[0] = '\0';
                r2_l54_set_err(out_errno, ROME2_VFS_L54_ENOMEM);
                return 0u;
            }
            out_buf[written] = ch;
        }
        ++written;
        ++cur;
    }
    if (written == 0u || (mode == 0u && written < max_chars && input_state->fmt_18.width_18 > 0u)) {
        if (input_state->fmt_18.suppress_16 == 0u && out_cap > 0u) {
            out_buf[0] = '\0';
        }
        return 0u;
    }
    *inout_cursor = cur;
    if (input_state->fmt_18.suppress_16 == 0u && mode != 0u) {
        out_buf[written] = '\0';
    }
    return 1u;
}

/* `0x11692817` */
uint8_t rome2_vfs_crt_scanf_process_string_wide(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    const char *stream_text,
    size_t *inout_cursor,
    size_t max_len,
    uint32_t mode,
    uint8_t is_whitespace_delimited,
    uint16_t *out_buf,
    size_t out_cap_wchars,
    int32_t *out_errno) {
    (void)is_whitespace_delimited;
    if (!input_state || !stream_text || !inout_cursor || *inout_cursor > max_len) {
        return 0u;
    }
    if (input_state->fmt_18.suppress_16 == 0u && (!out_buf || out_cap_wchars == 0u)) {
        r2_l54_set_err(out_errno, ROME2_VFS_L54_EINVAL);
        return 0u;
    }
    size_t cur = *inout_cursor;
    size_t max_chars = max_len - cur;
    if (input_state->fmt_18.width_18 > 0u && (size_t)input_state->fmt_18.width_18 < max_chars) {
        max_chars = (size_t)input_state->fmt_18.width_18;
    } else if (mode == 0u && input_state->fmt_18.width_18 == 0u && max_chars > 1u) {
        max_chars = 1u;
    }

    size_t written = 0u;
    size_t cap_w = input_state->fmt_18.suppress_16 == 0u
        ? (mode == 0u ? out_cap_wchars : out_cap_wchars - 1u)
        : SIZE_MAX;

    while (written < max_chars && stream_text[cur] != '\0') {
        char ch = stream_text[cur];
        if (mode == 1u && r2_l54_isspace(ch) != 0u) {
            break;
        }
        if (mode == 8u && r2_l54_scanset_contains(&input_state->fmt_18, (uint8_t)ch) == 0u) {
            break;
        }
        if (input_state->fmt_18.suppress_16 == 0u) {
            if (written >= cap_w) {
                out_buf[0] = 0u;
                return 0u;
            }
            out_buf[written] = (uint8_t)ch;
        }
        ++written;
        ++cur;
    }
    if (written == 0u) {
        if (input_state->fmt_18.suppress_16 == 0u && out_cap_wchars > 0u) {
            out_buf[0] = 0u;
        }
        return 0u;
    }
    *inout_cursor = cur;
    if (input_state->fmt_18.suppress_16 == 0u && mode != 0u) {
        out_buf[written] = 0u;
    }
    return 1u;
}

/* `0x116963d4` */
uint8_t rome2_vfs_crt_scanf_process_string_specifier(
    const rome2_vfs_crt_scanf_input116_32 *input_state,
    const char *stream_text,
    size_t *inout_cursor,
    size_t max_len,
    uint32_t mode,
    void *out_buf,
    size_t out_cap_units,
    int32_t *out_errno) {
    if (!input_state || !stream_text || !inout_cursor || *inout_cursor > max_len) {
        return 0u;
    }
    if (mode == 1u) {
        while (*inout_cursor < max_len && stream_text[*inout_cursor] != '\0' &&
               r2_l54_isspace(stream_text[*inout_cursor]) != 0u) {
            ++(*inout_cursor);
        }
    }
    uint32_t char_bytes = rome2_vfs_crt_scanf_format_length(&input_state->fmt_18);
    if (char_bytes == 1u) {
        return rome2_vfs_crt_scanf_process_string_narrow(
            input_state, stream_text, inout_cursor, max_len, mode, 0u,
            (char *)out_buf, out_cap_units, out_errno);
    }
    if (char_bytes == 2u) {
        return rome2_vfs_crt_scanf_process_string_wide(
            input_state, stream_text, inout_cursor, max_len, mode, 0u,
            (uint16_t *)out_buf, out_cap_units, out_errno);
    }
    return 0u;
}

/* `0x1169e7db` */
int64_t rome2_vfs_crt_lseeki64_forward(
    int32_t fh,
    int64_t offset,
    int32_t origin,
    rome2_vfs_crt_lseeki64_fn impl_fn,
    void *ctx) {
    if (!impl_fn) {
        return -1LL;
    }
    return impl_fn(fh, offset, origin, ctx);
}

/* `0x1169e998` */
const char *rome2_vfs_crt_common_getenv_nolock(
    const char *varname,
    const char *const *envp,
    size_t env_count) {
    if (!envp || !varname) {
        return NULL;
    }
    size_t name_len = strlen(varname);
    for (size_t i = 0u; i < env_count; ++i) {
        const char *entry = envp[i];
        if (!entry) {
            continue;
        }
        size_t entry_len = strlen(entry);
        if (entry_len > name_len && entry[name_len] == '=' &&
            r2_l54_ascii_icmp_n(entry, varname, name_len) == 0) {
            return entry + name_len + 1u;
        }
    }
    return NULL;
}

/* `0x1169eadf` */
void rome2_vfs_crt_getenv_seh_unlock(
    rome2_vfs_crt_unlock_fn unlock_fn,
    void *ctx) {
    if (unlock_fn) {
        unlock_fn(0x0bu, ctx);
    }
}

/* `0x1169eb47` */
int32_t rome2_vfs_crt_common_getenv_s_nolock(
    size_t *out_required_bytes,
    char *buf,
    size_t size_in_bytes,
    const char *varname,
    const char *const *envp,
    size_t env_count,
    int32_t *out_errno) {
    if (!out_required_bytes) {
        r2_l54_set_err(out_errno, ROME2_VFS_L54_EINVAL);
        return ROME2_VFS_L54_EINVAL;
    }
    *out_required_bytes = 0u;
    if ((buf == NULL && size_in_bytes > 0u) || (buf != NULL && size_in_bytes == 0u) || !varname) {
        if (buf && size_in_bytes > 0u) {
            buf[0] = '\0';
        }
        r2_l54_set_err(out_errno, ROME2_VFS_L54_EINVAL);
        return ROME2_VFS_L54_EINVAL;
    }
    const char *val = rome2_vfs_crt_common_getenv_nolock(varname, envp, env_count);
    if (!val) {
        if (buf && size_in_bytes > 0u) {
            buf[0] = '\0';
        }
        return 0;
    }
    size_t need = strlen(val) + 1u;
    *out_required_bytes = need;
    if (!buf) {
        return 0;
    }
    if (size_in_bytes < need) {
        buf[0] = '\0';
        r2_l54_set_err(out_errno, ROME2_VFS_L54_ERANGE);
        return ROME2_VFS_L54_ERANGE;
    }
    memcpy(buf, val, need);
    return 0;
}

/* `0x116a5645` */
uint8_t rome2_vfs_crt_write_buffer_nolock_char(
    uint8_t ch,
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint8_t *host_buf,
    size_t host_buf_cap,
    size_t *inout_pos,
    uint8_t is_append_mode,
    rome2_vfs_crt_lowio_seek_fn seek_fn,
    rome2_vfs_crt_lowio_write_fn write_fn,
    void *ctx) {
    if (!stream || !write_fn) {
        return 0u;
    }
    if ((stream->flags_0c & ROME2_VFS_L54_IOWRTA) != 0u) {
        size_t pos = inout_pos ? *inout_pos : 0u;
        uint32_t to_flush = (uint32_t)pos;
        if (host_buf && host_buf_cap > 0u) {
            if (inout_pos) {
                *inout_pos = 1u;
            }
            stream->cnt_08 = stream->bufsiz_18 - 1;
            int32_t written = 0;
            if (to_flush > 0u) {
                if (is_append_mode != 0u && seek_fn) {
                    (void)seek_fn(stream->file_10, 0LL, 2, ctx);
                }
                written = write_fn(stream->file_10, host_buf, to_flush, ctx);
                if (written < 0 || (uint32_t)written != to_flush) {
                    return 0u;
                }
            }
            host_buf[0] = ch;
            return 1u;
        }
        return write_fn(stream->file_10, &ch, 1u, ctx) == 1 ? 1u : 0u;
    }
    return write_fn(stream->file_10, &ch, 1u, ctx) == 1 ? 1u : 0u;
}

/* `0x116a5711` */
uint8_t rome2_vfs_crt_write_buffer_nolock_wchar(
    uint16_t wch,
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint8_t *host_buf,
    size_t host_buf_cap,
    size_t *inout_pos,
    uint8_t is_append_mode,
    rome2_vfs_crt_lowio_seek_fn seek_fn,
    rome2_vfs_crt_lowio_write_fn write_fn,
    void *ctx) {
    uint8_t le_pair[2] = { (uint8_t)(wch & 0xffu), (uint8_t)((wch >> 8) & 0xffu) };
    if (!stream || !write_fn) {
        return 0u;
    }
    if ((stream->flags_0c & ROME2_VFS_L54_IOWRTA) != 0u) {
        size_t pos = inout_pos ? *inout_pos : 0u;
        uint32_t to_flush = (uint32_t)pos;
        if (host_buf && host_buf_cap >= 2u) {
            if (inout_pos) {
                *inout_pos = 2u;
            }
            stream->cnt_08 = stream->bufsiz_18 - 2;
            if (to_flush > 0u) {
                if (is_append_mode != 0u && seek_fn) {
                    (void)seek_fn(stream->file_10, 0LL, 2, ctx);
                }
                int32_t written = write_fn(stream->file_10, host_buf, to_flush, ctx);
                if (written < 0 || (uint32_t)written != to_flush) {
                    return 0u;
                }
            }
            host_buf[0] = le_pair[0];
            host_buf[1] = le_pair[1];
            return 1u;
        }
        return write_fn(stream->file_10, le_pair, 2u, ctx) == 2 ? 1u : 0u;
    }
    return write_fn(stream->file_10, le_pair, 2u, ctx) == 2 ? 1u : 0u;
}

/* `0x116a57df` */
uint8_t rome2_vfs_crt_is_at_eof_for_write_transition(
    const rome2_vfs_crt_stdio_stream56_32 *stream,
    uint8_t has_valid_os_handle,
    uint8_t seek_ok,
    int64_t current_pos,
    uint8_t size_ok,
    int64_t file_size) {
    if (!stream) {
        return 0u;
    }
    if ((stream->flags_0c & ROME2_VFS_L54_IOEOF) != 0u) {
        return 1u;
    }
    if (has_valid_os_handle == 0u || seek_ok == 0u || size_ok == 0u) {
        return 0u;
    }
    return current_pos == file_size ? 1u : 0u;
}

/* `0x116a6534` */
void rome2_vfs_crt_fp_shift_bytes_right(
    char *buf,
    size_t buf_cap,
    size_t start_off,
    size_t count) {
    if (!buf || count == 0u || start_off >= buf_cap) {
        return;
    }
    size_t avail = buf_cap - start_off;
    size_t tail_len = 0u;
    while (tail_len < avail && buf[start_off + tail_len] != '\0') {
        ++tail_len;
    }
    if (tail_len + count + 1u > avail) {
        return;
    }
    memmove(buf + start_off + count, buf + start_off, tail_len + 1u);
}

/* `0x116a83d7` */
uint32_t rome2_vfs_crt_try_get_locale_name_to_lcid(
    rome2_vfs_crt_resolve_api54_fn resolve_fn,
    void *ctx) {
    static const rome2_vfs_crt_api_mod_desc8_32 k_mods[2] = {
        { 3u, 16u }, /* 0x11914d84 */
        { 0u, 0u },  /* end marker at 0x11914d8c */
    };
    if (!resolve_fn) {
        return 0u;
    }
    return resolve_fn(0x16u, "LocaleNameToLCID", &k_mods[0], &k_mods[1], ctx);
}

/* `0x116b14bc` */
uint32_t rome2_vfs_crt_c32rtomb_utf8(
    uint8_t *dst,
    size_t dst_cap,
    uint32_t c32,
    rome2_vfs_crt_mbstate8_32 *ps,
    int32_t *out_errno) {
    if (!ps) {
        return ROME2_VFS_L54_INVALID_SIZE;
    }
    if (!dst) {
        ps->wchar_00 = 0u;
        ps->byte_04 = 0u;
        ps->state_06 = 0u;
        return 1u;
    }
    if (c32 == 0u) {
        if (dst_cap == 0u) {
            r2_l54_set_err(out_errno, ROME2_VFS_L54_ERANGE);
            return ROME2_VFS_L54_INVALID_SIZE;
        }
        dst[0] = 0u;
        ps->wchar_00 = 0u;
        ps->byte_04 = 0u;
        ps->state_06 = 0u;
        return 1u;
    }
    if (c32 <= 0x7fu) {
        if (dst_cap == 0u) {
            r2_l54_set_err(out_errno, ROME2_VFS_L54_ERANGE);
            return ROME2_VFS_L54_INVALID_SIZE;
        }
        dst[0] = (uint8_t)c32;
        return 1u;
    }
    if ((c32 >= 0xd800u && c32 <= 0xdfffu) || c32 > 0x10ffffu) {
        ps->wchar_00 = 0u;
        ps->byte_04 = 0u;
        ps->state_06 = 0u;
        r2_l54_set_err(out_errno, ROME2_VFS_L54_EILSEQ);
        return ROME2_VFS_L54_INVALID_SIZE;
    }

    uint32_t need = 0u;
    uint8_t out_tmp[4] = { 0u, 0u, 0u, 0u };
    if (c32 <= 0x7ffu) {
        out_tmp[0] = (uint8_t)(0xc0u | (c32 >> 6));
        out_tmp[1] = (uint8_t)(0x80u | (c32 & 0x3fu));
        need = 2u;
    } else if (c32 <= 0xffffu) {
        out_tmp[0] = (uint8_t)(0xe0u | (c32 >> 12));
        out_tmp[1] = (uint8_t)(0x80u | ((c32 >> 6) & 0x3fu));
        out_tmp[2] = (uint8_t)(0x80u | (c32 & 0x3fu));
        need = 3u;
    } else {
        out_tmp[0] = (uint8_t)(0xf0u | (c32 >> 18));
        out_tmp[1] = (uint8_t)(0x80u | ((c32 >> 12) & 0x3fu));
        out_tmp[2] = (uint8_t)(0x80u | ((c32 >> 6) & 0x3fu));
        out_tmp[3] = (uint8_t)(0x80u | (c32 & 0x3fu));
        need = 4u;
    }

    if (dst_cap < need) {
        r2_l54_set_err(out_errno, ROME2_VFS_L54_ERANGE);
        return ROME2_VFS_L54_INVALID_SIZE;
    }
    memcpy(dst, out_tmp, need);
    ps->wchar_00 = 0u;
    ps->byte_04 = 0u;
    ps->state_06 = 0u;
    return need;
}

/* `0x116b1c0d` */
void rome2_vfs_crt_stdio_allocate_buffer_nolock(
    rome2_vfs_crt_stdio_stream56_32 *stream,
    uint32_t allocated_buf_guest_ptr,
    uint32_t inline_charbuf_guest_ptr,
    uint32_t *inout_cflush) {
    if (!stream) {
        return;
    }
    if (inout_cflush) {
        ++(*inout_cflush);
    }
    stream->base_04 = allocated_buf_guest_ptr;
    int32_t sz = 0x1000;
    if (stream->base_04 != 0u) {
        stream->flags_0c |= ROME2_VFS_L54_IOBUFFER_CRT;
    } else {
        stream->flags_0c |= ROME2_VFS_L54_IOBUFFER_NONE;
        stream->base_04 = inline_charbuf_guest_ptr;
        sz = 2;
    }
    stream->bufsiz_18 = sz;
    stream->cnt_08 = 0;
    stream->ptr_00 = stream->base_04;
}

/* `0x116b80ef` */
int32_t rome2_vfs_crt_downlevel_locale_index(
    const uint16_t *name,
    const rome2_vfs_crt_locale_entry_pair *sorted_entries,
    size_t entry_count) {
    if (!name || !sorted_entries || entry_count == 0u) {
        return -1;
    }
    int32_t lo = 0;
    int32_t hi = (int32_t)entry_count - 1;
    while (lo <= hi) {
        int32_t mid = lo + (hi - lo) / 2;
        int32_t cmp = r2_l54_wcsnicmp_85(name, sorted_entries[mid].name);
        if (cmp == 0) {
            return sorted_entries[mid].table_idx;
        }
        if (cmp < 0) {
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    return -1;
}

/* `0x116b81e9` */
uint32_t rome2_vfs_crt_downlevel_locale_name_to_lcid(
    const uint16_t *name,
    const rome2_vfs_crt_locale_entry_pair *sorted_entries,
    const uint32_t *lcid_by_idx,
    size_t entry_count) {
    if (!name || !sorted_entries || !lcid_by_idx || entry_count == 0u) {
        return 0u;
    }
    int32_t idx = rome2_vfs_crt_downlevel_locale_index(name, sorted_entries, entry_count);
    if (idx < 0 || (size_t)idx >= entry_count) {
        return 0u;
    }
    return lcid_by_idx[idx];
}

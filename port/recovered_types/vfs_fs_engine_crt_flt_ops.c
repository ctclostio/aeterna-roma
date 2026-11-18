#include "vfs_fs_engine_crt_flt_ops.h"

#include <errno.h>
#include <math.h>
#include <string.h>

void rome2_vfs_crt_clear_u32_flag(uint32_t *flag)
{
    if (flag) {
        *flag = 0u;
    }
}

rome2_vfs_crt_output_adapter_base *rome2_vfs_crt_output_adapter_base_init(
    rome2_vfs_crt_output_adapter_base *self)
{
    size_t i;
    if (!self) {
        return NULL;
    }
    for (i = 0u; i < 11u; ++i) {
        self->header_dwords_00[i] = 0u;
    }
    self->byte_30 = 0u;
    self->word_32 = 0u;
    self->dword_38 = 0u;
    self->byte_3c = 0u;
    self->dword_440 = 0u;
    self->dword_444 = 0u;
    return self;
}

uint8_t rome2_vfs_crt_win32_buffer_deallocate(
    rome2_vfs_crt_win32_buffer24_32 *buf,
    uint32_t *out_freed_va)
{
    if (out_freed_va) {
        *out_freed_va = 0u;
    }
    if (!buf || buf->allocated_14 == 0u) {
        return 0u;
    }
    if (out_freed_va) {
        *out_freed_va = buf->data_08;
    }
    buf->allocated_14 = 0u;
    return 1u;
}

int32_t rome2_vfs_crt_win32_buffer_alloc_wchar(
    rome2_vfs_crt_win32_buffer24_32 *buf,
    uint32_t count_words,
    int32_t alloc_err,
    uint32_t alloc_va,
    uint32_t *out_freed_va,
    uint32_t *out_alloc_bytes)
{
    if (out_freed_va) {
        *out_freed_va = 0u;
    }
    if (out_alloc_bytes) {
        *out_alloc_bytes = 0u;
    }
    if (!buf) {
        return ROME2_VFS_L44_EINVAL_MSVC;
    }
    (void)rome2_vfs_crt_win32_buffer_deallocate(buf, out_freed_va);
    if (out_alloc_bytes) {
        *out_alloc_bytes = count_words * 2u;
    }
    if (alloc_err != 0) {
        buf->capacity_words_0c = 0u;
        buf->allocated_14 = 0u;
        return alloc_err;
    }
    buf->data_08 = alloc_va;
    buf->allocated_14 = 1u;
    buf->capacity_words_0c = count_words;
    return 0;
}

void rome2_vfs_crt_free_wrap(
    uint8_t ptr_non_null,
    uint8_t heap_free_ok,
    uint32_t last_err,
    int32_t *out_errno)
{
    rome2_vfs_crt_free_check(ptr_non_null, heap_free_ok, last_err, out_errno);
}

uint8_t rome2_vfs_crt_unpack_loctotime_args(
    const uint16_t *yr,
    const uint16_t *mon,
    const uint16_t *day,
    const uint16_t *hr,
    const uint16_t *min,
    const uint16_t *sec,
    const int32_t *isdst,
    uint32_t out_args[7])
{
    if (!yr || !mon || !day || !hr || !min || !sec || !isdst || !out_args) {
        return 0u;
    }
    out_args[0] = (uint32_t)*yr;
    out_args[1] = (uint32_t)*mon;
    out_args[2] = (uint32_t)*day;
    out_args[3] = (uint32_t)*hr;
    out_args[4] = (uint32_t)*min;
    out_args[5] = (uint32_t)*sec;
    out_args[6] = (uint32_t)*isdst;
    return 1u;
}

uint32_t rome2_vfs_crt_getptd_or_abort(
    uint32_t fls_index,
    uint32_t existing_ptd_va,
    uint32_t alloc_ptd_va,
    uint8_t fls_set_ok,
    uint8_t *out_initialized_new,
    uint8_t *out_freed_on_fail,
    uint8_t *out_aborted)
{
    uint32_t ptd_va = rome2_vfs_crt_getptd_resolve(
        fls_index,
        existing_ptd_va,
        alloc_ptd_va,
        fls_set_ok,
        out_initialized_new,
        out_freed_on_fail);
    if (out_aborted) {
        *out_aborted = (ptd_va == 0u) ? 1u : 0u;
    }
    return ptd_va;
}

uint8_t rome2_vfs_crt_stdio_begin_tmpbuf_nolock(
    rome2_vfs_crt_filex56_32 *stream,
    uint32_t stream_va,
    uint8_t is_tty,
    uint32_t stream_slot,
    uint32_t *inout_cflush,
    uint32_t *inout_slot_buf_va,
    uint32_t alloc_buf_va)
{
    if (!stream || !inout_cflush || !inout_slot_buf_va || is_tty == 0u) {
        return 0u;
    }
    if (stream_slot != 1u && stream_slot != 2u) {
        return 0u;
    }
    (*inout_cflush)++;
    if ((stream->flag_0c & ROME2_VFS_L44_STDIO_BLOCK_MASK) != 0u) {
        return 0u;
    }
    stream->flag_0c |= ROME2_VFS_L44_STDIO_TMPBUF_FLAGS;
    if (*inout_slot_buf_va == 0u) {
        *inout_slot_buf_va = alloc_buf_va;
    }
    if (*inout_slot_buf_va == 0u) {
        /* Fallback uses inline 2-byte charbuf at +0x14; UCRT places _base at +0x04 and _cnt at +0x08. */
        uint32_t inline_va = stream_va + 0x14u;
        stream->ptr_00 = inline_va;
        stream->cnt_04 = inline_va;
        stream->base_08 = 2u;
        stream->bufsiz_18 = 2u;
        return 1u;
    }
    stream->ptr_00 = *inout_slot_buf_va;
    stream->cnt_04 = *inout_slot_buf_va;
    stream->base_08 = ROME2_VFS_L44_STDIO_TMPBUF_SIZE;
    stream->bufsiz_18 = ROME2_VFS_L44_STDIO_TMPBUF_SIZE;
    return 1u;
}

uint8_t rome2_vfs_crt_stdio_end_tmpbuf_nolock(
    uint8_t enabled_flag,
    rome2_vfs_crt_filex56_32 *stream)
{
    uint8_t did_flush = 0u;
    if (enabled_flag == 0u || !stream) {
        return 0u;
    }
    if ((stream->flag_0c & ROME2_VFS_L44_STDIO_ALLOCATED_BIT) != 0u) {
        did_flush = 1u;
        stream->flag_0c &= ~0x280u;
        stream->bufsiz_18 = 0u;
        stream->cnt_04 = 0u;
        stream->ptr_00 = 0u;
    }
    return did_flush;
}

uint8_t rome2_vfs_crt_sync_ptd_global_slot(
    const rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t per_thread_flag_mask,
    uint32_t global_va,
    uint32_t refreshed_va,
    uint32_t *inout_slot_va)
{
    if (!ptd || !inout_slot_va) {
        return 0u;
    }
    if (*inout_slot_va != global_va && (ptd->ownlocale_350 & per_thread_flag_mask) == 0u) {
        *inout_slot_va = refreshed_va;
        return 1u;
    }
    return 0u;
}

int32_t rome2_vfs_crt_fp_classify_bits(uint64_t f64_bits)
{
    uint32_t lo = (uint32_t)(f64_bits & 0xffffffffu);
    uint32_t hi = (uint32_t)(f64_bits >> 32);
    uint32_t exp = (hi >> 20) & 0x7ffu;
    uint32_t frac_hi;

    if (exp != 0x7ffu) {
        return 0;
    }
    frac_hi = hi & 0xfffffu;
    if ((lo | frac_hi) == 0u) {
        return 1;
    }
    if (((int32_t)hi < 0) && lo == 0u && frac_hi == 0x80000u) {
        return 4;
    }
    if ((hi & 0x80000u) != 0u) {
        return 2;
    }
    return 3;
}

int32_t rome2_vfs_crt_fp_classify_ptr(const double *px)
{
    uint64_t bits = 0u;
    if (!px) {
        return 0;
    }
    (void)memcpy(&bits, px, sizeof(bits));
    return rome2_vfs_crt_fp_classify_bits(bits);
}

int32_t rome2_vfs_crt_sptype_bits(uint64_t f64_bits)
{
    uint32_t lo = (uint32_t)(f64_bits & 0xffffffffu);
    uint32_t hi = (uint32_t)(f64_bits >> 32);
    uint16_t top16 = (uint16_t)(hi >> 16);
    uint16_t tagged;

    if (hi == 0x7ff00000u && lo == 0u) {
        return 1;
    }
    if (hi == 0xfff00000u && lo == 0u) {
        return 2;
    }
    tagged = (uint16_t)(top16 & 0x7ff8u);
    if (tagged == 0x7ff8u) {
        return 3;
    }
    if (tagged == 0x7ff0u && (((hi & 0x7ffffu) != 0u) || lo != 0u)) {
        return 4;
    }
    return 0;
}

int32_t rome2_vfs_crt_sptype_f64(double x)
{
    uint64_t bits = 0u;
    (void)memcpy(&bits, &x, sizeof(bits));
    return rome2_vfs_crt_sptype_bits(bits);
}

uint32_t rome2_vfs_crt_normalize_mbtowc_flags(uint32_t code_page, uint32_t dw_flags)
{
    if (code_page == 0x2au ||
        (code_page >= 0xc42cu && code_page <= 0xc42eu) ||
        code_page == 0xc431u ||
        code_page == 0xc433u ||
        code_page == 0xc435u ||
        (code_page >= 0xdeaau && code_page <= 0xdeb3u) ||
        code_page == 0xfde8u ||
        code_page == 0xfde9u) {
        return 0u;
    }
    if (code_page == 0xd698u) {
        return dw_flags & 8u;
    }
    return dw_flags;
}

uint32_t rome2_vfs_crt_are_file_apis_ansi_dispatch(
    uint32_t resolved_proc_va,
    uint32_t invoked_result,
    uint8_t *out_invoked)
{
    if (resolved_proc_va != 0u) {
        if (out_invoked) {
            *out_invoked = 1u;
        }
        return invoked_result;
    }
    if (out_invoked) {
        *out_invoked = 0u;
    }
    return 1u;
}

uint8_t rome2_vfs_crt_fls_dispatch_mode(
    uint32_t api_id,
    uint32_t resolved_proc_va,
    uint8_t *out_cfg_checked)
{
    uint8_t use_fls = ((api_id == ROME2_VFS_L44_FLS_GET_VALUE_API || api_id == ROME2_VFS_L44_FLS_SET_VALUE_API) &&
                       resolved_proc_va != 0u)
                          ? 1u
                          : 0u;
    if (out_cfg_checked) {
        *out_cfg_checked = use_fls;
    }
    return use_fls;
}

int32_t rome2_vfs_crt_fp_strflt_to_string(
    char *buf,
    size_t size_in_bytes,
    int32_t digits,
    rome2_vfs_crt_strflt12_32 *flt,
    const char *src_digits,
    int32_t *out_errno)
{
    size_t need;
    size_t out_idx;
    size_t src_idx = 0u;
    int32_t rem = digits;

    if (!buf || size_in_bytes == 0u) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return ROME2_VFS_L44_EINVAL_MSVC;
    }
    buf[0] = '\0';
    need = (size_t)((digits > 0) ? digits : 0) + 1u;
    if (size_in_bytes <= need) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_ERANGE_MSVC;
        }
        return ROME2_VFS_L44_ERANGE_MSVC;
    }
    if (!flt || !src_digits) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return ROME2_VFS_L44_EINVAL_MSVC;
    }

    buf[0] = '0';
    out_idx = 1u;
    while (rem > 0) {
        char ch = src_digits[src_idx];
        if (ch != '\0') {
            src_idx++;
        } else {
            ch = '0';
        }
        buf[out_idx++] = ch;
        rem--;
    }
    buf[out_idx] = '\0';

    if (rem >= 0 && src_digits[src_idx] >= '5') {
        size_t pos = out_idx;
        while (pos > 0u) {
            pos--;
            if (buf[pos] == '9') {
                buf[pos] = '0';
            } else {
                buf[pos] = (char)(buf[pos] + 1);
                break;
            }
        }
    }

    if (buf[0] == '1') {
        flt->decpt_04 += 1;
    } else {
        size_t tail_len = strlen(buf + 1u) + 1u;
        (void)rome2_vfs_crt_memmove(buf, buf + 1u, tail_len);
    }
    if (out_errno) {
        *out_errno = 0;
    }
    return 0;
}

uint8_t rome2_vfs_crt_calloc_plan(
    uint32_t count,
    uint32_t elem_size,
    uint32_t *out_alloc_bytes,
    int32_t *out_errno)
{
    uint32_t total;
    if (count != 0u && (0xffffffe0u / count) < elem_size) {
        if (out_alloc_bytes) {
            *out_alloc_bytes = 0u;
        }
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_ENOMEM_MSVC;
        }
        return 0u;
    }
    total = count * elem_size;
    if (total == 0u) {
        total = 1u;
    }
    if (out_alloc_bytes) {
        *out_alloc_bytes = total;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    return 1u;
}

int32_t rome2_vfs_crt_ctrlfp(
    uint16_t current_cw,
    uint32_t new_val,
    uint32_t mask,
    uint16_t *out_next_cw)
{
    uint16_t next = (uint16_t)((current_cw & (uint16_t)(~mask)) | ((uint16_t)(new_val & mask)));
    if (out_next_cw) {
        *out_next_cw = next;
    }
    return (int32_t)(int16_t)current_cw;
}

uint8_t rome2_vfs_crt_has_user_matherr(uint32_t encoded_handler, uint32_t security_cookie)
{
    return (rome2_vfs_crt_decode_pointer32(encoded_handler, security_cookie) != 0u) ? 1u : 0u;
}

int32_t rome2_vfs_crt_fegetenv(rome2_vfs_crt_fp_env8_32 *env, uint32_t w0, uint32_t w1)
{
    if (!env) {
        return 1;
    }
    env->word0_00 = w0;
    env->word1_04 = w1;
    return 0;
}

int32_t rome2_vfs_crt_fesetenv_verify(
    const rome2_vfs_crt_fp_env8_32 *target,
    int32_t readback_rc,
    const rome2_vfs_crt_fp_env8_32 *readback)
{
    if (!target || !readback || readback_rc != 0) {
        return 1;
    }
    if (readback->word0_00 == target->word0_00 && readback->word1_04 == target->word1_04) {
        return 0;
    }
    return 1;
}

int32_t rome2_vfs_crt_feholdexcept(
    const rome2_vfs_crt_fp_env8_32 *current,
    rome2_vfs_crt_fp_env8_32 *out_saved,
    int32_t apply_verify_rc,
    uint32_t *out_masked_w0,
    uint8_t *out_cleared_fp)
{
    if (!current || !out_saved) {
        if (out_cleared_fp) {
            *out_cleared_fp = 0u;
        }
        return 1;
    }
    out_saved->word0_00 = current->word0_00;
    out_saved->word1_04 = current->word1_04;
    if (out_masked_w0) {
        *out_masked_w0 = current->word0_00 | 0x1fu;
    }
    if (apply_verify_rc != 0) {
        if (out_cleared_fp) {
            *out_cleared_fp = 0u;
        }
        return 1;
    }
    if (out_cleared_fp) {
        *out_cleared_fp = 1u;
    }
    return 0;
}

uint8_t rome2_vfs_crt_libm_use_sse2_fastpath(
    uint32_t sse2_enabled,
    uint32_t mxcsr,
    uint16_t x87_cw)
{
    if (sse2_enabled == 0u) {
        return 0u;
    }
    if ((mxcsr & 0x7f80u) != 0x1f80u) {
        return 0u;
    }
    return ((x87_cw & 0x7fu) == 0x7fu) ? 1u : 0u;
}

double rome2_vfs_crt_frnd(double x)
{
    return nearbyint(x);
}

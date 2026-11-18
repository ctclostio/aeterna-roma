#include "vfs_fs_engine_crt_env_ops.h"

#include <errno.h>
#include <math.h>
#include <string.h>

static void l45_parser_fail_reset(rome2_vfs_crt_fmt_parser76_32 *fp, int32_t err_code)
{
    fp->mode_10 = 0u;
    fp->lit_ch_14 = 0u;
    fp->suppress_16 = 0u;
    fp->width_18 = 0u;
    fp->length_mod_1c = 0u;
    fp->length_idx_20 = 0u;
    fp->is_wide_24 = 0u;
    fp->conv_idx_28 = 0u;
    fp->err_0c = err_code;
}

static uint8_t l45_is_slash_w(uint16_t ch)
{
    return (ch == (uint16_t)'\\' || ch == (uint16_t)'/') ? 1u : 0u;
}

static uint8_t l45_is_ascii_alpha_w(uint16_t ch)
{
    return ((ch >= (uint16_t)'A' && ch <= (uint16_t)'Z') ||
            (ch >= (uint16_t)'a' && ch <= (uint16_t)'z'))
               ? 1u
               : 0u;
}

static uint32_t l45_hw_fp_to_sw(uint32_t hw)
{
    uint32_t sw;
    if ((hw & 0x3fu) == 0u) {
        return 0u;
    }
    sw = (hw & 1u) << 4;
    if ((hw & 0x04u) != 0u) {
        sw |= ROME2_VFS_L45_FP_SW_ZERODIVIDE;
    }
    if ((hw & 0x08u) != 0u) {
        sw |= ROME2_VFS_L45_FP_SW_OVERFLOW;
    }
    if ((hw & 0x10u) != 0u) {
        sw |= ROME2_VFS_L45_FP_SW_UNDERFLOW;
    }
    if ((hw & 0x20u) != 0u) {
        sw |= ROME2_VFS_L45_FP_SW_INEXACT;
    }
    if ((hw & 0x02u) != 0u) {
        sw |= ROME2_VFS_L45_FP_SW_DENORMAL;
    }
    return sw;
}

int32_t rome2_vfs_crt_stdio_flush_nolock(
    rome2_vfs_crt_filex56_32 *stream,
    int32_t write_rc,
    uint32_t *out_pending_bytes)
{
    uint32_t pending = 0u;
    if (out_pending_bytes) {
        *out_pending_bytes = 0u;
    }
    if (!stream) {
        return -1;
    }
    if ((stream->flag_0c & ROME2_VFS_L45_STDIO_IOMASK_RW) == ROME2_VFS_L45_STDIO_IOWRT_BIT &&
        (stream->flag_0c & ROME2_VFS_L45_STDIO_BUFFER_BITS) != 0u) {
        int32_t signed_pending = (int32_t)(stream->ptr_00 - stream->cnt_04);
        stream->ptr_00 = stream->cnt_04;
        stream->base_08 = 0u;
        if (signed_pending > 0) {
            pending = (uint32_t)signed_pending;
            if (out_pending_bytes) {
                *out_pending_bytes = pending;
            }
            if (write_rc != signed_pending) {
                stream->flag_0c |= ROME2_VFS_L45_STDIO_IOERR_BIT;
                return -1;
            }
            if ((stream->flag_0c & ROME2_VFS_L45_STDIO_IORW_BIT) != 0u) {
                stream->flag_0c &= ~ROME2_VFS_L45_STDIO_IOWRT_BIT;
            }
        }
    }
    return 0;
}

uint8_t rome2_vfs_crt_malloc_plan(
    uint32_t size_bytes,
    uint32_t *out_alloc_bytes,
    int32_t *out_errno)
{
    if (size_bytes > 0xffffffe0u) {
        if (out_alloc_bytes) {
            *out_alloc_bytes = 0u;
        }
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_ENOMEM_MSVC;
        }
        return 0u;
    }
    if (out_alloc_bytes) {
        *out_alloc_bytes = (size_bytes == 0u) ? 1u : size_bytes;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    return 1u;
}

int32_t rome2_vfs_crt_win32_buffer_dyn_alloc(
    uint32_t *out_ptr_va,
    uint32_t size_bytes,
    uint32_t heap_alloc_va,
    int32_t *out_errno)
{
    uint32_t planned = 0u;
    if (!out_ptr_va) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return ROME2_VFS_L44_EINVAL_MSVC;
    }
    if (!rome2_vfs_crt_malloc_plan(size_bytes, &planned, out_errno) || heap_alloc_va == 0u) {
        *out_ptr_va = 0u;
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_ENOMEM_MSVC;
        }
        return ROME2_VFS_L44_ENOMEM_MSVC;
    }
    (void)planned;
    *out_ptr_va = heap_alloc_va;
    if (out_errno) {
        *out_errno = 0;
    }
    return 0;
}

uint8_t rome2_vfs_crt_fmt_scan_field_width(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len)
{
    size_t pos;
    uint8_t ch;
    uint64_t val = 0u;
    uint8_t overflow = 0u;

    if (!fp || !fmt_buf || !inout_off || *inout_off >= fmt_len) {
        return 0u;
    }
    pos = *inout_off;
    ch = (uint8_t)fmt_buf[pos];
    if (ch < '0' || ch > '9') {
        return 1u;
    }
    while (pos < fmt_len && fmt_buf[pos] >= '0' && fmt_buf[pos] <= '9') {
        uint64_t d = (uint64_t)(uint8_t)(fmt_buf[pos] - '0');
        if (val > (UINT64_MAX - d) / 10u) {
            overflow = 1u;
        } else {
            val = val * 10u + d;
        }
        pos++;
    }
    if (overflow) {
        val = UINT64_MAX;
    }
    if (val == 0u || pos == *inout_off) {
        l45_parser_fail_reset(fp, ROME2_VFS_L44_EINVAL_MSVC);
        return 0u;
    }
    fp->width_18 = (uint32_t)(val & 0xffffffffu);
    fp->length_mod_1c = (uint32_t)(val >> 32);
    *inout_off = pos;
    return 1u;
}

void rome2_vfs_crt_fmt_scan_length_modifier(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len)
{
    size_t pos;
    char ch;
    if (!fp || !fmt_buf || !inout_off || *inout_off >= fmt_len) {
        return;
    }
    pos = *inout_off;
    ch = fmt_buf[pos];
    if (ch == 'h') {
        if (pos + 1u < fmt_len && fmt_buf[pos + 1u] == 'h') {
            fp->length_idx_20 = 1u;
            *inout_off = pos + 2u;
        } else {
            fp->length_idx_20 = 2u;
            *inout_off = pos + 1u;
        }
        return;
    }
    if (ch == 'T') {
        fp->length_idx_20 = 11u;
        *inout_off = pos + 1u;
        return;
    }
    if (ch == 'L') {
        fp->length_idx_20 = 8u;
        *inout_off = pos + 1u;
        return;
    }
    if (ch == 'j') {
        fp->length_idx_20 = 5u;
        *inout_off = pos + 1u;
        return;
    }
    if (ch == 'z') {
        fp->length_idx_20 = 6u;
        *inout_off = pos + 1u;
        return;
    }
    if (ch == 't') {
        fp->length_idx_20 = 7u;
        *inout_off = pos + 1u;
        return;
    }
    if (ch == 'l') {
        if (pos + 1u < fmt_len && fmt_buf[pos + 1u] == 'l') {
            fp->length_idx_20 = 4u;
            *inout_off = pos + 2u;
        } else {
            fp->length_idx_20 = 3u;
            *inout_off = pos + 1u;
        }
        return;
    }
    if (ch == 'I' && pos + 1u < fmt_len) {
        char n1 = fmt_buf[pos + 1u];
        char n2 = (pos + 2u < fmt_len) ? fmt_buf[pos + 2u] : '\0';
        if (n1 == '3' && n2 == '2') {
            fp->length_idx_20 = 9u;
            *inout_off = pos + 3u;
        } else if (n1 == '6' && n2 == '4') {
            fp->length_idx_20 = 10u;
            *inout_off = pos + 3u;
        } else if (n1 == 'd' || n1 == 'i' || n1 == 'o' || n1 == 'u' || n1 == 'x' || n1 == 'X') {
            fp->length_idx_20 = 9u;
        }
    }
}

uint8_t rome2_vfs_crt_fmt_scan_trail_bytes(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    uint16_t lead_ctype,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len)
{
    uint8_t trail;
    if (!fp || !fmt_buf || !inout_off) {
        return 0u;
    }
    if ((lead_ctype & ROME2_VFS_L45_LEADBYTE_FLAG) == 0u) {
        return 1u;
    }
    trail = (*inout_off < fmt_len) ? (uint8_t)fmt_buf[*inout_off] : 0u;
    if (trail == 0u) {
        l45_parser_fail_reset(fp, ROME2_VFS_L45_EILSEQ_MSVC);
        return 0u;
    }
    (*inout_off)++;
    fp->lit_ch_14 = (uint16_t)((fp->lit_ch_14 & 0x00ffu) | ((uint16_t)trail << 8));
    return 1u;
}

void rome2_vfs_crt_fmt_scan_wide_modifier(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len)
{
    char ch;
    if (!fp || !fmt_buf || !inout_off || *inout_off >= fmt_len) {
        return;
    }
    ch = fmt_buf[*inout_off];
    if (ch == 'w') {
        (*inout_off)++;
        fp->is_wide_24 = 1u;
    } else if (ch == 'C' || ch == 'S') {
        fp->is_wide_24 = 1u;
    }
}

uint32_t rome2_vfs_crt_call_wfullpath_select(
    uint32_t fixed_res_va,
    int32_t internal_errno,
    uint32_t dyn_res_va,
    int32_t caller_errno,
    int32_t *out_errno)
{
    if (fixed_res_va != 0u) {
        if (out_errno) {
            *out_errno = caller_errno;
        }
        return fixed_res_va;
    }
    if (internal_errno == ROME2_VFS_L44_ERANGE_MSVC) {
        if (out_errno) {
            *out_errno = caller_errno;
        }
        return dyn_res_va;
    }
    if (out_errno) {
        *out_errno = internal_errno;
    }
    return 0u;
}

uint8_t rome2_vfs_crt_is_root_or_empty_w(const uint16_t *wpath)
{
    const uint16_t *cur = wpath;
    if (!cur) {
        return 0u;
    }
    if (l45_is_ascii_alpha_w(cur[0]) && cur[1] == (uint16_t)':') {
        cur += 2;
    }
    if (cur[0] == 0u) {
        return 1u;
    }
    return (l45_is_slash_w(cur[0]) && cur[1] == 0u) ? 1u : 0u;
}

uint8_t rome2_vfs_crt_is_root_unc_name_w(const uint16_t *wpath)
{
    size_t len = 0u;
    const uint16_t *cur;
    if (!wpath) {
        return 0u;
    }
    while (wpath[len] != 0u) {
        len++;
    }
    if (len < 5u) {
        return 0u;
    }
    if (!l45_is_slash_w(wpath[0]) || !l45_is_slash_w(wpath[1]) || l45_is_slash_w(wpath[2])) {
        return 0u;
    }
    cur = wpath + 3u;
    while (*cur != 0u && !l45_is_slash_w(*cur)) {
        cur++;
    }
    if (*cur == 0u) {
        return 0u;
    }
    cur++;
    if (*cur == 0u) {
        return 0u;
    }
    while (*cur != 0u && !l45_is_slash_w(*cur)) {
        cur++;
    }
    if (*cur != 0u && cur[1] != 0u) {
        return 0u;
    }
    return 1u;
}

int32_t rome2_vfs_crt_getdrive_from_cwd_w(
    const uint16_t *cwd_w,
    uint32_t cwd_req_len,
    uint8_t heap_alloc_ok,
    int32_t *out_errno)
{
    uint16_t ch;
    if (cwd_req_len > 0x104u && (!heap_alloc_ok || !cwd_w)) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_ENOMEM_MSVC;
        }
        return 0;
    }
    if (!cwd_w) {
        return 0;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    ch = cwd_w[0];
    if (cwd_w[1] == (uint16_t)':') {
        if (ch >= (uint16_t)'a' && ch <= (uint16_t)'z') {
            return (int32_t)(ch - (uint16_t)'a' + 1u);
        }
        if (ch >= (uint16_t)'A' && ch <= (uint16_t)'Z') {
            return (int32_t)(ch - (uint16_t)'A' + 1u);
        }
    }
    return 0;
}

uint32_t rome2_vfs_crt_clearfp_sw(
    uint16_t x87_sw,
    uint32_t mxcsr,
    int32_t sse2_isa_level,
    uint32_t *out_next_mxcsr)
{
    uint32_t sw_x87 = l45_hw_fp_to_sw((uint32_t)x87_sw);
    if (sse2_isa_level >= 1) {
        if (out_next_mxcsr) {
            *out_next_mxcsr = mxcsr & 0xffffffc0u;
        }
        return sw_x87 | l45_hw_fp_to_sw(mxcsr);
    }
    if (out_next_mxcsr) {
        *out_next_mxcsr = mxcsr;
    }
    return sw_x87;
}

double rome2_vfs_crt_fp_decomp(double x, int32_t *out_exp)
{
    int32_t exp_val = 0;
    double res;
    if (x == 0.0) {
        if (out_exp) {
            *out_exp = 0;
        }
        return 0.0;
    }
    res = frexp(x, &exp_val);
    if (out_exp) {
        *out_exp = exp_val;
    }
    return res;
}

int32_t rome2_vfs_crt_signext_sw16(uint16_t sw)
{
    return (int32_t)(int16_t)sw;
}

uint16_t rome2_vfs_crt_raise_fp_status_bits(uint32_t exc_mask)
{
    uint16_t hw = 0u;
    if ((exc_mask & 0x01u) != 0u) {
        hw |= 0x0001u;
    }
    if ((exc_mask & 0x08u) != 0u) {
        hw |= 0x0028u;
    }
    if ((exc_mask & 0x10u) != 0u) {
        hw |= 0x0030u;
    }
    if ((exc_mask & 0x04u) != 0u) {
        hw |= 0x0004u;
    }
    if ((exc_mask & 0x20u) != 0u) {
        hw |= 0x0020u;
    }
    return hw;
}

uint8_t rome2_vfs_crt_isspace_dispatch(
    uint8_t locale_changed,
    int32_t ch,
    uint16_t ctype_flags,
    uint8_t locale_result)
{
    (void)ch;
    if (locale_changed != 0u) {
        return locale_result;
    }
    return ((ctype_flags & ROME2_VFS_L45_ISSPACE_MASK) != 0u) ? 1u : 0u;
}

int32_t rome2_vfs_crt_fileno(const rome2_vfs_crt_filex56_32 *stream, int32_t *out_errno)
{
    if (!stream) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return -1;
    }
    return stream->file_10;
}

uint32_t rome2_vfs_crt_lock_slot_va(int32_t lock_id)
{
    return ROME2_VFS_L45_CRTLOCK_TABLE_VA + ((uint32_t)lock_id * ROME2_VFS_L45_LOCK_STRIDE_BYTES);
}

uint32_t rome2_vfs_crt_encode_pointer32(uint32_t ptr_va, uint32_t security_cookie)
{
    uint32_t rot = security_cookie & 0x1fu;
    uint32_t rol = (rot == 0u) ? ptr_va : ((ptr_va << rot) | (ptr_va >> (32u - rot)));
    return rol ^ security_cookie;
}

int32_t rome2_vfs_crt_onexit_append_step(
    rome2_vfs_crt_onexit_table12_32 *tbl,
    uint32_t fn_va,
    uint32_t security_cookie,
    uint8_t grow_primary_ok,
    uint8_t grow_fallback_ok,
    uint32_t new_base_va,
    uint32_t *out_new_capacity,
    uint32_t *out_written_slot_enc)
{
    uint32_t first_va;
    uint32_t last_va;
    uint32_t end_va;
    if (out_new_capacity) {
        *out_new_capacity = 0u;
    }
    if (out_written_slot_enc) {
        *out_written_slot_enc = 0u;
    }
    if (!tbl || tbl->first_enc_00 == 0u) {
        return -1;
    }
    first_va = rome2_vfs_crt_decode_pointer32(tbl->first_enc_00, security_cookie);
    last_va = rome2_vfs_crt_decode_pointer32(tbl->last_enc_04, security_cookie);
    end_va = rome2_vfs_crt_decode_pointer32(tbl->end_enc_08, security_cookie);

    if (last_va == end_va) {
        uint32_t count = (end_va - first_va) / 4u;
        uint32_t inc = (count > 0x200u) ? 0x200u : count;
        uint32_t cap = count + inc;
        if (cap == 0u) {
            cap = 0x20u;
        }
        if (cap < count || !grow_primary_ok) {
            cap = count + 4u;
            if (!grow_fallback_ok) {
                return -1;
            }
        }
        first_va = new_base_va;
        last_va = first_va + count * 4u;
        end_va = first_va + cap * 4u;
        if (out_new_capacity) {
            *out_new_capacity = cap;
        }
    }

    if (out_written_slot_enc) {
        *out_written_slot_enc = rome2_vfs_crt_encode_pointer32(fn_va, security_cookie);
    }
    tbl->first_enc_00 = rome2_vfs_crt_encode_pointer32(first_va, security_cookie);
    tbl->last_enc_04 = rome2_vfs_crt_encode_pointer32(last_va + 4u, security_cookie);
    tbl->end_enc_08 = rome2_vfs_crt_encode_pointer32(end_va, security_cookie);
    return 0;
}

uint8_t rome2_vfs_crt_retain_mbc_ref(
    const rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t *inout_mbc_refcount,
    uint32_t *out_mbcinfo_va)
{
    if (!ptd || !inout_mbc_refcount) {
        return 0u;
    }
    if (out_mbcinfo_va) {
        *out_mbcinfo_va = ptd->ptmbcinfo_48;
    }
    (*inout_mbc_refcount)++;
    return 1u;
}

uint8_t rome2_vfs_crt_retain_locale_ref(
    uint32_t *out_locinfo_ptr_va,
    uint32_t global_locinfo_va)
{
    if (!out_locinfo_ptr_va) {
        return 0u;
    }
    *out_locinfo_ptr_va = global_locinfo_va;
    return 1u;
}

uint32_t rome2_vfs_crt_try_get_function_slot(
    uint32_t *inout_encoded_slot,
    uint32_t security_cookie,
    uint8_t module_ok,
    uint32_t proc_va,
    uint8_t *out_resolved_fresh)
{
    uint32_t decoded;
    if (out_resolved_fresh) {
        *out_resolved_fresh = 0u;
    }
    if (!inout_encoded_slot) {
        return 0u;
    }
    decoded = rome2_vfs_crt_decode_pointer32(*inout_encoded_slot, security_cookie);
    if (decoded == 0xffffffffu) {
        return 0u;
    }
    if (decoded != 0u) {
        return decoded;
    }
    if (module_ok != 0u && proc_va != 0u) {
        *inout_encoded_slot = rome2_vfs_crt_encode_pointer32(proc_va, security_cookie);
        if (out_resolved_fresh) {
            *out_resolved_fresh = 1u;
        }
        return proc_va;
    }
    *inout_encoded_slot = rome2_vfs_crt_encode_pointer32(0xffffffffu, security_cookie);
    return 0u;
}

uint32_t rome2_vfs_crt_try_get_are_file_apis_ansi(
    uint32_t *table_base_encoded,
    uint32_t table_len,
    uint32_t security_cookie,
    uint8_t module_ok,
    uint32_t proc_va,
    uint8_t *out_resolved_fresh)
{
    if (!table_base_encoded || ROME2_VFS_L45_ARE_FILE_APIS_ANSI_ID >= table_len) {
        if (out_resolved_fresh) {
            *out_resolved_fresh = 0u;
        }
        return 0u;
    }
    return rome2_vfs_crt_try_get_function_slot(
        &table_base_encoded[ROME2_VFS_L45_ARE_FILE_APIS_ANSI_ID],
        security_cookie,
        module_ok,
        proc_va,
        out_resolved_fresh);
}

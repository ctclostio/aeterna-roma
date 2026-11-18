#include "vfs_fs_engine_crt_sec_ops.h"

#include <errno.h>
#include <float.h>
#include <math.h>
#include <string.h>

static const uint8_t g_l43_fmt_compat_table[120] = {
    0x01,0x00,0x01,0x01, 0x01,0x00,0x00,0x00, 0x01,0x00,0x00,0x01,
    0x01,0x00,0x01,0x01, 0x01,0x00,0x00,0x00, 0x01,0x00,0x00,0x01,
    0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01, 0x00,0x01,0x01,0x00,
    0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01, 0x00,0x01,0x01,0x00,
    0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01, 0x00,0x01,0x01,0x00,
    0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01, 0x00,0x01,0x01,0x00,
    0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01, 0x00,0x01,0x01,0x00,
    0x01,0x01,0x01,0x01, 0x01,0x01,0x01,0x01, 0x00,0x01,0x01,0x00,
    0x01,0x00,0x00,0x01, 0x00,0x00,0x00,0x00, 0x01,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x01, 0x01,0x01,0x01,0x01,
};

typedef struct l43_umatherr_pair {
    int32_t op_code;
    uint32_t name_va;
} l43_umatherr_pair;

static const l43_umatherr_pair g_l43_umatherr_table[ROME2_VFS_L43_UMATHERR_OP_COUNT] = {
    { 20, 0x118dee54u }, { 29, 0x118dee58u }, { 26, 0x118d4af0u }, { 27, 0x11913830u },
    { 31, 0x11913838u }, { 19, 0x11913840u }, { 33, 0x11913848u }, { 14, 0x11913850u },
    { 13, 0x11913858u }, { 15, 0x11913860u }, { 16, 0x11913868u }, { 5,  0x11913870u },
    { 30, 0x11913878u }, { 18, 0x1191387cu }, { 32, 0x11913880u }, { 12, 0x11913884u },
    { 11, 0x1191388cu }, { 21, 0x11913894u }, { 28, 0x1191389cu }, { 25, 0x119138a4u },
    { 17, 0x119138acu }, { 24, 0x119138b4u }, { 22, 0x119138bcu }, { 23, 0x119138c4u },
    { 34, 0x119138ccu }, { 35, 0x119138d0u }, { 36, 0x119138d4u }, { 37, 0x119138d8u },
    { 38, 0x119138e0u },
};

static uint8_t l43_is_ascii_space(uint8_t ch)
{
    return (ch == ' ' || (ch >= '\t' && ch <= '\r')) ? 1u : 0u;
}

static uint8_t l43_str_ieq4(const char *a, const char *b)
{
    size_t i;
    for (i = 0u; i < 4u; ++i) {
        uint8_t ca = (uint8_t)a[i];
        uint8_t cb = (uint8_t)b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (uint8_t)(ca + 0x20u);
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (uint8_t)(cb + 0x20u);
        }
        if (ca != cb) {
            return 0u;
        }
        if (ca == '\0') {
            return 1u;
        }
    }
    return (a[4] == '\0' && b[4] == '\0') ? 1u : 0u;
}

uint32_t rome2_vfs_crt_chkstk_plan(
    uint32_t stack_top,
    uint32_t alloc_bytes,
    uint32_t *out_touched_pages)
{
    uint32_t target = (stack_top >= alloc_bytes) ? (stack_top - alloc_bytes) : 0u;
    uint32_t page_top = stack_top & 0xfffff000u;
    uint32_t touches = 0u;

    while (target < page_top) {
        page_top -= 0x1000u;
        touches++;
    }
    if (out_touched_pages) {
        *out_touched_pages = touches;
    }
    return target;
}

uint8_t rome2_vfs_crt_security_check_cookie(uint32_t ecx_cookie, uint32_t global_cookie)
{
    return (ecx_cookie == global_cookie) ? 1u : 0u;
}

rome2_vfs_reg_status rome2_vfs_crt_raise_secfail_record_init(
    rome2_vfs_win32_exception_record80_32 *rec,
    rome2_vfs_win32_exception_pointers8_32 *ptrs,
    uint32_t exc_code,
    uint32_t exc_flags,
    uint32_t caller_ip,
    uint32_t rec_va,
    uint32_t ctx_va)
{
    if (!rec || !ptrs) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    (void)rome2_vfs_crt_memset(rec, 0, sizeof(*rec));
    rec->exception_code_00 = exc_code;
    rec->exception_flags_04 = exc_flags;
    rec->exception_address_0c = caller_ip;
    ptrs->exception_record_00 = rec_va;
    ptrs->context_record_04 = ctx_va;
    return ROME2_VFS_REG_OK;
}

int32_t rome2_vfs_crt_string_input_get(rome2_vfs_crt_string_input_adapter *ad)
{
    uint8_t ch;
    if (!ad || ad->cur == ad->end) {
        return -1;
    }
    ch = (uint8_t)*ad->cur;
    ad->cur++;
    return (int32_t)ch;
}

void rome2_vfs_crt_string_input_unget(rome2_vfs_crt_string_input_adapter *ad, int32_t ch)
{
    if (!ad || ad->cur == ad->begin) {
        return;
    }
    if (ad->cur == ad->end && ch == -1) {
        return;
    }
    ad->cur--;
}

uint8_t rome2_vfs_crt_string_input_validate(const rome2_vfs_crt_string_input_adapter *ad, int32_t *out_errno)
{
    if (!ad || !ad->cur || ad->cur > ad->end) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return 0u;
    }
    return 1u;
}

uint8_t rome2_vfs_crt_fmt_parser_validate(const rome2_vfs_crt_fmt_parser76_32 *fp, int32_t *out_errno)
{
    if (!fp || fp->fmt_cur_08 == 0u) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return 0u;
    }
    return 1u;
}

rome2_vfs_reg_status rome2_vfs_crt_fmt_parser_init(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    uint32_t locinfo_va,
    uint32_t state_val,
    uint32_t fmt_va)
{
    if (!fp) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    (void)rome2_vfs_crt_memset(fp, 0, sizeof(*fp));
    fp->locinfo_00 = locinfo_va;
    fp->state_val_04 = state_val;
    fp->fmt_cur_08 = fmt_va;
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_crt_fmt_compat_allowed(uint32_t conv_idx, uint32_t length_idx)
{
    size_t idx = (size_t)conv_idx * ROME2_VFS_L43_FMT_COMPAT_COLS + (size_t)length_idx;
    if (conv_idx >= ROME2_VFS_L43_FMT_COMPAT_ROWS || length_idx >= ROME2_VFS_L43_FMT_COMPAT_COLS) {
        return 0u;
    }
    return g_l43_fmt_compat_table[idx];
}

uint8_t rome2_vfs_crt_fmt_parser_advance(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len)
{
    size_t off;
    uint8_t ch;

    if (!fp || !fmt_buf || !inout_off) {
        return 0u;
    }
    if (fp->err_0c != 0) {
        return 0u;
    }
    fp->mode_10 = 0u;
    fp->lit_ch_14 = 0u;
    fp->suppress_16 = 0u;
    fp->width_18 = 0u;
    fp->length_mod_1c = 0u;
    fp->length_idx_20 = 0u;
    fp->is_wide_24 = 0u;
    fp->conv_idx_28 = 0u;

    off = *inout_off;
    ch = (off < fmt_len) ? (uint8_t)fmt_buf[off] : 0u;
    if (ch == '\0') {
        fp->mode_10 = 1u;
        return 0u;
    }
    if (l43_is_ascii_space(ch)) {
        fp->mode_10 = 2u;
        while (off < fmt_len && l43_is_ascii_space((uint8_t)fmt_buf[off])) {
            off++;
        }
        *inout_off = off;
        return 1u;
    }
    if (ch == '%' && (off + 1u) < fmt_len && fmt_buf[off + 1u] != '%') {
        fp->mode_10 = 4u;
        off++;
        if (off < fmt_len && fmt_buf[off] == '*') {
            fp->suppress_16 = 1u;
            off++;
        }
        *inout_off = off;
        return 1u;
    }
    fp->mode_10 = 3u;
    fp->lit_ch_14 = (uint16_t)ch;
    off += (ch == '%' && (off + 1u) < fmt_len && fmt_buf[off + 1u] == '%') ? 2u : 1u;
    *inout_off = off;
    return 1u;
}

int32_t rome2_vfs_crt_mbs_to_wcs_cp(
    const char *src,
    uint16_t *dst_w,
    size_t dst_cap_words,
    size_t *out_len_words,
    int32_t *out_errno)
{
    size_t len = 0u;
    if (!dst_w || dst_cap_words == 0u || !out_len_words) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return EINVAL;
    }
    if (!src || src[0] == '\0') {
        dst_w[0] = 0u;
        *out_len_words = 0u;
        if (out_errno) {
            *out_errno = 0;
        }
        return 0;
    }
    while (src[len] != '\0') {
        if (len + 1u >= dst_cap_words) {
            dst_w[0] = 0u;
            *out_len_words = 0u;
            if (out_errno) {
                *out_errno = ERANGE;
            }
            return ERANGE;
        }
        dst_w[len] = (uint16_t)(uint8_t)src[len];
        len++;
    }
    dst_w[len] = 0u;
    *out_len_words = len;
    if (out_errno) {
        *out_errno = 0;
    }
    return 0;
}

int64_t rome2_vfs_crt_filetime_or_fallback(
    uint32_t ft_lo,
    uint32_t ft_hi,
    int64_t fallback_unix,
    uint8_t sys_time_ok,
    int64_t converted_unix)
{
    if (ft_lo == 0u && ft_hi == 0u) {
        return fallback_unix;
    }
    if (!sys_time_ok) {
        return -1;
    }
    return converted_unix;
}

uint8_t rome2_vfs_crt_stat_store_size64(
    uint32_t size_hi,
    uint32_t size_lo,
    int64_t *out_size,
    int32_t *out_errno)
{
    if (!out_size) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return 0u;
    }
    if (size_hi > 0x7fffffffu) {
        *out_size = 0;
        if (out_errno) {
            *out_errno = ROME2_VFS_L43_EOVERFLOW_MSVC;
        }
        return 0u;
    }
    *out_size = (int64_t)((((uint64_t)size_hi) << 32) | (uint64_t)size_lo);
    return 1u;
}

uint16_t rome2_vfs_crt_dtoxmode_w(uint32_t dw_file_attrs, uint8_t is_root_dir, const char *path_ext_ascii)
{
    uint32_t base_mode = ((dw_file_attrs & 0x10u) != 0u || is_root_dir) ? 0x4140u : 0x8100u;
    uint32_t mode = base_mode | (((dw_file_attrs & 1u) == 0u) ? 0x80u : 0u);

    if (path_ext_ascii &&
        (l43_str_ieq4(path_ext_ascii, ".exe") ||
         l43_str_ieq4(path_ext_ascii, ".cmd") ||
         l43_str_ieq4(path_ext_ascii, ".bat") ||
         l43_str_ieq4(path_ext_ascii, ".com"))) {
        mode |= 0x40u;
    }
    mode |= (mode >> 3) & 0x38u;
    mode |= (mode >> 6) & 0x07u;
    return (uint16_t)mode;
}

uint8_t rome2_vfs_crt_extract_drive_w(
    const uint16_t *wpath,
    uint32_t fallback_drive,
    uint32_t *out_drive,
    int32_t *out_errno)
{
    uint16_t c0;
    if (!wpath || !out_drive) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return 0u;
    }
    *out_drive = 0u;
    c0 = wpath[0];
    if (((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z')) && wpath[1] == (uint16_t)':') {
        uint16_t low = (c0 >= 'A' && c0 <= 'Z') ? (uint16_t)(c0 + 0x20u) : c0;
        if (wpath[2] == 0u) {
            if (out_errno) {
                *out_errno = ENOENT;
            }
            return 0u;
        }
        *out_drive = (uint32_t)(low - (uint16_t)'a' + 1u);
        return 1u;
    }
    *out_drive = fallback_drive;
    return 1u;
}

uint8_t rome2_vfs_crt_validate_stat_path_w(
    const uint16_t *wpath,
    uint8_t has_dot_or_slash,
    uint32_t full_len,
    uint8_t root_unc_valid,
    uint32_t drive_type)
{
    (void)wpath;
    if (!has_dot_or_slash) {
        return 0u;
    }
    if (full_len != 3u && !root_unc_valid) {
        return 0u;
    }
    return (drive_type > 1u) ? 1u : 0u;
}

uint32_t rome2_vfs_crt_file_unlock_offset_va(uint32_t filex_va)
{
    return rome2_vfs_crt_file_lock_offset_va(filex_va);
}

uint32_t rome2_vfs_crt_fp_exc_to_matherr_type(uint32_t fp_flags)
{
    if ((fp_flags & 0x20u) != 0u) {
        return 5u;
    }
    if ((fp_flags & 0x08u) != 0u) {
        return 1u;
    }
    if ((fp_flags & 0x04u) != 0u) {
        return 2u;
    }
    if ((fp_flags & 0x01u) != 0u) {
        return 3u;
    }
    return (fp_flags & 2u) * 2u;
}

uint8_t rome2_vfs_crt_handle_exc_f64(
    uint32_t exc_flags,
    double *inout_val,
    uint32_t fp_cw,
    uint8_t frexp_ok,
    uint32_t *out_cleared_mask)
{
    uint32_t rem = exc_flags & 0x1fu;
    (void)frexp_ok;
    if (!inout_val) {
        return 0u;
    }
    if ((exc_flags & 8u) != 0u && (fp_cw & 1u) != 0u) {
        rem &= ~8u;
    } else if ((exc_flags & fp_cw & 4u) != 0u) {
        rem &= ~4u;
    } else if ((exc_flags & 1u) != 0u && (fp_cw & 8u) != 0u) {
        uint32_t rc = fp_cw & 0xc00u;
        if (rc == 0x000u) {
            *inout_val = (*inout_val < 0.0) ? -INFINITY : INFINITY;
        } else if (rc == 0x400u) {
            *inout_val = (*inout_val < 0.0) ? -INFINITY : DBL_MAX;
        } else if (rc == 0x800u) {
            *inout_val = (*inout_val < 0.0) ? -DBL_MAX : INFINITY;
        } else {
            *inout_val = (*inout_val < 0.0) ? -DBL_MAX : DBL_MAX;
        }
        rem &= ~1u;
    }
    if ((exc_flags & 0x10u) != 0u && (fp_cw & 0x20u) != 0u) {
        rem &= ~0x10u;
    }
    if (out_cleared_mask) {
        *out_cleared_mask = rem;
    }
    return (rem == 0u) ? 1u : 0u;
}

void rome2_vfs_crt_errcode_set_errno(uint32_t matherr_type, int32_t *out_errno)
{
    if (!out_errno) {
        return;
    }
    if (matherr_type == 1u) {
        *out_errno = 0x21;
    } else if (matherr_type == 2u || matherr_type == 3u) {
        *out_errno = 0x22;
    }
}

uint32_t rome2_vfs_crt_raise_exc_map_code(uint32_t exc_flags, uint32_t *out_cause_bits)
{
    uint32_t cause = 0u;
    uint32_t status = 0xc000000du;

    if ((exc_flags & 0x10u) != 0u) {
        status = 0xc000008fu;
        cause |= 1u;
    }
    if ((exc_flags & 2u) != 0u) {
        status = 0xc0000093u;
        cause |= 2u;
    }
    if ((exc_flags & 1u) != 0u) {
        status = 0xc0000091u;
        cause |= 4u;
    }
    if ((exc_flags & 4u) != 0u) {
        status = 0xc000008eu;
        cause |= 8u;
    }
    if ((exc_flags & 8u) != 0u) {
        status = 0xc0000090u;
        cause |= 0x10u;
    }
    if (out_cause_bits) {
        *out_cause_bits = cause;
    }
    return status;
}

uint32_t rome2_vfs_crt_umatherr_lookup_name_va(int32_t op_code)
{
    size_t i;
    for (i = 0u; i < ROME2_VFS_L43_UMATHERR_OP_COUNT; ++i) {
        if (g_l43_umatherr_table[i].op_code == op_code) {
            return g_l43_umatherr_table[i].name_va;
        }
    }
    return 0u;
}

rome2_vfs_reg_status rome2_vfs_crt_initptd(
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t *out_holdrand,
    uint32_t *out_xcptacttab_va,
    uint32_t *out_ptmbcinfo_va)
{
    if (!ptd || !out_holdrand || !out_xcptacttab_va || !out_ptmbcinfo_va) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    (void)rome2_vfs_crt_memset(ptd, 0, sizeof(*ptd));
    ptd->ownlocale_350 = 1u;
    *out_holdrand = 1u;
    *out_xcptacttab_va = ROME2_VFS_L43_XCPT_ACT_TAB_VA;
    *out_ptmbcinfo_va = ROME2_VFS_L43_DEFAULT_MBCINFO_VA;
    return ROME2_VFS_REG_OK;
}

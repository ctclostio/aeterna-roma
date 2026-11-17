#include "vfs_fs_engine_crt_io_ops.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static const rome2_vfs_crt_errentry8_32 g_l42_errentry_table[ROME2_VFS_L42_ERRENTRY_COUNT] = {
    { 1u,    22 }, { 2u,    2  }, { 3u,    2  }, { 4u,    24 }, { 5u,    13 },
    { 6u,    9  }, { 7u,    12 }, { 8u,    12 }, { 9u,    12 }, { 10u,   7  },
    { 11u,   8  }, { 12u,   22 }, { 13u,   22 }, { 15u,   2  }, { 16u,   13 },
    { 17u,   18 }, { 18u,   2  }, { 33u,   13 }, { 53u,   2  }, { 65u,   13 },
    { 67u,   2  }, { 80u,   17 }, { 82u,   13 }, { 83u,   13 }, { 87u,   22 },
    { 89u,   11 }, { 108u,  13 }, { 109u,  32 }, { 112u,  28 }, { 114u,  9  },
    { 128u,  10 }, { 129u,  10 }, { 130u,  9  }, { 131u,  22 }, { 132u,  13 },
    { 145u,  41 }, { 158u,  13 }, { 161u,  2  }, { 164u,  11 }, { 167u,  13 },
    { 183u,  17 }, { 206u,  2  }, { 215u,  11 }, { 1113u, 42 }, { 1816u, 12 },
};

rome2_vfs_reg_status rome2_vfs_cstr_repeat_fill(
    char fill_ch,
    uint32_t count,
    char *dst,
    uint32_t dst_cap,
    uint32_t *out_len,
    uint8_t *out_used_empty_sentinel)
{
    if (!dst || dst_cap == 0u || !out_len || !out_used_empty_sentinel) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (count == 0u) {
        dst[0] = '\0';
        *out_len = 0u;
        *out_used_empty_sentinel = 1u;
        return ROME2_VFS_REG_OK;
    }
    if (count + 1u > dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    (void)rome2_vfs_crt_memset(dst, (unsigned char)fill_ch, (size_t)count);
    dst[count] = '\0';
    *out_len = count;
    *out_used_empty_sentinel = 0u;
    return ROME2_VFS_REG_OK;
}

int64_t rome2_vfs_crt_allshl(int64_t val, uint8_t shift)
{
    uint64_t u = (uint64_t)val;
    uint32_t lo = (uint32_t)(u & 0xffffffffu);
    uint32_t hi = (uint32_t)(u >> 32);

    if (shift >= 64u) {
        return 0;
    }
    if (shift >= 32u) {
        uint8_t sub = (uint8_t)(shift & 31u);
        uint32_t out_hi = lo << sub;
        return (int64_t)(((uint64_t)out_hi) << 32);
    }
    if (shift == 0u) {
        return val;
    }
    {
        uint32_t out_hi = (hi << shift) | (lo >> (32u - shift));
        uint32_t out_lo = lo << shift;
        return (int64_t)((((uint64_t)out_hi) << 32) | (uint64_t)out_lo);
    }
}

uint32_t rome2_vfs_crt_gs_entropy_fold(
    uint32_t ft_lo,
    uint32_t ft_hi,
    uint32_t tid,
    uint32_t pid,
    uint32_t qpc_lo,
    uint32_t qpc_hi,
    uint32_t slot_addr_hint)
{
    uint32_t cookie = ft_hi ^ ft_lo;
    cookie ^= tid;
    cookie ^= pid;
    return (qpc_hi ^ qpc_lo ^ cookie ^ slot_addr_hint);
}

uint32_t rome2_vfs_crt_decode_pointer32(uint32_t encoded, uint32_t security_cookie)
{
    uint32_t rot = security_cookie & 0x1fu;
    uint32_t x = encoded ^ security_cookie;
    if (rot == 0u) {
        return x;
    }
    return (x >> rot) | (x << (32u - rot));
}

uint32_t rome2_vfs_crt_invalid_param_dispatch(
    const rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t encoded_global_handler,
    uint32_t security_cookie,
    uint32_t *out_watson_status)
{
    if (out_watson_status) {
        *out_watson_status = 0u;
    }
    if (ptd && ptd->invalid_parameter_handler_35c != 0u) {
        return ptd->invalid_parameter_handler_35c;
    }
    {
        uint32_t decoded = rome2_vfs_crt_decode_pointer32(encoded_global_handler, security_cookie);
        if (decoded != 0u) {
            return decoded;
        }
    }
    if (out_watson_status) {
        *out_watson_status = ROME2_VFS_L42_STATUS_INVALID_CRUNTIME_PARAMETER;
    }
    return 0u;
}

uint32_t rome2_vfs_crt_file_lock_offset_va(uint32_t filex_va)
{
    return filex_va + ROME2_VFS_L42_FILEX_LOCK_CS_OFFSET;
}

rome2_vfs_reg_status rome2_vfs_crt_locale_update_init(
    rome2_vfs_crt_locale_update16_32 *lu,
    uint8_t has_caller_locale,
    uint32_t caller_locinfo_va,
    uint32_t caller_mbcinfo_va,
    uint8_t locale_changed,
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t ptd_va)
{
    if (!lu) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    lu->updated_0c = 0u;
    lu->ptd_00 = 0u;
    lu->pad_0d[0] = 0u;
    lu->pad_0d[1] = 0u;
    lu->pad_0d[2] = 0u;

    if (has_caller_locale) {
        lu->locinfo_04 = caller_locinfo_va;
        lu->mbcinfo_08 = caller_mbcinfo_va;
        return ROME2_VFS_REG_OK;
    }
    if (!locale_changed) {
        lu->locinfo_04 = ROME2_VFS_L42_DEFAULT_LOCINFO_VA;
        lu->mbcinfo_08 = ROME2_VFS_L42_DEFAULT_MBCINFO_VA;
        return ROME2_VFS_REG_OK;
    }
    if (!ptd) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    lu->ptd_00 = ptd_va;
    lu->locinfo_04 = ROME2_VFS_L42_DEFAULT_LOCINFO_VA;
    lu->mbcinfo_08 = ROME2_VFS_L42_DEFAULT_MBCINFO_VA;
    if ((ptd->ownlocale_350 & 2u) == 0u) {
        ptd->ownlocale_350 |= 2u;
        lu->updated_0c = 1u;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_vfs_crt_locale_update_release(
    const rome2_vfs_crt_locale_update16_32 *lu,
    rome2_vfs_crt_tiddata868_32 *ptd)
{
    if (!lu) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (lu->updated_0c != 0u) {
        if (!ptd) {
            return ROME2_VFS_REG_BAD_ARGUMENT;
        }
        ptd->ownlocale_350 &= ~2u;
    }
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_vfs_crt_is_utf8_or_clocale(uint32_t locinfo_cp, uint32_t mb_cur_max)
{
    if (locinfo_cp == ROME2_VFS_L42_UTF8_CP) {
        return ROME2_VFS_L42_UTF8_CP;
    }
    return (mb_cur_max == 0u) ? 1u : 0u;
}

rome2_vfs_reg_status rome2_vfs_crt_ascii_to_utf16_path(
    const char *src,
    uint16_t *dst_w,
    size_t dst_words,
    size_t *out_written)
{
    size_t i = 0u;
    if (!src || !dst_w || dst_words == 0u || !out_written) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    while (src[i] != '\0') {
        if (i + 1u >= dst_words) {
            dst_w[0] = 0u;
            *out_written = 0u;
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        dst_w[i] = (uint16_t)(uint8_t)src[i];
        i++;
    }
    dst_w[i] = 0u;
    *out_written = i;
    return ROME2_VFS_REG_OK;
}

int32_t rome2_vfs_crt_memcpy_s(void *dst, size_t dst_cap, const void *src, size_t count)
{
    if (count == 0u) {
        return 0;
    }
    if (!dst) {
        return EINVAL;
    }
    if (!src) {
        (void)rome2_vfs_crt_memset(dst, 0, dst_cap);
        return EINVAL;
    }
    if (dst_cap < count) {
        (void)rome2_vfs_crt_memset(dst, 0, dst_cap);
        return ERANGE;
    }
    (void)rome2_vfs_crt_memcpy(dst, src, count);
    return 0;
}

int32_t rome2_vfs_crt_strcpy_s(char *dst, size_t dst_cap, const char *src)
{
    size_t rem;
    char *p;
    const char *q;

    if (!dst || dst_cap == 0u) {
        return EINVAL;
    }
    if (!src) {
        dst[0] = '\0';
        return EINVAL;
    }

    p = dst;
    q = src;
    rem = dst_cap;
    while ((*p++ = *q++) != '\0' && --rem > 0u) {
    }
    if (rem == 0u) {
        dst[0] = '\0';
        return ERANGE;
    }
    return 0;
}

size_t rome2_vfs_crt_strnlen(const char *str, size_t max_count)
{
    size_t n = 0u;
    while (n < max_count && str[n] != '\0') {
        n++;
    }
    return n;
}

int32_t rome2_vfs_crt_stdio_input_process(
    uint8_t adapter_ok,
    uint8_t fmt_ok,
    int32_t matched_count,
    uint32_t state_mode,
    uint8_t at_eof,
    uint32_t flags,
    int32_t tracked_err,
    int32_t *out_errno)
{
    int32_t res = matched_count;
    if (out_errno) {
        *out_errno = 0;
    }
    if (!adapter_ok || !fmt_ok) {
        return -1;
    }
    if (res == 0 && state_mode != 1u && at_eof) {
        res = -1;
    }
    if ((flags & 1u) != 0u && tracked_err != 0) {
        if (out_errno) {
            *out_errno = tracked_err;
        }
    }
    return res;
}

int32_t rome2_vfs_crt_get_errno_from_oserr(uint32_t oserr)
{
    size_t i;
    for (i = 0u; i < ROME2_VFS_L42_ERRENTRY_COUNT; ++i) {
        if (g_l42_errentry_table[i].oserr_00 == oserr) {
            return g_l42_errentry_table[i].errnocode_04;
        }
    }
    if (oserr - 0x13u <= 0x11u) {
        return 13;
    }
    if (oserr - 0xbcu <= 0x0eu) {
        return 8;
    }
    return 22;
}

uint32_t rome2_vfs_crt_doserrno_slot_va(uint32_t ptd_va)
{
    if (ptd_va == 0u) {
        return ROME2_VFS_L42_DOSERRNO_FALLBACK_VA;
    }
    return ptd_va + 0x14u;
}

rome2_vfs_reg_status rome2_vfs_crt_stat56_init_epoch1980(
    rome2_vfs_crt_stat56_32 *st,
    uint32_t drive_1based,
    uint16_t st_mode,
    int64_t epoch1980_unix)
{
    uint32_t dev;
    if (!st || drive_1based == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    dev = drive_1based - 1u;
    st->st_mode_06 = st_mode;
    st->st_nlink_08 = 1;
    st->st_dev_00 = dev;
    st->st_rdev_10 = dev;
    st->st_atime_20 = epoch1980_unix;
    st->st_mtime_28 = epoch1980_unix;
    st->st_ctime_30 = epoch1980_unix;
    return ROME2_VFS_REG_OK;
}

uint8_t rome2_vfs_crt_stat56_classify_handle(
    rome2_vfs_crt_stat56_32 *st,
    uint32_t file_type_raw,
    uint32_t fd_num,
    uint32_t pipe_avail_bytes,
    uint32_t win32_err,
    int32_t *out_errno)
{
    uint32_t ftype = file_type_raw & 0xffff7fffu;
    if (!st) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return 0u;
    }
    if (out_errno) {
        *out_errno = 0;
    }

    if (ftype == 1u) {
        st->st_nlink_08 = 1;
        return 1u;
    }
    if (ftype == 2u || ftype == 3u) {
        st->st_mode_06 = (ftype == 2u) ? 0x2000u : 0x1000u;
        st->st_nlink_08 = 1;
        st->st_dev_00 = fd_num;
        st->st_rdev_10 = fd_num;
        if (ftype == 3u) {
            st->st_size_18 = (int64_t)pipe_avail_bytes;
        }
        return 1u;
    }

    if (ftype == 0u) {
        if (out_errno) {
            *out_errno = EBADF;
        }
        return 0u;
    }
    if (out_errno) {
        *out_errno = rome2_vfs_crt_get_errno_from_oserr(win32_err);
    }
    return 0u;
}

uint32_t rome2_vfs_crt_onexit_root_push(
    uint32_t *table,
    uint32_t cap,
    uint32_t *inout_count,
    uint32_t fn_va)
{
    return rome2_vfs_crt_onexit_append(table, cap, inout_count, fn_va);
}

double rome2_vfs_crt_libm_err_result(
    int32_t op_code,
    int32_t mode,
    double y_res,
    uint8_t has_sse2,
    uint32_t *out_cw_mask,
    int32_t *out_errno)
{
    int32_t exc_type = 0;
    (void)mode;
    (void)rome2_vfs_crt_libm_handle_error(op_code, out_errno, &exc_type);
    if (out_cw_mask) {
        *out_cw_mask = has_sse2 ? 0u : 0xffffu;
    }
    return y_res;
}

uint32_t rome2_vfs_crt_getptd_resolve(
    uint32_t fls_index,
    uint32_t existing_ptd_va,
    uint32_t alloc_ptd_va,
    uint8_t fls_set_ok,
    uint8_t *out_initialized_new,
    uint8_t *out_freed_on_fail)
{
    if (out_initialized_new) {
        *out_initialized_new = 0u;
    }
    if (out_freed_on_fail) {
        *out_freed_on_fail = 0u;
    }

    if (fls_index != 0xffffffffu && existing_ptd_va != 0u && existing_ptd_va != 0xffffffffu) {
        return existing_ptd_va;
    }
    if (alloc_ptd_va == 0u || !fls_set_ok) {
        if (alloc_ptd_va != 0u && out_freed_on_fail) {
            *out_freed_on_fail = 1u;
        }
        return 0u;
    }
    if (out_initialized_new) {
        *out_initialized_new = 1u;
    }
    return alloc_ptd_va;
}

void rome2_vfs_crt_free_check(
    uint8_t ptr_non_null,
    uint8_t heap_free_ok,
    uint32_t last_err,
    int32_t *out_errno)
{
    if (!ptr_non_null || heap_free_ok) {
        return;
    }
    if (out_errno) {
        *out_errno = rome2_vfs_crt_get_errno_from_oserr(last_err);
    }
}

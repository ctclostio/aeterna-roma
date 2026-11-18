#include "vfs_fs_engine_crt_strtox_ops.h"

#include <math.h>
#include <string.h>

static uint8_t l47_is_ascii_space(uint8_t ch)
{
    return (ch == (uint8_t)' ' || (ch >= 0x09u && ch <= 0x0du)) ? 1u : 0u;
}

static int32_t l47_ascii_digit(uint8_t ch)
{
    if (ch >= (uint8_t)'0' && ch <= (uint8_t)'9') {
        return (int32_t)(ch - (uint8_t)'0');
    }
    if (ch >= (uint8_t)'a' && ch <= (uint8_t)'z') {
        return (int32_t)(ch - (uint8_t)'a') + 10;
    }
    if (ch >= (uint8_t)'A' && ch <= (uint8_t)'Z') {
        return (int32_t)(ch - (uint8_t)'A') + 10;
    }
    return -1;
}

void rome2_vfs_crt_cstr_source_init(
    rome2_vfs_crt_cstr_source8_32 *src,
    uint32_t cstr_va,
    uint32_t endptr_slot_va)
{
    if (!src) {
        return;
    }
    src->cur_00 = cstr_va;
    src->endptr_slot_04 = endptr_slot_va;
}

uint64_t rome2_vfs_crt_parse_uint64_cstr(
    const char *nptr,
    const char **endptr,
    int32_t base,
    uint8_t is_signed,
    int32_t *out_errno)
{
    const char *p = nptr;
    const char *start = nptr;
    uint32_t flags = is_signed ? 1u : 0u;
    uint64_t acc = 0u;
    uint64_t max_q;
    uint64_t max_r;
    uint8_t ch;
    int32_t digit;

    if (out_errno) {
        *out_errno = 0;
    }
    if (!nptr || (base != 0 && (base < 2 || base > 36))) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        if (endptr) {
            *endptr = nptr;
        }
        return 0u;
    }

    while (*p != '\0' && l47_is_ascii_space((uint8_t)*p)) {
        ++p;
    }

    ch = (uint8_t)*p;
    if (ch == (uint8_t)'-') {
        flags |= 2u;
        ++p;
        ch = (uint8_t)*p;
    } else if (ch == (uint8_t)'+') {
        ++p;
        ch = (uint8_t)*p;
    }

    if (base == 0 || base == 16) {
        if (ch == (uint8_t)'0') {
            uint8_t nxt = (uint8_t)p[1];
            if (nxt == (uint8_t)'x' || nxt == (uint8_t)'X') {
                if (base == 0) {
                    base = 16;
                }
                p += 2;
                ch = (uint8_t)*p;
            } else {
                if (base == 0) {
                    base = 8;
                }
            }
        } else if (base == 0) {
            base = 10;
        }
    }

    max_q = UINT64_MAX / (uint64_t)(uint32_t)base;
    max_r = UINT64_MAX % (uint64_t)(uint32_t)base;

    for (;;) {
        digit = l47_ascii_digit(ch);
        if (digit < 0 || digit >= base) {
            break;
        }
        flags |= 8u;
        if (acc > max_q || (acc == max_q && (uint64_t)(uint32_t)digit > max_r)) {
            flags |= 4u;
        } else {
            acc = acc * (uint64_t)(uint32_t)base + (uint64_t)(uint32_t)digit;
        }
        ++p;
        ch = (uint8_t)*p;
    }

    if ((flags & 8u) == 0u) {
        p = start;
        acc = 0u;
    } else {
        uint8_t overflow = (flags & 4u) != 0u ? 1u : 0u;
        if ((flags & 1u) != 0u) {
            uint64_t limit = (flags & 2u) != 0u ? ((uint64_t)INT64_MAX + 1ULL) : (uint64_t)INT64_MAX;
            if (acc > limit) {
                overflow = 1u;
            }
        }
        if (overflow) {
            if (out_errno) {
                *out_errno = ROME2_VFS_L47_ERANGE_MSVC;
            }
            if ((flags & 1u) == 0u) {
                acc = UINT64_MAX;
            } else if ((flags & 2u) != 0u) {
                acc = 0x8000000000000000ULL;
            } else {
                acc = 0x7fffffffffffffffULL;
            }
        } else if ((flags & 2u) != 0u) {
            acc = 0ULL - acc;
        }
    }

    if (endptr) {
        *endptr = p;
    }
    return acc;
}

uint32_t rome2_vfs_crt_ischartype_l(
    const uint16_t *ctype_257,
    int32_t mb_cur_max,
    int32_t ch,
    uint32_t mask,
    uint8_t has_locinfo)
{
    if (!has_locinfo || !ctype_257) {
        return 0u;
    }
    if ((uint32_t)(ch + 1) <= 0x100u) {
        return rome2_vfs_crt_locale_get_ctype_value(ctype_257, ch, mask);
    }
    return (mb_cur_max > 1) ? 1u : 0u;
}

int32_t rome2_vfs_crt_wcsncmp(const uint16_t *lhs, const uint16_t *rhs, size_t count)
{
    size_t n = count;
    if (!lhs || !rhs || n == 0u) {
        return 0;
    }
    while (--n != 0u && *lhs != 0u && *lhs == *rhs) {
        ++lhs;
        ++rhs;
    }
    return (int32_t)(uint32_t)*lhs - (int32_t)(uint32_t)*rhs;
}

int32_t rome2_vfs_crt_wcsicmp_ascii(const uint16_t *lhs, const uint16_t *rhs, int32_t *out_errno)
{
    if (!lhs || !rhs) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return 0x7fffffff;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    for (;;) {
        uint16_t a = *lhs++;
        uint16_t b = *rhs++;
        if (a >= (uint16_t)'A' && a <= (uint16_t)'Z') {
            a = (uint16_t)(a + 0x20u);
        }
        if (b >= (uint16_t)'A' && b <= (uint16_t)'Z') {
            b = (uint16_t)(b + 0x20u);
        }
        if (a != b || a == 0u) {
            return (int32_t)(uint32_t)a - (int32_t)(uint32_t)b;
        }
    }
}

uint8_t rome2_vfs_crt_common_wfullpath_gate(
    uint32_t buf_va,
    const uint16_t *path,
    size_t max_chars,
    uint8_t *out_alloc_result,
    uint32_t *out_ret_va)
{
    if (out_alloc_result) {
        *out_alloc_result = 0u;
    }
    if (!path || path[0] == 0u) {
        if (out_ret_va) {
            *out_ret_va = (max_chars > 0u && buf_va != 0u) ? buf_va : 0u;
        }
        return 0u;
    }
    if (buf_va != 0u) {
        if (out_ret_va) {
            *out_ret_va = buf_va;
        }
        return 1u;
    }
    if (out_alloc_result) {
        *out_alloc_result = 1u;
    }
    if (out_ret_va) {
        *out_ret_va = 0u;
    }
    return 1u;
}

uint8_t rome2_vfs_crt_realloc_base_plan(
    uint32_t block_va,
    uint32_t new_size,
    uint32_t heap_realloc_va,
    int32_t new_mode,
    uint8_t callnewh_retry,
    uint32_t *out_result_va,
    uint8_t *out_use_malloc,
    uint8_t *out_use_free,
    int32_t *out_errno)
{
    if (out_use_malloc) {
        *out_use_malloc = 0u;
    }
    if (out_use_free) {
        *out_use_free = 0u;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    if (block_va == 0u) {
        if (out_use_malloc) {
            *out_use_malloc = 1u;
        }
        if (out_result_va) {
            *out_result_va = heap_realloc_va;
        }
        return 1u;
    }
    if (new_size == 0u) {
        if (out_use_free) {
            *out_use_free = 1u;
        }
        if (out_result_va) {
            *out_result_va = 0u;
        }
        return 1u;
    }
    if (new_size > 0xffffffe0u) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_ENOMEM_MSVC;
        }
        if (out_result_va) {
            *out_result_va = 0u;
        }
        return 0u;
    }
    if (heap_realloc_va != 0u) {
        if (out_result_va) {
            *out_result_va = heap_realloc_va;
        }
        return 1u;
    }
    if (new_mode != 0 && callnewh_retry != 0u) {
        if (out_result_va) {
            *out_result_va = 1u;
        }
        return 1u;
    }
    if (out_errno) {
        *out_errno = ROME2_VFS_L44_ENOMEM_MSVC;
    }
    if (out_result_va) {
        *out_result_va = 0u;
    }
    return 0u;
}

int32_t rome2_vfs_crt_msize_base_gate(
    uint32_t block_va,
    int32_t heap_size_val,
    int32_t *out_errno)
{
    if (block_va == 0u) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return -1;
    }
    if (out_errno) {
        *out_errno = 0;
    }
    return heap_size_val;
}

uint32_t rome2_vfs_crt_query_new_handler_decode(
    uint32_t encoded_newh_slot,
    uint32_t security_cookie)
{
    return rome2_vfs_crt_decode_pointer32(encoded_newh_slot, security_cookie);
}

double rome2_vfs_crt_errmath_restore_cw(double handled_val, uint16_t saved_cw, uint16_t *out_restored_cw)
{
    if (out_restored_cw) {
        *out_restored_cw = (saved_cw != 0x027fu) ? saved_cw : 0x027fu;
    }
    return handled_val;
}

uint64_t rome2_vfs_crt_f64_quiet_nan_widen(uint32_t fp_class_eax, uint64_t f64_bits)
{
    if ((fp_class_eax & 0x00080000u) != 0u) {
        return f64_bits;
    }
    /* Emulate `fadd qword ptr [0x1191b3e0]` (add 1.0): sets IEEE-754 f64 quiet-NaN bit on NaN. */
    if ((f64_bits & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL &&
        (f64_bits & 0x000fffffffffffffULL) != 0ULL) {
        return f64_bits | 0x0008000000000000ULL;
    }
    {
        double val;
        (void)memcpy(&val, &f64_bits, sizeof(val));
        val += 1.0;
        (void)memcpy(&f64_bits, &val, sizeof(f64_bits));
    }
    return f64_bits;
}

int64_t rome2_vfs_crt_ftol2_truncate(double x)
{
    if (!isfinite(x)) {
        return (int64_t)0x8000000000000000ULL;
    }
    if (x >= 9223372036854775808.0 || x < -9223372036854775808.0) {
        return (int64_t)0x8000000000000000ULL;
    }
    return (int64_t)trunc(x);
}

static void l47_step_locale_refs(
    rome2_vfs_crt_threadlocinfo184_32 *locinfo,
    int32_t ref_pools[10],
    int32_t cat_ref_pools[6][2],
    int32_t delta)
{
    size_t i;
    locinfo->refcount_0c += delta;
    if (locinfo->lconv_intl_refcount_7c != 0u) {
        ref_pools[0] += delta;
    }
    if (locinfo->lconv_mon_refcount_84 != 0u) {
        ref_pools[1] += delta;
    }
    if (locinfo->lconv_num_refcount_80 != 0u) {
        ref_pools[2] += delta;
    }
    if (locinfo->ctype1_refcount_8c != 0u) {
        ref_pools[3] += delta;
    }
    for (i = 0u; i < 6u; ++i) {
        if (locinfo->cats_1c[i].wlocale_name_04 != ROME2_VFS_L47_C_LOCALE_NAME_VA &&
            locinfo->cats_1c[i].wrefcount_ptr_0c != 0u) {
            cat_ref_pools[i][1] += delta;
        }
        if (locinfo->cats_1c[i].locale_name_00 != 0u &&
            locinfo->cats_1c[i].refcount_ptr_08 != 0u) {
            cat_ref_pools[i][0] += delta;
        }
    }
}

uint32_t rome2_vfs_crt_locale_add_ref(
    rome2_vfs_crt_threadlocinfo184_32 *locinfo,
    int32_t ref_pools[10],
    int32_t cat_ref_pools[6][2],
    uint32_t *out_lctime_va)
{
    if (out_lctime_va) {
        *out_lctime_va = locinfo ? locinfo->lc_time_curr_9c : 0u;
    }
    if (!locinfo || !ref_pools || !cat_ref_pools) {
        return 0u;
    }
    l47_step_locale_refs(locinfo, ref_pools, cat_ref_pools, 1);
    return locinfo->lc_time_curr_9c;
}

uint32_t rome2_vfs_crt_locale_release_ref(
    rome2_vfs_crt_threadlocinfo184_32 *locinfo,
    int32_t ref_pools[10],
    int32_t cat_ref_pools[6][2],
    uint32_t *out_lctime_va)
{
    if (out_lctime_va) {
        *out_lctime_va = locinfo ? locinfo->lc_time_curr_9c : 0u;
    }
    if (!locinfo || !ref_pools || !cat_ref_pools) {
        return 0u;
    }
    l47_step_locale_refs(locinfo, ref_pools, cat_ref_pools, -1);
    return locinfo->lc_time_curr_9c;
}

uint32_t rome2_vfs_crt_free_locale_plan(
    const rome2_vfs_crt_threadlocinfo184_32 *locinfo,
    const int32_t ref_pools[10],
    const int32_t cat_wref_pools[6],
    uint32_t *out_lctime_destroy_va,
    uint8_t *out_free_locinfo)
{
    uint32_t mask = 0u;
    size_t i;
    if (out_lctime_destroy_va) {
        *out_lctime_destroy_va = locinfo ? locinfo->lc_time_curr_9c : 0u;
    }
    if (out_free_locinfo) {
        *out_free_locinfo = locinfo ? 1u : 0u;
    }
    if (!locinfo || !ref_pools || !cat_wref_pools) {
        return 0u;
    }
    if (locinfo->lconv_88 != 0u && locinfo->lconv_88 != ROME2_VFS_L47_LCONV_DEFAULT_VA &&
        locinfo->lconv_intl_refcount_7c != 0u && ref_pools[0] == 0) {
        if (locinfo->lconv_mon_refcount_84 != 0u && ref_pools[1] == 0) {
            mask |= 1u;
        }
        if (locinfo->lconv_num_refcount_80 != 0u && ref_pools[2] == 0) {
            mask |= 2u;
        }
        mask |= 4u;
    }
    if (locinfo->ctype1_refcount_8c != 0u && ref_pools[3] == 0) {
        mask |= 8u;
    }
    for (i = 0u; i < 6u; ++i) {
        if (locinfo->cats_1c[i].wlocale_name_04 != ROME2_VFS_L47_C_LOCALE_NAME_VA &&
            locinfo->cats_1c[i].wrefcount_ptr_0c != 0u && cat_wref_pools[i] == 0) {
            mask |= (uint32_t)(1u << (4u + i));
        }
    }
    return mask;
}

uint32_t rome2_vfs_crt_update_thread_mbc_internal(
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t *inout_global_mbc_slot_va,
    int32_t *inout_old_mbc_refcount,
    int32_t *inout_new_mbc_refcount,
    uint32_t per_thread_mask,
    uint8_t *out_freed_old,
    uint8_t *out_aborted)
{
    uint32_t mbc;
    if (out_freed_old) {
        *out_freed_old = 0u;
    }
    if (out_aborted) {
        *out_aborted = 0u;
    }
    if (!ptd || !inout_global_mbc_slot_va) {
        if (out_aborted) {
            *out_aborted = 1u;
        }
        return 0u;
    }
    if ((ptd->ownlocale_350 & per_thread_mask) != 0u && ptd->ptlocinfo_4c != 0u) {
        mbc = ptd->ptmbcinfo_48;
        if (mbc == 0u && out_aborted) {
            *out_aborted = 1u;
        }
        return mbc;
    }
    mbc = ptd->ptmbcinfo_48;
    if (mbc != *inout_global_mbc_slot_va) {
        if (mbc != 0u && inout_old_mbc_refcount) {
            int32_t next_old = *inout_old_mbc_refcount - 1;
            *inout_old_mbc_refcount = next_old;
            if (next_old == 0 && mbc != ROME2_VFS_L43_DEFAULT_MBCINFO_VA && out_freed_old) {
                *out_freed_old = 1u;
            }
        }
        mbc = *inout_global_mbc_slot_va;
        ptd->ptmbcinfo_48 = mbc;
        if (mbc != 0u && inout_new_mbc_refcount) {
            *inout_new_mbc_refcount += 1;
        }
    }
    if (mbc == 0u && out_aborted) {
        *out_aborted = 1u;
    }
    return mbc;
}

uint32_t rome2_vfs_crt_update_thread_locale_internal(
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t global_locinfo_va,
    uint32_t updated_locinfo_va,
    uint32_t per_thread_mask,
    uint8_t *out_updated_flag,
    uint8_t *out_aborted)
{
    uint32_t loc = 0u;
    if (out_updated_flag) {
        *out_updated_flag = 0u;
    }
    if (out_aborted) {
        *out_aborted = 0u;
    }
    if (!ptd) {
        if (out_aborted) {
            *out_aborted = 1u;
        }
        return 0u;
    }
    if ((ptd->ownlocale_350 & per_thread_mask) != 0u) {
        loc = ptd->ptlocinfo_4c;
        if (loc != 0u) {
            return loc;
        }
    }
    loc = (updated_locinfo_va != 0u) ? updated_locinfo_va : global_locinfo_va;
    if (ptd->ptlocinfo_4c != loc) {
        ptd->ptlocinfo_4c = loc;
        if (out_updated_flag) {
            *out_updated_flag = 1u;
        }
    }
    if (loc == 0u && out_aborted) {
        *out_aborted = 1u;
    }
    return loc;
}

uint32_t rome2_vfs_crt_mxcsr_to_fenv_ctrl(uint32_t mxcsr)
{
    uint32_t dn = mxcsr & 0x8040u;
    uint32_t fe_dn;
    uint32_t fe_rc = 0u;
    uint32_t exc;

    if (dn == 0x8000u) {
        fe_dn = 0x0c00u;
    } else if (dn == 0x0040u) {
        fe_dn = 0x0800u;
    } else if (dn == 0x8040u) {
        fe_dn = 0x0400u;
    } else {
        fe_dn = 0u;
    }

    switch (mxcsr & 0x6000u) {
    case 0x2000u:
        fe_rc = 0x0100u;
        break;
    case 0x4000u:
        fe_rc = 0x0200u;
        break;
    case 0x6000u:
        fe_rc = 0x0300u;
        break;
    default:
        break;
    }

    exc = (((mxcsr >> 8) & 1u) << 5) |
          (((mxcsr >> 7) & 1u) << 4) |
          (((mxcsr >> 9) & 1u) << 3) |
          (((mxcsr >> 10) & 1u) << 2) |
          (((mxcsr >> 11) & 1u) << 1) |
          ((mxcsr >> 12) & 1u);
    return exc | fe_rc | fe_dn;
}

uint32_t rome2_vfs_crt_x87_cw_to_fenv_ctrl(uint16_t x87_cw)
{
    uint32_t w = (uint32_t)x87_cw;
    uint32_t fe_ic = (w & 0x1000u) << 2;
    uint32_t pc = w & 0x0300u;
    uint32_t fe_pc;
    uint32_t fe_rc = 0u;
    uint32_t exc;

    if (pc == 0u) {
        fe_pc = 0x2000u;
    } else if (pc == 0x0200u) {
        fe_pc = 0x1000u;
    } else {
        fe_pc = 0u;
    }

    switch (w & 0x0c00u) {
    case 0x0400u:
        fe_rc = 0x0100u;
        break;
    case 0x0800u:
        fe_rc = 0x0200u;
        break;
    case 0x0c00u:
        fe_rc = 0x0300u;
        break;
    default:
        break;
    }

    exc = (((w >> 1) & 1u) << 5) |
          ((w & 1u) << 4) |
          (((w >> 2) & 1u) << 3) |
          (((w >> 3) & 1u) << 2) |
          (((w >> 4) & 1u) << 1) |
          ((w >> 5) & 1u);
    return exc | fe_rc | fe_pc | fe_ic;
}

uint32_t rome2_vfs_crt_fenv_ctrl_to_mxcsr(uint32_t fenv_ctrl)
{
    uint32_t packed = ((fenv_ctrl & 0xc03fffffu) | (fenv_ctrl >> 2)) >> 22;
    uint32_t dn = 0u;
    uint32_t rc = 0u;
    uint32_t exc;

    switch (fenv_ctrl & 0x0c00u) {
    case 0x0400u:
        dn = 0x8040u;
        break;
    case 0x0800u:
        dn = 0x0040u;
        break;
    case 0x0c00u:
        dn = 0x8000u;
        break;
    default:
        break;
    }

    switch (packed & 0x0300u) {
    case 0x0100u:
        rc = 0x2000u;
        break;
    case 0x0200u:
        rc = 0x4000u;
        break;
    case 0x0300u:
        rc = 0x6000u;
        break;
    default:
        break;
    }

    exc = (((packed >> 1) & 1u) << 11) |
          (((packed >> 2) & 1u) << 10) |
          (((packed >> 3) & 1u) << 9) |
          (((packed >> 5) & 1u) << 8) |
          (((packed >> 4) & 1u) << 7) |
          ((packed & 1u) << 12);
    return exc | dn | rc;
}

uint16_t rome2_vfs_crt_fenv_ctrl_to_x87_cw(uint32_t fenv_ctrl)
{
    uint32_t ic = (fenv_ctrl >> 2) & 0x1000u;
    uint32_t packed = (((fenv_ctrl >> 2) & 0x000fc000u) | (fenv_ctrl & 0x00c00000u)) >> 14;
    uint32_t pc;
    uint32_t rc = 0u;
    uint32_t exc;

    if ((fenv_ctrl & 0x3000u) == 0u) {
        pc = 0x0300u;
    } else if ((fenv_ctrl & 0x3000u) == 0x1000u) {
        pc = 0x0200u;
    } else {
        pc = 0u;
    }

    switch (packed & 0x0300u) {
    case 0x0100u:
        rc = 0x0400u;
        break;
    case 0x0200u:
        rc = 0x0800u;
        break;
    case 0x0300u:
        rc = 0x0c00u;
        break;
    default:
        break;
    }

    exc = ((packed & 1u) << 5) |
          (((packed >> 1) & 1u) << 4) |
          (((packed >> 2) & 1u) << 3) |
          (((packed >> 3) & 1u) << 2) |
          (((packed >> 5) & 1u) << 1) |
          ((packed >> 4) & 1u);
    return (uint16_t)(exc | ic | pc | rc);
}

int32_t rome2_vfs_crt_woutput_process_step(
    uint8_t has_valid_stream,
    const uint16_t *fmt,
    int32_t *inout_chars_written,
    uint8_t *out_ok,
    int32_t *out_errno)
{
    int32_t written = inout_chars_written ? *inout_chars_written : 0;
    if (out_errno) {
        *out_errno = 0;
    }
    if (!has_valid_stream || !fmt) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        if (out_ok) {
            *out_ok = 0u;
        }
        return -1;
    }
    while (*fmt != 0u && written >= 0) {
        if (*fmt != (uint16_t)'%') {
            ++written;
        } else if (fmt[1] == (uint16_t)'%') {
            ++written;
            ++fmt;
        } else if (fmt[1] == 0u) {
            if (out_errno) {
                *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
            }
            if (out_ok) {
                *out_ok = 0u;
            }
            return -1;
        }
        ++fmt;
    }
    if (inout_chars_written) {
        *inout_chars_written = written;
    }
    if (out_ok) {
        *out_ok = 1u;
    }
    return written;
}

static void l47_bigint_trim(rome2_vfs_crt_bigint464 *n)
{
    while (n->used > 0u && n->data[n->used - 1u] == 0u) {
        --n->used;
    }
}

uint64_t rome2_vfs_crt_bigint_div_u32(
    rome2_vfs_crt_bigint464 *numerator,
    const rome2_vfs_crt_bigint464 *denominator)
{
    uint32_t u_used;
    uint32_t v_used;
    uint64_t q_accum = 0u;

    if (!numerator || !denominator ||
        numerator->used > ROME2_VFS_L47_BIGINT_LIMBS ||
        denominator->used > ROME2_VFS_L47_BIGINT_LIMBS) {
        return 0u;
    }
    u_used = numerator->used;
    v_used = denominator->used;
    if (u_used == 0u || v_used == 0u) {
        return 0u;
    }

    if (v_used == 1u) {
        uint32_t d0 = denominator->data[0];
        uint64_t rem = 0u;
        uint32_t idx;
        if (d0 == 0u) {
            return 0u;
        }
        if (d0 == 1u && u_used == 1u) {
            q_accum = numerator->data[0];
            (void)memset(numerator, 0, sizeof(*numerator));
            return q_accum;
        }
        idx = u_used;
        while (idx > 0u) {
            uint64_t cur;
            --idx;
            cur = (rem << 32) | (uint64_t)numerator->data[idx];
            q_accum = (q_accum << 32) | (cur / (uint64_t)d0);
            rem = cur % (uint64_t)d0;
        }
        (void)memset(numerator->data, 0, sizeof(numerator->data));
        numerator->data[0] = (uint32_t)rem;
        numerator->used = (rem != 0u) ? 1u : 0u;
        return q_accum;
    }

    if (v_used < 2u || v_used > ROME2_VFS_L47_BIGINT_LIMBS ||
        u_used < v_used || u_used > ROME2_VFS_L47_BIGINT_LIMBS) {
        return 0u;
    }

    {
        uint32_t v_hi_idx = v_used - 1u;
        uint32_t v_lo_idx = v_used - 2u;
        uint32_t shift = 0u;
        uint32_t v_top = denominator->data[v_hi_idx];
        uint32_t u_norm[ROME2_VFS_L47_BIGINT_LIMBS + 1u];
        uint32_t v_norm[ROME2_VFS_L47_BIGINT_LIMBS];
        uint32_t vn1;
        uint32_t vn2;
        uint32_t i;
        uint32_t m = u_used - v_used;

        if (v_top == 0u) {
            return 0u;
        }
        while ((v_top & 0x80000000u) == 0u) {
            v_top <<= 1;
            ++shift;
        }

        (void)memset(u_norm, 0, sizeof(u_norm));
        (void)memset(v_norm, 0, sizeof(v_norm));
        if (shift == 0u) {
            for (i = 0u; i < u_used; ++i) {
                u_norm[i] = numerator->data[i];
            }
            for (i = 0u; i < v_used; ++i) {
                v_norm[i] = denominator->data[i];
            }
        } else {
            uint32_t carry = 0u;
            for (i = 0u; i < u_used; ++i) {
                uint32_t limb = numerator->data[i];
                u_norm[i] = (limb << shift) | carry;
                carry = limb >> (32u - shift);
            }
            u_norm[u_used] = carry;
            carry = 0u;
            for (i = 0u; i < v_used; ++i) {
                uint32_t limb = denominator->data[i];
                v_norm[i] = (limb << shift) | carry;
                carry = limb >> (32u - shift);
            }
        }

        vn1 = v_norm[v_hi_idx];
        vn2 = v_norm[v_lo_idx];
        if (vn1 == 0u) {
            return 0u;
        }

        for (i = m + 1u; i > 0u; --i) {
            uint32_t j = i - 1u;
            uint32_t u_top_idx = j + v_used;
            if (u_top_idx > ROME2_VFS_L47_BIGINT_LIMBS || u_top_idx < 2u) {
                break;
            }
            {
                uint64_t num_hi = ((uint64_t)u_norm[u_top_idx] << 32) | (uint64_t)u_norm[u_top_idx - 1u];
                uint64_t qhat = num_hi / (uint64_t)vn1;
                uint64_t rhat = num_hi % (uint64_t)vn1;
                uint64_t u2 = (uint64_t)u_norm[u_top_idx - 2u];
                uint64_t borrow = 0u;
                uint32_t k;

                if (qhat >= 0x100000000ULL || (qhat * (uint64_t)vn2) > ((rhat << 32) | u2)) {
                    --qhat;
                    rhat += (uint64_t)vn1;
                    if (rhat < 0x100000000ULL &&
                        (qhat >= 0x100000000ULL || (qhat * (uint64_t)vn2) > ((rhat << 32) | u2))) {
                        --qhat;
                    }
                }

                for (k = 0u; k < v_used; ++k) {
                    uint64_t prod = qhat * (uint64_t)v_norm[k] + borrow;
                    uint64_t sub = (uint64_t)u_norm[j + k] - (prod & 0xffffffffULL);
                    u_norm[j + k] = (uint32_t)sub;
                    borrow = (prod >> 32) + ((sub >> 63) != 0ULL ? 1ULL : 0ULL);
                }
                {
                    uint64_t top_sub = (uint64_t)u_norm[u_top_idx] - borrow;
                    u_norm[u_top_idx] = (uint32_t)top_sub;
                    if ((top_sub >> 63) != 0ULL) {
                        uint64_t carry2 = 0u;
                        --qhat;
                        for (k = 0u; k < v_used; ++k) {
                            uint64_t sum = (uint64_t)u_norm[j + k] + (uint64_t)v_norm[k] + carry2;
                            u_norm[j + k] = (uint32_t)sum;
                            carry2 = sum >> 32;
                        }
                        u_norm[u_top_idx] += (uint32_t)carry2;
                    }
                }
                q_accum = (q_accum << 32) | (qhat & 0xffffffffULL);
            }
        }

        (void)memset(numerator->data, 0, sizeof(numerator->data));
        if (shift == 0u) {
            for (i = 0u; i < v_used; ++i) {
                numerator->data[i] = u_norm[i];
            }
        } else {
            for (i = 0u; i < v_used; ++i) {
                numerator->data[i] = (u_norm[i] >> shift) | (u_norm[i + 1u] << (32u - shift));
            }
        }
        numerator->used = v_used;
        l47_bigint_trim(numerator);
        return q_accum;
    }
}

uint8_t rome2_vfs_crt_input_process_state(
    rome2_vfs_crt_fmt_parser76_32 *parser,
    int32_t next_char,
    uint8_t whitespace_ok,
    uint8_t has_suppress,
    uint8_t trailing_non_ws,
    uint32_t *inout_matched_count)
{
    if (!parser) {
        return 0u;
    }
    switch (parser->mode_10) {
    case 2u:
        return whitespace_ok ? 1u : 0u;
    case 3u:
        if (next_char == -1 || (uint32_t)next_char != (uint32_t)parser->lit_ch_14) {
            return 0u;
        }
        return 1u;
    case 4u:
        if (!has_suppress || trailing_non_ws ||
            parser->conv_idx_28 == 9u || parser->is_wide_24 != 0u) {
            return 0u;
        }
        if (inout_matched_count) {
            *inout_matched_count += 1u;
        }
        return 1u;
    default:
        return 0u;
    }
}

uint8_t rome2_vfs_crt_scan_conversion_specifier(
    rome2_vfs_crt_fmt_parser76_32 *fp,
    const char *fmt_buf,
    size_t *inout_off,
    size_t fmt_len)
{
    uint8_t ch;
    if (!fp || !fmt_buf || !inout_off || *inout_off >= fmt_len) {
        return 0u;
    }
    ch = (uint8_t)fmt_buf[*inout_off];
    switch (ch) {
    case 'c':
        if (fp->width_18 == 0u && fp->length_mod_1c == 0u) {
            fp->width_18 = 1u;
            fp->length_mod_1c = 0u;
        }
        fp->conv_idx_28 = 0u;
        *inout_off += 1u;
        return 1u;
    case 'C':
    case 's':
    case 'S':
        fp->conv_idx_28 = 1u;
        *inout_off += 1u;
        return 1u;
    case 'd':
        fp->conv_idx_28 = 3u;
        *inout_off += 1u;
        return 1u;
    case 'i':
    case 'I':
        fp->conv_idx_28 = 2u;
        *inout_off += 1u;
        return 1u;
    case 'o':
        fp->conv_idx_28 = 4u;
        *inout_off += 1u;
        return 1u;
    case 'u':
        fp->conv_idx_28 = 5u;
        *inout_off += 1u;
        return 1u;
    case 'p':
        fp->length_idx_20 = 9u;
        /* fall through */
    case 'x':
    case 'X':
        fp->conv_idx_28 = 6u;
        *inout_off += 1u;
        return 1u;
    case 'A':
    case 'a':
    case 'E':
    case 'e':
    case 'F':
    case 'f':
    case 'G':
    case 'g':
        fp->conv_idx_28 = 7u;
        *inout_off += 1u;
        return 1u;
    case 'n':
        fp->conv_idx_28 = 9u;
        *inout_off += 1u;
        return 1u;
    case '[':
    {
        size_t pos = *inout_off + 1u;
        uint8_t invert = 0u;
        uint8_t prev = 0u;
        uint8_t has_prev = 0u;
        (void)memset(fp->scanset_words_2c, 0, sizeof(fp->scanset_words_2c));
        fp->conv_idx_28 = 8u;
        if (pos < fmt_len && fmt_buf[pos] == '^') {
            invert = 1u;
            ++pos;
        }
        if (pos < fmt_len && fmt_buf[pos] == ']') {
            uint8_t idx = (uint8_t)']';
            fp->scanset_words_2c[idx >> 5] |= (1u << (idx & 31u));
            prev = idx;
            has_prev = 1u;
            ++pos;
        }
        while (pos < fmt_len && fmt_buf[pos] != ']' && fmt_buf[pos] != '\0') {
            uint8_t cur = (uint8_t)fmt_buf[pos];
            if (cur == (uint8_t)'-' && has_prev && pos + 1u < fmt_len && fmt_buf[pos + 1u] != ']') {
                uint8_t hi = (uint8_t)fmt_buf[pos + 1u];
                uint8_t lo = prev;
                uint32_t c;
                if (lo > hi) {
                    uint8_t t = lo;
                    lo = hi;
                    hi = t;
                }
                for (c = (uint32_t)lo; c <= (uint32_t)hi; ++c) {
                    fp->scanset_words_2c[c >> 5] |= (1u << (c & 31u));
                }
                pos += 2u;
                has_prev = 0u;
            } else {
                fp->scanset_words_2c[cur >> 5] |= (1u << (cur & 31u));
                prev = cur;
                has_prev = 1u;
                ++pos;
            }
        }
        if (pos >= fmt_len || fmt_buf[pos] != ']') {
            fp->err_0c = ROME2_VFS_L44_EINVAL_MSVC;
            fp->conv_idx_28 = 0u;
            return 0u;
        }
        if (invert) {
            size_t w;
            for (w = 0u; w < 8u; ++w) {
                fp->scanset_words_2c[w] ^= 0xffffffffu;
            }
        }
        *inout_off = pos + 1u;
        return 1u;
    }
    default:
        fp->err_0c = ROME2_VFS_L44_EINVAL_MSVC;
        fp->conv_idx_28 = 0u;
        return 0u;
    }
}

int32_t rome2_vfs_crt_write_gate(
    int32_t fh,
    int32_t nhandle,
    const rome2_vfs_crt_ioinfo56_32 *chunk64,
    uint32_t buf_len,
    int32_t nolock_write_ret,
    int32_t *out_errno,
    uint32_t *out_doserrno)
{
    if (out_errno) {
        *out_errno = 0;
    }
    if (out_doserrno) {
        *out_doserrno = 0u;
    }
    if (fh == -2 || fh < 0 || fh >= nhandle || !chunk64) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L46_EBADF_MSVC;
        }
        return -1;
    }
    if ((chunk64[(uint32_t)fh & 0x3fu].osfile_28 & ROME2_VFS_L47_OSFILE_OPEN_BIT) == 0u) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L46_EBADF_MSVC;
        }
        return -1;
    }
    (void)buf_len;
    return nolock_write_ret;
}

static uint8_t l47_is_leap_year_crt(int32_t y_since_1900)
{
    int32_t y = y_since_1900 + 1900;
    return ((y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)) ? 1u : 0u;
}

int64_t rome2_vfs_crt_loctotime64_utc(
    int32_t tm_year,
    int32_t tm_mon,
    int32_t tm_mday,
    int32_t tm_hour,
    int32_t tm_min,
    int32_t tm_sec,
    int32_t isdst,
    int64_t tz_bias_sec,
    int64_t dst_bias_sec,
    uint8_t dst_active_flag,
    int32_t *out_errno)
{
    static const int32_t k_cum_days[13] = {
        0, -1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333
    };
    int32_t y = tm_year;
    int32_t days;
    int64_t utc;
    uint32_t m_idx;

    if (out_errno) {
        *out_errno = 0;
    }
    /* `common_loctotime_t` at `0x116adc11`: `y = yr - 1900`, checks `70 <= y <= 1101` (`0x46..0x44d`). */
    if (y >= 1900) {
        y -= 1900;
    }
    if (y < 70 || y > 1101 || tm_mon < 1 || tm_mon > 12 ||
        tm_mday < 1 || tm_mday > 31 || tm_hour < 0 || tm_hour > 23 ||
        tm_min < 0 || tm_min > 59 || tm_sec < 0 || tm_sec > 59) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return -1;
    }

    m_idx = (uint32_t)tm_mon;
    days = k_cum_days[m_idx] + tm_mday;
    if (l47_is_leap_year_crt(y) && tm_mon > 2) {
        ++days;
    }
    days += (y - 70) * 365 + ((y - 69) / 4) - ((y - 1) / 100) + ((y + 299) / 400);

    utc = ((int64_t)days * 86400LL) + ((int64_t)tm_hour * 3600LL) +
          ((int64_t)tm_min * 60LL) + (int64_t)tm_sec + tz_bias_sec;
    if (isdst == 1 || (isdst == -1 && dst_active_flag != 0u)) {
        utc += dst_bias_sec;
    }
    return utc;
}

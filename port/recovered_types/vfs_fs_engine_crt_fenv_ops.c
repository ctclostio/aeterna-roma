#include "vfs_fs_engine_crt_fenv_ops.h"

#include <errno.h>
#include <math.h>
#include <string.h>

static uint8_t l46_starts_with_ci7_w(const uint16_t *s, const char *prefix7)
{
    size_t i;
    if (!s) {
        return 0u;
    }
    for (i = 0u; i < 7u; ++i) {
        uint16_t wc = s[i];
        uint8_t pc = (uint8_t)prefix7[i];
        if (wc >= (uint16_t)'A' && wc <= (uint16_t)'Z') {
            wc = (uint16_t)(wc + 0x20u);
        }
        if (wc != (uint16_t)pc) {
            return 0u;
        }
    }
    return 1u;
}

static uint32_t l46_hw6_to_fe_exc(uint32_t hw6)
{
    uint32_t fe = 0u;
    if ((hw6 & 0x04u) != 0u) {
        fe |= 0x08u;
    }
    if ((hw6 & 0x02u) != 0u) {
        fe |= 0x20u;
    }
    if ((hw6 & 0x08u) != 0u) {
        fe |= 0x04u;
    }
    if ((hw6 & 0x10u) != 0u) {
        fe |= 0x02u;
    }
    if ((hw6 & 0x01u) != 0u) {
        fe |= 0x10u;
    }
    if ((hw6 & 0x20u) != 0u) {
        fe |= 0x01u;
    }
    return fe;
}

static uint32_t l46_fe_exc_to_hw6(uint32_t fe6)
{
    uint32_t hw = 0u;
    if ((fe6 & 0x02u) != 0u) {
        hw |= 0x10u;
    }
    if ((fe6 & 0x01u) != 0u) {
        hw |= 0x20u;
    }
    if ((fe6 & 0x04u) != 0u) {
        hw |= 0x08u;
    }
    if ((fe6 & 0x08u) != 0u) {
        hw |= 0x04u;
    }
    if ((fe6 & 0x10u) != 0u) {
        hw |= 0x01u;
    }
    if ((fe6 & 0x20u) != 0u) {
        hw |= 0x02u;
    }
    return hw;
}

static double l46_f64_from_u64(uint64_t bits)
{
    double v = 0.0;
    (void)memcpy(&v, &bits, sizeof(v));
    return v;
}

uint32_t rome2_vfs_crt_fast_encode_pointer32(uint32_t ptr_va, uint32_t security_cookie)
{
    return rome2_vfs_crt_encode_pointer32(ptr_va, security_cookie);
}

uint32_t rome2_vfs_crt_locale_get_ctype_value(
    const uint16_t *ctype_257,
    int32_t ch,
    uint32_t mask)
{
    uint32_t shifted = (uint32_t)(ch + 1);
    if (!ctype_257 || shifted > 0x100u) {
        return 0u;
    }
    return (uint32_t)ctype_257[shifted] & mask;
}

uint8_t rome2_vfs_crt_is_slash_w(uint16_t ch)
{
    return (ch == (uint16_t)'\\' || ch == (uint16_t)'/') ? 1u : 0u;
}

uint32_t rome2_vfs_crt_get_drive_number_from_path_w(const uint16_t *wpath)
{
    uint16_t c;
    if (!wpath || wpath[0] == 0u || wpath[1] != (uint16_t)':') {
        return 0u;
    }
    c = wpath[0];
    if (c >= (uint16_t)'a' && c <= (uint16_t)'z') {
        c = (uint16_t)(c - 0x20u);
    }
    return (uint32_t)(uint16_t)(c - 0x40u);
}

uint64_t rome2_vfs_crt_strtoull_ascii(
    const char *nptr,
    const char **endptr,
    int32_t base,
    int32_t *out_errno)
{
    const char *s = nptr;
    const char *start = nptr;
    uint8_t neg = 0u;
    uint64_t acc = 0u;
    uint64_t cutoff;
    uint64_t cutlim;
    int any = 0;
    int32_t radix = base;

    if (out_errno) {
        *out_errno = 0;
    }
    if (!nptr || (radix != 0 && (radix < 2 || radix > 36))) {
        if (endptr) {
            *endptr = nptr;
        }
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_EINVAL_MSVC;
        }
        return 0u;
    }

    while (*s == ' ' || (*s >= '\t' && *s <= '\r')) {
        s++;
    }
    if (*s == '-') {
        neg = 1u;
        s++;
    } else if (*s == '+') {
        s++;
    }

    if ((radix == 0 || radix == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        radix = 16;
    } else if (radix == 0) {
        radix = (*s == '0') ? 8 : 10;
    }

    cutoff = UINT64_MAX / (uint64_t)radix;
    cutlim = UINT64_MAX % (uint64_t)radix;

    for (;; s++) {
        uint8_t c = (uint8_t)*s;
        uint64_t d;
        if (c >= '0' && c <= '9') {
            d = (uint64_t)(c - '0');
        } else if (c >= 'a' && c <= 'z') {
            d = (uint64_t)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'Z') {
            d = (uint64_t)(c - 'A' + 10);
        } else {
            break;
        }
        if (d >= (uint64_t)radix) {
            break;
        }
        if (any < 0 || acc > cutoff || (acc == cutoff && d > cutlim)) {
            any = -1;
        } else {
            any = 1;
            acc = acc * (uint64_t)radix + d;
        }
    }

    if (any < 0) {
        acc = UINT64_MAX;
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_ERANGE_MSVC;
        }
    } else if (neg && any > 0) {
        acc = (uint64_t)(-(int64_t)acc);
    }

    if (endptr) {
        *endptr = (any != 0) ? s : start;
    }
    return acc;
}

uint8_t rome2_vfs_crt_isspace_l(
    uint8_t is_ctype_space,
    rome2_vfs_crt_locale_update16_32 *lu,
    rome2_vfs_crt_tiddata868_32 *ptd)
{
    if (lu && ptd) {
        (void)rome2_vfs_crt_locale_update_release(lu, ptd);
    }
    return is_ctype_space ? 1u : 0u;
}

uint32_t rome2_vfs_crt_unlock_slot_va(int32_t lock_id)
{
    return rome2_vfs_crt_lock_slot_va(lock_id);
}

uint32_t rome2_vfs_crt_pctype_func_resolve(
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t global_locinfo_va,
    uint32_t refreshed_locinfo_va,
    uint32_t deref_pctype_va)
{
    uint32_t cached;
    if (!ptd) {
        return 0u;
    }
    cached = ptd->ptlocinfo_4c;
    (void)rome2_vfs_crt_sync_ptd_global_slot(
        ptd,
        0xfffffffeu,
        global_locinfo_va,
        refreshed_locinfo_va,
        &cached);
    ptd->ptlocinfo_4c = cached;
    return deref_pctype_va;
}

uint32_t rome2_vfs_crt_replace_thread_locinfo_nolock(
    rome2_vfs_crt_tiddata868_32 *ptd,
    uint32_t new_locinfo_va,
    uint32_t default_locinfo_slot_val,
    int32_t old_refcount,
    uint8_t *out_should_free_old,
    uint8_t *out_retained_new)
{
    uint32_t old_va;
    uint8_t free_old = 0u;
    uint8_t ret_new = 0u;

    if (!ptd) {
        if (out_should_free_old) {
            *out_should_free_old = 0u;
        }
        if (out_retained_new) {
            *out_retained_new = 0u;
        }
        return 0u;
    }

    old_va = ptd->ptlocinfo_4c;
    if (old_va != 0u &&
        old_va != default_locinfo_slot_val &&
        old_va != ROME2_VFS_L42_DEFAULT_LOCINFO_VA &&
        old_refcount == 0) {
        free_old = 1u;
    }
    ptd->ptlocinfo_4c = new_locinfo_va;
    if (new_locinfo_va != 0u) {
        ret_new = 1u;
    }
    if (out_should_free_old) {
        *out_should_free_old = free_old;
    }
    if (out_retained_new) {
        *out_retained_new = ret_new;
    }
    return old_va;
}

uint8_t rome2_vfs_crt_is_apiset_name_w(const uint16_t *mod_name)
{
    return (l46_starts_with_ci7_w(mod_name, "api-ms-") ||
            l46_starts_with_ci7_w(mod_name, "ext-ms-"))
               ? 1u
               : 0u;
}

uint32_t rome2_vfs_crt_try_get_first_available_module(
    uint32_t *cached_handles,
    size_t table_len,
    const uint32_t *mod_ids,
    const uint16_t *const *mod_names,
    size_t id_count,
    const uint32_t *gmh_results,
    const uint32_t *gmh_last_errs,
    const uint32_t *loadlib_results,
    uint8_t *out_used_loadlib_fallback)
{
    size_t i;
    if (out_used_loadlib_fallback) {
        *out_used_loadlib_fallback = 0u;
    }
    if (!cached_handles || !mod_ids) {
        return 0u;
    }

    for (i = 0u; i < id_count; ++i) {
        uint32_t id = mod_ids[i];
        uint32_t h;
        if ((size_t)id >= table_len) {
            continue;
        }
        h = cached_handles[id];
        if (h == 0xffffffffu) {
            continue;
        }
        if (h != 0u) {
            return h;
        }
        h = gmh_results ? gmh_results[i] : 0u;
        if (h == 0u &&
            gmh_last_errs &&
            gmh_last_errs[i] == ROME2_VFS_L46_ERR_INVALID_PARAM_WIN32 &&
            mod_names &&
            !rome2_vfs_crt_is_apiset_name_w(mod_names[i])) {
            h = loadlib_results ? loadlib_results[i] : 0u;
            if (out_used_loadlib_fallback) {
                *out_used_loadlib_fallback = 1u;
            }
        }
        if (h == 0u) {
            cached_handles[id] = 0xffffffffu;
            continue;
        }
        cached_handles[id] = h;
        return h;
    }
    return 0u;
}

double rome2_vfs_crt_set_exp(double x, int32_t exp_val)
{
    uint64_t bits = 0u;
    uint16_t top16;
    uint16_t next16;
    (void)memcpy(&bits, &x, sizeof(bits));
    top16 = (uint16_t)(bits >> 48);
    next16 = (uint16_t)((top16 & 0x800fu) | (uint16_t)(((exp_val + 0x3fe) & 0x7ff) << 4));
    bits = (bits & 0x0000ffffffffffffULL) | (((uint64_t)next16) << 48);
    return l46_f64_from_u64(bits);
}

rome2_vfs_reg_status rome2_vfs_crt_wfullpath_dispatch(
    uint32_t dst_va,
    uint32_t path_va,
    uint32_t max_words,
    uint8_t *out_ignore_case,
    uint8_t *out_must_exist,
    uint8_t *out_normal_alloc)
{
    (void)dst_va;
    (void)path_va;
    (void)max_words;
    if (!out_ignore_case || !out_must_exist || !out_normal_alloc) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    *out_ignore_case = 1u;
    *out_must_exist = 0u;
    *out_normal_alloc = 0u;
    return ROME2_VFS_REG_OK;
}

const uint16_t *rome2_vfs_crt_wcspbrk(const uint16_t *wstr, const uint16_t *control)
{
    const uint16_t *s;
    if (!wstr || !control) {
        return NULL;
    }
    for (s = wstr; *s != 0u; ++s) {
        const uint16_t *c;
        for (c = control; *c != 0u; ++c) {
            if (*s == *c) {
                return s;
            }
        }
    }
    return NULL;
}

uint8_t rome2_vfs_crt_f64_is_nan_or_inf_bits(uint64_t f64_bits)
{
    uint32_t hi = (uint32_t)(f64_bits >> 32);
    return ((hi & 0x7ff00000u) == 0x7ff00000u) ? 1u : 0u;
}

double rome2_vfs_crt_log10_guarded(double x, int32_t *out_libm_err_code)
{
    uint64_t bits = 0u;
    uint32_t hi;
    uint32_t lo;

    (void)memcpy(&bits, &x, sizeof(bits));
    hi = (uint32_t)(bits >> 32);
    lo = (uint32_t)(bits & 0xffffffffu);

    if ((hi & 0x7ff00000u) == 0x7ff00000u) {
        if ((hi & 0x000fffffu) != 0u || lo != 0u) {
            if (out_libm_err_code) {
                *out_libm_err_code = 0;
            }
            return x;
        }
        if ((hi & 0x80000000u) != 0u) {
            if (out_libm_err_code) {
                *out_libm_err_code = ROME2_VFS_L46_LOG10_ERR_NEG;
            }
            return l46_f64_from_u64(0xfff8000000000000ULL);
        }
        if (out_libm_err_code) {
            *out_libm_err_code = 0;
        }
        return x;
    }

    if ((hi & 0x7fffffffu) == 0u && lo == 0u) {
        if (out_libm_err_code) {
            *out_libm_err_code = ROME2_VFS_L46_LOG10_ERR_ZERO;
        }
        return l46_f64_from_u64(0xfff0000000000000ULL);
    }

    if ((hi & 0x80000000u) != 0u) {
        if (out_libm_err_code) {
            *out_libm_err_code = ROME2_VFS_L46_LOG10_ERR_NEG;
        }
        return l46_f64_from_u64(0xfff8000000000000ULL);
    }

    if (out_libm_err_code) {
        *out_libm_err_code = 0;
    }
    return log10(x);
}

const uint16_t *rome2_vfs_crt_wcsrchr(const uint16_t *wstr, uint16_t wc)
{
    const uint16_t *last = NULL;
    const uint16_t *cur;
    if (!wstr) {
        return NULL;
    }
    cur = wstr;
    for (;;) {
        if (*cur == wc) {
            last = cur;
        }
        if (*cur == 0u) {
            break;
        }
        cur++;
    }
    return last;
}

uint8_t rome2_vfs_crt_update_thread_mbc_gate(
    uint32_t ptd_va,
    uint32_t global_mbc_slot_va,
    uint32_t *out_target_slot_va)
{
    if (out_target_slot_va) {
        *out_target_slot_va = global_mbc_slot_va;
    }
    return (ptd_va != 0u && global_mbc_slot_va != 0u) ? 1u : 0u;
}

uint8_t rome2_vfs_crt_recalloc_plan(
    uint32_t old_bytes,
    uint32_t count,
    uint32_t elem_size,
    uint32_t *out_new_bytes,
    uint32_t *out_zero_tail_offset,
    uint32_t *out_zero_tail_bytes,
    int32_t *out_errno)
{
    uint32_t next;
    if (count != 0u && (0xffffffe0u / count) < elem_size) {
        if (out_new_bytes) {
            *out_new_bytes = 0u;
        }
        if (out_zero_tail_offset) {
            *out_zero_tail_offset = 0u;
        }
        if (out_zero_tail_bytes) {
            *out_zero_tail_bytes = 0u;
        }
        if (out_errno) {
            *out_errno = ROME2_VFS_L44_ENOMEM_MSVC;
        }
        return 0u;
    }
    next = count * elem_size;
    if (out_new_bytes) {
        *out_new_bytes = next;
    }
    if (next > old_bytes) {
        if (out_zero_tail_offset) {
            *out_zero_tail_offset = old_bytes;
        }
        if (out_zero_tail_bytes) {
            *out_zero_tail_bytes = next - old_bytes;
        }
    } else {
        if (out_zero_tail_offset) {
            *out_zero_tail_offset = 0u;
        }
        if (out_zero_tail_bytes) {
            *out_zero_tail_bytes = 0u;
        }
    }
    if (out_errno) {
        *out_errno = 0;
    }
    return 1u;
}

uint8_t rome2_vfs_crt_callnewh_dispatch(uint32_t decoded_handler_va, int32_t handler_ret)
{
    if (decoded_handler_va != 0u && handler_ret != 0) {
        return 1u;
    }
    return 0u;
}

int32_t rome2_vfs_crt_query_new_mode(int32_t newmode_global)
{
    return newmode_global;
}

int32_t rome2_vfs_crt_invoke_user_matherr(
    uint32_t encoded_handler,
    uint32_t security_cookie,
    const rome2_vfs_crt_math_exception32_32 *exc,
    int32_t handler_ret,
    uint8_t *out_invoked)
{
    uint32_t fn_va = rome2_vfs_crt_decode_pointer32(encoded_handler, security_cookie);
    if (fn_va == 0u || !exc) {
        if (out_invoked) {
            *out_invoked = 0u;
        }
        return 0;
    }
    if (out_invoked) {
        *out_invoked = 1u;
    }
    return handler_ret;
}

int32_t rome2_vfs_crt_isatty(
    int32_t fh,
    int32_t nhandle,
    const rome2_vfs_crt_ioinfo56_32 *chunk64,
    int32_t *out_errno)
{
    if (fh == -2 || fh < 0 || fh >= nhandle || !chunk64) {
        if (out_errno) {
            *out_errno = ROME2_VFS_L46_EBADF_MSVC;
        }
        return 0;
    }
    return (int32_t)(chunk64[(uint32_t)fh & 0x3fu].osfile_28 & ROME2_VFS_L46_OSFILE_DEV_BIT);
}

uint32_t rome2_vfs_crt_fenv_pack_control(
    uint32_t x87_ctrl_fe,
    uint32_t mxcsr_ctrl_fe,
    int32_t sse2_isa_level)
{
    uint32_t eax_m = (sse2_isa_level >= 1) ? mxcsr_ctrl_fe : 0u;
    uint32_t esi_x = x87_ctrl_fe;
    uint32_t edx = ((eax_m & 0x3fu) << 2) | (eax_m & 0xffffff00u);
    edx = (edx << 6) | (esi_x & 0x3fu);
    edx = (edx << 2) | (esi_x & 0x300u);
    edx <<= 14;
    return edx | eax_m | esi_x;
}

uint32_t rome2_vfs_crt_fenv_get_status(
    uint16_t x87_sw,
    uint32_t mxcsr,
    int32_t sse2_isa_level)
{
    uint32_t esi = l46_hw6_to_fe_exc((uint32_t)x87_sw & 0x3fu);
    uint32_t ecx = (sse2_isa_level >= 1) ? l46_hw6_to_fe_exc(mxcsr & 0x3fu) : 0u;
    uint32_t eax = ((ecx << 8) | esi) << 16;
    return eax | ecx | esi;
}

void rome2_vfs_crt_fenv_set_control(
    rome2_vfs_x87_env28_32 *x87_env,
    uint16_t x87_cw_mapped,
    uint32_t mxcsr_ctrl_mapped,
    int32_t sse2_isa_level,
    uint32_t *inout_mxcsr)
{
    if (x87_env) {
        uint32_t cur = x87_env->cw_00;
        x87_env->cw_00 = cur ^ ((cur ^ (uint32_t)x87_cw_mapped) & ROME2_VFS_L46_X87_CW_MASK);
    }
    if (sse2_isa_level >= 1 && inout_mxcsr) {
        *inout_mxcsr = (*inout_mxcsr & ~ROME2_VFS_L46_MXCSR_CTRL_MASK) |
                       (mxcsr_ctrl_mapped & ROME2_VFS_L46_MXCSR_CTRL_MASK);
    }
}

void rome2_vfs_crt_fenv_set_status(
    rome2_vfs_x87_env28_32 *x87_env,
    uint32_t fenv_stat_word,
    int32_t sse2_isa_level,
    uint32_t *inout_mxcsr)
{
    uint32_t hw_x87 = l46_fe_exc_to_hw6((fenv_stat_word >> 16) & 0x3fu);
    uint32_t hw_mx = l46_fe_exc_to_hw6((fenv_stat_word >> 24) & 0x3fu);
    if (x87_env) {
        x87_env->sw_04 = (x87_env->sw_04 & ~0x3fu) | (hw_x87 & 0x3fu);
    }
    if (sse2_isa_level >= 1 && inout_mxcsr) {
        *inout_mxcsr = (*inout_mxcsr & ~0x3fu) | (hw_mx & 0x3fu);
    }
}
